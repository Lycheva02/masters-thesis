from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urlparse
import re

from data.csic_actions import abstract_path

REQUEST_LINE_RE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+https?://", re.IGNORECASE)


@dataclass(frozen=True)
class RawHttpRequest:
    method: str
    url: str
    path: str
    query_params: tuple[tuple[str, str], ...]
    headers: dict[str, str]
    body: str
    body_params: tuple[tuple[str, str], ...]
    action: str
    session_id: str


def _extract_session_id(cookie_value: str) -> str:
    for chunk in cookie_value.split(";"):
        chunk = chunk.strip()
        if chunk.startswith("JSESSIONID="):
            return chunk.split("=", 1)[1]
    return cookie_value.strip() or "NOSESSION"


def _parse_request_lines(lines: list[str]) -> RawHttpRequest | None:
    lines = [line.rstrip("\r") for line in lines if line.strip() != ""]
    if not lines:
        return None

    request_line = lines[0]
    parts = request_line.split()
    if len(parts) < 2:
        return None

    method = parts[0]
    url = parts[1]
    parsed = urlparse(url)
    path = parsed.path
    query_params = tuple(parse_qsl(parsed.query, keep_blank_values=True))

    headers: dict[str, str] = {}
    body_start = len(lines)
    for idx, line in enumerate(lines[1:], start=1):
        if ":" not in line:
            body_start = idx
            break
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    body = "\n".join(lines[body_start:]).strip() if body_start < len(lines) else ""
    body_params = tuple(parse_qsl(body, keep_blank_values=True)) if body else ()
    cookie = headers.get("cookie", "")

    return RawHttpRequest(
        method=method,
        url=url,
        path=path,
        query_params=query_params,
        headers=headers,
        body=body,
        body_params=body_params,
        action=abstract_path(path),
        session_id=_extract_session_id(cookie),
    )


def iter_raw_requests(path: str | Path) -> Iterable[RawHttpRequest]:
    current: list[str] = []
    with Path(path).open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")
            if REQUEST_LINE_RE.match(line):
                if current:
                    parsed = _parse_request_lines(current)
                    if parsed is not None:
                        yield parsed
                    current = []
            current.append(line)

    if current:
        parsed = _parse_request_lines(current)
        if parsed is not None:
            yield parsed
