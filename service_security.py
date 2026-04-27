from __future__ import annotations

import hashlib
import hmac
from typing import Optional


def hash_client_binding(pop_key: str, client_id: str) -> str:
    digest = hashlib.sha256()
    digest.update(pop_key.encode("utf-8"))
    digest.update(b"|")
    digest.update(client_id.encode("utf-8"))
    return digest.hexdigest()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def build_pop_message(
    *,
    method: str,
    path: str,
    client_id: str,
    timestamp: int,
    nonce: str,
    token: Optional[str] = None,
) -> bytes:
    token_hash = hash_token(token) if token else ""
    message = "|".join(
        [
            method.upper(),
            path,
            client_id,
            str(timestamp),
            nonce,
            token_hash,
        ]
    )
    return message.encode("utf-8")


def make_pop_proof(
    pop_key: str,
    *,
    method: str,
    path: str,
    client_id: str,
    timestamp: int,
    nonce: str,
    token: Optional[str] = None,
) -> str:
    message = build_pop_message(
        method=method,
        path=path,
        client_id=client_id,
        timestamp=timestamp,
        nonce=nonce,
        token=token,
    )
    return hmac.new(pop_key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify_pop_proof(
    provided_proof: str,
    pop_key: str,
    *,
    method: str,
    path: str,
    client_id: str,
    timestamp: int,
    nonce: str,
    token: Optional[str] = None,
) -> bool:
    expected_proof = make_pop_proof(
        pop_key,
        method=method,
        path=path,
        client_id=client_id,
        timestamp=timestamp,
        nonce=nonce,
        token=token,
    )
    return hmac.compare_digest(provided_proof, expected_proof)