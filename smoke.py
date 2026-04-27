import json
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests


@dataclass(frozen=True)
class Endpoints:
    auth: str = "http://localhost:8001"
    risk: str = "http://localhost:8002"
    resource: str = "http://localhost:8003"


POP_KEY = "test_pop_key_123"
CLIENT_ID = "device_abc"


def _request(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    timeout: float = 5.0,
) -> Tuple[int, str, Optional[Dict[str, Any]]]:
    try:
        r = requests.request(method, url, headers=headers, json=json_body, timeout=timeout)
        text = r.text
        parsed = None
        try:
            parsed = r.json()
        except Exception:
            parsed = None
        return r.status_code, text, parsed
    except requests.RequestException as e:
        return 0, f"REQUEST_ERROR: {e}", None


def assert_ok(name: str, cond: bool, details: str = "") -> None:
    if cond:
        print(f"[OK]   {name}")
        if details:
            print(f"       {details}")
        return
    print(f"[FAIL] {name}")
    if details:
        print(f"       {details}")
    sys.exit(1)


def warn(name: str, cond: bool, details: str = "") -> None:
    if cond:
        print(f"[OK]   {name}")
        if details:
            print(f"       {details}")
    else:
        print(f"[WARN] {name}")
        if details:
            print(f"       {details}")


def health_check(ep: Endpoints) -> None:
    for svc, base in [("auth", ep.auth), ("risk", ep.risk), ("resource", ep.resource)]:
        code, text, _ = _request("GET", f"{base}/health")
        assert_ok(
            f"{svc} health",
            code == 200,
            details=f"code={code} body={text[:200]}",
        )


def risk_evaluate(ep: Endpoints) -> None:
    payload = {
        "user_id": "alice",
        "path": "/auth/token",
        "method": "POST",
        "ip": "127.0.0.1",
        "user_agent": "python-smoke",
        "timestamp": time.time(),
    }
    code, text, js = _request("POST", f"{ep.risk}/risk/evaluate", json_body=payload)
    assert_ok(
        "risk evaluate",
        code == 200 and isinstance(js, dict) and ("src" in js),
        details=f"code={code} body={text[:300]}",
    )


def auth_login(ep: Endpoints) -> Dict[str, str]:
    headers = {"X-POP-KEY": POP_KEY, "X-CLIENT-ID": CLIENT_ID}
    payload = {"username": "alice", "password": "wonderland"}
    code, text, js = _request("POST", f"{ep.auth}/auth/token", headers=headers, json_body=payload)
    assert_ok(
        "auth login",
        code == 200 and isinstance(js, dict) and ("access_token" in js) and ("refresh_token" in js),
        details=f"code={code} body={text[:300]}",
    )
    access = js["access_token"]
    refresh = js["refresh_token"]
    warn("access token format", access.count(".") == 2, details=access[:30] + "...")
    return {"access_token": access, "refresh_token": refresh}


def resource_access(ep: Endpoints, access_token: str, client_id: str = CLIENT_ID) -> Tuple[int, str, Optional[Dict[str, Any]]]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-POP-KEY": POP_KEY,
        "X-CLIENT-ID": client_id,
    }
    return _request("GET", f"{ep.resource}/resource", headers=headers)


def auth_refresh(ep: Endpoints, refresh_token: str) -> Dict[str, str]:
    headers = {"X-POP-KEY": POP_KEY, "X-CLIENT-ID": CLIENT_ID}
    payload = {"refresh_token": refresh_token}
    code, text, js = _request("POST", f"{ep.auth}/auth/refresh", headers=headers, json_body=payload)
    assert_ok(
        "auth refresh",
        code == 200 and isinstance(js, dict) and ("access_token" in js),
        details=f"code={code} body={text[:300]}",
    )
    return {"access_token": js["access_token"]}


def main() -> None:
    ep = Endpoints()

    print("=== 1. health ===")
    health_check(ep)

    print("\n=== 2. risk ===")
    risk_evaluate(ep)

    print("\n=== 3. login ===")
    tokens = auth_login(ep)
    access = tokens["access_token"]
    refresh = tokens["refresh_token"]

    print("\n=== 4. resource ===")
    code, text, js = resource_access(ep, access, CLIENT_ID)
    if code == 200:
        rho = None
        if isinstance(js, dict):
            rho = js.get("rho")
        print("[OK]   resource access")
        print(f"       rho={rho} body={text[:200]}")
    else:
        print("[INFO] resource access rejected")
        print(f"       code={code} body={text[:400]}")
        assert_ok("resource decision", code in (401, 403), details=f"code={code}")

    print("\n=== 5. binding mismatch ===")
    code2, text2, _ = resource_access(ep, access, "device_WRONG")
    assert_ok(
        "binding check",
        code2 in (401, 403),
        details=f"code={code2} body={text2[:250]}",
    )

    print("\n=== 6. refresh ===")
    newtok = auth_refresh(ep, refresh)
    new_access = newtok["access_token"]
    warn("access token rotated", new_access != access)

    print("\n=== ok ===")


if __name__ == "__main__":
    main()
