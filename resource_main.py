from __future__ import annotations

import time
from typing import Optional

import httpx
import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from service_config import (
    AUTH_ALG,
    AUTH_ISS,
    AUTH_SECRET,
    POP_NONCE_TTL,
    POP_PROOF_TTL,
    RHO_MIN,
    RISK_ALG,
    RISK_ISS,
    RISK_SECRET,
    RISK_ENGINE_URL,
    SRC_TTL,
)
from service_security import hash_client_binding, verify_pop_proof

app = FastAPI(title="Resource service")
used_nonces: dict[str, float] = {}


class ResourceResponse(BaseModel):
    message: str
    user: str
    rho: float


class RiskInput(BaseModel):
    user_id: str
    path: str
    method: str
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: Optional[float] = None


async def get_authorization(authorization: Optional[str] = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token is required")
    return authorization.split(" ", 1)[1]


async def get_pop_key(x_pop_key: Optional[str] = Header(None)) -> str:
    if not x_pop_key:
        raise HTTPException(status_code=400, detail="X-POP-KEY header is required")
    return x_pop_key


async def get_client_id(x_client_id: Optional[str] = Header(None)) -> str:
    if not x_client_id:
        raise HTTPException(status_code=400, detail="X-CLIENT-ID header is required")
    return x_client_id


async def get_pop_timestamp(x_pop_ts: Optional[str] = Header(None)) -> int:
    if not x_pop_ts:
        raise HTTPException(status_code=400, detail="X-POP-TS header is required")
    try:
        return int(x_pop_ts)
    except ValueError:
        raise HTTPException(status_code=400, detail="X-POP-TS header is invalid")


async def get_pop_nonce(x_pop_nonce: Optional[str] = Header(None)) -> str:
    if not x_pop_nonce:
        raise HTTPException(status_code=400, detail="X-POP-NONCE header is required")
    if len(x_pop_nonce) < 16 or len(x_pop_nonce) > 128:
        raise HTTPException(status_code=400, detail="X-POP-NONCE header has invalid length")
    return x_pop_nonce


async def get_pop_proof(x_pop_proof: Optional[str] = Header(None)) -> str:
    if not x_pop_proof:
        raise HTTPException(status_code=400, detail="X-POP-PROOF header is required")
    return x_pop_proof




def verify_src(src_token: str, expected_user: str) -> float:
    try:
        payload = jwt.decode(src_token, RISK_SECRET, algorithms=[RISK_ALG])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Risk token is invalid")

    if payload.get("iss") != RISK_ISS:
        raise HTTPException(status_code=401, detail="Risk token issuer mismatch")
    if payload.get("sub") != expected_user:
        raise HTTPException(status_code=401, detail="Risk token subject mismatch")

    ts = payload.get("ts")
    if ts is None or abs(time.time() - ts) > SRC_TTL:
        raise HTTPException(status_code=401, detail="Risk token is too old")

    rho = payload.get("rho")
    if rho is None:
        raise HTTPException(status_code=500, detail="Risk token has no rho")
    return float(rho)


def register_nonce(subject: str, nonce: str, now: float) -> None:
    expired = [key for key, exp in used_nonces.items() if exp <= now]
    for key in expired:
        del used_nonces[key]

    nonce_key = f"{subject}:{nonce}"
    if nonce_key in used_nonces:
        raise HTTPException(status_code=401, detail="PoP nonce was already used")

    used_nonces[nonce_key] = now + POP_NONCE_TTL


def verify_request_proof(
    *,
    request: Request,
    user: str,
    token: str,
    pop_key: str,
    client_id: str,
    pop_ts: int,
    pop_nonce: str,
    pop_proof: str,
) -> None:
    now = time.time()
    if abs(now - pop_ts) > POP_PROOF_TTL:
        raise HTTPException(status_code=401, detail="PoP proof is too old")

    if not verify_pop_proof(
        pop_proof,
        pop_key,
        method=request.method,
        path=request.url.path,
        client_id=client_id,
        timestamp=pop_ts,
        nonce=pop_nonce,
        token=token,
    ):
        raise HTTPException(status_code=401, detail="PoP proof is invalid")

    register_nonce(user, pop_nonce, now)


async def call_risk_engine(user_id: str, request: Request) -> float:
    payload = RiskInput(
        user_id=user_id,
        path=request.url.path,
        method=request.method,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        timestamp=time.time(),
    )
    async with httpx.AsyncClient() as client:
        response = await client.post(RISK_ENGINE_URL, json=payload.model_dump())

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Risk service is unavailable")

    src_token = response.json().get("src")
    if not src_token:
        raise HTTPException(status_code=500, detail="Risk service returned no risk token")

    return verify_src(src_token, expected_user=user_id)


@app.get("/resource", response_model=ResourceResponse)
async def protected_resource(
    request: Request,
    token: str = Depends(get_authorization),
    pop_key: str = Depends(get_pop_key),
    client_id: str = Depends(get_client_id),
    pop_ts: int = Depends(get_pop_timestamp),
    pop_nonce: str = Depends(get_pop_nonce),
    pop_proof: str = Depends(get_pop_proof),
) -> ResourceResponse:
    try:
        payload = jwt.decode(token, AUTH_SECRET, algorithms=[AUTH_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Access token is invalid")

    if payload.get("iss") != AUTH_ISS or payload.get("typ") != "access":
        raise HTTPException(status_code=401, detail="Wrong token issuer or type")

    user = payload.get("sub")
    if not user:
        raise HTTPException(status_code=401, detail="Token subject is missing")

    bound = payload.get("bound")
    if not bound:
        raise HTTPException(status_code=401, detail="Token binding is missing")

    expected_bound = hash_client_binding(pop_key, client_id)
    if expected_bound != bound:
        raise HTTPException(status_code=401, detail="Client binding mismatch")

    verify_request_proof(
        request=request,
        user=user,
        token=token,
        pop_key=pop_key,
        client_id=client_id,
        pop_ts=pop_ts,
        pop_nonce=pop_nonce,
        pop_proof=pop_proof,
    )
    
    rho = await call_risk_engine(user_id=user, request=request)
    if rho < RHO_MIN:
        raise HTTPException(status_code=403, detail=f"rho is below the threshold ({rho:.2f})")

    return ResourceResponse(
        message="Access granted",
        user=user,
        rho=rho,
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
