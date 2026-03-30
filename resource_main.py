from __future__ import annotations

import time
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from service_config import (
    AUTH_ALG,
    AUTH_ISS,
    AUTH_SECRET,
    RHO_MIN,
    RISK_ALG,
    RISK_ISS,
    RISK_SECRET,
    SRC_TTL,
)
from service_security import hash_client_binding

app = FastAPI(title="Resource service")


class ResourceResponse(BaseModel):
    message: str
    user: str
    rho: float


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


@app.get("/resource", response_model=ResourceResponse)
async def protected_resource(
    token: str = Depends(get_authorization),
    pop_key: str = Depends(get_pop_key),
    client_id: str = Depends(get_client_id),
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

    src_token = payload.get("src")
    if not src_token:
        raise HTTPException(status_code=401, detail="Risk token is missing")

    rho = verify_src(src_token, expected_user=user)
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
