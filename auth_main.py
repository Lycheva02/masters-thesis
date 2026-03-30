from __future__ import annotations

import time
from typing import Dict, Optional

import httpx
import jwt
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from service_config import (
    ACCESS_TTL,
    AUTH_ALG,
    AUTH_ISS,
    AUTH_SECRET,
    REFRESH_TTL,
    RISK_ENGINE_URL,
)
from service_security import hash_client_binding

app = FastAPI(title="Auth service")

refresh_store: Dict[str, dict] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RiskInput(BaseModel):
    user_id: str
    path: str
    method: str
    ip: str
    user_agent: str
    timestamp: float


async def get_pop_key(x_pop_key: Optional[str] = Header(None)) -> str:
    if not x_pop_key:
        raise HTTPException(status_code=400, detail="X-POP-KEY header is required")
    return x_pop_key


async def get_client_id(x_client_id: Optional[str] = Header(None)) -> str:
    if not x_client_id:
        raise HTTPException(status_code=400, detail="X-CLIENT-ID header is required")
    return x_client_id


async def call_risk_engine(user_id: str) -> str:
    payload = RiskInput(
        user_id=user_id,
        path="/auth/token",
        method="POST",
        ip="127.0.0.1",
        user_agent="auth-service",
        timestamp=time.time(),
    )
    async with httpx.AsyncClient() as client:
        response = await client.post(RISK_ENGINE_URL, json=payload.model_dump())
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Risk service is unavailable")
    return response.json()["src"]


async def issue_tokens(username: str, pop_key: str, client_id: str) -> TokenResponse:
    now = int(time.time())
    bound = hash_client_binding(pop_key, client_id)
    src = await call_risk_engine(user_id=username)

    access_payload = {
        "iss": AUTH_ISS,
        "sub": username,
        "iat": now,
        "exp": now + ACCESS_TTL,
        "typ": "access",
        "bound": bound,
        "src": src,
    }
    access_token = jwt.encode(access_payload, AUTH_SECRET, algorithm=AUTH_ALG)

    refresh_id = f"{username}:{now}:{bound}"
    refresh_payload = {
        "iss": AUTH_ISS,
        "sub": username,
        "iat": now,
        "exp": now + REFRESH_TTL,
        "typ": "refresh",
        "jti": refresh_id,
    }
    refresh_token = jwt.encode(refresh_payload, AUTH_SECRET, algorithm=AUTH_ALG)

    refresh_store[refresh_id] = {
        "sub": username,
        "exp": now + REFRESH_TTL,
        "bound": bound,
        "used": False,
    }

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TTL,
    )


@app.post("/auth/token", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    pop_key: str = Depends(get_pop_key),
    client_id: str = Depends(get_client_id),
) -> TokenResponse:
    if body.username != "alice" or body.password != "wonderland":
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return await issue_tokens(body.username, pop_key, client_id)


@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    pop_key: str = Depends(get_pop_key),
    client_id: str = Depends(get_client_id),
) -> TokenResponse:
    try:
        payload = jwt.decode(body.refresh_token, AUTH_SECRET, algorithms=[AUTH_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Refresh token is invalid")

    if payload.get("typ") != "refresh":
        raise HTTPException(status_code=400, detail="Token type is not refresh")

    jti = payload.get("jti")
    record = refresh_store.get(jti)
    if not record:
        raise HTTPException(status_code=401, detail="Refresh token was not found")

    now = int(time.time())
    if record["exp"] < now:
        del refresh_store[jti]
        raise HTTPException(status_code=401, detail="Refresh token has expired")

    bound = hash_client_binding(pop_key, client_id)
    if record["bound"] != bound:
        del refresh_store[jti]
        raise HTTPException(status_code=401, detail="Client binding mismatch")

    if record["used"]:
        del refresh_store[jti]
        raise HTTPException(status_code=401, detail="Refresh token was already used")

    record["used"] = True
    return await issue_tokens(record["sub"], pop_key, client_id)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
