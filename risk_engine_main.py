from __future__ import annotations

import math
import time
from typing import Optional

import jwt
import torch
import torch.nn.functional as F
from fastapi import FastAPI
from pydantic import BaseModel

from data.csic_actions import make_action_token
from lstm_model import LSTM
from service_config import (
    RISK_ALG,
    RISK_CHECKPOINT_PATH,
    RISK_HISTORY_LEN,
    RISK_ISS,
    RISK_SECRET,
    RISK_SESSION_BUFFER,
)

app = FastAPI(title="Risk service")


class RiskInput(BaseModel):
    user_id: str
    path: str
    method: str
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: Optional[float] = None


class RiskResponse(BaseModel):
    src: str


class RiskEngine:
    def __init__(self, checkpoint_path: str) -> None:
        checkpoint = torch.load(checkpoint_path, map_location="cpu")
        self.action_to_id = checkpoint["action_to_id"]
        self.model = LSTM(len(self.action_to_id))
        self.model.load_state_dict(checkpoint["model_state"])
        self.model.eval()
        self.session_actions: dict[str, list[str]] = {}

    def _behavior_risk(self, history: list[str], action: str) -> float:
        if len(history) < RISK_HISTORY_LEN:
            return 0.0

        try:
            sequence = [self.action_to_id[token] for token in history[-RISK_HISTORY_LEN:]]
            target_id = self.action_to_id[action]
        except KeyError:
            return 2.0

        x = torch.tensor([sequence], dtype=torch.long)
        with torch.no_grad():
            logits = self.model(x)
            probs = F.softmax(logits, dim=1)

        probability = probs[0, target_id].item()
        return -math.log(probability + 1e-9)

    @staticmethod
    def _heuristic_risk(action: str, timestamp: float) -> float:
        risk = 0.0

        hour = time.localtime(timestamp).tm_hour
        if hour < 6 or hour > 22:
            risk += 0.2

        if action.endswith(("PAY", "DELETE", "ADMIN", "CONFIG")):
            risk += 0.3

        return risk

    def evaluate(self, event: RiskInput) -> float:
        action = make_action_token(event.method, event.path)
        timestamp = event.timestamp or time.time()

        history = self.session_actions.setdefault(event.user_id, [])
        history.append(action)
        # Only keep a short tail for the current session.
        if len(history) > RISK_SESSION_BUFFER:
            history[:] = history[-RISK_SESSION_BUFFER:]

        behavior_risk = self._behavior_risk(history, action)
        heuristic_risk = self._heuristic_risk(action, timestamp)
        combined_risk = 0.7 * behavior_risk + 0.3 * heuristic_risk

        rho = math.exp(-combined_risk)
        return max(0.0, min(1.0, rho))


risk_engine = RiskEngine(RISK_CHECKPOINT_PATH)


@app.post("/risk/evaluate", response_model=RiskResponse)
async def evaluate_risk(data: RiskInput) -> RiskResponse:
    rho = risk_engine.evaluate(data)
    payload = {
        "iss": RISK_ISS,
        "sub": data.user_id,
        "rho": rho,
        "ts": time.time(),
        "path": data.path,
        "method": data.method,
    }
    src_token = jwt.encode(payload, RISK_SECRET, algorithm=RISK_ALG)
    return RiskResponse(src=src_token)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
