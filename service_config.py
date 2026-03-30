AUTH_SECRET = "change_this_auth_secret"
AUTH_ISS = "auth-service"
AUTH_ALG = "HS256"

RISK_SECRET = "change_this_risk_secret"
RISK_ISS = "risk-engine"
RISK_ALG = "HS256"

ACCESS_TTL = 60 * 5
REFRESH_TTL = 60 * 30
SRC_TTL = 60

RHO_MIN = 0.7

RISK_ENGINE_URL = "http://localhost:8002/risk/evaluate"
RISK_CHECKPOINT_PATH = "data/lstm_risk_model.pt"
RISK_HISTORY_LEN = 3
RISK_SESSION_BUFFER = 10
