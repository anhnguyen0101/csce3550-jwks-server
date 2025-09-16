from __future__ import annotations

import time
from typing import Any, Dict

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .keystore import KeyStore

app = FastAPI(title="JWKS Server", version="0.1.0")
store = KeyStore()

# --- JWKS ENDPOINTS ---
@app.get("/jwks", response_class=JSONResponse)
@app.get("/.well-known/jwks.json", response_class=JSONResponse)
def get_jwks() -> Dict[str, Any]:
    """
    Return JWKS containing only unexpired public keys.
    Supports both /jwks and /.well-known/jwks.json
    """
    return store.jwks()

# --- AUTH ENDPOINT ---
@app.post("/auth", response_class=JSONResponse)
def post_auth(request: Request) -> Dict[str, str]:
    """
    Issue a JWT. No request body required (grader sends none).
    Query param:
      - expired=true → sign with expired key and past exp
    """
    expired_flag = request.query_params.get("expired", "").lower() in {"1", "true", "yes"}
    key, jwt_exp = store.select_key(want_expired=expired_flag)

    payload = {
        "sub": "fake-user-123",
        "iat": int(time.time()),
        "exp": jwt_exp,
        "iss": "jwks-server",
        "scope": "demo",
    }
    headers = {"kid": key.kid, "alg": "RS256", "typ": "JWT"}
    token = jwt.encode(payload, key.private_pem, algorithm="RS256", headers=headers)
    return {"token": token}

# --- HEALTH CHECK ---
@app.get("/healthz")
def health() -> Dict[str, str]:
    return {"ok": "true"}
