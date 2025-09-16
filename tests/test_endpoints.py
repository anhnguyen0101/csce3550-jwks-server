import time
import jwt
import httpx
from fastapi.testclient import TestClient

from app.main import app, store

client = TestClient(app)


def test_jwks_serves_only_unexpired():
    data = client.get("/jwks").json()
    kids = [k["kid"] for k in data["keys"]]
    assert store.current.kid in kids
    assert store.expired.kid not in kids


def test_auth_returns_valid_jwt_with_kid():
    resp = client.post("/auth")
    assert resp.status_code == 200
    token = resp.json()["token"]

    unverified = jwt.get_unverified_header(token)
    assert unverified.get("kid") == store.current.kid

    # Verify with current public key
    payload = jwt.decode(
        token,
        store.current.public_pem,
        algorithms=["RS256"],
        options={"verify_aud": False},
    )
    assert payload["sub"] == "fake-user-123"


def test_auth_expired_param_uses_expired_key_and_past_exp():
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    token = resp.json()["token"]

    # Header should reference the expired key
    unverified = jwt.get_unverified_header(token)
    assert unverified.get("kid") == store.expired.kid

    # Decoding with expired validation should raise
    try:
        jwt.decode(
            token,
            store.expired.public_pem,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
        assert False, "Token should be expired"
    except jwt.ExpiredSignatureError:
        pass
