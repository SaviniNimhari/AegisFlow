from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.core.security import (
    create_access_token,
    decode_access_token,
    get_password_hash,
    verify_password,
)
from backend.app.models.user import UserRole
from backend.app.schemas.user import UserCreate
from backend.app.services.auth_service import AuthService


def test_argon2_password_hashing():
    raw_password = "SuperSecretPassword123!"
    hashed = get_password_hash(raw_password)
    assert hashed != raw_password
    assert hashed.startswith("$argon2id$")
    assert verify_password(raw_password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_token_generation_and_decoding():
    token = create_access_token(subject="user-uuid-1234", role="admin")
    assert isinstance(token, str)
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "user-uuid-1234"
    assert payload["role"] == "admin"


def test_user_registration(client: TestClient):
    payload = {
        "email": "analyst@aegisflow.io",
        "username": "soc_analyst",
        "password": "StrongPassword2026!",
        "full_name": "SOC Analyst One",
        "role": "analyst"
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "analyst@aegisflow.io"
    assert data["username"] == "soc_analyst"
    assert data["role"] == "analyst"
    assert data["is_active"] is True
    assert "hashed_password" not in data


def test_user_registration_duplicate(client: TestClient):
    payload = {
        "email": "admin@aegisflow.io",
        "username": "sysadmin",
        "password": "StrongPassword2026!",
        "full_name": "System Administrator",
        "role": "admin"
    }
    res1 = client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    # Attempt duplicate email
    res2 = client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"]


def test_user_login_success(client: TestClient):
    # Register first
    client.post("/api/v1/auth/register", json={
        "email": "investigator@aegisflow.io",
        "username": "investigator",
        "password": "SecurePassword123!",
        "full_name": "Lead Investigator",
        "role": "analyst"
    })

    # Login with username
    login_res = client.post("/api/v1/auth/login", json={
        "username_or_email": "investigator",
        "password": "SecurePassword123!"
    })
    assert login_res.status_code == 200
    data = login_res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "investigator"

    # Login with email
    login_email_res = client.post("/api/v1/auth/login", json={
        "username_or_email": "investigator@aegisflow.io",
        "password": "SecurePassword123!"
    })
    assert login_email_res.status_code == 200


def test_user_login_invalid_password(client: TestClient):
    client.post("/api/v1/auth/register", json={
        "email": "testuser@aegisflow.io",
        "username": "testuser",
        "password": "CorrectPassword123!",
    })

    res = client.post("/api/v1/auth/login", json={
        "username_or_email": "testuser",
        "password": "WrongPassword999!"
    })
    assert res.status_code == 401


def test_get_current_user_profile(client: TestClient):
    reg = client.post("/api/v1/auth/register", json={
        "email": "me_test@aegisflow.io",
        "username": "me_user",
        "password": "ValidPassword123!",
        "role": "admin"
    })
    assert reg.status_code == 201

    login = client.post("/api/v1/auth/login", json={
        "username_or_email": "me_user",
        "password": "ValidPassword123!"
    })
    token = login.json()["access_token"]

    # Request /me with Bearer token
    me_res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me_res.status_code == 200
    user_data = me_res.json()
    assert user_data["username"] == "me_user"
    assert user_data["role"] == "admin"


def test_unauthorized_access(client: TestClient):
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401


def test_brute_force_account_lockout(db_session: Session):
    # Direct service test for security lockout rules
    user_in = UserCreate(
        email="target@aegisflow.io",
        username="target_user",
        password="ValidPassword123!",
        role=UserRole.VIEWER
    )
    AuthService.create_user(db_session, user_in)

    # Simulate 5 failed attempts
    for _ in range(5):
        u, err = AuthService.authenticate_user(db_session, "target_user", "IncorrectPassword")
        assert u is None

    # 6th attempt should return lockout message
    u, err = AuthService.authenticate_user(db_session, "target_user", "IncorrectPassword")
    assert u is None
    assert "temporarily locked" in err.lower()
