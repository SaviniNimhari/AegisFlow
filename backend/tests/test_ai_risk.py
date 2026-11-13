from fastapi.testclient import TestClient

from backend.app.core.security import create_access_token
from backend.app.models.user import UserRole
from backend.app.schemas.user import UserCreate


def get_auth_headers(client: TestClient, role: UserRole, username: str) -> dict[str, str]:
    user_in = UserCreate(
        email=f"{username}@example.com",
        username=username,
        full_name=f"{username.capitalize()} User",
        password="ValidStrongPassword123!",
        role=role,
    )
    res = client.post("/api/v1/auth/register", json=user_in.model_dump())
    assert res.status_code == 201
    user_id = res.json()["id"]

    token = create_access_token(subject=user_id, role=role.value)
    return {"Authorization": f"Bearer {token}"}


def test_benign_telemetry_prediction(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_ai_benign")

    payload = {
        "event_type": "auth_success",
        "source": "internal_sso",
        "source_ip": "192.168.1.45",
        "destination_port": 443,
        "username": "sarah.connor",
        "raw_log": "SSO-AUTH-OK: standard corporate web portal login",
        "details": {"failed_login_ratio": 0.0, "frequency_zscore": 0.1},
    }

    res = client.post("/api/v1/ai-risk/analyze", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()

    assert data["risk_score"] < 0.40
    assert data["risk_level"] in ("low", "benign")
    assert "attributions" in data
    assert len(data["attributions"]) > 0
    assert data["model_name"] == "AegisFlow-Ensemble-v1"


def test_malicious_ioc_prediction(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_ai_ioc")

    payload = {
        "event_type": "malware_indicator",
        "source": "edr_endpoint",
        "source_ip": "10.0.10.15",
        "username": "developer",
        "raw_log": "EDR: Process spawn with known malware hash signature",
        "details": {
            "file_hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR
            "command": "trojan.exe -exec",
        },
    }

    res = client.post("/api/v1/ai-risk/analyze", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()

    assert data["risk_score"] >= 0.85
    assert data["risk_level"] == "critical"
    assert data["threat_category"] == "command_control"

    # Verify SHAP / feature attribution contains ioc_signature_match
    attr_names = [a["feature_name"] for a in data["attributions"]]
    assert "ioc_signature_match" in attr_names
    ioc_attr = next(a for a in data["attributions"] if a["feature_name"] == "ioc_signature_match")
    assert ioc_attr["impact_direction"] == "increases_risk"


def test_brute_force_threat_prediction(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_ai_brute")

    payload = {
        "event_type": "auth_failure",
        "source": "edge_router",
        "source_ip": "198.51.100.88",  # Public external IP
        "destination_port": 22,  # Sensitive SSH port
        "username": "root",
        "raw_log": "Failed password for root from 198.51.100.88 port 51234 ssh2",
        "details": {"frequency_zscore": 3.2},
    }

    res = client.post("/api/v1/ai-risk/analyze", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()

    assert data["risk_score"] >= 0.70
    assert data["risk_level"] in ("high", "critical")
    assert data["threat_category"] == "credential_access"


def test_privilege_escalation_ai_prediction(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_ai_priv")

    payload = {
        "event_type": "privilege_escalation",
        "source": "auditd",
        "source_ip": "10.0.1.20",
        "username": "guest_app",
        "raw_log": "audit: USER_CMD sudo su root [res=success]",
        "details": {"command": "sudo -i", "frequency_zscore": 1.5},
    }

    res = client.post("/api/v1/ai-risk/analyze", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()

    assert data["risk_score"] >= 0.70
    assert data["threat_category"] == "privilege_abuse"


def test_analyst_feedback_workflow(client: TestClient):
    analyst_headers = get_auth_headers(client, UserRole.ANALYST, "analyst_feedback")

    # 1. Create a prediction
    res = client.post(
        "/api/v1/ai-risk/analyze",
        json={
            "event_type": "auth_failure",
            "source": "sshd",
            "source_ip": "203.0.113.1",
            "username": "test_user",
        },
        headers=analyst_headers,
    )
    assert res.status_code == 201
    pred_id = res.json()["id"]

    # 2. Update feedback to true_positive
    feedback_payload = {
        "analyst_feedback": "true_positive",
        "analyst_notes": "Confirmed malicious brute force attempts from cloud proxy.",
    }
    patch_res = client.patch(
        f"/api/v1/ai-risk/predictions/{pred_id}/feedback",
        json=feedback_payload,
        headers=analyst_headers,
    )
    assert patch_res.status_code == 200
    updated_data = patch_res.json()
    assert updated_data["analyst_feedback"] == "true_positive"
    assert "Confirmed malicious" in updated_data["analyst_notes"]


def test_viewer_rbac_restrictions(client: TestClient):
    viewer_headers = get_auth_headers(client, UserRole.VIEWER, "viewer_ai")

    # Viewer cannot trigger analyze or feedback
    res = client.post(
        "/api/v1/ai-risk/analyze",
        json={"event_type": "auth_failure", "source": "test"},
        headers=viewer_headers,
    )
    assert res.status_code == 403

    # Viewer CAN view summary and model metadata
    summary_res = client.get("/api/v1/ai-risk/summary", headers=viewer_headers)
    assert summary_res.status_code == 200

    meta_res = client.get("/api/v1/ai-risk/model-metadata", headers=viewer_headers)
    assert meta_res.status_code == 200
    assert meta_res.json()["accuracy"] > 0.90
