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


def test_posture_overview_calculation(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_rep1")

    # Create an asset
    asset_payload = {
        "name": "Corporate Domain Controller",
        "ip_address": "10.0.0.1",
        "asset_type": "server",
        "criticality": "critical",
        "environment": "production",
    }
    res_asset = client.post("/api/v1/assets", json=asset_payload, headers=headers)
    assert res_asset.status_code == 201

    # Check posture overview
    res = client.get("/api/v1/reports/posture", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert "posture_score" in data
    assert 0.0 <= data["posture_score"] <= 100.0
    assert data["posture_grade"] in ["A", "B", "C", "D", "F"]
    assert data["total_assets"] >= 1
    assert "compliance_scores" in data
    assert "NIST CSF" in data["compliance_scores"]


def test_generate_executive_report(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_rep2")

    payload = {
        "title": "Q4 Executive Cybersecurity Readiness Report",
        "time_window_days": 90,
        "include_compliance_summary": True,
        "include_ai_intelligence": True,
    }
    res = client.post("/api/v1/reports/executive", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()

    assert data["report_type"] == "executive_posture"
    assert data["title"] == payload["title"]
    assert data["posture_score"] is not None
    assert "executive_summary" in data["content"]
    assert "rendered_html" in data
    assert "<html" in data["rendered_html"]
    assert "## Executive Summary" in data["rendered_markdown"]


def test_generate_incident_postmortem(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_rep3")

    # 1. Create an incident
    inc_payload = {
        "title": "Active Data Exfiltration via Encrypted DNS Tunnel",
        "description": "High volumes of anomalous TXT records observed outbound to external command node.",
        "severity": "critical",
        "category": "data_exfiltration",
    }
    res_inc = client.post("/api/v1/incidents", json=inc_payload, headers=headers)
    assert res_inc.status_code == 201
    inc_id = res_inc.json()["id"]

    # 2. Generate postmortem report
    pm_payload = {
        "incident_id": inc_id,
        "include_timeline": True,
        "include_forensics": True,
        "executive_summary": "DNS tunnel confirmed and suppressed. Zero sensitive records leaked.",
        "root_cause_analysis": "Outbound DNS traffic allowed without domain categorization inspection.",
        "corrective_actions": [
            "Enforce DNS sinkholing on recursive resolvers.",
            "Deploy endpoint behavioral agent to block anomalous tunneling processes.",
        ],
    }
    res_pm = client.post("/api/v1/reports/incident", json=pm_payload, headers=headers)
    assert res_pm.status_code == 201
    pm_data = res_pm.json()

    assert pm_data["report_type"] == "incident_postmortem"
    assert pm_data["incident_id"] == inc_id
    assert "DNS tunnel confirmed" in pm_data["summary"]
    assert len(pm_data["content"]["corrective_actions"]) == 2


def test_export_report_formats(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_rep4")

    # Create a report
    res_gen = client.post("/api/v1/reports/executive", json={}, headers=headers)
    assert res_gen.status_code == 201
    rep_id = res_gen.json()["id"]

    # Export HTML
    res_html = client.get(f"/api/v1/reports/{rep_id}/export?export_format=html", headers=headers)
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers["content-type"]
    assert "<html" in res_html.text

    # Export Markdown
    res_md = client.get(f"/api/v1/reports/{rep_id}/export?export_format=markdown", headers=headers)
    assert res_md.status_code == 200
    assert "text/markdown" in res_md.headers["content-type"]
    assert "# " in res_md.text

    # Export JSON
    res_json = client.get(f"/api/v1/reports/{rep_id}/export?export_format=json", headers=headers)
    assert res_json.status_code == 200
    assert "application/json" in res_json.headers["content-type"]


def test_report_rbac_enforcement(client: TestClient):
    analyst_headers = get_auth_headers(client, UserRole.ANALYST, "analyst_rep5")
    viewer_headers = get_auth_headers(client, UserRole.VIEWER, "viewer_rep5")

    # Analyst can create report
    res_create = client.post("/api/v1/reports/executive", json={}, headers=analyst_headers)
    assert res_create.status_code == 201
    rep_id = res_create.json()["id"]

    # Viewer CANNOT create report (403 Forbidden)
    res_denied = client.post("/api/v1/reports/executive", json={}, headers=viewer_headers)
    assert res_denied.status_code == 403

    # Viewer CAN view list and retrieve report
    res_list = client.get("/api/v1/reports/", headers=viewer_headers)
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1

    res_get = client.get(f"/api/v1/reports/{rep_id}", headers=viewer_headers)
    assert res_get.status_code == 200
    assert res_get.json()["id"] == rep_id
