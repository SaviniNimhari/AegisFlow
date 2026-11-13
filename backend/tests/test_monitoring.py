from fastapi.testclient import TestClient

from backend.app.core.security import create_access_token
from backend.app.models.user import UserRole
from backend.app.schemas.user import UserCreate


def get_auth_headers(client: TestClient, role: UserRole, username: str) -> dict[str, str]:
    """Helper to register and generate a Bearer authorization header."""
    user_in = UserCreate(
        email=f"{username}@aegisflow.io",
        username=username,
        password="SecureTestPassword123!",
        role=role,
    )
    res = client.post("/api/v1/auth/register", json=user_in.model_dump())
    assert res.status_code == 201
    user_id = res.json()["id"]

    token = create_access_token(subject=user_id, role=role.value)
    return {"Authorization": f"Bearer {token}"}


def test_event_ingestion(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_mon1")

    event_payload = {
        "event_type": "auth_success",
        "source": "linux_pam",
        "source_ip": "10.0.1.100",
        "username": "sysadmin",
        "raw_log": "pam_unix(sshd:session): session opened for user sysadmin",
    }
    res = client.post("/api/v1/monitoring/events", json=event_payload, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["events_ingested"] == 1
    assert data["alerts_triggered"] == 0


def test_brute_force_rule_detection(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_brute")

    # Ingest 4 failed attempts - should not trigger yet
    for i in range(4):
        res = client.post(
            "/api/v1/monitoring/events",
            json={
                "event_type": "auth_failure",
                "source": "ssh_gateway",
                "source_ip": "198.51.100.25",
                "username": "target_victim",
                "raw_log": f"Failed password for target_victim attempt {i+1}",
            },
            headers=headers,
        )
        assert res.status_code == 201
        assert res.json()["alerts_triggered"] == 0

    # 5th failed attempt must trigger the Brute Force detection rule!
    res5 = client.post(
        "/api/v1/monitoring/events",
        json={
            "event_type": "auth_failure",
            "source": "ssh_gateway",
            "source_ip": "198.51.100.25",
            "username": "target_victim",
            "raw_log": "Failed password for target_victim attempt 5",
        },
        headers=headers,
    )
    assert res5.status_code == 201
    data5 = res5.json()
    assert data5["alerts_triggered"] == 1
    alert = data5["alerts"][0]
    assert "Brute-Force" in alert["title"]
    assert alert["severity"] == "high"
    assert alert["mitre_attack_id"] == "T1110"
    assert alert["source_ip"] == "198.51.100.25"
    assert alert["target_user"] == "target_victim"


def test_malicious_file_hash_detection(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_hash")

    res = client.post(
        "/api/v1/monitoring/events",
        json={
            "event_type": "malware_indicator",
            "source": "edr_agent",
            "source_ip": "10.0.5.12",
            "username": "john_doe",
            "details": {
                "file_path": "/tmp/suspicious_payload.bin",
                "file_hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR SHA256
            },
        },
        headers=headers,
    )
    assert res.status_code == 201
    data = res.json()
    assert data["alerts_triggered"] == 1
    alert = data["alerts"][0]
    assert "Malicious File Hash" in alert["title"]
    assert alert["severity"] == "critical"
    assert alert["mitre_attack_id"] == "T1204"


def test_privilege_escalation_detection(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_priv")

    res = client.post(
        "/api/v1/monitoring/events",
        json={
            "event_type": "privilege_escalation",
            "source": "auditd",
            "source_ip": "10.0.2.14",
            "username": "guest_user",
            "raw_log": "sudo su root",
            "details": {"command": "sudo -i"},
        },
        headers=headers,
    )
    assert res.status_code == 201
    data = res.json()
    assert data["alerts_triggered"] == 1
    assert "Privilege Escalation" in data["alerts"][0]["title"]
    assert data["alerts"][0]["severity"] == "high"


def test_unauthorized_port_connection(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_port")

    res = client.post(
        "/api/v1/monitoring/events",
        json={
            "event_type": "network_connection",
            "source": "border_firewall",
            "source_ip": "203.0.113.88",
            "destination_ip": "10.0.1.15",
            "destination_port": 3389,  # RDP restricted port
            "raw_log": "Inbound connection allowed from external WAN to internal RDP",
        },
        headers=headers,
    )
    assert res.status_code == 201
    data = res.json()
    assert data["alerts_triggered"] == 1
    assert "Port 3389" in data["alerts"][0]["title"]


def test_alert_triage_lifecycle(client: TestClient):
    analyst_headers = get_auth_headers(client, UserRole.ANALYST, "analyst_triage")

    # Generate an alert
    ingest = client.post(
        "/api/v1/monitoring/events",
        json={
            "event_type": "malware_indicator",
            "source": "antivirus",
            "details": {"file_hash": "44d88612fea8a8f36de82e1278abb02f"},
        },
        headers=analyst_headers,
    ).json()
    assert ingest["alerts_triggered"] >= 1
    alert_id = ingest["alerts"][0]["id"]

    # 1. Update status to investigating
    patch1 = client.patch(
        f"/api/v1/monitoring/alerts/{alert_id}",
        json={"status": "investigating", "assigned_to": "bob_analyst"},
        headers=analyst_headers,
    )
    assert patch1.status_code == 200
    assert patch1.json()["status"] == "investigating"
    assert patch1.json()["assigned_to"] == "bob_analyst"
    assert patch1.json()["resolved_at"] is None

    # 2. Update status to resolved
    patch2 = client.patch(
        f"/api/v1/monitoring/alerts/{alert_id}",
        json={"status": "resolved", "resolution_notes": "Identified benign EICAR testing package. Cleared."},
        headers=analyst_headers,
    )
    assert patch2.status_code == 200
    assert patch2.json()["status"] == "resolved"
    assert patch2.json()["resolved_at"] is not None


def test_alert_statistics(client: TestClient):
    analyst_headers = get_auth_headers(client, UserRole.ANALYST, "analyst_stat_mon")

    res = client.get("/api/v1/monitoring/alerts/stats", headers=analyst_headers)
    assert res.status_code == 200
    stats = res.json()
    assert "total_alerts" in stats
    assert "open_alerts" in stats
    assert "critical_alerts" in stats
    assert "by_severity" in stats
    assert "by_status" in stats
