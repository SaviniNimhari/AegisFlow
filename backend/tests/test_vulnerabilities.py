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


def test_create_vulnerability_as_analyst(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_vuln1")

    payload = {
        "cve_id": "CVE-2024-3094",
        "title": "XZ Utils Backdoor Remote Code Execution",
        "description": "Malicious code in upstream tarballs of xz-utils leading to SSH bypass.",
        "severity": "critical",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe_id": "CWE-506",
        "affected_component": "xz-utils",
        "affected_versions": "5.6.0, 5.6.1",
        "fixed_version": "5.6.2",
        "remediation_guidance": "Downgrade xz-utils to 5.4.x or upgrade to 5.6.2 immediately.",
        "is_exploited": True,
    }

    res = client.post("/api/v1/vulnerabilities", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["cve_id"] == "CVE-2024-3094"
    assert data["severity"] == "critical"
    assert data["cvss_score"] == 10.0
    assert data["is_exploited"] is True
    assert "id" in data


def test_duplicate_cve_rejection(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_vuln_dup")

    payload = {
        "cve_id": "CVE-2023-44487",
        "title": "HTTP/2 Rapid Reset Attack",
        "severity": "high",
        "affected_component": "nginx",
    }
    res1 = client.post("/api/v1/vulnerabilities", json=payload, headers=headers)
    assert res1.status_code == 201

    res2 = client.post("/api/v1/vulnerabilities", json=payload, headers=headers)
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"]


def test_viewer_cannot_ingest_cve(client: TestClient):
    headers = get_auth_headers(client, UserRole.VIEWER, "viewer_vuln")

    payload = {
        "cve_id": "CVE-2021-44228",
        "title": "Log4Shell Remote Code Execution",
        "severity": "critical",
        "affected_component": "log4j",
    }
    res = client.post("/api/v1/vulnerabilities", json=payload, headers=headers)
    assert res.status_code == 403


def test_list_and_search_vulnerabilities(client: TestClient):
    analyst_headers = get_auth_headers(client, UserRole.ANALYST, "analyst_list_vuln")
    viewer_headers = get_auth_headers(client, UserRole.VIEWER, "viewer_list_vuln")

    # Ingest CVEs
    client.post(
        "/api/v1/vulnerabilities",
        json={
            "cve_id": "CVE-2024-1111",
            "title": "OpenSSH Terrapin Prefix Truncation",
            "severity": "medium",
            "affected_component": "ssh",
        },
        headers=analyst_headers,
    )
    client.post(
        "/api/v1/vulnerabilities",
        json={
            "cve_id": "CVE-2024-2222",
            "title": "PostgreSQL Privilege Escalation",
            "severity": "high",
            "affected_component": "postgresql",
        },
        headers=analyst_headers,
    )

    # Viewer lists
    res = client.get("/api/v1/vulnerabilities", headers=viewer_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 2

    # Search keyword
    search_res = client.get("/api/v1/vulnerabilities?search=terrapin", headers=viewer_headers)
    assert search_res.status_code == 200
    assert search_res.json()["total"] == 1
    assert "OpenSSH" in search_res.json()["items"][0]["title"]


def test_scan_asset_detects_vulnerability(client: TestClient):
    analyst_headers = get_auth_headers(client, UserRole.ANALYST, "analyst_scanner")

    # 1. Register an asset with SSH and PostgreSQL open ports
    asset_res = client.post(
        "/api/v1/assets",
        json={
            "name": "vulnerable-app-server",
            "ip_address": "10.0.10.20",
            "asset_type": "server",
            "open_ports": [
                {"port": 22, "service": "ssh"},
                {"port": 5432, "service": "postgresql"},
            ],
            "os_family": "Linux",
        },
        headers=analyst_headers,
    )
    assert asset_res.status_code == 201
    asset_id = asset_res.json()["id"]

    # 2. Ingest matching CVE definitions for SSH and PostgreSQL
    client.post(
        "/api/v1/vulnerabilities",
        json={
            "cve_id": "CVE-2024-6387",
            "title": "regreSSHion: Remote Unauthenticated Code Execution in OpenSSH",
            "severity": "critical",
            "cvss_score": 8.1,
            "affected_component": "ssh",
        },
        headers=analyst_headers,
    )
    client.post(
        "/api/v1/vulnerabilities",
        json={
            "cve_id": "CVE-2024-7348",
            "title": "PostgreSQL SQL Injection in pg_dump",
            "severity": "high",
            "cvss_score": 7.5,
            "affected_component": "postgresql",
        },
        headers=analyst_headers,
    )

    # 3. Trigger vulnerability assessment scan
    scan_res = client.post(f"/api/v1/vulnerabilities/scan/{asset_id}", headers=analyst_headers)
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["asset_id"] == asset_id
    assert scan_data["matches_found"] >= 2
    assert any(f["vulnerability"]["affected_component"] == "ssh" for f in scan_data["findings"])


def test_remediation_lifecycle(client: TestClient):
    analyst_headers = get_auth_headers(client, UserRole.ANALYST, "analyst_remed")

    # Seed asset & vuln
    asset = client.post(
        "/api/v1/assets",
        json={"name": "test-remed-node", "ip_address": "10.0.88.88", "open_ports": [{"port": 80, "service": "http"}]},
        headers=analyst_headers,
    ).json()

    client.post(
        "/api/v1/vulnerabilities",
        json={"cve_id": "CVE-2024-9999", "title": "HTTP Desync", "severity": "high", "affected_component": "http"},
        headers=analyst_headers,
    )

    # Scan to produce finding
    scan = client.post(f"/api/v1/vulnerabilities/scan/{asset['id']}", headers=analyst_headers).json()
    assert scan["matches_found"] >= 1
    finding_id = scan["findings"][0]["id"]

    # 1. Update finding to in_progress
    up1 = client.patch(
        f"/api/v1/vulnerabilities/findings/{finding_id}",
        json={"status": "in_progress", "assigned_to": "alice_secops", "remediation_notes": "Patching nginx binary"},
        headers=analyst_headers,
    )
    assert up1.status_code == 200
    assert up1.json()["status"] == "in_progress"
    assert up1.json()["assigned_to"] == "alice_secops"
    assert up1.json()["resolved_at"] is None

    # 2. Update finding to resolved
    up2 = client.patch(
        f"/api/v1/vulnerabilities/findings/{finding_id}",
        json={"status": "resolved", "remediation_notes": "Verified patch v2.4 applied and port verified."},
        headers=analyst_headers,
    )
    assert up2.status_code == 200
    assert up2.json()["status"] == "resolved"
    assert up2.json()["resolved_at"] is not None


def test_vulnerability_statistics(client: TestClient):
    analyst_headers = get_auth_headers(client, UserRole.ANALYST, "analyst_stat_vuln")

    res = client.get("/api/v1/vulnerabilities/stats", headers=analyst_headers)
    assert res.status_code == 200
    stats = res.json()
    assert "total_cves" in stats
    assert "open_findings" in stats
    assert "critical_findings" in stats
    assert "by_severity" in stats
    assert "by_remediation_status" in stats
