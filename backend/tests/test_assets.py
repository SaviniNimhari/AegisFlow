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
    # Register user via API
    res = client.post("/api/v1/auth/register", json=user_in.model_dump())
    assert res.status_code == 201
    user_id = res.json()["id"]

    token = create_access_token(subject=user_id, role=role.value)
    return {"Authorization": f"Bearer {token}"}


def test_create_asset_as_analyst(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_assets")

    asset_payload = {
        "name": "core-db-cluster-01",
        "hostname": "db01.prod.aegis.corp",
        "ip_address": "10.0.1.50",
        "mac_address": "00:1A:2B:3C:4D:5E",
        "asset_type": "server",
        "criticality": "critical",
        "status": "active",
        "environment": "production",
        "os_family": "Linux",
        "os_version": "Ubuntu 24.04 LTS",
        "open_ports": [
            {"port": 5432, "service": "postgresql", "protocol": "tcp", "state": "open"},
            {"port": 22, "service": "ssh", "protocol": "tcp", "state": "open"},
        ],
        "tags": ["database", "pci-dss", "core-infrastructure"],
        "description": "Primary PostgreSQL production cluster",
        "owner": "Data Platform Team",
    }

    res = client.post("/api/v1/assets", json=asset_payload, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "core-db-cluster-01"
    assert data["ip_address"] == "10.0.1.50"
    assert data["criticality"] == "critical"
    assert len(data["open_ports"]) == 2
    assert "id" in data


def test_create_asset_duplicate_ip(client: TestClient):
    headers = get_auth_headers(client, UserRole.ANALYST, "analyst_dup")

    payload1 = {
        "name": "web-gateway-01",
        "ip_address": "192.168.1.10",
        "asset_type": "server",
    }
    res1 = client.post("/api/v1/assets", json=payload1, headers=headers)
    assert res1.status_code == 201

    payload2 = {
        "name": "web-gateway-02",
        "ip_address": "192.168.1.10",
        "asset_type": "server",
    }
    res2 = client.post("/api/v1/assets", json=payload2, headers=headers)
    assert res2.status_code == 400
    assert "already registered" in res2.json()["detail"]


def test_viewer_cannot_create_asset(client: TestClient):
    headers = get_auth_headers(client, UserRole.VIEWER, "viewer_assets")

    payload = {
        "name": "unauthorized-node",
        "ip_address": "10.10.10.10",
        "asset_type": "workstation",
    }
    res = client.post("/api/v1/assets", json=payload, headers=headers)
    assert res.status_code == 403


def test_list_and_search_assets(client: TestClient):
    analyst_headers = get_auth_headers(client, UserRole.ANALYST, "analyst_lister")
    viewer_headers = get_auth_headers(client, UserRole.VIEWER, "viewer_lister")

    # Seed 3 distinct assets
    client.post(
        "/api/v1/assets",
        json={
            "name": "edge-firewall-01",
            "ip_address": "10.0.0.1",
            "asset_type": "firewall",
            "criticality": "critical",
        },
        headers=analyst_headers,
    )
    client.post(
        "/api/v1/assets",
        json={
            "name": "analyst-workstation-99",
            "ip_address": "10.0.5.99",
            "asset_type": "workstation",
            "criticality": "low",
        },
        headers=analyst_headers,
    )
    client.post(
        "/api/v1/assets",
        json={
            "name": "k8s-worker-node",
            "ip_address": "10.0.2.15",
            "asset_type": "server",
            "criticality": "high",
        },
        headers=analyst_headers,
    )

    # Viewer lists all assets
    res = client.get("/api/v1/assets", headers=viewer_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 3
    assert len(data["items"]) >= 3

    # Search by keyword
    search_res = client.get("/api/v1/assets?search=firewall", headers=viewer_headers)
    assert search_res.status_code == 200
    search_data = search_res.json()
    assert search_data["total"] == 1
    assert search_data["items"][0]["name"] == "edge-firewall-01"

    # Filter by asset_type
    type_res = client.get("/api/v1/assets?asset_type=workstation", headers=viewer_headers)
    assert type_res.status_code == 200
    type_data = type_res.json()
    assert all(item["asset_type"] == "workstation" for item in type_data["items"])


def test_update_asset(client: TestClient):
    analyst_headers = get_auth_headers(client, UserRole.ANALYST, "analyst_updater")
    viewer_headers = get_auth_headers(client, UserRole.VIEWER, "viewer_updater")

    # Create asset
    create_res = client.post(
        "/api/v1/assets",
        json={"name": "stage-api-server", "ip_address": "10.0.3.10", "status": "active", "criticality": "medium"},
        headers=analyst_headers,
    )
    asset_id = create_res.json()["id"]

    # Viewer cannot update
    fail_res = client.put(
        f"/api/v1/assets/{asset_id}",
        json={"criticality": "high"},
        headers=viewer_headers,
    )
    assert fail_res.status_code == 403

    # Analyst can update
    success_res = client.put(
        f"/api/v1/assets/{asset_id}",
        json={"criticality": "high", "status": "maintenance"},
        headers=analyst_headers,
    )
    assert success_res.status_code == 200
    updated_data = success_res.json()
    assert updated_data["criticality"] == "high"
    assert updated_data["status"] == "maintenance"


def test_delete_asset_rbac(client: TestClient):
    admin_headers = get_auth_headers(client, UserRole.ADMIN, "admin_deleter")
    analyst_headers = get_auth_headers(client, UserRole.ANALYST, "analyst_deleter")

    # Create asset
    create_res = client.post(
        "/api/v1/assets",
        json={"name": "test-decommission-node", "ip_address": "10.0.9.99"},
        headers=analyst_headers,
    )
    asset_id = create_res.json()["id"]

    # Analyst cannot delete (Admin only)
    analyst_del = client.delete(f"/api/v1/assets/{asset_id}", headers=analyst_headers)
    assert analyst_del.status_code == 403

    # Admin deletes successfully
    admin_del = client.delete(f"/api/v1/assets/{asset_id}", headers=admin_headers)
    assert admin_del.status_code == 204

    # Verification: should now return 404
    get_res = client.get(f"/api/v1/assets/{asset_id}", headers=admin_headers)
    assert get_res.status_code == 404


def test_asset_stats(client: TestClient):
    analyst_headers = get_auth_headers(client, UserRole.ANALYST, "analyst_stats")

    # Seed assets
    client.post(
        "/api/v1/assets",
        json={"name": "stats-node-01", "ip_address": "172.16.0.1", "asset_type": "firewall", "criticality": "critical"},
        headers=analyst_headers,
    )
    client.post(
        "/api/v1/assets",
        json={"name": "stats-node-02", "ip_address": "172.16.0.2", "asset_type": "server", "criticality": "high"},
        headers=analyst_headers,
    )

    stats_res = client.get("/api/v1/assets/stats", headers=analyst_headers)
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_assets"] >= 2
    assert stats["active_assets"] >= 2
    assert stats["critical_assets"] >= 1
    assert "firewall" in stats["by_type"]
    assert "server" in stats["by_type"]
