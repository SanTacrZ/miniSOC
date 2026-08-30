import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent / "api"))
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"]=="ok"

def test_login_fail():
    r = client.post("/auth/login", json={"username":"admin","password":"wrongpass123"})
    assert r.status_code in (401,423)

def test_login_success():
    r = client.post("/auth/login", json={"username":"admin","password":"Admin_Str0ng!_2026"})
    # may require MFA if enabled; for default admin mfa false -> should succeed
    assert r.status_code==200
    j = r.json()
    assert "access_token" in j

def test_rbac_viewer_cannot_admin():
    # login as viewer
    r = client.post("/auth/login", json={"username":"viewer","password":"Viewer_Str0ng!_2026"})
    token = r.json()["access_token"]
    r2 = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code==403

def test_validation_rejects_extra_field():
    r = client.post("/auth/login", json={"username":"admin","password":"Admin_Str0ng!_2026","extra":"hack"})
    assert r.status_code==422

def test_rate_limit():
    for i in range(7):
        client.post("/auth/login", json={"username":"viewer","password":"wrong"})
    r = client.post("/auth/login", json={"username":"viewer","password":"wrong"})
    assert r.status_code in (401,429,423)
