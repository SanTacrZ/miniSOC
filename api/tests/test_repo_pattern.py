from api.app.repositories.user_repository import FileUserRepository
from api.app.repositories.record_repository import InMemoryRecordRepository
from api.app.repositories.audit_repository import FileAuditRepository
from api.app.services.auth_service import AuthService
from api.app.services.record_service import RecordService
import tempfile, pathlib

def test_user_repo():
    with tempfile.TemporaryDirectory() as tmp:
        repo = FileUserRepository(pathlib.Path(tmp)/"users.json")
        repo.create("alice", "hash123", "analyst")
        assert repo.exists("alice")
        assert repo.get_by_username("alice")["role"]=="analyst"
        repo.update("alice", mfa_enabled=True)
        assert repo.get_by_username("alice")["mfa_enabled"]==True

def test_record_repo():
    repo = InMemoryRecordRepository()
    r = repo.create("test", 123, "note", "alice")
    assert r["id"]==1
    assert repo.get(1)["title"]=="test"
    assert len(repo.list())==1
    assert len(repo.list("alice"))==1
    assert len(repo.list("bob"))==0

def test_auth_service_isolation():
    with tempfile.TemporaryDirectory() as tmp:
        urepo = FileUserRepository(pathlib.Path(tmp)/"users.json")
        arepo = FileAuditRepository([pathlib.Path(tmp)/"audit.jsonl"])
        from api.app.auth.passwords import hash_password
        urepo.create("bob", hash_password("StrongPass!123"), "viewer")
        svc = AuthService(urepo, arepo)
        res = svc.authenticate("bob", "StrongPass!123", "1.2.3.4", "test-agent")
        assert "access_token" in res
        assert not res["mfa_required"]
