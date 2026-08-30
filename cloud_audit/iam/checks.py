"""IAM checks — AC-2, AC-3, AC-6, IA-2(1)"""
from __future__ import annotations
import json, pathlib, time

def check_iam_wildcard(policies: list[dict]) -> dict:
    fails=[]
    for p in policies:
        for stmt in p.get("Statement", []):
            if stmt.get("Effect")=="Allow" and stmt.get("Action")=="*" and stmt.get("Resource")=="*":
                fails.append(p.get("PolicyName","unknown"))
    return {"id":"IAM-001","status":"FAIL" if fails else "PASS","severity":"critical","resources":fails, "title":"No wildcard Action:*"}

def check_inactive_users(users: list[dict]) -> dict:
    now=time.time()
    fails=[u["username"] for u in users if u.get("last_login") and now - u["last_login"] > 45*86400]
    # also users never logged but created >45d
    fails+=[u["username"] for u in users if not u.get("last_login") and now - u.get("created_at",now) > 45*86400]
    return {"id":"IAM-002","status":"FAIL" if fails else "PASS","severity":"medium","resources":fails, "title":"Inactive >45d"}

def check_mfa(users: list[dict]) -> dict:
    fails=[u["username"] for u in users if u.get("role") in ("admin","analyst","responder") and not u.get("mfa_enabled")]
    return {"id":"IAM-003","status":"FAIL" if fails else "PASS","severity":"high","resources":fails, "title":"MFA required for privileged"}

def run_all(users_path: pathlib.Path | None = None):
    if users_path is None:
        # try multiple locations
        for p in [pathlib.Path("infra/users.json"), pathlib.Path("api/infra/users.json"), pathlib.Path(__file__).parent.parent.parent / "infra" / "users.json"]:
            if p.exists():
                users_path=p; break
    users=[]
    if users_path and users_path.exists():
        try:
            data=json.loads(users_path.read_text())
            users=list(data.values()) if isinstance(data, dict) else data
        except: pass
    # if empty, simulate policies from terraform
    policies=[]
    tf_path = pathlib.Path(__file__).parent.parent.parent / "infra" / "terraform"
    if tf_path.exists():
        for tf in tf_path.glob("*.tf"):
            txt=tf.read_text()
            if 'Action = "*"' in txt or 'action = "*"' in txt:
                policies.append({"PolicyName": tf.name, "Statement": [{"Effect":"Allow","Action":"*","Resource":"*"}]})
    return [
        check_iam_wildcard(policies),
        check_inactive_users(users),
        check_mfa(users),
    ]
if __name__=="__main__":
    import json; print(json.dumps(run_all(), indent=2))
