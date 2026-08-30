#!/bin/bash
set -e
source "$(dirname "$0")/../.venv/bin/activate"
echo "[*] Bootstrap IAM — seeding users + MFA"
python << 'PY'
from api.app.repositories.user_repository import get_user_repository
from api.app.auth.passwords import hash_password
import time

repo = get_user_repository()

def ensure(user, pwd, role):
    if repo.exists(user):
        print(f" [=] {user} exists")
        return
    repo.create(user, hash_password(pwd), role)
    print(f" [+] {user} ({role})")

ensure("admin", "Admin_Str0ng!_2026", "admin")
ensure("analyst", "Analyst_Str0ng!_2026", "analyst")
ensure("responder", "Responder_Str0ng!_2026", "responder")
ensure("viewer", "Viewer_Str0ng!_2026", "viewer")

# Show
for u in repo.list_all():
    print(f" - {u['username']:10} role={u['role']:10} mfa={u['mfa_enabled']} active={u['active']}")
PY
echo "[*] MFA setup for admin/analyst: curl POST /auth/mfa/setup with token"
