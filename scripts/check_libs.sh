#!/bin/bash
set -e
source "$(dirname "$0")/../.venv/bin/activate"
echo "[*] pip check"
pip check
echo "[*] imports"
python -c "import fastapi, pydantic, jose, pyotp, cryptography, argon2, yaml; print('OK all libs')"
echo "[*] crypto test"
python -c "from cryptography.hazmat.primitives.asymmetric import rsa; k=rsa.generate_private_key(65537,2048); print('rsa OK')"
echo "[*] argon2 test"
python -c "from argon2 import PasswordHasher; ph=PasswordHasher(); h=ph.hash('test'); assert ph.verify(h,'test'); print('argon2 OK')"
echo "[✓] Librerías verificadas sin corrupción"
