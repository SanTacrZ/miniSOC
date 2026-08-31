"""Pytest bootstrap.

El repositorio no usa packaging (ni pyproject/setup.cfg), asi que pytest no
pone la raiz en sys.path: con importmode=prepend solo inserta el directorio del
test (api/tests), y por eso `from api.app...` falla con ModuleNotFoundError.

Este conftest vive en la raiz, asi que pytest inserta la raiz automaticamente;
dejamos el insert explicito para que tambien funcione invocando pytest desde
otro directorio o con --import-mode=importlib.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for p in (ROOT, ROOT / "api"):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)
