"""
Pydantic strict models — SI-10 Input Validation
OWASP ASVS 5.1, NIST SI-10
"""
from __future__ import annotations
import re
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional

# Strict: deny unknown fields
STRICT = ConfigDict(extra="forbid", str_strip_whitespace=True)

SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9_\- ]{1,64}$")
SAFE_NOTE_RE = re.compile(r"^[\w\s\-\.,;:!?@#\$%\^&\*\(\)\[\]\{\}\/\\]{0,4096}$")

class LoginRequest(BaseModel):
    model_config = STRICT
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_\-\.]{3,32}$")
    password: str = Field(..., min_length=8, max_length=128)

class MFAVerifyRequest(BaseModel):
    model_config = STRICT
    username: str = Field(..., min_length=3, max_length=32)
    code: str = Field(..., pattern=r"^\d{6}$")

classMFASetupResponse = None

class MFASetupResponse(BaseModel):
    model_config = STRICT
    otpauth_url: str
    secret: str
    backup_codes: list[str]

class TokenResponse(BaseModel):
    model_config = STRICT
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    mfa_required: bool = False

class RefreshRequest(BaseModel):
    model_config = STRICT
    refresh_token: str

class UserCreate(BaseModel):
    model_config = STRICT
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_\-\.]{3,32}$")
    password: str = Field(..., min_length=12, max_length=128)
    role: str = Field(..., pattern=r"^(viewer|analyst|responder|admin)$")

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str):
        if not re.search(r"[A-Z]", v): raise ValueError("Need uppercase")
        if not re.search(r"[a-z]", v): raise ValueError("Need lowercase")
        if not re.search(r"[0-9]", v): raise ValueError("Need digit")
        if not re.search(r"[^A-Za-z0-9]", v): raise ValueError("Need symbol")
        # simulate HIBP check: block common
        common = {"Password123!", "Admin12345!", "Letmein123!"}
        if v in common:
            raise ValueError("Password is too common")
        return v

class RecordCreate(BaseModel):
    model_config = STRICT
    title: str = Field(..., min_length=1, max_length=64)
    value: int = Field(..., ge=-1_000_000, le=1_000_000)
    note: Optional[str] = Field(None, max_length=4096)

    @field_validator("title")
    @classmethod
    def title_safe(cls, v: str):
        if not SAFE_NAME_RE.match(v):
            raise ValueError("title contains illegal chars")
        return v

    @field_validator("note")
    @classmethod
    def note_safe(cls, v: Optional[str]):
        if v is None:
            return v
        if len(v) > 4096:
            raise ValueError("note too long")
        # block obvious injection for SI-10 but allow hunting signals: we log but not block high-sev?
        # For API we block shell metachars in note? Relaxed for demo: allow but alert
        # If you want strict, uncomment:
        # if re.search(r"[;`$\\]", v):
        #     raise ValueError("note contains forbidden chars")
        return v

class RecordOut(BaseModel):
    model_config = STRICT
    id: int
    title: str
    value: int
    note: Optional[str]
    owner: str
