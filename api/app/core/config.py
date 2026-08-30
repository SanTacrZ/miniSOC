"""App config — 12factor"""
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "Mini-SOC Secure API"
    jwt_alg: str = "RS256"
    access_expire: int = 900
    refresh_expire: int = 604800
    rate_global: int = 60
    rate_auth: int = 5

settings = Settings()
