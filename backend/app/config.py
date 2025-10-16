from pydantic import BaseSettings
from typing import Optional, List

class Settings(BaseSettings):
    APP_NAME: str = "Vulnerability Scanner"
    VERSION: str = "1.0.0"
    DEBUG: bool = True
    ENVIRONMENT: str = "development"

    DATABASE_URL: str = "postgresql://scanner_user:scanner_pass@localhost:5432/scanner_db"

    REDIS_URL: str = "redis://localhost:6379/0"

    SECRET_KEY: str = "your-super-secret-key-change-me-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    SCANNERS_ENABLED: List[str] = ['nmap', 'zap', 'openvas']
    NMAP_TIMEOUT: int = 1800
    ZAP_API_KEY: str = 'your-zap-api-key'
    ZAP_PROXY: str = 'http://localhost:8080'
    ZAP_TIMEOUT: int = 7200
    OPENVAS_USERNAME: str = 'admin'
    OPENVAS_PASSWORD: str = 'admin'
    OPENVAS_HOST: str = 'localhost'
    OPENVAS_PORT: int = 9390
    OPENVAS_TIMEOUT: int = 14400

    SMTP_HOST: Optional[str] = None
    SMTP_PORT: Optional[int] = None
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    EMAIL_FROM: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
