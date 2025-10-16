from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List, Dict, Any
from enum import Enum

class ScanType(str, Enum):
    NETWORK = "network"
    WEB = "web"
    FULL = "full"

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None

class TokenData(BaseModel):
    username: Optional[str] = None
    scopes: List[str] = []

class UserBase(BaseModel):
    email: EmailStr
    username: Optional[str] = None
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v

class UserInDB(UserBase):
    id: int
    is_active: bool
    is_superuser: bool
    email_verified: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        orm_mode = True

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

class EmailVerificationRequest(BaseModel):
    token: str

class ScanCreate(BaseModel):
    target: str
    scan_type: ScanType
    options: Dict[str, Any] = {}

class ScanOut(BaseModel):
    id: int
    target: str
    scan_type: ScanType
    status: str
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    user_id: int
    
    class Config:
        orm_mode = True

class ScanUpdate(BaseModel):
    status: Optional[str] = None
    options: Optional[Dict[str, Any]] = None

class VulnerabilityOut(BaseModel):
    id: int
    cve_id: str
    name: str
    severity: str
    cvss_score: float
    description: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    solution: Optional[str] = None
    
    class Config:
        orm_mode = True

class ScanStats(BaseModel):
    scan_id: int
    total_vulnerabilities: int
    severity_counts: Dict[str, int]
    duration: Optional[float]
    status: str

class ScanScheduleCreate(BaseModel):
    name: str
    target: str
    scan_type: ScanType
    cron_expression: Optional[str] = None
    one_shot: bool = False
    start_at: Optional[datetime] = None
    is_active: bool = True

class ReportOut(BaseModel):
    id: int
    scan_id: int
    title: str
    report_type: str
    created_at: datetime
    is_public: bool
    
    class Config:
        orm_mode = True
