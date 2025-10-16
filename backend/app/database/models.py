from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Text, JSON, Enum
from sqlalchemy.orm import relationship
from enum import Enum as PyEnum
import uuid
from .database import Base
import secrets

class ScanType(PyEnum):
    NETWORK = "network"
    WEB = "web"
    FULL = "full"

class ScanStatus(PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class UserRole(PyEnum):
    ADMIN = "admin"
    SCANNER = "scanner"
    VIEWER = "viewer"
    GUEST = "guest"

class VulnerabilitySeverity(PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(50), unique=True, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    role = Column(Enum(UserRole), default=UserRole.VIEWER)
    last_login = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    email_verified = Column(Boolean, default=False)

    refresh_tokens = relationship("RefreshToken", back_populates="user")
    verification_tokens = relationship("VerificationToken", back_populates="user")
    password_reset_tokens = relationship("PasswordResetToken", back_populates="user")
    scans = relationship("ScanTask", back_populates="owner")
    reports = relationship("Report", back_populates="owner")

    def __repr__(self):
        return f"<User {self.username}>"

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(255), unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    revoked = Column(Boolean, default=False)
    
    user = relationship("User", back_populates="refresh_tokens")

class VerificationToken(Base):
    __tablename__ = "verification_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(64), unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    expires_at = Column(DateTime)
    
    user = relationship("User", back_populates="verification_tokens")

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(64), unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    expires_at = Column(DateTime)
    
    user = relationship("User", back_populates="password_reset_tokens")

class ScanTask(Base):
    __tablename__ = "scan_tasks"
    
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String(36), default=lambda: str(uuid.uuid4()), unique=True)
    target = Column(String(200), nullable=False)
    scan_type = Column(Enum(ScanType), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    options = Column(JSON, default={})
    priority = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    user_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")
    reports = relationship("Report", back_populates="scan")
    
    @property
    def duration(self):
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None
    
    def __repr__(self):
        return f"<ScanTask {self.task_id} ({self.status})>"

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_tasks.id"))
    cve_id = Column(String(20), index=True)
    name = Column(String(200))
    description = Column(Text)
    severity = Column(Enum(VulnerabilitySeverity))
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    solution = Column(Text)
    references = Column(JSON)
    port = Column(Integer)
    protocol = Column(String(10))
    detected_at = Column(DateTime, default=datetime.utcnow)
    is_false_positive = Column(Boolean, default=False)

    scan = relationship("ScanTask", back_populates="vulnerabilities")
    
    def __repr__(self):
        return f"<Vulnerability {self.cve_id} ({self.severity})>"

class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_tasks.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String(200))
    description = Column(Text)
    report_type = Column(String(50))
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_public = Column(Boolean, default=False)

    scan = relationship("ScanTask", back_populates="reports")
    owner = relationship("User", back_populates="reports")
    
    def __repr__(self):
        return f"<Report for scan {self.scan_id}>"

class ScanSchedule(Base):
    __tablename__ = "scan_schedules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    target = Column(String(200), nullable=False)
    scan_type = Column(Enum(ScanType), nullable=False)
    cron_expression = Column(String(50))
    one_shot = Column(Boolean, default=False)
    start_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    last_run = Column(DateTime)
    next_run = Column(DateTime)
    
    def __repr__(self):
        return f"<ScanSchedule {self.name}>"

class SystemLog(Base):
    __tablename__ = "system_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    level = Column(String(10))
    source = Column(String(50))
    message = Column(Text)
    details = Column(JSON)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    def __repr__(self):
        return f"<Log {self.level} {self.message[:50]}>"

class APIToken(Base):
    __tablename__ = "api_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(300), unique=True, index=True)
    name = Column(String(100))
    user_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    scopes = Column(JSON)
    
    def __repr__(self):
        return f"<APIToken {self.name}>"
