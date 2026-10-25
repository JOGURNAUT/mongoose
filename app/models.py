from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field
from sqlmodel import SQLModel, Field as SQLField, Column, JSON


class AlertType(str, Enum):
    ip_traffic = "ip_traffic"
    file_hash = "file_hash"
    login = "login"


class Severity(str, Enum):
    low = "LOW"
    medium = "MEDIUM"
    high = "HIGH"
    unknown = "UNKNOWN"


class AlertIn(BaseModel):
    """What a caller (a detection system, a SIEM, a test script) submits."""

    type: AlertType
    source_ip: Optional[str] = None
    file_hash: Optional[str] = None
    user: Optional[str] = None
    # login-specific context; required for `type == login`, ignored otherwise
    failed_attempts_last_5min: Optional[int] = None
    country: Optional[str] = None
    last_known_country: Optional[str] = None
    minutes_since_last_login: Optional[float] = None
    raw_event: dict = Field(default_factory=dict)


class EnrichmentResult(BaseModel):
    source: str  # "abuseipdb" | "virustotal" | "none" | "mock"
    ok: bool
    data: dict = Field(default_factory=dict)
    error: Optional[str] = None


class ClassificationResult(BaseModel):
    severity: Severity
    reasons: list[str]  # evidence, not a guess — every severity traces to a stated reason


class PlaybookResult(BaseModel):
    actions: list[str]
    fail_closed: bool  # true when the verdict is UNKNOWN and we deliberately escalate rather than clear it


class Alert(SQLModel, table=True):
    id: Optional[int] = SQLField(default=None, primary_key=True)
    type: str
    source_ip: Optional[str] = None
    file_hash: Optional[str] = None
    user: Optional[str] = None
    received_at: datetime = SQLField(default_factory=lambda: datetime.now(timezone.utc))

    enrichment: dict = SQLField(default_factory=dict, sa_column=Column(JSON))
    severity: str = Severity.unknown.value
    reasons: list[str] = SQLField(default_factory=list, sa_column=Column(JSON))
    actions: list[str] = SQLField(default_factory=list, sa_column=Column(JSON))
    raw_event: dict = SQLField(default_factory=dict, sa_column=Column(JSON))


class AlertOut(BaseModel):
    id: int
    type: str
    source_ip: Optional[str]
    file_hash: Optional[str]
    user: Optional[str]
    received_at: datetime
    enrichment: dict
    severity: str
    reasons: list[str]
    actions: list[str]
