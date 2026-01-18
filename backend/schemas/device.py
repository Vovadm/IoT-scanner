import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class DeviceBase(BaseModel):
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    manufacturer: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    operating_system: Optional[str] = None
    os: Optional[str] = None
    open_ports: Optional[List[Dict[str, Any]]] = None

    @field_validator("open_ports", mode="before")
    @classmethod
    def parse_open_ports(cls, v):
        """Parse JSON string to list if needed."""
        if v is None:
            return []
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, list) else []
            except Exception:
                return []
        return v


class DeviceCreate(DeviceBase):
    pass


class Device(DeviceBase):
    id: int
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class VulnerabilityOut(BaseModel):
    id: int
    title: str
    severity: str
    fixed: str

    class Config:
        from_attributes = True


class DeviceWithVulnerabilities(Device):
    vulnerabilities: List[VulnerabilityOut] = Field(default_factory=list)
