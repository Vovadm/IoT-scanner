from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class DeviceBase(BaseModel):
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    operating_system: Optional[str] = None
    open_ports: Optional[str] = None


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
