from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Union, Any
from datetime import datetime
import json


class DeviceBase(BaseModel):
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    operating_system: Optional[str] = None

    open_ports: Optional[Union[str, List[Any]]] = None

    @field_validator("open_ports", mode="before")
    @classmethod
    def normalize_open_ports(cls, value):
        if value is None:
            return None

        if isinstance(value, str):
            return value

        if isinstance(value, list):
            try:
                return json.dumps(value)
            except Exception:
                return "[]"

        return str(value)


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
