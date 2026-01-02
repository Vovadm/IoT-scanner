from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from models import ScanStatus, VulnerabilitySeverity


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


class DeviceWithVulnerabilities(Device):
    vulnerabilities: List["Vulnerability"] = []


class ScanBase(BaseModel):
    name: Optional[str] = None
    target_network: str = Field(
        ..., description="Network CIDR notation, e.g., 192.168.1.0/24"
    )


class ScanCreate(ScanBase):
    pass


class Scan(ScanBase):
    id: int
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    devices_found: int
    created_at: datetime

    class Config:
        from_attributes = True


class VulnerabilityBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: VulnerabilitySeverity
    cve_id: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    recommendation: str


class VulnerabilityCreate(VulnerabilityBase):
    device_id: int


class VulnerabilityUpdate(BaseModel):
    fixed: Optional[str] = None


class Vulnerability(VulnerabilityBase):
    id: int
    device_id: int
    fixed: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    scan: Scan
    message: str
