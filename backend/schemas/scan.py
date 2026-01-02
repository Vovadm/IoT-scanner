from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field
from models.enums import ScanStatus


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


class ScanResponse(BaseModel):
    scan: Scan
    message: str
