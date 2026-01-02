# models/scan.py
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING

from sqlalchemy import String, Integer, DateTime, Enum as SQLEnum
from sqlalchemy.orm import relationship, Mapped, mapped_column

# adjust this import to match your project structure:
# from core.database import Base
from database import Base

from .enums import ScanStatus
from .device import scan_devices_association

if TYPE_CHECKING:
    from .device import Device  # noqa: F401


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    target_network: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        SQLEnum(ScanStatus), default=ScanStatus.PENDING
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )
    devices_found: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    devices: Mapped[List["Device"]] = relationship(
        "Device", secondary=scan_devices_association, back_populates="scans"
    )
