# models/device.py
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING

from sqlalchemy import (
    Column,
    String,
    Integer,
    DateTime,
    Text,
    Table,
    ForeignKey,
)
from sqlalchemy.orm import relationship, Mapped, mapped_column

# adjust this import to match your project structure:
# from core.database import Base
from database import Base

if TYPE_CHECKING:
    from .vulnerability import Vulnerability  # noqa: F401
    from .scan import Scan  # noqa: F401

scan_devices_association = Table(
    "scan_devices",
    Base.metadata,
    Column("scan_id", Integer, ForeignKey("scans.id"), primary_key=True),
    Column("device_id", Integer, ForeignKey("devices.id"), primary_key=True),
)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ip_address: Mapped[str] = mapped_column(
        String(45), unique=True, index=True, nullable=False
    )
    mac_address: Mapped[Optional[str]] = mapped_column(
        String(17), index=True, nullable=True
    )
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_type: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    manufacturer: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    model: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    operating_system: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    open_ports: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # relationships
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="device", cascade="all, delete-orphan"
    )
    scans: Mapped[List["Scan"]] = relationship(
        "Scan", secondary=scan_devices_association, back_populates="devices"
    )
