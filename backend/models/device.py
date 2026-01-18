from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from core.database import Base

from .associations import scan_devices_association


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    mac_address = Column(String(17), nullable=True)
    hostname = Column(String(255), nullable=True)
    device_type = Column(String(100), nullable=True)
    manufacturer = Column(String(100), nullable=True)
    vendor = Column(String(100), nullable=True)
    model = Column(String(100), nullable=True)
    operating_system = Column(String(100), nullable=True)
    open_ports = Column(Text, nullable=True)
    extra_info = Column(Text, nullable=True)

    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="device",
        cascade="all, delete-orphan",
    )

    scans = relationship(
        "Scan",
        secondary=scan_devices_association,
        back_populates="devices",
    )
