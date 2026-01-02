from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Text,
    ForeignKey,
    Enum as SQLEnum,
    Table,
)
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from database import Base

# Association table for many-to-many relationship
scan_devices_association = Table(
    "scan_devices",
    Base.metadata,
    Column("scan_id", Integer, ForeignKey("scans.id"), primary_key=True),
    Column("device_id", Integer, ForeignKey("devices.id"), primary_key=True),
)


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class VulnerabilitySeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    mac_address = Column(String(17), index=True)
    hostname = Column(String(255))
    device_type = Column(String(100))
    manufacturer = Column(String(100))
    model = Column(String(100))
    operating_system = Column(String(100))
    open_ports = Column(Text)  # JSON string of ports
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    vulnerabilities = relationship(
        "Vulnerability", back_populates="device", cascade="all, delete-orphan"
    )
    scans = relationship(
        "Scan", secondary=scan_devices_association, back_populates="devices"
    )


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255))
    target_network = Column(
        String(50), nullable=False
    )  # e.g., "192.168.1.0/24"
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    devices_found = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    devices = relationship(
        "Device", secondary=scan_devices_association, back_populates="scans"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(SQLEnum(VulnerabilitySeverity), nullable=False)
    cve_id = Column(String(50))  # Common Vulnerabilities and Exposures ID
    port = Column(Integer)
    service = Column(String(100))
    recommendation = Column(Text, nullable=False)  # Как исправить уязвимость
    fixed = Column(String(10), default="false")  # "true" or "false"
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    device = relationship("Device", back_populates="vulnerabilities")
