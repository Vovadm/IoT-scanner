from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, Enum
from sqlalchemy.orm import relationship

from core.database import Base
from models.enums import ScanStatus
from models.device import scan_devices_association


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=True)
    target_network = Column(String(50), nullable=False)

    status = Column(
        Enum(ScanStatus),
        default=ScanStatus.PENDING,
        nullable=False,
    )

    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    devices_found = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    devices = relationship(
        "Device",
        secondary=scan_devices_association,
        back_populates="scans",
    )
