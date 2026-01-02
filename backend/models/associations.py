from sqlalchemy import Table, Column, Integer, ForeignKey
from core.database import Base

scan_devices_association = Table(
    "scan_devices",
    Base.metadata,
    Column("scan_id", Integer, ForeignKey("scans.id"), primary_key=True),
    Column("device_id", Integer, ForeignKey("devices.id"), primary_key=True),
)
