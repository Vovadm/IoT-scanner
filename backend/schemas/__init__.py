from .device import Device, DeviceBase, DeviceCreate, DeviceWithVulnerabilities
from .scan import Scan, ScanBase, ScanCreate, ScanResponse
from .vulnerability import (
    Vulnerability,
    VulnerabilityBase,
    VulnerabilityCreate,
    VulnerabilityUpdate,
)

__all__ = [
    "DeviceBase",
    "DeviceCreate",
    "Device",
    "DeviceWithVulnerabilities",
    "ScanBase",
    "ScanCreate",
    "Scan",
    "ScanResponse",
    "VulnerabilityBase",
    "VulnerabilityCreate",
    "VulnerabilityUpdate",
    "Vulnerability",
]
