import json
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from models import Device as DeviceModel
from repositories.device_repository import DeviceRepository
from schemas import Device, DeviceWithVulnerabilities
from schemas.device import DeviceCreate

ALLOWED_FIELDS = {
    "ip_address",
    "mac_address",
    "hostname",
    "vendor",
    "device_type",
    "operating_system",
    "open_ports",
    "extra_info",
}


class DeviceService:
    def __init__(self, session: AsyncSession):
        self.repository = DeviceRepository(session)
        self.session = session

    async def get_all(self, skip: int = 0, limit: int = 100) -> List[Device]:
        devices = await self.repository.get_all(skip=skip, limit=limit)
        return [Device.model_validate(device) for device in devices]

    async def get_by_id(
        self, device_id: int
    ) -> Optional[DeviceWithVulnerabilities]:
        device = await self.repository.get_with_vulnerabilities(device_id)
        if not device:
            return None
        return DeviceWithVulnerabilities.model_validate(device)

    async def create_or_update(self, device_data: DeviceCreate) -> DeviceModel:
        """Create a new device or update existing by IP address."""
        data = device_data.model_dump(exclude_none=True)
        return await self.get_or_create_by_ip(data)

    async def get_or_create_by_ip(self, device_data: dict) -> DeviceModel:
        ip = device_data.get("ip_address") or device_data.get("ip")
        if not ip:
            raise ValueError("device_data missing ip_address")

        existing_device = await self.repository.get_by_ip(ip)
        filtered: Dict[str, Any] = {"ip_address": ip}

        for k, v in device_data.items():
            if k in ALLOWED_FIELDS and v is not None:
                filtered[k] = v

        if device_data.get("os"):
            filtered["operating_system"] = device_data["os"]

        open_ports = device_data.get("open_ports")
        if isinstance(open_ports, list):
            filtered["open_ports"] = json.dumps(open_ports)
        elif isinstance(open_ports, str):
            filtered["open_ports"] = open_ports
        else:
            filtered["open_ports"] = "[]"

        extra_info = {}
        if device_data.get("ssdp"):
            extra_info["ssdp"] = device_data["ssdp"]
        if device_data.get("tls_subject"):
            extra_info["tls_subject"] = device_data["tls_subject"]

        try:
            ports_list = json.loads(filtered["open_ports"])
            if ports_list:
                first_http = next(
                    (
                        p.get("http")
                        for p in ports_list
                        if isinstance(p, dict) and p.get("http")
                    ),
                    None,
                )
                if first_http:
                    extra_info["http"] = first_http
        except Exception:
            pass

        if extra_info:
            filtered["extra_info"] = json.dumps(extra_info)

        if existing_device:
            for key, value in filtered.items():
                if hasattr(existing_device, key):
                    setattr(existing_device, key, value)
            await self.session.flush()
            await self.session.refresh(existing_device)
            return existing_device
        else:
            return await self.repository.create(**filtered)

    async def delete(self, device_id: int) -> bool:
        return await self.repository.delete(device_id)

    async def scan_device_vulnerabilities(
        self,
        device_data: dict,
        ports: List[int],
    ) -> List[dict]:
        """
        Заглушка.
        В будущем:
        - CVE по banner / product / version
        - NVD API
        - exploit-db
        """
        return []
