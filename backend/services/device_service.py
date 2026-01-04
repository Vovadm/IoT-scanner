# backend/services/device_service.py
import json
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from repositories.device_repository import DeviceRepository
from schemas import Device, DeviceWithVulnerabilities
from models import Device as DeviceModel


ALLOWED_FIELDS = {
    "ip_address",
    "mac_address",
    "hostname",
    "device_type",
    "manufacturer",
    "model",
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

    async def get_or_create_by_ip(self, device_data: dict) -> DeviceModel:
        ip = device_data.get("ip_address") or device_data.get("ip")
        if not ip:
            raise ValueError("device_data missing ip_address")

        existing_device = await self.repository.get_by_ip(ip)
        filtered: Dict[str, Any] = {"ip_address": ip}

        # copy allowed fields
        for k, v in device_data.items():
            if k in ALLOWED_FIELDS and v is not None:
                filtered[k] = v

        # os -> operating_system
        if device_data.get("os"):
            filtered["operating_system"] = device_data["os"]

        # normalize open_ports to list for JSON column
        open_ports = filtered.get("open_ports")
        if isinstance(open_ports, str):
            try:
                parsed = json.loads(open_ports)
                filtered["open_ports"] = parsed if isinstance(parsed, list) else []
            except Exception:
                filtered["open_ports"] = []
        elif open_ports is None:
            filtered["open_ports"] = []

        # extra_info: combine ssdp/mdns/tls/http into extra_info JSON
        extra_info: Dict[str, Any] = {}
        if "ssdp" in device_data and device_data["ssdp"]:
            extra_info["ssdp"] = device_data["ssdp"]
        if "mdns" in device_data and device_data["mdns"]:
            extra_info["mdns"] = device_data["mdns"]
        if "tls_subject" in device_data and device_data["tls_subject"]:
            extra_info["tls_subject"] = device_data["tls_subject"]

        # try to guess manufacturer from http headers banner or existing field
        if not filtered.get("manufacturer"):
            # first try vendor in extra_info (arp-scan may have added manufacturer)
            if device_data.get("manufacturer"):
                filtered["manufacturer"] = device_data.get("manufacturer")
            else:
                # extract from first open_ports http headers server field (if present)
                for p in filtered["open_ports"]:
                    http = p.get("http")
                    if http and http.get("headers") and http["headers"].get("server"):
                        filtered["manufacturer"] = http["headers"].get("server")
                        break

        if extra_info:
            filtered["extra_info"] = extra_info

        # update existing or create
        if existing_device:
            for key, value in filtered.items():
                if hasattr(existing_device, key) and value is not None:
                    setattr(existing_device, key, value)
            await self.session.flush()
            await self.session.refresh(existing_device)
            return existing_device

        return await self.repository.create(**filtered)

    async def delete(self, device_id: int) -> bool:
        return await self.repository.delete(device_id)

    async def scan_device_vulnerabilities(
        self,
        device_data: dict,
        ports: List[int],
    ) -> List[dict]:
        # Заглушка, можно расширить: CVE lookup по баннерам, NVD, vulners API и т.д.
        return []
