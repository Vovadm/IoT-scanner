from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from repositories.device_repository import DeviceRepository
from schemas import Device, DeviceWithVulnerabilities
from models import Device as DeviceModel


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
        existing_device = await self.repository.get_by_ip(
            device_data["ip_address"]
        )

        if existing_device:
            for key, value in device_data.items():
                if value:
                    setattr(existing_device, key, value)
            await self.session.flush()
            await self.session.refresh(existing_device)
            return existing_device
        else:
            return await self.repository.create(**device_data)

    async def delete(self, device_id: int) -> bool:
        return await self.repository.delete(device_id)
