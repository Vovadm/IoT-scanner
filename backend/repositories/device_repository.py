from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from models.device import Device
from repositories.base_repository import BaseRepository


class DeviceRepository(BaseRepository[Device]):

    def __init__(self, session: AsyncSession):
        super().__init__(Device, session)

    async def get_by_ip(self, ip_address: str) -> Optional[Device]:
        return await self.get_by_field("ip_address", ip_address)

    async def get_with_vulnerabilities(
        self, device_id: int
    ) -> Optional[Device]:
        result = await self.session.execute(
            select(Device)
            .where(Device.id == device_id)
            .options(selectinload(Device.vulnerabilities))
        )
        return result.scalar_one_or_none()

    async def get_all_with_vulnerabilities(
        self, skip: int = 0, limit: int = 100
    ) -> List[Device]:
        result = await self.session.execute(
            select(Device)
            .options(selectinload(Device.vulnerabilities))
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())
