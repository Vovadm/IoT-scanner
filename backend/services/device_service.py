from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from repositories.device_repository import DeviceRepository
from schemas.device import Device, DeviceWithVulnerabilities
from models.device import Device as DeviceModel


class DeviceService:
    """
    Сервис для работы с устройствами
    Обеспечивает бизнес-логику для операций с устройствами
    """

    def __init__(self, session: AsyncSession):
        self.repository = DeviceRepository(session)
        self.session = session

    async def get_all(self, skip: int = 0, limit: int = 100) -> List[Device]:
        """
        Получить все устройства

        Args:
                skip: Количество записей для пропуска
                limit: Максимальное количество записей

        Returns:
                Список устройств
        """
        devices = await self.repository.get_all(skip=skip, limit=limit)
        return [Device.model_validate(device) for device in devices]

    async def get_by_id(
        self, device_id: int
    ) -> Optional[DeviceWithVulnerabilities]:
        """
        Получить устройство по ID с уязвимостями

        Args:
                device_id: ID устройства

        Returns:
                Устройство с уязвимостями или None
        """
        device = await self.repository.get_with_vulnerabilities(device_id)
        if not device:
            return None
        return DeviceWithVulnerabilities.model_validate(device)

    async def get_or_create_by_ip(self, device_data: dict) -> DeviceModel:
        """
        Получить устройство по IP или создать новое

        Args:
                device_data: Данные об устройстве

        Returns:
                Устройство
        """
        existing_device = await self.repository.get_by_ip(
            device_data["ip_address"]
        )

        if existing_device:
            # Обновляем информацию
            for key, value in device_data.items():
                if value:
                    setattr(existing_device, key, value)
            await self.session.flush()
            await self.session.refresh(existing_device)
            return existing_device
        else:
            # Создаем новое устройство
            return await self.repository.create(**device_data)

    async def delete(self, device_id: int) -> bool:
        """
        Удалить устройство

        Args:
                device_id: ID устройства

        Returns:
                True если удалено успешно
        """
        return await self.repository.delete(device_id)
