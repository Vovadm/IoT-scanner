import json
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import insert

from repositories.scan_repository import ScanRepository
from repositories.device_repository import DeviceRepository
from repositories.vulnerability_repository import VulnerabilityRepository
from services.scanner_service import ScannerService
from schemas.scan import Scan, ScanCreate, ScanResponse
from models.enums import ScanStatus
from models import scan_devices_association

if TYPE_CHECKING:
    from models.device import Device


class ScanService:
    """
    Сервис для работы со сканированиями
    Обеспечивает бизнес-логику для операций со сканированиями сети
    """

    def __init__(self, session: AsyncSession):
        self.repository = ScanRepository(session)
        self.device_repository = DeviceRepository(session)
        self.vulnerability_repository = VulnerabilityRepository(session)
        self.scanner_service = ScannerService()
        self.session = session

    async def create_scan(self, scan_data: ScanCreate) -> ScanResponse:
        """
        Создать новое сканирование

        Args:
                scan_data: Данные для создания сканирования

        Returns:
                Результат создания сканирования
        """
        scan = await self.repository.create(
            name=scan_data.name
            or f"Scan {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}",
            target_network=scan_data.target_network,
            status=ScanStatus.PENDING,
        )
        await self.session.commit()
        await self.session.refresh(scan)

        return ScanResponse(
            scan=Scan.model_validate(scan), message="Scan started successfully"
        )

    async def get_all(self, skip: int = 0, limit: int = 100) -> List[Scan]:
        """
        Получить все сканирования

        Args:
                skip: Количество записей для пропуска
                limit: Максимальное количество записей

        Returns:
                Список сканирований
        """
        scans = await self.repository.get_all_ordered(skip=skip, limit=limit)
        return [Scan.model_validate(scan) for scan in scans]

    async def get_by_id(self, scan_id: int) -> Optional[Scan]:
        """
        Получить сканирование по ID

        Args:
                scan_id: ID сканирования

        Returns:
                Сканирование или None
        """
        scan = await self.repository.get_by_id(scan_id)
        if not scan:
            return None
        return Scan.model_validate(scan)

    async def execute_scan(self, scan_id: int) -> None:
        """
        Выполнить сканирование сети

        Args:
                scan_id: ID сканирования
        """
        scan = await self.repository.get_by_id(scan_id)
        if not scan:
            return

        # Обновляем статус на RUNNING
        await self.repository.update_status(scan_id, ScanStatus.RUNNING)
        await self.session.commit()

        try:
            # Запускаем сканер
            devices_data = await self.scanner_service.scan_network(
                scan.target_network
            )

            devices_found = 0
            for device_data in devices_data:
                # Получаем или создаем устройство
                device = await self._get_or_create_device(device_data)

                # Связываем устройство со сканированием
                await self.session.execute(
                    insert(scan_devices_association).values(
                        scan_id=scan_id, device_id=device.id
                    )
                )

                # Сканируем уязвимости
                ports_data = json.loads(device_data.get("open_ports", "[]"))
                vulnerabilities_data = (
                    await self.scanner_service.scan_device_vulnerabilities(
                        device_data, ports_data
                    )
                )

                # Удаляем старые уязвимости для этого устройства
                await self.vulnerability_repository.delete_by_device_id(
                    device.id
                )

                # Добавляем новые уязвимости
                for vuln_data in vulnerabilities_data:
                    await self.vulnerability_repository.create(
                        device_id=device.id, **vuln_data
                    )

                devices_found += 1

            # Завершаем сканирование
            await self.repository.update(
                scan_id,
                status=ScanStatus.COMPLETED,
                completed_at=datetime.utcnow(),
                devices_found=devices_found,
            )
            await self.session.commit()

        except Exception as e:
            # Обработка ошибок
            print(f"Error in scan execution: {e}")
            await self.repository.update_status(scan_id, ScanStatus.FAILED)
            await self.session.commit()
            raise

    async def _get_or_create_device(self, device_data: dict) -> "Device":
        """
        Внутренний метод для получения или создания устройства
        """
        from services.device_service import DeviceService

        device_service = DeviceService(self.session)
        return await device_service.get_or_create_by_ip(device_data)
