import json
import logging
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING, cast

from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession

from models.enums import ScanStatus
from models.device import scan_devices_association
from repositories.device_repository import DeviceRepository
from repositories.scan_repository import ScanRepository
from repositories.vulnerability_repository import VulnerabilityRepository
from schemas.scan import Scan, ScanCreate, ScanResponse
from services.scanner_service import ScannerService

if TYPE_CHECKING:
    from models.device import Device

logger = logging.getLogger("ScanService")


class ScanService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repository = ScanRepository(session)
        self.device_repository = DeviceRepository(session)
        self.vulnerability_repository = VulnerabilityRepository(session)
        self.scanner_service = ScannerService()

        logger.info("ScanService initialized")

    async def create_scan(self, scan_data: ScanCreate) -> ScanResponse:
        logger.info("Creating scan for network: %s", scan_data.target_network)

        scan = await self.repository.create(
            name=scan_data.name
            or f"Scan {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}",
            target_network=scan_data.target_network,
            status=ScanStatus.PENDING,
        )

        await self.session.commit()
        await self.session.refresh(scan)

        logger.info("Scan created with id: %s", scan.id)

        return ScanResponse(
            scan=Scan.model_validate(scan),
            message="Scan started successfully",
        )

    async def get_all(self, skip: int = 0, limit: int = 100) -> List[Scan]:
        logger.debug("Fetching scans list")
        scans = await self.repository.get_all_ordered(skip=skip, limit=limit)
        return [Scan.model_validate(scan) for scan in scans]

    async def get_by_id(self, scan_id: int) -> Optional[Scan]:
        logger.debug("Fetching scan by id: %s", scan_id)
        scan = await self.repository.get_by_id(scan_id)
        return Scan.model_validate(scan) if scan else None

    async def execute_scan(self, scan_id: int) -> None:
        logger.info("Starting execution of scan id: %s", scan_id)

        scan = await self.repository.get_by_id(scan_id)
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return

        await self.repository.update_status(scan_id, ScanStatus.RUNNING)
        await self.session.commit()
        logger.info("Scan id %s status updated to RUNNING", scan_id)

        try:
            devices_data = await self.scanner_service.scan_network(
                cast(str, scan.target_network)
            )

            devices_found = 0

            for device_data in devices_data:
                device = await self._get_or_create_device(device_data)

                await self.session.execute(
                    insert(scan_devices_association).values(
                        scan_id=scan_id,
                        device_id=device.id,
                    )
                )

                ports_data = json.loads(device_data.get("open_ports", "[]"))

                vulns = await self.scanner_service.scan_device_vulnerabilities(
                    device_data, ports_data
                )

                device_id = cast(int, device.id)
                await self.vulnerability_repository.delete_by_device_id(
                    device_id
                )

                for vuln in vulns:
                    await self.vulnerability_repository.create(
                        device_id=device.id,
                        **vuln,
                    )

                devices_found += 1
                logger.info(
                    "Processed device %s (%d/%d)",
                    device.ip_address,
                    devices_found,
                    len(devices_data),
                )

            await self.repository.update(
                scan_id,
                status=ScanStatus.COMPLETED,
                completed_at=datetime.utcnow(),
                devices_found=devices_found,
            )
            await self.session.commit()

            logger.info("Scan %s completed successfully", scan_id)

        except Exception:
            logger.exception("Scan %s failed", scan_id)
            await self.repository.update_status(scan_id, ScanStatus.FAILED)
            await self.session.commit()
            raise

    async def _get_or_create_device(self, device_data: dict) -> "Device":
        from services.device_service import DeviceService

        device_service = DeviceService(self.session)
        device = await device_service.get_or_create_by_ip(device_data)

        logger.debug("Device resolved: %s", device.ip_address)
        return device
