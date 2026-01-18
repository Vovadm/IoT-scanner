import logging
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.device import scan_devices_association
from models.enums import ScanStatus
from repositories.device_repository import DeviceRepository
from repositories.scan_repository import ScanRepository
from repositories.vulnerability_repository import VulnerabilityRepository
from schemas.scan import Scan, ScanCreate, ScanResponse

if TYPE_CHECKING:
    from models.device import Device

logger = logging.getLogger("ScanService")


class ScanService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repository = ScanRepository(session)
        self.device_repository = DeviceRepository(session)
        self.vulnerability_repository = VulnerabilityRepository(session)

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

    async def _get_or_create_device(self, device_data: dict) -> "Device":
        from services.device_service import DeviceService

        device_service = DeviceService(self.session)
        device = await device_service.get_or_create_by_ip(device_data)

        logger.debug("Device resolved: %s", device.ip_address)
        return device

    async def link_device_to_scan(self, scan_id: int, device_id: int) -> None:
        """Link a device to a scan (for external host scanner)."""
        await self.session.execute(
            insert(scan_devices_association).values(
                scan_id=scan_id,
                device_id=device_id,
            )
        )
        await self.session.commit()
        logger.info("Linked device %d to scan %d", device_id, scan_id)

    async def complete_scan(self, scan_id: int) -> None:
        """Mark scan as completed."""
        scan = await self.repository.get_by_id(scan_id)
        if not scan:
            return

        from sqlalchemy import func, select

        result = await self.session.execute(
            select(func.count()).where(
                scan_devices_association.c.scan_id == scan_id
            )
        )
        devices_found = result.scalar() or 0

        await self.repository.update(
            scan_id,
            status=ScanStatus.COMPLETED,
            completed_at=datetime.utcnow(),
            devices_found=devices_found,
        )
        await self.session.commit()
        logger.info(
            "Scan %d completed with %d devices",
            scan_id,
            devices_found,
        )

    async def get_pending_scans(self) -> List[dict]:
        """Get all scans with PENDING status (for Go scanner watch mode)."""
        from models.scan import Scan as ScanModel

        result = await self.session.execute(
            select(ScanModel).where(ScanModel.status == ScanStatus.PENDING)
        )
        scans = result.scalars().all()
        return [
            {
                "id": scan.id,
                "target_network": scan.target_network,
                "name": scan.name,
                "status": scan.status.value,
            }
            for scan in scans
        ]

    async def update_status(self, scan_id: int, status: str) -> None:
        """Update scan status."""
        status_enum = ScanStatus(status)
        await self.repository.update(scan_id, status=status_enum)
        await self.session.commit()
        logger.info("Scan %d status updated to %s", scan_id, status)
