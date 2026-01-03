import json
import logging
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING, cast

from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession

from repositories.scan_repository import ScanRepository
from repositories.device_repository import DeviceRepository
from repositories.vulnerability_repository import VulnerabilityRepository
from services.scanner_service import ScannerService
from services.device_service import DeviceService
from schemas.scan import Scan, ScanCreate, ScanResponse
from models.enums import ScanStatus
from models.device import scan_devices_association

if TYPE_CHECKING:
    from models.device import Device

logger = logging.getLogger("ScanService")
logger.setLevel(logging.INFO)


class ScanService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repository = ScanRepository(session)
        self.device_repository = DeviceRepository(session)
        self.vulnerability_repository = VulnerabilityRepository(session)
        self.scanner_service = ScannerService()
        self.device_service = DeviceService(session)
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
        scans = await self.repository.get_all_ordered(skip=skip, limit=limit)
        return [Scan.model_validate(scan) for scan in scans]

    async def get_by_id(self, scan_id: int) -> Optional[Scan]:
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

        try:
            network = cast(str, scan.target_network)
            devices_data = await self.scanner_service.scan_network(network)

            devices_found = 0
            total = len(devices_data)

            for idx, device_data in enumerate(devices_data, start=1):
                device = await self._get_or_create_device(device_data)

                await self.session.execute(
                    insert(scan_devices_association).values(
                        scan_id=int(scan_id),
                        device_id=cast(int, device.id),
                    )
                )

                ports_field = device_data.get("open_ports", [])
                ports_list = []

                if isinstance(ports_field, str):
                    try:
                        parsed = json.loads(ports_field)
                        if isinstance(parsed, list):
                            ports_list = parsed
                    except Exception:
                        ports_list = []
                elif isinstance(ports_field, list):
                    ports_list = ports_field

                ports_ints: List[int] = []
                for p in ports_list:
                    if not isinstance(p, dict):
                        continue
                    port_val = p.get("port")
                    if isinstance(port_val, int):
                        ports_ints.append(port_val)
                        continue
                    if isinstance(port_val, str):
                        try:
                            ports_ints.append(int(port_val))
                        except Exception:
                            continue

                vulnerabilities_data = (
                    await self.device_service.scan_device_vulnerabilities(
                        device_data, ports_ints
                    )
                )

                await self.vulnerability_repository.delete_by_device_id(
                    cast(int, device.id)
                )

                for vuln_data in vulnerabilities_data:
                    await self.vulnerability_repository.create(
                        device_id=cast(int, device.id),
                        **vuln_data,
                    )

                devices_found += 1
                logger.info(
                    "Processed device %s (%d/%d)",
                    device.ip_address,
                    idx,
                    total,
                )

            await self.repository.update(
                scan_id,
                status=ScanStatus.COMPLETED,
                completed_at=datetime.utcnow(),
                devices_found=devices_found,
            )
            await self.session.commit()

            logger.info(
                "Scan %s completed successfully (devices_found=%d)",
                scan_id,
                devices_found,
            )

        except Exception:
            logger.exception("Scan %s failed", scan_id)
            try:
                await self.repository.update_status(scan_id, ScanStatus.FAILED)
                await self.session.commit()
            except Exception:
                logger.exception("Failed to mark scan as FAILED")
            raise

    async def _get_or_create_device(self, device_data: dict) -> "Device":
        return await self.device_service.get_or_create_by_ip(device_data)
