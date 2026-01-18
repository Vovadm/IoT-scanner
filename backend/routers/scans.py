from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from schemas.device import DeviceCreate
from schemas.scan import Scan, ScanCreate, ScanResponse
from services.device_service import DeviceService
from services.scan_service import ScanService

router = APIRouter()


class HostScanResult(BaseModel):
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    os: str | None = None
    open_ports: List[int] | List[Dict[str, Any]] | None = None
    port_details: List[str] | None = None


@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new scan. Use Go scanner to execute."""
    service = ScanService(db)
    scan_response = await service.create_scan(scan_data)
    return scan_response


@router.post("/{scan_id}/results")
async def post_scan_result(
    scan_id: int,
    result: HostScanResult,
    db: AsyncSession = Depends(get_db),
):
    """Accept scan result from external host scanner."""
    scan_service = ScanService(db)
    device_service = DeviceService(db)

    scan = await scan_service.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    open_ports = result.open_ports or []
    if open_ports and isinstance(open_ports[0], int):
        open_ports = [{"port": p} for p in open_ports]

    device_data = DeviceCreate(
        ip_address=result.ip_address,
        mac_address=result.mac_address,
        hostname=result.hostname,
        vendor=result.vendor,
        device_type=result.device_type,
        os=result.os,
        open_ports=open_ports,
    )

    device = await device_service.create_or_update(device_data)
    await scan_service.link_device_to_scan(scan_id, device.id)

    return {"status": "ok", "device_id": device.id}


@router.post("/{scan_id}/complete")
async def complete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Mark scan as completed by external host scanner."""
    scan_service = ScanService(db)

    scan = await scan_service.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await scan_service.complete_scan(scan_id)
    return {"status": "completed"}


@router.get("/", response_model=List[Scan])
async def get_scans(
    skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)
):
    service = ScanService(db)
    scans = await service.get_all(skip=skip, limit=limit)
    return scans


@router.get("/pending")
async def get_pending_scans(db: AsyncSession = Depends(get_db)):
    """Get all scans with pending status (for Go scanner watch mode)."""
    service = ScanService(db)
    scans = await service.get_pending_scans()
    return {"scans": scans}


@router.patch("/{scan_id}/status")
async def update_scan_status(
    scan_id: int,
    status_data: dict,
    db: AsyncSession = Depends(get_db),
):
    """Update scan status (for Go scanner)."""
    service = ScanService(db)
    scan = await service.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    status = status_data.get("status")
    if status:
        await service.update_status(scan_id, status)
    return {"status": "updated"}


@router.get("/{scan_id}", response_model=Scan)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    service = ScanService(db)
    scan = await service.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
