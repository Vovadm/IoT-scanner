from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from core.database import get_db, AsyncSessionLocal
from services.scan_service import ScanService
from schemas.scan import Scan, ScanCreate, ScanResponse

router = APIRouter()


async def scan_network_background(scan_id: int):
    db = AsyncSessionLocal()
    try:
        service = ScanService(db)
        await service.execute_scan(scan_id)
    finally:
        await db.close()


@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    service = ScanService(db)
    scan_response = await service.create_scan(scan_data)

    background_tasks.add_task(scan_network_background, scan_response.scan.id)

    return scan_response


@router.get("/", response_model=List[Scan])
async def get_scans(
    skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)
):
    service = ScanService(db)
    scans = await service.get_all(skip=skip, limit=limit)
    return scans


@router.get("/{scan_id}", response_model=Scan)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    service = ScanService(db)
    scan = await service.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
