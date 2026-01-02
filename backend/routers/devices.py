from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from core.database import get_db
from services.device_service import DeviceService
from schemas.device import Device, DeviceWithVulnerabilities

router = APIRouter()


@router.get("/", response_model=List[Device])
async def get_devices(
    skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)
):
    service = DeviceService(db)
    devices = await service.get_all(skip=skip, limit=limit)
    return devices


@router.get("/{device_id}", response_model=DeviceWithVulnerabilities)
async def get_device(device_id: int, db: AsyncSession = Depends(get_db)):
    service = DeviceService(db)
    device = await service.get_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.delete("/{device_id}")
async def delete_device(device_id: int, db: AsyncSession = Depends(get_db)):
    service = DeviceService(db)
    deleted = await service.delete(device_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"message": "Device deleted successfully"}
