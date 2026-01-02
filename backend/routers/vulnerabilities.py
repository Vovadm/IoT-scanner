from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional

from core.database import get_db
from services.vulnerability_service import VulnerabilityService
from schemas.vulnerability import Vulnerability, VulnerabilityUpdate
from models.enums import VulnerabilitySeverity

router = APIRouter()


@router.get("/", response_model=List[Vulnerability])
async def get_vulnerabilities(
    device_id: Optional[int] = None,
    severity: Optional[VulnerabilitySeverity] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
):
    service = VulnerabilityService(db)
    vulnerabilities = await service.get_all(
        device_id=device_id, severity=severity, skip=skip, limit=limit
    )
    return vulnerabilities


@router.get("/{vulnerability_id}", response_model=Vulnerability)
async def get_vulnerability(
    vulnerability_id: int, db: AsyncSession = Depends(get_db)
):
    service = VulnerabilityService(db)
    vulnerability = await service.get_by_id(vulnerability_id)
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vulnerability


@router.patch("/{vulnerability_id}", response_model=Vulnerability)
async def update_vulnerability(
    vulnerability_id: int,
    vuln_update: VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db),
):
    service = VulnerabilityService(db)
    vulnerability = await service.update(vulnerability_id, vuln_update)
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vulnerability
