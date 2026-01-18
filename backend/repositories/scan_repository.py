from typing import List, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.enums import ScanStatus
from models.scan import Scan
from repositories.base_repository import BaseRepository


class ScanRepository(BaseRepository[Scan]):

    def __init__(self, session: AsyncSession):
        super().__init__(Scan, session)

    async def get_all_ordered(
        self, skip: int = 0, limit: int = 100
    ) -> List[Scan]:
        result = await self.session.execute(
            select(Scan)
            .order_by(desc(Scan.created_at))
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def update_status(
        self, scan_id: int, status: ScanStatus
    ) -> Optional[Scan]:
        return await self.update(scan_id, status=status)
