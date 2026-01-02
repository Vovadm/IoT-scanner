from typing import Generic, TypeVar, Type, Optional, List, cast
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from core.database import Base
from sqlalchemy.engine import Result

ModelType = TypeVar("ModelType", bound=Base)  # type: ignore


class BaseRepository(Generic[ModelType]):
    def __init__(self, model: Type[ModelType], session: AsyncSession):
        self.model = model
        self.session = session

    async def get_by_id(self, id: int) -> Optional[ModelType]:
        result: Result = await self.session.execute(
            select(self.model).where(self.model.id == id)
        )
        return result.scalar_one_or_none()

    async def get_all(
        self, skip: int = 0, limit: int = 100
    ) -> List[ModelType]:
        result: Result = await self.session.execute(
            select(self.model).offset(skip).limit(limit)
        )
        return cast(List[ModelType], result.scalars().all())

    async def create(self, **kwargs) -> ModelType:
        instance = self.model(**kwargs)
        self.session.add(instance)
        await self.session.flush()
        await self.session.refresh(instance)
        return instance

    async def update(self, id: int, **kwargs) -> Optional[ModelType]:
        await self.session.execute(
            update(self.model).where(self.model.id == id).values(**kwargs)
        )
        await self.session.flush()
        return await self.get_by_id(id)

    async def delete(self, id: int) -> bool:
        result: Result = await self.session.execute(
            delete(self.model).where(self.model.id == id)
        )
        await self.session.flush()
        return getattr(result, "rowcount", 0) > 0

    async def get_by_field(
        self, field_name: str, value: object
    ) -> Optional[ModelType]:
        field = getattr(self.model, field_name)
        result: Result = await self.session.execute(
            select(self.model).where(field == value)
        )
        return result.scalar_one_or_none()
