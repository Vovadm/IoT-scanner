from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn
import logging

from core.database import Base, engine
from core.config import settings
from routers import devices, scans, vulnerabilities

# Настраиваем логирование
logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle события приложения
    Создает таблицы БД при запуске
    """
    # Вывод DATABASE_URL в лог при старте приложения
    logging.info(f"DATABASE_URL: {settings.database_url}")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(
    title="IoT Scanner API",
    description="API для сканирования IoT устройств и обнаружения уязвимостей",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins or [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(
    vulnerabilities.router,
    prefix="/api/vulnerabilities",
    tags=["vulnerabilities"],
)


@app.get("/")
async def root():
    return {"message": "IoT Scanner API", "version": "1.0.0"}


@app.get("/api/health")
async def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
