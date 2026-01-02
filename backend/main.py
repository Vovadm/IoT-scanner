import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from core.init_db import init_db
from routers import devices, scans, vulnerabilities

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.info("🔥 INIT DB START")
    init_db()
    logging.info("✅ INIT DB DONE")
    yield


app = FastAPI(
    title="IoT Scanner API",
    description="API для сканирования IoT устройств",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins or [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(
    vulnerabilities.router,
    prefix="/api/vulnerabilities",
    tags=["vulnerabilities"],
)


@app.get("/")
def root():
    return {"message": "IoT Scanner API"}


@app.get("/api/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
