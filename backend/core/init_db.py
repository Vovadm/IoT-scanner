import logging
from typing import List, Dict, Any

from sqlalchemy.exc import SQLAlchemyError

from core.database import Base, engine, SessionLocal
import models  # noqa: F401
from models.device import Device

logger = logging.getLogger("init_db")


def _sample_devices() -> List[Dict[str, Any]]:
    """
    Возвращает список примерных устройств для первоначального заполнения БД.
    Можно дополнить или изменить по необходимости.
    """
    return [
        {
            "ip_address": "192.168.1.101",
            "mac_address": "00:11:22:33:44:55",
            "hostname": "office-printer-01",
            "device_type": "Printer",
            "manufacturer": "HP",
            "model": "LaserJet Pro M404",
            "operating_system": "Embedded Linux",
            "open_ports": [
                {
                    "port": 80,
                    "service": "http",
                    "product": "HP HTTP Server",
                    "version": "1.0",
                    "banner": "HP Printer Web Interface",
                },
                {
                    "port": 631,
                    "service": "ipp",
                    "product": "IPP",
                    "version": "",
                    "banner": "Internet Printing Protocol",
                },
                {
                    "port": 9100,
                    "service": "jetdirect",
                    "product": "HP JetDirect",
                    "version": "",
                    "banner": "Raw printing (9100)",
                },
            ],
            "extra_info": {
                "http": {
                    "headers": {"server": "HP-Web"},
                    "title": "HP LaserJet Pro M404",
                },
            },
        },
        {
            "ip_address": "192.168.1.102",
            "mac_address": "66:77:88:99:AA:BB",
            "hostname": "frontdoor-cam",
            "device_type": "Camera/IP Camera",
            "manufacturer": "Dahua",
            "model": "IPC-HDW5231",
            "operating_system": "RTOS",
            "open_ports": [
                {
                    "port": 80,
                    "service": "http",
                    "product": "Embedded Web Server",
                    "version": "2.3",
                    "banner": "Dahua Web UI",
                },
                {
                    "port": 554,
                    "service": "rtsp",
                    "product": "RTSP",
                    "version": "",
                    "banner": "Real Time Streaming Protocol",
                },
                {
                    "port": 8899,
                    "service": "onvif",
                    "product": "ONVIF",
                    "version": "",
                    "banner": "ONVIF service",
                },
            ],
            "extra_info": {
                "ssdp": [
                    {
                        "location": "http://192.168.1.102:80/description.xml",
                        "server": "Dahua/1.0",
                    }
                ],
                "http": {
                    "headers": {"server": "Dahua-Cam"},
                    "title": "Front Door Camera",
                },
            },
        },
    ]


def init_db() -> None:
    """
    Создаёт таблицы (если ещё не созданы) и добавляет примерные устройства
    при старте приложения (если таких IP ещё нет).
    """
    logger.info("📦 TABLES BEFORE: %s", list(Base.metadata.tables.keys()))

    # создаём таблицы
    Base.metadata.create_all(bind=engine)

    logger.info("📦 TABLES AFTER: %s", list(Base.metadata.tables.keys()))

    # пытаемся открыть синхронную сессию для простого initial seed
    try:
        session = SessionLocal()
    except Exception as e:
        logger.exception("Не удалось создать DB session: %s", e)
        return

    samples = _sample_devices()

    try:
        for s in samples:
            ip = s.get("ip_address")
            if not ip:
                continue

            # проверяем, есть ли уже устройство с таким IP
            existing = session.query(Device).filter_by(ip_address=ip).first()
            if existing:
                logger.info("Sample device %s already exists, skipping", ip)
                continue

            device = Device(
                ip_address=s["ip_address"],
                mac_address=s.get("mac_address"),
                hostname=s.get("hostname"),
                device_type=s.get("device_type"),
                manufacturer=s.get("manufacturer"),
                model=s.get("model"),
                operating_system=s.get("operating_system"),
                open_ports=s.get("open_ports"),
                extra_info=s.get("extra_info"),
            )
            session.add(device)
            logger.info("Added sample device %s (%s)", ip, s.get("hostname"))

        session.commit()
        logger.info("Sample devices inserted (if they did not exist)")
    except SQLAlchemyError as e:
        session.rollback()
        logger.exception("Ошибка при вставке примерных устройств: %s", e)
    except Exception as e:
        session.rollback()
        logger.exception("Unexpected error while seeding sample devices: %s", e)
    finally:
        session.close()
