import logging

from core.database import Base, engine
import models  # noqa: F401


def init_db() -> None:
    logging.info("📦 TABLES BEFORE: %s", list(Base.metadata.tables.keys()))
    Base.metadata.create_all(bind=engine)
    logging.info("📦 TABLES AFTER: %s", list(Base.metadata.tables.keys()))
