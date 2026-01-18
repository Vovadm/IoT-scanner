import logging

import models  # noqa: F401
from core.database import Base, engine


def init_db() -> None:
    logging.info("📦 TABLES BEFORE: %s", list(Base.metadata.tables.keys()))
    Base.metadata.create_all(bind=engine)
    logging.info("📦 TABLES AFTER: %s", list(Base.metadata.tables.keys()))
