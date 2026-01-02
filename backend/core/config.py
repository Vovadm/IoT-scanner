from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    postgres_user: str
    postgres_password: str
    postgres_db: str
    postgres_host: str
    postgres_port: int = 5432

    secret_key: str
    cors_origins: List[str] = [
        "http://localhost:3000",
        "http://frontend:3000",
    ]

    @property
    def database_url(self) -> str:
        return f"postgresql://{self.postgres_user}:{self.postgres_password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
