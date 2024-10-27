from pathlib import Path

from pydantic import PostgresDsn
from pydantic_settings import BaseSettings
from pydantic_settings import SettingsConfigDict

BASE_DIR = Path(__file__).parent.parent.parent


class Settings(BaseSettings):
    DB_HOST: str
    DB_PORT: int
    DB_NAME: str
    DB_USER: str
    DB_PASS: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    DATABASE_URL: PostgresDsn
    ADMIN_PASSWORD: str
    ADMIN_USERNAME: str
    ADMIN_EMAIL: str

    model_config = SettingsConfigDict(env_file=BASE_DIR / ".env")


settings = Settings()


class AuthSettings(BaseSettings):
    private_key_path: Path = BASE_DIR / "certs" / "private.pem"
    public_key_path: Path = BASE_DIR / "certs" / "public.pem"
    algorithm: str = "RS256"
    access_token_expire_minutes: int = 15


auth_settings = AuthSettings()
