
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "AegisFlow"
    APP_ENV: str = "development"
    API_V1_PREFIX: str = "/api/v1"
    CORS_ORIGINS: list[str] = ["http://localhost:5173"]

    DATABASE_URL: str = "postgresql+psycopg://aegisflow_user:change_this_dev_password@localhost:5432/aegisflow"
    REDIS_URL: str = "redis://localhost:6379/0"

    SECRET_KEY: str = "replace_with_a_long_random_secret_at_least_32_characters"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    ALGORITHM: str = "HS256"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
