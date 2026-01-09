import os
from pydantic import AnyUrl, field_validator, ValidationInfo
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    BACKEND_CORS_ORIGINS: list[str] | str = []

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(
        cls, v: str | list[str], info: ValidationInfo
    ) -> list[str] | str:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    DATABASE_URL: AnyUrl
    DATABASE_WORKER_URL: AnyUrl | None = None  # Separate URL for Celery workers
    REDIS_URL: AnyUrl | None = None
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    EMAIL_VERIFY_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_TTL_DAYS: int = 7
    CACHE_DEFAULT_TTL_SECONDS: int = 900
    UNVERIFIED_USER_EXPIRE_DAYS: int = 3
    RATE_LIMIT_LOGIN_CAPACITY: int = 5
    RATE_LIMIT_LOGIN_REFILL_TOKENS: int = 5
    RATE_LIMIT_LOGIN_REFILL_PERIOD_SECONDS: int = 60
    RATE_LIMIT_REGISTER_CAPACITY: int = 3
    RATE_LIMIT_REGISTER_REFILL_TOKENS: int = 3
    RATE_LIMIT_REGISTER_REFILL_PERIOD_SECONDS: int = 60
    RATE_LIMIT_VERIFY_SEND_CAPACITY: int = 5
    RATE_LIMIT_VERIFY_SEND_REFILL_TOKENS: int = 5
    RATE_LIMIT_VERIFY_SEND_REFILL_PERIOD_SECONDS: int = 300
    RATE_LIMIT_VERIFY_DOMAIN_CAPACITY: int = 10
    RATE_LIMIT_VERIFY_DOMAIN_REFILL_TOKENS: int = 10
    RATE_LIMIT_VERIFY_DOMAIN_REFILL_PERIOD_SECONDS: int = 300
    RATE_LIMIT_VERIFY_EMAIL_CAPACITY: int = 3
    RATE_LIMIT_VERIFY_EMAIL_REFILL_TOKENS: int = 3
    RATE_LIMIT_VERIFY_EMAIL_REFILL_PERIOD_SECONDS: int = 300
    RATE_LIMIT_REFRESH_CAPACITY: int = 30
    RATE_LIMIT_REFRESH_REFILL_TOKENS: int = 30
    RATE_LIMIT_REFRESH_REFILL_PERIOD_SECONDS: int = 60
    RATE_LIMIT_AVATAR_UPLOAD_CAPACITY: int = 2
    RATE_LIMIT_AVATAR_UPLOAD_REFILL_TOKENS: int = 2
    RATE_LIMIT_AVATAR_UPLOAD_REFILL_PERIOD_SECONDS: int = 600
    RATE_LIMIT_AVATAR_COMMIT_CAPACITY: int = 4
    RATE_LIMIT_AVATAR_COMMIT_REFILL_TOKENS: int = 4
    RATE_LIMIT_AVATAR_COMMIT_REFILL_PERIOD_SECONDS: int = 600
    RATE_LIMIT_SUBMISSION_ADJUST_CAPACITY: int = 10
    RATE_LIMIT_SUBMISSION_ADJUST_REFILL_TOKENS: int = 10
    RATE_LIMIT_SUBMISSION_ADJUST_REFILL_PERIOD_SECONDS: int = 3600
    RATE_LIMIT_TRUST_ADJUST_CAPACITY: int = 10
    RATE_LIMIT_TRUST_ADJUST_REFILL_TOKENS: int = 10
    RATE_LIMIT_TRUST_ADJUST_REFILL_PERIOD_SECONDS: int = 3600
    RATE_LIMIT_USER_CHECK_CAPACITY: int = 60
    RATE_LIMIT_USER_CHECK_REFILL_TOKENS: int = 60
    RATE_LIMIT_USER_CHECK_REFILL_PERIOD_SECONDS: int = 60
    RATE_LIMIT_USER_UPDATE_CAPACITY: int = 3
    RATE_LIMIT_USER_UPDATE_REFILL_TOKENS: int = 3
    RATE_LIMIT_USER_UPDATE_REFILL_PERIOD_SECONDS: int = 3600
    EMAIL_VERIFY_BASE_URL: str = "https://localhost:8000/verify-email?token="
    JWT_PRIVATE_KEY_PATH: str = "keys/private_key.pem"
    JWT_PUBLIC_KEY_PATH: str = "keys/public_key.pem"
    JWT_ALGORITHM: str = "RS256"
    JWT_ISSUER: str = "auth-service"
    JWT_AUDIENCE: str = "backend-services"
    COOKIE_SECURE: bool = False
    MAIL_FROM: str = "no-reply@example.com"
    CELERY_BROKER_URL: str | None = None
    CELERY_RESULT_BACKEND: str | None = None
    CELERY_TASK_DEFAULT_QUEUE: str = "default"
    CELERY_TIMEZONE: str = "UTC"
    # Media / avatar uploads
    S3_MEDIA_BUCKET: str | None = None
    S3_MEDIA_REGION: str | None = None
    AVATAR_UPLOAD_EXPIRES_SECONDS: int = 600
    AVATAR_MAX_BYTES: int = 2 * 1024 * 1024
    AVATAR_ALLOWED_MIME_TYPES: list[str] = [
        "image/jpeg",
        "image/png",
        "image/webp",
    ]
    AVATAR_MAX_PIXELS: int = 25_000_000
    AVATAR_TARGET_SIZES: list[int] = [512, 256, 128, 64]
    AVATAR_RESIZE_MAX_SIDE: int = 512
    AVATAR_UPSCALE_MAX: float = 2.0
    AVATAR_OUTPUT_FORMAT: str = "WEBP"
    AVATAR_JPEG_QUALITY: int = 85
    CLAMAV_HOST: str | None = None
    CLAMAV_PORT: int = 3310
    ALEMBIC_DATABASE_URL: str | None = None
    # Phase 2: Trust & roles
    SERVICE_API_KEY: str | None = None  # Shared secret for service-to-service auth
    ROLE_UPGRADE_DELAY_SECONDS: int = 900  # 15 minutes default
    AWS_REGION: str | None = "ap-southeast-2"


settings = Settings()
