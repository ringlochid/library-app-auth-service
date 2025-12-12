from pydantic import AnyUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    DATABASE_URL: AnyUrl
    REDIS_URL: AnyUrl

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
    RATE_LIMIT_VERIFICATION_EMAIL_CAPACITY: int = 1
    RATE_LIMIT_VERIFICATION_EMAIL_REFILL_TOKENS: int = 1
    RATE_LIMIT_VERIFICATION_EMAIL_REFILL_PERIOD_SECONDS: int = 60
    EMAIL_VERIFY_BASE_URL: str = "https://localhost:8000/verify-email?token="
    JWT_PRIVATE_KEY_PATH: str = "keys/private_key.pem"
    JWT_PUBLIC_KEY_PATH: str = "keys/public_key.pem"
    JWT_ALGORITHM: str = "RS256"
    JWT_ISSUER: str = "auth-service"
    JWT_AUDIENCE: str = "backend-services"
    COOKIE_SECURE: bool = False
    MAIL_FROM: str = "no-reply@example.com"
    MAIL_HOST: str | None = None
    MAIL_PORT: int = 587
    MAIL_USER: str | None = None
    MAIL_PASSWORD: str | None = None


settings = Settings()
