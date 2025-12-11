from pydantic import BaseSettings, AnyUrl


class Settings(BaseSettings):
    DATABASE_URL: AnyUrl
    REDIS_URL: AnyUrl

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_TTL_DAYS: int = 7
    JWT_PRIVATE_KEY_PATH: str = "keys/private_key.pem"
    JWT_PUBLIC_KEY_PATH: str = "keys/public_key.pem"
    JWT_ALGORITHM: str = "RS256"
    JWT_ISSUER: str = "auth-service"
    JWT_AUDIENCE: str = "backend-services"
    COOKIE_SECURE: bool = False

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
