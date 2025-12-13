import io
import uuid

import boto3
import asyncio

import boto3
import pytest
from botocore.exceptions import ClientError
from fastapi import status
from httpx import AsyncClient
from moto import mock_aws
from PIL import Image

from app.main import app
from app.models import Base, User
from app.settings import settings
from app.database import engine, AsyncSessionLocal
from app.security import _now_utc


@pytest.fixture(autouse=True)
def setup_db():
    asyncio.run(_create_schema())
    yield
    asyncio.run(_drop_schema())


async def _create_schema():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def _drop_schema():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


def seed_user():
    async def _seed():
        async with AsyncSessionLocal() as session:
            user_id = uuid.uuid4()
            user = User(
                id=user_id,
                name=f"user-{user_id}",
                email=f"{user_id}@example.com",
                hashed_password="x",
                email_verified_at=_now_utc(),
            )
            session.add(user)
            await session.commit()
            return user

    return asyncio.run(_seed())


@mock_aws
def test_avatar_upload_and_commit_happy_path(monkeypatch):
    user = seed_user()

    async def fake_current_user():
        return user

    monkeypatch.setattr(
        "app.routers.auth.get_current_user_with_access_token", fake_current_user
    )

    settings.S3_MEDIA_BUCKET = "test-bucket"
    settings.S3_MEDIA_REGION = "us-east-1"
    settings.AVATAR_ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"]

    s3 = boto3.client("s3", region_name=settings.S3_MEDIA_REGION)
    s3.create_bucket(Bucket=settings.S3_MEDIA_BUCKET)

    async def _run_flow():
        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.post(
                "/auth/avatar/upload", json={"content_type": "image/jpeg"}
            )
            assert resp.status_code == status.HTTP_200_OK
            data = resp.json()
            key = data["key"]
            assert key.startswith(f"tmp/avatars/{user.id}/")

            buf = io.BytesIO()
            Image.new("RGB", (600, 400), color="green").save(buf, format="JPEG")
            buf.seek(0)
            s3.put_object(
                Bucket=settings.S3_MEDIA_BUCKET,
                Key=key,
                Body=buf.getvalue(),
                ContentType="image/jpeg",
            )

            resp2 = await client.post("/auth/avatar/commit", json={"key": key})
            assert resp2.status_code == status.HTTP_204_NO_CONTENT
            return key

    key = asyncio.run(_run_flow())

    from app.tasks.media import process_upload

    result = process_upload(key)
    assert result["status"] == "ok"
    with pytest.raises(ClientError):
        s3.head_object(Bucket=settings.S3_MEDIA_BUCKET, Key=key)


@mock_aws
def test_avatar_commit_rejects_bad_mime(monkeypatch):
    user = seed_user()

    async def fake_current_user():
        return user

    monkeypatch.setattr(
        "app.routers.auth.get_current_user_with_access_token", fake_current_user
    )

    settings.S3_MEDIA_BUCKET = "test-bucket"
    settings.S3_MEDIA_REGION = "us-east-1"
    s3 = boto3.client("s3", region_name=settings.S3_MEDIA_REGION)
    s3.create_bucket(Bucket=settings.S3_MEDIA_BUCKET)

    async def _run_flow():
        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.post(
                "/auth/avatar/upload", json={"content_type": "image/jpeg"}
            )
            assert resp.status_code == status.HTTP_200_OK
            data = resp.json()
            key = data["key"]
            s3.put_object(
                Bucket=settings.S3_MEDIA_BUCKET,
                Key=key,
                Body=b"not an image",
                ContentType="text/plain",
            )
            resp2 = await client.post("/auth/avatar/commit", json={"key": key})
            return resp2

    resp = asyncio.run(_run_flow())
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


@mock_aws
def test_avatar_commit_rate_limit(monkeypatch):
    user = seed_user()

    async def fake_current_user():
        return user

    monkeypatch.setattr(
        "app.routers.auth.get_current_user_with_access_token", fake_current_user
    )

    settings.S3_MEDIA_BUCKET = "test-bucket"
    settings.S3_MEDIA_REGION = "us-east-1"
    s3 = boto3.client("s3", region_name=settings.S3_MEDIA_REGION)
    s3.create_bucket(Bucket=settings.S3_MEDIA_BUCKET)

    monkeypatch.setattr(settings, "RATE_LIMIT_AVATAR_COMMIT_CAPACITY", 1)
    monkeypatch.setattr(settings, "RATE_LIMIT_AVATAR_COMMIT_REFILL_TOKENS", 1)
    monkeypatch.setattr(settings, "RATE_LIMIT_AVATAR_COMMIT_REFILL_PERIOD_SECONDS", 60)

    async def _run_flow():
        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.post(
                "/auth/avatar/upload", json={"content_type": "image/jpeg"}
            )
            data = resp.json()
            key = data["key"]
            s3.put_object(
                Bucket=settings.S3_MEDIA_BUCKET,
                Key=key,
                Body=b"x",
                ContentType="image/jpeg",
            )
            await client.post("/auth/avatar/commit", json={"key": key})
            resp2 = await client.post("/auth/avatar/commit", json={"key": key})
            return resp2

    resp = asyncio.run(_run_flow())
    assert resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS
