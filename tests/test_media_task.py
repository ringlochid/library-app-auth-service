import io
import uuid

import asyncio
import boto3
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from botocore.exceptions import ClientError
from moto import mock_aws
from PIL import Image
from unittest.mock import AsyncMock

from app.models import Base, User
from app.tasks.media import process_upload
from app.settings import settings


@mock_aws
def test_process_upload_promotes_and_updates_user(monkeypatch):
    """
    Happy-path: tmp upload is scanned, resized, moved to final key, tmp deleted, and user updated.
    """
    # Avoid touching real Redis/AV during the test.
    async def fake_init_redis():
        return None


    monkeypatch.setattr("app.tasks.media.init_redis", fake_init_redis)
    monkeypatch.setattr("app.cache.delete_cached_user_info", AsyncMock())
    monkeypatch.setattr("app.cache.delete_cached_user_profile", AsyncMock())
    monkeypatch.setattr(settings, "CLAMAV_HOST", None)

    monkeypatch.setattr(settings, "S3_MEDIA_BUCKET", "test-bucket")
    monkeypatch.setattr(settings, "S3_MEDIA_REGION", "us-east-1")
    monkeypatch.setattr(settings, "AVATAR_MAX_BYTES", 5 * 1024 * 1024)
    monkeypatch.setattr(settings, "AVATAR_TARGET_SIZES", [256, 128])
    monkeypatch.setattr(settings, "AVATAR_OUTPUT_FORMAT", "PNG")

    # Use a throwaway async engine/session (Postgres) to avoid loop reuse issues.
    test_engine = create_async_engine(
        str(settings.DATABASE_URL), future=True, poolclass=NullPool
    )
    TestSessionLocal = async_sessionmaker(test_engine, expire_on_commit=False)
    monkeypatch.setattr("app.tasks.media.AsyncSessionLocal", TestSessionLocal)

    async def setup_user():
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with TestSessionLocal() as session:
            user = User(
                id=user_id,
                name=f"user-{user_id}",
                email=f"{user_id}@example.com",
                hashed_password="x",
            )
            session.add(user)
            await session.commit()

    user_id = uuid.uuid4()
    asyncio.run(setup_user())

    # Prepare a sample JPEG upload in tmp.
    img_buf = io.BytesIO()
    Image.new("RGB", (800, 600), color="red").save(img_buf, format="JPEG")
    img_buf.seek(0)

    tmp_key = f"tmp/avatars/{user_id}/{uuid.uuid4()}"
    s3 = boto3.client("s3", region_name=settings.S3_MEDIA_REGION)
    s3.create_bucket(Bucket=settings.S3_MEDIA_BUCKET)
    s3.put_object(
        Bucket=settings.S3_MEDIA_BUCKET,
        Key=tmp_key,
        Body=img_buf.getvalue(),
        ContentType="image/jpeg",
    )

    result = process_upload(tmp_key)

    assert result["status"] == "ok"
    assert result["user_id"] == str(user_id)
    assert set(result["variants"].keys()) == {256, 128}
    assert result["primary_size"] == 256
    assert result["final_key"] == result["variants"][256]["key"]

    # Final object exists with the returned key and content type.
    final_meta = s3.head_object(
        Bucket=settings.S3_MEDIA_BUCKET, Key=result["final_key"]
    )
    assert final_meta["ContentType"] == result["content_type"]

    # Smaller variant exists.
    variant_128 = result["variants"][128]["key"]
    v128_meta = s3.head_object(Bucket=settings.S3_MEDIA_BUCKET, Key=variant_128)
    assert v128_meta["ContentType"] == result["variants"][128]["content_type"]

    # Tmp object should be removed.
    with pytest.raises(ClientError):
        s3.head_object(Bucket=settings.S3_MEDIA_BUCKET, Key=tmp_key)

    # User avatar_key updated.
    async def fetch_user():
        async with TestSessionLocal() as session:
            return await session.get(User, user_id)

    refreshed = asyncio.run(fetch_user())
    assert refreshed is not None
    assert refreshed.avatar_key == result["final_key"]


@mock_aws
def test_process_upload_handles_portrait_and_alpha(monkeypatch):
    """
    Ensure portrait images with alpha are center-cropped to square variants and retain content type.
    """
    async def fake_init_redis():
        return None


    monkeypatch.setattr("app.tasks.media.init_redis", fake_init_redis)
    monkeypatch.setattr("app.cache.delete_cached_user_info", AsyncMock())
    monkeypatch.setattr("app.cache.delete_cached_user_profile", AsyncMock())
    monkeypatch.setattr(settings, "CLAMAV_HOST", None)

    monkeypatch.setattr(settings, "S3_MEDIA_BUCKET", "test-bucket")
    monkeypatch.setattr(settings, "S3_MEDIA_REGION", "us-east-1")
    monkeypatch.setattr(settings, "AVATAR_MAX_BYTES", 5 * 1024 * 1024)
    monkeypatch.setattr(settings, "AVATAR_TARGET_SIZES", [128])
    monkeypatch.setattr(settings, "AVATAR_OUTPUT_FORMAT", "PNG")

    test_engine = create_async_engine(
        str(settings.DATABASE_URL), future=True, poolclass=NullPool
    )
    TestSessionLocal = async_sessionmaker(test_engine, expire_on_commit=False)
    monkeypatch.setattr("app.tasks.media.AsyncSessionLocal", TestSessionLocal)

    async def setup_user():
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with TestSessionLocal() as session:
            user = User(
                id=user_id,
                name=f"user-{user_id}",
                email=f"{user_id}@example.com",
                hashed_password="x",
            )
            session.add(user)
            await session.commit()

    user_id = uuid.uuid4()
    asyncio.run(setup_user())

    img_buf = io.BytesIO()
    Image.new("RGBA", (600, 1200), color=(255, 0, 0, 128)).save(img_buf, format="PNG")
    img_buf.seek(0)

    tmp_key = f"tmp/avatars/{user_id}/{uuid.uuid4()}"
    s3 = boto3.client("s3", region_name=settings.S3_MEDIA_REGION)
    s3.create_bucket(Bucket=settings.S3_MEDIA_BUCKET)
    s3.put_object(
        Bucket=settings.S3_MEDIA_BUCKET,
        Key=tmp_key,
        Body=img_buf.getvalue(),
        ContentType="image/png",
    )

    result = process_upload(tmp_key)

    assert result["status"] == "ok"
    assert result["primary_size"] == 128
    assert set(result["variants"].keys()) == {128}
    variant = result["variants"][128]
    assert variant["width"] == 128 and variant["height"] == 128
    assert variant["content_type"] == "image/png"

    # Tmp object should be removed.
    with pytest.raises(ClientError):
        s3.head_object(Bucket=settings.S3_MEDIA_BUCKET, Key=tmp_key)
