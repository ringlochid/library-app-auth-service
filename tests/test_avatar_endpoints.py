import io
import uuid

import boto3
import pytest
from fastapi import status
from httpx import ASGITransport, AsyncClient
from moto import mock_aws
from PIL import Image

from app.main import app
from app.security import get_current_user_with_access_token
from app.services.storage import get_s3_client
from app.redis_client import get_redis
from app.settings import settings


class DummyUser:
    def __init__(self, user_id: uuid.UUID):
        self.id = user_id


class FakeRedis:
    def __init__(self):
        self.kv_store = {}
        self.hash_store = {}

    async def hgetall(self, key):
        return self.hash_store.get(key, {})

    async def hset(self, key, mapping):
        self.hash_store.setdefault(key, {}).update({k: str(v) for k, v in mapping.items()})

    async def expire(self, key, seconds):
        # TTL tracking not needed for these tests.
        return True

    async def set(self, key, value, ex=None):
        self.kv_store[key] = value

    async def get(self, key):
        return self.kv_store.get(key)

    async def delete(self, key):
        self.kv_store.pop(key, None)

    async def exists(self, key):
        return 1 if key in self.kv_store else 0

    def pipeline(self):
        return _FakePipeline(self)


class _FakePipeline:
    def __init__(self, redis_client: FakeRedis):
        self.redis = redis_client
        self.ops = []

    def get(self, key):
        self.ops.append(("get", key))
        return self

    def delete(self, key):
        self.ops.append(("delete", key))
        return self

    async def execute(self):
        results = []
        for op, key in self.ops:
            if op == "get":
                results.append(await self.redis.get(key))
            elif op == "delete":
                await self.redis.delete(key)
                results.append(1)
        return results


class DummyTask:
    def delay(self, key):
        return {"queued": key}


@pytest.mark.asyncio
async def test_avatar_upload_and_commit_happy_path(monkeypatch):
    user = DummyUser(uuid.uuid4())

    async def fake_current_user():
        return user

    settings.S3_MEDIA_BUCKET = "test-bucket"
    settings.S3_MEDIA_REGION = "us-east-1"
    settings.AVATAR_ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"]

    with mock_aws():
        s3 = boto3.client("s3", region_name=settings.S3_MEDIA_REGION)
        s3.create_bucket(Bucket=settings.S3_MEDIA_BUCKET)
        monkeypatch.setattr("app.tasks.media.process_upload", DummyTask())

        fake_redis = FakeRedis()

        async def override_get_redis():
            return fake_redis

        async def override_get_s3_client():
            return s3

        app.dependency_overrides.update(
            {
                get_current_user_with_access_token: fake_current_user,
                get_redis: override_get_redis,
                get_s3_client: override_get_s3_client,
            }
        )

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
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
        finally:
            app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_avatar_commit_rejects_bad_mime(monkeypatch):
    user = DummyUser(uuid.uuid4())

    async def fake_current_user():
        return user

    settings.S3_MEDIA_BUCKET = "test-bucket"
    settings.S3_MEDIA_REGION = "us-east-1"
    with mock_aws():
        s3 = boto3.client("s3", region_name=settings.S3_MEDIA_REGION)
        s3.create_bucket(Bucket=settings.S3_MEDIA_BUCKET)
        monkeypatch.setattr("app.tasks.media.process_upload", DummyTask())

        fake_redis = FakeRedis()

        async def override_get_redis():
            return fake_redis

        async def override_get_s3_client():
            return s3

        app.dependency_overrides.update(
            {
                get_current_user_with_access_token: fake_current_user,
                get_redis: override_get_redis,
                get_s3_client: override_get_s3_client,
            }
        )

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
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
                assert resp2.status_code == status.HTTP_400_BAD_REQUEST
        finally:
            app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_avatar_commit_rate_limit(monkeypatch):
    user = DummyUser(uuid.uuid4())

    async def fake_current_user():
        return user

    settings.S3_MEDIA_BUCKET = "test-bucket"
    settings.S3_MEDIA_REGION = "us-east-1"
    with mock_aws():
        s3 = boto3.client("s3", region_name=settings.S3_MEDIA_REGION)
        s3.create_bucket(Bucket=settings.S3_MEDIA_BUCKET)
        monkeypatch.setattr("app.tasks.media.process_upload", DummyTask())

        monkeypatch.setattr(settings, "RATE_LIMIT_AVATAR_COMMIT_CAPACITY", 1)
        monkeypatch.setattr(settings, "RATE_LIMIT_AVATAR_COMMIT_REFILL_TOKENS", 1)
        monkeypatch.setattr(settings, "RATE_LIMIT_AVATAR_COMMIT_REFILL_PERIOD_SECONDS", 60)

        fake_redis = FakeRedis()

        async def override_get_redis():
            return fake_redis

        async def override_get_s3_client():
            return s3

        app.dependency_overrides.update(
            {
                get_current_user_with_access_token: fake_current_user,
                get_redis: override_get_redis,
                get_s3_client: override_get_s3_client,
            }
        )

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/auth/avatar/upload", json={"content_type": "image/jpeg"}
                )
                data = resp.json()
                key = data["key"]
                s3.put_object(
                    Bucket=settings.S3_MEDIA_BUCKET,
                    Key=key,
                    Body=b"xx",
                    ContentType="image/jpeg",
                )
                await client.post("/auth/avatar/commit", json={"key": key})
                resp2 = await client.post("/auth/avatar/commit", json={"key": key})
                assert resp2.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        finally:
            app.dependency_overrides.clear()
