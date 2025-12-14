"""
Tests for UserRead schema, particularly avatar_urls computed field.
"""
import uuid
from datetime import datetime, timezone

import pytest

from app.schemas.user import UserRead
from app.settings import settings


# Helper function to create complete user data with all required fields
def create_user_data(
    user_id=None,
    name="testuser",
    email="test@example.com",
    is_active=True,
    is_admin=False,
    is_blacklisted=False,
    roles=None,
    trust_score=0,
    reputation_percentage=100.0,
    scopes=None,
    avatar_key=None,
):
    """Create complete user data dict with all required fields."""
    if user_id is None:
        user_id = uuid.uuid4()
    if roles is None:
        roles = ["user"]
    if scopes is None:
        scopes = []
    
    now = datetime.now(timezone.utc)
    return {
        "id": user_id,
        "name": name,
        "email": email,
        "created_at": now,
        "updated_at": now,
        "is_active": is_active,
        "is_admin": is_admin,
        "is_blacklisted": is_blacklisted,
        "roles": roles,
        "trust_score": trust_score,
        "reputation_percentage": reputation_percentage,
        "scopes": scopes,
        "avatar_key": avatar_key,
    }


def test_avatar_urls_generated_correctly(monkeypatch):
    """
    Test that avatar_urls computes all size variants with correct S3 URLs.
    """
    monkeypatch.setattr(settings, "S3_MEDIA_BUCKET", "test-bucket")
    monkeypatch.setattr(settings, "S3_MEDIA_REGION", "us-east-1")
    monkeypatch.setattr(settings, "AVATAR_TARGET_SIZES", [512, 256, 128, 64])

    user_data = create_user_data(avatar_key="avatars/550e8400-e29b/a1b2c3d4/512.webp")
    user = UserRead(**user_data)

    assert user.avatar_urls is not None
    assert len(user.avatar_urls) == 4
    
    # All sizes should be present
    assert "512" in user.avatar_urls
    assert "256" in user.avatar_urls
    assert "128" in user.avatar_urls
    assert "64" in user.avatar_urls

    # URLs should follow the pattern
    expected_base = "https://test-bucket.s3.us-east-1.amazonaws.com/avatars/550e8400-e29b/a1b2c3d4"
    assert user.avatar_urls["512"] == f"{expected_base}/512.webp"
    assert user.avatar_urls["256"] == f"{expected_base}/256.webp"
    assert user.avatar_urls["128"] == f"{expected_base}/128.webp"
    assert user.avatar_urls["64"] == f"{expected_base}/64.webp"


def test_avatar_urls_with_jpg_extension(monkeypatch):
    """
    Test avatar_urls works with different image formats (jpg).
    """
    monkeypatch.setattr(settings, "S3_MEDIA_BUCKET", "test-bucket")
    monkeypatch.setattr(settings, "S3_MEDIA_REGION", "ap-southeast-2")
    monkeypatch.setattr(settings, "AVATAR_TARGET_SIZES", [512, 256, 128, 64])

    user_data = create_user_data(name="jpguser", email="jpg@example.com", avatar_key="avatars/user-id/uuid-123/512.jpg")
    user = UserRead(**user_data)

    assert user.avatar_urls is not None
    expected_base = "https://test-bucket.s3.ap-southeast-2.amazonaws.com/avatars/user-id/uuid-123"
    assert user.avatar_urls["512"] == f"{expected_base}/512.jpg"
    assert user.avatar_urls["256"] == f"{expected_base}/256.jpg"
    assert user.avatar_urls["128"] == f"{expected_base}/128.jpg"
    assert user.avatar_urls["64"] == f"{expected_base}/64.jpg"


def test_avatar_urls_returns_none_when_no_key(monkeypatch):
    """
    Test that avatar_urls is None when avatar_key is not set.
    """
    monkeypatch.setattr(settings, "S3_MEDIA_BUCKET", "test-bucket")
    monkeypatch.setattr(settings, "S3_MEDIA_REGION", "us-east-1")

    user_data = create_user_data(name="noavataruser", email="noavatar@example.com", avatar_key=None)
    user = UserRead(**user_data)
    assert user.avatar_urls is None


def test_avatar_urls_returns_none_when_s3_bucket_not_configured(monkeypatch):
    """
    Test that avatar_urls returns None when S3_MEDIA_BUCKET is not configured.
    """
    monkeypatch.setattr(settings, "S3_MEDIA_BUCKET", None)
    monkeypatch.setattr(settings, "S3_MEDIA_REGION", "us-east-1")

    user_data = create_user_data(name="noS3user", email="nos3@example.com", avatar_key="avatars/user-id/uuid-123/512.webp")
    user = UserRead(**user_data)
    assert user.avatar_urls is None


def test_avatar_urls_returns_none_when_s3_region_not_configured(monkeypatch):
    """
    Test that avatar_urls returns None when S3_MEDIA_REGION is not configured.
    """
    monkeypatch.setattr(settings, "S3_MEDIA_BUCKET", "test-bucket")
    monkeypatch.setattr(settings, "S3_MEDIA_REGION", None)

    user_data = create_user_data(name="noregionuser", email="noregion@example.com", avatar_key="avatars/user-id/uuid-123/512.webp")
    user = UserRead(**user_data)
    assert user.avatar_urls is None


def test_avatar_urls_handles_malformed_key(monkeypatch):
    """
    Test that avatar_urls gracefully handles malformed keys (no extension).
    """
    monkeypatch.setattr(settings, "S3_MEDIA_BUCKET", "test-bucket")
    monkeypatch.setattr(settings, "S3_MEDIA_REGION", "us-east-1")

    user_data = create_user_data(name="malformeduser", email="malformed@example.com", avatar_key="avatars/user-id/uuid-123/512")
    user = UserRead(**user_data)
    # Should gracefully return None for invalid key format
    assert user.avatar_urls is None


def test_avatar_urls_handles_malformed_key_no_slash(monkeypatch):
    """
    Test that avatar_urls handles keys without proper structure.
    """
    monkeypatch.setattr(settings, "S3_MEDIA_BUCKET", "test-bucket")
    monkeypatch.setattr(settings, "S3_MEDIA_REGION", "us-east-1")

    user_data = create_user_data(name="invalidkeyuser", email="invalidkey@example.com", avatar_key="singlepartkey.webp")
    user = UserRead(**user_data)
    # Should gracefully return None for invalid key format
    assert user.avatar_urls is None


def test_avatar_urls_respects_dynamic_target_sizes(monkeypatch):
    """
    Test that avatar_urls respects AVATAR_TARGET_SIZES configuration.
    """
    monkeypatch.setattr(settings, "S3_MEDIA_BUCKET", "test-bucket")
    monkeypatch.setattr(settings, "S3_MEDIA_REGION", "us-east-1")
    # Custom sizes: only 256 and 128
    monkeypatch.setattr(settings, "AVATAR_TARGET_SIZES", [256, 128])

    user_data = create_user_data(name="customsizesuser", email="customsizes@example.com", avatar_key="avatars/user-id/uuid-123/256.webp")
    user = UserRead(**user_data)

    assert user.avatar_urls is not None
    # Should only have 256 and 128, not 512 or 64
    assert len(user.avatar_urls) == 2
    assert "256" in user.avatar_urls
    assert "128" in user.avatar_urls
    assert "512" not in user.avatar_urls
    assert "64" not in user.avatar_urls
