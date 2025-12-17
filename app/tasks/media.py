"""
Media-related tasks: validation, resize, virus scan, S3 moves.
"""
import asyncio
import io
import math
import tempfile
import uuid
from typing import Any

import boto3
from PIL import Image, ImageOps, UnidentifiedImageError
from botocore.exceptions import ClientError

from app.celery_app import app
from app.cache import delete_cached_user_info, delete_cached_user_profile
from app.database import AsyncSessionLocal
from app.models import User
from app.redis_client import init_redis
from app.settings import settings

try:
    import clamd  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    clamd = None

# Guard against image bombs; Pillow will raise if exceeded.
Image.MAX_IMAGE_PIXELS = settings.AVATAR_MAX_PIXELS


class MediaProcessingError(Exception):
    """Raised when an avatar upload fails validation or processing."""


def _allowed_extensions() -> set[str]:
    """
    Derive allowed filename extensions from allowed MIME types.
    """
    mime_to_ext = {
        "image/jpeg": {"jpg", "jpeg"},
        "image/png": {"png"},
        "image/webp": {"webp"},
        "image/avif": {"avif"},
    }
    allowed_exts: set[str] = set()
    for mime in settings.AVATAR_ALLOWED_MIME_TYPES:
        allowed_exts.update(mime_to_ext.get(mime, set()))
    return allowed_exts


def _clamd_client():
    if not settings.CLAMAV_HOST:
        return None
    if clamd is None:
        raise MediaProcessingError(
            "CLAMAV_HOST is set but the clamd package is not installed"
        )
    return clamd.ClamdNetworkSocket(
        host=settings.CLAMAV_HOST, port=settings.CLAMAV_PORT
    )


def _av_scan(file_path: str) -> None:
    """
    Perform an AV scan via clamd if configured.
    Raises MediaProcessingError on detection or scan errors.
    """
    client = _clamd_client()
    if client is None:
        return
    try:
        result = client.scan(file_path)
    except Exception as exc:  # pragma: no cover - depends on runtime AV setup
        raise MediaProcessingError(f"AV scan failed: {exc}") from exc
    if not result:
        raise MediaProcessingError("AV scan returned no result")
    status = list(result.values())[0]
    if status[0] != "OK":
        raise MediaProcessingError(f"AV scan blocked file: {status}")


def _ensure_key_and_user(key: str) -> uuid.UUID:
    """
    Validate tmp key pattern and return user_id extracted from it.
    Expected: tmp/avatars/{user_id}/{uuid}[.ext]
    """
    parts = key.split("/")
    if len(parts) != 4 or parts[0] != "tmp" or parts[1] != "avatars":
        raise MediaProcessingError("Unexpected key format")
    leaf = parts[3]
    leaf_uuid = leaf
    if "." in leaf:
        leaf_uuid, ext = leaf.rsplit(".", 1)
        # reject keys with multiple dots to avoid sneaky extensions
        if "." in leaf_uuid:
            raise MediaProcessingError("Key has an invalid filename")
        if ext.lower() not in _allowed_extensions():
            raise MediaProcessingError("Key has a disallowed file extension")
    try:
        user_id = uuid.UUID(parts[2])
    except ValueError as exc:
        raise MediaProcessingError("Key does not include a valid user id") from exc
    try:
        uuid.UUID(leaf_uuid)
    except ValueError as exc:
        raise MediaProcessingError("Key does not include a valid upload id") from exc
    return user_id


def _transform_image(
    file_path: str, header_content_type: str | None
) -> dict[int, dict[str, Any]]:
    """
    Open, normalize, and generate resized variants using a cover+center-crop strategy.
    Returns a mapping of size -> {bytes, content_type, width, height, format}.
    """
    allowed = set(settings.AVATAR_ALLOWED_MIME_TYPES)
    output_format = settings.AVATAR_OUTPUT_FORMAT.upper()
    target_sizes = sorted(
        set(settings.AVATAR_TARGET_SIZES or [settings.AVATAR_RESIZE_MAX_SIDE]),
        reverse=True,
    )
    try:
        with Image.open(file_path) as img:
            # Normalize orientation early.
            img = ImageOps.exif_transpose(img)

            mime_from_image = Image.MIME.get(img.format or "", "")
            effective_content_type = header_content_type or mime_from_image

            # prefer actual image-detected mime if the header is missing or not allowed
            if effective_content_type not in allowed and mime_from_image in allowed:
                effective_content_type = mime_from_image
            if effective_content_type not in allowed:
                raise MediaProcessingError("Unsupported image type")

            width, height = img.size
            if width * height > settings.AVATAR_MAX_PIXELS:
                raise MediaProcessingError("Image has too many pixels")

            has_alpha = "A" in img.getbands()
            variants: dict[int, dict[str, Any]] = {}

            for target in target_sizes:
                # cover resize then center crop to target x target
                scale = max(target / width, target / height)
                if settings.AVATAR_UPSCALE_MAX:
                    scale = min(scale, settings.AVATAR_UPSCALE_MAX)
                new_w = max(1, math.ceil(width * scale))
                new_h = max(1, math.ceil(height * scale))
                resized = img.resize((new_w, new_h), Image.LANCZOS)

                if resized.width >= target and resized.height >= target:
                    left = (resized.width - target) // 2
                    top = (resized.height - target) // 2
                    resized = resized.crop(
                        (left, top, left + target, top + target)
                    )

                # Ensure color space is compatible with output format
                if output_format == "JPEG":
                    resized = resized.convert("RGB")
                elif output_format in {"PNG", "WEBP"} and resized.mode not in {
                    "RGB",
                    "RGBA",
                }:
                    resized = resized.convert("RGBA" if has_alpha else "RGB")

                buffer = io.BytesIO()
                save_kwargs: dict[str, Any] = {}
                if output_format in {"JPEG", "WEBP"}:
                    save_kwargs["quality"] = settings.AVATAR_JPEG_QUALITY
                if output_format == "WEBP":
                    save_kwargs["method"] = 6
                resized.save(buffer, format=output_format, **save_kwargs)
                buffer.seek(0)

                out_content_type = f"image/{output_format.lower()}"
                if output_format == "JPEG":
                    out_content_type = "image/jpeg"

                variants[target] = {
                    "bytes": buffer.getvalue(),
                    "content_type": out_content_type,
                    "width": resized.width,
                    "height": resized.height,
                    "format": output_format,
                }

            return variants
    except UnidentifiedImageError as exc:
        raise MediaProcessingError("File is not a valid image") from exc


async def _update_user_avatar(user_id: uuid.UUID, final_key: str) -> str | None:
    """
    Persist the new avatar key, returning the previous one if it existed.
    """
    async with AsyncSessionLocal() as session:
        user = await session.get(User, user_id)
        if user is None:
            raise MediaProcessingError("User not found for avatar update")
        old = user.avatar_key
        user.avatar_key = final_key
        await session.commit()
        return old


async def _persist_avatar_and_bust_cache(
    user_id: uuid.UUID, final_key: str
) -> str | None:
    """
    Persist the avatar and invalidate cached user info.
    """
    old_key = await _update_user_avatar(user_id, final_key)
    try:
        redis = await init_redis()
        await delete_cached_user_info(user_id, redis)
        await delete_cached_user_profile(user_id, None, redis)
    except Exception:
        pass
    return old_key


@app.task(name="tasks.media.process_upload")
def process_upload(key: str) -> dict[str, Any]:
    """
    Validate, scan, resize, and promote an uploaded avatar from tmp to final storage.
    """
    bucket = settings.S3_MEDIA_BUCKET
    if not bucket:
        raise MediaProcessingError("S3 media bucket is not configured")
    user_id = _ensure_key_and_user(key)

    s3 = boto3.client("s3", region_name=settings.S3_MEDIA_REGION)

    try:
        meta = s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        raise MediaProcessingError("Upload not found in tmp bucket") from exc

    size = meta.get("ContentLength") or 0
    if size < 1 or size > settings.AVATAR_MAX_BYTES:
        raise MediaProcessingError("Avatar size is out of allowed range")
    header_content_type = meta.get("ContentType")

    with tempfile.NamedTemporaryFile(suffix=".upload") as tmp:
        s3.download_fileobj(bucket, key, tmp)
        tmp.flush()
        _av_scan(tmp.name)
        variants = _transform_image(tmp.name, header_content_type)

    output_format = settings.AVATAR_OUTPUT_FORMAT.upper()
    ext = "jpg" if output_format == "JPEG" else output_format.lower()
    base_prefix = f"avatars/{user_id}/{uuid.uuid4()}"

    variant_info: dict[int, dict[str, Any]] = {}
    for size, data in variants.items():
        variant_key = f"{base_prefix}/{size}.{ext}"
        s3.put_object(
            Bucket=bucket,
            Key=variant_key,
            Body=data["bytes"],
            ContentType=data["content_type"],
            Metadata={"source": "processed", "variant": str(size)},
        )
        variant_info[size] = {
            "key": variant_key,
            "content_type": data["content_type"],
            "width": data["width"],
            "height": data["height"],
        }

    if not variant_info:
        raise MediaProcessingError("No avatar variants were generated")

    # Use the largest target as the canonical avatar key.
    primary_size = max(variant_info.keys())
    primary_key = variant_info[primary_size]["key"]

    old_key = asyncio.run(_persist_avatar_and_bust_cache(user_id, primary_key))

    # Clean up tmp object; ignore errors here to avoid masking avatar success.
    try:
        s3.delete_object(Bucket=bucket, Key=key)
    except Exception:
        pass

    if old_key:
        try:
            s3.delete_object(Bucket=bucket, Key=old_key)
        except Exception:
            # Non-blocking; orphan can be cleaned later.
            pass

    return {
        "status": "ok",
        "final_key": primary_key,
        "primary_size": primary_size,
        "variants": variant_info,
        "user_id": str(user_id),
        "content_type": variant_info[primary_size]["content_type"],
    }
