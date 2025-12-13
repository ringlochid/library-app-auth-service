import boto3
from fastapi import HTTPException

from app.settings import settings


async def get_s3_client():
    """
    Return a boto3 S3 client configured for media uploads.
    Raises HTTPException if required settings are missing.
    """
    if not settings.S3_MEDIA_BUCKET:
        raise HTTPException(
            status_code=500, detail="S3 media bucket is not configured on the server"
        )
    return boto3.client("s3", region_name=settings.S3_MEDIA_REGION)