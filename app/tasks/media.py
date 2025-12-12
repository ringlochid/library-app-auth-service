"""
Media-related tasks: validation, resize, virus scan, S3 moves.
"""
from app.celery_app import app


@app.task(name="tasks.media.process_upload")
def process_upload(key: str) -> str:
    # TODO
    return key
