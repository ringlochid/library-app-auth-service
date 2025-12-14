from datetime import datetime, timezone, timedelta
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query

router = APIRouter(prefix='/user', tags=["user services"])