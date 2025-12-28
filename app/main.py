from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from sqlalchemy import text

from app.database import AsyncSessionLocal
from app.redis_client import close_redis, init_redis
from app.routers import auth, user, reports


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = await init_redis()
    try:
        yield
    finally:
        await close_redis()


app = FastAPI(lifespan=lifespan)

# TODO, move to env
origins = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "https://ppmrpzxpd4.ap-southeast-2.awsapprunner.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_request_meta(request: Request, call_next):
    ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    request.state.meta = {"ip": ip, "user_agent": user_agent}
    response = await call_next(request)
    return response


app.include_router(auth.router)
app.include_router(user.router)
app.include_router(reports.router)


@app.get("/health", tags=["Health"])
async def health_check():
    """
    Liveness probe - always returns 200 OK.
    """
    return {"status": "ok"}


@app.get("/test", tags=["Test"], response_class=FileResponse)
async def serve_test_frontend():
    """
    Serve the Auth Tester frontend for interactive API testing.
    """
    return FileResponse("frontend-test/index.html", media_type="text/html")


@app.get("/ready", tags=["Health"])
async def readiness_check():
    """
    Readiness probe - checks DB and Redis connectivity.
    Returns 200 if all dependencies are healthy, 503 otherwise.
    Used by AWS App Runner to determine if the service can accept traffic.
    """
    errors = []

    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
    except Exception as e:
        errors.append(f"Database: {str(e)}")

    try:
        redis = await init_redis()
        await redis.ping()
    except Exception as e:
        errors.append(f"Redis: {str(e)}")

    if errors:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "errors": errors},
        )

    return {"status": "ready", "database": "ok", "redis": "ok"}
