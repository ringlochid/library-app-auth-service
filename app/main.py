from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.redis_client import close_redis, init_redis
from app.routers import auth, user


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = await init_redis()
    try:
        yield
    finally:
        await close_redis()


app = FastAPI(lifespan=lifespan)

origins = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
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
