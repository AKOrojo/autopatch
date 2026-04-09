from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.config import Settings
from src.shared.database import init_engine, close_engine
from src.shared.redis_client import init_redis, close_redis
from src.shared.logging import setup_logging
from src.api.routes import auth, assets, scans, vulnerabilities, remediations, reports, webhooks, enrichment, users, approvals, sse

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings()
    setup_logging(settings.log_level)
    init_engine(settings.database_url)
    init_redis(settings.redis_url)
    yield
    await close_engine()
    await close_redis()

app = FastAPI(title="Autopatch", description="Autonomous vulnerability remediation platform", version="0.1.0", lifespan=lifespan)

app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

app.include_router(auth.router)
app.include_router(assets.router)
app.include_router(scans.router)
app.include_router(vulnerabilities.router)
app.include_router(remediations.router)
app.include_router(reports.router)
app.include_router(webhooks.router)
app.include_router(enrichment.router)
app.include_router(users.router)
app.include_router(approvals.router)
app.include_router(sse.router)

@app.get("/health")
async def health():
    return {"status": "ok"}
