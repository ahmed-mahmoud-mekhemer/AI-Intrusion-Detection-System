# backend/main.py
# ─────────────────────────────────────────────────────────────────────────────
# FastAPI application: registers all routers, initializes DB on startup.
# Run with: uvicorn backend.main:app --reload  (from project root)
# ─────────────────────────────────────────────────────────────────────────────
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routers import analyze, realtime, alerts, stats, live_monitor, honeypot
from backend.middleware.http_flood import HTTPFloodMiddleware
from backend.utils.database import init_db
from backend.utils.logger import get_logger

logger = get_logger(__name__)

app = FastAPI(
    title="AI-Based IDS API",
    description="Backend API for the AI Intrusion Detection System graduation project.",
    version="1.0.0",
)

# Allow requests from the desktop app (localhost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://127.0.0.1"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Layer-7 HTTP flood detection — counts requests per source IP using a sliding
# window. Fires a HIGH alert via save_alert() when the threshold is exceeded.
app.add_middleware(HTTPFloodMiddleware)

# ── Register routers ─────────────────────────────────────────────────────────
app.include_router(analyze.router)
app.include_router(realtime.router)
app.include_router(alerts.router)
app.include_router(stats.router)
app.include_router(live_monitor.router)
app.include_router(honeypot.router)


@app.on_event("startup")
def on_startup():
    """Initialize the database tables when the server starts."""
    init_db()
    logger.info("IDS Backend started. Database initialized.")


@app.get("/")
def root():
    return {"message": "IDS Backend is running. Visit /docs for the API reference."}
