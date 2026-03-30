"""
Specter-OS — Main FastAPI Application
Entry point for the Specter-OS API server.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.database import init_db
from app.api.campaigns import router as campaigns_router
from app.api.attacks import router as attacks_router
from app.api.reports import router as reports_router
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger("main")


# ── Lifespan ──────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("⚡ Specter-OS starting up...")
    await init_db()
    logger.info("✅ Database initialized")

    # Ensure reports directory exists
    Path(settings.reports_dir).mkdir(parents=True, exist_ok=True)

    logger.info(
        f"\n{'='*50}\n"
        f"  SPECTER-OS v1.0 — ONLINE\n"
        f"  API: http://{settings.host}:{settings.port}\n"
        f"  Docs: http://{settings.host}:{settings.port}/docs\n"
        f"  Dashboard: http://{settings.host}:{settings.port}/dashboard\n"
        f"{'='*50}"
    )
    yield
    logger.info("Specter-OS shutting down...")


# ── App ───────────────────────────────────────────────

app = FastAPI(
    title="Specter-OS",
    description=(
        "⚡ **Autonomous AI Agent Red Teaming Engine**\n\n"
        "Specter-OS automatically discovers, attacks, and reports vulnerabilities "
        "in AI agents using a 5-phase pipeline:\n"
        "1. **Scout** — Behavioral intelligence gathering\n"
        "2. **Forge** — Tailored attack generation\n"
        "3. **Inject** — Adaptive multi-turn execution\n"
        "4. **Judge** — Independent LLM verdict\n"
        "5. **Report** — CISO-ready PDF output\n\n"
        "Part of the Aegis Security Suite."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────

app.include_router(campaigns_router, prefix="/api/v1")
app.include_router(attacks_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")

# ── Static Dashboard ──────────────────────────────────

dashboard_dir = Path(__file__).parent.parent / "dashboard"
if dashboard_dir.exists():
    app.mount("/dashboard", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard")


# ── Health Check ──────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    return {
        "status": "operational",
        "service": "Specter-OS",
        "version": "1.0.0",
        "llm_model": settings.specter_llm_model,
    }


@app.get("/", tags=["System"])
async def root():
    return JSONResponse({
        "service": "Specter-OS",
        "tagline": "Autonomous AI Agent Red Teaming Engine",
        "version": "1.0.0",
        "docs": "/docs",
        "dashboard": "/dashboard",
        "api": "/api/v1",
    })
