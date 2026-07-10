"""
Aegis OSINT AI - Simplified Backend
Lightweight Windows-first OSINT investigation framework
"""

import json
import logging
import os
import re
import sqlite3
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from backend.config.settings import get_settings, settings
from backend.provider_manager import ProviderManager

# APScheduler for scheduled scans (Phase 2)
try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.cron import CronTrigger
    HAS_SCHEDULER = True
except ImportError:
    HAS_SCHEDULER = False

logger = logging.getLogger(__name__)

# Initialize provider manager (non-async init)
provider_manager = ProviderManager()

# Database path from settings
DATABASE_PATH = settings.database_path


# --- Database Context Manager ---
def get_db():
    """Context manager for SQLite connections - auto-closes on exit."""
    os.makedirs(os.path.dirname(DATABASE_PATH) if os.path.dirname(DATABASE_PATH) else ".", exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Initialize SQLite database with schema."""
    os.makedirs(os.path.dirname(DATABASE_PATH) if os.path.dirname(DATABASE_PATH) else ".", exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT NOT NULL,
            target_type TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            source TEXT,
            category TEXT,
            severity TEXT,
            confidence REAL,
            data TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_id) REFERENCES targets (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            format TEXT,
            content TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_id) REFERENCES targets (id)
        )
    ''')

    # Scheduled scans table (Phase 2)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT NOT NULL,
            target_type TEXT,
            schedule TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            last_run TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


# --- Lifespan Handler (replaces deprecated on_event) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize DB and discover plugins on startup."""
    init_db()
    from backend.plugin_manager import PluginManager
    pm = PluginManager()
    pm.discover_plugins()

    # Initialize APScheduler (Phase 2)
    global scheduler
    if HAS_SCHEDULER:
        scheduler = AsyncIOScheduler()
        scheduler.start()
        logger.info("APScheduler started for scheduled scans")
    yield

    if scheduler:
        scheduler.shutdown()


# Initialize FastAPI app
app = FastAPI(
    title="Aegis OSINT AI",
    version="1.0.0",
    description="Lightweight OSINT investigation framework",
    lifespan=lifespan
)

# Global scheduler instance. Use Any so importing the app still works when
# APScheduler is intentionally not installed.
scheduler: Any = None

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # False is required per spec when allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]


def format_response(data: Any = None, success: bool = True, errors: list[str] | None = None, metadata: dict[str, Any] | None = None):
    return {
        "success": success,
        "data": data if data is not None else {},
        "errors": errors or [],
        "metadata": metadata or {}
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content=format_response(success=False, errors=[str(exc)])
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=format_response(success=False, errors=[exc.detail])
    )


# --- Pydantic Models ---

class TargetCreate(BaseModel):
    query: str = Field(..., min_length=1, max_length=1000)
    target_type: str | None = "auto"


class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=1000)
    target_type: str | None = "auto"


class BulkSearchRequest(BaseModel):
    queries: list[str] = Field(..., min_length=1, max_length=50)
    target_type: str | None = "auto"


class ReportRequest(BaseModel):
    target_id: int = Field(..., gt=0)
    format: str = "html"


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000)
    provider: str | None = "openrouter"
    model: str | None = ""
    image_urls: list[str] | None = None
    video_urls: list[str] | None = None


class ConfigureProviderRequest(BaseModel):
    api_key: str | None = None
    username: str | None = None
    password: str | None = None


class SaveSettingsRequest(BaseModel):
    api_key: str | None = None


# --- Scheduled Scans Models (Phase 2) ---

class ScheduleCreate(BaseModel):
    query: str = Field(..., min_length=1, max_length=1000)
    target_type: str | None = "auto"
    schedule: str = Field(..., description="Cron expression, e.g. '0 9 * * *' (daily at 9:00)")


class ScheduleResponse(BaseModel):
    id: int
    query: str
    target_type: str
    schedule: str
    enabled: bool
    last_run: str | None = None
    created_at: str


# --- Static File Routes ---

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_LEGACY_DIR = BASE_DIR / "frontend"
FRONTEND_DIST_DIR = BASE_DIR / "frontend_dist"
FRONTEND_ROOT = (
    FRONTEND_DIST_DIR
    if (FRONTEND_DIST_DIR / "index.html").exists()
    else FRONTEND_LEGACY_DIR
)


def _frontend_file(filename: str) -> FileResponse:
    path = FRONTEND_ROOT / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Frontend asset not found: {filename}")
    return FileResponse(path)


@app.get("/")
async def root():
    """Serve the available frontend.

    The repository currently ships the legacy static frontend under `frontend/`.
    If a future React/Vite build exists in `frontend_dist/`, it is preferred.
    """
    return _frontend_file("index.html")


@app.get("/style.css", include_in_schema=False)
async def frontend_style():
    return _frontend_file("style.css")


@app.get("/app.js", include_in_schema=False)
async def frontend_app_js():
    return _frontend_file("app.js")


# Mount only directories that actually exist. This prevents FastAPI imports from
# failing when `frontend_dist/` has not been built.
if (FRONTEND_ROOT / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_ROOT / "assets")), name="assets")
if FRONTEND_ROOT.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_ROOT)), name="static")


@app.get("/health")
async def health():
    return format_response({"status": "healthy", "database": "connected", "scheduler": "active" if scheduler else "disabled"})


# --- Scheduled Scans Helper ---

async def run_scheduled_investigation(query: str, target_type: str, schedule_id: int):
    """Function executed by the scheduler."""
    try:
        logger.info(f"Running scheduled scan #{schedule_id}: {query}")

        # Reuse the search logic without going through the HTTP/rate-limit wrapper.
        payload = SearchRequest(query=query, target_type=target_type)
        await run_search(payload)

        # Update last_run timestamp
        conn_gen = get_db()
        conn = next(conn_gen)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE scheduled_scans SET last_run = ? WHERE id = ?",
            (datetime.now(UTC).isoformat(), schedule_id)
        )
        conn.commit()
        conn.close()

        logger.info(f"Scheduled scan #{schedule_id} completed successfully")
    except Exception as e:
        logger.error(f"Scheduled scan #{schedule_id} failed: {e}")


# --- PROVIDER MANAGEMENT ENDPOINTS ---

@app.get("/api/providers")
async def list_providers():
    return format_response(provider_manager.get_providers())


@app.get("/api/providers/{provider}")
async def get_provider(provider: str):
    try:
        return format_response(provider_manager.get_provider(provider))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@app.get("/api/providers/{provider}/status")
async def get_provider_status(provider: str):
    try:
        p = provider_manager.get_provider(provider)
        return format_response({"status": p["status"]})
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@app.post("/api/providers/{provider}/configure")
async def configure_provider(provider: str, payload: ConfigureProviderRequest):
    # Validate provider exists
    try:
        provider_manager.get_provider(provider)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    try:
        config_data = {}
        if payload.api_key is not None:
            config_data["api_key"] = payload.api_key
        if payload.username is not None:
            config_data["username"] = payload.username
        if payload.password is not None:
            config_data["password"] = payload.password
        provider_manager.configure_provider(provider, config_data)
        return format_response({"message": f"{provider} configured successfully."})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/api/providers/{provider}/test")
async def test_provider(provider: str):
    try:
        is_ok = provider_manager.test_provider(provider)
        if is_ok:
            return format_response({"message": f"Connection to {provider} successful."})
        else:
            return format_response(success=False, errors=["Missing or invalid credentials."])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.delete("/api/providers/{provider}")
async def disconnect_provider(provider: str):
    try:
        provider_manager.disconnect_provider(provider)
        return format_response({"message": f"{provider} disconnected successfully."})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


# Settings endpoints using Pydantic settings
@app.get("/api/settings")
async def get_app_settings():
    """Get current settings from the config module."""
    return format_response(get_settings().model_dump(exclude={
        "openai_api_key": True,
        "anthropic_api_key": True,
        "gemini_api_key": True,
        "openrouter_api_key": True,
        "groq_api_key": True,
        "mistral_api_key": True,
        "nvidia_api_key": True,
        "github_token": True,
        "shodan_api_key": True,
        "virustotal_api_key": True,
        "hibp_api_key": True,
        "hunter_api_key": True,
        "google_search_api_key": True,
        "google_search_cx": True,
        "censys_api_id": True,
        "censys_api_secret": True,
        "securitytrails_api_key": True,
    }))


@app.post("/api/settings/save")
async def save_app_settings(payload: dict[str, str]):
    """Save settings to .env file (api keys only)."""
    env_path = Path(".env")

    # Build env content with current values
    lines = [
        "# Aegis OSINT AI Configuration",
        f"OPENAI_API_KEY={os.getenv('OPENAI_API_KEY', '')}",
        f"ANTHROPIC_API_KEY={os.getenv('ANTHROPIC_API_KEY', '')}",
        f"GEMINI_API_KEY={os.getenv('GEMINI_API_KEY', '')}",
        f"OPENROUTER_API_KEY={os.getenv('OPENROUTER_API_KEY', '')}",
        f"GROQ_API_KEY={os.getenv('GROQ_API_KEY', '')}",
        f"MISTRAL_API_KEY={os.getenv('MISTRAL_API_KEY', '')}",
        f"GITHUB_TOKEN={os.getenv('GITHUB_TOKEN', '')}",
        f"DATABASE={settings.database_path}",
        f"HOST={settings.host}",
        f"PORT={settings.port}",
    ]

    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return format_response({"message": "Settings saved successfully"})


# --- INVESTIGATION ENDPOINTS ---

@app.post("/api/targets")
async def create_target(payload: TargetCreate):
    conn_gen = get_db()
    conn = None
    try:
        conn = next(conn_gen)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO targets (query, target_type) VALUES (?, ?)",
            (payload.query, payload.target_type)
        )
        target_id = cursor.lastrowid
        conn.commit()
    finally:
        if conn:
            conn.close()

    return format_response({
        "id": target_id,
        "query": payload.query,
        "target_type": payload.target_type,
        "status": "pending",
        "created_at": datetime.now(UTC).isoformat()
    })


@app.get("/api/targets")
async def list_targets():
    conn_gen = get_db()
    conn = None
    try:
        conn = next(conn_gen)
        cursor = conn.cursor()
        cursor.execute("SELECT id, query, target_type, status, created_at FROM targets ORDER BY created_at DESC")
        rows = cursor.fetchall()
    finally:
        if conn:
            conn.close()

    targets = [{"id": r[0], "query": r[1], "target_type": r[2], "status": r[3], "created_at": r[4]} for r in rows]
    return format_response(targets)


@app.post("/api/search/bulk")
@limiter.limit("3/minute")
async def bulk_search(request: Request, payload: BulkSearchRequest):
    """Bulk investigation endpoint - processes multiple queries."""
    results = []

    for query in payload.queries:
        try:
            single_payload = SearchRequest(query=query, target_type=payload.target_type)
            result = await run_search(single_payload)
            results.append(result)
        except Exception as e:
            results.append(format_response(success=False, errors=[str(e)]))

    return format_response({
        "total_queries": len(payload.queries),
        "results": results
    })


@app.post("/api/search")
@limiter.limit("10/minute")
async def search(request: Request, payload: SearchRequest):
    """Start a single investigation."""
    return await run_search(payload)


async def run_search(payload: SearchRequest):
    # 1. Determine target type
    target_type_str = payload.target_type or "auto"
    from backend.models import TargetType
    try:
        if target_type_str == "auto":
            if re.match(r'^\d{11}$', payload.query):
                target_type = TargetType.ABN
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', payload.query):
                target_type = TargetType.IP
            elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', payload.query):
                target_type = TargetType.DOMAIN
            else:
                target_type = TargetType.COMPANY
        else:
            target_type = TargetType(target_type_str)
    except ValueError:
        target_type = TargetType.COMPANY

    # 2. Create target in DB
    conn_gen = get_db()
    conn = None
    try:
        conn = next(conn_gen)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO targets (query, target_type, status) VALUES (?, ?, ?)",
            (payload.query, target_type.value, "pending")
        )
        target_id = cursor.lastrowid
        conn.commit()
    finally:
        if conn:
            conn.close()

    # 3. Run investigation
    from backend.engine import InvestigationEngine
    engine = InvestigationEngine(DATABASE_PATH)

    result = await engine.run_investigation(target_id, target_type, payload.query)

    from backend.storage import SQLiteStorage
    storage = SQLiteStorage(DATABASE_PATH)
    entities = [e.model_dump() for e in storage.get_entities_for_target(target_id)]
    relationships = [r.model_dump() for r in storage.get_relationships_for_target(target_id)]
    timeline = [t.model_dump() for t in storage.get_timeline(target_id)]

    return format_response({
        "target_id": target_id,
        "query": payload.query,
        "findings_count": result.get("findings_count", 0),
        "findings": [f.model_dump() if hasattr(f, 'model_dump') else f for f in result.get("results", [])],
        "entities": entities,
        "relationships": relationships,
        "timeline": timeline
    })


@app.get("/api/targets/{target_id}/entities")
async def get_target_entities(target_id: int):
    from backend.storage import SQLiteStorage
    storage = SQLiteStorage(DATABASE_PATH)
    return format_response([e.model_dump() for e in storage.get_entities_for_target(target_id)])


@app.get("/api/targets/{target_id}/relationships")
async def get_target_relationships(target_id: int):
    from backend.storage import SQLiteStorage
    storage = SQLiteStorage(DATABASE_PATH)
    return format_response([r.model_dump() for r in storage.get_relationships_for_target(target_id)])


@app.get("/api/targets/{target_id}/timeline")
async def get_target_timeline(target_id: int):
    from backend.storage import SQLiteStorage
    storage = SQLiteStorage(DATABASE_PATH)
    return format_response([t.model_dump() for t in storage.get_timeline(target_id)])


@app.get("/api/plugins")
async def list_plugins():
    from backend.plugin_manager import PluginManager
    pm = PluginManager()
    return format_response(pm.list_plugins())


@app.get("/api/findings")
async def list_findings(target_id: int | None = None):
    conn_gen = get_db()
    conn = None
    try:
        conn = next(conn_gen)
        cursor = conn.cursor()

        if target_id:
            cursor.execute("SELECT id, target_id, source, category, severity, confidence, data, created_at FROM findings WHERE target_id = ?", (target_id,))
        else:
            cursor.execute("SELECT id, target_id, source, category, severity, confidence, data, created_at FROM findings ORDER BY created_at DESC")

        rows = cursor.fetchall()
    finally:
        if conn:
            conn.close()

    findings = [
        {
            "id": r[0], "target_id": r[1], "source": r[2], "category": r[3],
            "severity": r[4], "confidence": r[5], "data": json.loads(r[6]) if r[6] else {}, "created_at": r[7]
        }
        for r in rows
    ]
    return format_response(findings)


@app.post("/api/reports")
async def create_report(payload: ReportRequest):
    conn_gen = get_db()
    conn = None
    try:
        conn = next(conn_gen)
        cursor = conn.cursor()
        cursor.execute("SELECT id, query, target_type, status, created_at FROM targets WHERE id = ?", (payload.target_id,))
        target_row = cursor.fetchone()

        cursor.execute("SELECT id, target_id, source, category, severity, confidence, data, created_at FROM findings WHERE target_id = ?", (payload.target_id,))
        finding_rows = cursor.fetchall()
    finally:
        if conn:
            conn.close()

    if not target_row:
        raise HTTPException(status_code=404, detail="Target not found")

    target = {
        "id": target_row[0],
        "query": target_row[1],
        "target_type": target_row[2],
        "status": target_row[3],
        "created_at": target_row[4]
    }

    findings = [
        {
            "id": r[0], "target_id": r[1], "source": r[2], "category": r[3],
            "severity": r[4], "confidence": r[5], "data": json.loads(r[6]) if r[6] else {}, "created_at": r[7]
        }
        for r in finding_rows
    ]

    from backend.report import ReportGenerator
    from backend.storage import SQLiteStorage
    storage = SQLiteStorage(DATABASE_PATH)

    entities = [e.model_dump() for e in storage.get_entities_for_target(payload.target_id)]
    relationships = [r.model_dump() for r in storage.get_relationships_for_target(payload.target_id)]
    timeline = [t.model_dump() for t in storage.get_timeline(payload.target_id)]

    generator = ReportGenerator()
    report_content = generator.generate(payload.format, target, findings, entities, relationships, timeline)

    conn_gen2 = get_db()
    conn2 = None
    try:
        conn2 = next(conn_gen2)
        cursor = conn2.cursor()
        cursor.execute(
            "INSERT INTO reports (target_id, format, content) VALUES (?, ?, ?)",
            (payload.target_id, payload.format, report_content)
        )
        report_id = cursor.lastrowid
        conn2.commit()
    finally:
        if conn2:
            conn2.close()

    return format_response({
        "report_id": report_id,
        "target_id": payload.target_id,
        "format": payload.format,
        "content": report_content
    })


@app.get("/api/reports/{report_id}")
async def get_report(report_id: int):
    conn_gen = get_db()
    conn = None
    try:
        conn = next(conn_gen)
        cursor = conn.cursor()
        cursor.execute("SELECT id, target_id, format, content, created_at FROM reports WHERE id = ?", (report_id,))
        row = cursor.fetchone()
    finally:
        if conn:
            conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Report not found")

    return format_response({
        "report_id": row[0],
        "target_id": row[1],
        "format": row[2],
        "content": row[3],
        "created_at": row[4]
    })


# --- SCHEDULED SCANS ENDPOINTS (Phase 2) ---

@app.post("/api/schedules")
async def create_schedule(payload: ScheduleCreate):
    if not HAS_SCHEDULER or scheduler is None:
        raise HTTPException(status_code=503, detail="Scheduler not available (install apscheduler)")

    conn_gen = get_db()
    conn = None
    try:
        conn = next(conn_gen)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scheduled_scans (query, target_type, schedule) VALUES (?, ?, ?)",
            (payload.query, payload.target_type, payload.schedule)
        )
        schedule_id = cursor.lastrowid
        conn.commit()
    finally:
        if conn:
            conn.close()

    # Add job to scheduler
    try:
        trigger = CronTrigger.from_crontab(payload.schedule)
        scheduler.add_job(
            run_scheduled_investigation,
            trigger=trigger,
            args=[payload.query, payload.target_type, schedule_id],
            id=f"schedule_{schedule_id}",
            replace_existing=True
        )
    except Exception as e:
        logger.warning(f"Failed to schedule job: {e}")

    return format_response({
        "schedule_id": schedule_id,
        "query": payload.query,
        "schedule": payload.schedule,
        "message": "Scheduled scan created successfully"
    })


@app.get("/api/schedules")
async def list_schedules():
    conn_gen = get_db()
    conn = None
    try:
        conn = next(conn_gen)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, query, target_type, schedule, enabled, last_run, created_at FROM scheduled_scans ORDER BY created_at DESC"
        )
        rows = cursor.fetchall()
    finally:
        if conn:
            conn.close()

    schedules = [
        {
            "id": r[0],
            "query": r[1],
            "target_type": r[2],
            "schedule": r[3],
            "enabled": bool(r[4]),
            "last_run": r[5],
            "created_at": r[6]
        }
        for r in rows
    ]
    return format_response(schedules)


@app.delete("/api/schedules/{schedule_id}")
async def delete_schedule(schedule_id: int):
    conn_gen = get_db()
    conn = None
    try:
        conn = next(conn_gen)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scheduled_scans WHERE id = ?", (schedule_id,))
        conn.commit()
    finally:
        if conn:
            conn.close()

    # Remove from scheduler
    if scheduler:
        try:
            scheduler.remove_job(f"schedule_{schedule_id}")
        except Exception:
            pass

    return format_response({"message": f"Schedule {schedule_id} deleted"})


@app.post("/api/chat")
async def chat(payload: ChatRequest):
    from backend.providers import AIProviderFactory

    message = payload.message
    provider = payload.provider or "openrouter"
    model = payload.model or ""

    provider_inst = AIProviderFactory.get_provider(provider)
    if not provider_inst:
        return format_response(
            data={
                "response": f"'{provider}' API key not configured.",
                "provider": provider,
            },
            success=False,
            errors=["no_api_key"]
        )

    # Use default model if none specified
    if not model:
        model = getattr(provider_inst, '_default_model', None) or \
                {"openrouter": "gpt-3.5-turbo", "openai": "gpt-4", "anthropic": "claude-3-haiku-20240307", "gemini": "gemini-1.5-flash"}.get(provider, model)

    # Support multimodal chat (image/video URLs)
    image_urls = payload.image_urls
    video_urls = payload.video_urls

    try:
        if (image_urls or video_urls) and hasattr(provider_inst, 'chat_multimodal'):
            ai_response = await provider_inst.chat_multimodal(message, model, image_urls=image_urls, video_urls=video_urls)
        else:
            ai_response = await provider_inst.chat(message, model)
        return format_response({
            "response": ai_response.content,
            "provider": provider,
            "model": model
        })
    except Exception as e:
        return format_response(
            data={
                "response": f"Error calling {provider}: {str(e)}",
                "provider": provider
            },
            success=False,
            errors=[str(e)]
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
