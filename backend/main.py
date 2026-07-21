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

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from backend.config.settings import get_settings, settings
from backend.provider_manager import ProviderManager

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

    conn.commit()
    conn.close()


# --- Lifespan Handler (replaces deprecated on_event) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize DB and discover plugins on startup."""
    init_db()
    from backend.plugin_manager import PluginManager
    from backend.storage import SQLiteStorage

    pm = PluginManager()
    pm.discover_plugins()

    # Initialize global async storage pool
    app.state.storage = SQLiteStorage(DATABASE_PATH)
    await app.state.storage._get_connection()  # Pre-warm connection

    yield

    # Cleanup on shutdown
    if hasattr(app.state, 'storage'):
        await app.state.storage.close()
    from backend.http_client import SharedHTTPClient
    await SharedHTTPClient.close()


# Initialize FastAPI app
app = FastAPI(
    title="Aegis OSINT AI",
    version="1.0.0",
    description="Lightweight OSINT investigation framework",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # False is required per spec when allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)


def format_response(data: Any = None, success: bool = True, errors: list[str] = None, metadata: dict = None):
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


class ReportRequest(BaseModel):
    target_id: int = Field(..., gt=0)
    format: str = "html"


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000)
    provider: str | None = "openrouter"
    model: str | None = ""
    image_urls: list[str] | None = None
    video_urls: list[str] | None = None


class SaveSettingsRequest(BaseModel):
    api_key: str | None = None


# --- Jinja2 Templates ---
templates = Jinja2Templates(directory="backend/templates")

# Mount static files (if backend/static exists, otherwise skip)
if os.path.exists("backend/static"):
    app.mount("/static", StaticFiles(directory="backend/static"), name="static")


# --- Template Routes (replacing React SPA) ---

@app.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """Dashboard page with new investigation form"""
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"active_page": "dashboard"}
    )


@app.get("/investigations", response_class=HTMLResponse)
async def investigations_page(request: Request):
    """Investigations list page"""
    return templates.TemplateResponse(
        request=request,
        name="investigations.html",
        context={"active_page": "investigations"}
    )


@app.get("/results/{target_id}", response_class=HTMLResponse)
async def results_page(request: Request, target_id: int):
    """Investigation results page with graph visualization"""
    return templates.TemplateResponse(
        request=request,
        name="results.html",
        context={"target_id": target_id, "active_page": "results"}
    )


@app.get("/plugins", response_class=HTMLResponse)
async def plugins_page(request: Request):
    """Plugins management page"""
    return templates.TemplateResponse(
        request=request,
        name="plugins.html",
        context={"active_page": "plugins"}
    )


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page"""
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={"active_page": "settings"}
    )


@app.get("/health")
async def health():
    return format_response({"status": "healthy", "database": "connected"})


# --- PROVIDER MANAGEMENT ENDPOINTS ---

@app.get("/api/providers")
async def list_providers():
    return format_response(provider_manager.get_providers())


@app.get("/api/providers/{provider}")
async def get_provider(provider: str):
    try:
        return format_response(provider_manager.get_provider(provider))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/providers/{provider}/status")
async def get_provider_status(provider: str):
    try:
        p = provider_manager.get_provider(provider)
        return format_response({"status": p["status"]})
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/providers/{provider}/configure")
async def configure_provider(provider: str, api_key: str | None = Form(None), username: str | None = Form(None), password: str | None = Form(None)):
    # Validate provider exists
    try:
        provider_manager.get_provider(provider)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    try:
        config_data = {}
        if api_key is not None:
            config_data["api_key"] = api_key
        if username is not None:
            config_data["username"] = username
        if password is not None:
            config_data["password"] = password
        provider_manager.configure_provider(provider, config_data)
        return format_response({"message": f"{provider} configured successfully."})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/providers/{provider}/test")
async def test_provider(provider: str):
    try:
        is_ok = provider_manager.test_provider(provider)
        if is_ok:
            return format_response({"message": f"Connection to {provider} successful."})
        else:
            return format_response(success=False, errors=["Missing or invalid credentials."])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/providers/{provider}")
async def disconnect_provider(provider: str):
    try:
        provider_manager.disconnect_provider(provider)
        return format_response({"message": f"{provider} disconnected successfully."})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Settings endpoints using Pydantic settings
@app.get("/api/settings")
async def get_app_settings():
    """Get current settings from the config module."""
    return format_response(get_settings().model_dump(exclude={"openai_api_key": True, "anthropic_api_key": True, "gemini_api_key": True, "openrouter_api_key": True, "groq_api_key": True, "mistral_api_key": True, "github_token": True, "shodan_api_key": True, "securitytrails_api_key": True}))


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
async def list_targets(request: Request, format: str = "json"):
    """Return targets as JSON or HTML partial."""
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

    if format == "html":
        return templates.TemplateResponse("components/targets_list.html", {
            "request": request,
            "targets": targets
        })
    return format_response(targets)


@app.post("/api/search")
async def search(request: Request, query: str = Form(...), target_type: str | None = Form("auto"), format: str = "json"):
    """Start investigation and return JSON or HTML partial."""
    # 1. Determine target type
    target_type_str = target_type or "auto"
    from backend.models import TargetType
    try:
        if target_type_str == "auto":
            if re.match(r'^\d{11}$', query):
                target_type = TargetType.ABN
            elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query):
                target_type = TargetType.DOMAIN
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query):
                target_type = TargetType.IP
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
            (query, target_type.value, "pending")
        )
        target_id = cursor.lastrowid
        conn.commit()
    finally:
        if conn:
            conn.close()

    # 3. Run investigation
    from backend.engine import InvestigationEngine
    engine = InvestigationEngine.get_instance(DATABASE_PATH)
    if not engine._initialized:
        await engine.initialize()

    result = await engine.run_investigation(target_id, target_type, query)

    storage = app.state.storage
    entities = [e.model_dump() for e in await storage.get_entities_for_target(target_id)]
    relationships = [r.model_dump() for r in await storage.get_relationships_for_target(target_id)]
    timeline = [t.model_dump() for t in await storage.get_timeline(target_id)]

    if format == "html" or request.headers.get("HX-Request"):
        return templates.TemplateResponse("components/investigation_result.html", {
            "request": request,
            "target_id": target_id,
            "status": result.get("status", "completed")
        })

    return format_response({
        "target_id": target_id,
        "query": query,
        "findings_count": result.get("findings_count", 0),
        "findings": [f.model_dump() if hasattr(f, 'model_dump') else f for f in result.get("results", [])],
        "entities": entities,
        "relationships": relationships,
        "timeline": timeline
    })


@app.get("/api/targets/{target_id}/entities")
async def get_target_entities(request: Request, target_id: int, format: str = "json"):
    """Return entities as JSON or HTML partial."""
    storage = app.state.storage
    entities = await storage.get_entities_for_target(target_id)

    if format == "html":
        return templates.TemplateResponse("components/entities.html", {
            "request": request,
            "entities": entities
        })
    return format_response([e.model_dump() for e in entities])


@app.get("/api/targets/{target_id}/relationships")
async def get_target_relationships(request: Request, target_id: int, format: str = "json"):
    """Return relationships as JSON or HTML partial."""
    storage = app.state.storage
    relationships = await storage.get_relationships_for_target(target_id)

    if format == "html":
        return templates.TemplateResponse("components/relationships.html", {
            "request": request,
            "relationships": relationships
        })
    return format_response([r.model_dump() for r in relationships])


@app.get("/api/targets/{target_id}/timeline")
async def get_target_timeline(request: Request, target_id: int, format: str = "json"):
    """Return timeline as JSON or HTML partial."""
    storage = app.state.storage
    timeline = await storage.get_timeline(target_id)

    if format == "html":
        return templates.TemplateResponse("components/timeline.html", {
            "request": request,
            "timeline": timeline
        })
    return format_response([t.model_dump() for t in timeline])


@app.get("/api/plugins")
async def list_plugins(request: Request):
    from backend.plugin_manager import PluginManager
    pm = PluginManager()
    plugins = pm.list_plugins()
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("components/plugins_grid.html", {
            "request": request,
            "plugins": plugins
        })
    return format_response(plugins)


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
    storage = app.state.storage

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


@app.post("/api/chat")
async def chat(payload: ChatRequest):
    from backend.providers import AIProviderFactory

    message = payload.message
    provider = payload.provider
    model = payload.model

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
# --- HTMX Partial Endpoints (return HTML instead of JSON) ---

@app.get("/api/targets/{target_id}/graph-data")
async def graph_data(target_id: int):
    """Return graph data in JSON format for vis-network"""
    storage = app.state.storage
    entities = await storage.get_entities_for_target(target_id)
    relationships = await storage.get_relationships_for_target(target_id)

    nodes = [{"id": e.id, "value": e.value, "type": e.type.value} for e in entities]
    edges = [{"from": r.source_entity_id, "to": r.target_entity_id, "type": r.relationship_type.value} for r in relationships]

    return {"nodes": nodes, "edges": edges}

@app.get("/htmx/providers", response_class=HTMLResponse)
async def htmx_providers_list(request: Request):
    """HTMX endpoint - returns HTML partial with providers list"""
    providers_data = provider_manager.get_providers()
    return templates.TemplateResponse(
        request=request,
        name="components/providers_list.html",
        context={"providers": providers_data}
    )
