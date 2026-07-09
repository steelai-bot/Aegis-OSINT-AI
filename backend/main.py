"""
Aegis OSINT AI - Simplified Backend
Lightweight Windows-first OSINT investigation framework
"""

import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import sqlite3
import json
import httpx
from fastapi.middleware.cors import CORSMiddleware
from backend.provider_manager import ProviderManager
import traceback

# Load environment variables from .env
load_dotenv(".env")

# Initialize FastAPI app
app = FastAPI(
    title="Aegis OSINT AI",
    version="1.0.0",
    description="Lightweight OSINT investigation framework"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

provider_manager = ProviderManager()

# Database setup
DATABASE_PATH = os.getenv("DATABASE", "data/aegis.db")

def init_db():
    """Initialize SQLite database with schema."""
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
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

@app.on_event("startup")
async def startup_event():
    init_db()
    # Discover plugins on startup
    from backend.plugin_manager import PluginManager
    pm = PluginManager()
    pm.discover_plugins()

def format_response(data: Any = None, success: bool = True, errors: List[str] = None, metadata: Dict = None):
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

class TargetCreate(BaseModel):
    query: str
    target_type: Optional[str] = "auto"

class SearchRequest(BaseModel):
    query: str
    target_type: Optional[str] = "auto"
    custom_search: Optional[str] = None

class ReportRequest(BaseModel):
    target_id: int
    format: str = "html"

@app.get("/")
async def root():
    return FileResponse("frontend/index.html")

app.mount("/static", StaticFiles(directory="frontend"), name="static")
app.mount("/assets", StaticFiles(directory="frontend"), name="assets")

# Exception for main index to serve frontend
@app.get("/app.js")
async def get_app_js():
    return FileResponse("frontend/app.js")

@app.get("/style.css")
async def get_style_css():
    return FileResponse("frontend/style.css")


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
async def configure_provider(provider: str, payload: Dict[str, str]):
    try:
        provider_manager.configure_provider(provider, payload)
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

# Backward compatibility for settings page (if needed, but we should use providers)
@app.get("/api/settings")
async def get_settings():
    providers = provider_manager.get_providers()
    settings = {}
    for p in providers:
        # Just return connected state or something, or actual keys (not recommended for security)
        key_name = f"{p['id'].upper()}_API_KEY"
        settings[p['id']] = os.getenv(key_name, "")
    return format_response(settings)

@app.post("/api/settings")
async def save_settings(payload: Dict[str, str]):
    for key, val in payload.items():
        if val:
            provider_manager.configure_provider(key, {"api_key": val})
    return format_response({"message": "Settings saved successfully"})

# --- INVESTIGATION ENDPOINTS ---

@app.post("/api/targets")
async def create_target(payload: TargetCreate):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO targets (query, target_type) VALUES (?, ?)",
        (payload.query, payload.target_type)
    )
    target_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return format_response({
        "id": target_id,
        "query": payload.query,
        "target_type": payload.target_type,
        "status": "pending",
        "created_at": datetime.now().isoformat()
    })

@app.get("/api/targets")
async def list_targets():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, query, target_type, status, created_at FROM targets ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    
    targets = [{"id": r[0], "query": r[1], "target_type": r[2], "status": r[3], "created_at": r[4]} for r in rows]
    return format_response(targets)

@app.post("/api/search")
async def search(payload: SearchRequest):
    # 1. Determine target type
    target_type_str = payload.target_type or "auto"
    from backend.models import TargetType
    try:
        if target_type_str == "auto":
            import re
            if re.match(r'^\d{11}$', payload.query):
                target_type = TargetType.ABN
            elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', payload.query):
                target_type = TargetType.DOMAIN
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', payload.query):
                target_type = TargetType.IP
            else:
                target_type = TargetType.COMPANY
        else:
            target_type = TargetType(target_type_str)
    except ValueError:
        target_type = TargetType.COMPANY

    # 2. Create target in DB
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO targets (query, target_type, status) VALUES (?, ?, ?)",
        (payload.query, target_type.value, "pending")
    )
    target_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # 3. Run investigation
    from backend.engine import InvestigationEngine
    engine = InvestigationEngine(DATABASE_PATH)
    
    result = await engine.run_investigation(target_id, target_type, payload.query)
    
    from backend.storage import SQLiteStorage
    storage = SQLiteStorage(DATABASE_PATH)
    entities = [e.dict() for e in storage.get_entities_for_target(target_id)]
    relationships = [r.dict() for r in storage.get_relationships_for_target(target_id)]
    timeline = [t.dict() for t in storage.get_timeline(target_id)]
    
    return format_response({
        "target_id": target_id,
        "query": payload.query,
        "findings_count": result.get("findings_count", 0),
        "findings": [f.dict() if hasattr(f, 'dict') else f for f in result.get("results", [])],
        "entities": entities,
        "relationships": relationships,
        "timeline": timeline
    })

@app.get("/api/targets/{target_id}/entities")
async def get_target_entities(target_id: int):
    from backend.storage import SQLiteStorage
    storage = SQLiteStorage(DATABASE_PATH)
    return format_response([e.dict() for e in storage.get_entities_for_target(target_id)])

@app.get("/api/targets/{target_id}/relationships")
async def get_target_relationships(target_id: int):
    from backend.storage import SQLiteStorage
    storage = SQLiteStorage(DATABASE_PATH)
    return format_response([r.dict() for r in storage.get_relationships_for_target(target_id)])

@app.get("/api/targets/{target_id}/timeline")
async def get_target_timeline(target_id: int):
    from backend.storage import SQLiteStorage
    storage = SQLiteStorage(DATABASE_PATH)
    return format_response([t.dict() for t in storage.get_timeline(target_id)])

@app.get("/api/plugins")
async def list_plugins():
    from backend.plugin_manager import PluginManager
    pm = PluginManager()
    return format_response(pm.list_plugins())

@app.get("/api/findings")
async def list_findings(target_id: Optional[int] = None):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    if target_id:
        cursor.execute("SELECT id, target_id, source, category, severity, confidence, data, created_at FROM findings WHERE target_id = ?", (target_id,))
    else:
        cursor.execute("SELECT id, target_id, source, category, severity, confidence, data, created_at FROM findings ORDER BY created_at DESC")
    
    rows = cursor.fetchall()
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
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, query, target_type, status, created_at FROM targets WHERE id = ?", (payload.target_id,))
    target_row = cursor.fetchone()
    
    cursor.execute("SELECT id, target_id, source, category, severity, confidence, data, created_at FROM findings WHERE target_id = ?", (payload.target_id,))
    finding_rows = cursor.fetchall()
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
    
    entities = [e.dict() for e in storage.get_entities_for_target(payload.target_id)]
    relationships = [r.dict() for r in storage.get_relationships_for_target(payload.target_id)]
    timeline = [t.dict() for t in storage.get_timeline(payload.target_id)]
    
    generator = ReportGenerator()
    report_content = generator.generate(payload.format, target, findings, entities, relationships, timeline)
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO reports (target_id, format, content) VALUES (?, ?, ?)",
        (payload.target_id, payload.format, report_content)
    )
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return format_response({
        "report_id": report_id,
        "target_id": payload.target_id,
        "format": payload.format,
        "content": report_content
    })

@app.get("/api/reports/{report_id}")
async def get_report(report_id: int):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, target_id, format, content, created_at FROM reports WHERE id = ?", (report_id,))
    row = cursor.fetchone()
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
async def chat(payload: Dict[str, Any]):
    from backend.providers import AIProviderFactory
    
    message = payload.get("message", "")
    provider = payload.get("provider", "openrouter")
    model = payload.get("model", "gpt-3.5-turbo")
    
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
    
    try:
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