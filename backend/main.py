"""
Aegis OSINT AI - Simplified Backend
Lightweight Windows-first OSINT investigation framework
"""

import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import sqlite3
import json
import httpx

# Load environment variables from .env
load_dotenv(".env")

# Initialize FastAPI app
app = FastAPI(
    title="Aegis OSINT AI",
    version="1.0.0",
    description="Lightweight OSINT investigation framework"
)

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

class TargetCreate(BaseModel):
    query: str
    target_type: Optional[str] = "auto"

class TargetRead(BaseModel):
    id: int
    query: str
    target_type: str
    status: str
    created_at: str

class Finding(BaseModel):
    id: int
    target_id: int
    source: str
    category: str
    severity: str
    confidence: float
    data: Dict[str, Any]
    created_at: str

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
# Also mount the frontend directory at the root for assets like app.js and style.css
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

@app.get("/health")
async def health():
    return {"status": "healthy", "database": "connected"}

@app.get("/api/settings")
async def get_settings():
    """Retrieve API keys from .env or config."""
    providers = [
        "openrouter", "openai", "anthropic", "gemini", "nvidia",
        "virustotal", "shodan", "hunter", "intelx", "censys", "abuseipdb", "urlscan"
    ]
    settings = {}
    for p in providers:
        settings[p] = os.getenv(f"{p.upper()}_API_KEY", "")
    return settings

@app.post("/api/settings")
async def save_settings(payload: Dict[str, str]):
    """Save API keys to .env file."""
    try:
        # Read existing .env
        lines = []
        if os.path.exists(".env"):
            with open(".env", "r") as f:
                lines = f.readlines()

        # Update or add keys
        for key, value in payload.items():
            env_key = f"{key.upper()}_API_KEY"
            found = False
            for i, line in enumerate(lines):
                if line.startswith(f"{env_key}="):
                    lines[i] = f"{env_key}={value}\n"
                    found = True
                    break
            if not found:
                lines.append(f"{env_key}={value}\n")

        with open(".env", "w") as f:
            f.writelines(lines)
        
        # Reload environment variables
        load_dotenv(".env", override=True)
        
        return {"status": "success", "message": "Settings saved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/targets", response_model=TargetRead)
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
    
    return TargetRead(
        id=target_id,
        query=payload.query,
        target_type=payload.target_type,
        status="pending",
        created_at=datetime.now().isoformat()
    )

@app.get("/api/targets", response_model=List[TargetRead])
async def list_targets():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, query, target_type, status, created_at FROM targets ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    
    return [TargetRead(id=r[0], query=r[1], target_type=r[2], status=r[3], created_at=r[4]) for r in rows]

@app.post("/api/search", response_model=Dict[str, Any])
async def search(payload: SearchRequest):
    """
    Initiates an investigation via the InvestigationEngine.
    """
    # 1. Determine target type
    target_type_str = payload.target_type or "auto"
    
    # Map string to TargetType enum
    from backend.models import TargetType
    try:
        if target_type_str == "auto":
            # Simple auto-detection logic
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
    
    # For MVP, we await it. In production, this should be a background task.
    result = await engine.run_investigation(target_id, target_type, payload.query)
    
    # Fetch entities, relationships, timeline for response
    from backend.storage import SQLiteStorage
    storage = SQLiteStorage(DATABASE_PATH)
    entities = [e.dict() for e in storage.get_entities_for_target(target_id)]
    relationships = [r.dict() for r in storage.get_relationships_for_target(target_id)]
    timeline = [t.dict() for t in storage.get_timeline(target_id)]
    
    return {
        "target_id": target_id,
        "query": payload.query,
        "findings_count": result.get("findings_count", 0),
        "findings": [f.dict() if hasattr(f, 'dict') else f for f in result.get("results", [])],
        "entities": entities,
        "relationships": relationships,
        "timeline": timeline
    }

@app.get("/api/targets/{target_id}/entities")
async def get_target_entities(target_id: int):
    from backend.storage import SQLiteStorage
    storage = SQLiteStorage(DATABASE_PATH)
    return [e.dict() for e in storage.get_entities_for_target(target_id)]

@app.get("/api/targets/{target_id}/relationships")
async def get_target_relationships(target_id: int):
    from backend.storage import SQLiteStorage
    storage = SQLiteStorage(DATABASE_PATH)
    return [r.dict() for r in storage.get_relationships_for_target(target_id)]

@app.get("/api/targets/{target_id}/timeline")
async def get_target_timeline(target_id: int):
    from backend.storage import SQLiteStorage
    storage = SQLiteStorage(DATABASE_PATH)
    return [t.dict() for t in storage.get_timeline(target_id)]

@app.get("/api/plugins")
async def list_plugins():
    from backend.plugin_manager import PluginManager
    pm = PluginManager()
    pm.discover_plugins()
    return [p.dict() for p in pm.list_plugins()]

@app.get("/api/findings", response_model=List[Finding])
async def list_findings(target_id: Optional[int] = None):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    if target_id:
        cursor.execute("SELECT id, target_id, source, category, severity, confidence, data, created_at FROM findings WHERE target_id = ?", (target_id,))
    else:
        cursor.execute("SELECT id, target_id, source, category, severity, confidence, data, created_at FROM findings ORDER BY created_at DESC")
    
    rows = cursor.fetchall()
    conn.close()
    
    return [Finding(
        id=r[0], target_id=r[1], source=r[2], category=r[3],
        severity=r[4], confidence=r[5], data=json.loads(r[6]) if r[6] else {}, created_at=r[7]
    ) for r in rows]

@app.post("/api/reports", response_model=Dict[str, Any])
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
    
    return {
        "report_id": report_id,
        "target_id": payload.target_id,
        "format": payload.format,
        "content": report_content
    }

@app.get("/api/reports/{report_id}")
async def get_report(report_id: int):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, target_id, format, content, created_at FROM reports WHERE id = ?", (report_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return {
        "report_id": row[0],
        "target_id": row[1],
        "format": row[2],
        "content": row[3],
        "created_at": row[4]
    }

@app.post("/api/chat")
async def chat(payload: Dict[str, Any]):
    """Chat endpoint using AI providers."""
    from backend.providers import AIProviderFactory, AIResponse
    
    message = payload.get("message", "")
    provider = payload.get("provider", "openrouter")
    model = payload.get("model", "gpt-3.5-turbo")
    
    provider_inst = AIProviderFactory.get_provider(provider)
    if not provider_inst:
        return {
            "response": f"'{provider}' API key not configured. Please set {provider.upper()}_API_KEY in .env",
            "provider": provider,
            "error": "no_api_key"
        }
    
    try:
        ai_response = await provider_inst.chat(message, model)
        return {
            "response": ai_response.content,
            "provider": provider,
            "model": model
        }
    except Exception as e:
        return {
            "response": f"Error calling {provider}: {str(e)}",
            "provider": provider,
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)