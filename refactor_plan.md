# Aegis-OSINT-AI Code Review & Refactoring Plan

## P0 — CRITICAL SECURITY (Fix First)

### P0-1: XSS in frontend/app.js
**File:** `frontend/app.js`
All user-controlled data rendered via `innerHTML` with NO sanitization.
- Lines 100-108: `${t.query}` in dashboard
- Lines 190-207: `${f.source}`, `${f.category}`, `${f.data}` in findings
- Lines 220-229: `${e.type}`, `${e.value}`, `${e.display_name}` in entities
- Lines 240-254: `${t.description}` in timeline
- Lines 327-334: `${p.name}`, `${p.description}`, tags in plugins
- Lines 346-368: `${p.name}`, `${p.description}` in providers
- Lines 513-518: `${text}` in chat messages

**Fix:** Add `escapeHtml()` helper function, apply to ALL template literals. Use `textContent` where possible.

### P0-2: Insecure CORS configuration
**File:** `backend/main.py`, lines 31-37
`allow_origins=["*"]` with `allow_credentials=True` — invalid combo per spec.

**Fix:** Change to `allow_origins=["*"]` with `allow_credentials=False`, or restrict origins.

### P0-3: Blind settings endpoint
**File:** `backend/main.py`, lines 212-217
`/api/settings` POST accepts arbitrary key-value pairs. Only allow known provider IDs.

**Fix:** Validate keys against ProviderManager's known providers list.

### P0-4: Missing input validation on API endpoints
**File:** `backend/main.py`
- SearchRequest at line 122-125: `query` has no length/sanitization validation
- `/api/chat` at line 429: accepts raw dict with no Pydantic model
- All provider endpoints accept raw strings without sanitization

**Fix:** Add Pydantic models with validation for all endpoints.

## P1 — IMPORTANT ARCHITECTURAL FIXES

### P1-1: Deprecated `@app.on_event("startup")`
**File:** `backend/main.py`, line 88
Replace with FastAPI lifespan handler.

### P1-2: Database context manager
**File:** `backend/main.py` and `backend/storage.py`
Manual `sqlite3.connect()` / close() pattern risk connection leaks.

**Fix:** Add a context manager `get_db()` that yields connection and auto-closes.

### P1-3: Pydantic v2 deprecation — `.dict()` → `.model_dump()`
**Files:**
- `backend/plugin_manager.py` line 111: `plugin.metadata.dict()`
- `backend/storage.py`: Entity/Reltionship/TimelineEvent `.dict()` calls
- `backend/main.py`: `.dict()` calls on entities, relationships, timeline

**Fix:** Replace all `.dict()` with `.model_dump()`.

### P1-4: `datetime.utcnow()` deprecation
**Files:** `backend/storage.py`, `backend/models.py`

**Fix:** Replace `.utcnow()` with `.now(datetime.UTC)`.

### P1-5: Plugin error isolation
**File:** `backend/plugin_manager.py`
Plugin crash propagates and crashes the app. Wrap plugin execution in try/except with logging.

### P1-6: Plugin metadata validation and Pydantic model
**File:** `backend/plugin_manager.py`
Add `PluginMetadata` Pydantic model with version, dependency fields.

### P1-7: Fix `except Exception` bare catches
**Files:** Multiple — replace broad catches with specific exceptions where possible. At minimum, log the traceback.

## P2 — CODE QUALITY & UX IMPROVEMENTS

### P2-1: Loading states & Typing indicator for chat
**File:** `frontend/app.js`
- Add typing indicator during AI responses
- Add loading skeleton/spinner for initial plugin/provider loads

### P2-2: Toast notifications instead of alert()
**File:** `frontend/app.js`
Replace `alert()` calls with styled toast notifications.

### P2-3: Chat input Enter key support
**File:** `frontend/index.html` / `frontend/app.js`
Add Enter key handler for chat input.

### P2-4: Remove dead code
**Files:**
- `backend/main.py`: `custom_search` field in SearchRequest (never used)
- `backend/providers.py`: `chat_template_kwargs` attribute (never used)

## P3 — TESTS & DOCUMENTATION

### P3-1: Add tests for new validation/sanitization
### P3-2: Update README with security notes
### P3-3: Add config validation at startup

---

## Execution Order
1. P0-1 (XSS fix) — most critical
2. P0-2 (CORS fix)
3. P0-3 (Settings validation)
4. P0-4 (Input validation models)
5. P1-1 (Lifespan handler)
6. P1-2 (DB context manager)
7. P1-3 + P1-4 (Deprecation fixes)
8. P1-5 + P1-6 (Plugin isolation)
9. P1-7 (Error handling)
10. P2 (UX improvements)
11. P3 (Tests & docs)