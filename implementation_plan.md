# Implementation Plan

[Overview]
Add dark-web / breach intelligence capabilities to Aegis OSINT AI: new plugins that search info-stealer logs, dark-web forums and chat sources (clearnet + optional Tor), and leaked databases, plus a dedicated "Dark Web" results page in the UI with links and download URLs where available.

The existing codebase already has the right seams: a plugin architecture (`backend/plugins/*.py` inheriting `BasePlugin`, auto-discovered on startup), a `TargetType` enum that already includes `EMAIL`, `PHONE`, `USERNAME`, `LEAK`, a `SQLiteStorage`/`get_db` persistence layer that stores plugin `PluginResponse.evidence` as JSON findings, and a Jinja2/HTMX/Alpine frontend with a sidebar (`base.html`), results page (`results.html`) and reusable list components. Two placeholder plugins (`exposed_credentials_plugin.py`, `database_scanner_plugin.py`) exist but are mostly conceptual (mock data) and are disabled because they declare required API keys (`VIRUSTOTAL_API_KEY`, `INTELX_API_KEY`, `SHODAN_API_KEY`) that are not configured.

The implementation adds five new plugins and reworks one:
1. `stealer_logs_plugin.py` — searches info-stealer log aggregators for a query (email/username/phone/domain): clearnet sources always (public Telegram stealer-log channels via `t.me/s/` preview scraping, paste-site search via psbdmp.ws dump search, HaveIBeenPwned for emails), plus optional Tor `.onion` endpoints (Ahmia search API) when a local Tor SOCKS5 proxy is reachable.
2. `darkweb_monitor_plugin.py` — searches dark-web/cybercrime forums and breach chatter: Ahmia (onion search engine, works via Tor), plus clearnet mirrors/aggregators (e.g. `onion.live` search, `dark.fail` listings, Google dork fallback) so the plugin still returns results without Tor.
3. `breach_check_plugin.py` — proper email breach checking via HaveIBeenPwned v3 `breachedaccount` + `pastes` endpoints when `HIBP_API_KEY` is set (free k-anonymity password check kept as fallback), plus optional paid aggregators queried when their keys exist: Dehashed (`DEHASHED_API_KEY`), LeakCheck (`LEAKCHECK_API_KEY`), Snusbase (`SNUSBASE_API_KEY`), Intelligence X (`INTELX_API_KEY`). The plugin is enabled with zero keys (falls back to free sources) and enriches results automatically when keys are added.
4. `leaked_db_plugin.py` — leaked-database/dump lookup: psbdmp.ws dump search, leak directory listing sites, and (with Tor) Ahmia queries for `{query} database dump/combolist`; evidence includes dump name, date, record count when known, source URL, and direct download link when one is published.
5. `telegram_osint_plugin.py` — public Telegram channel/group search for mentions of the query via `t.me/s/{channel}` HTML previews and known stealer-log channel lists; returns channel name, post date, snippet and link.

`exposed_credentials_plugin.py` is rewritten to delegate to real sources (HIBP pastes + psbdmp + optional paid APIs) instead of mock data, and its `required_api_keys` is emptied so it is enabled out of the box (free tier) and auto-enriches when keys appear — matching the agreed UX: "работи веднага, подобрява се с ключ".

Tor access is **optional**: a small helper (`backend/tor_client.py`) probes `127.0.0.1:9050` (SOCKS5) once, caches the result for 5 minutes, and exposes an httpx client routed through `socks5://127.0.0.1:9050` using `httpx-socks`. If Tor is not running, every dark-web plugin silently degrades to clearnet sources only and marks evidence with `"tor_available": false`. No Tor installation is performed.

For the UI, a new "Dark Web" page is added at `/darkweb` (sidebar entry in `base.html`, icon `eye-off`/`ghost`): a search form (query + type auto-detect) that posts to a new `POST /api/darkweb/search` endpoint which runs **only** the dark-web plugin subset via `PluginManager.execute_plugin()` directly (not a full investigation), aggregates the `PluginResponse` list, normalizes each evidence item into a flat "hit" record `{source, category, title, snippet, url, download_url, date, severity, tor}` and renders a dedicated partial `components/darkweb_results.html` showing result cards grouped by category (Stealer Logs / Breaches / Forum Mentions / Database Dumps / Telegram) with clickable links, a "Download" button when `download_url` exists, and a Tor-status badge. Dark-web hits found during normal investigations also appear as findings (category `darkweb`) on the existing results page — the new page is a focused, on-demand search window on top of that.

Planning templates in `planner.py` gain dark-web steps for `EMAIL`, `USERNAME`, `PHONE`, `PERSON` target types so the new plugins also run inside standard investigations. Planner prompt/valid sets are updated to include the new plugin names.

[Types]
Extend `TargetType` usage (no new enum members needed — `LEAK`, `EMAIL`, `PHONE`, `USERNAME`, `PERSON`, `DOMAIN` already exist) and add internal, non-DB helper models for the dark-web feature.

New Pydantic model in `backend/models.py`:
- `DarkWebHit(BaseModel)` — normalized single result for the UI:
  - `source: str` (plugin/source name, e.g. "ahmia", "psbdmp", "hibp_pastes", "telegram")
  - `category: str` (one of `stealer_log`, `breach`, `forum_mention`, `database_dump`, `telegram`, `paste`)
  - `title: str`
  - `snippet: str = ""` (max ~500 chars, HTML-escaped at render)
  - `url: str | None = None`
  - `download_url: str | None = None`
  - `date: str | None = None` (ISO or raw string from source)
  - `severity: str = "info"` (`info|warning|critical`)
  - `confidence: float = 0.7`
  - `tor: bool = False` (True when the hit came via Tor)
  - `extra: dict[str, Any] = {}`

New request/response shapes in `backend/main.py` (module-level, consistent with existing style):
- `DarkWebSearchRequest(BaseModel)`: `query: str = Field(..., min_length=1, max_length=500)`, `target_type: str | None = "auto"`, `use_tor: bool = True`
- Response uses the existing `format_response()` envelope; `data` contains `{query, target_type, tor_available, hits: list[DarkWebHit], hits_by_category: dict[str, int], sources_used: list[str]}`.

Plugin evidence contract (what each plugin puts in `PluginResponse.evidence` items): every evidence dict includes `type` (category string above), `title`, `url`, `snippet`, plus optional `download_url`, `date`, `severity`, `tor` — so a single normalizer in main.py can convert any dark-web plugin's evidence into `DarkWebHit` without per-plugin parsing.

New settings fields in `backend/config/settings.py` (all optional, synced to `os.environ` via the existing `_sync_to_environ` key map):
- `hibp_api_key: str | None` (`HIBP_API_KEY`)
- `dehashed_api_key: str | None` (`DEHASHED_API_KEY`)
- `leakcheck_api_key: str | None` (`LEAKCHECK_API_KEY`)
- `snusbase_api_key: str | None` (`SNUSBASE_API_KEY`)
- `tor_proxy_host: str = "127.0.0.1"` (`TOR_PROXY_HOST`)
- `tor_proxy_port: int = 9050` (`TOR_PROXY_PORT`)
- `tor_enabled: bool = True` (`TOR_ENABLED`, master switch)
Also added to `create_default_env()` template and `/api/settings/save` env writer.

[Files]
One new backend helper module, four new plugins, one rewritten plugin, and edits to models/settings/planner/main/templates/dependencies.

New files:
- `backend/tor_client.py` — `TorClient` singleton: `is_available()` (cached TCP probe of the SOCKS5 port, 5-min TTL), `get_client()` returning an `httpx.AsyncClient` with `proxy="socks5://host:port"` (via `httpx-socks`/`httpx[sox]` transport) or raising `TorUnavailableError`, `status()` for the UI badge.
- `backend/plugins/stealer_logs_plugin.py` — `StealerLogsPlugin` (see Functions).
- `backend/plugins/darkweb_monitor_plugin.py` — `DarkWebMonitorPlugin`.
- `backend/plugins/breach_check_plugin.py` — `BreachCheckPlugin`.
- `backend/plugins/leaked_db_plugin.py` — `LeakedDBPlugin`.
- `backend/plugins/telegram_osint_plugin.py` — `TelegramOSINTPlugin`.
- `backend/templates/darkweb.html` — new page (extends `base.html`): search form (Alpine, mirrors dashboard submit pattern), Tor-status badge (`GET /api/darkweb/status`), results container.
- `backend/templates/components/darkweb_results.html` — HTMX partial rendering grouped `DarkWebHit` cards with link/download buttons, severity colors, onion-badge for tor hits.
- `tests/test_darkweb_plugins.py` — respx-mocked tests for all five plugins (clearnet paths, Tor-unavailable path, key-gated paid-API paths) + the `/api/darkweb/search` endpoint.

Modified files:
- `backend/models.py` — add `DarkWebHit` model.
- `backend/config/settings.py` — new fields listed in [Types]; extend `key_map`, `create_default_env()` template.
- `backend/planner.py` — add templates: `TargetType.EMAIL` → `["email_discovery", "breach_check", "exposed_credentials", "stealer_logs", "darkweb_monitor", "telegram_osint"]`; `TargetType.USERNAME` → `["username_enumeration", "exposed_credentials", "stealer_logs", "darkweb_monitor", "telegram_osint"]`; `TargetType.PHONE` → `["exposed_credentials", "breach_check", "stealer_logs", "telegram_osint"]`; `TargetType.PERSON` → `["username_enumeration", "exposed_credentials", "stealer_logs", "darkweb_monitor", "telegram_osint"]`; append `leaked_db` + `darkweb_monitor` to `DOMAIN`/`NZ_DOMAIN` templates; extend `_plan_dynamically` prompt's plugin list and `valid_known` set with the 5 new names.
- `backend/main.py` — add routes: `GET /darkweb` (template), `POST /api/darkweb/search` (form or JSON; auto-detect type reuse of the regex block from `/api/search`; run the dark-web plugin subset in parallel via `asyncio.gather` on `PluginManager.execute_plugin` with per-plugin try/except so one failure doesn't 500; normalize evidence → `DarkWebHit`; return HTML partial when `HX-Request`), `GET /api/darkweb/status` (`{tor_available, tor_address, enabled_plugins: [...]}`). Extend `/api/settings/save` line list with the new env keys.
- `backend/templates/base.html` — sidebar nav link "Dark Web" (icon `ghost`) between Investigations and Plugins, active-state wired to `active_page == 'darkweb'`.
- `backend/plugins/exposed_credentials_plugin.py` — rewrite: `required_api_keys=[]`, real HIBP `pastes/{email}` call (needs `HIBP_API_KEY`, optional), psbdmp email search, keep k-anonymity password check, delegate phone/username paths to shared helpers; evidence items follow the contract in [Types] with `category`/`url` fields.
- `backend/plugins/database_scanner_plugin.py` — keep, but mark deprecated-in-favor: no functional change (avoid scope creep); optionally strip the always-true mock `_search_breach_db` so it returns `None` instead of fake hits (prevents fabricated findings).
- `requirements.txt` — add `httpx-socks>=0.10.0` (SOCKS5 transport for Tor) and `beautifulsoup4>=4.12.0` (HTML snippet extraction from t.me/s and forum pages).
- `pyproject.toml` — mirror the two deps if a `[project] dependencies` list exists there (check at implementation time).
- `README.md` / `AGENTS.md` — short section documenting new env keys and the optional Tor proxy.

No files deleted. No DB schema changes (findings table already stores arbitrary JSON evidence; `DarkWebHit` is transport/UI-only).

[Functions]
New and modified functions, by file.

`backend/tor_client.py` (new):
- `class TorUnavailableError(Exception)` — raised when proxy probe fails.
- `class TorClient`:
  - `__new__` / `get_instance()` — singleton (mirrors `EnhancedHTTPClient` pattern).
  - `async is_available(self, force: bool = False) -> bool` — cached probe: open async TCP connection to `(tor_proxy_host, tor_proxy_port)` with 2s timeout; cache `(result, timestamp)` for 300s; respects `settings.tor_enabled`.
  - `async get_client(self) -> httpx.AsyncClient` — returns a short-lived `httpx.AsyncClient(proxy=f"socks5://{host}:{port}", timeout=30)`; raises `TorUnavailableError` if probe fails.
  - `async status(self) -> dict` — `{available: bool, address: "127.0.0.1:9050", enabled: bool}`.

`backend/plugins/stealer_logs_plugin.py` (new) — `class StealerLogsPlugin(BasePlugin)`:
- `metadata` → name `stealer_logs`, version `1.0.0`, supported `[EMAIL, USERNAME, PHONE, DOMAIN, PERSON]`, `required_api_keys=[]`, tags `["stealer-logs","darkweb","credentials"]`, cost 3.0, est. 20s.
- `async execute(query, target_type) -> list[PluginResponse]` — fans out (asyncio.gather, return_exceptions) to `_search_psbdmp`, `_search_telegram_channels`, `_search_ahmia` (only if `TorClient.is_available()`), `_search_paid_apis` (only configured ones); merges results; one `PluginResponse` per source with contract-shaped evidence; returns `[]` when nothing found (no fake findings).
- `_search_psbdmp(client, query)` — `GET https://psbdmp.ws/api/search/{query}` (JSON) → items `{title, url, date, snippet}` category `stealer_log`/`paste`.
- `_search_telegram_channels(client, query)` — scrape `https://t.me/s/{chan}` for a small built-in list of known public stealer-log channels (`redlogslounge`, `cloudlogsgroup`, … maintained as module constant `STEALER_CHANNELS`), count mentions of `query` in post text → category `stealer_log`, url `https://t.me/{chan}/{post_id}` when matched.
- `_search_ahmia(query)` — via Tor client: `GET http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}` (Ahmia onion) parse result `<li class="result">` titles/links; fallback clearnet `https://ahmia.fi/search/?q=` (no Tor needed) — both category `forum_mention`/`stealer_log`, `tor` flag set accordingly.
- `_search_paid_apis(client, query, target_type)` — Dehashed `GET https://api.dehashed.com/search?query=` (Basic auth `DEHASHED_API_KEY` as `email:key` or bearer), LeakCheck `GET https://leakcheck.io/api/public?check={query}` (+ `LEAKCHECK_API_KEY` header for full results), Snusbase `POST https://api.snusbase.com/data/search` (`SNUSBASE_API_KEY`), IntelX kept as future stub. Each returns raw credential rows → evidence `category: "stealer_log"`, snippet with redacted password (`pass[:2] + "***"`) unless key-owner opts in, `download_url` when the source exposes one.
- `_redact_secret(value: str) -> str` — helper masking all but first 2 chars.

`backend/plugins/darkweb_monitor_plugin.py` (new) — `class DarkWebMonitorPlugin(BasePlugin)`:
- `metadata` → name `darkweb_monitor`, supported `[EMAIL, USERNAME, DOMAIN, PHONE, PERSON, LEAK]`, tags `["darkweb","forums","monitoring"]`, cost 4.0, est. 25s.
- `execute()` — `_search_ahmia_clearnet` (always), `_search_ahmia_onion` (Tor only), `_search_onion_live` (`https://onion.live/?s={query}` clearnet index of onion services), `_google_dork_darkweb` (reuse existing google plugin dork patterns with terms `"darknet forum"`, `"breachforums"`, `"onion"` when `GOOGLE_SEARCH_API_KEY` present); evidence `category: "forum_mention"`, fields `title/url/snippet/date/tor`.
- All network calls wrapped per-source with try/except + debug log, never raising past the plugin.

`backend/plugins/breach_check_plugin.py` (new) — `class BreachCheckPlugin(BasePlugin)`:
- `metadata` → name `breach_check`, supported `[EMAIL, PHONE, USERNAME]`, `required_api_keys=[]`, tags `["breach","hibp","credentials"]`, cost 2.0, est. 15s.
- `execute()` — for EMAIL: `_hibp_breaches` (`GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false`, header `hibp-api-key`, respect 429 + 1.5s delay) → per-breach evidence `{category:"breach", title: breach Name, date: BreachDate, snippet: DataClasses joined, url: https://haveibeenpwned.com/PwnedWebsites#{Name}, severity:"critical"}`; `_hibp_pastes` (`/api/v3/pasteaccount/{email}`) → `category:"paste"`, url=Source url, download_url when paste `Id` is on Pastebin (`https://pastebin.com/raw/{Id}`); without `HIBP_API_KEY`, fall back to existing k-anonymity password-range check (kept from `exposed_credentials`) and return an info hit noting the free-tier limitation. For PHONE/USERNAME: query paid APIs only (Dehashed/LeakCheck support phone/username), otherwise a single informational hit.
- `_paid_lookup(client, query)` — Dehashed/LeakCheck/Snusbase as in stealer plugin (shared via small module-level helper functions to avoid duplication).

`backend/plugins/leaked_db_plugin.py` (new) — `class LeakedDBPlugin(BasePlugin)`:
- `metadata` → name `leaked_db`, supported `[DOMAIN, EMAIL, USERNAME, LEAK, COMPANY]`, `required_api_keys=[]`, tags `["database","dumps","leak"]`, cost 3.5, est. 20s.
- `execute()` — `_search_psbdmp_dumps` (dump search, `download_url` from psbdmp item when present), `_search_leak_directories` (clearnet index pages, e.g. `https://leak.site` style public listings — implemented as configurable list `LEAK_INDEX_URLS`), `_search_ahmia_dumps` (Tor; query `"{query}" database dump`, `"{query}" combolist`); evidence `category:"database_dump"`, `title` = dump name, `date`, `snippet` = description/record count, `url`, `download_url` when available, `severity:"critical"` when query appears in title.
- Returns `[]` on no hits — no mock data.

`backend/plugins/telegram_osint_plugin.py` (new) — `class TelegramOSINTPlugin(BasePlugin)`:
- `metadata` → name `telegram_osint`, supported `[EMAIL, USERNAME, PHONE, DOMAIN, PERSON]`, tags `["telegram","chat","social"]`, cost 2.5, est. 15s.
- `execute()` — `_search_channel_previews(client, query)`: for each channel in `OSINT_CHANNELS` + `STEALER_CHANNELS` constants, fetch `https://t.me/s/{channel}`, BeautifulSoup-parse `.tgme_widget_message_text` blocks, match query (case-insensitive, plus digit-normalized phone variant), build hits with permalink `https://t.me/{channel}/{msg_id}`; `_search_telegram_global` best-effort via DuckDuckGo HTML (`https://html.duckduckgo.com/html/?q=site:t.me {query}`) for public channel posts mentioning the query (clearnet, no key). Evidence `category:"telegram"`.

`backend/plugins/exposed_credentials_plugin.py` (rewrite):
- `metadata.required_api_keys = []` (was `["VIRUSTOTAL_API_KEY","INTELX_API_KEY"]`), version bump `1.1.0`.
- `execute()` — EMAIL: HIBP pastes (if key) + psbdmp + k-anonymity password check; USERNAME: psbdmp + telegram stealer channels (reuse helpers from stealer plugin by importing its module-level functions); PHONE: paid APIs only + informational hit; remove all hardcoded mock/`scan_sources` filler; evidence follows contract (`category`, `url`, `snippet`, optional `download_url`).
- Keep `_normalize_phone` (fix the broken regex to simple digit extraction).

`backend/plugins/database_scanner_plugin.py` (small edit):
- `_search_breach_db()` → return `None` (was always-truthy mock dict) so the plugin stops fabricating findings; real functionality superseded by `leaked_db` plugin.

`backend/planner.py` (edits):
- `AIPlanner.__init__` — add/extend templates per [Files].
- `_plan_dynamically()` — extend prompt plugin list and `valid_known` with `stealer_logs, darkweb_monitor, breach_check, leaked_db, telegram_osint, exposed_credentials`.

`backend/main.py` (new endpoints + settings):
- `_detect_target_type(query: str) -> TargetType` — extract the regex auto-detect block from `search()` into a shared helper used by both `/api/search` and `/api/darkweb/search`.
- `darkweb_page(request)` — `GET /darkweb` → `darkweb.html` with `active_page="darkweb"`.
- `darkweb_status()` — `GET /api/darkweb/status` → TorClient.status() + list of dark-web plugins with enabled/disabled state from PluginManager.
- `darkweb_search(request, query: str = Form(...), target_type: str = Form("auto"))` — `POST /api/darkweb/search`; detects type; runs `["stealer_logs","darkweb_monitor","breach_check","leaked_db","telegram_osint","exposed_credentials"]` (filtered to enabled + type-supporting) via `asyncio.gather(..., return_exceptions=True)` on `PluginManager().execute_plugin`; normalizes evidence → `DarkWebHit` via `_evidence_to_hits(provider, response)`; sorts by severity (critical→warning→info) then date desc; returns `components/darkweb_results.html` for HTMX or `format_response` JSON otherwise.
- `_evidence_to_hits(provider: str, responses: list[PluginResponse]) -> list[DarkWebHit]` — mapping helper implementing the [Types] contract (tolerant of missing keys).
- `save_app_settings()` — add new env keys to the written `.env` lines.

`backend/templates/base.html` — sidebar link block (copy existing `<a>` pattern):
`<a href="/darkweb" class="... {% if active_page == 'darkweb' %}...{% endif %}"><i data-lucide="ghost" class="w-4 h-4"></i><span>Dark Web</span></a>` inserted after Investigations link.

[Classes]
New classes only; no existing class signatures are broken.

- `TorClient` (`backend/tor_client.py`) — singleton; methods above; no inheritance.
- `TorUnavailableError(Exception)`.
- `StealerLogsPlugin(BasePlugin)` (`backend/plugins/stealer_logs_plugin.py`).
- `DarkWebMonitorPlugin(BasePlugin)` (`backend/plugins/darkweb_monitor_plugin.py`).
- `BreachCheckPlugin(BasePlugin)` (`backend/plugins/breach_check_plugin.py`).
- `LeakedDBPlugin(BasePlugin)` (`backend/plugins/leaked_db_plugin.py`).
- `TelegramOSINTPlugin(BasePlugin)` (`backend/plugins/telegram_osint_plugin.py`).
- `ExposedCredentialsPlugin` (`backend/plugins/exposed_credentials_plugin.py`) — modified: new sources, no mock fallbacks, empty `required_api_keys`, version `1.1.0`.
- `AegisSettings` (`backend/config/settings.py`) — modified: 7 new optional fields; `key_map` and `create_default_env` extended.
- `AIPlanner` (`backend/planner.py`) — modified: new investigation templates + dynamic prompt list.
- `DarkWebHit(BaseModel)` (`backend/models.py`).

No classes removed. `DatabaseScannerPlugin` stays registered (deprecation is documentation-only) to avoid breaking existing investigations referencing its name.

[Dependencies]
Two new Python packages; no version bumps to existing packages; no system-level installs (Tor stays optional/external).

- `httpx-socks>=0.10.0` — async SOCKS5 transport so `httpx.AsyncClient(proxy="socks5://...")` works; only exercised when Tor is reachable.
- `beautifulsoup4>=4.12.0` — robust HTML parsing for `t.me/s` previews, Ahmia results and onion.live listings.

Both added to `requirements.txt` (and `pyproject.toml` project dependencies if present). Dev-side, existing `pytest`, `pytest-asyncio`, `respx` cover all new tests — no new test deps. `.env.example`/`create_default_env` gain the new optional keys (`HIBP_API_KEY`, `DEHASHED_API_KEY`, `LEAKCHECK_API_KEY`, `SNUSBASE_API_KEY`, `TOR_PROXY_HOST`, `TOR_PROXY_PORT`, `TOR_ENABLED`).

[Testing]
pytest + pytest-asyncio + respx, mirroring `tests/test_new_plugins.py` patterns (including its `reset_http_singleton` fixture for the shared client).

New file `tests/test_darkweb_plugins.py`:
- `TorClient`: availability probe with monkeypatched socket connect (success/failure), cache TTL behavior, `get_client` raises `TorUnavailableError` when down.
- `StealerLogsPlugin`: respx-mocked psbdmp JSON hit → one `PluginResponse`, category `stealer_log`, URL preserved; t.me/s HTML with a matching post → telegram-category hit with permalink; Tor unavailable → Ahmia skipped, no exception; no hits → `[]`.
- `DarkWebMonitorPlugin`: mocked Ahmia clearnet HTML → `forum_mention` hits parsed; all sources fail → `[]` (never raises).
- `BreachCheckPlugin`: with `HIBP_API_KEY` monkeypatched, mocked v3 `breachedaccount` (2 breaches) + `pasteaccount` (1 Pastebin paste → `download_url` = `https://pastebin.com/raw/...`) → critical hits; 401 from HIBP → warning hit, no crash; without key → k-anonymity path (mock `api.pwnedpasswords.com/range/...`).
- `LeakedDBPlugin`: psbdmp dump hit with download link → `database_dump` critical evidence carrying `download_url`.
- `TelegramOSINTPlugin`: mocked t.me/s page + DuckDuckGo HTML → hits with permalinks; query absent → `[]`.
- `ExposedCredentialsPlugin` (rewritten): email path with psbdmp hit returns evidence with contract keys; phone path without keys returns single informational hit.
- Endpoint tests (`httpx.AsyncClient` + ASGI transport like `test_api.py`): `POST /api/darkweb/search` with all plugins monkeypatched/mocked → 200, `hits` non-empty, `hits_by_category` sums match; HTMX header → HTML partial containing hit title; `GET /api/darkweb/status` → JSON with `tor_available` bool.
- Planner: `plan_investigation(TargetType.EMAIL, ...)` returns template containing `breach_check` and `stealer_logs`.

Existing tests must stay green: run `ruff check backend tests`, `mypy backend --ignore-missing-imports`, `pytest tests/ -v`. The `database_scanner` change (mock removal) may require updating any test asserting its mock findings — check `tests/` for references and adjust.

[Implementation Order]
Backend helpers and models first, then plugins, then wiring (planner/endpoints), then UI, then tests and quality gates.

1. `requirements.txt` (+`pyproject.toml` if applicable): add `httpx-socks`, `beautifulsoup4`; `pip install` them in `.venv`.
2. `backend/config/settings.py`: new optional fields, `key_map`, `create_default_env` template; verify `pytest tests/test_settings.py` still passes.
3. `backend/models.py`: add `DarkWebHit`.
4. `backend/tor_client.py`: `TorClient` + `TorUnavailableError`.
5. Plugins in dependency order: `stealer_logs_plugin.py` (helpers reused later), `telegram_osint_plugin.py`, `breach_check_plugin.py`, `leaked_db_plugin.py`, `darkweb_monitor_plugin.py`; then rewrite `exposed_credentials_plugin.py`; small edit to `database_scanner_plugin.py` (mock removal). Sanity: start app, confirm discovery logs show all new plugins `enabled` (no keys needed).
6. `backend/planner.py`: new templates + dynamic prompt sets.
7. `backend/main.py`: `_detect_target_type` extraction, `/darkweb`, `/api/darkweb/status`, `/api/darkweb/search`, `_evidence_to_hits`, settings-save env keys.
8. Templates: `darkweb.html`, `components/darkweb_results.html`, sidebar link in `base.html`; manual browser check (search with a known-breached test email, verify cards/links/download buttons, Tor badge shows "offline" when Tor isn't running).
9. `tests/test_darkweb_plugins.py` + adjust any broken existing tests.
10. Quality gates: `ruff check backend tests` → `ruff format` → `mypy backend --ignore-missing-imports` → `pytest tests/ -v` (all green), then update `README.md`/`AGENTS.md` env-key docs and commit.
