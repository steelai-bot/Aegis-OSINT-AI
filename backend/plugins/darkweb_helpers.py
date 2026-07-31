"""
Shared helpers for dark-web / breach intelligence plugins.

All helpers are defensive: network errors are caught by the caller (plugins
fan out with asyncio.gather(return_exceptions=True)) and secrets are always
redacted before being placed into evidence.
"""

import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Public Telegram channels known to redistribute info-stealer log samples.
# Maintained as a best-effort list; dead channels simply return 404 and are skipped.
STEALER_CHANNELS: list[str] = [
    "redlogslounge",
    "cloudlogsgroup",
    "stealerlogshub",
    "logscloud",
    "baseleak",
]

# Public OSINT/breach discussion channels worth scanning for mentions.
OSINT_CHANNELS: list[str] = [
    "breachdetector",
    "databreaches",
    "osint_channel",
]

# Clearnet indexes of onion services / leak listings.
LEAK_INDEX_URLS: list[str] = [
    "https://onion.live/?s={query}",
]

AHMIA_CLEARNET_URL = "https://ahmia.fi/search/?q={query}"
AHMIA_ONION_URL = (
    "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}"
)

_BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"


def _attr_str(value: Any) -> str | None:
    """Coerce a BeautifulSoup attribute value (str | list | None) to str | None."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value)
    return str(value)


def redact_secret(value: str | None, keep: int = 2) -> str:
    """Mask a secret (password/hash/token), keeping only the first `keep` chars."""
    if not value:
        return ""
    value = str(value)
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "***"


def normalize_phone_digits(phone: str) -> str | None:
    """Extract digits from a phone string; return None if not plausible (10-15 digits)."""
    digits = re.sub(r"\D", "", phone or "")
    if 10 <= len(digits) <= 15:
        return digits
    return None


def make_hit(
    source: str,
    category: str,
    title: str,
    snippet: str = "",
    url: str | None = None,
    download_url: str | None = None,
    date: str | None = None,
    severity: str = "info",
    tor: bool = False,
    **extra: Any,
) -> dict[str, Any]:
    """Build an evidence dict following the DarkWebHit contract."""
    hit: dict[str, Any] = {
        "type": category,
        "source": source,
        "title": title[:300],
        "snippet": snippet[:500],
        "url": url,
        "download_url": download_url,
        "date": date,
        "severity": severity,
        "tor": tor,
    }
    if extra:
        hit["extra"] = extra
    return hit


async def search_psbdmp(client: httpx.AsyncClient, query: str) -> list[dict[str, Any]]:
    """Search psbdmp.ws paste/dump index. Returns raw hit dicts (contract-shaped)."""
    hits: list[dict[str, Any]] = []
    try:
        resp = await client.get(
            f"https://psbdmp.ws/api/search/{query}",
            headers={"User-Agent": _BROWSER_UA},
        )
        if resp.status_code != 200:
            return hits
        data = resp.json()
        items = data.get("data", []) if isinstance(data, dict) else []
        for item in items[:20]:
            if not isinstance(item, dict):
                continue
            paste_id = item.get("id") or ""
            url = f"https://psbdmp.ws/{paste_id}" if paste_id else None
            download_url = f"https://psbdmp.ws/api/dump/get/{paste_id}" if paste_id else None
            text = (item.get("text") or item.get("title") or "")[:400]
            hits.append(
                make_hit(
                    source="psbdmp",
                    category="paste",
                    title=item.get("title") or f"Paste {paste_id}",
                    snippet=text,
                    url=url,
                    download_url=download_url,
                    date=item.get("time") or item.get("date"),
                    severity="warning",
                )
            )
    except Exception as e:
        logger.debug(f"psbdmp search failed for '{query}': {e}")
    return hits


async def search_telegram_channel(
    client: httpx.AsyncClient, channel: str, query: str, source: str = "telegram"
) -> list[dict[str, Any]]:
    """Scrape a public Telegram channel preview (t.me/s/{channel}) for query mentions."""
    hits: list[dict[str, Any]] = []
    try:
        from bs4 import BeautifulSoup

        resp = await client.get(
            f"https://t.me/s/{channel}",
            headers={"User-Agent": _BROWSER_UA},
        )
        if resp.status_code != 200:
            return hits

        soup = BeautifulSoup(resp.text, "html.parser")
        query_lower = query.lower()
        query_digits = re.sub(r"\D", "", query)

        for msg in soup.select(".tgme_widget_message")[:50]:
            text_el = msg.select_one(".tgme_widget_message_text")
            if not text_el:
                continue
            text = text_el.get_text(" ", strip=True)
            text_lower = text.lower()
            matched = query_lower in text_lower
            if not matched and query_digits and len(query_digits) >= 7:
                matched = query_digits in re.sub(r"\D", "", text)
            if not matched:
                continue

            link_el = msg.select_one("a.tgme_widget_message_date")
            permalink = _attr_str(link_el.get("href")) if link_el else f"https://t.me/s/{channel}"
            date_el = msg.select_one("time")
            date = _attr_str(date_el.get("datetime")) if date_el else None

            hits.append(
                make_hit(
                    source=source,
                    category="telegram",
                    title=f"Telegram mention in @{channel}",
                    snippet=text,
                    url=permalink,
                    date=date,
                    severity="warning",
                    channel=channel,
                )
            )
    except Exception as e:
        logger.debug(f"Telegram channel @{channel} scan failed: {e}")
    return hits


def parse_ahmia_results(html: str, source: str, tor: bool, category: str = "forum_mention") -> list[dict[str, Any]]:
    """Parse Ahmia search result HTML into hit dicts."""
    hits: list[dict[str, Any]] = []
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "html.parser")
        for result in soup.select("li.result")[:15]:
            link_el = result.select_one("a")
            if not link_el:
                continue
            title = link_el.get_text(" ", strip=True)
            url = _attr_str(link_el.get("href"))
            snippet_el = result.select_one("p")
            snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""
            if not title:
                continue
            hits.append(
                make_hit(
                    source=source,
                    category=category,
                    title=title,
                    snippet=snippet,
                    url=url,
                    severity="warning" if tor else "info",
                    tor=tor,
                )
            )
    except Exception as e:
        logger.debug(f"Ahmia result parsing failed: {e}")
    return hits


async def search_dehashed(client: httpx.AsyncClient, query: str) -> list[dict[str, Any]]:
    """Query Dehashed API (requires DEHASHED_API_KEY as 'email:key' or plain key)."""
    api_key = os.getenv("DEHASHED_API_KEY")
    if not api_key:
        return []
    hits: list[dict[str, Any]] = []
    try:
        if ":" in api_key:
            email, key = api_key.split(":", 1)
            auth: Any = (email, key)
            headers = {"Accept": "application/json"}
        else:
            auth = None
            headers = {"Accept": "application/json", "Authorization": f"Bearer {api_key}"}
        resp = await client.get(
            "https://api.dehashed.com/search",
            params={"query": query, "size": 20},
            headers=headers,
            auth=auth,
        )
        if resp.status_code != 200:
            logger.debug(f"Dehashed returned {resp.status_code}")
            return hits
        data = resp.json()
        for entry in data.get("entries", [])[:20]:
            if not isinstance(entry, dict):
                continue
            parts = [
                f"{k}: {redact_secret(str(v)) if k in ('password', 'hashed_password') else v}"
                for k, v in entry.items()
                if v and k in ("email", "username", "password", "hashed_password", "name", "phone", "database_name")
            ]
            db_name = entry.get("database_name") or "unknown breach"
            hits.append(
                make_hit(
                    source="dehashed",
                    category="stealer_log",
                    title=f"Dehashed record in '{db_name}'",
                    snippet=" | ".join(parts),
                    url="https://dehashed.com/",
                    severity="critical",
                    database=db_name,
                )
            )
    except Exception as e:
        logger.debug(f"Dehashed search failed: {e}")
    return hits


async def search_leakcheck(client: httpx.AsyncClient, query: str) -> list[dict[str, Any]]:
    """Query LeakCheck public API (free tier works keyless, key raises limits)."""
    hits: list[dict[str, Any]] = []
    try:
        headers = {"Accept": "application/json"}
        api_key = os.getenv("LEAKCHECK_API_KEY")
        if api_key:
            headers["X-API-Key"] = api_key
        resp = await client.get(
            "https://leakcheck.io/api/public",
            params={"check": query},
            headers=headers,
        )
        if resp.status_code != 200:
            return hits
        data = resp.json()
        if not data.get("success"):
            return hits
        for source in data.get("sources", [])[:20]:
            if not isinstance(source, dict):
                continue
            name = source.get("name") or "unknown"
            hits.append(
                make_hit(
                    source="leakcheck",
                    category="breach",
                    title=f"LeakCheck: found in '{name}'",
                    snippet=f"Query '{query}' appears in breach '{name}'"
                    + (f" (date: {source.get('date')})" if source.get("date") else ""),
                    url="https://leakcheck.io/",
                    date=source.get("date"),
                    severity="critical",
                )
            )
    except Exception as e:
        logger.debug(f"LeakCheck search failed: {e}")
    return hits


async def search_snusbase(client: httpx.AsyncClient, query: str) -> list[dict[str, Any]]:
    """Query Snusbase API (requires SNUSBASE_API_KEY)."""
    api_key = os.getenv("SNUSBASE_API_KEY")
    if not api_key:
        return []
    hits: list[dict[str, Any]] = []
    try:
        resp = await client.post(
            "https://api.snusbase.com/data/search",
            headers={"Auth": api_key, "Content-Type": "application/json"},
            json={"terms": [query], "types": ["email", "username", "lastip", "hash", "password", "name"]},
        )
        if resp.status_code != 200:
            return hits
        data = resp.json()
        results = data.get("results", {}) if isinstance(data, dict) else {}
        for db_name, rows in list(results.items())[:10]:
            if not isinstance(rows, list):
                continue
            for row in rows[:5]:
                if not isinstance(row, dict):
                    continue
                parts = [
                    f"{k}: {redact_secret(str(v)) if k in ('password', 'hash') else v}"
                    for k, v in row.items()
                    if v and k in ("email", "username", "password", "hash", "name", "lastip")
                ]
                hits.append(
                    make_hit(
                        source="snusbase",
                        category="stealer_log",
                        title=f"Snusbase record in '{db_name}'",
                        snippet=" | ".join(parts),
                        url="https://snusbase.com/",
                        severity="critical",
                        database=db_name,
                    )
                )
    except Exception as e:
        logger.debug(f"Snusbase search failed: {e}")
    return hits


async def search_paid_apis(client: httpx.AsyncClient, query: str) -> list[dict[str, Any]]:
    """Fan out to all configured paid breach APIs; returns merged hits."""
    import asyncio

    results = await asyncio.gather(
        search_dehashed(client, query),
        search_leakcheck(client, query),
        search_snusbase(client, query),
        return_exceptions=True,
    )
    hits: list[dict[str, Any]] = []
    for res in results:
        if isinstance(res, list):
            hits.extend(res)
    return hits
