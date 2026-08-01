"""AI-powered executive summaries for completed investigations.

Uses the first configured AI provider (OpenRouter -> OpenAI -> Anthropic ->
Gemini -> Groq -> Mistral) to turn raw findings/entities into a professional
analyst-style report. The summary is persisted in the reports table with
format='ai_summary'.
"""

import json
import logging
from typing import Any

from backend.providers import AIProviderFactory

logger = logging.getLogger(__name__)

PROVIDER_FALLBACK_ORDER = ["openrouter", "openai", "anthropic", "gemini", "groq", "mistral"]

DEFAULT_MODELS = {
    "openrouter": "gpt-3.5-turbo",
    "openai": "gpt-4",
    "anthropic": "claude-3-haiku-20240307",
    "gemini": "gemini-1.5-flash",
    "groq": "llama-3.1-8b-instant",
    "mistral": "mistral-small-latest",
}

MAX_CONTEXT_CHARS = 12000
MAX_FINDINGS = 50
MAX_ENTITIES = 80


class SummaryError(Exception):
    """Raised when no AI provider is available or generation fails."""


def build_summary_prompt(
    target: dict[str, Any],
    findings: list[dict[str, Any]],
    entities: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
) -> str:
    """Build the LLM prompt from investigation data (truncated to fit context)."""
    findings_brief = []
    for f in findings[:MAX_FINDINGS]:
        data = f.get("data")
        findings_brief.append(
            {
                "source": f.get("source"),
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "data": data if isinstance(data, dict | list) else str(data)[:300],
            }
        )

    entities_brief = [
        {"type": e.get("type"), "value": e.get("value"), "confidence": e.get("confidence")}
        for e in entities[:MAX_ENTITIES]
    ]

    context = {"target": target, "findings": findings_brief, "entities": entities_brief}
    context_json = json.dumps(context, default=str, ensure_ascii=False)[:MAX_CONTEXT_CHARS]

    return (
        "You are a senior OSINT analyst writing an executive summary of a completed "
        "investigation for a professional intelligence report.\n\n"
        f"Investigation data (JSON):\n{context_json}\n\n"
        "Write a concise, professional executive summary in Markdown with these sections:\n"
        "1. **Overview** - what was investigated and the overall assessment\n"
        "2. **Key Findings** - the most important discoveries (bullet points, cite sources)\n"
        "3. **Exposure & Leaks** - where the target's data has leaked or is exposed (if any)\n"
        "4. **Digital Footprint Map** - connected accounts, infrastructure and identifiers\n"
        "5. **Risk Assessment** - Low/Medium/High with justification\n"
        "6. **Recommended Next Steps** - concrete investigative or remediation actions\n\n"
        "Be factual - only state what the data supports. Note confidence levels where relevant."
    )


async def generate_summary(
    target: dict[str, Any],
    findings: list[dict[str, Any]],
    entities: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate an executive summary using the first configured AI provider."""
    provider = None
    provider_name = None
    for name in PROVIDER_FALLBACK_ORDER:
        provider = AIProviderFactory.get_provider(name)
        if provider:
            provider_name = name
            break

    if not provider or not provider_name:
        raise SummaryError(
            "No AI provider configured. Set an API key for one of: "
            + ", ".join(PROVIDER_FALLBACK_ORDER)
        )

    model = getattr(provider, "_default_model", None) or DEFAULT_MODELS.get(
        provider_name, "gpt-3.5-turbo"
    )
    prompt = build_summary_prompt(target, findings, entities, timeline)

    try:
        response = await provider.chat(prompt, model)
    except Exception as e:
        raise SummaryError(f"AI provider '{provider_name}' failed: {e}") from e

    return {"summary": response.content, "provider": provider_name, "model": model}
