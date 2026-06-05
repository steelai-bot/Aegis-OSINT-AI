from __future__ import annotations

import importlib.util
from pathlib import Path


def load_lifecycle_module():
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "dev_lifecycle.py"
    spec = importlib.util.spec_from_file_location("dev_lifecycle", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_parse_env_file_ignores_comments_and_blank_lines(tmp_path):
    lifecycle = load_lifecycle_module()
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n# comment\nAEGIS_LLM_PROVIDER=disabled\n\nAEGIS_API_PREFIX=/api/v1\n",
        encoding="utf-8",
    )

    assert lifecycle.parse_env_file(env_path) == {
        "AEGIS_LLM_PROVIDER": "disabled",
        "AEGIS_API_PREFIX": "/api/v1",
    }


def test_ensure_env_file_appends_missing_defaults_without_overwriting(tmp_path):
    lifecycle = load_lifecycle_module()
    env_path = tmp_path / ".env"
    env_path.write_text("AEGIS_OPENAI_API_KEY=already-set\n", encoding="utf-8")

    lifecycle.ensure_env_file(
        env_path,
        {
            "AEGIS_OPENAI_API_KEY": "",
            "AEGIS_LLM_PROVIDER": "disabled",
        },
        "Test env",
    )

    values = lifecycle.parse_env_file(env_path)
    assert values["AEGIS_OPENAI_API_KEY"] == "already-set"
    assert values["AEGIS_LLM_PROVIDER"] == "disabled"
