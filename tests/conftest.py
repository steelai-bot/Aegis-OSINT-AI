"""Shared pytest configuration.

Isolates the default database BEFORE any backend module is imported.
backend/main.py reads settings.database_path at import time, so the
DATABASE env var must be set here (pytest imports conftest.py first).
This makes the API tests hermetic: they no longer depend on a
pre-existing data/aegis.db in the working directory.
"""

import os
import tempfile

_fd, _TEST_DB_PATH = tempfile.mkstemp(prefix="aegis_test_", suffix=".db")
os.close(_fd)
os.environ["DATABASE"] = _TEST_DB_PATH
