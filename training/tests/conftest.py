"""Pytest path bootstrap for the repository-local ``training`` package."""

from __future__ import annotations

import sys
from pathlib import Path

# Pytest can invoke these tests through the venv entrypoint, which does not
# always prepend the repository root to ``sys.path``. Inserting the root here
# keeps ``pytest training/tests/`` aligned with the ``make train`` module path.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
