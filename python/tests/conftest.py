"""Shared pytest fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_DIR = REPO_ROOT / "testdata" / "corpus"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def corpus() -> Path:
    """Path to ``testdata/corpus``; tests using it are skipped when the corpus is absent."""
    if not CORPUS_DIR.is_dir():
        pytest.skip("reference corpus not present (testdata/corpus)")
    return CORPUS_DIR


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES_DIR
