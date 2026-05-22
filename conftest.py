"""
conftest.py — Pytest configuration and fixtures for WP VulnScanner
===================================================================
Provides:
  - Flask app factory fixture
  - Test client fixture
  - Mock scan engine fixtures
  - Test database fixtures
  - Mock data generators
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import uuid

import pytest  # type: ignore[import-not-found]
from flask import Flask


@pytest.fixture
def test_env_vars(monkeypatch):
    """Set environment variables for testing."""
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("API_KEY", "test-api-key-12345678901234567890")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-12345678901234567890")
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("VERIFY_SSL", "false")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "5")
    monkeypatch.setenv("SCAN_TIMEOUT_SECONDS", "30")


@pytest.fixture
def test_db_path():
    """Create temporary database file for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    # Cleanup
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def test_db(test_db_path):
    """Create test database with schema."""
    conn = sqlite3.connect(test_db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    
    # Create tables
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            result_json TEXT,
            started_ts REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            started_ts REAL,
            updated_ts REAL DEFAULT CURRENT_TIMESTAMP,
            legal_accepted BOOLEAN DEFAULT 0,
            user_ip TEXT,
            result_json TEXT,
            error TEXT
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pwa_cache (
            url TEXT PRIMARY KEY,
            scan_id TEXT,
            cached_at TIMESTAMP,
            result_json TEXT
        )
    """)
    
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture
def app(test_env_vars, test_db_path, monkeypatch):
    """Create Flask app for testing."""
    # Use test database
    monkeypatch.setenv("DB_PATH", test_db_path)

    # Reload state/db/app to honor test env and DB_PATH
    import importlib
    import sys
    import state as state_module
    import db as db_module

    importlib.reload(state_module)
    importlib.reload(db_module)
    if "app" in sys.modules:
        importlib.reload(sys.modules["app"])
    else:
        import app  # noqa: F401
    flask_app = sys.modules["app"].app
    
    # Configure for testing
    flask_app.config["TESTING"] = True
    flask_app.config["PROPAGATE_EXCEPTIONS"] = True
    
    return flask_app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def app_context(app):
    """Create app context for tests that need it."""
    with app.app_context():
        yield app


@pytest.fixture
def mock_scan_result():
    """Create mock scan result."""
    return {
        "scan_id": str(uuid.uuid4())[:12],
        "target_url": "https://example.com",
        "scanned_at": "2024-05-14 12:00:00",
        "risk_label": "MEDIUM",
        "risk_score": 5.5,
        "status": "completed",
        "findings": {
            "vulnerabilities": [
                {
                    "type": "Insecure Software",
                    "title": "WordPress 6.0",
                    "severity": "medium",
                }
            ]
        },
        "ssl_unverified": False,
        "legal_accepted": True,
        "partial": False,
    }


@pytest.fixture
def mock_scan_engine(monkeypatch):
    """Mock the scan engine _run_scan function."""
    mock_func = MagicMock()
    
    def mock_run_scan(job_id, url, legal, user_ip, callback_url=""):
        # Simulate scan completion
        result = {
            "scan_id": job_id,
            "target_url": url,
            "scanned_at": "2024-05-14 12:00:00",
            "risk_label": "LOW",
            "risk_score": 2.5,
            "status": "completed",
            "findings": {"vulnerabilities": []},
            "ssl_unverified": False,
            "legal_accepted": legal,
            "partial": False,
        }
        mock_func.return_value = result
    
    mock_func.side_effect = mock_run_scan
    
    # Patch the function in scan_engine module
    monkeypatch.setattr(
        "scan_engine._run_scan",
        mock_func,
        raising=False
    )
    
    return mock_func


@pytest.fixture
def valid_scan_request():
    """Create valid scan request data."""
    return {
        "url": "https://example.com",
        "legal_accepted": True,
        "force_rescan": False,
    }


@pytest.fixture
def api_headers():
    """Create request headers with API key."""
    return {
        "Authorization": "Bearer test-api-key-12345678901234567890",
        "Content-Type": "application/json",
    }


@pytest.fixture
def mock_job_data():
    """Create mock job data for testing."""
    job_id = str(uuid.uuid4())[:12]
    return {
        "id": job_id,
        "url": "https://example.com",
        "status": "done",
        "started_ts": 1715593200.0,
        "result_json": json.dumps({
            "scan_id": job_id,
            "target_url": "https://example.com",
            "scanned_at": "2024-05-14 12:00:00",
            "risk_label": "LOW",
            "risk_score": 2.5,
            "findings": {"vulnerabilities": []},
        }),
        "legal_accepted": True,
        "user_ip": "127.0.0.1",
    }


# ──── Pytest Hooks ───────────────────────────────────────────────────


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )
