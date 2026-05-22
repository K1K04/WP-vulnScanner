"""
conftest.py — Fixtures compartidos para tests de WP VulnScanner
=================================================================
"""

import os
import tempfile
import sqlite3
import pytest
from unittest.mock import Mock, patch
import json


@pytest.fixture
def temp_db():
    """Crea una base de datos SQLite temporal para tests."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    
    # Inicializar estructura de DB
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id             TEXT PRIMARY KEY,
            url            TEXT NOT NULL,
            scanned_at     TEXT NOT NULL,
            duration       REAL,
            risk_score     INTEGER,
            risk_label     TEXT,
            vuln_count     INTEGER,
            critical_count INTEGER,
            high_count     INTEGER,
            plugin_count   INTEGER,
            theme_count    INTEGER,
            exposed_count  INTEGER,
            users_count    INTEGER,
            malware_count  INTEGER,
            wp_version     TEXT,
            wp_outdated    INTEGER DEFAULT 0,
            xmlrpc_enabled INTEGER DEFAULT 0,
            wpscan_api     INTEGER DEFAULT 0,
            legal_accepted INTEGER DEFAULT 0,
            user_ip        TEXT,
            result_json    TEXT,
            job_status     TEXT    DEFAULT 'done'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id            TEXT PRIMARY KEY,
            url           TEXT NOT NULL,
            status        TEXT NOT NULL,
            started_ts    REAL NOT NULL,
            updated_ts    REAL NOT NULL,
            legal_accepted INTEGER DEFAULT 0,
            user_ip       TEXT,
            error         TEXT,
            result_json   TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rate_limit (
            ip         TEXT NOT NULL,
            endpoint   TEXT NOT NULL DEFAULT 'scan',
            ts         REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    
    yield path
    
    # Cleanup
    try:
        os.unlink(path)
    except:
        pass


@pytest.fixture
def mock_scan_result():
    """Resultado de escaneo mock para tests."""
    return {
        "scan_id": "test-scan-123",
        "target_url": "https://example.com",
        "scanned_at": "2024-01-01 12:00:00",
        "duration": 15.5,
        "risk_score": 75,
        "risk_label": "high",
        "summary": {
            "vulns_found": 5,
            "critical_vulns": 1,
            "high_vulns": 2,
            "medium_vulns": 2,
            "plugins_found": 10,
            "themes_found": 3,
            "exposed_files": 2,
            "users_found": 1,
            "malware_found": 0,
            "outdated_plugins": 3,
            "outdated_themes": 1,
        },
        "vulnerabilities": [
            {
                "id": "CVE-2024-1234",
                "title": "Test Vulnerability",
                "severity": "critical",
                "affected_component": "plugin/test-plugin",
            }
        ],
        "plugins": [
            {"name": "test-plugin", "version": "1.0", "outdated": True}
        ],
        "themes": [
            {"name": "test-theme", "version": "2.0", "outdated": True}
        ],
        "wp_version": "6.4.0",
        "wp_outdated": True,
        "xmlrpc_enabled": True,
    }


@pytest.fixture
def mock_scan_result_low_risk():
    """Resultado de escaneo mock con riesgo bajo."""
    return {
        "scan_id": "test-scan-low-456",
        "target_url": "https://safe-example.com",
        "scanned_at": "2024-01-01 13:00:00",
        "duration": 10.2,
        "risk_score": 20,
        "risk_label": "low",
        "summary": {
            "vulns_found": 0,
            "critical_vulns": 0,
            "high_vulns": 0,
            "medium_vulns": 0,
            "plugins_found": 5,
            "themes_found": 1,
            "exposed_files": 0,
            "users_found": 0,
            "malware_found": 0,
            "outdated_plugins": 0,
            "outdated_themes": 0,
        },
        "vulnerabilities": [],
        "plugins": [],
        "themes": [],
        "wp_version": "6.4.2",
        "wp_outdated": False,
        "xmlrpc_enabled": False,
    }


@pytest.fixture
def mock_app():
    """Aplicación Flask mock para tests de blueprints."""
    from flask import Flask
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    return app


@pytest.fixture
def mock_scanner():
    """Scanner mock para tests."""
    scanner = Mock()
    scanner.scan.return_value = Mock(
        to_dict=Mock(return_value={
            "target_url": "https://example.com",
            "risk_score": 50,
            "risk_label": "medium",
            "summary": {
                "vulns_found": 2,
                "critical_vulns": 0,
                "high_vulns": 1,
                "medium_vulns": 1,
            }
        })
    )
    return scanner


@pytest.fixture
def mock_requests_session():
    """Session de requests mock para tests de API externas."""
    session = Mock()
    session.get.return_value = Mock(
        status_code=200,
        json=Mock(return_value={}),
        text="{}"
    )
    session.post.return_value = Mock(
        status_code=200,
        json=Mock(return_value={"status": "success"})
    )
    return session


@pytest.fixture
def sample_urls():
    """URLs de ejemplo para tests."""
    return [
        "https://example.com",
        "https://test-site.org",
        "http://insecure-site.net",
    ]


@pytest.fixture
def mock_job_queue():
    """Queue de job mock para tests de scan_engine."""
    import queue
    return queue.Queue()


@pytest.fixture
def env_vars_debug():
    """Variables de entorno para modo debug."""
    original_debug = os.environ.get("DEBUG")
    os.environ["DEBUG"] = "true"
    yield
    if original_debug is None:
        os.environ.pop("DEBUG", None)
    else:
        os.environ["DEBUG"] = original_debug


@pytest.fixture
def env_vars_production():
    """Variables de entorno para modo producción."""
    original_debug = os.environ.get("DEBUG")
    os.environ["DEBUG"] = "false"
    yield
    if original_debug is None:
        os.environ.pop("DEBUG", None)
    else:
        os.environ["DEBUG"] = original_debug
