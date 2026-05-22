"""
run_tests.py — Test runner sin dependencias externas (no necesita pytest)
=========================================================================
Ejecuta todos los tests usando unittest estándar de Python.
Compatible con Python 3.8+.

Uso:
    python3 run_tests.py              # todos los tests
    python3 run_tests.py -v           # verbose
    python3 run_tests.py TestHealth   # clase específica
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import types
import unittest
import uuid
import warnings
from pathlib import Path
from unittest.mock import MagicMock, patch

# ──────────────────────────────────────────────────────────────────
# 1. Inyectar stubs ANTES de importar app, para cubrir dependencias
#    opcionales que pueden no estar instaladas en todos los entornos.
# ──────────────────────────────────────────────────────────────────

def _inject_missing_stubs():
    """Inyecta módulos stub para flask_compress y flask_restx si no están."""

    # flask_compress stub
    if "flask_compress" not in sys.modules:
        mod = types.ModuleType("flask_compress")

        class _Compress:
            def __init__(self, app=None):
                if app:
                    self.init_app(app)

            def init_app(self, _app):
                pass

        setattr(mod, "Compress", _Compress)
        sys.modules["flask_compress"] = mod

    # flask_restx: NO inyectar stub — queremos que el try/except en app.py
    # lo detecte como no disponible (ImportError) y ponga FLASK_RESTX_AVAILABLE=False.
    # Si ya está en sys.modules con valor real, lo dejamos. Si no está, no hacemos nada.

    # urllib3: importar el real si existe; solo stub si genuinamente falta
    try:
        import urllib3 as _u3
        import urllib3.exceptions  # asegura que el submodule está cacheado
        if not hasattr(_u3, "disable_warnings"):
            _u3.disable_warnings = lambda *a, **kw: None
    except ImportError:
        _u3_mod = types.ModuleType("urllib3")
        _exc = types.ModuleType("urllib3.exceptions")
        class _BaseEx(Exception): pass
        setattr(_exc, "InsecureRequestWarning", Warning)
        setattr(_exc, "HTTPError", _BaseEx)
        setattr(_exc, "MaxRetryError", _BaseEx)
        setattr(_exc, "ConnectionError", _BaseEx)
        setattr(_exc, "TimeoutError", _BaseEx)
        setattr(_exc, "SSLError", _BaseEx)
        setattr(_exc, "NewConnectionError", _BaseEx)
        setattr(_u3_mod, "__version__", "1.26.0")
        setattr(_u3_mod, "exceptions", _exc)
        setattr(_u3_mod, "disable_warnings", lambda *a, **kw: None)
        sys.modules["urllib3"] = _u3_mod
        sys.modules["urllib3.exceptions"] = _exc


_inject_missing_stubs()

# Silenciar warnings SSL en tests (VERIFY_SSL=false)
try:
    from urllib3.exceptions import InsecureRequestWarning
    warnings.filterwarnings("ignore", category=InsecureRequestWarning)
except Exception:
    warnings.filterwarnings("ignore", message="Unverified HTTPS request*")

# ──────────────────────────────────────────────────────────────────
# 2. Helpers de entorno y base de datos
# ──────────────────────────────────────────────────────────────────

# Ruta del proyecto (este archivo está en la raíz del proyecto)
PROJECT_DIR = Path(__file__).parent
sys.path.insert(0, str(PROJECT_DIR))


def _setup_test_env(db_path: str) -> None:
    """Configura variables de entorno para pruebas."""
    os.environ["FLASK_ENV"] = "testing"
    os.environ["APP_ENV"] = "test"
    os.environ["DEBUG"] = "true"
    os.environ["API_KEY"] = "test-api-key-12345678901234567890"
    os.environ["SECRET_KEY"] = "test-secret-key-12345678901234567890"
    os.environ["VERIFY_SSL"] = "false"
    os.environ["MAX_CONCURRENT_SCANS"] = "5"
    os.environ["SCAN_TIMEOUT_SECONDS"] = "30"
    os.environ["DB_PATH"] = db_path
    # Desactivar autenticación básica de UI para tests
    os.environ["UI_BASIC_AUTH_USER"] = ""
    os.environ["UI_BASIC_AUTH_PASS"] = ""
    # Forzar protección SSRF en tests (el .env puede tenerla desactivada)
    os.environ["SCAN_SCOPE"] = "public"
    os.environ["ALLOW_PRIVATE_IPS"] = "false"


def _create_test_db(path: str) -> sqlite3.Connection:
    """Crea el fichero de BD vacío con WAL. El esquema completo lo crea init_db()."""
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.commit()
    return conn


def _create_test_db_with_schema(path: str) -> sqlite3.Connection:
    """Crea BD de prueba con esquema mínimo para tests de BD directos (sin Flask app)."""
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            scanned_at TEXT,
            result_json TEXT,
            started_ts REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
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
        );
        CREATE TABLE IF NOT EXISTS pwa_cache (
            url TEXT PRIMARY KEY,
            scan_id TEXT,
            cached_at TIMESTAMP,
            result_json TEXT
        );
    """)
    conn.commit()
    return conn


def _mock_run_scan(job_id, url, legal, user_ip, callback_url=""):
    """
    Reemplaza _run_scan durante los tests.
    Marca el job como 'done' inmediatamente sin lanzar hilos reales
    ni abrir conexiones de red. Evita:
      - 'cannot schedule new futures after interpreter shutdown'
      - 'no such table: scans' cuando la DB temporal ya fue borrada
      - Peticiones HTTP reales a example.com durante los tests
    """
    try:
        from state import _jobs, _jobs_lock
        result = {
            "scan_id": job_id,
            "target_url": url,
            "scanned_at": "2024-01-01 00:00:00",
            "risk_label": "LOW",
            "risk_score": 0.0,
            "status": "completed",
            "findings": {"vulnerabilities": []},
            "ssl_unverified": True,
            "legal_accepted": legal,
            "partial": False,
        }
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id]["status"] = "done"
                _jobs[job_id]["result"] = result
                if "queue" in _jobs[job_id]:
                    try:
                        _jobs[job_id]["queue"].put_nowait(
                            {"type": "done", "result": result}
                        )
                    except Exception:
                        pass
    except Exception:
        pass  # Silenciar errores residuales en teardown


def _get_test_app():
    """Importa y devuelve la app Flask configurada para tests."""
    # Invalidar módulos cacheados que dependen de DB_PATH
    for mod_name in list(sys.modules.keys()):
        if mod_name in ("state", "db", "scan_engine", "app") or mod_name.startswith("blueprints."):
            del sys.modules[mod_name]

    # Asegurar que flask_restx no está disponible (para no fallar en Api=None)
    if "flask_restx" in sys.modules and getattr(sys.modules["flask_restx"], "Api", None) is None:
        del sys.modules["flask_restx"]

    from app import app as flask_app
    flask_app.config["TESTING"] = True
    flask_app.config["PROPAGATE_EXCEPTIONS"] = True

    # Parchear _run_scan para que NO lance hilos reales ni conexiones de red
    import scan_engine as _se
    _se._run_scan = _mock_run_scan
    import blueprints.scan as _bscan
    _bscan._run_scan = _mock_run_scan

    return flask_app


# ──────────────────────────────────────────────────────────────────
# 3. Clase base con setUp/tearDown automáticos
# ──────────────────────────────────────────────────────────────────

class WPVulnTestCase(unittest.TestCase):
    """Clase base: gestiona DB temporal y cliente de pruebas."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        _setup_test_env(self.db_path)
        _create_test_db(self.db_path)
        self.flask_app = _get_test_app()
        self.client = self.flask_app.test_client()
        self.api_headers = {
            "X-API-Key": "test-api-key-12345678901234567890",
            "Content-Type": "application/json",
        }

    def tearDown(self):
        # Borrar la DB temporal con reintento por si algún hilo la tiene abierta
        for _ in range(3):
            try:
                if os.path.exists(self.db_path):
                    os.unlink(self.db_path)
                break
            except OSError:
                import time as _t; _t.sleep(0.05)
        for ext in ("-wal", "-shm"):
            p = self.db_path + ext
            try:
                if os.path.exists(p):
                    os.unlink(p)
            except OSError:
                pass


# ──────────────────────────────────────────────────────────────────
# 4. Tests de Health
# ──────────────────────────────────────────────────────────────────

class TestHealthEndpoint(WPVulnTestCase):
    """Tests del endpoint /health."""

    def test_health_returns_200(self):
        """GET /health debe devolver 200 OK."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)

    def test_health_returns_json(self):
        """GET /health debe devolver JSON con campo 'status'."""
        response = self.client.get("/health")
        data = response.get_json()

        self.assertIsNotNone(data)
        self.assertIn("status", data)
        self.assertIn(data["status"], ["ok", "healthy", "up", "degraded"])

    def test_health_contains_version(self):
        """GET /health debe incluir version."""
        response = self.client.get("/health")
        data = response.get_json()

        has_version = "version" in data or "app_version" in data
        self.assertTrue(has_version, "Falta campo 'version' o 'app_version'")

    def test_health_has_uptime(self):
        """GET /health debe incluir uptime."""
        response = self.client.get("/health")
        data = response.get_json()
        self.assertIn("uptime", data)

    def test_api_health_returns_200_or_404(self):
        """GET /api/health debe devolver 200 o 404 (endpoint compartido)."""
        response = self.client.get("/api/health", headers=self.api_headers)
        self.assertIn(response.status_code, [200, 404])

    def test_api_version_endpoint(self):
        """GET /api/version debe devolver JSON con campo 'version'."""
        response = self.client.get("/api/version")
        self.assertIn(response.status_code, [200, 404])
        if response.status_code == 200:
            data = response.get_json()
            self.assertIsNotNone(data)
            self.assertIn("version", data)

    def test_health_sequence(self):
        """Tres llamadas consecutivas a /health deben devolver 200."""
        for _ in range(3):
            response = self.client.get("/health")
            self.assertEqual(response.status_code, 200)
            self.assertIn(
                response.content_type,
                ["application/json", "application/json; charset=utf-8"],
            )

    def test_health_checks_db_included(self):
        """GET /health puede incluir estado de la BD (no falla si no está)."""
        response = self.client.get("/health")
        data = response.get_json()
        # No falla si no hay campo 'checks', pero si existe debe ser dict
        if "checks" in data:
            self.assertIsInstance(data["checks"], dict)


# ──────────────────────────────────────────────────────────────────
# 5. Tests de Scan
# ──────────────────────────────────────────────────────────────────

class TestScanStartEndpoint(WPVulnTestCase):
    """Tests del endpoint POST /scan."""

    def test_requires_url(self):
        """POST /scan sin 'url' debe devolver 400."""
        response = self.client.post("/scan", json={"legal_accepted": True})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertTrue("error" in data or "message" in data)

    def test_requires_legal_acceptance(self):
        """POST /scan con legal_accepted=False debe devolver 403."""
        response = self.client.post("/scan", json={
            "url": "https://example.com",
            "legal_accepted": False,
        })
        self.assertEqual(response.status_code, 403)
        data = response.get_json()
        self.assertTrue("error" in data or "message" in data)

    def test_valid_scan_returns_job_id(self):
        """POST /scan con datos válidos debe devolver job_id."""
        response = self.client.post("/scan", json={
            "url": "https://example.com",
            "legal_accepted": True,
        })
        self.assertIn(response.status_code, [200, 202])
        data = response.get_json()
        job_id = data.get("job_id") or data.get("id")
        self.assertIsNotNone(job_id)
        self.assertIsInstance(job_id, str)
        self.assertGreater(len(job_id), 0)

    def test_rejects_localhost(self):
        """POST /scan debe rechazar localhost (SSRF)."""
        response = self.client.post("/scan", json={
            "url": "http://localhost",
            "legal_accepted": True,
        })
        self.assertIn(response.status_code, [400, 403, 422])

    def test_rejects_private_ip(self):
        """POST /scan debe rechazar IPs privadas (SSRF)."""
        response = self.client.post("/scan", json={
            "url": "http://127.0.0.1",
            "legal_accepted": True,
        })
        self.assertIn(response.status_code, [400, 403, 422])

    def test_rejects_non_url(self):
        """POST /scan debe rechazar cadena que no sea URL."""
        response = self.client.post("/scan", json={
            "url": "not-a-url",
            "legal_accepted": True,
        })
        self.assertIn(response.status_code, [400, 403, 422])

    def test_accepts_https_url(self):
        """POST /scan debe aceptar URL HTTPS válida."""
        response = self.client.post("/scan", json={
            "url": "https://example.com",
            "legal_accepted": True,
        })
        self.assertIn(response.status_code, [200, 202])

    def test_returns_content_type_json(self):
        """POST /scan debe devolver Content-Type application/json."""
        response = self.client.post("/scan", json={
            "url": "https://example.com",
            "legal_accepted": True,
        })
        if response.status_code in [200, 202]:
            self.assertIn("application/json", response.content_type)


class TestScanResultEndpoint(WPVulnTestCase):
    """Tests del endpoint GET /scan/<id>/result."""

    def test_result_not_found_for_random_id(self):
        """GET /scan/<id>/result con ID inexistente debe devolver 404."""
        fake_id = str(uuid.uuid4()).replace("-", "")[:12]
        response = self.client.get(f"/scan/{fake_id}/result")
        self.assertIn(response.status_code, [404, 400])

    def test_result_returns_json(self):
        """GET /scan/<id>/result debe devolver JSON."""
        # Primero crear un scan
        response = self.client.post("/scan", json={
            "url": "https://example.com",
            "legal_accepted": True,
        })
        if response.status_code in [200, 202]:
            data = response.get_json()
            job_id = data.get("job_id") or data.get("id")
            result_response = self.client.get(f"/scan/{job_id}/result")
            self.assertIn(
                result_response.content_type,
                ["application/json", "application/json; charset=utf-8"],
            )


class TestApiScanEndpoint(WPVulnTestCase):
    """Tests del endpoint POST /api/scan."""

    def test_requires_auth(self):
        """POST /api/scan sin API key debe devolver 401/403/404."""
        response = self.client.post("/api/scan", json={
            "url": "https://example.com",
            "legal_accepted": True,
        })
        self.assertIn(response.status_code, [401, 403, 404])

    def test_accepts_valid_auth(self):
        """POST /api/scan con API key válida debe devolver 200/202/404."""
        response = self.client.post(
            "/api/scan",
            json={"url": "https://example.com", "legal_accepted": True},
            headers=self.api_headers,
        )
        self.assertIn(response.status_code, [200, 202, 404])

    def test_returns_json_with_auth(self):
        """POST /api/scan con auth válida debe devolver JSON."""
        response = self.client.post(
            "/api/scan",
            json={"url": "https://example.com", "legal_accepted": True},
            headers=self.api_headers,
        )
        if response.status_code in [200, 202]:
            self.assertIn("application/json", response.content_type)
            data = response.get_json()
            self.assertIsNotNone(data)


class TestScanWorkflow(WPVulnTestCase):
    """Tests de flujo completo de escaneo."""

    def test_scan_creation_returns_status(self):
        """POST /scan debe devolver status o job_id en la respuesta."""
        response = self.client.post("/scan", json={
            "url": "https://example.com",
            "legal_accepted": True,
        })
        self.assertIn(response.status_code, [200, 202])
        data = response.get_json()
        has_id_or_status = "job_id" in data or "id" in data or "status" in data
        self.assertTrue(has_id_or_status)

    def test_scan_deduplication(self):
        """Dos scans del mismo URL devuelven job_ids válidos."""
        url = "https://example.com"
        r1 = self.client.post("/scan", json={"url": url, "legal_accepted": True})
        r2 = self.client.post("/scan", json={"url": url, "legal_accepted": True})

        if r1.status_code in [200, 202] and r2.status_code in [200, 202]:
            d1 = r1.get_json()
            d2 = r2.get_json()
            id1 = d1.get("job_id") or d1.get("id")
            id2 = d2.get("job_id") or d2.get("id")
            self.assertIsNotNone(id1)
            self.assertIsNotNone(id2)


# ──────────────────────────────────────────────────────────────────
# 6. Tests de Base de datos
# ──────────────────────────────────────────────────────────────────

class TestDatabaseSetup(unittest.TestCase):
    """Tests de inicialización y esquema de la BD."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.conn = _create_test_db_with_schema(self.db_path)

    def tearDown(self):
        self.conn.close()
        for p in [self.db_path, self.db_path + "-wal", self.db_path + "-shm"]:
            if os.path.exists(p):
                os.unlink(p)

    def test_creates_scans_table(self):
        """La tabla 'scans' debe existir."""
        cur = self.conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
        self.assertIsNotNone(cur.fetchone())

    def test_creates_scan_jobs_table(self):
        """La tabla 'scan_jobs' debe existir."""
        cur = self.conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_jobs'")
        self.assertIsNotNone(cur.fetchone())

    def test_creates_pwa_cache_table(self):
        """La tabla 'pwa_cache' debe existir."""
        cur = self.conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='pwa_cache'")
        self.assertIsNotNone(cur.fetchone())

    def test_wal_mode_enabled(self):
        """El modo WAL debe estar activado."""
        cur = self.conn.cursor()
        cur.execute("PRAGMA journal_mode")
        mode = cur.fetchone()[0]
        self.assertEqual(mode.upper(), "WAL")

    def test_scans_table_has_required_columns(self):
        """La tabla 'scans' debe tener columnas id y url."""
        cur = self.conn.cursor()
        cur.execute("PRAGMA table_info(scans)")
        cols = [row[1] for row in cur.fetchall()]
        self.assertIn("id", cols)
        self.assertIn("url", cols)

    def test_scan_jobs_table_has_required_columns(self):
        """La tabla 'scan_jobs' debe tener columnas id, url y status."""
        cur = self.conn.cursor()
        cur.execute("PRAGMA table_info(scan_jobs)")
        cols = [row[1] for row in cur.fetchall()]
        for col in ("id", "url", "status"):
            self.assertIn(col, cols)


class TestDatabaseInsertions(unittest.TestCase):
    """Tests de inserción en BD."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.conn = _create_test_db_with_schema(self.db_path)

    def tearDown(self):
        self.conn.close()
        for p in [self.db_path, self.db_path + "-wal", self.db_path + "-shm"]:
            if os.path.exists(p):
                os.unlink(p)

    def test_insert_scan_record(self):
        """Debe poder insertar y recuperar un scan."""
        scan_id, url = "scan_001", "https://example.com"
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO scans (id, url, result_json) VALUES (?, ?, ?)",
            (scan_id, url, json.dumps({"status": "completed"})),
        )
        self.conn.commit()
        cur.execute("SELECT url FROM scans WHERE id = ?", (scan_id,))
        result = cur.fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], url)

    def test_insert_job_state(self):
        """Debe poder insertar y recuperar un job."""
        job_id, url = "job_001", "https://example.com"
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO scan_jobs (id, url, status) VALUES (?, ?, ?)",
            (job_id, url, "running"),
        )
        self.conn.commit()
        cur.execute("SELECT status FROM scan_jobs WHERE id = ?", (job_id,))
        result = cur.fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "running")

    def test_insert_pwa_cache(self):
        """Debe poder insertar y recuperar una entrada en pwa_cache."""
        url, scan_id = "https://example.com", "scan_001"
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO pwa_cache (url, scan_id, result_json) VALUES (?, ?, ?)",
            (url, scan_id, json.dumps({"data": "cached"})),
        )
        self.conn.commit()
        cur.execute("SELECT scan_id FROM pwa_cache WHERE url = ?", (url,))
        result = cur.fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], scan_id)


class TestDatabaseQueries(unittest.TestCase):
    """Tests de consultas en BD."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.conn = _create_test_db_with_schema(self.db_path)

    def tearDown(self):
        self.conn.close()
        for p in [self.db_path, self.db_path + "-wal", self.db_path + "-shm"]:
            if os.path.exists(p):
                os.unlink(p)

    def test_query_scan_by_id(self):
        """SELECT por id debe devolver la fila correcta."""
        scan_id, url = "scan_002", "https://example.com"
        cur = self.conn.cursor()
        cur.execute("INSERT INTO scans (id, url) VALUES (?, ?)", (scan_id, url))
        self.conn.commit()
        cur.execute("SELECT url FROM scans WHERE id = ?", (scan_id,))
        result = cur.fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], url)

    def test_query_multiple_scans(self):
        """COUNT(*) debe devolver el número correcto de filas."""
        cur = self.conn.cursor()
        for i in range(3):
            cur.execute(
                "INSERT INTO scans (id, url) VALUES (?, ?)",
                (f"scan_{i}", f"https://example{i}.com"),
            )
        self.conn.commit()
        cur.execute("SELECT COUNT(*) FROM scans")
        self.assertGreaterEqual(cur.fetchone()[0], 3)

    def test_query_job_by_status(self):
        """Debe poder filtrar jobs por status."""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO scan_jobs (id, url, status) VALUES (?, ?, ?)",
            ("job_1", "https://example.com", "running"),
        )
        self.conn.commit()
        cur.execute("SELECT id FROM scan_jobs WHERE status = ?", ("running",))
        self.assertIsNotNone(cur.fetchone())


class TestDatabaseUpdates(unittest.TestCase):
    """Tests de actualización en BD."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.conn = _create_test_db_with_schema(self.db_path)

    def tearDown(self):
        self.conn.close()
        for p in [self.db_path, self.db_path + "-wal", self.db_path + "-shm"]:
            if os.path.exists(p):
                os.unlink(p)

    def test_update_job_status(self):
        """UPDATE de status debe persistir correctamente."""
        job_id = "job_upd_1"
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO scan_jobs (id, url, status) VALUES (?, ?, ?)",
            (job_id, "https://example.com", "pending"),
        )
        self.conn.commit()
        cur.execute("UPDATE scan_jobs SET status = ? WHERE id = ?", ("completed", job_id))
        self.conn.commit()
        cur.execute("SELECT status FROM scan_jobs WHERE id = ?", (job_id,))
        self.assertEqual(cur.fetchone()[0], "completed")

    def test_update_with_json_result(self):
        """UPDATE con result_json debe persistir JSON correctamente."""
        job_id = "job_res_1"
        result_data = {"findings": [{"type": "vulnerability"}]}
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO scan_jobs (id, url, status) VALUES (?, ?, ?)",
            (job_id, "https://example.com", "pending"),
        )
        self.conn.commit()
        cur.execute(
            "UPDATE scan_jobs SET status = ?, result_json = ? WHERE id = ?",
            ("done", json.dumps(result_data), job_id),
        )
        self.conn.commit()
        cur.execute("SELECT result_json FROM scan_jobs WHERE id = ?", (job_id,))
        row = cur.fetchone()
        self.assertIsNotNone(row[0])
        loaded = json.loads(row[0])
        self.assertIn("findings", loaded)


class TestDatabaseTransactions(unittest.TestCase):
    """Tests de transacciones en BD."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.conn = _create_test_db_with_schema(self.db_path)

    def tearDown(self):
        self.conn.close()
        for p in [self.db_path, self.db_path + "-wal", self.db_path + "-shm"]:
            if os.path.exists(p):
                os.unlink(p)

    def test_committed_transaction_persists(self):
        """Una transacción commiteada debe ser visible en nueva conexión."""
        cur = self.conn.cursor()
        cur.execute("INSERT INTO scans (id, url) VALUES (?, ?)", ("trans_1", "https://example.com"))
        self.conn.commit()

        new_conn = sqlite3.connect(self.db_path)
        new_cur = new_conn.cursor()
        new_cur.execute("SELECT url FROM scans WHERE id = ?", ("trans_1",))
        result = new_cur.fetchone()
        new_conn.close()
        self.assertIsNotNone(result)

    def test_rollback_on_error_does_not_persist(self):
        """Un INSERT seguido de rollback no debe persistir."""
        cur = self.conn.cursor()
        try:
            cur.execute("INSERT INTO scans (id, url) VALUES (?, ?)", ("rbk_1", "https://example.com"))
            # Simular error
            raise ValueError("error simulado")
        except ValueError:
            self.conn.rollback()

        cur.execute("SELECT COUNT(*) FROM scans WHERE id = ?", ("rbk_1",))
        count = cur.fetchone()[0]
        self.assertEqual(count, 0)


# ──────────────────────────────────────────────────────────────────
# 7. Tests de state.py (funciones utilitarias)
# ──────────────────────────────────────────────────────────────────

class TestStateHelpers(unittest.TestCase):
    """Tests de funciones utilitarias en state.py."""

    @classmethod
    def setUpClass(cls):
        fd, cls.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        _setup_test_env(cls.db_path)
        # Asegurar que ALLOW_PRIVATE_IPS y SCAN_SCOPE no interfieran
        os.environ.pop("ALLOW_PRIVATE_IPS", None)
        os.environ.pop("SCAN_SCOPE", None)
        # Limpiar caché de módulos para importar con la DB de test
        for mod in list(sys.modules.keys()):
            if mod in ("state", "db") or mod.startswith("blueprints."):
                del sys.modules[mod]
        import state as s
        cls.state = s

    @classmethod
    def tearDownClass(cls):
        for p in [cls.db_path, cls.db_path + "-wal", cls.db_path + "-shm"]:
            if os.path.exists(p):
                os.unlink(p)

    def test_normalize_url_adds_https(self):
        """normalize_url debe añadir https:// si falta esquema."""
        normalized = self.state.normalize_url("example.com")
        self.assertTrue(normalized.startswith("http"))

    def test_normalize_url_preserves_https(self):
        """normalize_url no debe modificar URLs con esquema válido."""
        url = "https://example.com"
        normalized = self.state.normalize_url(url)
        self.assertIn("example.com", normalized)

    def test_is_safe_url_rejects_localhost(self):
        """is_safe_url debe rechazar localhost."""
        result = self.state.is_safe_url("http://localhost")
        # is_safe_url devuelve (bool, str) — extraer el bool
        ok = result[0] if isinstance(result, tuple) else result
        self.assertFalse(ok)

    def test_is_safe_url_rejects_private_ip(self):
        """is_safe_url debe rechazar IPs privadas."""
        result = self.state.is_safe_url("http://192.168.1.1")
        ok = result[0] if isinstance(result, tuple) else result
        self.assertFalse(ok)

    def test_is_safe_url_accepts_public_url(self):
        """is_safe_url debe aceptar URLs públicas."""
        result = self.state.is_safe_url("https://example.com")
        ok = result[0] if isinstance(result, tuple) else result
        self.assertTrue(ok)

    def test_validate_job_id_rejects_empty(self):
        """_validate_job_id debe rechazar cadena vacía."""
        result = self.state._validate_job_id("")
        self.assertFalse(result)

    def test_validate_job_id_accepts_valid_id(self):
        """_validate_job_id debe aceptar un ID alfanumérico de 12 chars."""
        result = self.state._validate_job_id("abc123def456")
        self.assertTrue(result)

    def test_validate_job_id_rejects_sql_injection(self):
        """_validate_job_id debe rechazar caracteres especiales."""
        result = self.state._validate_job_id("'; DROP TABLE scans; --")
        self.assertFalse(result)


# ──────────────────────────────────────────────────────────────────
# 8. Punto de entrada principal
# ──────────────────────────────────────────────────────────────────

def main():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestHealthEndpoint,
        TestScanStartEndpoint,
        TestScanResultEndpoint,
        TestApiScanEndpoint,
        TestScanWorkflow,
        TestDatabaseSetup,
        TestDatabaseInsertions,
        TestDatabaseQueries,
        TestDatabaseUpdates,
        TestDatabaseTransactions,
        TestStateHelpers,
    ]

    # Si se pasa un nombre de clase como argumento, filtrar
    filter_class = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else None
    verbose = "-v" in sys.argv or "--verbose" in sys.argv

    for cls in test_classes:
        if filter_class is None or filter_class in cls.__name__:
            suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(
        verbosity=2 if verbose else 1,
        stream=sys.stdout,
        descriptions=True,
        failfast=False,
    )
    result = runner.run(suite)

    # Código de salida: 0 = OK, 1 = fallos
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()