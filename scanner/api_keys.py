"""
WP VulnScanner — API Key Manager
=====================================
Gestión segura de claves API de terceros (VirusTotal, AbuseIPDB, etc.)
con cifrado Fernet (AES-128-CBC + HMAC-SHA256) derivado de SECRET_KEY.

Tabla SQLite: `api_keys`
  id          TEXT PK       — uuid4
  service     TEXT NOT NULL — identificador del servicio (VT_API_KEY, etc.)
  label       TEXT          — nombre legible por humanos
  value_enc   TEXT          — valor cifrado en base64
  created_at  TEXT NOT NULL
  last_used   TEXT          — última vez que se leyó en un escaneo
  last_tested TEXT          — última prueba de conectividad
  test_ok     INTEGER       — 1=OK, 0=FAIL, NULL=no probado
  active      INTEGER DEFAULT 1

Buenas prácticas implementadas:
  - La clave Fernet se deriva de SECRET_KEY vía SHA-256 → base64url 32B
  - No se almacena el valor en claro nunca, ni en logs ni en JSON de respuesta
  - El endpoint GET /api/settings/keys devuelve valor ofuscado (****ABCD)
  - Test de conectividad por servicio antes de guardar
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

                                                                                
SERVICES: dict[str, dict] = {
    "VT_API_KEY": {
        "label":       "VirusTotal",
        "description": "Valida reputación de dominios y URLs detectadas.",
        "priority":    "recommended",
        "test_url":    "https://www.virustotal.com/api/v3/domains/google.com",
        "test_header": "x-apikey",
        "env_var":     "VT_API_KEY",
        "docs_url":    "https://www.virustotal.com/gui/my-apikey",
        "icon":        "globe",
    },
    "ABUSEIPDB_API_KEY": {
        "label":       "AbuseIPDB",
        "description": "Revisa reputación de IPs y rangos sospechosos.",
        "priority":    "optional",
        "test_url":    "https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1",
        "test_header": "Key",
        "env_var":     "ABUSEIPDB_API_KEY",
        "docs_url":    "https://www.abuseipdb.com/account/api",
        "icon":        "server",
    },
    "GSB_API_KEY": {
        "label":       "Google Safe Browsing",
        "description": "Detecta URLs marcadas como phishing o malware.",
        "priority":    "optional",
        "test_url":    None,                                   
        "test_header": None,
        "env_var":     "GSB_API_KEY",
        "docs_url":    "https://developers.google.com/safe-browsing/v4/get-started",
        "icon":        "shield",
    },
    "WPSCAN_API_TOKEN": {
        "label":       "WPScan",
        "description": "Aporta CVEs de WordPress/plugins/temas actualizados.",
        "priority":    "recommended",
        "test_url":    "https://wpscan.com/api/v3/status",
        "test_header": "Authorization",
        "test_header_prefix": "Token token=",
        "env_var":     "WPSCAN_API_TOKEN",
        "docs_url":    "https://wpscan.com/profile",
        "icon":        "key",
    },
    "SMTP_PASS": {
        "label":       "SMTP Password",
        "description": "Permite enviar alertas por email desde el sistema.",
        "priority":    "optional",
        "test_url":    None,
        "test_header": None,
        "env_var":     "SMTP_PASS",
        "docs_url":    None,
        "icon":        "lock",
    },
    "GEMINI_API_KEY": {
        "label":       "Google Gemini (IA)",
        "description": "Habilita el chat IA y el plan de remediación automático.",
        "priority":    "recommended",
        "test_url":    None,
        "test_header": None,
        "env_var":     "GEMINI_API_KEY",
        "docs_url":    "https://aistudio.google.com/app/apikey",
        "icon":        "key",
    },
    "GITHUB_TOKEN": {
        "label":       "GitHub (Advisory DB)",
        "description": "Sube el límite de actualizaciones desde Advisory DB.",
        "priority":    "optional",
        "test_url":    None,
        "test_header": None,
        "env_var":     "GITHUB_TOKEN",
        "docs_url":    "https://github.com/settings/tokens",
        "icon":        "key",
    },
}


                                                                                

def _get_fernet():
    """
    Crea un objeto Fernet con clave derivada de SECRET_KEY.
    Fernet = AES-128-CBC + HMAC-SHA256, implementado en cryptography.
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError as e:
        raise RuntimeError(
            "Instala cryptography: pip install cryptography"
        ) from e

    secret = os.environ.get("SECRET_KEY", "default-insecure-key-change-me")
                                                                      
    key_bytes = hashlib.sha256(secret.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)


def encrypt_value(plaintext: str) -> str:
    """Cifra un valor sensible. Devuelve token Fernet en base64."""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    """Descifra un valor cifrado con encrypt_value.
    Retorna cadena vacía si el token es inválido (p.ej. SECRET_KEY cambió).
    """
    try:
        from cryptography.fernet import InvalidToken
        return _get_fernet().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, Exception):
        log.warning("decrypt_value: token inválido o SECRET_KEY cambió — retornando vacío")
        return ""


def mask_value(plaintext: str) -> str:
    """Ofusca un valor para mostrar en UI: ****ABCD (últimos 4 chars)."""
    if len(plaintext) <= 4:
        return "****"
    return "****" + plaintext[-4:]


                                                                                

def init_api_keys_table(conn: sqlite3.Connection) -> None:
    """Crea la tabla api_keys si no existe. Llamar desde init_db()."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id          TEXT PRIMARY KEY,
            service     TEXT NOT NULL UNIQUE,
            label       TEXT NOT NULL,
            value_enc   TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            last_used   TEXT,
            last_tested TEXT,
            test_ok     INTEGER,
            active      INTEGER DEFAULT 1
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_apikeys_service ON api_keys(service)")
    conn.commit()


def upsert_api_key(db_path: str, service: str, plaintext_value: str) -> dict:
    """
    Inserta o actualiza una clave API cifrada.
    Devuelve el registro con valor enmascarado (sin plaintext).
    """
    if service not in SERVICES:
        raise ValueError(f"Servicio desconocido: {service}")
    if not plaintext_value.strip():
        raise ValueError("El valor no puede estar vacío")

    meta    = SERVICES[service]
    enc     = encrypt_value(plaintext_value.strip())
    now     = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    key_id  = str(uuid.uuid4())[:12]

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        existing = conn.execute(
            "SELECT id FROM api_keys WHERE service=?", (service,)
        ).fetchone()

        if existing:
            conn.execute(
                "UPDATE api_keys SET value_enc=?, active=1 WHERE service=?",
                (enc, service)
            )
            key_id = existing["id"]
        else:
            conn.execute(
                """INSERT INTO api_keys (id,service,label,value_enc,created_at,active)
                   VALUES (?,?,?,?,?,1)""",
                (key_id, service, meta["label"], enc, now)
            )

                                                                              
        os.environ[meta["env_var"]] = plaintext_value.strip()

        conn.commit()
        log.info("API key upserted for service: %s", service)
    finally:
        conn.close()

    return {
        "id":         key_id,
        "service":    service,
        "label":      meta["label"],
        "value_mask": mask_value(plaintext_value.strip()),
        "active":     True,
    }


def delete_api_key(db_path: str, service: str) -> bool:
    """Elimina la clave de un servicio (también del env)."""
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM api_keys WHERE service=?", (service,))
    changed = conn.total_changes > 0
    conn.commit()
    conn.close()

    meta = SERVICES.get(service, {})
    if meta.get("env_var") and meta["env_var"] in os.environ:
        del os.environ[meta["env_var"]]

    log.info("API key deleted for service: %s (found: %s)", service, changed)
    return changed


def get_api_keys(db_path: str) -> list[dict]:
    """
    Lista todas las claves con valores enmascarados.
    Nunca devuelve el plaintext ni el ciphertext.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id,service,label,value_enc,created_at,last_used,last_tested,test_ok,active "
        "FROM api_keys ORDER BY service"
    ).fetchall()
    conn.close()

    result = []
    for row in rows:
        meta = SERVICES.get(row["service"], {})
        try:
            plain = decrypt_value(row["value_enc"])
            mask  = mask_value(plain)
        except Exception:
            mask = "****INVALID"

        result.append({
            "id":          row["id"],
            "service":     row["service"],
            "label":       row["label"],
            "description": meta.get("description", ""),
            "priority":    meta.get("priority", "optional"),
            "env_var":     meta.get("env_var", row["service"]),
            "docs_url":    meta.get("docs_url"),
            "icon":        meta.get("icon", "key"),
            "value_mask":  mask,
            "created_at":  row["created_at"],
            "last_used":   row["last_used"],
            "last_tested": row["last_tested"],
            "test_ok":     row["test_ok"],
            "active":      bool(row["active"]),
        })

    return result


def get_decrypted_key(db_path: str, service: str) -> Optional[str]:
    """
    Devuelve el valor en claro de una clave para uso interno.
    Primero consulta la BD; si no está, cae a env vars.
    Actualiza last_used tras la lectura.
    """
                             
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT value_enc FROM api_keys WHERE service=? AND active=1",
        (service,)
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE api_keys SET last_used=? WHERE service=?",
            (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"), service)
        )
        conn.commit()
        conn.close()
        try:
            return decrypt_value(row[0])
        except Exception as e:
            log.warning("Error decrypting key for %s: %s", service, e)
            return None

    conn.close()

                                      
    env_var = SERVICES.get(service, {}).get("env_var", service)
    return os.environ.get(env_var) or None


def load_keys_to_env(db_path: str) -> None:
    """
    Carga todas las claves activas al os.environ al iniciar la app.
    Llamar desde init_db() / app startup.
    """
    try:
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT service, value_enc FROM api_keys WHERE active=1"
        ).fetchall()
        conn.close()

        loaded = 0
        for service, value_enc in rows:
            meta = SERVICES.get(service, {})
            env_var = meta.get("env_var", service)
            try:
                plain = decrypt_value(value_enc)
                os.environ[env_var] = plain
                loaded += 1
            except Exception as e:
                log.warning("Could not load key for %s: %s", service, e)

        if loaded:
            log.info("Loaded %d API key(s) from DB into environment", loaded)
    except Exception as e:
        log.warning("load_keys_to_env failed: %s", e)


                                                                                

def test_api_key(db_path: str, service: str) -> dict:
    """
    Prueba la conectividad de una clave API.
    Actualiza test_ok y last_tested en la BD.
    """
    import requests                                                 

    meta = SERVICES.get(service)
    if not meta:
        return {"ok": False, "error": "Servicio desconocido"}

    plain = get_decrypted_key(db_path, service)
    if not plain:
        return {"ok": False, "error": "Clave no configurada"}

    test_url = meta.get("test_url")
    if not test_url:
        return {"ok": True, "message": "Conectividad no verificable automáticamente"}

    try:
        headers: dict = {}
        header_name = meta.get("test_header")
        if header_name:
            prefix = meta.get("test_header_prefix", "")
            headers[header_name] = prefix + plain

        r = requests.get(test_url, headers=headers, timeout=8, allow_redirects=False)
        ok = r.status_code in (200, 204)
        result = {
            "ok":          ok,
            "status_code": r.status_code,
            "message":     "Conexión correcta" if ok else f"HTTP {r.status_code}",
        }
    except requests.exceptions.Timeout:
        result = {"ok": False, "error": "Timeout al conectar"}
    except requests.exceptions.ConnectionError:
        result = {"ok": False, "error": "Error de conexión"}
    except Exception as e:
        result = {"ok": False, "error": str(e)}

                   
    try:
        conn = sqlite3.connect(db_path)
        conn.execute(
            "UPDATE api_keys SET last_tested=?, test_ok=? WHERE service=?",
            (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"), 1 if result["ok"] else 0, service)
        )
        conn.commit()
        conn.close()
    except Exception as db_e:
        log.warning("Could not update test result for %s: %s", service, db_e)

    return result


def get_services_catalog() -> list[dict]:
    """Devuelve el catálogo de servicios soportados (sin datos sensibles)."""
    return [
        {
            "service":     svc,
            "label":       meta["label"],
            "description": meta["description"],
            "priority":    meta.get("priority", "optional"),
            "env_var":     meta.get("env_var", svc),
            "docs_url":    meta.get("docs_url"),
            "icon":        meta.get("icon", "key"),
        }
        for svc, meta in SERVICES.items()
    ]
