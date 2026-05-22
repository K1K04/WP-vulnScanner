"""
openapi_schemas.py — Flask-RESTX models and schemas for OpenAPI documentation
==============================================================================
"""

from flask_restx import fields, Model


# ──── Response Models ────────────────────────────────────────────────────────

ScanResult = {
    "scan_id": fields.String(required=True, description="Identificador único del escaneo"),
    "target_url": fields.String(required=True, description="URL escaneada"),
    "scanned_at": fields.String(required=True, description="Timestamp del escaneo"),
    "risk_label": fields.String(description="Etiqueta de riesgo (LOW, MEDIUM, HIGH, CRITICAL)"),
    "risk_score": fields.Float(description="Puntuación de riesgo (0-10)"),
    "status": fields.String(description="Estado del escaneo"),
    "findings": fields.Raw(description="Hallazgos del escaneo"),
    "ssl_unverified": fields.Boolean(description="Si SSL fue verificado"),
    "legal_accepted": fields.Boolean(description="Si acepto términos legales"),
    "partial": fields.Boolean(description="Si el resultado es parcial (timeout)"),
}

ScanJob = {
    "job_id": fields.String(required=True, description="Identificador del job"),
    "status": fields.String(description="Estado del job (pending, running, done, error)"),
    "url": fields.String(description="URL being scanned"),
    "created_at": fields.DateTime(description="Timestamp de creación"),
    "completed_at": fields.DateTime(description="Timestamp de completación"),
}

HealthResponse = {
    "status": fields.String(required=True, description="Estado del servicio (ok, unhealthy)"),
    "version": fields.String(description="Versión de la aplicación"),
    "timestamp": fields.DateTime(description="Timestamp actual"),
    "database": fields.String(description="Estado de la BD"),
    "uptime": fields.Float(description="Tiempo de operación en segundos"),
}

ErrorResponse = {
    "error": fields.String(required=True, description="Mensaje de error"),
    "error_code": fields.String(description="Código de error estandarizado"),
    "status": fields.Integer(description="HTTP status code"),
    "timestamp": fields.DateTime(description="Timestamp del error"),
    "job_id": fields.String(description="Job ID si aplica"),
}

# ──── Request Models ────────────────────────────────────────────────────────

ScanRequest = {
    "url": fields.String(required=True, description="URL a escanear"),
    "legal_accepted": fields.Boolean(required=True, description="Aceptación de términos legales"),
    "force_rescan": fields.Boolean(description="Forzar reescaneo evitando caché"),
    "callback_url": fields.String(description="URL para webhook de resultado"),
}

BulkScanRequest = {
    "urls": fields.List(fields.String, required=True, description="Lista de URLs a escanear"),
    "legal_accepted": fields.Boolean(required=True, description="Aceptación de términos legales"),
}

ApiKeyRequest = {
    "name": fields.String(required=True, description="Nombre de la API key"),
    "expires_in_days": fields.Integer(description="Días hasta expiración"),
}
