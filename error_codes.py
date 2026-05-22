"""
error_codes.py — Códigos de error estandarizados para WP VulnScanner
====================================================================
Contiene:
  - ErrorCode enum: códigos estandarizados
  - ScanError: excepción con código y contexto debug
  - format_error: convertidor de excepciones a errores estructurados
"""

from __future__ import annotations

import logging
import os
import traceback
from datetime import datetime
from enum import Enum
from typing import Any, Optional

log = logging.getLogger("wpvulnscan.errors")


class ErrorCode(Enum):
    """Códigos de error estandarizados con HTTP status y mensajes por defecto."""
    
    # Errores de escaneo (400-499)
    SCAN_TIMEOUT = ("SCAN_TIMEOUT", 422, "El escaneo superó el tiempo límite configurado")
    SCAN_BUSY = ("SCAN_BUSY", 429, "Servidor ocupado. Demasiados escaneos simultáneos.")
    SCAN_CANCELLED = ("SCAN_CANCELLED", 400, "El escaneo fue cancelado por el usuario")
    SCAN_INVALID_URL = ("SCAN_INVALID_URL", 400, "URL inválida o no accesible")
    SCAN_SSL_ERROR = ("SCAN_SSL_ERROR", 422, "Error de certificado SSL/TLS")
    SCAN_DNS_ERROR = ("SCAN_DNS_ERROR", 422, "Error de resolución DNS")
    SCAN_CONNECTION_ERROR = ("SCAN_CONNECTION_ERROR", 422, "Error de conexión al objetivo")
    SCAN_TIMEOUT_MODULE = ("SCAN_TIMEOUT_MODULE", 422, "Un módulo de escaneo superó su tiempo límite")
    
    # Errores de configuración (500)
    CONFIG_MISSING_API_KEY = ("CONFIG_MISSING_API_KEY", 500, "Falta API key requerida")
    CONFIG_INVALID_TIMEOUT = ("CONFIG_INVALID_TIMEOUT", 500, "Valor de timeout inválido")
    CONFIG_INVALID_CONCURRENCY = ("CONFIG_INVALID_CONCURRENCY", 500, "Valor de concurrencia inválido")
    
    # Errores de base de datos (500)
    DB_CONNECTION_ERROR = ("DB_CONNECTION_ERROR", 500, "Error de conexión a la base de datos")
    DB_QUERY_ERROR = ("DB_QUERY_ERROR", 500, "Error en consulta a la base de datos")
    DB_SAVE_ERROR = ("DB_SAVE_ERROR", 500, "Error al guardar en la base de datos")
    DB_NOT_FOUND = ("DB_NOT_FOUND", 404, "Registro no encontrado en la base de datos")
    
    # Errores de API (401-403, 400)
    API_UNAUTHORIZED = ("API_UNAUTHORIZED", 401, "No autorizado. API key inválida o faltante")
    API_RATE_LIMIT = ("API_RATE_LIMIT", 429, "Límite de rate excedido")
    API_INVALID_REQUEST = ("API_INVALID_REQUEST", 400, "Solicitud inválida")
    API_FORBIDDEN = ("API_FORBIDDEN", 403, "Acceso denegado")
    
    # Errores generales (500)
    INTERNAL_ERROR = ("INTERNAL_ERROR", 500, "Error interno del servidor")
    UNKNOWN_ERROR = ("UNKNOWN_ERROR", 500, "Error desconocido")
    
    @property
    def code_str(self) -> str:
        """Get the code string."""
        return self.value[0]
    
    @property
    def http_status(self) -> int:
        """Get the HTTP status code."""
        return self.value[1]
    
    @property
    def default_message(self) -> str:
        """Get the default message."""
        return self.value[2]
    
    def __str__(self) -> str:
        return self.code_str


ERROR_MESSAGES = {
    ErrorCode.SCAN_TIMEOUT: "El escaneo superó el tiempo límite configurado",
    ErrorCode.SCAN_BUSY: "Servidor ocupado. Demasiados escaneos simultáneos.",
    ErrorCode.SCAN_CANCELLED: "El escaneo fue cancelado por el usuario",
    ErrorCode.SCAN_INVALID_URL: "URL inválida o no accesible",
    ErrorCode.SCAN_SSL_ERROR: "Error de certificado SSL/TLS",
    ErrorCode.SCAN_DNS_ERROR: "Error de resolución DNS",
    ErrorCode.SCAN_CONNECTION_ERROR: "Error de conexión al objetivo",
    ErrorCode.SCAN_TIMEOUT_MODULE: "Un módulo de escaneo superó su tiempo límite",
    
    ErrorCode.CONFIG_MISSING_API_KEY: "Falta API key requerida",
    ErrorCode.CONFIG_INVALID_TIMEOUT: "Valor de timeout inválido",
    ErrorCode.CONFIG_INVALID_CONCURRENCY: "Valor de concurrencia inválido",
    
    ErrorCode.DB_CONNECTION_ERROR: "Error de conexión a la base de datos",
    ErrorCode.DB_QUERY_ERROR: "Error en consulta a la base de datos",
    ErrorCode.DB_SAVE_ERROR: "Error al guardar en la base de datos",
    ErrorCode.DB_NOT_FOUND: "Registro no encontrado en la base de datos",
    
    ErrorCode.API_UNAUTHORIZED: "No autorizado. API key inválida o faltante",
    ErrorCode.API_RATE_LIMIT: "Límite de rate excedido",
    ErrorCode.API_INVALID_REQUEST: "Solicitud inválida",
    ErrorCode.API_FORBIDDEN: "Acceso denegado",
    
    ErrorCode.INTERNAL_ERROR: "Error interno del servidor",
    ErrorCode.UNKNOWN_ERROR: "Error desconocido",
}


class ScanError(Exception):
    """Excepción base para errores de escaneo con código estandarizado.
    
    Uso:
        error = ScanError(
            ErrorCode.SCAN_TIMEOUT,
            job_id="scan_123",
            url="https://example.com",
            timeout_seconds=300
        )
        response = error.to_dict(debug_mode=True)
    """
    
    def __init__(
        self,
        code: ErrorCode,
        message: str = "",
        job_id: str = "",
        url: str = "",
        **context: Any
    ):
        self.code = code
        self.message = message or ERROR_MESSAGES.get(code, "Error desconocido")
        self.job_id = job_id
        self.url = url
        self.context = context
        self.timestamp = datetime.now().isoformat()
        super().__init__(self.message)
    
    def to_dict(self, debug_mode: bool = False) -> dict:
        """Convierte el error a dict con formato estándar.
        
        Args:
            debug_mode: Si True, incluye detalles técnicos (context, traceback)
        
        Returns:
            Dict con estructura estandarizada de error
        """
        error_response = {
            "error_code": self.code.code_str,
            "error": self.message,
            "status": self.code.http_status,
            "timestamp": self.timestamp,
        }
        
        if self.job_id:
            error_response["job_id"] = self.job_id
        
        if self.url:
            error_response["url"] = self.url
        
        debug_enabled = debug_mode or os.environ.get("DEBUG", "false").lower() == "true"
        if debug_enabled and self.context:
            error_response["debug"] = {
                "context": self.context,
            }
            # Si hay excepción en contexto, incluir traceback
            if "exception" in self.context:
                try:
                    error_response["debug"]["traceback"] = traceback.format_exc()
                except Exception:
                    pass
        
        return error_response


def format_error(
    code: ErrorCode,
    message: str = "",
    debug_mode: bool = False,
    job_id: str = "",
    url: str = "",
    **context: Any
) -> dict:
    """Formatea un error con código, mensaje y detalles de debug si está activado.
    
    Args:
        code: Código de error del enum ErrorCode
        message: Mensaje personalizado (opcional, usa el default si está vacío)
        debug_mode: Si True, incluye detalles técnicos
        job_id: ID del scan (opcional)
        url: URL escaneada (opcional)
        **context: Contexto adicional del error
        
    Returns:
        Dict con estructura estandarizada de error
    """
    error = ScanError(code, message=message, job_id=job_id, url=url, **context)
    return error.to_dict(debug_mode=debug_mode)
