"""
blueprints/ai.py — Plan de remediación IA y chat con Gemini + Claude + fallback Ollama
"""
from __future__ import annotations

import json
import logging
import os
import socket as _socket
import sys
import time
import urllib.error as _ue
import urllib.request as _ur

from flask import Blueprint, current_app, jsonify, request

from db import delete_ai_chat_history, get_ai_chat_history, save_ai_chat_message
from state import _validate_job_id, rate_limit

log = logging.getLogger("wpvulnscan.ai")
ai_bp = Blueprint("ai", __name__)

_GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
_CLAUDE_ENDPOINT = "https://api.anthropic.com/v1/messages"
_DEFAULT_GEMINI_MODEL = "gemini-2.0-flash"
_DEFAULT_CLAUDE_MODEL = "claude-haiku-4-5-20251001"
_DEFAULT_OLLAMA_BASE = "http://127.0.0.1:11434"
_DEFAULT_OLLAMA_MODEL = "qwen2.5:3b"
_DEFAULT_OLLAMA_FALLBACKS = "qwen2.5:3b,qwen2.5:7b,llama3.2:3b,mistral:7b-instruct,phi3:mini"
_DEFAULT_GEMINI_TIMEOUT_SECONDS = 60
_DEFAULT_GEMINI_STREAM_TIMEOUT_SECONDS = 90
_DEFAULT_CLAUDE_TIMEOUT_SECONDS = 75
_DEFAULT_CLAUDE_STREAM_TIMEOUT_SECONDS = 120
_DEFAULT_OLLAMA_TIMEOUT_SECONDS = 180
_DEFAULT_OLLAMA_STREAM_TIMEOUT_SECONDS = 180
_DEFAULT_OLLAMA_PLAN_TIMEOUT_SECONDS = 300
_DEFAULT_OLLAMA_TAGS_TIMEOUT_SECONDS = 5
_OLLAMA_MODELS_CACHE = {"ts": 0.0, "models": []}


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int, min_val: int = 1, max_val: int = 3600) -> int:
    raw = _env(name, str(default))
    try:
        val = int(raw)
    except Exception:
        return default
    if val < min_val:
        return min_val
    if val > max_val:
        return max_val
    return val


def _gemini_api_key() -> str:
    return (
        getattr(sys.modules.get("state"), "GEMINI_API_KEY", "")
        or _env("GEMINI_API_KEY", "")
        or ""
    )


def _claude_api_key() -> str:
    return (
        getattr(sys.modules.get("state"), "ANTHROPIC_API_KEY", "")
        or _env("ANTHROPIC_API_KEY", "")
        or ""
    )


def _get_api_key() -> str:
                                                            
    return _gemini_api_key()


def _gemini_model() -> str:
    return _env("GEMINI_MODEL", _DEFAULT_GEMINI_MODEL)


def _claude_model() -> str:
    return _env("CLAUDE_MODEL", _DEFAULT_CLAUDE_MODEL)


def _ollama_base() -> str:
    return _env("OLLAMA_BASE_URL", _DEFAULT_OLLAMA_BASE).rstrip("/")


def _ollama_model() -> str:
    return _env("OLLAMA_MODEL", _DEFAULT_OLLAMA_MODEL)


def _ollama_fallback_models() -> list[str]:
    raw = _env("OLLAMA_MODEL_FALLBACKS", _DEFAULT_OLLAMA_FALLBACKS)
    out: list[str] = []
    for part in raw.replace(";", ",").split(","):
        model = part.strip()
        if model and model not in out:
            out.append(model)
    return out


def _ollama_list_local_models(force: bool = False) -> list[str]:
    now = time.time()
    cached = _OLLAMA_MODELS_CACHE.get("models") or []
    cached_ts = float(_OLLAMA_MODELS_CACHE.get("ts") or 0.0)

                                                              
    if not force and cached and (now - cached_ts) < 30:
        return list(cached)

    try:
        req = _ur.Request(_ollama_url("/api/tags"), headers=_headers(), method="GET")
        with _ur.urlopen(
            req,
            timeout=_env_int(
                "OLLAMA_TAGS_TIMEOUT_SECONDS",
                _DEFAULT_OLLAMA_TAGS_TIMEOUT_SECONDS,
                min_val=2,
                max_val=120,
            ),
        ) as resp:
            result = json.loads(resp.read().decode("utf-8"))

        models: list[str] = []
        for item in result.get("models", []):
            name = str(item.get("name", "")).strip()
            if name and name not in models:
                models.append(name)

        _OLLAMA_MODELS_CACHE["ts"] = now
        _OLLAMA_MODELS_CACHE["models"] = models
        return models
    except Exception:
        if force:
            _OLLAMA_MODELS_CACHE["ts"] = now
            _OLLAMA_MODELS_CACHE["models"] = []
        return list(_OLLAMA_MODELS_CACHE.get("models") or [])


def _resolve_ollama_model() -> str:
    preferred = _ollama_model()
    local_models = _ollama_list_local_models()

                                                                      
    if not local_models or preferred in local_models:
        return preferred

    for cand in _ollama_fallback_models():
        if cand in local_models:
            log.warning("OLLAMA_MODEL=%s no instalado. Usando fallback local %s", preferred, cand)
            return cand

    chosen = local_models[0]
    log.warning("OLLAMA_MODEL=%s no instalado. Usando modelo local detectado %s", preferred, chosen)
    return chosen


def _provider_pref(raw: str = "") -> str:
    p = (raw or _env("AI_PROVIDER", "auto")).lower().strip()
    if p in ("auto", "gemini", "claude", "ollama"):
        return p
    return "auto"


def _is_timeout_exception(exc: Exception) -> bool:
    if isinstance(exc, (TimeoutError, _socket.timeout)):
        return True
    low = str(exc).lower()
    return "timed out" in low or "timeout" in low


def _gemini_timeout(stream: bool = False) -> int:
    if stream:
        return _env_int(
            "GEMINI_STREAM_TIMEOUT_SECONDS",
            _DEFAULT_GEMINI_STREAM_TIMEOUT_SECONDS,
            min_val=5,
            max_val=1800,
        )
    return _env_int(
        "GEMINI_TIMEOUT_SECONDS",
        _DEFAULT_GEMINI_TIMEOUT_SECONDS,
        min_val=5,
        max_val=1800,
    )


def _claude_timeout(stream: bool = False) -> int:
    if stream:
        return _env_int(
            "CLAUDE_STREAM_TIMEOUT_SECONDS",
            _DEFAULT_CLAUDE_STREAM_TIMEOUT_SECONDS,
            min_val=5,
            max_val=1800,
        )
    return _env_int(
        "CLAUDE_TIMEOUT_SECONDS",
        _DEFAULT_CLAUDE_TIMEOUT_SECONDS,
        min_val=5,
        max_val=1800,
    )


def _ollama_timeout(stream: bool = False, purpose: str = "chat") -> int:
    if stream:
        base_stream = _env_int(
            "OLLAMA_STREAM_TIMEOUT_SECONDS",
            _DEFAULT_OLLAMA_STREAM_TIMEOUT_SECONDS,
            min_val=5,
            max_val=3600,
        )
        if purpose == "plan":
            return max(base_stream, _env_int("OLLAMA_PLAN_TIMEOUT_SECONDS", _DEFAULT_OLLAMA_PLAN_TIMEOUT_SECONDS, 10, 3600))
        return base_stream

    base = _env_int(
        "OLLAMA_TIMEOUT_SECONDS",
        _DEFAULT_OLLAMA_TIMEOUT_SECONDS,
        min_val=5,
        max_val=3600,
    )
    if purpose == "plan":
        return max(base, _env_int("OLLAMA_PLAN_TIMEOUT_SECONDS", _DEFAULT_OLLAMA_PLAN_TIMEOUT_SECONDS, 10, 3600))
    return base


def _gemini_url(stream: bool = False) -> str:
    key = _get_api_key()
    action = "streamGenerateContent" if stream else "generateContent"
    qs = "alt=sse&key=" + key if stream else "key=" + key
    return f"{_GEMINI_BASE}/{_gemini_model()}:{action}?{qs}"


def _claude_url() -> str:
    return _CLAUDE_ENDPOINT


def _ollama_url(path: str) -> str:
    return f"{_ollama_base()}{path}"


def _headers() -> dict:
    return {"Content-Type": "application/json"}


def _claude_headers() -> dict:
    return {
        "Content-Type": "application/json",
        "x-api-key": _claude_api_key(),
        "anthropic-version": "2023-06-01",
    }


def _read_http_error(exc: _ue.HTTPError) -> str:
    try:
        raw = exc.read()
        txt = raw.decode("utf-8", errors="ignore") if isinstance(raw, (bytes, bytearray)) else str(raw)
        if not txt:
            return str(exc.reason or f"HTTP {exc.code}")
        try:
            obj = json.loads(txt)
            if isinstance(obj.get("error"), dict):
                msg = obj.get("error", {}).get("message", "")
                if msg:
                    return str(msg)
            if isinstance(obj.get("error"), str):
                return obj["error"]
            if isinstance(obj.get("message"), str):
                return obj["message"]
        except Exception:
            pass
        return txt[:500]
    except Exception:
        return str(exc.reason or f"HTTP {exc.code}")


def _is_quota_message(msg: str) -> bool:
    low = (msg or "").lower()
    markers = (
        "quota exceeded",
        "exceeded your current quota",
        "free_tier_requests",
        "free_tier_input_token_count",
        "limit: 0",
        "billing",
    )
    return any(m in low for m in markers)


def _should_fallback(code: int, msg: str) -> bool:
                                                                             
    return code == 429 or (code in (403, 400) and _is_quota_message(msg))


def _json_err(error: str, status: int, hint: str = "", extra: dict | None = None):
    payload = {"error": error}
    if hint:
        payload["hint"] = hint
    if extra:
        payload.update(extra)
    return jsonify(payload), status


def _no_gemini_key_response():
    return _json_err(
        "GEMINI_API_KEY no configurada",
        503,
        "Añade GEMINI_API_KEY=... a .env o usa AI_PROVIDER=ollama para modo local gratis.",
    )


def _no_provider_response(detail: str = ""):
    hint = (
        "Configura GEMINI_API_KEY o ANTHROPIC_API_KEY, "
        "o activa Ollama local gratis con: `ollama serve` y `ollama pull qwen2.5:3b`."
    )
    extra = {
        "providers": {
            "gemini_key_set": bool(_gemini_api_key()),
            "claude_key_set": bool(_claude_api_key()),
            "ollama_base": _ollama_base(),
        }
    }
    if detail:
        extra["detail"] = detail[:220]
    return _json_err("No hay proveedor IA disponible", 503, hint, extra=extra)


def _map_gemini_http_error(exc: _ue.HTTPError, body_msg: str = ""):
    msg = body_msg or _read_http_error(exc)
    log.error("Gemini HTTP %s — %s", exc.code, msg)
    if exc.code == 400:
        return _json_err(f"Bad Request Gemini: {msg}", 400)
    if exc.code in (401, 403) and not _is_quota_message(msg):
        return _json_err("API key inválida — revisa GEMINI_API_KEY en .env", 401)
    if _should_fallback(exc.code, msg):
        return _json_err(
            "Gemini sin cuota disponible en este momento",
            429,
            "Activa Ollama local gratis (AI_PROVIDER=ollama) o espera al reset de cuota.",
            extra={"provider": "gemini", "reason": msg[:180]},
        )
    return _json_err(f"Gemini HTTP {exc.code}: {msg}", 502)


def _map_claude_http_error(exc: _ue.HTTPError, body_msg: str = ""):
    msg = body_msg or _read_http_error(exc)
    log.error("Claude HTTP %s — %s", exc.code, msg)
    if exc.code == 400:
        return _json_err(f"Bad Request Claude: {msg}", 400)
    if exc.code in (401, 403):
        return _json_err("API key inválida — revisa ANTHROPIC_API_KEY en .env", 401)
    if exc.code == 429:
        return _json_err(
            "Claude con rate limit/cuota temporal",
            429,
            "Prueba en unos segundos o usa Ollama local (AI_PROVIDER=ollama).",
            extra={"provider": "claude", "reason": msg[:180]},
        )
    return _json_err(f"Claude HTTP {exc.code}: {msg}", 502)


def _map_claude_exception(exc: Exception):
    if _is_timeout_exception(exc):
        return _json_err(
            "Claude tardó demasiado en responder",
            504,
            "Aumenta CLAUDE_TIMEOUT_SECONDS/CLAUDE_STREAM_TIMEOUT_SECONDS en .env o reintenta.",
            extra={"provider": "claude"},
        )
    return _json_err(f"Error contactando Claude: {str(exc)[:180]}", 502)


def _map_ollama_http_error(exc: _ue.HTTPError, body_msg: str = ""):
    msg = body_msg or _read_http_error(exc)
    low = msg.lower()
    log.error("Ollama HTTP %s — %s", exc.code, msg)
    if "model" in low and "not found" in low:
        local_models = _ollama_list_local_models(force=True)
        if local_models:
            shown = ", ".join(local_models[:6])
            hint = (
                f"Modelo configurado no instalado. Modelos locales detectados: {shown}. "
                f"Ajusta OLLAMA_MODEL o ejecuta: ollama pull {_ollama_model()}"
            )
        else:
            fallback_cmds = " | ".join([f"ollama pull {m}" for m in _ollama_fallback_models()[:4]])
            hint = (
                f"Ejecuta: ollama pull {_ollama_model()} "
                f"(alternativas: {fallback_cmds})"
            )
        return _json_err(
            "Modelo de Ollama no encontrado",
            503,
            hint,
            extra={
                "provider": "ollama",
                "reason": msg[:160],
                "configured_model": _ollama_model(),
                "available_models": local_models,
            },
        )
    if exc.code == 404:
        return _json_err(
            "Ollama no responde en la ruta esperada",
            503,
            "Verifica OLLAMA_BASE_URL y que `ollama serve` esté activo.",
            extra={"provider": "ollama", "base_url": _ollama_base()},
        )
    return _json_err(f"Ollama HTTP {exc.code}: {msg}", 502)


def _map_ollama_exception(exc: Exception):
    if _is_timeout_exception(exc):
        return _json_err(
            "Ollama tardó demasiado en responder",
            504,
            (
                "El modelo local necesita más tiempo o está saturado. "
                "Prueba un modelo más ligero o ajusta OLLAMA_PLAN_TIMEOUT_SECONDS/"
                "OLLAMA_TIMEOUT_SECONDS en .env."
            ),
            extra={"provider": "ollama", "base_url": _ollama_base()},
        )
    low = str(exc).lower()
    if "connection refused" in low or "failed to establish a new connection" in low:
        return _json_err(
            "Ollama no está disponible",
            503,
            "Inicia Ollama con `ollama serve` y descarga un modelo con `ollama pull qwen2.5:3b`.",
            extra={"provider": "ollama", "base_url": _ollama_base()},
        )
    return _json_err(f"Error contactando Ollama: {str(exc)[:180]}", 502)


def _gemini_human_error(code: int, msg: str) -> str:
    if code == 400:
        return f"Bad Request Gemini: {msg}"
    if code in (401, 403) and not _is_quota_message(msg):
        return "API key de Gemini inválida — revisa GEMINI_API_KEY en .env"
    if _should_fallback(code, msg):
        return "Gemini sin cuota disponible. Configura Ollama local gratis o espera al reset."
    return f"Gemini HTTP {code}: {msg}"


def _claude_human_error(code: int, msg: str) -> str:
    if code == 400:
        return f"Bad Request Claude: {msg}"
    if code in (401, 403):
        return "API key de Claude inválida — revisa ANTHROPIC_API_KEY en .env"
    if code == 429:
        return "Claude con límite temporal. Reintenta o usa Ollama local."
    return f"Claude HTTP {code}: {msg}"


def _ollama_human_error(msg: str) -> str:
    low = msg.lower()
    if "timed out" in low or "timeout" in low:
        return (
            "Ollama tardó demasiado en responder. "
            "Prueba un modelo más ligero o aumenta OLLAMA_PLAN_TIMEOUT_SECONDS/OLLAMA_TIMEOUT_SECONDS."
        )
    if "model" in low and "not found" in low:
        local_models = _ollama_list_local_models(force=True)
        if local_models:
            shown = ", ".join(local_models[:6])
            return (
                f"Modelo de Ollama no encontrado. Disponibles en local: {shown}. "
                f"Ajusta OLLAMA_MODEL o ejecuta: ollama pull {_ollama_model()}"
            )
        return f"Modelo de Ollama no encontrado. Ejecuta: ollama pull {_ollama_model()}"
    if "connection refused" in low or "failed to establish a new connection" in low:
        return "Ollama no está activo. Ejecuta: ollama serve"
    return f"Error Ollama: {msg[:180]}"


def _build_payload(
    messages: list[dict],
    system: str = "",
    max_tokens: int = 4096,
    temperature: float = 0.7,
) -> dict:
    """Convierte mensajes estilo {role, content} al formato Gemini contents."""
    contents = []
    for m in messages:
        role = "user" if m.get("role") == "user" else "model"
        contents.append({
            "role": role,
            "parts": [{"text": str(m.get("content", "")).strip()}],
        })
    payload: dict = {
        "contents": contents,
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature},
    }
    if system:
        payload["systemInstruction"] = {"parts": [{"text": system}]}
    return payload


def _build_ollama_messages(messages: list[dict], system: str = "") -> list[dict]:
    out: list[dict] = []
    if system:
        out.append({"role": "system", "content": system})
    for m in messages:
        role = "assistant" if m.get("role") == "assistant" else "user"
        content = str(m.get("content", "")).strip()
        if content:
            out.append({"role": role, "content": content})
    return out


def _build_ollama_payload(
    messages: list[dict],
    system: str = "",
    max_tokens: int = 2048,
    stream: bool = False,
    model: str | None = None,
    temperature: float = 0.7,
) -> dict:
    return {
        "model": model or _ollama_model(),
        "messages": _build_ollama_messages(messages, system=system),
        "stream": stream,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }


def _build_claude_messages(messages: list[dict]) -> list[dict]:
    out: list[dict] = []
    for m in messages:
        role = "assistant" if m.get("role") == "assistant" else "user"
        content = str(m.get("content", "")).strip()
        if content:
            out.append({"role": role, "content": content})
    return out


def _build_claude_payload(
    messages: list[dict],
    system: str = "",
    max_tokens: int = 2048,
    stream: bool = False,
    model: str | None = None,
    temperature: float = 0.7,
) -> dict:
    payload: dict = {
        "model": model or _claude_model(),
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": _build_claude_messages(messages),
        "stream": stream,
    }
    if system:
        payload["system"] = system
    return payload


def _extract_text(result: dict) -> str:
    text = ""
    for candidate in result.get("candidates", []):
        for part in candidate.get("content", {}).get("parts", []):
            text += part.get("text", "")
    return text


def _extract_claude_text(result: dict) -> str:
    text = ""
    for part in result.get("content", []) or []:
        if isinstance(part, dict) and part.get("type") == "text":
            text += str(part.get("text", ""))
    return text


def _gemini_generate(
    messages: list[dict],
    system: str = "",
    max_tokens: int = 4096,
    timeout_s: int | None = None,
    temperature: float = 0.7,
) -> dict:
    payload = json.dumps(
        _build_payload(messages, system=system, max_tokens=max_tokens, temperature=temperature),
        ensure_ascii=False,
    ).encode("utf-8")
    req = _ur.Request(_gemini_url(False), data=payload, headers=_headers(), method="POST")
    with _ur.urlopen(req, timeout=timeout_s or _gemini_timeout(False)) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    return {"text": _extract_text(result), "model": _gemini_model(), "provider": "gemini"}


def _claude_generate(
    messages: list[dict],
    system: str = "",
    max_tokens: int = 2048,
    timeout_s: int | None = None,
    temperature: float = 0.7,
) -> dict:
    model_name = _claude_model()
    payload = json.dumps(
        _build_claude_payload(
            messages,
            system=system,
            max_tokens=max_tokens,
            stream=False,
            model=model_name,
            temperature=temperature,
        ),
        ensure_ascii=False,
    ).encode("utf-8")
    req = _ur.Request(_claude_url(), data=payload, headers=_claude_headers(), method="POST")
    with _ur.urlopen(req, timeout=timeout_s or _claude_timeout(False)) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    return {"text": _extract_claude_text(result), "model": f"claude:{model_name}", "provider": "claude"}


def _ollama_generate(
    messages: list[dict],
    system: str = "",
    max_tokens: int = 2048,
    timeout_s: int | None = None,
    model: str | None = None,
    temperature: float = 0.7,
) -> dict:
    selected_model = model or _resolve_ollama_model()
    payload = json.dumps(
        _build_ollama_payload(
            messages,
            system=system,
            max_tokens=max_tokens,
            stream=False,
            model=selected_model,
            temperature=temperature,
        ),
        ensure_ascii=False,
    ).encode("utf-8")
    req = _ur.Request(_ollama_url("/api/chat"), data=payload, headers=_headers(), method="POST")
    with _ur.urlopen(req, timeout=timeout_s or _ollama_timeout(stream=False, purpose="chat")) as resp:
        result = json.loads(resp.read().decode("utf-8"))

    if result.get("error"):
        raise RuntimeError(str(result.get("error")))

    model_name = result.get("model") or selected_model
    text = result.get("message", {}).get("content", "")
    return {"text": text, "model": f"ollama:{model_name}", "provider": "ollama"}


def _gemini_stream_chunks(
    messages: list[dict],
    system: str = "",
    max_tokens: int = 2048,
    timeout_s: int | None = None,
):
    payload = json.dumps(
        _build_payload(messages, system=system, max_tokens=max_tokens),
        ensure_ascii=False,
    ).encode("utf-8")
    req = _ur.Request(_gemini_url(True), data=payload, headers=_headers(), method="POST")
    with _ur.urlopen(req, timeout=timeout_s or _gemini_timeout(True)) as resp:
        for raw_line in resp:
            line = raw_line.decode("utf-8", errors="ignore").rstrip()
            if not line or not line.startswith("data: "):
                continue
            data_str = line[6:].strip()
            if not data_str or data_str == "[DONE]":
                break
            try:
                evt = json.loads(data_str)
                for candidate in evt.get("candidates", []):
                    for part in candidate.get("content", {}).get("parts", []):
                        chunk = part.get("text", "")
                        if chunk:
                            yield chunk
            except Exception:
                continue


def _claude_stream_chunks(
    messages: list[dict],
    system: str = "",
    max_tokens: int = 2048,
    timeout_s: int | None = None,
):
    payload = json.dumps(
        _build_claude_payload(
            messages,
            system=system,
            max_tokens=max_tokens,
            stream=True,
        ),
        ensure_ascii=False,
    ).encode("utf-8")
    req = _ur.Request(_claude_url(), data=payload, headers=_claude_headers(), method="POST")
    with _ur.urlopen(req, timeout=timeout_s or _claude_timeout(True)) as resp:
        for raw_line in resp:
            line = raw_line.decode("utf-8", errors="ignore").strip()
            if not line or not line.startswith("data:"):
                continue
            payload_raw = line[5:].strip()
            if not payload_raw or payload_raw == "[DONE]":
                continue
            try:
                evt = json.loads(payload_raw)
            except Exception:
                continue

                                               
                                              
                                             
            delta = evt.get("delta") if isinstance(evt, dict) else None
            if isinstance(delta, dict) and isinstance(delta.get("text"), str):
                chunk = delta.get("text", "")
                if chunk:
                    yield chunk
                continue

            if isinstance(evt.get("text"), str):
                chunk = evt.get("text", "")
                if chunk:
                    yield chunk


def _ollama_stream_chunks(
    messages: list[dict],
    system: str = "",
    max_tokens: int = 2048,
    timeout_s: int | None = None,
):
    selected_model = _resolve_ollama_model()
    payload = json.dumps(
        _build_ollama_payload(
            messages,
            system=system,
            max_tokens=max_tokens,
            stream=True,
            model=selected_model,
        ),
        ensure_ascii=False,
    ).encode("utf-8")
    req = _ur.Request(_ollama_url("/api/chat"), data=payload, headers=_headers(), method="POST")
    emitted = False
    with _ur.urlopen(req, timeout=timeout_s or _ollama_timeout(stream=True, purpose="chat")) as resp:
        for raw_line in resp:
            line = raw_line.decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            evt = json.loads(line)
            if evt.get("error"):
                raise RuntimeError(str(evt.get("error")))
                                                                                
                                                        
            chunk = evt.get("message", {}).get("content", "") or evt.get("response", "")
            if chunk:
                emitted = True
                yield chunk
            if evt.get("done"):
                break

                                                                          
                                                                                  
    if not emitted:
        log.warning("Ollama stream sin contenido. Intentando fallback no-stream.")
        try:
            out = _ollama_generate(
                messages,
                system=system,
                max_tokens=max_tokens,
                timeout_s=_ollama_timeout(stream=False, purpose="chat"),
                model=selected_model,
            )
            text = (out.get("text") or "").strip()
            if text:
                emitted = True
                yield text
            else:
                raise RuntimeError("Ollama devolvió stream vacío y respuesta no-stream vacía")
        except Exception as exc:
            log.warning("Fallback no-stream tras stream vacío falló: %s", exc)
            raise RuntimeError(str(exc))


def _sse_text(text: str) -> str:
    return f"data: {json.dumps({'text': text}, ensure_ascii=False)}\n\n"


def _sse_error(msg: str) -> str:
    return f"data: {json.dumps({'error': msg[:280]}, ensure_ascii=False)}\n\n"


def _invoke_ollama_nonstream(
    messages: list[dict],
    system: str,
    max_tokens: int,
    purpose: str = "chat",
    temperature: float = 0.7,
):
    timeout_s = _ollama_timeout(stream=False, purpose=purpose)
    try:
        return _ollama_generate(
            messages,
            system=system,
            max_tokens=max_tokens,
            timeout_s=timeout_s,
            temperature=temperature,
        ), None
    except _ue.HTTPError as exc:
        return None, _map_ollama_http_error(exc)
    except Exception as exc:
        if purpose == "plan" and _is_timeout_exception(exc):
            retry_tokens_cfg = _env_int("AI_PLAN_RETRY_MAX_TOKENS", 1536, min_val=256, max_val=4096)
            retry_tokens = min(max_tokens, retry_tokens_cfg)
            retry_timeout = _env_int(
                "OLLAMA_PLAN_RETRY_TIMEOUT_SECONDS",
                max(timeout_s + 60, 360),
                min_val=15,
                max_val=7200,
            )
            log.warning(
                "Timeout de Ollama al generar plan. Reintento con num_predict=%s y timeout=%ss",
                retry_tokens,
                retry_timeout,
            )
            try:
                out = _ollama_generate(
                    messages,
                    system=system,
                    max_tokens=retry_tokens,
                    timeout_s=retry_timeout,
                    temperature=temperature,
                )
                out["notice"] = "Se aplicó un reintento por latencia de Ollama local."
                out["retry"] = {
                    "reason": "timeout",
                    "max_tokens": retry_tokens,
                    "timeout_seconds": retry_timeout,
                }
                return out, None
            except _ue.HTTPError as rexc:
                return None, _map_ollama_http_error(rexc)
            except Exception as rexc:
                return None, _map_ollama_exception(rexc)
        return None, _map_ollama_exception(exc)


def _invoke_claude_nonstream(
    messages: list[dict],
    system: str,
    max_tokens: int,
    temperature: float = 0.7,
):
    try:
        return _claude_generate(
            messages,
            system=system,
            max_tokens=max_tokens,
            timeout_s=_claude_timeout(False),
            temperature=temperature,
        ), None
    except _ue.HTTPError as exc:
        return None, _map_claude_http_error(exc)
    except Exception as exc:
        return None, _map_claude_exception(exc)


def _invoke_nonstream(
    messages: list[dict],
    system: str,
    max_tokens: int,
    provider: str,
    purpose: str = "chat",
    temperature: float = 0.7,
):
    gemini_key_set = bool(_gemini_api_key())
    claude_key_set = bool(_claude_api_key())

    if provider == "gemini":
        if not gemini_key_set:
            return None, _no_gemini_key_response()
        try:
            return _gemini_generate(
                messages,
                system=system,
                max_tokens=max_tokens,
                timeout_s=_gemini_timeout(False),
                temperature=temperature,
            ), None
        except _ue.HTTPError as exc:
            return None, _map_gemini_http_error(exc)
        except Exception as exc:
            log.warning("Gemini non-stream error: %s", exc)
            return None, _json_err(f"Error contactando Gemini: {str(exc)[:180]}", 502)

    if provider == "claude":
        if not claude_key_set:
            return None, _json_err(
                "ANTHROPIC_API_KEY no configurada",
                503,
                "Añade ANTHROPIC_API_KEY=... a .env o usa AI_PROVIDER=ollama para modo local gratis.",
            )
        return _invoke_claude_nonstream(messages, system, max_tokens, temperature=temperature)

    if provider == "ollama":
        return _invoke_ollama_nonstream(messages, system, max_tokens, purpose=purpose, temperature=temperature)

                      
    if gemini_key_set:
        try:
            return _gemini_generate(
                messages,
                system=system,
                max_tokens=max_tokens,
                timeout_s=_gemini_timeout(False),
                temperature=temperature,
            ), None
        except _ue.HTTPError as exc:
            msg = _read_http_error(exc)
            if _should_fallback(exc.code, msg):
                log.warning("Gemini sin cuota/rate-limit (%s). Intentando fallback.", msg[:180])
                if claude_key_set:
                    out, cerr = _invoke_claude_nonstream(
                        messages,
                        system,
                        max_tokens,
                        temperature=temperature,
                    )
                    if not cerr:
                        out["fallback_from"] = "gemini"
                        out["notice"] = "Gemini sin cuota disponible; se usó Claude."
                        return out, None
                out, oerr = _invoke_ollama_nonstream(
                    messages,
                    system,
                    max_tokens,
                    purpose=purpose,
                    temperature=temperature,
                )
                if oerr:
                    return None, oerr
                out["fallback_from"] = "gemini"
                out["notice"] = "Gemini sin cuota disponible; se usó Ollama local."
                return out, None
            return None, _map_gemini_http_error(exc, body_msg=msg)
        except Exception as exc:
            log.warning("Gemini no disponible (%s). Intentando fallback.", exc)
            if claude_key_set:
                out, cerr = _invoke_claude_nonstream(
                    messages,
                    system,
                    max_tokens,
                    temperature=temperature,
                )
                if not cerr:
                    out["fallback_from"] = "gemini"
                    out["notice"] = "Gemini no disponible; se usó Claude."
                    return out, None
            out, oerr = _invoke_ollama_nonstream(
                messages,
                system,
                max_tokens,
                purpose=purpose,
                temperature=temperature,
            )
            if oerr:
                return None, oerr
            out["fallback_from"] = "gemini"
            out["notice"] = "Gemini no disponible; se usó Ollama local."
            return out, None

    if claude_key_set:
        out, cerr = _invoke_claude_nonstream(
            messages,
            system,
            max_tokens,
            temperature=temperature,
        )
        if not cerr:
            out["notice"] = "Usando Claude (Anthropic)."
            return out, None

                                                       
    out, oerr = _invoke_ollama_nonstream(
        messages,
        system,
        max_tokens,
        purpose=purpose,
        temperature=temperature,
    )
    if oerr:
        if not gemini_key_set and not claude_key_set:
            return None, _no_provider_response()
        return None, oerr
    out["notice"] = "Usando Ollama local (modo gratis)."
    return out, None


                                                                                

@ai_bp.route("/api/ai-plan", methods=["POST"])
@rate_limit(3)
def api_ai_plan():
    data = request.get_json(silent=True) or {}
    body = data.get("body") or {}
    prompt = (body.get("prompt") or data.get("prompt", "")).strip()
    if not prompt:
        return jsonify({"error": "prompt requerido"}), 400
    if len(prompt) > 24_000:
        prompt = prompt[:24_000]

    provider = _provider_pref((body.get("provider") or data.get("provider") or ""))
    system_prompt = (body.get("system") or data.get("system", "")).strip()
    plan_max_tokens = _env_int("AI_PLAN_MAX_TOKENS", 2048, min_val=512, max_val=4096)
    plan_temperature = 0.2

    result, err = _invoke_nonstream(
        messages=[{"role": "user", "content": prompt}],
        system=system_prompt,
        max_tokens=plan_max_tokens,
        provider=provider,
        purpose="plan",
        temperature=plan_temperature,
    )
    if err:
        return err
    return jsonify(result)


def _persist_chat_turn(
    scan_id: str,
    session_id: str,
    user_text: str,
    assistant_text: str,
    *,
    provider: str = "",
    model: str = "",
    persist_chat: bool = True,
):
    if not persist_chat:
        return
    if not scan_id or not _validate_job_id(scan_id):
        return
    user_txt = (user_text or "").strip()
    asst_txt = (assistant_text or "").strip()
    if not user_txt or not asst_txt:
        return
    try:
        save_ai_chat_message(scan_id, "user", user_txt, session_id=session_id)
        save_ai_chat_message(
            scan_id,
            "assistant",
            asst_txt,
            session_id=session_id,
            provider=provider,
            model=model,
        )
    except Exception as exc:
        log.debug("No se pudo persistir chat para %s: %s", scan_id, exc)


@ai_bp.route("/api/ai-chat/history", methods=["GET"])
@rate_limit(20)
def api_ai_chat_history_get():
    scan_id = (request.args.get("scan_id") or "").strip()
    session_id = (request.args.get("session_id") or "default").strip() or "default"
    limit_raw = request.args.get("limit", "80")

    if not scan_id:
        return jsonify({"error": "scan_id requerido"}), 400
    if not _validate_job_id(scan_id):
        return jsonify({"error": "scan_id inválido"}), 400

    try:
        limit = int(limit_raw)
    except Exception:
        limit = 80

    rows = get_ai_chat_history(scan_id, session_id=session_id, limit=limit)
    return jsonify({"scan_id": scan_id, "session_id": session_id, "messages": rows})


@ai_bp.route("/api/ai-chat/history", methods=["DELETE"])
@rate_limit(20)
def api_ai_chat_history_delete():
    data = request.get_json(silent=True) or {}
    scan_id = (
        (request.args.get("scan_id") or "").strip()
        or str(data.get("scan_id") or "").strip()
    )
    session_id = (
        (request.args.get("session_id") or "").strip()
        or str(data.get("session_id") or "").strip()
        or "default"
    )

    if not scan_id:
        return jsonify({"error": "scan_id requerido"}), 400
    if not _validate_job_id(scan_id):
        return jsonify({"error": "scan_id inválido"}), 400

    deleted = delete_ai_chat_history(scan_id, session_id=session_id)
    return jsonify({"ok": True, "deleted": deleted, "scan_id": scan_id, "session_id": session_id})


                                                                                

@ai_bp.route("/api/ai-chat", methods=["POST"])
@rate_limit(10)
def api_ai_chat():
    data = request.get_json(silent=True) or {}
    system = (data.get("system") or "").strip()
    messages = data.get("messages") or []
    do_stream = bool(data.get("stream", True))
    provider = _provider_pref(data.get("provider", ""))
    scan_id = str(data.get("scan_id") or "").strip()
    session_id = str(data.get("session_id") or "default").strip() or "default"
    persist_chat = bool(data.get("persist_chat", True))

    if not messages:
        return jsonify({"error": "messages requerido"}), 400
    if len(messages) > 40:
        return jsonify({"error": "Máximo 40 mensajes por conversación"}), 400
    if sum(len(str(m.get("content", ""))) for m in messages) + len(system) > 80_000:
        return jsonify({"error": "Contexto demasiado largo"}), 400
    if scan_id and not _validate_job_id(scan_id):
        return jsonify({"error": "scan_id inválido"}), 400

    clean = [
        {"role": m["role"], "content": str(m.get("content", "")).strip()}
        for m in messages
        if m.get("role") in ("user", "assistant") and str(m.get("content", "")).strip()
    ]
    if not clean:
        return jsonify({"error": "Sin mensajes válidos"}), 400

    last_user_text = ""
    for m in reversed(clean):
        if m.get("role") == "user":
            last_user_text = str(m.get("content") or "").strip()
            break

    if not do_stream:
        result, err = _invoke_nonstream(
            messages=clean,
            system=system,
            max_tokens=2048,
            provider=provider,
            purpose="chat",
        )
        if err:
            return err
        _persist_chat_turn(
            scan_id,
            session_id,
            last_user_text,
            str(result.get("text") or ""),
            provider=str(result.get("provider") or ""),
            model=str(result.get("model") or ""),
            persist_chat=persist_chat,
        )
        return jsonify(result)

    def generate():
        gemini_key_set = bool(_gemini_api_key())
        claude_key_set = bool(_claude_api_key())
        assistant_chunks: list[str] = []
        used_provider = ""
        used_model = ""

        def _stream_provider(name: str):
            nonlocal used_provider, used_model
            used_provider = name
            if name == "gemini":
                used_model = _gemini_model()
                for c in _gemini_stream_chunks(clean, system=system, max_tokens=2048):
                    if c:
                        assistant_chunks.append(c)
                        yield _sse_text(c)
                return
            if name == "claude":
                used_model = f"claude:{_claude_model()}"
                for c in _claude_stream_chunks(clean, system=system, max_tokens=2048):
                    if c:
                        assistant_chunks.append(c)
                        yield _sse_text(c)
                return

            used_model = f"ollama:{_resolve_ollama_model()}"
            for c in _ollama_stream_chunks(clean, system=system, max_tokens=2048):
                if c:
                    assistant_chunks.append(c)
                    yield _sse_text(c)

        def _done_frame() -> str:
            _persist_chat_turn(
                scan_id,
                session_id,
                last_user_text,
                "".join(assistant_chunks),
                provider=used_provider,
                model=used_model,
                persist_chat=persist_chat,
            )
            return "data: [DONE]\n\n"

                                      
        if provider == "gemini":
            if not gemini_key_set:
                yield _sse_error("GEMINI_API_KEY no configurada. Añádela a .env.")
                return
            try:
                for evt in _stream_provider("gemini"):
                    yield evt
                yield _done_frame()
                return
            except _ue.HTTPError as exc:
                msg = _read_http_error(exc)
                yield _sse_error(_gemini_human_error(exc.code, msg))
                return
            except Exception as exc:
                yield _sse_error(f"Error contactando Gemini: {str(exc)[:180]}")
                return

                                      
        if provider == "claude":
            if not claude_key_set:
                yield _sse_error("ANTHROPIC_API_KEY no configurada. Añádela a .env.")
                return
            try:
                for evt in _stream_provider("claude"):
                    yield evt
                yield _done_frame()
                return
            except _ue.HTTPError as exc:
                msg = _read_http_error(exc)
                yield _sse_error(_claude_human_error(exc.code, msg))
                return
            except Exception as exc:
                yield _sse_error(f"Error contactando Claude: {str(exc)[:180]}")
                return

                                      
        if provider == "ollama":
            try:
                for evt in _stream_provider("ollama"):
                    yield evt
                yield _done_frame()
                return
            except _ue.HTTPError as exc:
                yield _sse_error(_ollama_human_error(_read_http_error(exc)))
                return
            except Exception as exc:
                yield _sse_error(_ollama_human_error(str(exc)))
                return

                             
        if gemini_key_set:
            try:
                for evt in _stream_provider("gemini"):
                    yield evt
                yield _done_frame()
                return
            except _ue.HTTPError as exc:
                msg = _read_http_error(exc)
                if _should_fallback(exc.code, msg):
                    log.warning("Gemini sin cuota/rate-limit en stream. Fallback en auto.")
                    if claude_key_set:
                        try:
                            for evt in _stream_provider("claude"):
                                yield evt
                            yield _done_frame()
                            return
                        except Exception as cexc:
                            log.warning("Fallback Claude falló en stream: %s", cexc)
                    try:
                        for evt in _stream_provider("ollama"):
                            yield evt
                        yield _done_frame()
                        return
                    except _ue.HTTPError as oexc:
                        yield _sse_error(_ollama_human_error(_read_http_error(oexc)))
                        return
                    except Exception as oexc:
                        yield _sse_error(_ollama_human_error(str(oexc)))
                        return
                yield _sse_error(_gemini_human_error(exc.code, msg))
                return
            except Exception as gexc:
                log.warning("Gemini stream no disponible (%s). Intentando fallback.", gexc)
                if claude_key_set:
                    try:
                        for evt in _stream_provider("claude"):
                            yield evt
                        yield _done_frame()
                        return
                    except Exception as cexc:
                        log.warning("Claude fallback en stream falló: %s", cexc)
                try:
                    for evt in _stream_provider("ollama"):
                        yield evt
                    yield _done_frame()
                    return
                except Exception as oexc:
                    yield _sse_error(_ollama_human_error(str(oexc)))
                    return

        if claude_key_set:
            try:
                for evt in _stream_provider("claude"):
                    yield evt
                yield _done_frame()
                return
            except Exception as cexc:
                log.warning("Claude stream no disponible (%s). Intentando Ollama.", cexc)

        try:
            for evt in _stream_provider("ollama"):
                yield evt
            yield _done_frame()
            return
        except Exception as exc:
            yield _sse_error(
                "No hay proveedor IA disponible. Configura GEMINI_API_KEY/ANTHROPIC_API_KEY "
                "o activa Ollama local (ollama serve). "
                f"Detalle: {str(exc)[:140]}"
            )

    return current_app.response_class(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
