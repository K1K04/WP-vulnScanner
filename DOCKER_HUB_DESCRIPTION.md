# WP VulnScanner Pro

Escáner de seguridad pasivo para WordPress orientado a auditoría defensiva. Detecta vulnerabilidades en plugins/temas, versión core, cabeceras HTTP, postura SSL/TLS, exposición de archivos y señales de reputación, sin modificar el sitio objetivo.

Incluye panel web, API REST, exportes (PDF/Excel/CSV/JSON/HTML), escaneos programados y plan de remediación asistido por IA.

## Supported tags

| Tag | Uso recomendado |
|---|---|
| `latest` | Última build estable. Ideal para laboratorio y validaciones rápidas. |
| `3.0` | Release fija para producción. Opción recomendada. |
| `3` | Alias de la rama mayor estable (`3.x`). |

Recomendación de producción: usa `3.0` o `3`, evita depender de `latest`.

## Qué hace

- Descubrimiento pasivo de versión WordPress, `xmlrpc`, `readme` y señales de hardening.
- Detección de plugins y temas con cruce contra base local de CVEs (48k+).
- Revisión de cabeceras de seguridad: CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy.
- Validación SSL/TLS: protocolo, cifrados y caducidad de certificado.
- Análisis DNS: SPF, DMARC, DKIM y registros MX.
- Enumeración de subdominios con fuentes pasivas (DNS + CT logs).
- Reputación de dominio/IP con integraciones opcionales (VirusTotal, AbuseIPDB, GSB, Shodan, WPScan API).

## Qué incluye

- UI web completa: escáner, historial, dashboard, comparativas y mapa de ataque.
- API REST para automatización en pipelines CI/CD.
- Exportes técnico/ejecutivo: PDF, Excel, CSV, JSON y HTML standalone.
- Plan de acción priorizado por IA (Gemini, Claude u Ollama local).
- Scheduler de escaneos con notificación por email y webhooks.
- PWA con soporte de notificaciones push.

## Quick start

```bash
docker run --rm -p 5000:5000 \
  -e SECRET_KEY=cambia_esta_clave_ahora \
  -e HOST=0.0.0.0 \
  -v wpvulnscan_data:/data \
  kiko4/wpvulnscan:3.0
```

Abre `http://localhost:5000` y sigue este flujo:

1. Abre `Ajustes` y define `SECRET_KEY` antes de usar la app en serio.
2. Pega el dominio o la URL completa del WordPress que quieres auditar.
3. Marca la autorización y pulsa `ESCANEAR`.
4. Revisa primero `Vulnerabilidades` y después `Plan de Acción`.

Si vas a usar IA, feeds externos o integraciones, actívalos en `Ajustes` antes de escanear.

## Variables clave

Obligatoria:
- `SECRET_KEY` (min. 32 caracteres aleatorios)

Opcionales recomendadas:
- `API_KEY` para proteger `/api/*`
- `WPSCAN_API_TOKEN`, `SHODAN_API_KEY`, `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `GSB_API_KEY`
- `AI_PROVIDER` + `GEMINI_API_KEY` o `ANTHROPIC_API_KEY` (si usas IA cloud)

## Seguridad de la imagen

- Contenedor en usuario no root (`uid 1001`)
- Build multi-stage (runtime limpio, sin toolchain de compilación)
- Secretos solo en runtime (`--env-file` o variables), nunca embebidos en imagen

## Legal

Usar exclusivamente sobre sistemas propios o con autorización expresa del propietario. Esta herramienta se distribuye para uso defensivo, educativo y auditoría autorizada.
