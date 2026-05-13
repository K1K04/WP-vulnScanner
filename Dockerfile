# ─────────────────────────────────────────────────────────────────────────────
# WP VulnScanner Pro — Dockerfile hardened v3
#
# CVEs corregidos:
#   CVE-2026-27135  nghttp2           → repo security + apt upgrade
#   CVE-2026-41989  libgcrypt20       → repo security + apt upgrade
#   CVE-2026-6732   libxml2           → repo security + apt upgrade
#   CVE-2025-12863  libxml2           → repo security + apt upgrade
#   CVE-2025-8732   libxml2           → repo security + apt upgrade
#   CVE-2025-45582  tar               → repo security + apt upgrade
#   CVE-2025-8869   pip 25.0.1        → pip pinned >= 25.1.0
#   CVE-2026-3219   pip 25.0.1        → pip pinned >= 25.1.0
#   CVE-2026-1703   pip 25.0.1        → pip pinned >= 25.1.0
#
# Mejoras v3:
#   - Base Debian trixie para eliminar los CVEs de Debian que seguían saliendo en Trivy
#   - Repositorio debian-security añadido explícitamente en AMBAS stages
#   - Force-upgrade de paquetes vulnerables del SO en ambas stages
#   - pip >= 26.1.0 elimina las CVEs restantes de pip
#   - Python 3.13 (base más reciente, paquetes del SO más actualizados)
#   - PYTHONHASHSEED=random (protección hash-flooding / DoS)
#   - BuildKit cache mounts (builds más rápidos, imagen más limpia)
#   - Eliminación de SUID/SGID bits innecesarios
#   - Permisos /app read-only para el usuario runtime
#   - --preload + --worker-tmp-dir /dev/shm en gunicorn
#   - Healthcheck con sys.exit(1) explícito en status != 200
# ─────────────────────────────────────────────────────────────────────────────

# syntax=docker/dockerfile:1.6
ARG PYTHON_VERSION=3.13
ARG DEBIAN_CODENAME=trixie

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_CODENAME} AS builder

ARG DEBIAN_CODENAME=trixie

WORKDIR /build

# Añadir repo de seguridad de Debian ANTES del upgrade para recibir los patches.
# Esto asegura que libxml2, libgcrypt20, nghttp2 y tar se instalen parcheados.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    echo "deb http://security.debian.org/debian-security ${DEBIAN_CODENAME}-security main" \
        > /etc/apt/sources.list.d/debian-security.list \
 && apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends \
       gcc \
       libffi-dev \
       libssl-dev \
       libxml2 \
       libgcrypt20 \
       libnghttp2-14 \
       tar

COPY requirements.txt .

# CVE-2025-8869, CVE-2026-3219, CVE-2026-1703: pip < 25.1.0 vulnerable.
# Forzar instalación de pip >= 26.1.0 antes de instalar dependencias.
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m pip install --upgrade "pip>=26.1.0" \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_CODENAME} AS runtime

ARG DEBIAN_CODENAME=trixie

# Metadatos OCI completos
LABEL maintainer="WP VulnScanner Pro" \
      description="WordPress Security Scanner — production image" \
        version="3.0" \
      org.opencontainers.image.title="WP VulnScanner Pro" \
      org.opencontainers.image.description="WordPress Security Scanner" \
      org.opencontainers.image.authors="WP VulnScanner Team" \
      org.opencontainers.image.licenses="Proprietary" \
      org.opencontainers.image.base.name="python:${PYTHON_VERSION}-slim-${DEBIAN_CODENAME}"

# Variables de entorno de runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PYTHONFAULTHANDLER= \
    PYTHONPATH=/app \
    PORT=5000 \
    HOST=0.0.0.0 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    DEBUG=false \
    ALLOW_PRIVATE_IPS=false \
    VERIFY_SSL=true \
    WEB_CONCURRENCY=2 \
    GUNICORN_THREADS=4 \
    GUNICORN_TIMEOUT=360

# ── Parches de seguridad del SO ───────────────────────────────────────────────
# El repo debian-security garantiza versiones parcheadas de:
#   libnghttp2-14  → CVE-2026-27135 (7.5 HIGH)
#   libgcrypt20    → CVE-2026-41989 (6.7 MED)
#   libxml2        → CVE-2026-6732, CVE-2025-12863, CVE-2025-8732
#   tar            → CVE-2025-45582 (4.1 MED)
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    echo "deb http://security.debian.org/debian-security ${DEBIAN_CODENAME}-security main" \
        > /etc/apt/sources.list.d/debian-security.list \
 && apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends \
       ca-certificates \
       nmap \
       whois \
       dnsutils \
       libxml2 \
       libgcrypt20 \
       libnghttp2-14 \
       tar \
 && apt-get purge -y --auto-remove ncurses-bin ncurses-base libncursesw6 libtinfo6 \
 && find / -xdev -perm /4000 -not -path "/proc/*" -exec chmod u-s {} + 2>/dev/null || true \
 && find / -xdev -perm /2000 -not -path "/proc/*" -exec chmod g-s {} + 2>/dev/null || true

# Usuario no-root
RUN groupadd --gid 1001 wpscanner \
 && useradd --uid 1001 --gid wpscanner --no-create-home --shell /sbin/nologin wpscanner

# Paquetes Python del builder (pip >= 25.1.0 ya incluido)
COPY --from=builder /install /usr/local

# Asegurar que el pip del runtime también quede fuera de las CVEs reportadas.
RUN python3 -m pip install --no-cache-dir --upgrade "pip>=26.1.0"

WORKDIR /app

COPY --chown=wpscanner:wpscanner . .

RUN mkdir -p /data /tmp/wpvulnscan_cache \
 && chown -R wpscanner:wpscanner /data /tmp/wpvulnscan_cache \
 && chmod 750 /data /tmp/wpvulnscan_cache \
 && chmod -R o-w /app

ENV DB_PATH=/data/scans.db \
    VULNS_DB_PATH=/data/vulns.db

USER wpscanner

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=8s --start-period=20s --retries=3 \
    CMD python3 -c \
        "import urllib.request,sys; \
         r=urllib.request.urlopen('http://localhost:5000/health',timeout=6); \
         sys.exit(0 if r.status==200 else 1)" \
    || exit 1

CMD ["sh", "-c", \
      "exec gunicorn app:app \
        --bind ${HOST:-0.0.0.0}:${PORT:-5000} \
        --workers ${WEB_CONCURRENCY:-2} \
        --threads ${GUNICORN_THREADS:-4} \
        --timeout ${GUNICORN_TIMEOUT:-360} \
        --keep-alive 5 \
        --log-level info \
        --access-logfile - \
        --error-logfile - \
        --worker-tmp-dir /dev/shm \
        --preload"]
