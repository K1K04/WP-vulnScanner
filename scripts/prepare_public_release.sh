#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
STAMP="$(date +%Y%m%d_%H%M%S)"
PKG_NAME="wpvulnscan_public_${STAMP}"
PKG_DIR="${DIST_DIR}/${PKG_NAME}"
ARCHIVE="${DIST_DIR}/${PKG_NAME}.tar.gz"

INCLUDE_ITEMS=(
  "app.py"
  "db.py"
  "docker-compose.yml"
  "Dockerfile"
  "nginx.conf"
  "pdf_gen.py"
  "requirements.txt"
  "scan_engine.py"
  "scheduler.py"
  "state.py"
  "update_vulns.py"
  "wp_remediate.py"
  ".env.example"
  ".dockerignore"
  ".gitignore"
  "blueprints"
  "scanner"
  "static"
  "templates"
)

mkdir -p "${PKG_DIR}"

copy_item() {
  local rel="$1"
  local src="${ROOT_DIR}/${rel}"
  local dst="${PKG_DIR}/${rel}"

  if [[ ! -e "${src}" ]]; then
    echo "[WARN] Missing ${rel}, skipping" >&2
    return 0
  fi

  mkdir -p "$(dirname "${dst}")"
  cp -a "${src}" "${dst}"
}

for item in "${INCLUDE_ITEMS[@]}"; do
  copy_item "${item}"
done

cat > "${PKG_DIR}/DEPLOY.txt" <<'EOF'
WP VulnScanner Pro - Public deploy bundle

1) Create local env file:
   cp .env.example .env

2) Edit .env and set at minimum:
   - SECRET_KEY
   - API keys only if needed

3) Build and run with Docker:
   docker compose build --no-cache
   docker compose up -d

4) Open the app:
   http://localhost

Notes:
- This bundle intentionally excludes local DB files, secrets and markdown docs.
- Runtime data will be created in Docker volume /data.
EOF

# Safety cleanup in case some sensitive file slips in from copied directories.
find "${PKG_DIR}" -type f \
  \( -name ".env" -o -name ".env.*" -o -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" -o \
     -name "*.md" -o -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" \) \
  ! -name ".env.example" -delete

# Remove development-only directories if present inside copied trees.
find "${PKG_DIR}" -type d \( -name "tests" -o -name "__pycache__" -o -name ".pytest_cache" -o -name ".github" \) -prune -exec rm -rf {} +

mkdir -p "${DIST_DIR}"
tar -C "${DIST_DIR}" -czf "${ARCHIVE}" "${PKG_NAME}"
sha256sum "${ARCHIVE}" > "${ARCHIVE}.sha256"

echo "[OK] Public package directory: ${PKG_DIR}"
echo "[OK] Public archive: ${ARCHIVE}"
echo "[OK] SHA256 file: ${ARCHIVE}.sha256"
