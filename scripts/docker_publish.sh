#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE="${ROOT_DIR}/Dockerfile"
BUILD_CONTEXT="${ROOT_DIR}"

DOCKERHUB_USER="${DOCKERHUB_USER:-kiko4}"
IMAGE_NAME="${IMAGE_NAME:-wpvulnscan}"
VERSION=""
SOURCE_IMAGE="wpvulnscan:release-candidate"
TARGET_STAGE="runtime"
BUILD_IMAGE=1
PUSH_LATEST=1
DRY_RUN=0

usage() {
  cat <<'EOF'
Uso:
  ./scripts/docker_publish.sh --user <dockerhub_user> --version <X.Y|X.Y.Z> [opciones]

Opciones:
  -u, --user <user>          Usuario Docker Hub (tambien vale DOCKERHUB_USER)
  -r, --repo <repo>          Nombre del repositorio (default: wpvulnscan)
  -v, --version <version>    Version semantica, ej: 1.0 o 1.0.3
  --source-image <image>     Imagen local origen (default: wpvulnscan:release-candidate)
  --target <stage>           Target de Dockerfile para build (default: runtime)
  --no-build                 No construye; reutiliza --source-image ya creada
  --no-latest                No publica la etiqueta latest
  --dry-run                  Muestra comandos sin ejecutarlos
  -h, --help                 Mostrar ayuda

Ejemplo:
  ./scripts/docker_publish.sh -u kiko4 -r wpvulnscan -v 1.0
EOF
}

log() {
  printf '%s\n' "$*"
}

run_cmd() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run]'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

infer_user_from_docker() {
  if [[ -n "${DOCKERHUB_USER}" ]]; then
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi
  DOCKERHUB_USER="$(docker info --format '{{.Username}}' 2>/dev/null || true)"
}

validate_inputs() {
  if [[ -z "${DOCKERHUB_USER}" ]]; then
    log "Error: falta --user (o variable DOCKERHUB_USER)."
    exit 1
  fi

  if [[ -z "${VERSION}" ]]; then
    log "Error: falta --version."
    exit 1
  fi

  VERSION="${VERSION#v}"

  if [[ ! "${VERSION}" =~ ^([0-9]+)\.([0-9]+)(\.([0-9]+))?$ ]]; then
    log "Error: version invalida '${VERSION}'. Usa X.Y o X.Y.Z"
    exit 1
  fi

  if [[ "${BUILD_IMAGE}" -eq 0 && "${DRY_RUN}" -eq 0 ]]; then
    if ! docker image inspect "${SOURCE_IMAGE}" >/dev/null 2>&1; then
      log "Error: la imagen local ${SOURCE_IMAGE} no existe."
      log "Tip: ejecuta sin --no-build o crea la imagen antes."
      exit 1
    fi
  fi
}

build_tags() {
  local major minor patch
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  patch="${BASH_REMATCH[4]:-}"

  TAGS=()

  if [[ -n "${patch}" ]]; then
    TAGS+=("${major}.${minor}.${patch}")
  fi

  TAGS+=("${major}.${minor}")
  TAGS+=("${major}")

  if [[ "${PUSH_LATEST}" -eq 1 ]]; then
    TAGS+=("latest")
  fi

  # Deduplicacion preservando orden
  declare -A seen=()
  FINAL_TAGS=()
  local t
  for t in "${TAGS[@]}"; do
    if [[ -z "${seen[$t]+x}" ]]; then
      FINAL_TAGS+=("${t}")
      seen[$t]=1
    fi
  done
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -u|--user)
        DOCKERHUB_USER="$2"
        shift 2
        ;;
      -r|--repo)
        IMAGE_NAME="$2"
        shift 2
        ;;
      -v|--version)
        VERSION="$2"
        shift 2
        ;;
      --source-image)
        SOURCE_IMAGE="$2"
        shift 2
        ;;
      --target)
        TARGET_STAGE="$2"
        shift 2
        ;;
      --no-build)
        BUILD_IMAGE=0
        shift
        ;;
      --no-latest)
        PUSH_LATEST=0
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        log "Error: opcion no reconocida: $1"
        usage
        exit 1
        ;;
    esac
  done

  infer_user_from_docker
  validate_inputs
  build_tags

  local remote_image
  remote_image="${DOCKERHUB_USER}/${IMAGE_NAME}"

  log "Publicando imagen ${remote_image}"
  log "Version solicitada: ${VERSION}"
  log "Tags a publicar: ${FINAL_TAGS[*]}"
  log ""

  if [[ "${BUILD_IMAGE}" -eq 1 ]]; then
    run_cmd docker build --target "${TARGET_STAGE}" -t "${SOURCE_IMAGE}" -f "${DOCKERFILE}" "${BUILD_CONTEXT}"
  else
    log "Saltando build, usando imagen local: ${SOURCE_IMAGE}"
  fi

  local tag
  for tag in "${FINAL_TAGS[@]}"; do
    run_cmd docker tag "${SOURCE_IMAGE}" "${remote_image}:${tag}"
  done

  for tag in "${FINAL_TAGS[@]}"; do
    run_cmd docker push "${remote_image}:${tag}"
  done

  log ""
  log "Listo. Puedes probarlo con:"
  log "docker run --rm -p 5000:5000 -e SECRET_KEY=cambia_esta_clave -e HOST=0.0.0.0 -e PORT=5000 ${remote_image}:${FINAL_TAGS[0]}"
}

main "$@"
