#!/bin/bash
# insfrastructure/VM/build_images_vm.sh
set -euo pipefail

# Script para construir todas las imágenes Docker en la VM
echo "🔨 Construyendo todas las imágenes Docker localmente..."

# Directorio base del proyecto
PROJECT_ROOT="/home/idsadmin/projects/upgraded-happiness"
cd "$PROJECT_ROOT"

# Colores para output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date +'%H:%M:%S')] ⚠️${NC} $1"; }
error() { echo -e "${RED}[$(date +'%H:%M:%S')] ❌${NC} $1"; }

# Función para construir una imagen
build_image() {
    local service_name="$1"
    local dockerfile_path="$2"
    local context_path="$3"

    log "🔨 Construyendo $service_name..."

    if [ -f "$dockerfile_path" ]; then
        docker build -t "upgraded-happiness/$service_name:latest" -f "$dockerfile_path" "$context_path"
        log "✅ $service_name construida exitosamente"
    else
        warn "❌ Dockerfile no encontrado: $dockerfile_path"
        return 1
    fi
}

# Verificar Docker
if ! docker info >/dev/null 2>&1; then
    error "Docker no está disponible. ¿Está ejecutándose?"
    exit 1
fi

log "📋 Listando Dockerfiles disponibles..."
find . -name "Dockerfile" -o -name "dockerfile" | sort

echo

# Construir imágenes basándose en la estructura típica del proyecto
# Ajusta estas rutas según tu estructura real
SERVICES=(
    "geoip:./services/geoip/Dockerfile:./services/geoip"
    "ml-detector:./services/ml-detector/Dockerfile:./services/ml-detector"
    "scheduler-firewall:./services/scheduler-firewall/Dockerfile:./services/scheduler-firewall"
    "simple-firewall-agent:./services/simple-firewall-agent/Dockerfile:./services/simple-firewall-agent"
    "dashboard:./services/dashboard/Dockerfile:./services/dashboard"
    "sniffer:./services/sniffer/Dockerfile:./services/sniffer"
)

# También buscar automáticamente por Dockerfiles
log "🔍 Buscando Dockerfiles automáticamente..."
while IFS= read -r -d '' dockerfile; do
    # Extraer directorio y nombre del servicio
    dir=$(dirname "$dockerfile")
    service_name=$(basename "$dir")

    if [[ "$service_name" != "." && "$service_name" != "docker" ]]; then
        log "📦 Encontrado servicio: $service_name en $dir"

        if build_image "$service_name" "$dockerfile" "$dir"; then
            log "✅ Imagen $service_name construida"
        else
            warn "⚠️ Error construyendo $service_name"
        fi
    fi
done < <(find . -name "Dockerfile" -print0)

echo
log "📊 Resumen de imágenes construidas:"
docker images | grep "upgraded-happiness"

echo
log "✅ Construcción completada!"
log "🚀 Ahora puedes ejecutar: ./start_pipeline.sh"