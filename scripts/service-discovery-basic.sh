#!/bin/bash
# scripts/service-discovery-basic.sh
# Service discovery básico con etcd

set -e

ETCD_ENDPOINT="http://localhost:2379"
SERVICE_PREFIX="/services"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 Service Discovery Básico con etcd${NC}"
echo "Endpoint: $ETCD_ENDPOINT"
echo "Prefijo de servicios: $SERVICE_PREFIX"
echo ""

# Función para verificar etcd
check_etcd() {
    if ! curl -s $ETCD_ENDPOINT/health > /dev/null; then
        echo -e "${RED}❌ etcd no está disponible en $ETCD_ENDPOINT${NC}"
        echo "💡 Ejecuta primero: ./scripts/start-etcd-basic.sh"
        exit 1
    fi
    echo -e "${GREEN}✅ etcd está disponible${NC}"
}

# Función para registrar un servicio
register_service() {
    local service_name=$1
    local service_address=$2
    local service_port=$3
    local ttl=${4:-30}

    local key="$SERVICE_PREFIX/$service_name/$(hostname)-$$"
    local value="{\"address\":\"$service_address\",\"port\":$service_port,\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"hostname\":\"$(hostname)\",\"pid\":$$}"

    echo -e "${BLUE}📝 Registrando servicio: $service_name${NC}"
    echo "   Clave: $key"
    echo "   Dirección: $service_address:$service_port"
    echo "   TTL: ${ttl}s"

    # Registrar con TTL
    etcdctl --endpoints=$ETCD_ENDPOINT put $key "$value" --lease=$(etcdctl --endpoints=$ETCD_ENDPOINT lease grant $ttl | cut -d' ' -f2)

    echo -e "${GREEN}✅ Servicio registrado${NC}"
}

# Función para descubrir servicios
discover_services() {
    local service_name=${1:-""}

    if [ -z "$service_name" ]; then
        echo -e "${BLUE}🔍 Descubriendo todos los servicios:${NC}"
        etcdctl --endpoints=$ETCD_ENDPOINT get $SERVICE_PREFIX/ --prefix --keys-only | while read key; do
            if [ ! -z "$key" ]; then
                service=$(echo $key | cut -d'/' -f3)
                instance=$(echo $key | cut -d'/' -f4)
                value=$(etcdctl --endpoints=$ETCD_ENDPOINT get $key --print-value-only)
                echo -e "${GREEN}🏷️  Servicio: $service${NC}"
                echo -e "   📍 Instancia: $instance"
                echo -e "   📊 Datos: $value"
                echo ""
            fi
        done
    else
        echo -e "${BLUE}🔍 Descubriendo servicio: $service_name${NC}"
        etcdctl --endpoints=$ETCD_ENDPOINT get $SERVICE_PREFIX/$service_name/ --prefix --print-value-only | while read value; do
            if [ ! -z "$value" ]; then
                echo -e "${GREEN}📍 Instancia encontrada:${NC} $value"
            fi
        done
    fi
}

# Función para limpiar servicios expirados
cleanup_services() {
    echo -e "${YELLOW}🧹 Limpiando servicios expirados...${NC}"
    # etcd maneja automáticamente las claves con TTL
    echo -e "${GREEN}✅ Limpieza automática por TTL${NC}"
}

# Función para monitorear cambios
watch_services() {
    local service_name=${1:-""}

    if [ -z "$service_name" ]; then
        echo -e "${BLUE}👀 Monitoreando todos los servicios...${NC}"
        etcdctl --endpoints=$ETCD_ENDPOINT watch $SERVICE_PREFIX/ --prefix
    else
        echo -e "${BLUE}👀 Monitoreando servicio: $service_name${NC}"
        etcdctl --endpoints=$ETCD_ENDPOINT watch $SERVICE_PREFIX/$service_name/ --prefix
    fi
}

# Función de ayuda
show_help() {
    echo "Uso: $0 [comando] [argumentos]"
    echo ""
    echo "Comandos:"
    echo "  register <nombre> <dirección> <puerto> [ttl]  - Registrar servicio"
    echo "  discover [nombre]                             - Descubrir servicios"
    echo "  watch [nombre]                                - Monitorear cambios"
    echo "  cleanup                                       - Limpiar servicios"
    echo "  test                                          - Ejecutar pruebas"
    echo "  healthcheck                                   - Comprobar estado de salud."
    echo ""
    echo "Ejemplos:"
    echo "  $0 register axiom-api localhost 8080 60"
    echo "  $0 discover axiom-api"
    echo "  $0 watch"
}

# Función de prueba
run_tests() {
    echo -e "${BLUE}🧪 Ejecutando pruebas básicas...${NC}"

    # Registrar algunos servicios de prueba
    register_service "axiom-api" "localhost" "8080" 30
    register_service "axiom-worker" "localhost" "8081" 30
    register_service "axiom-db" "localhost" "5432" 60

    echo ""
    echo -e "${BLUE}📋 Servicios registrados:${NC}"
    discover_services

    echo ""
    echo -e "${BLUE}🔍 Buscando axiom-api específicamente:${NC}"
    discover_services "axiom-api"
}
# =============================================================================
# ARREGLO PARA healthcheck() - Reemplazar la función existente
# =============================================================================

healthcheck() {
    local service_name=${1:-""}

    echo -e "${BLUE}🏥 Ejecutando healthcheck de servicios...${NC}"

    if [ -z "$service_name" ]; then
        # Healthcheck de todos los servicios
        local healthy_count=0
        local total_count=0
        local temp_file="/tmp/healthcheck_results_$$"

        # Usar archivo temporal para evitar el problema del subshell
        etcdctl --endpoints=$ETCD_ENDPOINT get $SERVICE_PREFIX/ --prefix --keys-only | while read key; do
            if [ ! -z "$key" ]; then
                service=$(echo $key | cut -d'/' -f3)
                instance=$(echo $key | cut -d'/' -f4)
                value=$(etcdctl --endpoints=$ETCD_ENDPOINT get $key --print-value-only)

                # Extraer datos del servicio (usar cut si no hay jq)
                if command -v jq >/dev/null 2>&1; then
                    address=$(echo $value | jq -r '.address' 2>/dev/null || echo "localhost")
                    port=$(echo $value | jq -r '.port' 2>/dev/null || echo "unknown")
                else
                    # Fallback sin jq - parsing básico
                    address=$(echo $value | grep -o '"address":"[^"]*"' | cut -d'"' -f4 || echo "localhost")
                    port=$(echo $value | grep -o '"port":[0-9]*' | cut -d':' -f2 || echo "unknown")
                fi

                # Incrementar contador total
                echo "total++" >> "$temp_file"

                # Test de conectividad
                if [ "$port" != "unknown" ] && [ "$port" != "null" ] && [ ! -z "$port" ]; then
                    if timeout 3 bash -c "</dev/tcp/$address/$port" 2>/dev/null; then
                        echo -e "   ${GREEN}✅ $service ($instance): HEALTHY${NC} - $address:$port"
                        echo "healthy++" >> "$temp_file"
                    else
                        echo -e "   ${RED}❌ $service ($instance): UNHEALTHY${NC} - $address:$port"
                    fi
                else
                    echo -e "   ${YELLOW}⚠️  $service ($instance): UNKNOWN PORT${NC}"
                fi
            fi
        done

        # Leer contadores del archivo temporal
        if [ -f "$temp_file" ]; then
            total_count=$(grep -c "total++" "$temp_file" 2>/dev/null || echo 0)
            healthy_count=$(grep -c "healthy++" "$temp_file" 2>/dev/null || echo 0)
            rm -f "$temp_file"
        fi

        echo ""
        echo -e "${BLUE}📊 Resumen Healthcheck:${NC}"
        echo -e "   Total servicios: $total_count"
        echo -e "   Servicios healthy: ${GREEN}$healthy_count${NC}"
        echo -e "   Servicios unhealthy: ${RED}$((total_count - healthy_count))${NC}"

    else
        # Healthcheck de servicio específico
        echo -e "${BLUE}🔍 Checking $service_name...${NC}"
        etcdctl --endpoints=$ETCD_ENDPOINT get $SERVICE_PREFIX/$service_name/ --prefix --print-value-only | while read value; do
            if [ ! -z "$value" ]; then
                if command -v jq >/dev/null 2>&1; then
                    address=$(echo $value | jq -r '.address' 2>/dev/null || echo "localhost")
                    port=$(echo $value | jq -r '.port' 2>/dev/null || echo "unknown")
                else
                    address=$(echo $value | grep -o '"address":"[^"]*"' | cut -d'"' -f4 || echo "localhost")
                    port=$(echo $value | grep -o '"port":[0-9]*' | cut -d':' -f2 || echo "unknown")
                fi

                if [ "$port" != "unknown" ] && timeout 3 bash -c "</dev/tcp/$address/$port" 2>/dev/null; then
                    echo -e "   ${GREEN}✅ HEALTHY${NC} - $address:$port"
                else
                    echo -e "   ${RED}❌ UNHEALTHY${NC} - $address:$port"
                fi
            fi
        done
    fi
}

# Main
case "${1:-help}" in
    "register")
        check_etcd
        if [ $# -lt 4 ]; then
            echo -e "${RED}❌ Faltan argumentos${NC}"
            echo "Uso: $0 register <nombre> <dirección> <puerto> [ttl]"
            exit 1
        fi
        register_service "$2" "$3" "$4" "${5:-30}"
        ;;
    "discover")
        check_etcd
        discover_services "$2"
        ;;
    "watch")
        check_etcd
        watch_services "$2"
        ;;
    "cleanup")
        check_etcd
        cleanup_services
        ;;
    "test")
        check_etcd
        run_tests
        ;;
    "healthcheck")
        check_etcd
        healthcheck "$2"
        ;;
    "help"|*)
        show_help
        ;;

esac