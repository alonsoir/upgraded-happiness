#!/bin/bash

# =============================================================================
# QUICK START - SCADA Platform (MEJORADO v2.0)
# =============================================================================
# Script ultra-rápido para levantar la plataforma cuando ya está configurada
# Incorpora lecciones aprendidas de troubleshooting
# =============================================================================

set -e

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}🚀 QUICK START - SCADA Platform (v2.0)${NC}"
echo "========================================"

# Función para verificar componentes con más detalle
check_component_status() {
    local component=$1
    local process_name=$2

    if pgrep -f "$process_name" &>/dev/null; then
        echo -e "  ✅ $component: ${GREEN}ACTIVO${NC}"
        return 0
    else
        echo -e "  ❌ $component: ${RED}INACTIVO${NC}"
        return 1
    fi
}

# Limpiar procesos previos con verificación
echo -e "${YELLOW}🧹 Limpiando procesos previos...${NC}"
make stop &>/dev/null || true
pkill -f "smart_broker\|lightweight_ml\|promiscuous" &>/dev/null || true

# Esperar limpieza
sleep 3

# Verificar limpieza
remaining=$(pgrep -f "smart_broker\|lightweight_ml\|promiscuous" | wc -l)
if [ $remaining -eq 0 ]; then
    echo -e "${GREEN}✅ Limpieza completada${NC}"
else
    echo -e "${YELLOW}⚠️ Algunos procesos siguen activos ($remaining)${NC}"
fi

# Iniciar plataforma
echo -e "${YELLOW}⚡ Iniciando plataforma...${NC}"
if make quick-start; then
    echo -e "${GREEN}✅ Comando de inicio ejecutado${NC}"
else
    echo -e "${RED}❌ Error en comando de inicio${NC}"
    echo -e "Prueba ejecutar: ${YELLOW}./start-scada-platform.sh${NC} para diagnóstico completo"
    exit 1
fi

# Esperar inicialización más tiempo
echo -e "${CYAN}⏳ Esperando inicialización de componentes (10 segundos)...${NC}"
sleep 10

# Verificar estado con más detalle
echo -e "${YELLOW}🔍 Verificando estado de componentes...${NC}"
echo "=================================="

# Verificar cada componente
broker_ok=false
ml_ok=false
agent_ok=false

check_component_status "ZeroMQ Broker" "smart_broker" && broker_ok=true
check_component_status "ML Detector" "lightweight_ml" && ml_ok=true
check_component_status "Promiscuous Agent" "promiscuous" && agent_ok=true

echo ""

# Conteo de componentes
components_active=0
$broker_ok && ((components_active++))
$ml_ok && ((components_active++))
$agent_ok && ((components_active++))

# Verificación adicional de ZeroMQ
if $broker_ok; then
    echo -e "${CYAN}🔍 Verificando conectividad ZeroMQ...${NC}"
    if timeout 3 python3 -c "import zmq; ctx=zmq.Context(); sock=ctx.socket(zmq.REQ); sock.connect('tcp://localhost:5555'); sock.close(); ctx.term()" 2>/dev/null; then
        echo -e "${GREEN}✅ ZeroMQ respondiendo correctamente${NC}"
    else
        echo -e "${YELLOW}⚠️ ZeroMQ inicializándose...${NC}"
    fi
fi

echo ""
echo "=================================="
echo -e "${CYAN}📊 RESUMEN:${NC}"
echo -e "  Componentes activos: ${GREEN}$components_active/3${NC}"

if [ $components_active -eq 3 ]; then
    echo -e "${GREEN}🎉 ¡Plataforma completamente operativa!${NC}"
    success_status=true
elif [ $components_active -eq 2 ]; then
    echo -e "${YELLOW}⚠️ Plataforma parcialmente operativa${NC}"
    echo -e "${CYAN}💡 Esto puede ser suficiente para operación básica${NC}"
    success_status=true
else
    echo -e "${RED}❌ Plataforma con problemas${NC}"
    success_status=false
fi

echo ""
echo -e "${BLUE}📊 Comandos útiles:${NC}"
echo -e "  • Estado detallado:   ${YELLOW}./check-ports.sh${NC}"
echo -e "  • Monitor en vivo:    ${YELLOW}./monitor-platform.sh --live${NC}"
echo -e "  • Monitor oficial:    ${YELLOW}make monitor${NC}"
echo -e "  • Parar todo:         ${YELLOW}make stop${NC}"
echo -e "  • Tráfico de prueba:  ${YELLOW}make test-traffic${NC}"

if ! $success_status; then
    echo ""
    echo -e "${RED}🔧 Para diagnóstico completo:${NC}"
    echo -e "  ${YELLOW}./start-scada-platform.sh${NC}     # Setup completo"
    echo -e "  ${YELLOW}./fix-sudo-permissions.sh${NC}     # Arreglar permisos sudo"
    echo -e "  ${YELLOW}./troubleshoot-scada.sh${NC}       # Diagnóstico automático"
    exit 1
fi

# Mostrar estadísticas de captura si están disponibles
if $agent_ok; then
    echo ""
    echo -e "${CYAN}📡 El agente promiscuo está capturando tráfico de red${NC}"
    echo -e "${CYAN}💡 Espera unos minutos y ejecuta './monitor-platform.sh --live' para ver estadísticas${NC}"
fi

echo ""
echo -e "${GREEN}🚀 ¡Listo para proteger infraestructura crítica!${NC}"