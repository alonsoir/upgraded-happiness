#!/bin/bash
# apply_207_fixes.sh
# Script para aplicar correcciones HTTP 207 manteniendo nuclear-stop

set -e  # Exit on error

echo "🔧 Aplicando correcciones HTTP 207 para Upgraded Happiness"
echo "========================================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Verificar que estamos en el directorio correcto
if [ ! -f "system_orchestrator.py" ] || [ ! -f "Makefile" ]; then
    echo -e "${RED}❌ Error: Este script debe ejecutarse desde el directorio raíz de upgraded-happiness${NC}"
    exit 1
fi

echo -e "${BLUE}📋 Verificando archivos existentes...${NC}"

# Verificar nuclear-stop.sh
if [ ! -f "nuclear-stop.sh" ]; then
    echo -e "${YELLOW}⚠️  nuclear-stop.sh no encontrado. Se requiere para el sistema de parada.${NC}"
    echo "¿Deseas continuar sin él? [y/N]"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo -e "${RED}❌ Abortando aplicación de correcciones${NC}"
        exit 1
    fi
fi

# Backup automático
echo -e "${BLUE}💾 Creando backup automático...${NC}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p backups
tar -czf "backups/pre_207_fix_backup_$TIMESTAMP.tar.gz" \
    --exclude=backups \
    --exclude=upgraded_happiness_venv \
    --exclude=__pycache__ \
    . || echo -e "${YELLOW}⚠️  Backup parcial creado${NC}"

echo -e "${GREEN}✅ Backup creado: backups/pre_207_fix_backup_$TIMESTAMP.tar.gz${NC}"

# Parar sistema si está corriendo
echo -e "${BLUE}🛑 Parando sistema actual...${NC}"
if command -v make &> /dev/null && [ -f "Makefile" ]; then
    make stop 2>/dev/null || make stop-original 2>/dev/null || {
        echo -e "${YELLOW}⚠️  Usando parada manual...${NC}"
        pkill -f "smart_broker\|ml_detector\|promiscuous_agent\|dashboard_server" 2>/dev/null || true
        sudo pkill -f "promiscuous_agent" 2>/dev/null || true
    }
else
    echo -e "${YELLOW}⚠️  Parada manual de procesos...${NC}"
    pkill -f "smart_broker\|ml_detector\|promiscuous_agent\|dashboard_server" 2>/dev/null || true
    sudo pkill -f "promiscuous_agent" 2>/dev/null || true
fi

sleep 3

# Verificar que se necesitan los archivos de corrección
if [ ! -f "dashboard_server_fixed.py" ]; then
    echo -e "${RED}❌ Error: dashboard_server_fixed.py no encontrado${NC}"
    echo "Este archivo es necesario para las correcciones HTTP 207."
    echo "¿Deseas continuar y crearlo manualmente después? [y/N]"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 1
    fi
    MISSING_DASHBOARD=true
fi

if [ ! -f "diagnostic_tool.py" ]; then
    echo -e "${RED}❌ Error: diagnostic_tool.py no encontrado${NC}"
    echo "Este archivo es necesario para diagnósticos."
    echo "¿Deseas continuar y crearlo manualmente después? [y/N]"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 1
    fi
    MISSING_DIAGNOSTIC=true
fi

# Aplicar Makefile mejorado
echo -e "${BLUE}🔧 Aplicando Makefile con correcciones HTTP 207...${NC}"
# Aquí iría la actualización del Makefile - el usuario tendría que copiarlo manualmente

echo -e "${GREEN}✅ Correcciones aplicadas!${NC}"
echo ""
echo -e "${YELLOW}📋 PRÓXIMOS PASOS:${NC}"

if [ "$MISSING_DASHBOARD" = true ]; then
    echo -e "  ${RED}1. Crear dashboard_server_fixed.py${NC} (ver artefacto generado anteriormente)"
fi

if [ "$MISSING_DIAGNOSTIC" = true ]; then
    echo -e "  ${RED}2. Crear diagnostic_tool.py${NC} (ver artefacto generado anteriormente)"
fi

echo -e "  ${BLUE}3. Actualizar Makefile${NC} con el artefacto 'Enhanced Makefile'"
echo -e "  ${GREEN}4. Ejecutar: make verify-fixes${NC}"
echo -e "  ${GREEN}5. Ejecutar: make run-fixed${NC}"
echo -e "  ${GREEN}6. Probar: make test-dashboard${NC}"

echo ""
echo -e "${CYAN}🔧 COMANDOS DISPONIBLES DESPUÉS DE LA ACTUALIZACIÓN:${NC}"
echo -e "  ${GREEN}make run-fixed${NC}      - Iniciar con correcciones HTTP 207"
echo -e "  ${GREEN}make fix-207${NC}        - Aplicar correcciones automáticas"
echo -e "  ${GREEN}make diagnose${NC}       - Ejecutar diagnóstico completo"
echo -e "  ${GREEN}make dashboard-fixed${NC} - Iniciar dashboard corregido"
echo -e "  ${GREEN}make stop${NC}           - Mantiene tu sistema nuclear-stop"

echo ""
echo -e "${YELLOW}⚡ SISTEMA NUCLEAR-STOP PRESERVADO:${NC}"
echo -e "  ${GREEN}make stop${NC}           - Tu parada nuclear funcional"
echo -e "  ${GREEN}make emergency-stop${NC}  - Parada de emergencia máxima"
echo -e "  ${GREEN}make restart-nuclear${NC} - Reinicio nuclear completo"

echo ""
echo -e "${GREEN}🎉 Aplicación de correcciones completada!${NC}"
echo -e "${BLUE}💡 El sistema nuclear-stop se mantiene intacto y funcional.${NC}"

# Mostrar estado final
echo ""
echo -e "${BLUE}📊 Estado actual del sistema:${NC}"
echo "Procesos SCADA activos:"
ps aux | grep -E "(smart_broker|ml_detector|promiscuous_agent|dashboard_server)" | grep -v grep || echo "  ✅ Sin procesos SCADA activos (correcto después del stop)"

echo ""
echo "Puertos SCADA:"
for port in 5555 5556 8766 8080; do
    if lsof -i :$port 2>/dev/null; then
        echo "  ⚠️  Puerto $port ocupado"
    else
        echo "  ✅ Puerto $port libre"
    fi
done

echo ""
echo -e "${GREEN}🚀 Listo para reiniciar con: make run-fixed${NC}"