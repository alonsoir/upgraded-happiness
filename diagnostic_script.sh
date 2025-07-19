#!/bin/bash

# =============================================================================
# 🔍 Script de Diagnóstico - Sistema Autoinmune Digital v2.0
# =============================================================================
# Diagnóstica por qué promiscuous_agent no inicia con make start
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔍 DIAGNÓSTICO DEL SISTEMA AUTOINMUNE${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""

# 1. Verificar archivos principales
echo -e "${YELLOW}1. 📁 Verificando archivos principales...${NC}"
files=(
    "promiscuous_agent.py"
    "enhanced_agent_config.json"
    "Makefile"
)

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo -e "   ✅ $file existe"
    else
        echo -e "   ❌ $file falta"
    fi
done
echo ""

# 2. Verificar directorios
echo -e "${YELLOW}2. 📂 Verificando directorios...${NC}"
dirs=("logs" ".pids" "upgraded_happiness_venv")

for dir in "${dirs[@]}"; do
    if [ -d "$dir" ]; then
        echo -e "   ✅ $dir existe"
    else
        echo -e "   ❌ $dir falta"
    fi
done
echo ""

# 3. Verificar permisos sudo
echo -e "${YELLOW}3. 🔐 Verificando permisos sudo...${NC}"
if sudo -n echo "test" >/dev/null 2>&1; then
    echo -e "   ✅ Sudo sin contraseña: OK"
else
    echo -e "   ⚠️  Sudo requiere contraseña"
fi

# Verificar permisos específicos de iptables
if sudo -n iptables -L >/dev/null 2>&1; then
    echo -e "   ✅ Permisos iptables: OK"
else
    echo -e "   ❌ Permisos iptables: FALLO"
fi
echo ""

# 4. Verificar entorno virtual Python
echo -e "${YELLOW}4. 🐍 Verificando entorno Python...${NC}"
if [ -d "upgraded_happiness_venv" ]; then
    if [ -f "upgraded_happiness_venv/bin/python" ]; then
        echo -e "   ✅ Python virtual env: OK"
        echo -e "   📍 Versión: $(upgraded_happiness_venv/bin/python --version 2>&1)"
    else
        echo -e "   ❌ Python ejecutable falta en venv"
    fi
else
    echo -e "   ❌ Virtual environment no existe"
fi
echo ""

# 5. Verificar logs existentes
echo -e "${YELLOW}5. 📋 Verificando logs existentes...${NC}"
if [ -d "logs" ]; then
    if [ -f "logs/promiscuous_agent.log" ]; then
        echo -e "   📄 Log promiscuous_agent:"
        echo -e "   📅 Última modificación: $(stat -c %y logs/promiscuous_agent.log 2>/dev/null || stat -f %Sm logs/promiscuous_agent.log 2>/dev/null)"
        echo -e "   📏 Tamaño: $(wc -l < logs/promiscuous_agent.log 2>/dev/null || echo "0") líneas"
        echo -e "   🔍 Últimas 3 líneas:"
        tail -3 logs/promiscuous_agent.log 2>/dev/null | sed 's/^/      /'
    else
        echo -e "   ⚠️  No hay log de promiscuous_agent"
    fi

    echo -e "   📊 Otros logs disponibles:"
    ls -la logs/ 2>/dev/null | grep "\.log" | awk '{print "      📄 " $9 " (" $5 " bytes)"}' || echo "      Sin logs"
else
    echo -e "   ❌ Directorio logs no existe"
fi
echo ""

# 6. Verificar PIDs actuales
echo -e "${YELLOW}6. 🆔 Verificando PIDs...${NC}"
if [ -d ".pids" ]; then
    if [ -f ".pids/promiscuous_agent.pid" ]; then
        PID=$(cat .pids/promiscuous_agent.pid 2>/dev/null)
        echo -e "   📄 PID file existe: $PID"
        if ps -p "$PID" > /dev/null 2>&1; then
            echo -e "   ✅ Proceso $PID está activo"
        else
            echo -e "   ❌ Proceso $PID NO está activo (PID stale)"
        fi
    else
        echo -e "   ⚠️  No hay PID file para promiscuous_agent"
    fi

    echo -e "   📊 PIDs existentes:"
    ls -la .pids/ 2>/dev/null | grep "\.pid" | awk '{print "      🆔 " $9}' || echo "      Sin PIDs"
else
    echo -e "   ❌ Directorio .pids no existe"
fi
echo ""

# 7. Verificar procesos Python actuales
echo -e "${YELLOW}7. 🔄 Verificando procesos Python actuales...${NC}"
PYTHON_PROCS=$(ps aux | grep -E "python.*upgraded|python.*promiscuous|python.*geoip|python.*ml_detector|python.*dashboard|python.*firewall" | grep -v grep)

if [ -n "$PYTHON_PROCS" ]; then
    echo -e "   🏃 Procesos Python activos:"
    echo "$PYTHON_PROCS" | while read line; do
        PID=$(echo "$line" | awk '{print $2}')
        CMD=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
        echo -e "      🆔 PID $PID: $CMD"
    done
else
    echo -e "   ⚠️  No hay procesos Python relacionados activos"
fi
echo ""

# 8. Test manual del comando promiscuous
echo -e "${YELLOW}8. 🧪 Test manual del comando promiscuous...${NC}"
if [ -f "promiscuous_agent.py" ] && [ -f "enhanced_agent_config.json" ]; then
    echo -e "   🔧 Comando que debería ejecutar make:"
    echo -e "      sudo upgraded_happiness_venv/bin/python promiscuous_agent.py enhanced_agent_config.json"

    echo -e "   🧪 Probando validación básica..."
    if sudo -n upgraded_happiness_venv/bin/python -c "import sys; print('Python OK'); sys.exit(0)" 2>/dev/null; then
        echo -e "   ✅ Python bajo sudo: OK"
    else
        echo -e "   ❌ Python bajo sudo: FALLO"
    fi

    if upgraded_happiness_venv/bin/python -c "import scapy; print('Scapy importa OK')" 2>/dev/null; then
        echo -e "   ✅ Scapy disponible: OK"
    else
        echo -e "   ❌ Scapy no disponible"
    fi
else
    echo -e "   ❌ Archivos faltantes para test manual"
fi
echo ""

# 9. Análisis de Makefile
echo -e "${YELLOW}9. 📋 Análisis del Makefile...${NC}"
if [ -f "Makefile" ]; then
    echo -e "   🔍 Comando start para promiscuous_agent:"
    grep -A 5 -B 5 "promiscuous_agent" Makefile | grep -E "(echo|sudo|PROMISCUOUS)" | head -3 | sed 's/^/      /'

    # Verificar variables del Makefile
    PYTHON_VENV=$(grep "PYTHON_VENV" Makefile | head -1 | cut -d'=' -f2 | tr -d ' ')
    PROMISCUOUS_AGENT=$(grep "PROMISCUOUS_AGENT" Makefile | head -1 | cut -d'=' -f2 | tr -d ' ')

    echo -e "   📝 Variables detectadas:"
    echo -e "      PYTHON_VENV: $PYTHON_VENV"
    echo -e "      PROMISCUOUS_AGENT: $PROMISCUOUS_AGENT"
else
    echo -e "   ❌ Makefile no encontrado"
fi
echo ""

# 10. Recomendaciones
echo -e "${YELLOW}10. 💡 RECOMENDACIONES${NC}"
echo -e "${YELLOW}===================${NC}"

# Contar problemas
ISSUES=0

# Verificar problemas críticos
if [ ! -f "promiscuous_agent.py" ]; then ((ISSUES++)); fi
if [ ! -f "enhanced_agent_config.json" ]; then ((ISSUES++)); fi
if [ ! -d "upgraded_happiness_venv" ]; then ((ISSUES++)); fi
if ! sudo -n echo "test" >/dev/null 2>&1; then ((ISSUES++)); fi

if [ "$ISSUES" -eq "0" ]; then
    echo -e "✅ ${GREEN}Sistema parece correcto para diagnóstico avanzado${NC}"
    echo ""
    echo -e "${BLUE}🔧 Pasos siguientes sugeridos:${NC}"
    echo -e "   1. ${GREEN}make stop${NC}     # Limpiar procesos existentes"
    echo -e "   2. ${GREEN}make start${NC}    # Iniciar con verbose logging"
    echo -e "   3. ${GREEN}./monitor_autoinmune.sh -s${NC}  # Verificar estado"
    echo ""
    echo -e "${BLUE}🐛 Para debugging detallado:${NC}"
    echo -e "   ${GREEN}make start 2>&1 | tee make_start_debug.log${NC}"
else
    echo -e "❌ ${RED}Encontrados $ISSUES problemas críticos${NC}"
    echo -e "${BLUE}🔧 Soluciones recomendadas:${NC}"
    if [ ! -d "upgraded_happiness_venv" ]; then
        echo -e "   ${YELLOW}make setup install${NC}  # Recrear entorno"
    fi
    if ! sudo -n echo "test" >/dev/null 2>&1; then
        echo -e "   ${YELLOW}make setup-perms${NC}    # Configurar sudo"
    fi
fi

echo ""
echo -e "${BLUE}📊 Diagnóstico completado$(NC)"