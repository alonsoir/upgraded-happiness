#!/bin/bash

# =============================================================================
# CHECK PORTS - SCADA Platform (MEJORADO v2.0)
# =============================================================================
# Script mejorado para verificar puertos ZeroMQ y procesos SCADA
# Incorpora verificación real de conectividad ZeroMQ
# =============================================================================

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}🔍 Verificando puertos ZeroMQ y procesos SCADA...${NC}"
echo "================================================================="

echo -e "${CYAN}📊 Procesos SCADA activos:${NC}"
echo "--------------------------------"
scada_procs=$(ps aux | grep -E "(smart_broker|lightweight_ml|promiscuous)" | grep -v grep)
if [[ -n "$scada_procs" ]]; then
    echo "$scada_procs" | while read line; do
        echo -e "  ${GREEN}✅ $line${NC}"
    done
    echo ""

    # Conteo de procesos
    proc_count=$(echo "$scada_procs" | wc -l)
    echo -e "${CYAN}📈 Total procesos SCADA: ${GREEN}$proc_count${NC}"
else
    echo -e "  ${RED}❌ No hay procesos SCADA activos${NC}"
fi

echo ""
echo -e "${CYAN}📊 Verificación detallada de puertos:${NC}"
echo "--------------------------------"

# Verificar puertos usando múltiples métodos
echo -e "${YELLOW}🔍 Método 1 - netstat:${NC}"
netstat_result=$(netstat -an 2>/dev/null | grep -E ":555[56]|:55565")
if [[ -n "$netstat_result" ]]; then
    echo "$netstat_result" | while read line; do
        if echo "$line" | grep -q "LISTEN"; then
            port=$(echo "$line" | grep -o ":555[0-9]*" | tr -d ':')
            echo -e "  ${GREEN}✅ Puerto $port: ESCUCHANDO${NC}"
        fi
    done
else
    echo -e "  ${YELLOW}⚠️ No se detectaron puertos 555* con netstat${NC}"
fi

echo ""
echo -e "${YELLOW}🔍 Método 2 - lsof:${NC}"
lsof_result=$(lsof -i -P 2>/dev/null | grep python | grep -E ":555[0-9]")
if [[ -n "$lsof_result" ]]; then
    echo "$lsof_result" | while read line; do
        echo -e "  ${GREEN}✅ $line${NC}"
    done
else
    echo -e "  ${YELLOW}⚠️ No se detectaron puertos Python con lsof${NC}"
fi

echo ""
echo -e "${YELLOW}🔍 Método 3 - Conectividad ZeroMQ (más preciso):${NC}"
echo "--------------------------------"

# Probar conectividad real a ZeroMQ
for port in 5555 5556; do
    echo -n -e "  Puerto $port: "
    if timeout 3 python3 -c "
import zmq
import sys
try:
    ctx = zmq.Context()
    sock = ctx.socket(zmq.REQ)
    sock.setsockopt(zmq.LINGER, 0)
    sock.connect('tcp://localhost:$port')
    sock.close()
    ctx.term()
    print('${GREEN}✅ CONECTA${NC}')
    sys.exit(0)
except Exception as e:
    print('${RED}❌ NO CONECTA${NC}')
    sys.exit(1)
" 2>/dev/null; then
        true
    else
        echo -e "${YELLOW}❌ NO CONECTA (puede ser normal durante inicialización)${NC}"
    fi
done

echo ""
echo -e "${CYAN}📊 Verificación de interfaces de red:${NC}"
echo "--------------------------------"
echo -e "${YELLOW}🌐 Interfaces activas:${NC}"
if command -v ip &> /dev/null; then
    ip -o link show 2>/dev/null | awk -F': ' '{print "  • "$2}' | head -5
else
    ifconfig -a 2>/dev/null | grep "^[a-z]" | awk '{print "  • "$1}' | head -5
fi

echo ""
echo -e "${CYAN}📊 Estadísticas de captura (si está disponible):${NC}"
echo "--------------------------------"
if pgrep -f "promiscuous_agent" &>/dev/null; then
    echo -e "  ${GREEN}✅ Agente Promiscuo ejecutándose${NC}"
    echo -e "  ${CYAN}📡 Para ver estadísticas en tiempo real:${NC}"
    echo -e "     ${YELLOW}./monitor-platform.sh --live${NC}"
else
    echo -e "  ${RED}❌ Agente Promiscuo no detectado${NC}"
fi

echo ""
echo -e "${BLUE}🎯 Diagnóstico rápido:${NC}"
echo "=================================="

# Contador de componentes
broker_running=$(pgrep -f "smart_broker" &>/dev/null && echo "1" || echo "0")
ml_running=$(pgrep -f "lightweight_ml" &>/dev/null && echo "1" || echo "0")
agent_running=$(pgrep -f "promiscuous" &>/dev/null && echo "1" || echo "0")

total_running=$((broker_running + ml_running + agent_running))

echo -e "${CYAN}📊 Resumen de estado:${NC}"
echo -e "  • ZeroMQ Broker:      $([ $broker_running -eq 1 ] && echo "${GREEN}✅ ACTIVO${NC}" || echo "${RED}❌ INACTIVO${NC}")"
echo -e "  • ML Detector:        $([ $ml_running -eq 1 ] && echo "${GREEN}✅ ACTIVO${NC}" || echo "${RED}❌ INACTIVO${NC}")"
echo -e "  • Promiscuous Agent:  $([ $agent_running -eq 1 ] && echo "${GREEN}✅ ACTIVO${NC}" || echo "${RED}❌ INACTIVO${NC}")"
echo ""
echo -e "${CYAN}📈 Estado general: ${GREEN}$total_running/3${NC} componentes activos"

if [ $total_running -eq 3 ]; then
    echo -e "${GREEN}🎉 ¡Plataforma completamente operativa!${NC}"
elif [ $total_running -eq 2 ]; then
    echo -e "${YELLOW}⚠️ Plataforma parcialmente operativa${NC}"
elif [ $total_running -eq 1 ]; then
    echo -e "${YELLOW}⚠️ Solo un componente activo${NC}"
else
    echo -e "${RED}❌ Plataforma no operativa${NC}"
fi

echo ""
echo -e "${BLUE}🛠️ Comandos de verificación adicional:${NC}"
echo -e "  ${YELLOW}make monitor${NC}                # Monitor oficial"
echo -e "  ${YELLOW}./monitor-platform.sh${NC}       # Monitor detallado"
echo -e "  ${YELLOW}make test-traffic${NC}           # Generar tráfico de prueba"
echo -e "  ${YELLOW}./fix-sudo-permissions.sh${NC}   # Arreglar permisos si es necesario"
echo -e "  ${YELLOW}./troubleshoot-scada.sh${NC}     # Diagnóstico completo automático"

# Verificación adicional de ZeroMQ con más detalles
if [ $broker_running -eq 1 ]; then
    echo ""
    echo -e "${CYAN}🔍 Verificación adicional de ZeroMQ:${NC}"

    # Probar ambos puertos principales
    for port in 5555 5556; do
        if timeout 5 python3 -c "
import zmq
import time
try:
    ctx = zmq.Context()
    sock = ctx.socket(zmq.REQ)
    sock.setsockopt(zmq.LINGER, 0)
    sock.setsockopt(zmq.RCVTIMEO, 1000)
    sock.connect('tcp://localhost:$port')
    # No enviamos mensaje, solo probamos conexión
    sock.close()
    ctx.term()
    print('  ✅ Puerto $port: Funcional')
except Exception as e:
    print('  ⚠️ Puerto $port: No responde (' + str(e)[:30] + ')')
" 2>/dev/null; then
        true
    else
        echo -e "  ${YELLOW}⚠️ Puerto $port: Inicializándose o no disponible${NC}"
    fi
    done
fi

echo ""
#!/bin/bash

echo "🔍 Buscando procesos en puerto 8766..."

# Buscar procesos específicos del proyecto
echo "📋 Procesos del proyecto upgraded-happiness:"
ps aux | grep -E "(dashboard|upgraded-happiness|gis)" | grep -v grep

# Buscar procesos Python que podrían estar usando el puerto
echo "🐍 Procesos Python activos:"
ps aux | grep python | grep -v grep

# Verificar puertos IPv6 también
echo "🌐 Verificando puertos IPv6:"
netstat -an | grep 8766

# Verificar conexiones TCP
echo "🔗 Conexiones TCP:"
ss -tulpn | grep 8766

# Buscar procesos con lsof usando diferentes flags
echo "🔍 Verificación exhaustiva con lsof:"
sudo lsof -i TCP:8766
sudo lsof -i UDP:8766
sudo lsof -i :8766

# Terminar procesos específicos si los encuentra
echo "⚡ Terminando procesos relacionados..."
pkill -f "dashboard.*gis"
pkill -f "gis.*dashboard"

# Esperar un momento para que se liberen los sockets
sleep 2

echo "✅ Limpieza completada. Intenta ejecutar el dashboard nuevamente."
echo -e "${GREEN}🎯 Script de verificación completado${NC}"