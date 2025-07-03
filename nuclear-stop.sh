#!/bin/bash

# =============================================================================
# UPGRADED HAPPINESS - Nuclear Stop Script
# =============================================================================
# Parada REAL y efectiva de todos los componentes SCADA
# Incluye procesos root, puertos bloqueados, y limpieza completa
# =============================================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[STOP]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo -e "${RED}🛑 NUCLEAR STOP - PARADA FORZADA DE UPGRADED HAPPINESS${NC}\n"

# Función para verificar si un proceso existe
process_exists() {
    ps aux | grep -E "$1" | grep -v grep &>/dev/null
}

# Función para verificar si un puerto está ocupado
port_in_use() {
    if command -v lsof &> /dev/null; then
        lsof -i ":$1" &>/dev/null
    else
        netstat -an | grep -q ":$1.*LISTEN"
    fi
}

# 1. PARADA GENTIL PRIMERO (intentar el make stop original)
log "Intentando parada gentil primero..."

if command -v make &> /dev/null && [[ -f "Makefile" ]]; then
    log "Ejecutando 'make stop'..."
    timeout 10 make stop &>/dev/null || warning "make stop falló o tomó mucho tiempo"
else
    warning "Makefile no encontrado, saltando parada gentil"
fi

# Esperar un poco para procesos que se cierren correctamente
sleep 2

# 2. IDENTIFICAR PROCESOS SCADA ACTIVOS
log "Identificando procesos SCADA activos..."

scada_processes=(
    "smart_broker"
    "lightweight_ml_detector"
    "ml_detector"
    "promiscuous_agent"
    "uvicorn"
    "dashboard"
    "system_orchestrator"
    "bitdefender_integration"
)

active_processes=()
root_processes=()

for process in "${scada_processes[@]}"; do
    if process_exists "$process"; then
        # Obtener PIDs y usuarios
        local pids_info=$(ps aux | grep -E "$process" | grep -v grep | awk '{print $1 ":" $2}')

        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local user=$(echo "$line" | cut -d: -f1)
                local pid=$(echo "$line" | cut -d: -f2)

                if [[ "$user" == "root" ]]; then
                    root_processes+=("$pid:$process")
                    warning "⚠️ Proceso root detectado: $process (PID: $pid)"
                else
                    active_processes+=("$pid:$process")
                    log "Proceso usuario detectado: $process (PID: $pid)"
                fi
            fi
        done <<< "$pids_info"
    fi
done

# 3. PARADA FORZADA DE PROCESOS DE USUARIO
if [[ ${#active_processes[@]} -gt 0 ]]; then
    log "Parando procesos de usuario..."

    for proc_info in "${active_processes[@]}"; do
        local pid=$(echo "$proc_info" | cut -d: -f1)
        local name=$(echo "$proc_info" | cut -d: -f2)

        log "Matando proceso usuario: $name (PID: $pid)"
        kill -TERM "$pid" 2>/dev/null || true
    done

    # Esperar a que terminen
    sleep 3

    # Force kill si siguen activos
    for proc_info in "${active_processes[@]}"; do
        local pid=$(echo "$proc_info" | cut -d: -f1)
        local name=$(echo "$proc_info" | cut -d: -f2)

        if kill -0 "$pid" 2>/dev/null; then
            warning "Forzando kill: $name (PID: $pid)"
            kill -9 "$pid" 2>/dev/null || true
        fi
    done

    success "✅ Procesos de usuario terminados"
else
    success "✅ No hay procesos de usuario activos"
fi

# 4. PARADA FORZADA DE PROCESOS ROOT (NUCLEAR)
if [[ ${#root_processes[@]} -gt 0 ]]; then
    log "🚨 Ejecutando parada nuclear de procesos root..."

    # Métodos progresivamente más agresivos
    log "Método 1: pkill con sudo..."
    for process in "${scada_processes[@]}"; do
        sudo pkill -f "$process" 2>/dev/null || true
    done

    sleep 2

    # Verificar cuáles siguen activos
    surviving_pids=()
    for proc_info in "${root_processes[@]}"; do
        local pid=$(echo "$proc_info" | cut -d: -f1)
        if sudo kill -0 "$pid" 2>/dev/null; then
            surviving_pids+=("$pid")
        fi
    done

    if [[ ${#surviving_pids[@]} -gt 0 ]]; then
        log "Método 2: kill directo por PID..."
        for pid in "${surviving_pids[@]}"; do
            warning "Forzando kill root PID: $pid"
            sudo kill -9 "$pid" 2>/dev/null || true
        done

        sleep 1
    fi

    # Limpieza agresiva final
    log "Método 3: Limpieza agresiva por nombre..."
    sudo pkill -9 -f "promiscuous_agent" 2>/dev/null || true
    sudo pkill -9 -f "smart_broker" 2>/dev/null || true
    sudo pkill -9 -f "ml_detector" 2>/dev/null || true
    sudo pkill -9 -f "uvicorn.*8766" 2>/dev/null || true
    sudo pkill -9 -f "uvicorn.*8080" 2>/dev/null || true

    success "✅ Procesos root terminados (método nuclear)"
else
    success "✅ No hay procesos root activos"
fi

# 5. LIBERACIÓN FORZADA DE PUERTOS
log "Liberando puertos SCADA..."

scada_ports=(5555 5556 8766 8080 55565)
ports_cleared=0

for port in "${scada_ports[@]}"; do
    if port_in_use "$port"; then
        warning "Puerto $port en uso, liberando..."

        # Método 1: lsof + kill
        if command -v lsof &> /dev/null; then
            local pids=$(sudo lsof -ti ":$port" 2>/dev/null || true)
            if [[ -n "$pids" ]]; then
                echo "$pids" | xargs sudo kill -9 2>/dev/null || true
                ((ports_cleared++))
            fi
        fi

        # Método 2: netstat + kill (fallback)
        if port_in_use "$port"; then
            local pid=$(sudo netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d/ -f1 | head -1)
            if [[ -n "$pid" ]] && [[ "$pid" != "-" ]]; then
                sudo kill -9 "$pid" 2>/dev/null || true
                ((ports_cleared++))
            fi
        fi

        # Verificación final
        sleep 1
        if port_in_use "$port"; then
            error "❌ Puerto $port aún ocupado después de limpieza"
        else
            success "✅ Puerto $port liberado"
        fi
    else
        success "✅ Puerto $port ya libre"
    fi
done

# 6. LIMPIEZA DE ARCHIVOS TEMPORALES Y PID
log "Limpiando archivos temporales..."

cleanup_patterns=(
    "*.pid"
    "dashboard.pid"
    "./*scada*.pid"
    "/tmp/*scada*"
    "/tmp/*broker*"
    "/tmp/*zmq*"
    "/tmp/*upgraded-happiness*"
    "./logs/*.lock"
    "./*.lock"
)

files_cleaned=0
for pattern in "${cleanup_patterns[@]}"; do
    if [[ "$pattern" == "/tmp/*"* ]]; then
        # Usar sudo para archivos /tmp
        if sudo rm -f $pattern 2>/dev/null; then
            ((files_cleaned++))
        fi
    else
        # Archivos locales
        if rm -f $pattern 2>/dev/null; then
            ((files_cleaned++))
        fi
    fi
done

if [[ $files_cleaned -gt 0 ]]; then
    success "✅ $files_cleaned archivos temporales eliminados"
else
    success "✅ No hay archivos temporales para limpiar"
fi

# 7. LIMPIEZA DE MEMORIA COMPARTIDA Y SOCKETS
log "Limpiando recursos de sistema..."

# Limpiar shared memory segments de ZeroMQ
sudo ipcs -m 2>/dev/null | grep $(whoami) | awk '{print $2}' | xargs -r sudo ipcrm -m 2>/dev/null || true

# Limpiar sockets Unix
sudo find /tmp -name "*zmq*" -o -name "*ipc*" -o -name "*scada*" 2>/dev/null | xargs sudo rm -f 2>/dev/null || true

success "✅ Recursos de sistema limpiados"

# 8. VERIFICACIÓN FINAL
log "Ejecutando verificación final..."

echo -e "\n${CYAN}📋 ESTADO FINAL:${NC}"

# Verificar procesos
remaining_processes=$(ps aux | grep -E "(smart_broker|ml_detector|promiscuous_agent|uvicorn.*8766|dashboard)" | grep -v grep || true)
if [[ -z "$remaining_processes" ]]; then
    success "✅ Sin procesos SCADA activos"
else
    warning "⚠️ Procesos aún activos:"
    echo "$remaining_processes"
fi

# Verificar puertos
busy_ports=()
for port in "${scada_ports[@]}"; do
    if port_in_use "$port"; then
        busy_ports+=("$port")
    fi
done

if [[ ${#busy_ports[@]} -eq 0 ]]; then
    success "✅ Todos los puertos SCADA libres"
else
    warning "⚠️ Puertos aún ocupados: ${busy_ports[*]}"
fi

# Verificar archivos PID
remaining_pids=$(find . -name "*.pid" 2>/dev/null || true)
if [[ -z "$remaining_pids" ]]; then
    success "✅ Sin archivos PID restantes"
else
    warning "⚠️ Archivos PID encontrados: $remaining_pids"
fi

# 9. RESUMEN FINAL
echo -e "\n${GREEN}🎉 PARADA NUCLEAR COMPLETADA${NC}\n"

echo -e "${CYAN}📊 ESTADÍSTICAS:${NC}"
echo -e "  • Procesos usuario: ${#active_processes[@]} terminados"
echo -e "  • Procesos root: ${#root_processes[@]} terminados (nuclear)"
echo -e "  • Puertos liberados: $ports_cleared"
echo -e "  • Archivos limpiados: $files_cleaned"

if [[ ${#busy_ports[@]} -eq 0 ]] && [[ -z "$remaining_processes" ]]; then
    echo -e "\n${GREEN}✅ SISTEMA COMPLETAMENTE LIMPIO${NC}"
    echo -e "${GREEN}🚀 Listo para reiniciar con configuración sincronizada${NC}"
    exit 0
else
    echo -e "\n${YELLOW}⚠️ LIMPIEZA PARCIAL COMPLETADA${NC}"
    echo -e "${YELLOW}Algunos recursos pueden necesitar intervención manual${NC}"
    exit 1
fi