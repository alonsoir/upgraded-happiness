#!/bin/bash

# =============================================================================
# UPGRADED HAPPINESS - Nuclear Stop Script (Nueva Arquitectura)
# =============================================================================
# Parada REAL y efectiva de todos los componentes SCADA
# Arquitectura: promiscuous_agent → geoip_enricher → ml_detector → dashboard → firewall_agent
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

echo -e "${RED}🛑 NUCLEAR STOP - PARADA FORZADA DE UPGRADED HAPPINESS${NC}"
echo -e "${BLUE}🏗️ Arquitectura: promiscuous_agent → geoip_enricher → ml_detector → dashboard → firewall_agent${NC}\n"

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
    timeout 15 make stop &>/dev/null || warning "make stop falló o tomó mucho tiempo"
else
    warning "Makefile no encontrado, saltando parada gentil"
fi

# Esperar un poco para procesos que se cierren correctamente
sleep 3

# 2. IDENTIFICAR PROCESOS SCADA ACTIVOS (NUEVA ARQUITECTURA)
log "Identificando procesos SCADA activos (nueva arquitectura)..."

scada_processes=(
    "promiscuous_agent"
    "geoip_enricher"
    "lightweight_ml_detector"
    "real_zmq_dashboard_with_firewall"
    "simple_firewall_agent"
)

# También incluir algunos legacy por si acaso
legacy_processes=(
    "smart_broker"
    "ml_detector"
    "dashboard"
    "firewall_agent"
    "uvicorn"
)

all_processes=("${scada_processes[@]}" "${legacy_processes[@]}")

active_processes=()
root_processes=()

for process in "${all_processes[@]}"; do
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
    log "Parando procesos de usuario en orden inverso al inicio..."

    # Parar en orden inverso: dashboard → ml_detector → geoip_enricher → firewall_agent
    declare -A process_priority=(
        ["real_zmq_dashboard_with_firewall"]=1
        ["dashboard"]=1
        ["lightweight_ml_detector"]=2
        ["ml_detector"]=2
        ["geoip_enricher"]=3
        ["simple_firewall_agent"]=4
        ["firewall_agent"]=4
        ["smart_broker"]=5
        ["uvicorn"]=6
    )

    # Ordenar procesos por prioridad
    for priority in {1..6}; do
        for proc_info in "${active_processes[@]}"; do
            local pid=$(echo "$proc_info" | cut -d: -f1)
            local name=$(echo "$proc_info" | cut -d: -f2)

            local proc_priority=${process_priority[$name]:-99}

            if [[ $proc_priority -eq $priority ]]; then
                log "Matando proceso usuario (prioridad $priority): $name (PID: $pid)"
                kill -TERM "$pid" 2>/dev/null || true
                sleep 1
            fi
        done
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
    log "Método 1: pkill con sudo (nueva arquitectura)..."
    for process in "${scada_processes[@]}"; do
        sudo pkill -f "$process" 2>/dev/null || true
    done

    # También limpiar legacy
    for process in "${legacy_processes[@]}"; do
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

    # Limpieza agresiva final (nueva arquitectura)
    log "Método 3: Limpieza agresiva por nombre (nueva arquitectura)..."
    sudo pkill -9 -f "promiscuous_agent" 2>/dev/null || true
    sudo pkill -9 -f "geoip_enricher" 2>/dev/null || true
    sudo pkill -9 -f "lightweight_ml_detector" 2>/dev/null || true
    sudo pkill -9 -f "real_zmq_dashboard_with_firewall" 2>/dev/null || true
    sudo pkill -9 -f "simple_firewall_agent" 2>/dev/null || true

    # Legacy cleanup
    sudo pkill -9 -f "smart_broker" 2>/dev/null || true
    sudo pkill -9 -f "uvicorn.*8766" 2>/dev/null || true
    sudo pkill -9 -f "uvicorn.*8000" 2>/dev/null || true

    success "✅ Procesos root terminados (método nuclear)"
else
    success "✅ No hay procesos root activos"
fi

# 5. LIBERACIÓN FORZADA DE PUERTOS (NUEVA ARQUITECTURA)
log "Liberando puertos SCADA (nueva arquitectura)..."

# Puertos de la nueva arquitectura
scada_ports=(5559 5560 5561 5562 8000)

# Puertos legacy por si acaso
legacy_ports=(5555 5556 8766 8080 55565)

all_ports=("${scada_ports[@]}" "${legacy_ports[@]}")
ports_cleared=0

echo -e "${BLUE}🔌 Puertos nueva arquitectura: 5559→5560→5561→5562, UI:8000${NC}"

for port in "${all_ports[@]}"; do
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

# 6. LIMPIEZA DE ARCHIVOS TEMPORALES Y PID (NUEVA ARQUITECTURA)
log "Limpiando archivos temporales (nueva arquitectura)..."

cleanup_patterns=(
    "*.pid"
    ".pids/*.pid"
    "logs/*.lock"
    "./*.lock"
    "/tmp/*scada*"
    "/tmp/*broker*"
    "/tmp/*zmq*"
    "/tmp/*geoip*"
    "/tmp/*upgraded-happiness*"
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
        local found_files=$(ls $pattern 2>/dev/null || true)
        if [[ -n "$found_files" ]]; then
            rm -f $pattern 2>/dev/null && ((files_cleaned++))
        fi
    fi
done

# Limpieza específica de nueva arquitectura
rm -f .pids/promiscuous_agent.pid 2>/dev/null && ((files_cleaned++)) || true
rm -f .pids/geoip_enricher.pid 2>/dev/null && ((files_cleaned++)) || true
rm -f .pids/ml_detector.pid 2>/dev/null && ((files_cleaned++)) || true
rm -f .pids/dashboard.pid 2>/dev/null && ((files_cleaned++)) || true
rm -f .pids/firewall_agent.pid 2>/dev/null && ((files_cleaned++)) || true

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
sudo find /tmp -name "*zmq*" -o -name "*ipc*" -o -name "*scada*" -o -name "*geoip*" 2>/dev/null | xargs sudo rm -f 2>/dev/null || true

success "✅ Recursos de sistema limpiados"

# 8. VERIFICACIÓN FINAL (NUEVA ARQUITECTURA)
log "Ejecutando verificación final..."

echo -e "\n${CYAN}📋 ESTADO FINAL (Nueva Arquitectura):${NC}"

# Verificar procesos de nueva arquitectura
echo -e "${BLUE}🔍 Verificando procesos nueva arquitectura:${NC}"
for process in "${scada_processes[@]}"; do
    if process_exists "$process"; then
        warning "⚠️ $process aún activo"
    else
        success "✅ $process detenido"
    fi
done

# Verificar puertos de nueva arquitectura
echo -e "\n${BLUE}🔌 Verificando puertos nueva arquitectura:${NC}"
busy_ports=()
for port in "${scada_ports[@]}"; do
    if port_in_use "$port"; then
        busy_ports+=("$port")
        warning "⚠️ Puerto $port aún ocupado"
    else
        success "✅ Puerto $port libre"
    fi
done

# Verificar archivos PID
remaining_pids=$(find .pids -name "*.pid" 2>/dev/null || true)
if [[ -z "$remaining_pids" ]]; then
    success "✅ Sin archivos PID restantes"
else
    warning "⚠️ Archivos PID encontrados: $remaining_pids"
    rm -f .pids/*.pid 2>/dev/null || true
fi

# 9. RESUMEN FINAL
echo -e "\n${GREEN}🎉 PARADA NUCLEAR COMPLETADA (Nueva Arquitectura)${NC}\n"

echo -e "${CYAN}📊 ESTADÍSTICAS:${NC}"
echo -e "  • Procesos usuario: ${#active_processes[@]} terminados"
echo -e "  • Procesos root: ${#root_processes[@]} terminados (nuclear)"
echo -e "  • Puertos liberados: $ports_cleared"
echo -e "  • Archivos limpiados: $files_cleaned"

echo -e "\n${CYAN}🏗️ ARQUITECTURA VERIFICADA:${NC}"
echo -e "  • promiscuous_agent (5559): $(process_exists "promiscuous_agent" && echo "❌ Activo" || echo "✅ Detenido")"
echo -e "  • geoip_enricher (5560): $(process_exists "geoip_enricher" && echo "❌ Activo" || echo "✅ Detenido")"
echo -e "  • ml_detector (5561): $(process_exists "lightweight_ml_detector" && echo "❌ Activo" || echo "✅ Detenido")"
echo -e "  • dashboard (8000→5562): $(process_exists "real_zmq_dashboard_with_firewall" && echo "❌ Activo" || echo "✅ Detenido")"
echo -e "  • firewall_agent (5562): $(process_exists "simple_firewall_agent" && echo "❌ Activo" || echo "✅ Detenido")"

if [[ ${#busy_ports[@]} -eq 0 ]] && ! process_exists "promiscuous_agent|geoip_enricher|lightweight_ml_detector|real_zmq_dashboard_with_firewall|simple_firewall_agent"; then
    echo -e "\n${GREEN}✅ SISTEMA COMPLETAMENTE LIMPIO${NC}"
    echo -e "${GREEN}🚀 Listo para reiniciar con nueva arquitectura${NC}"
    echo -e "${BLUE}💡 Ejecutar: make start${NC}"
    exit 0
else
    echo -e "\n${YELLOW}⚠️ LIMPIEZA PARCIAL COMPLETADA${NC}"
    echo -e "${YELLOW}Algunos recursos pueden necesitar intervención manual${NC}"
    exit 1
fi