#!/bin/bash

# =============================================================================
# UPGRADED HAPPINESS - Configuration Synchronization Checker
# =============================================================================
# Verifica que todos los archivos estén sincronizados correctamente
# =============================================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

CONFIG_FILE="upgraded-happiness-bitdefender/bitdefender_config.yaml"

log() { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo -e "${BLUE}🔍 VERIFICADOR DE SINCRONIZACIÓN DE CONFIGURACIÓN${NC}\n"

# 1. Verificar estructura de archivos
log "Verificando estructura de archivos..."

required_files=(
    "Makefile"
    "requirements.txt"
    "$CONFIG_FILE"
    "dashboard_server_with_real_data.py"
)

all_files_ok=true
for file in "${required_files[@]}"; do
    if [[ -f "$file" ]]; then
        success "✅ $file existe"
    else
        error "❌ $file NO ENCONTRADO"
        all_files_ok=false
    fi
done

# 2. Leer y validar configuración YAML
log "\nVerificando configuración YAML..."

if [[ -f "$CONFIG_FILE" ]]; then
    if command -v python3 &> /dev/null; then
        config_check=$(python3 -c "
import yaml
import sys

try:
    with open('$CONFIG_FILE', 'r') as f:
        config = yaml.safe_load(f)

    # Verificar estructura requerida
    required_sections = ['zmq', 'dashboard', 'bitdefender']
    for section in required_sections:
        if section not in config:
            print(f'ERROR: Sección {section} faltante')
            sys.exit(1)

    # Extraer y mostrar configuración
    zmq_config = config.get('zmq', {})
    dashboard_config = config.get('dashboard', {})
    bitdefender_config = config.get('bitdefender', {})

    print('YAML_VALID=true')
    print(f'ZMQ_BROKER_PORT={zmq_config.get(\"broker_port\", 5555)}')
    print(f'ZMQ_DASHBOARD_PORT={zmq_config.get(\"dashboard_port\", 5556)}')
    print(f'DASHBOARD_PORT={dashboard_config.get(\"port\", 8766)}')
    print(f'DASHBOARD_HOST={dashboard_config.get(\"host\", \"localhost\")}')
    print(f'BITDEFENDER_ENABLED={bitdefender_config.get(\"enabled\", False)}')

except Exception as e:
    print(f'ERROR: {e}')
    print('YAML_VALID=false')
    sys.exit(1)
" 2>/dev/null)

        if [[ $? -eq 0 ]]; then
            eval "$config_check"
            if [[ "$YAML_VALID" == "true" ]]; then
                success "✅ Archivo YAML válido"
                log "Configuración detectada:"
                log "  • ZeroMQ Broker: puerto $ZMQ_BROKER_PORT"
                log "  • ZeroMQ Dashboard: puerto $ZMQ_DASHBOARD_PORT"
                log "  • Dashboard Web: ${DASHBOARD_HOST}:${DASHBOARD_PORT}"
                log "  • BitDefender: $([[ "$BITDEFENDER_ENABLED" == "True" ]] && echo "habilitado" || echo "deshabilitado")"
            else
                error "❌ Archivo YAML inválido"
                all_files_ok=false
            fi
        else
            error "❌ Error leyendo archivo YAML"
            all_files_ok=false
        fi
    else
        warning "⚠️ Python3 no disponible, no se puede validar YAML"
    fi
else
    error "❌ Archivo de configuración $CONFIG_FILE no encontrado"
    all_files_ok=false
fi

# 3. Verificar archivo de dashboard
log "\nVerificando archivo de dashboard..."

if [[ -f "dashboard_server_with_real_data.py" ]]; then
    dashboard_check=$(python3 -c "
import ast
import sys

try:
    with open('dashboard_server_with_real_data.py', 'r') as f:
        content = f.read()

    # Verificar imports clave
    has_fastapi = 'fastapi' in content.lower() or 'from fastapi' in content.lower()
    has_uvicorn = 'uvicorn' in content.lower()
    has_websocket = 'websocket' in content.lower()
    has_zmq = 'zmq' in content.lower()

    # Buscar definición de puerto
    import re
    port_matches = re.findall(r'port.*[=:].*(\d{4,5})', content)

    print(f'HAS_FASTAPI={has_fastapi}')
    print(f'HAS_UVICORN={has_uvicorn}')
    print(f'HAS_WEBSOCKET={has_websocket}')
    print(f'HAS_ZMQ={has_zmq}')
    if port_matches:
        print(f'DASHBOARD_FILE_PORT={port_matches[0]}')
    else:
        print('DASHBOARD_FILE_PORT=none')

except Exception as e:
    print(f'ERROR: {e}')
    sys.exit(1)
" 2>/dev/null)

    if [[ $? -eq 0 ]]; then
        eval "$dashboard_check"

        success "✅ dashboard_server_with_real_data.py encontrado"

        if [[ "$HAS_FASTAPI" == "True" ]]; then
            success "  ✅ FastAPI detectado"
        else
            warning "  ⚠️ FastAPI no detectado"
        fi

        if [[ "$HAS_UVICORN" == "True" ]]; then
            success "  ✅ Uvicorn detectado"
        else
            warning "  ⚠️ Uvicorn no detectado"
        fi

        if [[ "$HAS_WEBSOCKET" == "True" ]]; then
            success "  ✅ WebSocket detectado"
        else
            warning "  ⚠️ WebSocket no detectado"
        fi

        if [[ "$HAS_ZMQ" == "True" ]]; then
            success "  ✅ ZeroMQ detectado"
        else
            warning "  ⚠️ ZeroMQ no detectado"
        fi

        # Verificar sincronización de puertos
        if [[ "$DASHBOARD_FILE_PORT" != "none" ]] && [[ "$DASHBOARD_FILE_PORT" != "$DASHBOARD_PORT" ]]; then
            warning "  ⚠️ Puerto en archivo ($DASHBOARD_FILE_PORT) ≠ puerto en YAML ($DASHBOARD_PORT)"
            warning "    Se usará el puerto del YAML: $DASHBOARD_PORT"
        elif [[ "$DASHBOARD_FILE_PORT" == "$DASHBOARD_PORT" ]]; then
            success "  ✅ Puerto sincronizado: $DASHBOARD_PORT"
        fi
    else
        error "❌ Error analizando dashboard_server_with_real_data.py"
        all_files_ok=false
    fi
else
    error "❌ dashboard_server_with_real_data.py no encontrado"
    all_files_ok=false
fi

# 4. Verificar dependencias instaladas
log "\nVerificando dependencias Python..."

dependencies=("fastapi" "uvicorn" "websockets" "yaml" "zmq")
missing_deps=()

for dep in "${dependencies[@]}"; do
    if python3 -c "import $dep" 2>/dev/null; then
        version=$(python3 -c "import $dep; print(getattr($dep, '__version__', 'unknown'))" 2>/dev/null || echo "unknown")
        success "  ✅ $dep ($version)"
    else
        error "  ❌ $dep no instalado"
        missing_deps+=("$dep")
    fi
done

# 5. Verificar puertos disponibles
log "\nVerificando disponibilidad de puertos..."

if command -v lsof &> /dev/null; then
    ports_to_check=($ZMQ_BROKER_PORT $ZMQ_DASHBOARD_PORT $DASHBOARD_PORT 55565)

    for port in "${ports_to_check[@]}"; do
        if lsof -i ":$port" &>/dev/null; then
            process=$(lsof -i ":$port" | tail -1 | awk '{print $1 " (PID: " $2 ")"}')
            warning "  ⚠️ Puerto $port en uso: $process"
        else
            success "  ✅ Puerto $port disponible"
        fi
    done
else
    warning "  ⚠️ lsof no disponible, no se pueden verificar puertos"
fi

# 6. Verificar BitDefender (si está habilitado)
if [[ "$BITDEFENDER_ENABLED" == "True" ]]; then
    log "\nVerificando BitDefender..."

    bitdefender_paths=(
        "/Applications/Bitdefender/AntivirusforMac.app"
        "/Applications/Bitdefender/CoreSecurity.app"
        "/Applications/Bitdefender/BitdefenderAgent.app"
    )

    bitdefender_found=false
    for path in "${bitdefender_paths[@]}"; do
        if [[ -d "$path" ]]; then
            success "  ✅ BitDefender encontrado: $path"
            bitdefender_found=true
        fi
    done

    if ! $bitdefender_found; then
        warning "  ⚠️ BitDefender habilitado pero no encontrado en rutas esperadas"
    fi

    # Verificar procesos
    bd_processes=$(pgrep -f "Bitdefender\|BDL\|bd" 2>/dev/null | wc -l)
    if [[ $bd_processes -gt 0 ]]; then
        success "  ✅ $bd_processes procesos BitDefender activos"
    else
        warning "  ⚠️ No hay procesos BitDefender activos"
    fi
fi

# 7. Resumen final
echo -e "\n${BLUE}📋 RESUMEN DE SINCRONIZACIÓN${NC}"

if $all_files_ok && [[ ${#missing_deps[@]} -eq 0 ]]; then
    echo -e "${GREEN}✅ CONFIGURACIÓN COMPLETAMENTE SINCRONIZADA${NC}"
    echo -e "   Todos los archivos y dependencias están correctos"
    echo -e "   El script sincronizado funcionará correctamente"

    echo -e "\n${CYAN}🚀 COMANDO RECOMENDADO:${NC}"
    echo -e "${YELLOW}   ./start-scada-platform-with-dashboard-sync.sh${NC}"

elif $all_files_ok; then
    echo -e "${YELLOW}⚠️ CONFIGURACIÓN PARCIALMENTE SINCRONIZADA${NC}"
    echo -e "   Archivos OK, pero faltan dependencias: ${missing_deps[*]}"

    echo -e "\n${CYAN}🔧 ACCIONES RECOMENDADAS:${NC}"
    echo -e "${YELLOW}   pip install ${missing_deps[*]}${NC}"
    echo -e "${YELLOW}   ./start-scada-platform-with-dashboard-sync.sh${NC}"

else
    echo -e "${RED}❌ CONFIGURACIÓN NO SINCRONIZADA${NC}"
    echo -e "   Hay problemas que deben resolverse antes de continuar"

    echo -e "\n${CYAN}🔧 ACCIONES REQUERIDAS:${NC}"
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${YELLOW}   Crear/corregir archivo: $CONFIG_FILE${NC}"
    fi
    if [[ ! -f "dashboard_server_with_real_data.py" ]]; then
        echo -e "${YELLOW}   Verificar archivo: dashboard_server_with_real_data.py${NC}"
    fi
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${YELLOW}   Instalar dependencias: ${missing_deps[*]}${NC}"
    fi
fi

echo -e "\n${CYAN}💡 ARCHIVOS CLAVE:${NC}"
echo -e "   📝 Script principal: start-scada-platform-with-dashboard-sync.sh"
echo -e "   ⚙️  Configuración: $CONFIG_FILE"
echo -e "   🌐 Dashboard: dashboard_server_with_real_data.py"
echo -e "   🔍 Este checker: check-config-sync.sh"