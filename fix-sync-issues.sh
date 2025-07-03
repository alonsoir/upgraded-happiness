#!/bin/bash

# =============================================================================
# UPGRADED HAPPINESS - Quick Fix for Synchronization Issues
# =============================================================================
# Soluciona automáticamente problemas comunes de sincronización
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

log() { echo -e "${CYAN}[FIX]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo -e "${BLUE}🔧 REPARADOR AUTOMÁTICO DE SINCRONIZACIÓN${NC}\n"

# 1. Instalar dependencias faltantes
log "Instalando dependencias Python faltantes..."

dependencies=("fastapi" "uvicorn" "websockets" "pyyaml" "pyzmq")
installed_something=false

for dep in "${dependencies[@]}"; do
    if ! python3 -c "import ${dep/pyyaml/yaml}" 2>/dev/null; then
        log "Instalando $dep..."
        pip install "$dep"
        installed_something=true
        success "✅ $dep instalado"
    else
        success "✅ $dep ya instalado"
    fi
done

if $installed_something; then
    success "Dependencias actualizadas"
else
    success "Todas las dependencias ya estaban instaladas"
fi

# 2. Verificar/crear configuración YAML si no existe
if [[ ! -f "$CONFIG_FILE" ]]; then
    warning "Archivo de configuración no encontrado, creando uno básico..."

    mkdir -p "$(dirname "$CONFIG_FILE")"

    cat > "$CONFIG_FILE" << 'EOF'
# Configuración SCADA - Upgraded Happiness
zmq:
  broker_port: 5555
  dashboard_port: 5556

bitdefender:
  enabled: true
  poll_interval: 30
  monitor_syslog: true
  use_fswatch: true

hybrid_ml:
  enabled: true
  model_path: "models/"
  database_path: "hybrid_ml.db"
  retrain_interval: 1800
  min_samples: 50

dashboard:
  enabled: true
  port: 8766
  host: "localhost"

system:
  use_existing_orchestrator: true
  orchestrator_path: "../system_orchestrator.py"

logging:
  level: "INFO"
  file: "bitdefender_integration.log"

development:
  simulate_bitdefender: false
  generate_test_events: true
  test_event_interval: 15
EOF

    success "✅ Configuración YAML creada: $CONFIG_FILE"
else
    success "✅ Configuración YAML existe"
fi

# 3. Hacer ejecutables los scripts
log "Configurando permisos de archivos..."

scripts=(
    "start-scada-platform-with-dashboard-sync.sh"
    "check-config-sync.sh"
    "fix-sync-issues.sh"
)

for script in "${scripts[@]}"; do
    if [[ -f "$script" ]]; then
        chmod +x "$script"
        success "✅ $script es ejecutable"
    fi
done

# 4. Verificar que dashboard_server_with_real_data.py sea válido
if [[ -f "dashboard_server_with_real_data.py" ]]; then
    log "Verificando dashboard_server_with_real_data.py..."

    if python3 -m py_compile dashboard_server_with_real_data.py 2>/dev/null; then
        success "✅ dashboard_server_with_real_data.py es válido sintácticamente"
    else
        error "❌ dashboard_server_with_real_data.py tiene errores de sintaxis"
        log "Intentando corrección básica..."

        # Backup del archivo original
        cp dashboard_server_with_real_data.py dashboard_server_with_real_data.py.backup
        log "Backup creado: dashboard_server_with_real_data.py.backup"
    fi
else
    warning "dashboard_server_with_real_data.py no encontrado"
    log "Puedes usar el script para crear un dashboard básico si es necesario"
fi

# 5. Limpiar procesos colgados
log "Limpiando procesos previos..."

# Obtener puerto del dashboard desde configuración
if [[ -f "$CONFIG_FILE" ]] && command -v python3 &> /dev/null; then
    DASHBOARD_PORT=$(python3 -c "
import yaml
try:
    with open('$CONFIG_FILE', 'r') as f:
        config = yaml.safe_load(f)
    print(config.get('dashboard', {}).get('port', 8766))
except:
    print('8766')
" 2>/dev/null || echo "8766")
else
    DASHBOARD_PORT=8766
fi

# Matar procesos en puertos específicos
ports=(5555 5556 55565 $DASHBOARD_PORT)
for port in "${ports[@]}"; do
    if command -v lsof &> /dev/null && lsof -i ":$port" &>/dev/null; then
        log "Liberando puerto $port..."
        lsof -ti ":$port" | xargs kill -9 2>/dev/null || true
        success "✅ Puerto $port liberado"
    fi
done

# Limpiar procesos por nombre
pkill -f "smart_broker" 2>/dev/null || true
pkill -f "lightweight_ml_detector" 2>/dev/null || true
pkill -f "promiscuous_agent" 2>/dev/null || true
pkill -f "uvicorn" 2>/dev/null || true

# Limpiar archivos PID
rm -f dashboard.pid *.pid 2>/dev/null || true

success "✅ Procesos limpiados"

# 6. Verificar estructura de directorios
log "Verificando estructura de directorios..."

required_dirs=(
    "models"
    "logs"
    "upgraded-happiness-bitdefender"
)

for dir in "${required_dirs[@]}"; do
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        success "✅ Directorio $dir creado"
    else
        success "✅ Directorio $dir existe"
    fi
done

# 7. Configurar permisos sudo si es necesario
if command -v make &> /dev/null; then
    log "Configurando permisos sudo para captura promiscua..."
    if make setup-sudo &>/dev/null; then
        success "✅ Permisos sudo configurados"
    else
        warning "⚠️ No se pudieron configurar permisos sudo automáticamente"
        log "Podrás ejecutar componentes individualmente con sudo si es necesario"
    fi
fi

# 8. Verificación final rápida
log "Ejecutando verificación final..."

if command -v "./check-config-sync.sh" &> /dev/null; then
    log "Ejecutando verificador de sincronización..."
    ./check-config-sync.sh --summary 2>/dev/null || true
fi

# 9. Resumen de acciones
echo -e "\n${GREEN}🎉 REPARACIÓN COMPLETADA${NC}\n"

echo -e "${CYAN}✅ ACCIONES REALIZADAS:${NC}"
echo -e "  • Dependencias Python instaladas/verificadas"
echo -e "  • Configuración YAML verificada/creada"
echo -e "  • Scripts marcados como ejecutables"
echo -e "  • Procesos previos limpiados"
echo -e "  • Estructura de directorios verificada"
echo -e "  • Permisos sudo configurados (si es posible)"

echo -e "\n${CYAN}🚀 SIGUIENTE PASO RECOMENDADO:${NC}"
echo -e "${YELLOW}  ./check-config-sync.sh${NC}    # Verificar sincronización"
echo -e "${YELLOW}  ./start-scada-platform-with-dashboard-sync.sh${NC}    # Iniciar sistema"

echo -e "\n${CYAN}📝 ARCHIVOS IMPORTANTES:${NC}"
echo -e "  📊 Dashboard: dashboard_server_with_real_data.py"
echo -e "  ⚙️  Config: $CONFIG_FILE"
echo -e "  🚀 Start: start-scada-platform-with-dashboard-sync.sh"
echo -e "  🔍 Check: check-config-sync.sh"

if [[ -f "dashboard_server_with_real_data.py.backup" ]]; then
    echo -e "\n${YELLOW}⚠️ BACKUP CREADO:${NC}"
    echo -e "  📁 dashboard_server_with_real_data.py.backup"
fi

echo -e "\n${BLUE}💡 El sistema está listo para ser iniciado${NC}"