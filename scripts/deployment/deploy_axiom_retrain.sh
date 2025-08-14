#!/bin/bash
# deploy_axiom_retrain.sh - Despliegue de la feature axiom-retrain

set -e

echo "🚀 DEPLOYING AXIOM-RETRAIN FEATURE - AUTONOMOUS MODEL EVOLUTION"
echo "========================================================================"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
PROJECT_ROOT=$(pwd)
FEATURE_BRANCH="feature/axiom-retrain"

# Función de logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Verificar prerrequisitos
check_prerequisites() {
    log "Checking prerequisites..."

    # Python 3.8+
    if ! python3 --version | grep -E "3\.[8-9]|3\.1[0-9]" > /dev/null; then
        error "Python 3.8+ required"
    fi

    # Librerías críticas
    python3 -c "import sklearn, xgboost, lightgbm, sqlite3, psutil" 2>/dev/null || {
        warn "Missing ML libraries. Installing..."
        pip3 install -r requirements_axiom_retrain.txt
    }

    # Git branch
    if git branch | grep -q "$FEATURE_BRANCH"; then
        log "Feature branch exists"
    else
        warn "Creating feature branch: $FEATURE_BRANCH"
        git checkout -b "$FEATURE_BRANCH"
    fi

    log "✅ Prerequisites OK"
}

# Crear estructura de directorios
create_directory_structure() {
    log "Creating directory structure..."

    # Directorios principales
    mkdir -p {axioms/{templates,pending,processed,training_ready},protobuf_storage/{enriched,archived},models/{staging,production,retired},config,logs,data,reports,notifications/{ml_detector,model_evolution},backups/axioms}

    # Permisos específicos
    chmod 755 axioms/pending
    chmod 755 protobuf_storage/enriched
    chmod 755 models/production
    chmod 755 logs

    log "✅ Directory structure created"
}

# Configurar archivos de configuración
setup_configuration_files() {
    log "Setting up configuration files..."

    # Copiar templates de configuración
    cp config_scheduler_axiom.json ./config/
    cp config_autonomous_retrainer.json ./config/
    cp minimal_axiom_template.json ./axioms/templates/

    # Generar configuración específica del entorno
    cat > ./config/runtime_config.json << EOF
{
  "deployment": {
    "environment": "production",
    "project_root": "$PROJECT_ROOT",
    "deployed_at": "$(date -Iseconds)",
    "feature_version": "1.0.0"
  },
  "integration": {
    "scheduler_firewall_integration": true,
    "ml_detector_hot_reload": false,
    "etcd_integration": false,
    "dashboard_integration": true
  },
  "monitoring": {
    "metrics_collection": true,
    "health_checks": true,
    "performance_logging": true
  }
}
EOF

    log "✅ Configuration files ready"
}

# Integrar con scheduler_firewall existente
integrate_with_scheduler() {
    log "Integrating with existing scheduler_firewall..."

    # Backup del scheduler original
    if [ -f scheduler_firewall.py ]; then
        cp scheduler_firewall.py scheduler_firewall_backup_$(date +%Y%m%d_%H%M%S).py
        log "📦 Backup created for scheduler_firewall.py"
    fi

    # Crear archivo de integración
    cat > integration_hooks.py << 'EOF'
#!/usr/bin/env python3
"""
integration_hooks.py - Hooks de integración con scheduler_firewall
Código mínimo para integrar generación de axiomas
"""

from scheduler_firewall_axiom_missile import integrate_axiom_generation

class AxiomIntegration:
    def __init__(self, config_path="./config/config_scheduler_axiom.json"):
        self.axiom_hook = integrate_axiom_generation(None, config_path)

    def process_event(self, event_proto):
        """Llamar después del procesamiento ML, antes del envío al firewall"""
        self.axiom_hook(event_proto)

# Ejemplo de integración:
# axiom_integration = AxiomIntegration()
# # En tu scheduler_firewall.py, después de recibir del ml_detector:
# axiom_integration.process_event(event_proto)
EOF

    log "✅ Integration hooks ready"
}

# Configurar servicio systemd
setup_systemd_service() {
    log "Setting up systemd service..."

    cat > autonomous-retrainer.service << EOF
[Unit]
Description=Autonomous Model Retrainer Daemon
Documentation=https://github.com/alonsoir/upgraded-happiness
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$PROJECT_ROOT
Environment=PYTHONPATH=$PROJECT_ROOT
ExecStart=/usr/bin/python3 autonomous-retrainer-daemon.py ./config/config_autonomous_retrainer.json
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
KillSignal=SIGINT
TimeoutStopSec=30
Restart=always
RestartSec=10

# Recursos intensivos
MemoryMax=32G
CPUQuota=800%
IOWeight=200

# Logs
StandardOutput=journal
StandardError=journal
SyslogIdentifier=autonomous-retrainer

# Seguridad
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$PROJECT_ROOT

[Install]
WantedBy=multi-user.target
EOF

    log "✅ Systemd service file created"
    warn "To install as system service, run:"
    warn "  sudo cp autonomous-retrainer.service /etc/systemd/system/"
    warn "  sudo systemctl daemon-reload"
    warn "  sudo systemctl enable autonomous-retrainer"
}

# Crear archivo de requirements
create_requirements() {
    log "Creating requirements file..."

    cat > requirements_axiom_retrain.txt << EOF
# Core ML libraries
scikit-learn>=1.3.0
xgboost>=1.7.4
lightgbm>=3.3.5
numpy>=1.21.0
pandas>=1.5.0

# Deep Learning (optional)
tensorflow>=2.13.0

# System monitoring
psutil>=5.9.0

# Database
sqlite3  # Built-in

# Communication
zmq>=0.0.0

# Optimization
bayesian-optimization>=1.4.0
optuna>=3.0.0

# Utilities
tqdm>=4.64.0
matplotlib>=3.6.0
seaborn>=0.11.0
EOF

    log "✅ Requirements file created"
}

# Validar instalación
validate_deployment() {
    log "Validating deployment..."

    # Verificar estructura de directorios
    for dir in "axioms/pending" "protobuf_storage/enriched" "models/production" "logs"; do
        if [ ! -d "$dir" ]; then
            error "Directory missing: $dir"
        fi
    done

    # Verificar archivos de configuración
    for config in "config/config_scheduler_axiom.json" "config/config_autonomous_retrainer.json"; do
        if [ ! -f "$config" ]; then
            error "Configuration file missing: $config"
        fi
    done

    # Test de sintaxis Python
    python3 -m py_compile scheduler-firewall-axiom-missile.py || error "Syntax error in scheduler axiom missile"
    python3 -m py_compile autonomous-retrainer-daemon.py || error "Syntax error in autonomous daemon"

    log "✅ Deployment validation passed"
}

# Test inicial
run_initial_test() {
    log "Running initial test..."

    # Crear axioma de prueba
    cat > ./axioms/pending/test_axiom.json << EOF
{
  "axiom_id": "AX-TEST-$(date +%Y%m%d%H%M%S)",
  "timestamp": "$(date -Iseconds)",
  "event_id": "test_event_001",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "ml_pred": "DDOS",
  "ml_conf": 0.85,
  "pb_path": "",
  "retrain": true
}
EOF

    # Test de lectura de configuración
    python3 -c "
import json
with open('./config/config_autonomous_retrainer.json', 'r') as f:
    config = json.load(f)
print('✅ Configuration loaded successfully')
print(f'Enabled models: {config[\"enabled_models\"]}')
"

    log "✅ Initial test passed"
}

# Función principal
main() {
    log "🧠 INITIATING AUTONOMOUS MODEL EVOLUTION DEPLOYMENT"

    check_prerequisites
    create_directory_structure
    setup_configuration_files
    integrate_with_scheduler
    create_requirements
    setup_systemd_service
    validate_deployment
    run_initial_test

    echo ""
    log "🎯 DEPLOYMENT COMPLETED SUCCESSFULLY!"
    echo ""
    echo -e "${BLUE}========================================================================"
    echo -e "NEXT STEPS:"
    echo -e "========================================================================"
    echo -e "1. Integrate with your scheduler_firewall.py:"
    echo -e "   ${YELLOW}# Add to your scheduler_firewall.py:${NC}"
    echo -e "   ${YELLOW}from integration_hooks import AxiomIntegration${NC}"
    echo -e "   ${YELLOW}axiom_integration = AxiomIntegration()${NC}"
    echo -e "   ${YELLOW}# Call: axiom_integration.process_event(event_proto)${NC}"
    echo ""
    echo -e "2. Install system service (optional):"
    echo -e "   ${YELLOW}sudo cp autonomous-retrainer.service /etc/systemd/system/${NC}"
    echo -e "   ${YELLOW}sudo systemctl enable autonomous-retrainer${NC}"
    echo ""
    echo -e "3. Start autonomous retrainer:"
    echo -e "   ${YELLOW}python3 autonomous-retrainer-daemon.py ./config/config_autonomous_retrainer.json${NC}"
    echo ""
    echo -e "4. Monitor logs:"
    echo -e "   ${YELLOW}tail -f logs/autonomous_orchestrator.log${NC}"
    echo ""
    echo -e "${GREEN}🤖 YOUR MODELS WILL NOW EVOLVE AUTONOMOUSLY TOWARDS MATHEMATICAL PERFECTION${NC}"
    echo -e "${BLUE}========================================================================${NC}"
}

# Ejecutar
main "$@"