#!/bin/bash

# ============================================================================
# UPGRADED HAPPINESS - DEPLOYMENT TOOLKIT v1.0
# Script de deployment automático para el Sistema Autoinmune Digital
# ============================================================================

set -e  # Salir si hay errores

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables globales
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_NAME="upgraded_happiness_venv"
CONFIG_FILE="dashboard_config.json"
LOG_DIR="logs"
DATA_DIR="data"
BACKUP_DIR="backups"

# Banner de inicio
print_banner() {
    echo -e "${CYAN}"
    echo "███████╗██╗   ██╗███████╗████████╗███████╗███╗   ███╗ █████╗ "
    echo "██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║██╔══██╗"
    echo "███████╗ ╚████╔╝ ███████╗   ██║   █████╗  ██╔████╔██║███████║"
    echo "╚════██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║██╔══██║"
    echo "███████║   ██║   ███████║   ██║   ███████╗██║ ╚═╝ ██║██║  ██║"
    echo "╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝"
    echo ""
    echo "          🛡️  SISTEMA AUTOINMUNE DIGITAL  🛡️"
    echo "                  Deployment Toolkit v1.0"
    echo -e "${NC}"
}

# Función de logging
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} ${timestamp} - $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} ${timestamp} - $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} ${timestamp} - $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} ${timestamp} - $message"
            ;;
    esac
}

# Verificar dependencias del sistema
check_dependencies() {
    log "INFO" "🔍 Verificando dependencias del sistema..."

    # Verificar Python 3.8+
    if ! command -v python3 &> /dev/null; then
        log "ERROR" "Python 3 no encontrado. Por favor instala Python 3.8 o superior"
        exit 1
    fi

    local python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    local required_version="3.8"

    if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
        log "ERROR" "Python $python_version encontrado. Se requiere Python $required_version o superior"
        exit 1
    fi

    log "INFO" "✅ Python $python_version encontrado"

    # Verificar pip
    if ! command -v pip3 &> /dev/null; then
        log "ERROR" "pip3 no encontrado. Instalando..."
        python3 -m ensurepip --upgrade
    fi

    # Verificar git
    if ! command -v git &> /dev/null; then
        log "WARN" "Git no encontrado. Algunas funciones pueden no estar disponibles"
    fi

    # Verificar curl
    if ! command -v curl &> /dev/null; then
        log "WARN" "curl no encontrado. Instalando..."

        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y curl
        elif command -v yum &> /dev/null; then
            sudo yum install -y curl
        elif command -v brew &> /dev/null; then
            brew install curl
        else
            log "ERROR" "No se pudo instalar curl automáticamente"
            exit 1
        fi
    fi

    log "INFO" "✅ Dependencias verificadas correctamente"
}

# Crear estructura de directorios
create_directory_structure() {
    log "INFO" "📁 Creando estructura de directorios..."

    local dirs=(
        "$LOG_DIR"
        "$DATA_DIR"
        "$BACKUP_DIR"
        "templates"
        "static/css"
        "static/js"
        "static/images"
        "config"
        "scripts"
        "tests"
        "docs"
    )

    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log "INFO" "  ✅ Creado directorio: $dir"
        else
            log "DEBUG" "  📁 Directorio existe: $dir"
        fi
    done

    # Crear archivos .gitkeep para directorios vacíos
    for dir in "$LOG_DIR" "$DATA_DIR" "$BACKUP_DIR"; do
        touch "$dir/.gitkeep"
    done
}

# Configurar entorno virtual Python
setup_virtual_environment() {
    log "INFO" "🐍 Configurando entorno virtual Python..."

    if [ ! -d "$VENV_NAME" ]; then
        log "INFO" "Creando entorno virtual: $VENV_NAME"
        python3 -m venv "$VENV_NAME"
    else
        log "DEBUG" "Entorno virtual ya existe: $VENV_NAME"
    fi

    # Activar entorno virtual
    source "$VENV_NAME/bin/activate"

    # Actualizar pip
    log "INFO" "Actualizando pip..."
    pip install --upgrade pip

    # Instalar dependencias
    log "INFO" "Instalando dependencias Python..."

    # Crear requirements.txt si no existe
    if [ ! -f "requirements.txt" ]; then
        cat > requirements.txt << EOF
# Core dependencies
pyzmq==25.1.1
psutil==5.9.6
requests==2.31.0

# Web interface
flask==2.3.3
websockets==11.0.3

# Data processing
numpy==1.24.4
pandas==2.0.3

# Monitoring and logging
prometheus-client==0.17.1

# Security
cryptography==41.0.7

# Development dependencies
pytest==7.4.3
black==23.9.1
flake8==6.1.0

# Optional: Protocol Buffers support
protobuf==4.24.4
EOF
        log "INFO" "Archivo requirements.txt creado"
    fi

    pip install -r requirements.txt

    log "INFO" "✅ Entorno virtual configurado correctamente"
}

# Generar configuración automática
generate_configuration() {
    log "INFO" "⚙️ Generando configuración automática..."

    if [ -f "$CONFIG_FILE" ]; then
        log "WARN" "Archivo de configuración existe. Creando backup..."
        cp "$CONFIG_FILE" "$BACKUP_DIR/dashboard_config_$(date +%Y%m%d_%H%M%S).json.bak"
    fi

    # Detectar configuración automáticamente
    local hostname=$(hostname)
    local local_ip=$(hostname -I | awk '{print $1}' || echo "127.0.0.1")

    cat > "$CONFIG_FILE" << EOF
{
    "node_id": "dashboard_distributed_001",
    "component": {
        "name": "real_zmq_dashboard_with_firewall",
        "version": "2.1.0",
        "mode": "distributed_orchestrator",
        "role": "dashboard_coordinator",
        "hostname": "$hostname",
        "local_ip": "$local_ip"
    },
    "network": {
        "ml_events_input": {
            "address": "localhost",
            "port": 5570,
            "mode": "connect",
            "socket_type": "PULL",
            "high_water_mark": 10000,
            "expected_publishers": 50
        },
        "firewall_commands_output": {
            "address": "localhost",
            "port": 5580,
            "mode": "bind",
            "socket_type": "PUB",
            "high_water_mark": 5000,
            "expected_subscribers": 500
        },
        "firewall_responses_input": {
            "address": "localhost",
            "port": 5581,
            "mode": "bind",
            "socket_type": "PULL",
            "high_water_mark": 5000,
            "expected_publishers": 500
        },
        "admin_interface": {
            "address": "0.0.0.0",
            "port": 8080
        }
    },
    "zmq": {
        "context_io_threads": 4,
        "max_sockets": 1024,
        "tcp_keepalive": true,
        "tcp_keepalive_idle": 300,
        "immediate": true
    },
    "processing": {
        "threads": {
            "ml_events_consumers": 3,
            "firewall_command_producers": 2,
            "firewall_response_consumers": 2
        },
        "internal_queues": {
            "ml_events_queue_size": 5000,
            "firewall_commands_queue_size": 2000,
            "firewall_responses_queue_size": 2000
        }
    },
    "monitoring": {
        "stats_interval_seconds": 10,
        "detailed_metrics": true,
        "encoding_monitoring": {
            "enabled": true,
            "max_errors_logged": 100,
            "auto_diagnostic": true
        }
    },
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s - %(name)s - %(levelname)s - [node_id:{node_id}] [pid:{pid}] - %(message)s",
        "handlers": {
            "console": {
                "enabled": true
            },
            "file": {
                "enabled": true,
                "path": "logs/dashboard.log",
                "max_size_mb": 10,
                "backup_count": 5
            }
        }
    },
    "security": {
        "enable_auth": false,
        "api_key": null,
        "rate_limiting": {
            "enabled": true,
            "requests_per_minute": 100
        }
    },
    "web_interface": {
        "enable_debug": false,
        "static_file_cache": true,
        "compress_responses": true
    }
}
EOF

    log "INFO" "✅ Configuración generada: $CONFIG_FILE"
}

# Verificar y configurar firewall
configure_firewall() {
    log "INFO" "🔥 Configurando firewall del sistema..."

    # Verificar si ufw está disponible (Ubuntu/Debian)
    if command -v ufw &> /dev/null; then
        log "INFO" "Configurando ufw..."

        # Permitir puertos necesarios
        sudo ufw allow 8080/tcp comment "Dashboard Web Interface"
        sudo ufw allow 5570/tcp comment "ML Events Input"
        sudo ufw allow 5580/tcp comment "Firewall Commands"
        sudo ufw allow 5581/tcp comment "Firewall Responses"

        log "INFO" "✅ Reglas ufw configuradas"

    # Verificar si firewalld está disponible (CentOS/RHEL)
    elif command -v firewall-cmd &> /dev/null; then
        log "INFO" "Configurando firewalld..."

        sudo firewall-cmd --permanent --add-port=8080/tcp
        sudo firewall-cmd --permanent --add-port=5570/tcp
        sudo firewall-cmd --permanent --add-port=5580/tcp
        sudo firewall-cmd --permanent --add-port=5581/tcp
        sudo firewall-cmd --reload

        log "INFO" "✅ Reglas firewalld configuradas"

    else
        log "WARN" "No se detectó firewall configurado (ufw/firewalld)"
        log "WARN" "Asegúrate de abrir manualmente los puertos: 8080, 5570, 5580, 5581"
    fi
}

# Crear archivos de servicio systemd
create_systemd_service() {
    log "INFO" "🔧 Creando servicio systemd..."

    local service_file="/etc/systemd/system/upgraded-happiness-dashboard.service"
    local working_dir="$(pwd)"
    local venv_python="$working_dir/$VENV_NAME/bin/python"
    local user=$(whoami)

    if [ "$EUID" -eq 0 ]; then
        log "WARN" "Ejecutando como root. El servicio se configurará para el usuario actual"
    fi

    cat > /tmp/upgraded-happiness-dashboard.service << EOF
[Unit]
Description=Upgraded Happiness - Sistema Autoinmune Digital Dashboard
After=network.target
Wants=network.target

[Service]
Type=simple
User=$user
Group=$user
WorkingDirectory=$working_dir
Environment=PATH=$working_dir/$VENV_NAME/bin
ExecStart=$venv_python real_zmq_dashboard_with_firewall.py dashboard_config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=upgraded-happiness-dashboard

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$working_dir/logs $working_dir/data

[Install]
WantedBy=multi-user.target
EOF

    if [ "$EUID" -eq 0 ]; then
        mv /tmp/upgraded-happiness-dashboard.service "$service_file"
        systemctl daemon-reload
        systemctl enable upgraded-happiness-dashboard.service
        log "INFO" "✅ Servicio systemd creado y habilitado"
    else
        log "WARN" "Se requieren privilegios de root para instalar el servicio systemd"
        log "INFO" "Archivo de servicio creado en: /tmp/upgraded-happiness-dashboard.service"
        log "INFO" "Para instalarlo ejecuta:"
        log "INFO" "  sudo mv /tmp/upgraded-happiness-dashboard.service $service_file"
        log "INFO" "  sudo systemctl daemon-reload"
        log "INFO" "  sudo systemctl enable upgraded-happiness-dashboard.service"
    fi
}

# Crear scripts de utilidad
create_utility_scripts() {
    log "INFO" "📜 Creando scripts de utilidad..."

    # Script de inicio
    cat > scripts/start.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")/.."
source upgraded_happiness_venv/bin/activate
python real_zmq_dashboard_with_firewall.py dashboard_config.json
EOF

    # Script de parada
    cat > scripts/stop.sh << 'EOF'
#!/bin/bash
pkill -f "real_zmq_dashboard_with_firewall.py"
echo "Dashboard detenido"
EOF

    # Script de restart
    cat > scripts/restart.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
./stop.sh
sleep 2
./start.sh
EOF

    # Script de status
    cat > scripts/status.sh << 'EOF'
#!/bin/bash
if pgrep -f "real_zmq_dashboard_with_firewall.py" > /dev/null; then
    echo "✅ Dashboard está ejecutándose"
    echo "PID: $(pgrep -f real_zmq_dashboard_with_firewall.py)"
    echo "Puerto Web: http://localhost:8080"
else
    echo "❌ Dashboard no está ejecutándose"
fi
EOF

    # Script de logs
    cat > scripts/logs.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")/.."
tail -f logs/dashboard.log
EOF

    # Script de backup
    cat > scripts/backup.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")/.."
backup_file="backups/backup_$(date +%Y%m%d_%H%M%S).tar.gz"
tar -czf "$backup_file" \
    --exclude="upgraded_happiness_venv" \
    --exclude="logs/*.log" \
    --exclude="data/*.tmp" \
    .
echo "✅ Backup creado: $backup_file"
EOF

    # Hacer ejecutables todos los scripts
    chmod +x scripts/*.sh

    log "INFO" "✅ Scripts de utilidad creados en scripts/"
}

# Verificar la instalación
verify_installation() {
    log "INFO" "🔍 Verificando instalación..."

    local errors=0

    # Verificar archivos principales
    local required_files=(
        "real_zmq_dashboard_with_firewall.py"
        "dashboard_config.json"
        "templates/dashboard.html"
        "static/css/dashboard.css"
        "static/js/dashboard.js"
    )

    for file in "${required_files[@]}"; do
        if [ -f "$file" ]; then
            log "INFO" "  ✅ $file"
        else
            log "ERROR" "  ❌ $file (FALTANTE)"
            errors=$((errors + 1))
        fi
    done

    # Verificar entorno virtual
    if [ -d "$VENV_NAME" ]; then
        log "INFO" "  ✅ Entorno virtual: $VENV_NAME"
    else
        log "ERROR" "  ❌ Entorno virtual no encontrado"
        errors=$((errors + 1))
    fi

    # Verificar dependencias Python
    source "$VENV_NAME/bin/activate"
    local python_deps=("zmq" "psutil" "json")

    for dep in "${python_deps[@]}"; do
        if python3 -c "import $dep" 2>/dev/null; then
            log "INFO" "  ✅ Dependencia Python: $dep"
        else
            log "ERROR" "  ❌ Dependencia Python faltante: $dep"
            errors=$((errors + 1))
        fi
    done

    if [ $errors -eq 0 ]; then
        log "INFO" "✅ Verificación completada sin errores"
        return 0
    else
        log "ERROR" "❌ Verificación completada con $errors errores"
        return 1
    fi
}

# Función principal de deployment
main_deploy() {
    print_banner

    log "INFO" "🚀 Iniciando deployment del Sistema Autoinmune Digital..."

    check_dependencies
    create_directory_structure
    setup_virtual_environment
    generate_configuration
    configure_firewall
    create_systemd_service
    create_utility_scripts

    if verify_installation; then
        log "INFO" "🎉 ¡Deployment completado exitosamente!"
        echo ""
        echo -e "${GREEN}=== RESUMEN DE INSTALACIÓN ===${NC}"
        echo -e "📁 Directorio del proyecto: $(pwd)"
        echo -e "🐍 Entorno virtual: $VENV_NAME"
        echo -e "⚙️ Configuración: $CONFIG_FILE"
        echo -e "📜 Scripts de utilidad: scripts/"
        echo -e "🌐 Interfaz web: http://localhost:8080"
        echo ""
        echo -e "${CYAN}Para iniciar el sistema:${NC}"
        echo -e "  ./scripts/start.sh"
        echo ""
        echo -e "${CYAN}Para verificar el estado:${NC}"
        echo -e "  ./scripts/status.sh"
        echo ""
        echo -e "${CYAN}Para ver logs en tiempo real:${NC}"
        echo -e "  ./scripts/logs.sh"
        echo ""
    else
        log "ERROR" "❌ Deployment falló. Revisa los errores arriba."
        exit 1
    fi
}

# Función de ayuda
show_help() {
    echo "Upgraded Happiness - Deployment Toolkit"
    echo ""
    echo "Uso: $0 [OPCIÓN]"
    echo ""
    echo "Opciones:"
    echo "  deploy     Ejecutar deployment completo (por defecto)"
    echo "  verify     Solo verificar instalación existente"
    echo "  config     Solo generar configuración"
    echo "  service    Solo crear servicio systemd"
    echo "  help       Mostrar esta ayuda"
    echo ""
}

# Procesamiento de argumentos
case "${1:-deploy}" in
    "deploy")
        main_deploy
        ;;
    "verify")
        verify_installation
        ;;
    "config")
        generate_configuration
        ;;
    "service")
        create_systemd_service
        ;;
    "help"|"-h"|"--help")
        show_help
        ;;
    *)
        echo "Opción desconocida: $1"
        show_help
        exit 1
        ;;
esac