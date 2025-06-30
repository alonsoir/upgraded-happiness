#!/bin/bash
# Quick Setup Script INTELIGENTE para BitDefender Integration en macOS
# ===================================================================
# Versión 2.0 - Resiliente, idempotente y detecta instalaciones reales

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables globales
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="upgraded-happiness-bitdefender"
BITDEFENDER_PATHS=()
BITDEFENDER_PROCESSES=()
EXISTING_INSTALL=false
PORT_CONFLICTS=()

echo -e "${BLUE}🛡️  UPGRADED HAPPINESS + BITDEFENDER INTEGRATION v2.0${NC}"
echo -e "${BLUE}    Setup INTELIGENTE y RESILIENTE para macOS${NC}"
echo ""

# Verificar que estamos en macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo -e "${RED}❌ Este script es solo para macOS${NC}"
    exit 1
fi

macos_version=$(sw_vers -productVersion)
echo -e "${BLUE}🍎 macOS detectado: ${macos_version}${NC}"

# Función para imprimir pasos con mejor formato
print_step() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}📋 $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Función para verificar comando con mejor feedback
check_command() {
    if command -v "$1" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ $1 disponible${NC}"
        return 0
    else
        echo -e "${RED}❌ $1 no disponible${NC}"
        return 1
    fi
}

# Función para detectar instalación existente
detect_existing_installation() {
    if [ -d "$PROJECT_DIR" ]; then
        echo -e "${YELLOW}⚠️  Detectada instalación existente en $PROJECT_DIR${NC}"
        EXISTING_INSTALL=true

        if [ -f "$PROJECT_DIR/bitdefender_config.yaml" ]; then
            echo -e "${GREEN}   ✅ Configuración existente encontrada${NC}"
        fi

        if [ -d "$PROJECT_DIR/venv" ]; then
            echo -e "${GREEN}   ✅ Entorno virtual existente encontrado${NC}"
        fi

        if [ -f "$PROJECT_DIR/bitdefender_integration.py" ]; then
            echo -e "${GREEN}   ✅ Archivos de integración existentes${NC}"
        fi
    fi
}

# Función INTELIGENTE para detectar BitDefender
intelligent_bitdefender_detection() {
    echo -e "${PURPLE}🔍 Iniciando detección INTELIGENTE de BitDefender...${NC}"

    # Rutas reales conocidas desde instalación .dmg
    local known_paths=(
        "/Applications/Bitdefender"
        "/Applications/Bitdefender Antivirus for Mac.app"
        "/Applications/Bitdefender.app"
        "/Applications/Bitdefender Total Security.app"
    )

    # Buscar en todas las rutas posibles
    for path in "${known_paths[@]}"; do
        if [ -d "$path" ]; then
            echo -e "${GREEN}✅ BitDefender encontrado: $path${NC}"
            BITDEFENDER_PATHS+=("$path")

            # Explorar subdirectorios
            if [ "$path" = "/Applications/Bitdefender" ]; then
                echo -e "${CYAN}   🔍 Explorando componentes:${NC}"
                for subdir in "$path"/*.app; do
                    if [ -d "$subdir" ]; then
                        local app_name=$(basename "$subdir")
                        echo -e "${GREEN}      ✅ $app_name${NC}"
                        BITDEFENDER_PATHS+=("$subdir")

                        # Verificar logs específicos
                        local logs_path="$subdir/Contents/Resources/Logs"
                        if [ -d "$logs_path" ]; then
                            echo -e "${GREEN}         📁 Logs encontrados en $logs_path${NC}"
                        fi
                    fi
                done
            fi
        fi
    done

    # Buscar rutas de logs del sistema
    local system_log_paths=(
        "/Library/Application Support/Bitdefender"
        "/Library/Logs/Bitdefender"
        "/var/log/bitdefender"
        "/private/var/log/bitdefender"
    )

    echo -e "${CYAN}   🔍 Verificando rutas de logs del sistema:${NC}"
    for log_path in "${system_log_paths[@]}"; do
        if [ -d "$log_path" ]; then
            echo -e "${GREEN}      ✅ $log_path${NC}"
            BITDEFENDER_PATHS+=("$log_path")
        else
            echo -e "${YELLOW}      ⚠️  $log_path (no existe)${NC}"
        fi
    done

    # Detectar procesos en ejecución
    echo -e "${CYAN}   🔍 Detectando procesos de BitDefender:${NC}"
    local bd_keywords=("bitdefender" "bdl" "antivirus" "coresecurity" "agent")

    for keyword in "${bd_keywords[@]}"; do
        local processes=$(ps aux | grep -i "$keyword" | grep -v grep | awk '{print $11}' | sort -u)
        if [ ! -z "$processes" ]; then
            while IFS= read -r process; do
                echo -e "${GREEN}      ✅ Proceso: $(basename "$process")${NC}"
                BITDEFENDER_PROCESSES+=("$(basename "$process")")
            done <<< "$processes"
        fi
    done

    # Resumen de detección
    echo ""
    echo -e "${PURPLE}📊 RESUMEN DE DETECCIÓN:${NC}"
    echo -e "${GREEN}   Rutas encontradas: ${#BITDEFENDER_PATHS[@]}${NC}"
    echo -e "${GREEN}   Procesos detectados: ${#BITDEFENDER_PROCESSES[@]}${NC}"

    if [ ${#BITDEFENDER_PATHS[@]} -eq 0 ] && [ ${#BITDEFENDER_PROCESSES[@]} -eq 0 ]; then
        echo -e "${RED}   ❌ BitDefender no detectado completamente${NC}"
        return 1
    else
        echo -e "${GREEN}   ✅ BitDefender detectado exitosamente${NC}"
        return 0
    fi
}

# Función para detectar conflictos de puertos
detect_port_conflicts() {
    local ports=(5555 5556 8765)

    echo -e "${CYAN}🔍 Verificando puertos...${NC}"

    for port in "${ports[@]}"; do
        if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
            local process=$(lsof -Pi :$port -sTCP:LISTEN | tail -n +2 | awk '{print $1}' | head -1)
            echo -e "${YELLOW}⚠️  Puerto $port ocupado por: $process${NC}"
            PORT_CONFLICTS+=("$port:$process")
        else
            echo -e "${GREEN}✅ Puerto $port disponible${NC}"
        fi
    done
}

# Función para resolver conflictos automáticamente
resolve_conflicts() {
    if [ ${#PORT_CONFLICTS[@]} -gt 0 ]; then
        echo -e "${YELLOW}🔧 Resolviendo conflictos de puertos...${NC}"

        # Sugerir puertos alternativos
        local alt_ports=(5557 5558 8766 8767 8768)
        local zmq_port=5555
        local dashboard_port=8765

        for conflict in "${PORT_CONFLICTS[@]}"; do
            local port=${conflict%%:*}
            local process=${conflict##*:}

            case $port in
                5555|5556)
                    for alt_port in "${alt_ports[@]}"; do
                        if ! lsof -Pi :$alt_port -sTCP:LISTEN -t >/dev/null 2>&1; then
                            zmq_port=$alt_port
                            echo -e "${GREEN}   ✅ ZeroMQ reubicado al puerto $alt_port${NC}"
                            break
                        fi
                    done
                    ;;
                8765)
                    for alt_port in "${alt_ports[@]}"; do
                        if ! lsof -Pi :$alt_port -sTCP:LISTEN -t >/dev/null 2>&1; then
                            dashboard_port=$alt_port
                            echo -e "${GREEN}   ✅ Dashboard reubicado al puerto $alt_port${NC}"
                            break
                        fi
                    done
                    ;;
            esac
        done

        # Actualizar variables globales
        ZMQ_PORT=$zmq_port
        DASHBOARD_PORT=$dashboard_port
    else
        ZMQ_PORT=5555
        DASHBOARD_PORT=8765
    fi
}

# Función para crear configuración dinámica
create_dynamic_config() {
    echo -e "${YELLOW}📝 Creando configuración dinámica...${NC}"

    # Generar lista de rutas de logs
    local log_paths_yaml=""
    for path in "${BITDEFENDER_PATHS[@]}"; do
        if [[ "$path" == *"/Logs"* ]] || [[ "$path" == *".app" ]]; then
            if [[ "$path" == *".app" ]]; then
                path="$path/Contents/Resources/Logs/"
            fi
            log_paths_yaml="${log_paths_yaml}    - \"$path\"\n"
        fi
    done

    # Generar lista de procesos
    local processes_yaml=""
    for process in "${BITDEFENDER_PROCESSES[@]}"; do
        processes_yaml="${processes_yaml}    - \"$process\"\n"
    done

    # Crear configuración completa
    cat > "$PROJECT_DIR/bitdefender_config.yaml" << EOF
# Configuración DINÁMICA para BitDefender Integration en macOS
# Generada automáticamente el $(date)

zmq:
  broker_port: $ZMQ_PORT
  dashboard_port: $(($ZMQ_PORT + 1))

bitdefender:
  enabled: true
  # Rutas REALES detectadas en tu sistema
  log_paths:
$(echo -e "$log_paths_yaml")

  # Archivos específicos de log a monitorear
  log_files:
    - "BDLDaemon.log"
    - "BDLDaemonApp.log"
    - "bdav.log"
    - "quarantine.log"
    - "real_time_protection.log"
    - "system_scan.log"
    - "antivirus.log"
    - "coresecurity.log"
    - "agent.log"

  # Procesos REALES detectados en tu sistema
  processes:
$(echo -e "$processes_yaml")

  # Configuración de monitoreo
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
  port: $DASHBOARD_PORT
  host: "localhost"

system:
  use_existing_orchestrator: true
  orchestrator_path: "../system_orchestrator.py"

logging:
  level: "INFO"
  file: "bitdefender_integration.log"

# Configuración específica detectada
detection_info:
  installation_type: "dmg_install"
  detected_paths: ${#BITDEFENDER_PATHS[@]}
  detected_processes: ${#BITDEFENDER_PROCESSES[@]}
  zmq_port: $ZMQ_PORT
  dashboard_port: $DASHBOARD_PORT
  generated_at: "$(date -Iseconds)"

development:
  simulate_bitdefender: false
  generate_test_events: true
  test_event_interval: 15
EOF

    echo -e "${GREEN}✅ Configuración dinámica creada${NC}"
}

# Función para crear todos los archivos de integración
create_integration_files() {
    echo -e "${YELLOW}📁 Creando archivos de integración...${NC}"

    # Crear bitdefender_collector.py adaptado para macOS
    cat > "$PROJECT_DIR/bitdefender_collector.py" << 'EOF'
#!/usr/bin/env python3
"""
BitDefender Data Collector para macOS
=====================================
Versión optimizada para instalaciones .dmg en macOS
"""

import json
import time
import logging
import sqlite3
import threading
import zmq
import subprocess
import plistlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import re

@dataclass
class BitDefenderEvent:
    """Estructura de evento BitDefender normalizada"""
    timestamp: str
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    threat_name: Optional[str] = None
    action_taken: Optional[str] = None
    user_name: Optional[str] = None
    raw_data: Optional[Dict] = None
    event_id: Optional[str] = None

class MacOSBitDefenderCollector:
    """Colector específico para BitDefender en macOS"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.logger = logging.getLogger(__name__)

        # Rutas detectadas dinámicamente
        self.log_paths = config.get('bitdefender', {}).get('log_paths', [])
        self.processes = config.get('bitdefender', {}).get('processes', [])

        # ZeroMQ
        self.zmq_context = zmq.Context()
        self.zmq_socket = self.zmq_context.socket(zmq.PUB)

        self.logger.info(f"🔍 Inicializado con {len(self.log_paths)} rutas y {len(self.processes)} procesos")

    def start_collection(self):
        """Inicia la recolección de eventos"""
        self.running = True
        self.logger.info("🚀 Iniciando recolección de BitDefender...")

        try:
            # Conectar ZeroMQ
            zmq_port = self.config.get('zmq', {}).get('broker_port', 5555)
            self.zmq_socket.connect(f"tcp://localhost:{zmq_port}")

            # Iniciar workers
            threading.Thread(target=self._syslog_worker, daemon=True).start()
            threading.Thread(target=self._file_monitor_worker, daemon=True).start()
            threading.Thread(target=self._process_monitor_worker, daemon=True).start()

            self.logger.info("✅ Todos los workers iniciados")

            # Bucle principal
            while self.running:
                time.sleep(5)

        except Exception as e:
            self.logger.error(f"❌ Error en recolección: {e}")
            raise

    def _syslog_worker(self):
        """Worker para syslog de macOS"""
        while self.running:
            try:
                # Buscar eventos de BitDefender en syslog
                cmd = [
                    'log', 'show', '--last', '5m',
                    '--predicate', 'process CONTAINS "bitdefender" OR process CONTAINS "BDL"',
                    '--style', 'json'
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if result.returncode == 0 and result.stdout.strip():
                    try:
                        log_data = json.loads(result.stdout)
                        for entry in log_data:
                            event = self._parse_syslog_entry(entry)
                            if event:
                                self._send_event(event)
                    except json.JSONDecodeError:
                        # Fallback a parsing de texto
                        for line in result.stdout.splitlines():
                            if self._is_bitdefender_log(line):
                                event = self._parse_text_log(line)
                                if event:
                                    self._send_event(event)

            except Exception as e:
                self.logger.error(f"Error en syslog worker: {e}")

            time.sleep(60)  # Verificar cada minuto

    def _file_monitor_worker(self):
        """Worker para monitoreo de archivos"""
        while self.running:
            try:
                for log_path in self.log_paths:
                    path = Path(log_path)
                    if path.is_dir():
                        # Buscar archivos de log en el directorio
                        for log_file in path.glob("*.log"):
                            self._process_log_file(str(log_file))
                    elif path.is_file():
                        self._process_log_file(str(path))

            except Exception as e:
                self.logger.error(f"Error en file monitor: {e}")

            time.sleep(30)

    def _process_monitor_worker(self):
        """Worker para monitoreo de procesos"""
        while self.running:
            try:
                # Verificar que los procesos de BitDefender estén ejecutándose
                running_processes = []

                ps_output = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                for line in ps_output.stdout.splitlines():
                    for bd_proc in self.processes:
                        if bd_proc.lower() in line.lower():
                            running_processes.append(bd_proc)

                # Enviar evento de estado
                status_event = BitDefenderEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type='status_check',
                    severity='info' if running_processes else 'warning',
                    raw_data={
                        'running_processes': running_processes,
                        'expected_processes': self.processes,
                        'status': 'healthy' if running_processes else 'degraded'
                    }
                )

                self._send_event(status_event)

            except Exception as e:
                self.logger.error(f"Error en process monitor: {e}")

            time.sleep(300)  # Cada 5 minutos

    def _parse_syslog_entry(self, entry: Dict) -> Optional[BitDefenderEvent]:
        """Parsea entrada de syslog"""
        try:
            message = entry.get('eventMessage', '')
            process = entry.get('processImagePath', '')
            timestamp = entry.get('timestamp', datetime.now().isoformat())

            return BitDefenderEvent(
                timestamp=timestamp,
                event_type=self._classify_event(message),
                severity=self._determine_severity(message),
                process_name=process,
                raw_data={'syslog_entry': entry}
            )
        except Exception:
            return None

    def _parse_text_log(self, log_line: str) -> Optional[BitDefenderEvent]:
        """Parsea línea de log de texto"""
        try:
            return BitDefenderEvent(
                timestamp=datetime.now().isoformat(),
                event_type=self._classify_event(log_line),
                severity=self._determine_severity(log_line),
                raw_data={'log_line': log_line}
            )
        except Exception:
            return None

    def _process_log_file(self, file_path: str):
        """Procesa archivo de log específico"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Leer últimas líneas (tail -n 50)
                lines = f.readlines()
                for line in lines[-50:]:
                    if self._is_bitdefender_log(line):
                        event = self._parse_text_log(line.strip())
                        if event:
                            self._send_event(event)
        except Exception as e:
            self.logger.debug(f"No se pudo leer {file_path}: {e}")

    def _is_bitdefender_log(self, log_line: str) -> bool:
        """Verifica si es un log de BitDefender"""
        keywords = ['bitdefender', 'threat', 'virus', 'malware', 'quarantine', 'scan']
        return any(keyword in log_line.lower() for keyword in keywords)

    def _classify_event(self, message: str) -> str:
        """Clasifica el tipo de evento"""
        message_lower = message.lower()

        if any(word in message_lower for word in ['virus', 'malware', 'threat']):
            return 'malware_detected'
        elif 'quarantine' in message_lower:
            return 'threat_quarantined'
        elif 'scan' in message_lower:
            return 'scan_activity'
        elif 'update' in message_lower:
            return 'signature_update'
        else:
            return 'general'

    def _determine_severity(self, message: str) -> str:
        """Determina severidad del evento"""
        message_lower = message.lower()

        if any(word in message_lower for word in ['critical', 'virus', 'trojan']):
            return 'high'
        elif any(word in message_lower for word in ['threat', 'suspicious']):
            return 'medium'
        else:
            return 'low'

    def _send_event(self, event: BitDefenderEvent):
        """Envía evento via ZeroMQ"""
        try:
            payload = {
                'source': 'bitdefender_macos',
                'timestamp': event.timestamp,
                'event_type': event.event_type,
                'severity': event.severity,
                'data': asdict(event)
            }

            self.zmq_socket.send_multipart([
                b"bitdefender.events",
                json.dumps(payload).encode('utf-8')
            ])

            self.logger.debug(f"📤 Evento enviado: {event.event_type}")

        except Exception as e:
            self.logger.error(f"Error enviando evento: {e}")

    def stop(self):
        """Detiene la recolección"""
        self.running = False
        self.zmq_socket.close()
        self.zmq_context.term()
        self.logger.info("🛑 Recolección detenida")

def main():
    import yaml

    # Cargar configuración
    with open('bitdefender_config.yaml', 'r') as f:
        config = yaml.safe_load(f)

    # Configurar logging
    logging.basicConfig(level=logging.INFO)

    # Iniciar colector
    collector = MacOSBitDefenderCollector(config)

    try:
        collector.start_collection()
    except KeyboardInterrupt:
        print("\n🛑 Deteniendo colector...")
        collector.stop()

if __name__ == "__main__":
    main()
EOF

    # Crear script de test específico
    cat > "$PROJECT_DIR/test_bitdefender_detection.py" << 'EOF'
#!/usr/bin/env python3
"""Test específico para detección de BitDefender en macOS"""

import subprocess
import json
from pathlib import Path

def test_bitdefender_detection():
    print("🧪 Testando detección de BitDefender en macOS...")

    # Test 1: Verificar procesos
    print("\n1. Verificando procesos:")
    ps_output = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
    bd_processes = []
    for line in ps_output.stdout.splitlines():
        if any(proc in line.lower() for proc in ['bitdefender', 'bdl']):
            process_name = line.split()[10] if len(line.split()) > 10 else "unknown"
            bd_processes.append(process_name)
            print(f"   ✅ Proceso encontrado: {process_name}")

    if not bd_processes:
        print("   ❌ No se encontraron procesos de BitDefender")

    # Test 2: Verificar acceso a syslog
    print("\n2. Verificando acceso a syslog:")
    try:
        cmd = ['log', 'show', '--last', '1m', '--predicate', 'process CONTAINS "test"']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("   ✅ Acceso a syslog OK")
        else:
            print("   ⚠️  Acceso limitado a syslog")
    except Exception as e:
        print(f"   ❌ Error accediendo syslog: {e}")

    # Test 3: Verificar rutas de BitDefender
    print("\n3. Verificando rutas de BitDefender:")
    bd_paths = [
        "/Applications/Bitdefender",
        "/Library/Application Support/Bitdefender",
        "/Library/Logs/Bitdefender"
    ]

    for path in bd_paths:
        p = Path(path)
        if p.exists():
            print(f"   ✅ {path} existe")
            if p.is_dir():
                try:
                    contents = list(p.iterdir())[:5]  # Primeros 5
                    for item in contents:
                        print(f"      📁 {item.name}")
                except PermissionError:
                    print(f"      ⚠️  Sin permisos para listar")
        else:
            print(f"   ❌ {path} no existe")

    print(f"\n🎉 Test completado. Procesos encontrados: {len(bd_processes)}")
    return len(bd_processes) > 0

if __name__ == "__main__":
    test_bitdefender_detection()
EOF

    chmod +x "$PROJECT_DIR/test_bitdefender_detection.py"
    echo -e "${GREEN}✅ Archivos de integración creados${NC}"
}

# Función para crear scripts mejorados
create_improved_scripts() {
    echo -e "${YELLOW}🔧 Creando scripts mejorados...${NC}"

    # Script de inicio con detección de puertos
    cat > "$PROJECT_DIR/start_integration.sh" << EOF
#!/bin/bash
cd "\$(dirname "\$0")"
source venv/bin/activate

echo "🚀 Iniciando BitDefender Integration..."
echo "🌐 Dashboard disponible en: http://localhost:$DASHBOARD_PORT"
echo "⚡ ZeroMQ broker en puerto: $ZMQ_PORT"

python3 bitdefender_integration.py --config bitdefender_config.yaml
EOF

    # Script de solo dashboard
    cat > "$PROJECT_DIR/start_dashboard_only.sh" << EOF
#!/bin/bash
cd "\$(dirname "\$0")"
source venv/bin/activate

echo "📊 Iniciando solo Dashboard..."
echo "🌐 Dashboard estará disponible en: http://localhost:$DASHBOARD_PORT"
echo "⏹️  Presiona Ctrl+C para detener"

python3 bitdefender_integration.py --dashboard-only --config bitdefender_config.yaml
EOF

    # Script de test mejorado
    cat > "$PROJECT_DIR/test_all.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate

echo "🧪 Ejecutando tests completos..."

echo "1. Test de detección de BitDefender:"
python3 test_bitdefender_detection.py

echo -e "\n2. Test de configuración:"
python3 -c "import yaml; print('✅ Configuración válida' if yaml.safe_load(open('bitdefender_config.yaml')) else '❌ Error')"

echo -e "\n3. Test de dependencias:"
python3 -c "import zmq, websockets, yaml, sklearn, pandas; print('✅ Todas las dependencias OK')"

echo -e "\n4. Test de puertos:"
python3 -c "
import socket
def test_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('localhost', port))
    sock.close()
    return result != 0

config_file = 'bitdefender_config.yaml'
import yaml
with open(config_file) as f:
    config = yaml.safe_load(f)

zmq_port = config['zmq']['broker_port']
dashboard_port = config['dashboard']['port']

print(f'Puerto ZMQ {zmq_port}: {"✅ Disponible" if test_port(zmq_port) else "❌ Ocupado"}')
print(f'Puerto Dashboard {dashboard_port}: {"✅ Disponible" if test_port(dashboard_port) else "❌ Ocupado"}')
"

echo -e "\n🎉 Tests completados"
EOF

    chmod +x "$PROJECT_DIR"/*.sh
    echo -e "${GREEN}✅ Scripts mejorados creados${NC}"
}

# EJECUCIÓN PRINCIPAL DEL SCRIPT
print_step "PASO 1: Detección de instalación existente"
detect_existing_installation

print_step "PASO 2: Verificación de dependencias del sistema"

# Verificar Python 3
if check_command python3; then
    python_version=$(python3 --version)
    echo "   Versión: $python_version"
else
    echo -e "${RED}❌ Python 3 es requerido${NC}"
    exit 1
fi

check_command pip3 || echo -e "${YELLOW}⚠️  pip3 será instalado${NC}"
check_command git || echo -e "${YELLOW}💡 Git recomendado para desarrollo${NC}"

print_step "PASO 3: Detección INTELIGENTE de BitDefender"
intelligent_bitdefender_detection

print_step "PASO 4: Detección y resolución de conflictos"
detect_port_conflicts
resolve_conflicts

print_step "PASO 5: Configuración de herramientas del sistema"

# Verificar e instalar Homebrew si es necesario
if ! check_command brew; then
    echo -e "${YELLOW}🍺 Instalando Homebrew...${NC}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    # Configurar PATH para Apple Silicon
    if [[ $(uname -m) == 'arm64' ]]; then
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
        eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
fi

# Instalar fswatch
if ! check_command fswatch; then
    echo -e "${YELLOW}📁 Instalando fswatch...${NC}"
    brew install fswatch
fi

print_step "PASO 6: Configuración del entorno Python"

# Crear o verificar directorio del proyecto
if [ "$EXISTING_INSTALL" = true ]; then
    echo -e "${YELLOW}♻️  Usando instalación existente${NC}"
else
    mkdir -p "$PROJECT_DIR"
    echo -e "${GREEN}✅ Directorio del proyecto creado: $PROJECT_DIR${NC}"
fi

cd "$PROJECT_DIR"

# Crear o verificar entorno virtual
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}🐍 Creando entorno virtual...${NC}"
    python3 -m venv venv
fi

source venv/bin/activate
echo -e "${GREEN}✅ Entorno virtual activado${NC}"

# Actualizar pip
pip install --upgrade pip >/dev/null 2>&1

print_step "PASO 7: Instalación de dependencias Python"

dependencies=(
    "pyzmq>=25.1.0"
    "websockets>=10.4"
    "pyyaml>=6.0"
    "scikit-learn>=1.3.0"
    "pandas>=2.0.0"
    "numpy>=1.24.0"
    "joblib>=1.3.0"
    "psutil>=5.9.0"
    "aiofiles>=23.1.0"
)

echo -e "${YELLOW}📦 Instalando/verificando paquetes Python...${NC}"
for dep in "${dependencies[@]}"; do
    echo "   📥 $dep..."
    pip install "$dep" >/dev/null 2>&1
done

echo -e "${GREEN}✅ Todas las dependencias verificadas/instaladas${NC}"

print_step "PASO 8: Generación de configuración dinámica"
create_dynamic_config

print_step "PASO 9: Creación de archivos de integración"
create_integration_files

print_step "PASO 10: Creación de scripts optimizados"
create_improved_scripts

print_step "PASO 11: Verificación final del sistema"

# Ejecutar test de detección
echo -e "${YELLOW}🧪 Ejecutando test de detección...${NC}"
python3 test_bitdefender_detection.py

# Test final de configuración
echo -e "${YELLOW}🧪 Verificando configuración generada...${NC}"
python3 -c "
import yaml
with open('bitdefender_config.yaml', 'r') as f:
    config = yaml.safe_load(f)
print(f'✅ Configuración válida')
print(f'   - Puerto ZMQ: {config[\"zmq\"][\"broker_port\"]}')
print(f'   - Puerto Dashboard: {config[\"dashboard\"][\"port\"]}')
print(f'   - Rutas detectadas: {len(config[\"bitdefender\"][\"log_paths\"])}')
print(f'   - Procesos detectados: {len(config[\"bitdefender\"][\"processes\"])}')
"

print_step "🎉 SETUP COMPLETADO EXITOSAMENTE"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🎉 ¡INTEGRACIÓN LISTA PARA USAR!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}📊 RESUMEN DE DETECCIÓN:${NC}"
echo -e "${GREEN}   BitDefender encontrado: ${#BITDEFENDER_PATHS[@]} rutas, ${#BITDEFENDER_PROCESSES[@]} procesos${NC}"
echo -e "${GREEN}   Puerto ZeroMQ: $ZMQ_PORT${NC}"
echo -e "${GREEN}   Puerto Dashboard: $DASHBOARD_PORT${NC}"
echo ""
echo -e "${BLUE}🚀 COMANDOS RÁPIDOS:${NC}"
echo ""
echo -e "${YELLOW}1. Test completo del sistema:${NC}"
echo "   ./test_all.sh"
echo ""
echo -e "${YELLOW}2. Solo Dashboard (recomendado para empezar):${NC}"
echo "   ./start_dashboard_only.sh"
echo -e "${CYAN}   Luego abre: http://localhost:$DASHBOARD_PORT${NC}"
echo ""
echo -e "${YELLOW}3. Integración completa:${NC}"
echo "   ./start_integration.sh"
echo ""
echo -e "${YELLOW}4. Test de BitDefender específico:${NC}"
echo "   python3 test_bitdefender_detection.py"
echo ""
echo -e "${BLUE}📁 ARCHIVOS CREADOS:${NC}"
echo "   ✅ bitdefender_config.yaml (configuración dinámica)"
echo "   ✅ bitdefender_collector.py (colector para macOS)"
echo "   ✅ test_bitdefender_detection.py (tests específicos)"
echo "   ✅ Scripts de inicio optimizados"
echo ""
echo -e "${GREEN}✨ ¡Todo listo para experimentar con datos REALES de BitDefender!${NC}"