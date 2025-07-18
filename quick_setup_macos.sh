#!/bin/bash
# Quick Setup Script para BitDefender Integration en macOS
# ========================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛡️  UPGRADED HAPPINESS + BITDEFENDER INTEGRATION${NC}"
echo -e "${BLUE}    Setup rápido para macOS 15.5${NC}"
echo ""

# Verificar que estamos en macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo -e "${RED}❌ Este script es solo para macOS${NC}"
    exit 1
fi

# Verificar versión de macOS
macos_version=$(sw_vers -productVersion)
echo -e "${BLUE}🍎 macOS detectado: ${macos_version}${NC}"

# Función para imprimir pasos
print_step() {
    echo ""
    echo -e "${YELLOW}📋 $1${NC}"
    echo "----------------------------------------"
}

# Función para verificar comando
check_command() {
    if command -v "$1" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ $1 está disponible${NC}"
        return 0
    else
        echo -e "${RED}❌ $1 no está disponible${NC}"
        return 1
    fi
}

print_step "1. Verificando dependencias del sistema"

# Verificar Python 3
if check_command python3; then
    python_version=$(python3 --version)
    echo "   Versión: $python_version"
else
    echo -e "${RED}❌ Python 3 es requerido${NC}"
    echo "   Instala Python 3: https://python.org/downloads/"
    exit 1
fi

# Verificar pip3
if ! check_command pip3; then
    echo -e "${YELLOW}⚠️  pip3 no encontrado, instalando...${NC}"
    python3 -m ensurepip --upgrade
fi

# Verificar git
check_command git || echo -e "${YELLOW}⚠️  Git recomendado para versionado${NC}"

print_step "2. Verificando BitDefender"

# Verificar instalación de BitDefender
bitdefender_found=false
bd_paths=(
    "/Applications/Bitdefender Antivirus for Mac.app"
    "/Applications/Bitdefender.app"
    "/Applications/Bitdefender Total Security.app"
)

for path in "${bd_paths[@]}"; do
    if [ -d "$path" ]; then
        echo -e "${GREEN}✅ BitDefender encontrado en: $path${NC}"
        bitdefender_found=true

        # Obtener versión si es posible
        plist_path="$path/Contents/Info.plist"
        if [ -f "$plist_path" ]; then
            version=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "$plist_path" 2>/dev/null || echo "Desconocida")
            echo "   Versión: $version"
        fi
        break
    fi
done

if [ "$bitdefender_found" = false ]; then
    echo -e "${YELLOW}⚠️  BitDefender no detectado${NC}"
    echo "   La integración funcionará sin datos de BD en tiempo real"
    echo "   Para obtener BitDefender: https://bitdefender.com/mac/"
fi

# Verificar procesos de BitDefender
bd_processes=$(ps aux | grep -i bitdefender | grep -v grep | wc -l)
if [ "$bd_processes" -gt 0 ]; then
    echo -e "${GREEN}✅ $bd_processes procesos de BitDefender ejecutándose${NC}"
else
    echo -e "${YELLOW}⚠️  No se detectaron procesos de BitDefender ejecutándose${NC}"
fi

print_step "3. Instalando herramientas del sistema"

# Verificar e instalar Homebrew
if ! check_command brew; then
    echo -e "${YELLOW}🍺 Instalando Homebrew...${NC}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    # Añadir brew al PATH para Apple Silicon
    if [[ $(uname -m) == 'arm64' ]]; then
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
        eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
fi

# Instalar fswatch para monitoreo de archivos
if ! check_command fswatch; then
    echo -e "${YELLOW}📁 Instalando fswatch...${NC}"
    brew install fswatch
fi

print_step "4. Configurando entorno Python"

# Crear directorio del proyecto si no existe
project_dir="upgraded-happiness-bitdefender"
if [ ! -d "$project_dir" ]; then
    mkdir "$project_dir"
    echo -e "${GREEN}✅ Directorio del proyecto creado: $project_dir${NC}"
fi

cd "$project_dir"

# Crear entorno virtual
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}🐍 Creando entorno virtual...${NC}"
    python3 -m venv venv
    echo -e "${GREEN}✅ Entorno virtual creado${NC}"
fi

# Activar entorno virtual
source venv/bin/activate
echo -e "${GREEN}✅ Entorno virtual activado${NC}"

# Actualizar pip
pip install --upgrade pip

print_step "5. Instalando dependencias Python"

# Lista de dependencias necesarias
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

echo -e "${YELLOW}📦 Instalando paquetes Python...${NC}"
for dep in "${dependencies[@]}"; do
    echo "   Instalando $dep..."
    pip install "$dep"
done

echo -e "${GREEN}✅ Todas las dependencias instaladas${NC}"

print_step "6. Creando archivos de configuración"

# Crear archivo de configuración YAML
cat > bitdefender_config.yaml << 'EOF'
# Configuración para BitDefender Integration en macOS
zmq:
  broker_port: 5555
  dashboard_port: 5556

bitdefender:
  enabled: true
  log_paths:
    - "/Library/Application Support/Bitdefender/Logs/"
    - "/var/log/bitdefender/"
    - "/Library/Logs/Bitdefender/"
    - "/Applications/Bitdefender Antivirus for Mac.app/Contents/Resources/Logs/"
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
  port: 8765
  host: "localhost"

system:
  use_existing_orchestrator: true
  orchestrator_path: "system_orchestrator.py"

logging:
  level: "INFO"
  file: "bitdefender_integration.log"
EOF

echo -e "${GREEN}✅ Archivo de configuración creado${NC}"

# Crear directorios necesarios
mkdir -p models logs data
echo -e "${GREEN}✅ Directorios de trabajo creados${NC}"

print_step "7. Creando scripts de utilidad"

# Crear script de inicio
cat > start_integration.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
echo "🚀 Iniciando BitDefender Integration..."
python3 bitdefender_integration.py --config bitdefender_config.yaml
EOF

chmod +x start_integration.sh

# Crear script solo para dashboard
cat > start_dashboard_only.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
echo "📊 Iniciando solo Dashboard..."
echo "🌐 Dashboard estará disponible en: http://localhost:8765"
python3 bitdefender_integration.py --dashboard-only --config bitdefender_config.yaml
EOF

chmod +x start_dashboard_only.sh

# Crear script de verificación
cat > check_bitdefender.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python3 bitdefender_integration.py --check-bitdefender
EOF

chmod +x check_bitdefender.sh

echo -e "${GREEN}✅ Scripts de utilidad creados${NC}"

print_step "8. Verificando permisos del sistema"

# Verificar permisos para acceder a logs
echo -e "${YELLOW}🔐 Verificando permisos para logs del sistema...${NC}"
if log show --last 1m --predicate 'process CONTAINS "test"' >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Permisos para logs del sistema OK${NC}"
else
    echo -e "${YELLOW}⚠️  Permisos limitados para logs del sistema${NC}"
    echo "   Para acceso completo a logs, considera:"
    echo "   - Ejecutar con sudo (no recomendado para desarrollo)"
    echo "   - Configurar permisos de desarrollador en macOS"
    echo "   - Usar Terminal con permisos completos"
fi

# Verificar acceso a directorios de BitDefender
for path in "/Library/Application Support/Bitdefender" "/Library/Logs/Bitdefender"; do
    if [ -d "$path" ]; then
        if [ -r "$path" ]; then
            echo -e "${GREEN}✅ Acceso de lectura a $path${NC}"
        else
            echo -e "${YELLOW}⚠️  Sin acceso de lectura a $path${NC}"
        fi
    fi
done

print_step "9. Creando archivo de prueba"

# Crear script de test básico
cat > integration_test.py << 'EOF'
#!/usr/bin/env python3
"""Test básico de la integración BitDefender"""

import asyncio
import json
import time
from pathlib import Path

async def test_basic_functionality():
    """Test básico de funcionalidad"""
    print("🧪 Ejecutando tests básicos...")

    # Test 1: Verificar imports
    try:
        import zmq
        import websockets
        import yaml
        import sklearn
        import pandas as pd
        import numpy as np
        print("✅ Todas las dependencias se importan correctamente")
    except ImportError as e:
        print(f"❌ Error importando dependencias: {e}")
        return False

    # Test 2: Verificar configuración
    config_path = Path("bitdefender_config.yaml")
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            print("✅ Archivo de configuración válido")
        except Exception as e:
            print(f"❌ Error en configuración: {e}")
            return False
    else:
        print("❌ Archivo de configuración no encontrado")
        return False

    # Test 3: Test básico de ZeroMQ
    try:
        context = zmq.Context()
        socket = context.socket(zmq.PUB)
        socket.bind("tcp://*:5556")  # Puerto de test
        socket.close()
        context.term()
        print("✅ ZeroMQ funciona correctamente")
    except Exception as e:
        print(f"❌ Error con ZeroMQ: {e}")
        return False

    # Test 4: Verificar estructura de directorios
    required_dirs = ["models", "logs", "data"]
    for dir_name in required_dirs:
        if Path(dir_name).exists():
            print(f"✅ Directorio {dir_name} existe")
        else:
            print(f"⚠️  Directorio {dir_name} no existe")

    print("🎉 Tests básicos completados")
    return True

if __name__ == "__main__":
    asyncio.run(test_basic_functionality())
EOF

chmod +x integration_test.py

print_step "10. Ejecutando test básico"

python3 integration_test.py

print_step "Setup completado!"

echo ""
echo -e "${GREEN}🎉 ¡Setup completado exitosamente!${NC}"
echo ""
echo -e "${BLUE}📋 Próximos pasos:${NC}"
echo ""
echo -e "${YELLOW}1. Verificar BitDefender:${NC}"
echo "   ./check_bitdefender.sh"
echo ""
echo -e "${YELLOW}2. Probar solo el dashboard:${NC}"
echo "   ./start_dashboard_only.sh"
echo "   Luego abre: http://localhost:8765"
echo ""
echo -e "${YELLOW}3. Ejecutar integración completa:${NC}"
echo "   ./start_integration.sh"
echo ""
echo -e "${YELLOW}4. Para desarrollo:${NC}"
echo "   source venv/bin/activate"
echo "   python3 bitdefender_integration.py --help"
echo ""
echo -e "${BLUE}📁 Archivos creados:${NC}"
echo "   - bitdefender_config.yaml (configuración)"
echo "   - start_integration.sh (inicio completo)"
echo "   - start_dashboard_only.sh (solo dashboard)"
echo "   - check_bitdefender.sh (verificar BD)"
echo "   - test_integration.py (tests básicos)"
echo ""
echo -e "${GREEN}✨ ¡Disfruta experimentando con Upgraded Happiness!${NC}"