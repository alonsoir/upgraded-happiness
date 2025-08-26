#!/bin/bash
# 🚀 Quick Setup - Evolutionary Sniffer v3.1 with ETCD
# Este script configura todo lo necesario para ejecutar el sniffer

echo "🚀 EVOLUTIONARY SNIFFER v3.1 - QUICK SETUP"
echo "========================================"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para mostrar mensajes
info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

# 1. Check si estamos en el directorio correcto
info "Checking project directory..."
if [ ! -f "config/json/evolutionary_sniffer_config_v31_etcd.json" ]; then
    error "No se encuentra el archivo de configuración."
    error "Por favor ejecuta este script desde la raíz del proyecto upgraded-happiness"
    exit 1
fi
success "Project directory OK"

# 2. Crear directorio core si no existe
info "Setting up core directory..."
mkdir -p core
success "Core directory ready"

# 3. Check si ya existen los archivos corregidos
info "Checking for fixed sniffer files..."
files_needed=0

if [ ! -f "core/sniffer_components.py" ]; then
    warning "core/sniffer_components.py - MISSING"
    files_needed=1
fi

if [ ! -f "core/etcd_crypto_client_sniffer_fixed.py" ]; then
    warning "core/etcd_crypto_client_sniffer_fixed.py - MISSING"
    files_needed=1
fi

if [ ! -f "core/evolutionary_sniffer_standalone.py" ]; then
    warning "core/evolutionary_sniffer_standalone.py - MISSING"
    files_needed=1
fi

if [ ! -f "test_sniffer_integration_fixed.py" ]; then
    warning "test_sniffer_integration_fixed.py - MISSING"
    files_needed=1
fi

if [ $files_needed -eq 1 ]; then
    error "REQUIRED FILES MISSING!"
    echo ""
    echo "You need to save these artifacts from Claude:"
    echo "1. sniffer_components.py → core/"
    echo "2. etcd_crypto_client_sniffer_fixed.py → core/"
    echo "3. evolutionary_sniffer_standalone.py → core/"
    echo "4. test_sniffer_integration_fixed.py → root/"
    echo ""
    echo "After saving the files, run this script again."
    exit 1
fi

success "All required files present"

# 4. Fix protobuf issue
info "Fixing protobuf compatibility..."
export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python
echo "export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python" >> ~/.bashrc

# Downgrade protobuf if needed
current_protobuf=$(pip show protobuf 2>/dev/null | grep Version | cut -d' ' -f2)
if [ ! -z "$current_protobuf" ]; then
    major_version=$(echo $current_protobuf | cut -d'.' -f1)
    if [ "$major_version" -gt "3" ]; then
        warning "Protobuf version $current_protobuf is too new, downgrading..."
        pip install "protobuf<=3.20.3"
        success "Protobuf downgraded"
    else
        success "Protobuf version OK: $current_protobuf"
    fi
else
    info "Installing protobuf..."
    pip install "protobuf<=3.20.3"
fi

# 5. Install other dependencies
info "Installing dependencies..."

# Check and install zmq
if ! python3 -c "import zmq" 2>/dev/null; then
    info "Installing pyzmq..."
    pip install pyzmq
fi

# Check and install scapy
if ! python3 -c "import scapy" 2>/dev/null; then
    info "Installing scapy..."
    pip install scapy
fi

# Check and install etcd3
if ! python3 -c "import etcd3" 2>/dev/null; then
    info "Installing etcd3..."
    pip install etcd3
fi

success "Dependencies installed"

# 6. Enable development mode
info "Enabling development mode..."
export UPGRADED_HAPPINESS_DEV_MODE=true
echo "export UPGRADED_HAPPINESS_DEV_MODE=true" >> ~/.bashrc
success "Development mode enabled"

# 7. Test the installation
info "Testing installation..."
python3 test_sniffer_integration_fixed.py files

if [ $? -eq 0 ]; then
    success "File check passed"
else
    error "File check failed"
    exit 1
fi

# 8. Run integration tests
info "Running integration tests..."
python3 test_sniffer_integration_fixed.py

if [ $? -eq 0 ]; then
    success "All integration tests passed!"

    echo ""
    echo "🎉 SETUP COMPLETE!"
    echo "================"
    echo ""
    echo "Ready to run the sniffer:"
    echo "sudo python3 core/evolutionary_sniffer_standalone.py config/json/evolutionary_sniffer_config_v31_etcd.json"
    echo ""
    echo "Environment variables set:"
    echo "✅ PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python"
    echo "✅ UPGRADED_HAPPINESS_DEV_MODE=true"
    echo ""
    echo "Dependencies installed:"
    echo "✅ protobuf<=3.20.3"
    echo "✅ pyzmq"
    echo "✅ scapy"
    echo "✅ etcd3"
    echo ""
    echo "Files ready:"
    echo "✅ core/sniffer_components.py"
    echo "✅ core/etcd_crypto_client_sniffer_fixed.py"
    echo "✅ core/evolutionary_sniffer_standalone.py"
    echo "✅ test_sniffer_integration_fixed.py"

else
    error "Integration tests failed"
    echo ""
    echo "Please check the test output above and fix any issues."
    echo "You can run individual tests with:"
    echo "python3 test_sniffer_integration_fixed.py [1-6]"
fi

# 9. Show next steps
echo ""
echo "🔮 NEXT STEPS:"
echo "============="
echo ""
echo "1. Quick test run:"
echo "   export UPGRADED_HAPPINESS_DEV_MODE=true"
echo "   sudo python3 core/evolutionary_sniffer_standalone.py config/json/evolutionary_sniffer_config_v31_etcd.json"
echo ""
echo "2. For production (with real ETCD):"
echo "   - Start ETCD server"
echo "   - Unset UPGRADED_HAPPINESS_DEV_MODE"
echo "   - Run sniffer"
echo ""
echo "3. Monitoring:"
echo "   - Check logs for packet capture"
echo "   - Monitor performance stats"
echo "   - Verify ZMQ output"
echo ""
echo "4. Troubleshooting:"
echo "   python3 debug_sniffer.py"
echo ""

success "Setup script completed!"