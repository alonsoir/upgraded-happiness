#!/bin/bash

# ===================================================================
# Quick Setup y Test para Enhanced Promiscuous Agent
# Prepara todo y verifica funcionamiento
# ===================================================================

set -e

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

echo "🚀 Quick Setup y Test - Enhanced Promiscuous Agent"
echo "=================================================="

# Verificar estructura
verify_structure() {
    log_info "Verificando estructura del proyecto..."

    if [ ! -f "src/protocols/protobuf/network_event.proto" ]; then
        log_error "network_event.proto no encontrado"
        log_info "Asegúrate de estar en el directorio raíz de upgraded-happiness"
        exit 1
    fi

    if [ ! -f "promiscuous_agent.py" ]; then
        log_error "promiscuous_agent.py no encontrado"
        log_info "Copia el código del enhanced agent al archivo promiscuous_agent.py"
        exit 1
    fi

    log_success "Estructura del proyecto verificada"
}

# Compilar protobuf si es necesario
compile_protobuf() {
    log_info "Verificando protobuf compilado..."

    if [ ! -f "src/protocols/protobuf/network_event_pb2.py" ]; then
        log_info "Compilando protobuf..."
        cd src/protocols/protobuf/
        protoc --python_out=. network_event.proto
        cd ../../../

        if [ -f "src/protocols/protobuf/network_event_pb2.py" ]; then
            log_success "Protobuf compilado"
        else
            log_error "Error compilando protobuf"
            exit 1
        fi
    else
        log_success "Protobuf ya compilado"
    fi
}

# Instalar dependencias mínimas
install_deps() {
    log_info "Verificando dependencias..."

    # Verificar si el entorno virtual existe
    if [ -d "upgraded_happiness_venv" ]; then
        source upgraded_happiness_venv/bin/activate
        log_success "Entorno virtual activado"
    else
        log_warning "Entorno virtual no encontrado - usando Python del sistema"
    fi

    # Verificar dependencias críticas
    python3 -c "import scapy, zmq" 2>/dev/null || {
        log_error "Dependencias faltantes: scapy y/o zmq"
        log_info "Instalar con: pip install scapy pyzmq"
        exit 1
    }

    # Instalar GeoIP si no está
    python3 -c "import geoip2" 2>/dev/null || {
        log_warning "GeoIP2 no instalado - instalando..."
        pip install geoip2 maxminddb
    }

    log_success "Dependencias verificadas"
}

# Descargar GeoIP si no existe
download_geoip() {
    if [ ! -f "GeoLite2-City.mmdb" ]; then
        log_info "Descargando base de datos GeoIP..."

        if command -v wget &> /dev/null; then
            wget -O GeoLite2-City.mmdb "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
        elif command -v curl &> /dev/null; then
            curl -L -o GeoLite2-City.mmdb "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
        else
            log_warning "wget/curl no disponible - descargar manualmente GeoLite2-City.mmdb"
            return
        fi

        if [ -f "GeoLite2-City.mmdb" ]; then
            log_success "GeoIP descargado"
        fi
    else
        log_success "GeoIP ya existe"
    fi
}

# Crear configuración
create_config() {
    if [ ! -f "enhanced_agent_config.json" ]; then
        log_info "Creando configuración..."

        cat > enhanced_agent_config.json << 'EOF'
{
    "zmq_port": 5559,
    "zmq_host": "localhost",
    "interface": "any",
    "promiscuous_mode": true,
    "packet_filter": "",
    "geoip_db_path": "GeoLite2-City.mmdb",
    "max_packet_size": 65535,
    "geo_cache_ttl": 3600,
    "batch_size": 100
}
EOF
        log_success "Configuración creada"
    else
        log_success "Configuración ya existe"
    fi
}

# Test de importación
test_imports() {
    log_info "Testeando importaciones..."

    python3 -c "
import sys
try:
    from src.protocols.protobuf import network_event_pb2
    import scapy.all
    import zmq
    print('✅ Todas las importaciones OK')
except ImportError as e:
    print(f'❌ Error de importación: {e}')
    sys.exit(1)
" || exit 1

    log_success "Importaciones verificadas"
}

# Test básico del protobuf
test_protobuf() {
    log_info "Testeando protobuf..."

    python3 -c "
import time
from src.protocols.protobuf import network_event_pb2

# Crear evento de prueba
event = network_event_pb2.NetworkEvent()
event.event_id = 'test-123'
event.timestamp = int(time.time() * 1000)
event.source_ip = '192.168.1.100'
event.target_ip = '8.8.8.8'
event.latitude = 40.7128
event.longitude = -74.0060
event.agent_id = 'test-agent'
event.packet_size = 1500
event.src_port = 12345
event.dest_port = 80

# Serializar
data = event.SerializeToString()
print(f'✅ Protobuf serializado: {len(data)} bytes')

# Deserializar
event2 = network_event_pb2.NetworkEvent()
event2.ParseFromString(data)
print(f'✅ Coordenadas: {event2.latitude}, {event2.longitude}')
print(f'✅ Conexión: {event2.source_ip}:{event2.src_port} → {event2.target_ip}:{event2.dest_port}')
" || exit 1

    log_success "Protobuf funcionando correctamente"
}

# Verificar permisos
check_permissions() {
    log_info "Verificando permisos para captura promiscua..."

    if [[ $EUID -eq 0 ]]; then
        log_success "Ejecutándose como root - perfecto"
    else
        log_warning "No se ejecuta como root"
        log_info "El agente necesitará sudo para captura promiscua"
    fi
}

# Test ZeroMQ básico
test_zmq_basic() {
    log_info "Testeando ZeroMQ básico..."

    python3 -c "
import zmq
import time

# Test básico de publisher
context = zmq.Context()
socket = context.socket(zmq.PUB)

try:
    socket.bind('tcp://*:5559')
    print('✅ ZeroMQ puede bind al puerto 5559')
    time.sleep(0.1)
except Exception as e:
    print(f'❌ Error con ZeroMQ puerto 5559: {e}')
    exit(1)
finally:
    socket.close()
    context.term()
" || exit 1

    log_success "ZeroMQ funcionando"
}

# Crear scripts de test
create_test_scripts() {
    if [ ! -f "test_zmq_subscriber.py" ]; then
        log_info "Script de test subscriber ya debe estar creado"
        log_warning "Copia el código del test_zmq_subscriber.py"
    fi
}

# Función principal
main() {
    echo "Iniciando setup y test completo..."
    echo ""

    verify_structure
    compile_protobuf
    install_deps
    download_geoip
    create_config
    test_imports
    test_protobuf
    check_permissions
    test_zmq_basic
    create_test_scripts

    echo ""
    echo "================================================================="
    log_success "🎉 Setup y test completado exitosamente!"
    echo ""
    echo "🚀 Para probar el agente:"
    echo ""
    echo "1️⃣  Terminal 1 - Iniciar subscriber (para ver eventos):"
    echo "   python3 test_zmq_subscriber.py"
    echo ""
    echo "2️⃣  Terminal 2 - Iniciar agente promiscuo:"
    if [[ $EUID -eq 0 ]]; then
        echo "   python3 promiscuous_agent.py enhanced_agent_config.json"
    else
        echo "   sudo python3 promiscuous_agent.py enhanced_agent_config.json"
    fi
    echo ""
    echo "3️⃣  Generar tráfico de red (Terminal 3):"
    echo "   ping google.com"
    echo "   curl -s http://httpbin.org/ip"
    echo "   nslookup github.com"
    echo ""
    echo "📊 El subscriber mostrará:"
    echo "   - Eventos capturados en tiempo real"
    echo "   - Coordenadas GPS cuando se detecten"
    echo "   - Estadísticas de geolocalización"
    echo ""
    log_info "El agente buscará GPS en paquetes y usará GeoIP como fallback"
    log_info "Eventos serán enviados al puerto ZeroMQ 5559"
}

main "$@"