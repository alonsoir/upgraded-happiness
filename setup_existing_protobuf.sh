#!/bin/bash

# ===================================================================
# Setup Enhanced Promiscuous Agent - USANDO PROTOBUF EXISTENTE
# Adaptado para upgraded-happiness/src/protocols/protobuf/
# ===================================================================

set -e

echo "🚀 Configurando Enhanced Promiscuous Agent con Protobuf Existente"
echo "================================================================="

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }

# Verificar estructura del proyecto
check_project_structure() {
    log_info "Verificando estructura del proyecto..."

    if [ ! -f "src/protocols/protobuf/network_event.proto" ]; then
        log_warning "network_event.proto no encontrado en src/protocols/protobuf/"
        log_warning "Verifica que estás en el directorio raíz de upgraded-happiness"
        exit 1
    fi

    if [ ! -f "src/protocols/protobuf/network_event_pb2.py" ]; then
        log_info "Compilando protobuf existente..."
        cd src/protocols/protobuf/
        protoc --python_out=. network_event.proto
        cd ../../../

        if [ -f "src/protocols/protobuf/network_event_pb2.py" ]; then
            log_success "Protobuf compilado correctamente"
        else
            log_warning "Error compilando protobuf"
            exit 1
        fi
    else
        log_success "Protobuf ya compilado"
    fi
}

# Instalar dependencias Python mínimas
install_dependencies() {
    log_info "Instalando dependencias para geolocalización..."

    # Activar entorno virtual si existe
    if [ -d "upgraded_happiness_venv" ]; then
        source upgraded_happiness_venv/bin/activate
        log_success "Entorno virtual activado"
    fi

    # Instalar solo las nuevas dependencias para geolocalización
    pip install geoip2==4.7.0
    pip install maxminddb==2.2.0

    log_success "Dependencias de geolocalización instaladas"
}

# Descargar base de datos GeoIP
download_geoip() {
    log_info "Descargando base de datos GeoIP..."

    GEOIP_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"

    if [ ! -f "GeoLite2-City.mmdb" ]; then
        if command -v wget &> /dev/null; then
            wget -O GeoLite2-City.mmdb "$GEOIP_URL"
        elif command -v curl &> /dev/null; then
            curl -L -o GeoLite2-City.mmdb "$GEOIP_URL"
        else
            log_warning "wget/curl no disponible - descargar manualmente:"
            log_warning "$GEOIP_URL"
            return 1
        fi

        if [ -f "GeoLite2-City.mmdb" ]; then
            log_success "Base de datos GeoIP descargada"
        fi
    else
        log_success "Base de datos GeoIP ya existe"
    fi
}

# Crear configuración simple
create_config() {
    log_info "Creando configuración para agente mejorado..."

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

    log_success "Configuración creada: enhanced_agent_config.json"
}

# Crear script de test simple
create_test_script() {
    log_info "Creando script de test..."

    cat > test_enhanced_agent.py << 'EOF'
#!/usr/bin/env python3
"""
Test script para verificar que el enhanced agent funciona
"""

import sys
import time

try:
    from src.protocols.protobuf import network_event_pb2
    print("✅ Protobuf importado correctamente")

    # Crear evento de prueba
    event = network_event_pb2.NetworkEvent()
    event.event_id = "test-123"
    event.timestamp = int(time.time() * 1000)
    event.source_ip = "192.168.1.100"
    event.target_ip = "8.8.8.8"
    event.latitude = 40.7128  # NYC
    event.longitude = -74.0060
    event.agent_id = "test-agent"

    print(f"✅ Evento de prueba creado:")
    print(f"   📍 Coordenadas: {event.latitude}, {event.longitude}")
    print(f"   🌐 {event.source_ip} → {event.target_ip}")

    # Serializar
    data = event.SerializeToString()
    print(f"✅ Protobuf serializado: {len(data)} bytes")

    print("\n🎉 Test exitoso - el enhanced agent debería funcionar!")

except ImportError as e:
    print(f"❌ Error importando protobuf: {e}")
    print("💡 Verificar que network_event_pb2.py existe en src/protocols/protobuf/")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
EOF

    chmod +x test_enhanced_agent.py
    log_success "Script de test creado: test_enhanced_agent.py"
}

# Script de inicio
create_startup_script() {
    log_info "Creando script de inicio..."

    cat > start_enhanced_promiscuous_agent.sh << 'EOF'
#!/bin/bash

echo "🚀 Iniciando Enhanced Promiscuous Agent..."

# Activar entorno virtual si existe
if [ -d "upgraded_happiness_venv" ]; then
    source upgraded_happiness_venv/bin/activate
    echo "✅ Entorno virtual activado"
fi

# Verificar que tenemos permisos de root
if [[ $EUID -ne 0 ]]; then
    echo "⚡ Ejecutando con sudo para captura promiscua..."
    sudo python3 promiscuous_agent.py enhanced_agent_config.json
else
    echo "⚡ Ejecutando como root..."
    python3 promiscuous_agent.py enhanced_agent_config.json
fi
EOF

    chmod +x start_enhanced_promiscuous_agent.sh
    log_success "Script de inicio creado: start_enhanced_promiscuous_agent.sh"
}

# Verificar instalación
verify_setup() {
    log_info "Verificando setup..."

    # Ejecutar test
    python3 test_enhanced_agent.py

    # Verificar archivos
    files=("enhanced_agent_config.json" "GeoLite2-City.mmdb" "test_enhanced_agent.py" "start_enhanced_promiscuous_agent.sh")

    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            log_success "$file ✓"
        else
            log_warning "$file ✗"
        fi
    done
}

# Función principal
main() {
    echo "Configurando enhanced agent para protobuf existente..."
    echo ""

    check_project_structure
    install_dependencies
    download_geoip
    create_config
    create_test_script
    create_startup_script
    verify_setup

    echo ""
    echo "================================================================="
    log_success "🎉 Setup completado!"
    echo ""
    echo "📁 Archivos creados:"
    echo "   - enhanced_agent_config.json     (Configuración)"
    echo "   - GeoLite2-City.mmdb            (Base datos GeoIP)"
    echo "   - test_enhanced_agent.py        (Verificar setup)"
    echo "   - start_enhanced_promiscuous_agent.sh (Iniciar agente)"
    echo ""
    echo "🧪 Para verificar:"
    echo "   python3 test_enhanced_agent.py"
    echo ""
    echo "🚀 Para usar el nuevo agente:"
    echo "   1. Reemplazar tu promiscuous_agent.py actual"
    echo "   2. Ejecutar: ./start_enhanced_promiscuous_agent.sh"
    echo ""
    log_info "El agente usará tu protobuf existente con campos latitude/longitude"
}

main "$@"