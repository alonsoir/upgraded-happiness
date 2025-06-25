#!/bin/bash
# run_protobuf_research.sh - Script principal para ejecutar investigación de Protocol Buffers
# Uso: bash run_protobuf_research.sh [setup|test|benchmark|all]

set -e  # Salir en caso de error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# ============================================================
# FUNCIÓN DE SETUP COMPLETO
# ============================================================
setup_environment() {
    print_header "🔬 SETUP ENTORNO DE INVESTIGACIÓN SCADA"

    echo "📦 Paso 1: Instalando dependencias Python..."
    echo "  → Core research dependencies..."
    pip install "protobuf>=4.24.0"
    pip install "lz4>=4.3.2"
    pip install "cryptography>=41.0.0"
    pip install "msgpack>=1.0.5"

    echo "  → Advanced serialization..."
    pip install "pyarrow>=13.0.0"
    pip install "flatbuffers>=23.5.26"
    pip install "python-snappy>=0.6.1"

    echo "  → ML and analysis..."
    pip install "scikit-learn>=1.3.0"
    pip install "pandas>=2.0.0"
    pip install "matplotlib>=3.7.0"

    echo "  → Profiling tools..."
    pip install "memory-profiler>=0.61.0"
    pip install "psutil>=5.9.0"
    print_success "Dependencias instaladas"

    echo "📁 Paso 2: Creando estructura de directorios..."
    mkdir -p schemas
    mkdir -p src/{protocols/{protobuf,msgpack,arrow,flatbuffers},common,benchmarks,ml_pipeline}
    mkdir -p research_results/{benchmarks,plots,reports}
    mkdir -p tests/{performance,protocols}
    print_success "Estructura creada"

    echo "📄 Paso 3: Creando schema Protocol Buffers..."
    cat > schemas/scada_events.proto << 'EOF'
syntax = "proto3";
package scada.events;

enum EventType {
    UNKNOWN_EVENT = 0;
    HEARTBEAT = 1;
    SECURITY_ALERT = 2;
    NETWORK_ANOMALY = 3;
    PROTOCOL_VIOLATION = 4;
    PERFORMANCE_ISSUE = 5;
    SYSTEM_STATUS = 6;
    AGENT_START = 7;
    AGENT_STOP = 8;
    CONFIG_CHANGE = 9;
    SCADA_ALARM = 10;
}

enum Severity {
    UNKNOWN_SEVERITY = 0;
    INFO = 1;
    LOW = 2;
    MEDIUM = 3;
    HIGH = 4;
    CRITICAL = 5;
}

message NetworkInfo {
    string source_ip = 1;
    string target_ip = 2;
    uint32 source_port = 3;
    uint32 target_port = 4;
    string protocol = 5;
    uint64 bytes_transferred = 6;
    uint32 packet_count = 7;
    double latency_ms = 8;
}

message ScadaAlarmData {
    uint32 alarm_code = 1;
    string alarm_text = 2;
    double value = 3;
    double threshold = 4;
    string unit = 5;
    string alarm_state = 6;
    uint64 alarm_timestamp_ns = 7;
}

message SecurityEventData {
    string attack_type = 1;
    double confidence_score = 2;
    repeated string indicators = 3;
    string signature = 4;
}

message ScadaEvent {
    uint64 timestamp_ns = 1;
    uint32 agent_id_hash = 2;
    EventType event_type = 3;
    Severity severity = 4;
    uint32 sequence_number = 5;

    string node_hostname = 6;
    string node_ip = 7;

    oneof event_data {
        NetworkInfo network_data = 10;
        ScadaAlarmData alarm_data = 11;
        SecurityEventData security_data = 12;
        string simple_message = 14;
    }

    double anomaly_score = 30;
    repeated string ml_tags = 31;
    string ml_classification = 32;
}
EOF
    print_success "Schema Protocol Buffers creado"

    echo "⚙️ Paso 4: Compilando Protocol Buffers..."
    if command -v protoc &> /dev/null; then
        protoc --python_out=src/common/ schemas/scada_events.proto
        if [ -f "src/common/scada_events_pb2.py" ]; then
            print_success "Protocol Buffers compilado correctamente"
        else
            print_error "Error compilando Protocol Buffers"
            return 1
        fi
    else
        print_warning "protoc no encontrado. Instalando..."
        case "$OSTYPE" in
            linux*)
                sudo apt-get update && sudo apt-get install -y protobuf-compiler
                ;;
            darwin*)
                brew install protobuf
                ;;
            *)
                print_error "OS no soportado. Instala protobuf-compiler manualmente"
                return 1
                ;;
        esac
        protoc --python_out=src/common/ schemas/scada_events.proto
    fi

    echo "📋 Paso 5: Creando archivos __init__.py..."
    touch src/__init__.py
    touch src/protocols/__init__.py
    touch src/protocols/protobuf/__init__.py
    touch src/common/__init__.py
    print_success "Módulos Python configurados"

    echo "⚙️ Paso 6: Creando configuración de investigación..."
    cat > research_config.yaml << 'EOF'
research:
  name: "SCADA Protocol Performance Study"
  version: "1.0.0"

protocols:
  available:
    - protobuf_lz4_chacha20
    - msgpack_lz4_chacha20
    - arrow_lz4_chacha20
  default: "protobuf_lz4_chacha20"

benchmarks:
  event_counts: [1000, 10000, 100000]
  thread_counts: [1, 2, 4, 8]
  batch_sizes: [1, 10, 100, 1000]

zeromq:
  broker_endpoint: "tcp://localhost:5555"
  high_water_mark: 10000
EOF
    print_success "Configuración creada"

    print_header "✅ SETUP COMPLETADO"
    echo "🎯 Entorno de investigación configurado correctamente"
    echo "📝 Siguiente paso: bash scripts/run_protobuf_research.sh test"
}

# ============================================================
# FUNCIÓN DE TEST BÁSICO
# ============================================================
test_basic_functionality() {
    print_header "🧪 TEST BÁSICO DE FUNCIONALIDAD"

    echo "📋 Verificando setup..."

    # Verificar que Python puede importar todo
    python3 -c "
import sys
sys.path.insert(0, 'src')
sys.path.insert(0, 'src/protocols')

try:
    # Test imports básicos
    import os
    import sys

    # Verificar que existen los archivos necesarios
    required_files = [
        'src/common/base_interfaces.py',
        'src/protocols/protobuff/protobuf_serializer.py'
    ]

    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)

    if missing_files:
        print(f'❌ Archivos faltantes: {missing_files}')
        print('💡 Ejecuta primero: bash scripts/setup_research_environment.sh')
        exit(1)

    print('✅ Archivos necesarios encontrados')

    # Test imports
    from common.base_interfaces import CompressionAlgorithm, EncryptionAlgorithm
    from protocols.protobuff.protobuf_serializer import ProtobufEventSerializer

    print('✅ Todos los imports funcionan')

    # Test rápido de creación de serializer
    serializer = ProtobufEventSerializer()
    print('✅ Serializer creado correctamente')

except ImportError as e:
    print(f'❌ Error import: {e}')
    exit(1)
except Exception as e:
    print(f'❌ Error: {e}')
    exit(1)
"

    if [ $? -eq 0 ]; then
        print_success "Test básico PASADO"
        echo "🎯 Sistema funcionando correctamente"
        echo "📝 Siguiente paso: bash scripts/run_protobuf_research.sh benchmark"
    else
        print_error "Test básico FALLÓ"
        echo "💡 Ejecuta: bash scripts/setup_research_environment.sh"
        return 1
    fi
}

# ============================================================
# FUNCIÓN DE BENCHMARK COMPLETO
# ============================================================
run_full_benchmark() {
    print_header "📊 BENCHMARK COMPLETO PROTOCOL BUFFERS"

    echo "🚀 Ejecutando suite completa de benchmarks..."
    echo "⏱️  Esto puede tomar varios minutos..."

    # Verificar que existe el archivo de test
    if [ -f "tests/unit/test_protobuf_research.py" ]; then
        python3 -m pytest tests/unit/test_protobuf_research.py -v --benchmark-only
    else
        print_warning "Archivo de test no encontrado, ejecutando test básico..."
        python3 -c "
import sys
sys.path.insert(0, 'src')

from protocols.protobuff.protobuf_serializer import ProtobufEventSerializer
from common.base_interfaces import CompressionAlgorithm, EncryptionAlgorithm
import time

print('🧪 Ejecutando benchmark básico...')

# Datos de prueba
sample_data = {
    'event_id': 'benchmark_001',
    'timestamp': int(time.time() * 1000000000),
    'action': 'benchmark_test',
    'properties': {
        'test_data': 'x' * 1000,
        'iteration': 1
    }
}

serializer = ProtobufEventSerializer()

# Benchmark simple
import asyncio

async def simple_benchmark():
    start_time = time.perf_counter()

    for i in range(1000):
        serialized = await serializer.serialize(sample_data)
        deserialized = await serializer.deserialize(serialized)

    end_time = time.perf_counter()

    print(f'✅ 1000 operaciones completadas en {(end_time - start_time)*1000:.1f} ms')
    print(f'✅ {1000/(end_time - start_time):.0f} operaciones/segundo')

asyncio.run(simple_benchmark())
"
    fi

    if [ $? -eq 0 ]; then
        print_success "Benchmark completado exitosamente"

        # Crear directorio de resultados si no existe
        mkdir -p research_results/benchmarks

        echo ""
        echo "🎯 Próximos pasos en la investigación:"
        echo "   1. Implementar MessagePack + LZ4 + ChaCha20"
        echo "   2. Implementar Apache Arrow + LZ4 + ChaCha20"
        echo "   3. Ejecutar benchmark comparativo"
        echo "   4. Integrar con ZeroMQ y pipeline ML"

    else
        print_error "Benchmark falló"
        return 1
    fi
}

# ============================================================
# FUNCIÓN PRINCIPAL
# ============================================================
main() {
    local command=${1:-"help"}

    case $command in
        "setup")
            setup_environment
            ;;
        "test")
            test_basic_functionality
            ;;
        "benchmark")
            run_full_benchmark
            ;;
        "all")
            setup_environment && test_basic_functionality && run_full_benchmark
            ;;
        "help"|*)
            echo "🔬 SCADA Protocol Research - Protocol Buffers"
            echo ""
            echo "Uso: bash scripts/run_protobuf_research.sh [comando]"
            echo ""
            echo "Comandos disponibles:"
            echo "  setup     - Configurar entorno completo"
            echo "  test      - Ejecutar test básico de funcionalidad"
            echo "  benchmark - Ejecutar benchmark completo"
            echo "  all       - Ejecutar todo (setup + test + benchmark)"
            echo "  help      - Mostrar esta ayuda"
            echo ""
            echo "Ejemplo de uso completo:"
            echo "  bash scripts/run_protobuf_research.sh setup"
            echo "  bash scripts/run_protobuf_research.sh test"
            echo "  bash scripts/run_protobuf_research.sh benchmark"
            ;;
    esac
}

# Ejecutar función principal con argumentos
main "$@"