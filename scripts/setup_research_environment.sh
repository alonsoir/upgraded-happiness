#!/bin/bash

echo "🔬 Configurando entorno de investigación SCADA - Protocolos de Alto Rendimiento"
echo "=" * 80

# ============================================================
# PASO 1: INSTALAR DEPENDENCIAS DE INVESTIGACIÓN
# ============================================================

echo "📦 Instalando Protocol Buffers y dependencias de investigación..."

# Dependencias core de investigación
pip install protobuf>=4.24.0
pip install lz4>=4.3.2
pip install cryptography>=41.0.0
pip install msgpack>=1.0.5

# Dependencias adicionales para benchmarking científico
pip install pyarrow>=13.0.0          # Apache Arrow para comparación
pip install flatbuffers>=23.5.26     # FlatBuffers para comparación
pip install python-snappy>=0.6.1     # Snappy compression
pip install zstandard>=0.21.0        # Zstandard compression
pip install brotli>=1.0.9            # Brotli compression

# ML y análisis
pip install scikit-learn>=1.3.0      # Para ML pipeline
pip install pandas>=2.0.0            # Análisis de datos
pip install matplotlib>=3.7.0        # Visualización de benchmarks
pip install seaborn>=0.12.0          # Visualización estadística

# Performance profiling
pip install memory-profiler>=0.61.0  # Memory profiling
pip install psutil>=5.9.0            # System monitoring

echo "✅ Dependencias instaladas"

# ============================================================
# PASO 2: CREAR SCHEMA PROTOCOL BUFFERS
# ============================================================

echo "📄 Creando schema Protocol Buffers..."

# Crear directorio para schemas
mkdir -p schemas

# Crear schema de eventos SCADA
cat > schemas/scada_events.proto << 'EOF'
syntax = "proto3";

package scada.events;

// Tipos de eventos optimizados
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
  MODBUS_EVENT = 11;
  DNP3_EVENT = 12;
  IEC61850_EVENT = 13;
}

// Niveles de severidad
enum Severity {
  UNKNOWN_SEVERITY = 0;
  INFO = 1;
  LOW = 2;
  MEDIUM = 3;
  HIGH = 4;
  CRITICAL = 5;
}

// Información de red optimizada
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

// Información de dispositivo SCADA
message ScadaDeviceInfo {
  string device_id = 1;
  string device_type = 2;
  string location = 3;
  string firmware_version = 4;
  map<string, string> device_tags = 5;
}

// Datos de alarma SCADA
message ScadaAlarmData {
  uint32 alarm_code = 1;
  string alarm_text = 2;
  double value = 3;
  double threshold = 4;
  string unit = 5;
  string alarm_state = 6;
  uint64 alarm_timestamp_ns = 7;
}

// Datos de seguridad
message SecurityEventData {
  string attack_type = 1;
  double confidence_score = 2;
  repeated string indicators = 3;
  string signature = 4;
  map<string, string> metadata = 5;
}

// Métricas de performance
message PerformanceMetrics {
  double cpu_percent = 1;
  double memory_percent = 2;
  double disk_usage_percent = 3;
  double network_utilization = 4;
  uint32 active_connections = 5;
  double response_time_ms = 6;
}

// Evento principal altamente optimizado
message ScadaEvent {
  // Header compacto (campos más comunes primero para mejor compresión)
  uint64 timestamp_ns = 1;
  uint32 agent_id_hash = 2;  // Hash de 32-bit del agent_id original
  EventType event_type = 3;
  Severity severity = 4;
  uint32 sequence_number = 5;

  // Información del nodo (opcional, solo en eventos importantes)
  string node_hostname = 6;
  string node_ip = 7;

  // Datos específicos por tipo (solo uno se usa por evento)
  oneof event_data {
    NetworkInfo network_data = 10;
    ScadaAlarmData alarm_data = 11;
    SecurityEventData security_data = 12;
    PerformanceMetrics performance_data = 13;
    string simple_message = 14;  // Para eventos simples
  }

  // Datos adicionales opcionales (comprimidos automáticamente por protobuf)
  ScadaDeviceInfo device_info = 20;
  map<string, string> custom_fields = 21;

  // Información de procesamiento ML (agregada por pipeline)
  double anomaly_score = 30;
  repeated string ml_tags = 31;
  string ml_classification = 32;
}

// Lote de eventos para envío optimizado
message EventBatch {
  uint64 batch_timestamp_ns = 1;
  uint32 batch_id = 2;
  string agent_id = 3;
  uint32 event_count = 4;
  repeated ScadaEvent events = 5;

  // Metadatos del lote
  uint32 compression_type = 10;  // 0=none, 1=lz4, 2=zstd, 3=snappy
  uint32 encryption_type = 11;   // 0=none, 1=chacha20, 2=aes256
  bytes compression_metadata = 12;
}
EOF

echo "✅ Schema Protocol Buffers creado"

# ============================================================
# PASO 3: COMPILAR PROTOCOL BUFFERS
# ============================================================

echo "⚙️ Compilando Protocol Buffers..."

# Compilar a Python
protoc --python_out=src/common/ schemas/scada_events.proto

# Verificar que se generó correctamente
if [ -f "src/common/scada_events_pb2.py" ]; then
    echo "✅ Protocol Buffers compilado correctamente"
else
    echo "❌ Error compilando Protocol Buffers"
    echo "💡 Instala protobuf compiler: apt-get install protobuf-compiler (Linux) o brew install protobuf (Mac)"
fi

# ============================================================
# PASO 4: CREAR ESTRUCTURA DE INVESTIGACIÓN
# ============================================================

echo "📁 Creando estructura de investigación..."

# Estructura para diferentes protocolos
mkdir -p src/protocols/{protobuf,msgpack,arrow,flatbuffers}
mkdir -p src/benchmarks
mkdir -p src/ml_pipeline
mkdir -p research_results/{benchmarks,plots,reports}
mkdir -p tests/performance
mkdir -p tests/protocols

echo "✅ Estructura de investigación creada"

# ============================================================
# PASO 5: CREAR CONFIGURACIÓN DE INVESTIGACIÓN
# ============================================================

echo "⚙️ Creando configuración de investigación..."

cat > research_config.yaml << 'EOF'
# Configuración de investigación para protocolos SCADA

research:
  name: "SCADA Protocol Performance Study"
  version: "1.0.0"

protocols:
  available:
    - protobuf_lz4_chacha20
    - msgpack_lz4_chacha20
    - arrow_lz4_chacha20
    - flatbuffers_lz4_chacha20
    - msgpack_snappy
    - protobuf_zstd

  default: "protobuf_lz4_chacha20"

benchmarks:
  event_counts: [1000, 10000, 100000, 1000000]
  thread_counts: [1, 2, 4, 8]
  batch_sizes: [1, 10, 100, 1000]

  metrics:
    - serialization_time_ns
    - deserialization_time_ns
    - compressed_size_bytes
    - memory_usage_mb
    - cpu_usage_percent
    - events_per_second
    - throughput_mbps

ml_pipeline:
  enabled: true
  algorithms:
    - isolation_forest      # Anomaly detection
    - one_class_svm         # Outlier detection
    - dbscan               # Clustering
    - autoencoder          # Deep anomaly detection

  features:
    - event_frequency
    - value_distributions
    - temporal_patterns
    - network_patterns

zeromq:
  broker_endpoint: "tcp://localhost:5555"
  high_water_mark: 10000
  io_threads: 2

dashboard:
  real_time_buffer_size: 1000
  update_frequency_ms: 100
  offline_storage: true
EOF

echo "✅ Configuración de investigación creada"

echo ""
echo "🎉 Entorno de investigación configurado!"
echo ""
echo "📋 Próximos pasos:"
echo "1. python test_protobuf_setup.py     # Verificar Protocol Buffers"
echo "2. python create_base_interfaces.py  # Crear interfaces abstractas"
echo "3. python run_initial_benchmark.py   # Benchmark inicial"