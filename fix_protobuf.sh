#!/bin/bash

echo "=== SOLUCIONANDO PROBLEMAS DE PROTOBUF ==="

# Actualizar protobuf en el entorno virtual
echo "1. Actualizando protobuf..."
pip install --upgrade protobuf

# Verificar que protoc esté instalado
if ! command -v protoc &> /dev/null; then
    echo "2. Instalando protoc..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install protobuf
        else
            echo "   Instala Homebrew primero, luego ejecuta: brew install protobuf"
            exit 1
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        sudo apt-get update
        sudo apt-get install protobuf-compiler
    fi
else
    echo "2. protoc ya está instalado: $(protoc --version)"
fi

# Crear la estructura de directorios correcta
echo "3. Creando estructura de directorios..."
mkdir -p src/protocols/protobuf  # Sin doble 'f'

# Crear el archivo .proto si no existe
PROTO_FILE="src/protocols/protobuf/network_event.proto"
if [ ! -f "$PROTO_FILE" ]; then
    echo "4. Creando archivo .proto..."
    cat > "$PROTO_FILE" << 'EOF'
syntax = "proto3";

package network.events;

message NetworkEvent {
    string event_id = 1;
    int64 timestamp = 2;
    string source_ip = 3;
    string target_ip = 4;
    int32 packet_size = 5;
    int32 dest_port = 6;
    int32 src_port = 7;
    string agent_id = 8;
    float anomaly_score = 9;
    double latitude = 10;
    double longitude = 11;
}
EOF
else
    echo "4. Archivo .proto ya existe"
fi

# Limpiar archivos generados anteriormente
echo "5. Limpiando archivos anteriores..."
rm -f src/protocols/protobuf/*_pb2.py
rm -rf src/protocols/protobuff  # Eliminar directorio con typo

# Regenerar con versión compatible
echo "6. Regenerando archivos protobuf..."
protoc --python_out=. "$PROTO_FILE"

# Crear archivos __init__.py
echo "7. Creando archivos __init__.py..."
touch src/__init__.py
touch src/protocols/__init__.py
touch src/protocols/protobuf/__init__.py

# Verificar que se creó correctamente
if [ -f "src/protocols/protobuf/network_event_pb2.py" ]; then
    echo "✅ network_event_pb2.py creado exitosamente"

    # Verificar que no tenga referencias a runtime_version
    if grep -q "runtime_version" "src/protocols/protobuf/network_event_pb2.py"; then
        echo "⚠️  El archivo aún contiene runtime_version, vamos a arreglarlo..."

        # Crear una versión compatible manualmente
        python << 'PYTHON_EOF'
import sys
sys.path.append('.')

# Leer el archivo generado
with open('src/protocols/protobuf/network_event_pb2.py', 'r') as f:
    content = f.read()

# Remover las líneas problemáticas
lines = content.split('\n')
filtered_lines = []
skip_block = False

for line in lines:
    if 'runtime_version' in line or '_runtime_version' in line:
        continue
    if 'ValidateProtobufRuntimeVersion' in line:
        skip_block = True
        continue
    if skip_block and line.strip() == ')':
        skip_block = False
        continue
    if not skip_block:
        filtered_lines.append(line)

# Escribir el archivo corregido
with open('src/protocols/protobuf/network_event_pb2.py', 'w') as f:
    f.write('\n'.join(filtered_lines))

print("Archivo protobuf corregido para compatibilidad")
PYTHON_EOF
    else
        echo "✅ Archivo protobuf compatible generado"
    fi
else
    echo "❌ Error: No se pudo crear network_event_pb2.py"
    exit 1
fi

echo ""
echo "=== FINALIZADO ==="
echo "Archivos creados:"
echo "  - src/protocols/protobuf/network_event.proto"
echo "  - src/protocols/protobuf/network_event_pb2.py"
echo ""
echo "Ahora puedes ejecutar: python diagnose_versions.py para verificar"