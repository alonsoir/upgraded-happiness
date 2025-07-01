#!/bin/bash

# Script para regenerar los archivos protobuf

echo "Regenerando archivos protobuf..."

# Ir al directorio del proyecto
cd "$(dirname "$0")/.."

# Verificar que protoc esté instalado
if ! command -v protoc &> /dev/null; then
    echo "Error: protoc no está instalado"
    echo "En macOS: brew install protobuf"
    echo "En Ubuntu: sudo apt-get install protobuf-compiler"
    exit 1
fi

# Crear directorio de salida si no existe
mkdir -p src/protocols/protobuff

# Regenerar el archivo Python desde el .proto
protoc --python_out=. src/protocols/protobuff/network_event.proto

echo "Archivos protobuf regenerados"

# Verificar que el archivo se creó correctamente
if [ -f "src/protocols/protobuff/network_event_pb2.py" ]; then
    echo "✓ network_event_pb2.py creado exitosamente"

    # Mostrar las primeras líneas para verificar
    echo "Primeras líneas del archivo generado:"
    head -10 src/protocols/protobuff/network_event_pb2.py
else
    echo "✗ Error: No se pudo crear network_event_pb2.py"
fi

# Crear __init__.py para hacer que sea un paquete Python
touch src/__init__.py
touch src/protocols/__init__.py
touch src/protocols/protobuff/__init__.py

echo "Archivos __init__.py creados"
echo "Listo para usar!"