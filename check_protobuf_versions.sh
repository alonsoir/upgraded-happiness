#!/bin/bash
# check_protobuf_versions.sh
# Script para verificar las versiones de protobuf instaladas

echo "🔍 Verificando versiones de protobuf..."
echo

# Verificar protoc (compilador)
echo "📦 Versión de protoc (compilador):"
if command -v protoc &> /dev/null; then
    protoc --version
else
    echo "❌ protoc no está instalado"
fi
echo

# Verificar protobuf Python runtime
echo "🐍 Versión de protobuf Python runtime:"
python3 -c "
import google.protobuf
print(f'Protobuf runtime: {google.protobuf.__version__}')

# Verificar si runtime_version existe
try:
    from google.protobuf import runtime_version
    print('✅ runtime_version disponible')
    print(f'Runtime version module: {runtime_version}')
except ImportError:
    print('❌ runtime_version NO disponible - este es el problema')

# Verificar la versión del compilador mínimo esperado
try:
    from google.protobuf import __version__
    print(f'Versión completa: {__version__}')
except ImportError:
    pass
"
echo

# Verificar si hay múltiples instalaciones
echo "🔍 Buscando múltiples instalaciones de protoc:"
which -a protoc 2>/dev/null || echo "No se encontraron múltiples instalaciones"
echo

echo "🔍 Buscando bibliotecas protobuf instaladas:"
find /usr/local /opt/homebrew /usr -name "*protobuf*" 2>/dev/null | head -10