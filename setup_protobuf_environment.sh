#!/bin/bash

# setup_protobuf_environment.sh
# Script para configurar el entorno de investigación de Protocol Buffers

echo "🔧 Configurando entorno de investigación Protocol Buffers..."
echo "=================================================="

# Verificar que estamos en el directorio correcto
if [ ! -f "setup.py" ]; then
    echo "❌ Error: Ejecuta este script desde la raíz del proyecto upgraded-happiness"
    exit 1
fi

# Crear estructura de directorios si no existe
echo "📁 Creando estructura de directorios..."
mkdir -p src/protocols/protobuff
mkdir -p src/common
mkdir -p research_results/benchmarks
mkdir -p tests/unit

# Instalar dependencias de Python
echo "📦 Instalando dependencias de Python..."
pip install --upgrade pip

# Dependencias principales
pip install protobuf>=4.21.0
pip install lz4>=4.0.0
pip install pycryptodome>=3.15.0
pip install aiofiles>=0.8.0
pip install pytest-asyncio>=0.21.0
pip install pytest-benchmark>=4.0.0

# Verificar instalación
echo ""
echo "🔍 Verificando instalación de dependencias..."

python -c "import google.protobuf; print('✅ Protocol Buffers:', google.protobuf.__version__)" 2>/dev/null || echo "❌ Protocol Buffers no instalado"
python -c "import lz4; print('✅ LZ4 instalado')" 2>/dev/null || echo "❌ LZ4 no instalado"
python -c "from Crypto.Cipher import ChaCha20; print('✅ ChaCha20 (pycryptodome) instalado')" 2>/dev/null || echo "❌ pycryptodome no instalado"
python -c "import aiofiles; print('✅ aiofiles instalado')" 2>/dev/null || echo "❌ aiofiles no instalado"

# Compilar archivo .proto si existe y protoc está disponible
if command -v protoc &> /dev/null; then
    if [ -f "src/protocols/protobuff/scada_events.proto" ]; then
        echo ""
        echo "🔨 Compilando archivo .proto..."
        protoc --python_out=src/protocols/protobuff/ src/protocols/protobuff/scada_events.proto
        echo "✅ Archivo .proto compilado"
    fi
else
    echo "⚠️  protoc no encontrado. Instalalo con: brew install protobuf (macOS) o apt install protobuf-compiler (Linux)"
fi

# Crear archivos __init__.py
echo ""
echo "📄 Creando archivos __init__.py..."
touch src/__init__.py
touch src/protocols/__init__.py
touch src/protocols/protobuff/__init__.py
touch src/common/__init__.py
touch tests/__init__.py
touch tests/unit/__init__.py

# Mensaje final
echo ""
echo "✅ Configuración completada!"
echo ""
echo "📝 Próximos pasos:"
echo "   1. Copia los archivos base_interfaces.py y protobuf_serializer.py a sus ubicaciones"
echo "   2. Copia el test actualizado: cp test_protobuf_research.py tests/unit/"
echo "   3. Ejecuta los tests: pytest tests/unit/test_protobuf_research.py -v"
echo ""
echo "🚀 ¡Listo para investigación de protocolos!"