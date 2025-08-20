#!/bin/bash
# regenerate_protobuf.sh
# Script para regenerar archivos protobuf v3.1 compatible

set -e

echo "🚀 Regenerando archivos protobuf para upgraded-happiness v3.1..."
echo

# Colores para output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Directorio base del proyecto
PROJECT_DIR="$(pwd)"
PROTO_SOURCE_DIR="protocols/v3.1"
OUTPUT_DIR="protocols/v3.1"

echo -e "${YELLOW}📁 Directorio del proyecto: ${PROJECT_DIR}${NC}"
echo -e "${YELLOW}📁 Directorio de proto fuentes: ${PROTO_SOURCE_DIR}${NC}"
echo -e "${YELLOW}📁 Directorio de salida: ${OUTPUT_DIR}${NC}"
echo

# Verificar que estamos en el directorio correcto
if [ ! -d "protocols/v3.1" ]; then
    echo -e "${RED}❌ Error: No se encontró el directorio protocols/v3.1${NC}"
    echo -e "${RED}   Ejecuta este script desde el directorio raíz de upgraded-happiness${NC}"
    exit 1
fi

# Verificar que existen los archivos .proto
if [ ! -f "protocols/v3.1/network_security_clean_v31.proto" ]; then
    echo -e "${RED}❌ Error: No se encontró network_security_clean_v31.proto${NC}"
    exit 1
fi

# Crear backup de archivos existentes
echo -e "${YELLOW}💾 Creando backup de archivos existentes...${NC}"
if [ -f "${OUTPUT_DIR}/network_security_clean_v31_pb2.py" ]; then
    cp "${OUTPUT_DIR}/network_security_clean_v31_pb2.py" "${OUTPUT_DIR}/network_security_clean_v31_pb2.py.backup"
    echo "✅ Backup creado: network_security_clean_v31_pb2.py.backup"
fi

if [ -f "${OUTPUT_DIR}/firewall_commands_v31_pb2.py" ]; then
    cp "${OUTPUT_DIR}/firewall_commands_v31_pb2.py" "${OUTPUT_DIR}/firewall_commands_v31_pb2.py.backup"
    echo "✅ Backup creado: firewall_commands_v31_pb2.py.backup"
fi

# Limpiar archivos generados anteriores
echo -e "${YELLOW}🧹 Limpiando archivos generados anteriores...${NC}"
rm -f "${OUTPUT_DIR}"/*_pb2.py
rm -f "${OUTPUT_DIR}"/*_pb2_grpc.py
rm -rf "${OUTPUT_DIR}/__pycache__"

# Verificar versión de protoc
echo -e "${YELLOW}🔍 Verificando protoc...${NC}"
if ! command -v protoc &> /dev/null; then
    echo -e "${RED}❌ Error: protoc no está instalado${NC}"
    echo -e "${YELLOW}💡 Instala protoc:${NC}"
    echo "   macOS: brew install protobuf"
    echo "   Ubuntu: sudo apt-get install protobuf-compiler"
    exit 1
fi

PROTOC_VERSION=$(protoc --version)
echo -e "${GREEN}✅ ${PROTOC_VERSION}${NC}"

# Regenerar archivos Python
echo -e "${YELLOW}⚙️ Regenerando archivos Python desde proto...${NC}"

# Comando protoc con configuración específica
protoc \
    --proto_path="${PROTO_SOURCE_DIR}" \
    --python_out="${OUTPUT_DIR}" \
    "${PROTO_SOURCE_DIR}/network_security_clean_v31.proto" \
    "${PROTO_SOURCE_DIR}/firewall_commands_v31.proto"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Archivos protobuf regenerados exitosamente${NC}"
else
    echo -e "${RED}❌ Error regenerando archivos protobuf${NC}"
    exit 1
fi

# Verificar que se generaron los archivos
echo -e "${YELLOW}🔍 Verificando archivos generados...${NC}"
for file in "network_security_clean_v31_pb2.py" "firewall_commands_v31_pb2.py"; do
    if [ -f "${OUTPUT_DIR}/${file}" ]; then
        echo -e "${GREEN}✅ ${file}${NC}"

        # Verificar que no contiene referencias a runtime_version problemáticas
        if grep -q "runtime_version" "${OUTPUT_DIR}/${file}"; then
            echo -e "${YELLOW}⚠️  ${file} contiene referencias a runtime_version${NC}"
        fi
    else
        echo -e "${RED}❌ ${file} NO se generó${NC}"
        exit 1
    fi
done

# Regenerar __init__.py con imports correctos
echo -e "${YELLOW}📝 Regenerando __init__.py...${NC}"
cat > "${OUTPUT_DIR}/__init__.py" << 'EOF'
"""
Protobuf generated modules for upgraded-happiness v3.1
"""

# Importaciones seguras para evitar problemas de runtime_version
try:
    from . import network_security_clean_v31_pb2
    NETWORK_SECURITY_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Warning: No se pudo importar network_security_clean_v31_pb2: {e}")
    NETWORK_SECURITY_AVAILABLE = False

try:
    from . import firewall_commands_v31_pb2
    FIREWALL_COMMANDS_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Warning: No se pudo importar firewall_commands_v31_pb2: {e}")
    FIREWALL_COMMANDS_AVAILABLE = False

# Exports condicionales
__all__ = []

if NETWORK_SECURITY_AVAILABLE:
    __all__.append("network_security_clean_v31_pb2")

if FIREWALL_COMMANDS_AVAILABLE:
    __all__.append("firewall_commands_v31_pb2")

# Verificación de compatibilidad
def check_protobuf_compatibility():
    """Verifica compatibilidad de protobuf"""
    try:
        import google.protobuf
        version = google.protobuf.__version__
        print(f"✅ Protobuf runtime version: {version}")

        # Verificar runtime_version (opcional en versiones más antiguas)
        try:
            from google.protobuf import runtime_version
            print("✅ runtime_version disponible")
        except ImportError:
            print("ℹ️  runtime_version no disponible (normal en versiones < 5.x)")

        return True
    except Exception as e:
        print(f"❌ Error verificando protobuf: {e}")
        return False

# Verificar al importar
if __name__ != "__main__":
    check_protobuf_compatibility()
EOF

echo -e "${GREEN}✅ __init__.py regenerado${NC}"

# Verificar que las importaciones funcionan
echo -e "${YELLOW}🧪 Probando importaciones...${NC}"
cd "${PROJECT_DIR}"

python3 -c "
import sys
sys.path.insert(0, '.')

print('🧪 Probando importaciones...')

try:
    # Probar importación del módulo
    import protocols.v3_1
    print('✅ protocols.v3_1 importado correctamente')

    # Probar importación directa
    from protocols.v3_1 import network_security_clean_v31_pb2
    print('✅ network_security_clean_v31_pb2 importado correctamente')

    # Probar crear instancia de mensaje
    event = network_security_clean_v31_pb2.NetworkSecurityEvent()
    print('✅ NetworkSecurityEvent instanciado correctamente')

    # Verificar que tiene los campos esperados
    event.event_id = 'test'
    print('✅ Campos básicos funcionan correctamente')

    print('🎉 ¡Todas las importaciones funcionan correctamente!')

except Exception as e:
    print(f'❌ Error en importaciones: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}🎉 ¡Regeneración completada exitosamente!${NC}"
    echo
    echo -e "${YELLOW}📋 Siguientes pasos:${NC}"
    echo "1. Activa tu entorno virtual: source upgraded_happiness_venv/bin/activate"
    echo "2. Prueba ejecutar el sniffer: sudo -E python3 core/evolutionary_sniffer_standalone.py config/json/evolutionary_sniffer_config_v31_etcd.json"
    echo
    echo -e "${GREEN}✅ Los archivos protobuf han sido regenerados correctamente${NC}"
else
    echo -e "${RED}❌ Error en las pruebas de importación${NC}"
    echo -e "${YELLOW}💡 Puede ser necesario revisar la compatibilidad de versiones${NC}"
    exit 1
fi