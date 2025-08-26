#!/bin/bash
# fix_protobuf_deps.sh
# Script para arreglar dependencias de protobuf en upgraded-happiness

set -e

echo "🔧 Arreglando dependencias de protobuf para upgraded-happiness..."
echo

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Verificar si estamos en un entorno virtual
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo -e "${YELLOW}⚠️  No estás en un entorno virtual${NC}"
    echo -e "${YELLOW}   Recomendamos activar: source upgraded_happiness_venv/bin/activate${NC}"
    echo
    read -p "¿Continuar sin entorno virtual? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelado."
        exit 1
    fi
fi

# Verificar la versión actual de protobuf
echo -e "${YELLOW}🔍 Verificando versión actual de protobuf...${NC}"
CURRENT_PROTOBUF=$(python3 -c "import google.protobuf; print(google.protobuf.__version__)" 2>/dev/null || echo "no instalado")
echo -e "${YELLOW}   Versión actual: ${CURRENT_PROTOBUF}${NC}"

# Verificar disponibilidad de runtime_version
echo -e "${YELLOW}🔍 Verificando runtime_version...${NC}"
python3 -c "
try:
    from google.protobuf import runtime_version
    print('✅ runtime_version disponible')
except ImportError:
    print('❌ runtime_version NO disponible')
    print('   Esto puede indicar una versión de protobuf < 5.x')
" 2>/dev/null

echo

# Opciones de versiones compatibles
echo -e "${YELLOW}📋 Opciones de arreglo:${NC}"
echo "1. Actualizar a protobuf 5.x+ (recomendado para nuevos proyectos)"
echo "2. Mantener protobuf 3.x (compatible con código existente)"
echo "3. Regenerar con versión específica"
echo "4. Solo verificar sin cambios"
echo

read -p "Selecciona una opción (1-4): " -n 1 -r OPTION
echo
echo

case $OPTION in
    1)
        echo -e "${YELLOW}🔄 Actualizando a protobuf 5.x+...${NC}"
        pip install --upgrade protobuf
        NEW_VERSION=$(python3 -c "import google.protobuf; print(google.protobuf.__version__)")
        echo -e "${GREEN}✅ Protobuf actualizado a: ${NEW_VERSION}${NC}"
        ;;
    2)
        echo -e "${YELLOW}🔄 Instalando protobuf 3.20.x (compatible)...${NC}"
        pip install "protobuf>=3.20.0,<4.0.0"
        NEW_VERSION=$(python3 -c "import google.protobuf; print(google.protobuf.__version__)")
        echo -e "${GREEN}✅ Protobuf instalado: ${NEW_VERSION}${NC}"
        ;;
    3)
        echo -e "${YELLOW}🔄 Versión específica...${NC}"
        echo "Versiones recomendadas:"
        echo "  - 3.20.3 (estable, sin runtime_version)"
        echo "  - 4.25.x (transición)"
        echo "  - 5.27.x (moderna con runtime_version)"
        echo
        read -p "Especifica la versión (ej: 3.20.3): " SPECIFIC_VERSION
        if [[ ! -z "$SPECIFIC_VERSION" ]]; then
            pip install protobuf==${SPECIFIC_VERSION}
            NEW_VERSION=$(python3 -c "import google.protobuf; print(google.protobuf.__version__)")
            echo -e "${GREEN}✅ Protobuf instalado: ${NEW_VERSION}${NC}"
        fi
        ;;
    4)
        echo -e "${YELLOW}ℹ️  Solo verificando, sin cambios...${NC}"
        ;;
    *)
        echo -e "${RED}❌ Opción inválida${NC}"
        exit 1
        ;;
esac

echo

# Verificar protoc (compilador)
echo -e "${YELLOW}🔍 Verificando protoc (compilador)...${NC}"
if command -v protoc &> /dev/null; then
    PROTOC_VERSION=$(protoc --version)
    echo -e "${GREEN}✅ ${PROTOC_VERSION}${NC}"
else
    echo -e "${RED}❌ protoc no está instalado${NC}"
    echo -e "${YELLOW}💡 Instalando protoc...${NC}"

    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install protobuf
        else
            echo -e "${RED}❌ Homebrew no está disponible. Instala protoc manualmente.${NC}"
            exit 1
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y protobuf-compiler
        elif command -v yum &> /dev/null; then
            sudo yum install -y protobuf-compiler
        else
            echo -e "${RED}❌ Gestor de paquetes no soportado. Instala protoc manualmente.${NC}"
            exit 1
        fi
    else
        echo -e "${RED}❌ Sistema operativo no soportado.${NC}"
        exit 1
    fi

    # Verificar instalación
    if command -v protoc &> /dev/null; then
        PROTOC_VERSION=$(protoc --version)
        echo -e "${GREEN}✅ protoc instalado: ${PROTOC_VERSION}${NC}"
    else
        echo -e "${RED}❌ Error instalando protoc${NC}"
        exit 1
    fi
fi

echo

# Verificar compatibilidad final
echo -e "${YELLOW}🧪 Verificando compatibilidad final...${NC}"
python3 -c "
import sys

def verify_protobuf():
    try:
        import google.protobuf
        version = google.protobuf.__version__
        print(f'✅ Protobuf runtime: {version}')

        # Verificar componentes principales
        from google.protobuf import message
        from google.protobuf import timestamp_pb2
        print('✅ Componentes principales disponibles')

        # Verificar runtime_version (opcional)
        try:
            from google.protobuf import runtime_version
            print('✅ runtime_version disponible')
        except ImportError:
            print('ℹ️  runtime_version no disponible (normal en 3.x)')

        # Crear un mensaje de prueba
        ts = timestamp_pb2.Timestamp()
        ts.GetCurrentTime()
        print('✅ Funcionalidad básica funciona')

        print()
        print('🎉 Protobuf está funcionando correctamente')
        return True

    except Exception as e:
        print(f'❌ Error verificando protobuf: {e}')
        import traceback
        traceback.print_exc()
        return False

if not verify_protobuf():
    sys.exit(1)
"

if [ $? -eq 0 ]; then
    echo
    echo -e "${GREEN}🎉 ¡Dependencias de protobuf arregladas correctamente!${NC}"
    echo
    echo -e "${YELLOW}📋 Próximos pasos:${NC}"
    echo "1. Ejecuta el script de regeneración: ./regenerate_protobuf.sh"
    echo "2. Prueba el sniffer nuevamente"
    echo
else
    echo -e "${RED}❌ Hay problemas con la instalación de protobuf${NC}"
    echo -e "${YELLOW}💡 Considera reinstalar completamente protobuf:${NC}"
    echo "   pip uninstall protobuf"
    echo "   pip install protobuf==3.20.3"
    exit 1
fi