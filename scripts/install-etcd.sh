#!/bin/bash
# scripts/install-etcd.sh
# Script para instalar etcd en diferentes sistemas

set -e

ETCD_VERSION="v3.5.9"
INSTALL_DIR="/usr/local/bin"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🔧 Instalador de etcd ${ETCD_VERSION}${NC}"
echo ""

# Detectar OS y arquitectura
detect_system() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            echo -e "${RED}❌ Arquitectura no soportada: $ARCH${NC}"
            exit 1
            ;;
    esac

    case $OS in
        linux) OS="linux" ;;
        darwin) OS="darwin" ;;
        *)
            echo -e "${RED}❌ OS no soportado: $OS${NC}"
            exit 1
            ;;
    esac

    echo -e "${GREEN}✅ Sistema detectado: $OS-$ARCH${NC}"
}

# Verificar si etcd ya está instalado
check_existing() {
    if command -v etcd &> /dev/null; then
        CURRENT_VERSION=$(etcd --version | head -n1 | cut -d' ' -f3)
        echo -e "${YELLOW}⚠️  etcd ya está instalado: $CURRENT_VERSION${NC}"
        echo -e "¿Continuar con la instalación? (y/N): "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            echo "Instalación cancelada"
            exit 0
        fi
    fi
}

# Instalar usando package manager
install_with_package_manager() {
    case $OS in
        "darwin")
            if command -v brew &> /dev/null; then
                echo -e "${BLUE}📦 Instalando con Homebrew...${NC}"
                brew install etcd
                return 0
            fi
            ;;
        "linux")
            if command -v apt-get &> /dev/null; then
                echo -e "${BLUE}📦 Instalando con apt...${NC}"
                sudo apt-get update
                sudo apt-get install -y etcd-server etcd-client
                return 0
            elif command -v yum &> /dev/null; then
                echo -e "${BLUE}📦 Instalando con yum...${NC}"
                sudo yum install -y etcd
                return 0
            elif command -v dnf &> /dev/null; then
                echo -e "${BLUE}📦 Instalando with dnf...${NC}"
                sudo dnf install -y etcd
                return 0
            fi
            ;;
    esac
    return 1
}

# Instalar desde binarios
install_from_binary() {
    echo -e "${BLUE}📥 Descargando etcd desde GitHub...${NC}"

    DOWNLOAD_URL="https://github.com/etcd-io/etcd/releases/download/${ETCD_VERSION}/etcd-${ETCD_VERSION}-${OS}-${ARCH}.tar.gz"
    TEMP_DIR=$(mktemp -d)

    echo "📍 URL: $DOWNLOAD_URL"
    echo "📁 Temp dir: $TEMP_DIR"

    # Descargar
    echo -e "${BLUE}⬇️  Descargando...${NC}"
    curl -L "$DOWNLOAD_URL" -o "$TEMP_DIR/etcd.tar.gz"

    # Extraer
    echo -e "${BLUE}📦 Extrayendo...${NC}"
    cd "$TEMP_DIR"
    tar -xzf etcd.tar.gz

    # Instalar
    echo -e "${BLUE}📋 Instalando en $INSTALL_DIR...${NC}"
    EXTRACTED_DIR="etcd-${ETCD_VERSION}-${OS}-${ARCH}"

    if [ ! -d "$EXTRACTED_DIR" ]; then
        echo -e "${RED}❌ Error: directorio extraído no encontrado${NC}"
        ls -la
        exit 1
    fi

    # Verificar permisos
    if [ ! -w "$INSTALL_DIR" ]; then
        echo -e "${YELLOW}🔐 Se requieren permisos de administrador para instalar en $INSTALL_DIR${NC}"
        sudo cp "$EXTRACTED_DIR/etcd" "$EXTRACTED_DIR/etcdctl" "$INSTALL_DIR/"
        sudo chmod +x "$INSTALL_DIR/etcd" "$INSTALL_DIR/etcdctl"
    else
        cp "$EXTRACTED_DIR/etcd" "$EXTRACTED_DIR/etcdctl" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/etcd" "$INSTALL_DIR/etcdctl"
    fi

    # Limpiar
    rm -rf "$TEMP_DIR"

    echo -e "${GREEN}✅ Instalación desde binarios completada${NC}"
}

# Verificar instalación
verify_installation() {
    echo -e "${BLUE}🔍 Verificando instalación...${NC}"

    if command -v etcd &> /dev/null && command -v etcdctl &> /dev/null; then
        echo -e "${GREEN}✅ etcd instalado correctamente${NC}"
        echo ""
        echo "📋 Información de la instalación:"
        echo "   $(etcd --version | head -n1)"
        echo "   $(etcdctl version | head -n1)"
        echo "   Ubicación etcd: $(which etcd)"
        echo "   Ubicación etcdctl: $(which etcdctl)"
        echo ""
        echo -e "${GREEN}🎯 ¡Listo para usar!${NC}"
        echo ""
        echo "Próximos pasos:"
        echo "  make setup     # Configurar estructura"
        echo "  make start     # Iniciar etcd"
        echo "  make test      # Probar service discovery"
    else
        echo -e "${RED}❌ Error en la instalación${NC}"
        exit 1
    fi
}

# Mostrar ayuda
show_help() {
    echo "Uso: $0 [opciones]"
    echo ""
    echo "Opciones:"
    echo "  --binary         Forzar instalación desde binarios"
    echo "  --package        Forzar instalación con package manager"
    echo "  --version VER    Especificar versión (default: $ETCD_VERSION)"
    echo "  --install-dir DIR Directorio de instalación (default: $INSTALL_DIR)"
    echo "  --help           Mostrar esta ayuda"
    echo ""
    echo "Ejemplos:"
    echo "  $0                           # Instalación automática"
    echo "  $0 --binary                  # Forzar desde binarios"
    echo "  $0 --version v3.5.8          # Versión específica"
    echo "  $0 --install-dir ~/bin       # Directorio personalizado"
}

# Procesar argumentos
FORCE_BINARY=false
FORCE_PACKAGE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --binary)
            FORCE_BINARY=true
            shift
            ;;
        --package)
            FORCE_PACKAGE=true
            shift
            ;;
        --version)
            ETCD_VERSION="$2"
            shift 2
            ;;
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Opción desconocida: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Main
main() {
    detect_system
    check_existing

    echo ""

    # Intentar instalación
    if [ "$FORCE_BINARY" = true ]; then
        install_from_binary
    elif [ "$FORCE_PACKAGE" = true ]; then
        if ! install_with_package_manager; then
            echo -e "${RED}❌ No se pudo instalar con package manager${NC}"
            exit 1
        fi
    else
        # Intentar package manager primero, luego binarios
        if ! install_with_package_manager; then
            echo -e "${YELLOW}⚠️  Package manager no disponible, usando binarios...${NC}"
            install_from_binary
        fi
    fi

    verify_installation
}

# Ejecutar main
main "$@"