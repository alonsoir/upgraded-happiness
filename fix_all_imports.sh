#!/bin/bash
# Script para arreglar todas las referencias de protocols.v3.1 → protocols.v3_1

set -e

echo "🔧 Arreglando todas las referencias de protobuf v3.1..."
echo

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Directorio del proyecto
PROJECT_DIR="$(pwd)"
echo -e "${YELLOW}📁 Directorio del proyecto: ${PROJECT_DIR}${NC}"

# Verificar que estamos en el directorio correcto
if [ ! -d "protocols/v3_1" ]; then
    echo "❌ Error: No se encontró protocols/v3_1"
    echo "   ¿Renombraste correctamente el directorio?"
    exit 1
fi

echo -e "${YELLOW}📋 Archivos que necesitan actualización:${NC}"
FILES_TO_UPDATE=$(grep -r "protocols\.v3\.1" . --include="*.py" -l | sort)

if [ -z "$FILES_TO_UPDATE" ]; then
    echo "✅ No se encontraron archivos para actualizar"
else
    echo "$FILES_TO_UPDATE"
    echo

    echo -e "${YELLOW}🔄 Actualizando archivos...${NC}"

    # Actualizar cada archivo
    while IFS= read -r file; do
        if [ -f "$file" ]; then
            echo "   🔧 Actualizando: $file"

            # Crear backup
            cp "$file" "${file}.backup.$(date +%Y%m%d_%H%M%S)"

            # Realizar los cambios
            sed -i.tmp 's/protocols\.v3\.1/protocols.v3_1/g' "$file"

            # Limpiar archivo temporal
            rm -f "${file}.tmp"
        fi
    done <<< "$FILES_TO_UPDATE"
fi

echo
echo -e "${YELLOW}📋 Verificando cambios...${NC}"

# Contar referencias antiguas restantes
OLD_REFS=$(grep -r "protocols\.v3\.1" . --include="*.py" | wc -l | tr -d ' ')
NEW_REFS=$(grep -r "protocols\.v3_1" . --include="*.py" | wc -l | tr -d ' ')

echo "   Referencias antiguas (protocols.v3.1): $OLD_REFS"
echo "   Referencias nuevas (protocols.v3_1): $NEW_REFS"

if [ "$OLD_REFS" -eq 0 ]; then
    echo -e "${GREEN}✅ Todas las referencias actualizadas correctamente${NC}"
else
    echo "⚠️  Algunas referencias antiguas permanecen:"
    grep -r "protocols\.v3\.1" . --include="*.py"
fi

echo
echo -e "${YELLOW}🧪 Probando importaciones actualizadas...${NC}"

# Probar importación
python3 -c "
import sys
sys.path.insert(0, '.')

print('🧪 Probando importaciones...')

try:
    from protocols.v3_1 import network_security_clean_v31_pb2
    print('✅ network_security_clean_v31_pb2 importado')

    from protocols.v3_1 import firewall_commands_v31_pb2
    print('✅ firewall_commands_v31_pb2 importado')

    # Probar crear instancias
    event = network_security_clean_v31_pb2.NetworkSecurityEvent()
    event.event_id = 'test_fixed_imports'
    print('✅ NetworkSecurityEvent instanciado')

    cmd = firewall_commands_v31_pb2.FirewallCommand()
    print('✅ FirewallCommand instanciado')

    print('🎉 ¡Todas las importaciones funcionan!')

except Exception as e:
    print(f'❌ Error en importaciones: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"

if [ $? -eq 0 ]; then
    echo
    echo -e "${GREEN}🎉 ¡Arreglo completado exitosamente!${NC}"
    echo
    echo -e "${BLUE}📋 Próximos pasos:${NC}"
    echo "1. Probar el sniffer:"
    echo "   sudo -E python3 core/evolutionary_sniffer_standalone.py config/json/evolutionary_sniffer_config_v31_etcd.json"
    echo
    echo "2. Si hay otros errores, probablemente sean de configuración de ETCD o red"
    echo "   (no relacionados con protobuf)"
    echo
    echo -e "${GREEN}✅ El problema de protobuf está RESUELTO${NC}"
else
    echo -e "❌ Aún hay problemas con las importaciones"
    exit 1
fi