#!/bin/bash
# fix_sniffer_imports.sh
# Script para arreglar las importaciones en evolutionary_sniffer_standalone.py

set -e

echo "🔧 Arreglando importaciones en evolutionary_sniffer_standalone.py..."

# Archivo a modificar
SNIFFER_FILE="core/evolutionary_sniffer_standalone.py"

if [ ! -f "$SNIFFER_FILE" ]; then
    echo "❌ Error: No se encontró $SNIFFER_FILE"
    exit 1
fi

# Crear backup
cp "$SNIFFER_FILE" "${SNIFFER_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
echo "💾 Backup creado: ${SNIFFER_FILE}.backup.*"

# Arreglar las rutas v3.1 → v3_1
echo "🔄 Actualizando rutas de v3.1 a v3_1..."
sed -i.tmp 's/protocols\/v3\.1/protocols\/v3_1/g' "$SNIFFER_FILE"

# Limpiar archivo temporal
rm -f "${SNIFFER_FILE}.tmp"

echo "✅ Rutas actualizadas"

# Verificar cambios
echo "🔍 Verificando cambios realizados..."
if grep -q "protocols/v3\.1" "$SNIFFER_FILE"; then
    echo "⚠️  Algunas referencias a v3.1 aún permanecen:"
    grep -n "protocols/v3\.1" "$SNIFFER_FILE"
else
    echo "✅ Todas las referencias v3.1 fueron actualizadas"
fi

# Mostrar las nuevas referencias
echo "📋 Referencias v3_1 encontradas:"
grep -n "protocols/v3_1" "$SNIFFER_FILE" || echo "Ninguna encontrada"

echo
echo "🧪 Probando importaciones después del arreglo..."

# Probar la función de importación manualmente
python3 -c "
import sys
import os
sys.path.insert(0, '.')

# Setup environment como lo hace el sniffer
os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

# Variables globales como en el sniffer
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = 'unavailable'
NetworkSecurityEventProto = None

def import_protobuf_module():
    '''Importa el módulo protobuf v3.1.0 con múltiples estrategias'''
    global NetworkSecurityEventProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    # Estrategia 1: Importación relativa desde protocols.v3_1
    import_strategies = [
        ('protocols.v3_1.network_security_clean_v31_pb2', 'Paquete protocols.v3_1'),
        ('protocols.network_security_clean_v31_pb2', 'Paquete protocols'),
        ('network_security_clean_v31_pb2', 'Importación directa'),
    ]

    for import_path, description in import_strategies:
        try:
            NetworkSecurityEventProto = __import__(import_path, fromlist=[''])
            PROTOBUF_AVAILABLE = True
            PROTOBUF_VERSION = 'v3.1.0'
            print(f'✅ Protobuf v3.1 cargado: {description} ({import_path})')
            return True
        except ImportError as e:
            print(f'  ↳ Falló {import_path}: {e}')
            continue

    # Estrategia 2: Añadir path dinámico y importar
    current_dir = os.path.dirname(os.path.abspath('.'))
    possible_paths = [
        os.path.join(current_dir, 'protocols', 'v3_1'),  # Actualizado de v3.1 a v3_1
        os.path.join(os.getcwd(), 'protocols', 'v3_1'),   # Actualizado de v3.1 a v3_1
    ]

    for protocols_path in possible_paths:
        protocols_path = os.path.abspath(protocols_path)
        pb2_file = os.path.join(protocols_path, 'network_security_clean_v31_pb2.py')

        if os.path.exists(pb2_file):
            try:
                sys.path.insert(0, protocols_path)
                import network_security_clean_v31_pb2 as NetworkSecurityEventProto
                PROTOBUF_AVAILABLE = True
                PROTOBUF_VERSION = 'v3.1.0'
                print(f'✅ Protobuf v3.1 cargado desde path: {protocols_path}')
                return True
            except ImportError as e:
                if protocols_path in sys.path:
                    sys.path.remove(protocols_path)
                print(f'  ↳ Falló desde {protocols_path}: {e}')
                continue

    return False

# Ejecutar test
print('🧪 Probando función import_protobuf_module()...')
result = import_protobuf_module()
print()
print(f'📊 Resultado: {\"✅ ÉXITO\" if result else \"❌ FALLÓ\"}')
print(f'   PROTOBUF_AVAILABLE: {PROTOBUF_AVAILABLE}')
print(f'   PROTOBUF_VERSION: {PROTOBUF_VERSION}')
print(f'   NetworkSecurityEventProto: {\"✅ Cargado\" if NetworkSecurityEventProto else \"❌ None\"}')

if result:
    print()
    print('🎉 ¡La función de importación funciona correctamente!')
    print('   El sniffer debería funcionar ahora.')
else:
    print()
    print('❌ La función de importación aún falla.')
    print('   Necesita más debugging.')
    sys.exit(1)
"

if [ $? -eq 0 ]; then
    echo
    echo "🎉 ¡Arreglo completado exitosamente!"
    echo
    echo "📋 Próximo paso: Probar el sniffer"
    echo "sudo -E python3 core/evolutionary_sniffer_standalone.py config/json/evolutionary_sniffer_config_v31_etcd.json"
else
    echo "❌ Aún hay problemas con las importaciones"
    exit 1
fi