#!/bin/bash

# 🔧 ARREGLO RÁPIDO PROTOBUF PARA SNIFFER ETCD

echo "🔧 Arreglando importación protobuf en evolutionary_sniffer_v31_etcd.py..."

# 1. Reemplazar import de protobuf problemático (línea 43)
sed -i.protobuf_bak 's|from protocols.v3_1 import network_security_clean_v31_pb2|# from protocols.v3_1 import network_security_clean_v31_pb2|' core/evolutionary_sniffer_v31_etcd.py

# 2. Simplificar función import_protobuf_v31() para usar path directo
# Buscar línea donde empieza la función y reemplazar todo el bloque

cat > /tmp/simple_import_function.py << 'EOF'
def import_protobuf_v31():
    """Importa el protobuf v3.1 limpio - VERSIÓN SIMPLIFICADA"""
    global NetworkSecurityEventProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    # Agregar path directo al sys.path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)  # Subir un nivel desde core/
    protocols_path = os.path.join(project_root, 'protocols', 'v3_1')

    if protocols_path not in sys.path:
        sys.path.insert(0, protocols_path)

    try:
        # Importación directa desde path agregado
        import network_security_clean_v31_pb2

        NetworkSecurityEventProto = network_security_clean_v31_pb2
        PROTOBUF_AVAILABLE = True
        PROTOBUF_VERSION = "v3.1.0-clean"
        print(f"✅ Protobuf v3.1 LIMPIO cargado desde path directo: {protocols_path}")
        return True

    except ImportError as e:
        print(f"❌ Error importando protobuf v3.1: {e}")
        print(f"🔧 Path intentado: {protocols_path}")
        print("🔧 Recompila: cd protocols/v3_1 && protoc --python_out=. network_security_clean_v31.proto")

        # En modo dev, continuar sin protobuf
        if os.environ.get("UPGRADED_HAPPINESS_DEV_MODE") == "true":
            PROTOBUF_AVAILABLE = False
            PROTOBUF_VERSION = "unavailable"
            NetworkSecurityEventProto = None
            print("🧪 Modo dev: Continuando sin protobuf")
            return False
        else:
            raise RuntimeError("❌ Protobuf v3.1 requerido")

    return False
EOF

echo "📝 Función simplificada creada en /tmp/simple_import_function.py"

# 3. Mostrar las líneas que necesitan cambio manual
echo ""
echo "🎯 ARREGLO MANUAL NECESARIO:"
echo "   Edita core/evolutionary_sniffer_v31_etcd.py"
echo "   Busca la función import_protobuf_v31() (aprox línea 60-120)"
echo "   Reemplázala con el contenido de /tmp/simple_import_function.py"
echo ""
echo "🔍 Para encontrarla:"
echo "   grep -n 'def import_protobuf_v31' core/evolutionary_sniffer_v31_etcd.py"
echo ""
echo "🚀 Después del arreglo:"
echo "   sudo python core/evolutionary_sniffer_v31_etcd.py config/json/evolutionary_sniffer_config_v31_etcd.json"