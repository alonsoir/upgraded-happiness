#!/bin/bash

# 🧹 LIMPIEZA MASIVA DE IMPORTACIONES PROTOBUF V3.1
# Fecha: 22 agosto 2025
# Objetivo: SIMPLIFICAR todas las importaciones a solo v3.1

echo "🚀 INICIANDO LIMPIEZA MASIVA DE PROTOBUF..."

# Lista de archivos a procesar
FILES=(
    "core/dashboard_v31.py"
    "core/etcd_crypto_client_ml_detector_fixed.py"
    "core/etcd_crypto_client_scheduler_firewall_fixed.py"
    "core/etcd_crypto_client_simple_firewall_agent_fixed.py"
    "core/evolutionary_sniffer_standalone.py"
    "core/evolutionary_sniffer_v31.py"
    "core/evolutionary_sniffer_v31_etcd.py"
    "core/evolutionary_sniffer_v31_etcd_fixed.py"
    "core/geoip_enricher.py"
    "core/geoip_enricher_v31.py"
    "core/geoip_enricher_v31_etcd.py"
    "core/lightweight_ml_detector.py"
    "core/lightweight_ml_detector_tricapa_v31.py"
    "core/lightweight_ml_detector_tricapa_v31_etcd.py"
    "core/promiscuous_agent.py"
    "core/promiscuous_agent_v2.py"
    "core/real_zmq_dashboard_with_firewall.py"
    "core/scheduler-firewall.py"
    "core/scheduler-simple-consumer.py"
    "core/scheduler_firewall_v31_etcd.py"
    "core/simple_firewall_agent.py"
    "core/simple_firewall_agent_v31.py"
    "core/simple_firewall_agent_v31_etcd.py"
    "core/test_evolutionary_sniffer_v31.py"
)

# 🔍 PASO 1: Hacer backup
echo "📦 Creando backups..."
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        cp "$file" "$file.backup_$(date +%Y%m%d_%H%M%S)"
        echo "   ✅ Backup: $file"
    fi
done

# 🔧 PASO 2: Arreglar la línea crítica NetworkEvent()
echo "🎯 Arreglando NetworkEvent() -> NetworkSecurityEvent()..."
sed -i.tmp 's/NetworkEvent()/NetworkSecurityEvent()/g' core/scheduler_firewall_v31_etcd.py
echo "   ✅ scheduler_firewall_v31_etcd.py arreglado"

# 🧹 PASO 3: Simplificar importaciones complejas
echo "🧹 Simplificando importaciones complejas..."

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "   🔄 Procesando: $file"

        # Reemplazar importaciones complejas con try/except por importación directa
        # Buscar patrones como: from protocols.current import ...
        sed -i.tmp 's|from protocols\.current import|from protocols.v3_1 import|g' "$file"

        # Buscar patrones como: import protocols.current
        sed -i.tmp 's|import protocols\.current|import protocols.v3_1|g' "$file"

        # Reemplazar referencias a network_event_extended_v3_pb2 por network_security_clean_v31_pb2
        sed -i.tmp 's|network_event_extended_v3_pb2|network_security_clean_v31_pb2|g' "$file"

        # Reemplazar import dinámicos problemáticos
        sed -i.tmp 's|__import__(import_path, fromlist=\[\x27\x27\])|network_security_clean_v31_pb2|g' "$file"

        echo "   ✅ $file procesado"
    fi
done

# 🧽 PASO 4: Limpiar archivos temporales
echo "🧽 Limpiando archivos temporales..."
find core/ -name "*.tmp" -delete

# 🔍 PASO 5: Verificar resultados
echo "🔍 Verificando cambios..."
echo "   Archivos que aún mencionan 'current':"
grep -r "protocols.*current" core/ --include="*.py" | wc -l

echo "   Archivos que mencionan 'v3_1':"
grep -r "protocols.*v3_1" core/ --include="*.py" | wc -l

echo ""
echo "✅ LIMPIEZA COMPLETADA"
echo "📋 SIGUIENTE PASO: Revisar manualmente y recompilar protobuf"
echo ""
echo "🔧 Para recompilar protobuf:"
echo "   cd protocols/v3_1/"
echo "   protoc --python_out=. network_security_clean_v3.1.proto"
echo ""
echo "🚀 Para probar:"
echo "   python core/scheduler_firewall_v31_etcd.py config/json/scheduler_firewall_etcd_config_dev.json config/json/firewall_rules_v31.json"