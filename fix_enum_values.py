#!/usr/bin/env python3

import re

# Leer el archivo del sniffer
with open('core/evolutionary_sniffer_standalone.py', 'r') as f:
    content = f.read()

print("🔧 Arreglando valores de enum con nombres legibles...")

# Hacer backup
with open('core/evolutionary_sniffer_standalone.py.backup_enum_fix', 'w') as f:
    f.write(content)

# Reemplazos usando los valores de enum apropiados
# En el código usa NetworkSecurityEventProto como variable global
replacements = [
    # NodeRole enum
    ('node_role = "PACKET_SNIFFER"', 
     'node_role = NetworkSecurityEventProto.DistributedNode.NodeRole.PACKET_SNIFFER'),
    ('node_role = "FEATURE_PROCESSOR"', 
     'node_role = NetworkSecurityEventProto.DistributedNode.NodeRole.FEATURE_PROCESSOR'),
    ('node_role = "GEOIP_ENRICHER"', 
     'node_role = NetworkSecurityEventProto.DistributedNode.NodeRole.GEOIP_ENRICHER'),
    ('node_role = "ML_ANALYZER"', 
     'node_role = NetworkSecurityEventProto.DistributedNode.NodeRole.ML_ANALYZER'),
    ('node_role = "THREAT_DETECTOR"', 
     'node_role = NetworkSecurityEventProto.DistributedNode.NodeRole.THREAT_DETECTOR'),
    ('node_role = "FIREWALL_CONTROLLER"', 
     'node_role = NetworkSecurityEventProto.DistributedNode.NodeRole.FIREWALL_CONTROLLER'),
    ('node_role = "DATA_AGGREGATOR"', 
     'node_role = NetworkSecurityEventProto.DistributedNode.NodeRole.DATA_AGGREGATOR'),
    ('node_role = "DASHBOARD_VISUALIZER"', 
     'node_role = NetworkSecurityEventProto.DistributedNode.NodeRole.DASHBOARD_VISUALIZER'),
    ('node_role = "CLUSTER_COORDINATOR"', 
     'node_role = NetworkSecurityEventProto.DistributedNode.NodeRole.CLUSTER_COORDINATOR'),
     
    # NodeStatus enum
    ('node_status = "ACTIVE"', 
     'node_status = NetworkSecurityEventProto.DistributedNode.NodeStatus.ACTIVE'),
    ('node_status = "STARTING"', 
     'node_status = NetworkSecurityEventProto.DistributedNode.NodeStatus.STARTING'),
    ('node_status = "STOPPING"', 
     'node_status = NetworkSecurityEventProto.DistributedNode.NodeStatus.STOPPING'),
    ('node_status = "ERROR"', 
     'node_status = NetworkSecurityEventProto.DistributedNode.NodeStatus.ERROR'),
    ('node_status = "MAINTENANCE"', 
     'node_status = NetworkSecurityEventProto.DistributedNode.NodeStatus.MAINTENANCE'),
    ('node_status = "OVERLOADED"', 
     'node_status = NetworkSecurityEventProto.DistributedNode.NodeStatus.OVERLOADED'),
]

# Aplicar reemplazos
original_content = content
changes_made = 0

for old, new in replacements:
    if old in content:
        content = content.replace(old, new)
        print(f"✅ Reemplazado: {old}")
        print(f"    → {new}")
        changes_made += 1

# Escribir el archivo arreglado
if content != original_content:
    with open('core/evolutionary_sniffer_standalone.py', 'w') as f:
        f.write(content)
    print(f"\n✅ Archivo actualizado con {changes_made} cambios de enum")
    print("🎯 Valores de enum ahora son legibles y mantenibles!")
else:
    print("⚠️  No se encontraron cambios necesarios")

print("\n🧪 Probando que los enums funcionan...")

# Probar que los cambios son válidos
try:
    from protocols.v3_1 import network_security_clean_v31_pb2 as pb2
    
    # Verificar que los valores son correctos
    print(f"✅ PACKET_SNIFFER = {pb2.DistributedNode.NodeRole.PACKET_SNIFFER}")
    print(f"✅ ACTIVE = {pb2.DistributedNode.NodeStatus.ACTIVE}")
    print(f"✅ STARTING = {pb2.DistributedNode.NodeStatus.STARTING}")
    
    print("🎉 ¡Los enums están configurados correctamente!")
    
except Exception as e:
    print(f"❌ Error probando enums: {e}")
