#!/usr/bin/env python3
"""
EXTRACTOR DE FEATURES REQUERIDAS
Analiza los modelos entrenados para determinar exactamente qué features capturar con scapy
"""

import json
import os
from pathlib import Path
import pandas as pd


def load_model_metadata(model_path):
    """Carga metadatos de un modelo"""
    metadata_path = model_path.replace('.joblib', '_metadata.json')

    if os.path.exists(metadata_path):
        with open(metadata_path, 'r') as f:
            return json.load(f)
    else:
        print(f"⚠️ No se encontró metadata para {model_path}")
        return None


def analyze_feature_requirements():
    """Analiza los requirements de features de todos los modelos"""

    print(f"🔍 ANÁLISIS DE FEATURES REQUERIDAS PARA SCAPY")
    print("=" * 80)

    models = {
        'attack_detector': {
            'path': 'models/rf_production_final.joblib',
            'name': 'Detector de Ataques',
            'priority': 1
        },
        'web_detector': {
            'path': 'models/web_normal_detector.joblib',
            'name': 'Detector Web Normal',
            'priority': 2
        },
        'internal_detector': {
            'path': 'models/internal_normal_detector.joblib',
            'name': 'Detector Interno Normal',
            'priority': 3
        }
    }

    all_features = set()
    model_features = {}

    # Analizar cada modelo
    for model_key, model_info in models.items():
        print(f"\n📊 {model_info['name']}")
        print("-" * 50)

        metadata = load_model_metadata(model_info['path'])

        if metadata and 'feature_names' in metadata:
            features = metadata['feature_names']
            model_features[model_key] = {
                'features': features,
                'count': len(features),
                'name': model_info['name'],
                'priority': model_info['priority']
            }

            print(f"📋 Features requeridas: {len(features)}")
            for i, feature in enumerate(features, 1):
                print(f"   {i:2d}. {feature}")

            all_features.update(features)
        else:
            print(f"❌ No se pudieron cargar las features")
            model_features[model_key] = {
                'features': [],
                'count': 0,
                'name': model_info['name'],
                'priority': model_info['priority']
            }

    # Features consolidadas
    print(f"\n🎯 RESUMEN DE FEATURES CONSOLIDADAS")
    print("=" * 60)
    print(f"📊 Total de features únicas requeridas: {len(all_features)}")

    # Analizar overlaps
    feature_usage = {}
    for feature in all_features:
        usage = []
        for model_key, info in model_features.items():
            if feature in info['features']:
                usage.append(info['name'])
        feature_usage[feature] = usage

    # Clasificar features por importancia
    critical_features = [f for f, usage in feature_usage.items() if len(usage) >= 2]
    model_specific = [f for f, usage in feature_usage.items() if len(usage) == 1]

    print(f"\n🔴 FEATURES CRÍTICAS (usadas por múltiples modelos): {len(critical_features)}")
    for feature in sorted(critical_features):
        models_using = ", ".join(feature_usage[feature])
        print(f"   • {feature} → {models_using}")

    print(f"\n🔵 FEATURES ESPECÍFICAS (un solo modelo): {len(model_specific)}")
    for feature in sorted(model_specific):
        model_using = feature_usage[feature][0]
        print(f"   • {feature} → {model_using}")

    return all_features, feature_usage, model_features


def categorize_features_for_scapy(all_features):
    """Categoriza las features según cómo capturarlas con scapy"""

    print(f"\n🐍 MAPEADO DE FEATURES A SCAPY")
    print("=" * 60)

    # Definir categorías de features
    scapy_mapping = {
        'basic_packet': {
            'description': 'Información básica del paquete',
            'features': [],
            'scapy_fields': []
        },
        'tcp_specific': {
            'description': 'Campos específicos de TCP',
            'features': [],
            'scapy_fields': []
        },
        'flow_statistics': {
            'description': 'Estadísticas de flujo (requieren agregación)',
            'features': [],
            'scapy_fields': []
        },
        'timing': {
            'description': 'Información temporal',
            'features': [],
            'scapy_fields': []
        },
        'categorical': {
            'description': 'Datos categóricos',
            'features': [],
            'scapy_fields': []
        },
        'computed': {
            'description': 'Features computadas/derivadas',
            'features': [],
            'scapy_fields': []
        }
    }

    # Mapear cada feature
    for feature in sorted(all_features):
        feature_lower = feature.lower()

        if feature_lower in ['proto', 'protocol']:
            scapy_mapping['basic_packet']['features'].append(feature)
            scapy_mapping['basic_packet']['scapy_fields'].append('IP.proto')

        elif feature_lower in ['service']:
            scapy_mapping['basic_packet']['features'].append(feature)
            scapy_mapping['basic_packet']['scapy_fields'].append('TCP.dport / UDP.dport')

        elif feature_lower in ['state']:
            scapy_mapping['tcp_specific']['features'].append(feature)
            scapy_mapping['tcp_specific']['scapy_fields'].append('TCP.flags')

        elif feature_lower in ['spkts', 'dpkts']:
            scapy_mapping['flow_statistics']['features'].append(feature)
            scapy_mapping['flow_statistics']['scapy_fields'].append('count packets per direction')

        elif feature_lower in ['sbytes', 'dbytes']:
            scapy_mapping['flow_statistics']['features'].append(feature)
            scapy_mapping['flow_statistics']['scapy_fields'].append('sum(len(packet)) per direction')

        elif feature_lower in ['dur', 'duration']:
            scapy_mapping['timing']['features'].append(feature)
            scapy_mapping['timing']['scapy_fields'].append('last_time - first_time')

        elif feature_lower in ['rate']:
            scapy_mapping['computed']['features'].append(feature)
            scapy_mapping['computed']['scapy_fields'].append('bytes/duration')

        elif feature_lower in ['sttl', 'dttl']:
            scapy_mapping['basic_packet']['features'].append(feature)
            scapy_mapping['basic_packet']['scapy_fields'].append('IP.ttl')

        elif feature_lower in ['sload', 'dload']:
            scapy_mapping['computed']['features'].append(feature)
            scapy_mapping['computed']['scapy_fields'].append('bits_per_second per direction')

        elif feature_lower in ['sloss', 'dloss']:
            scapy_mapping['flow_statistics']['features'].append(feature)
            scapy_mapping['flow_statistics']['scapy_fields'].append('lost/retransmitted packets')

        elif feature_lower in ['sinpkt', 'dinpkt']:
            scapy_mapping['timing']['features'].append(feature)
            scapy_mapping['timing']['scapy_fields'].append('inter-arrival time statistics')

        elif 'ct_' in feature_lower:
            scapy_mapping['flow_statistics']['features'].append(feature)
            scapy_mapping['flow_statistics']['scapy_fields'].append('connection state counters')

        elif feature_lower in ['id']:
            scapy_mapping['basic_packet']['features'].append(feature)
            scapy_mapping['basic_packet']['scapy_fields'].append('IP.id or flow_id')

        else:
            # Features no categorizadas
            scapy_mapping['computed']['features'].append(feature)
            scapy_mapping['computed']['scapy_fields'].append(f'computed from packet data')

    # Mostrar categorización
    for category, info in scapy_mapping.items():
        if info['features']:
            print(f"\n📂 {category.upper().replace('_', ' ')}: {info['description']}")
            for i, (feature, scapy_field) in enumerate(zip(info['features'], info['scapy_fields']), 1):
                print(f"   {i:2d}. {feature:<15} → {scapy_field}")

    return scapy_mapping


def generate_scapy_capture_code(scapy_mapping, model_features):
    """Genera código de captura con scapy"""

    print(f"\n🐍 CÓDIGO DE CAPTURA CON SCAPY")
    print("=" * 60)

    code = '''#!/usr/bin/env python3
"""
CAPTURADOR DE FEATURES PARA MODELOS DE DETECCIÓN
Captura exactamente las features requeridas por los modelos entrenados
"""

from scapy.all import *
import pandas as pd
import numpy as np
from collections import defaultdict
import time
from datetime import datetime

class NetworkFeatureExtractor:
    def __init__(self):
        self.flows = defaultdict(lambda: {
            'packets': [],
            'first_time': None,
            'last_time': None,
            'src_packets': 0,
            'dst_packets': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'protocol': None,
            'service': None,
            'tcp_flags': set(),
            'src_ttl': [],
            'dst_ttl': []
        })

    def get_flow_key(self, packet):
        """Genera clave única para el flujo"""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                proto = 'TCP'
            elif UDP in packet:
                src_port = packet[UDP].sport  
                dst_port = packet[UDP].dport
                proto = 'UDP'
            else:
                src_port = dst_port = 0
                proto = str(packet[IP].proto)

            # Normalizar dirección del flujo
            if (src_ip, src_port) < (dst_ip, dst_port):
                return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
            else:
                return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
        return None

    def is_source_direction(self, packet, flow_key):
        """Determina si el paquete va en dirección source->dest"""
        if IP in packet:
            parts = flow_key.split('-')
            src_info = parts[0].split(':')
            flow_src_ip = src_info[0]
            return packet[IP].src == flow_src_ip
        return True

    def process_packet(self, packet):
        """Procesa un paquete individual"""
        flow_key = self.get_flow_key(packet)
        if not flow_key:
            return

        flow = self.flows[flow_key]
        current_time = time.time()

        # Inicializar tiempos
        if flow['first_time'] is None:
            flow['first_time'] = current_time
        flow['last_time'] = current_time

        # Agregar paquete
        flow['packets'].append(packet)

        # Determinar dirección
        is_source = self.is_source_direction(packet, flow_key)
        packet_size = len(packet)

        if is_source:
            flow['src_packets'] += 1
            flow['src_bytes'] += packet_size
        else:
            flow['dst_packets'] += 1  
            flow['dst_bytes'] += packet_size

        # Extraer información del protocolo
        if IP in packet:
            flow['protocol'] = packet[IP].proto

            if is_source:
                flow['src_ttl'].append(packet[IP].ttl)
            else:
                flow['dst_ttl'].append(packet[IP].ttl)

        # Información TCP
        if TCP in packet:
            flow['tcp_flags'].add(packet[TCP].flags)
            if not flow['service']:
                # Usar puerto de destino como servicio
                flow['service'] = packet[TCP].dport
        elif UDP in packet:
            if not flow['service']:
                flow['service'] = packet[UDP].dport

    def extract_features(self, flow_key):
        """Extrae features de un flujo para los modelos"""
        flow = self.flows[flow_key]

        # Calcular duración
        duration = flow['last_time'] - flow['first_time'] if flow['last_time'] != flow['first_time'] else 0.001

        # Features básicas'''

    # Agregar features específicas basadas en los modelos
    critical_features = []
    for model_key, info in model_features.items():
        critical_features.extend(info['features'])

    unique_features = sorted(set(critical_features))

    code += f'''

        features = {{}}

        # FEATURES REQUERIDAS POR LOS MODELOS:
        # {', '.join(unique_features)}

        # Basic packet features
        features['proto'] = flow['protocol'] or 0
        features['service'] = flow['service'] or 0

        # Flow statistics  
        features['spkts'] = flow['src_packets']
        features['dpkts'] = flow['dst_packets'] 
        features['sbytes'] = flow['src_bytes']
        features['dbytes'] = flow['dst_bytes']

        # Timing features
        features['dur'] = duration
        features['rate'] = (flow['src_bytes'] + flow['dst_bytes']) / duration if duration > 0 else 0

        # Load features (bits per second)
        features['sload'] = (flow['src_bytes'] * 8) / duration if duration > 0 else 0
        features['dload'] = (flow['dst_bytes'] * 8) / duration if duration > 0 else 0

        # TTL features
        features['sttl'] = np.mean(flow['src_ttl']) if flow['src_ttl'] else 0
        features['dttl'] = np.mean(flow['dst_ttl']) if flow['dst_ttl'] else 0

        # TCP state (simplified)
        if flow['tcp_flags']:
            # Convert TCP flags to state representation
            flags = list(flow['tcp_flags'])
            if 2 in flags and 16 in flags:  # SYN + ACK
                features['state'] = 'CON'
            elif 1 in flags:  # FIN
                features['state'] = 'FIN'  
            elif 4 in flags:  # RST
                features['state'] = 'RST'
            else:
                features['state'] = 'INT'
        else:
            features['state'] = 'INT'

        # Loss features (simplified - actual loss detection requires sequence analysis)
        features['sloss'] = 0  # Would need TCP sequence analysis
        features['dloss'] = 0

        # Inter-packet timing (simplified)
        if len(flow['packets']) > 1:
            times = [pkt.time for pkt in flow['packets'] if hasattr(pkt, 'time')]
            if len(times) > 1:
                intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
                features['sinpkt'] = np.mean(intervals) * 1000  # ms
                features['dinpkt'] = np.mean(intervals) * 1000  # ms  
            else:
                features['sinpkt'] = 0
                features['dinpkt'] = 0
        else:
            features['sinpkt'] = 0
            features['dinpkt'] = 0

        # Additional computed features
        features['id'] = hash(flow_key) % 100000  # Simple flow ID

        return features

    def capture_and_extract(self, interface="en0", timeout=60):
        """Captura paquetes y extrae features"""
        print(f"🔍 Iniciando captura en en0 por 60 segundos...")

        def packet_handler(packet):
            self.process_packet(packet)

        # Capturar paquetes
        sniff(iface=interface, prn=packet_handler, timeout=timeout, store=False)


        # Extraer features de todos los flujos
        features_list = []
        for flow_key in self.flows.keys():
            features = self.extract_features(flow_key)
            features['flow_id'] = flow_key
            features_list.append(features)

        return pd.DataFrame(features_list)

# Ejemplo de uso
if __name__ == "__main__":
    extractor = NetworkFeatureExtractor()

    # Capturar por 30 segundos
    df = extractor.capture_and_extract(timeout=30)

    print(f"📋 Features capturadas:")
    print(df.head())

    # Guardar para usar con los modelos
    df.to_csv('captured_features.csv', index=False)
    print(f"💾 Features guardadas en captured_features.csv")
'''

    return code


def create_feature_requirements_summary(all_features, model_features):
    """Crea resumen definitivo de requirements"""

    summary = f"""# 📋 FEATURES REQUERIDAS PARA MODELOS DE DETECCIÓN

## 🎯 RESUMEN EJECUTIVO

**Total de features únicas requeridas: {len(all_features)}**

### Modelos del Sistema:
"""

    for model_key, info in model_features.items():
        summary += f"""
**{info['name']}:** {info['count']} features
- Archivo: `{model_key.replace('_', '_')}.joblib`
- Features: {', '.join(info['features'][:5])}{'...' if len(info['features']) > 5 else ''}
"""

    summary += f"""
## 📊 LISTA DEFINITIVA DE FEATURES

Las siguientes features deben ser capturadas/calculadas desde el tráfico de red:

### Features Críticas (múltiples modelos):
"""

    # Encontrar features críticas
    feature_usage = {}
    for feature in all_features:
        usage_count = 0
        for model_key, info in model_features.items():
            if feature in info['features']:
                usage_count += 1
        feature_usage[feature] = usage_count

    critical = [f for f, count in feature_usage.items() if count >= 2]
    specific = [f for f, count in feature_usage.items() if count == 1]

    for i, feature in enumerate(sorted(critical), 1):
        summary += f"{i:2d}. **{feature}** (usado por {feature_usage[feature]} modelos)\n"

    summary += f"\n### Features Específicas (un modelo):\n"
    for i, feature in enumerate(sorted(specific), 1):
        summary += f"{i:2d}. {feature}\n"

    summary += f"""
## 🐍 IMPLEMENTACIÓN CON SCAPY

### Features Directas desde Paquetes:
- **proto**: `packet[IP].proto`
- **service**: `packet[TCP].dport` o `packet[UDP].dport`
- **sttl/dttl**: `packet[IP].ttl`
- **state**: Derivado de `packet[TCP].flags`

### Features de Flujo (requieren agregación):
- **spkts/dpkts**: Contador de paquetes por dirección
- **sbytes/dbytes**: Suma de bytes por dirección  
- **dur**: `last_packet_time - first_packet_time`

### Features Computadas:
- **rate**: `total_bytes / duration`
- **sload/dload**: `(bytes * 8) / duration` (bits por segundo)
- **sinpkt/dinpkt**: Tiempo inter-arrival promedio

### Features Complejas (requieren análisis avanzado):
- **sloss/dloss**: Análisis de secuencias TCP para detectar pérdidas
- **id**: Identificador único del flujo

## ⚠️ NOTAS IMPORTANTES

1. **Agregación por Flujo**: Muchas features requieren agrupar paquetes por flujo (src_ip:port → dst_ip:port)

2. **Dirección del Flujo**: Distinguir entre tráfico source→destination y destination→source

3. **Ventana Temporal**: Definir cuándo considerar un flujo "completo" para extraer features

4. **Preprocesamiento**: Los modelos esperan datos escalados - usar los scalers incluidos

## 🚀 CÓDIGO LISTO PARA USAR

El código de captura completo está incluido en este análisis.
"""

    return summary


def main():
    """Función principal"""
    print(f"🎯 EXTRACTOR DE FEATURES REQUERIDAS PARA SCAPY")
    print(f"Análisis de modelos entrenados para determinar requirements exactos")
    print("=" * 90)

    # Verificar que existen los modelos
    required_models = [
        'models/rf_production_final.joblib',
        'models/web_normal_detector.joblib',
        'models/internal_normal_detector.joblib'
    ]

    missing_models = [m for m in required_models if not os.path.exists(m)]
    if missing_models:
        print(f"❌ MODELOS FALTANTES:")
        for model in missing_models:
            print(f"   - {model}")
        print(f"💡 Ejecuta primero: python build_complete_system.py")
        return 1

    # Analizar requirements
    all_features, feature_usage, model_features = analyze_feature_requirements()

    # Categorizar para scapy
    scapy_mapping = categorize_features_for_scapy(all_features)

    # Generar código de captura
    capture_code = generate_scapy_capture_code(scapy_mapping, model_features)

    # Crear resumen
    summary = create_feature_requirements_summary(all_features, model_features)

    # Guardar archivos
    output_dir = Path('results')
    output_dir.mkdir(exist_ok=True)

    # Código de captura
    with open('results/scapy_feature_extractor.py', 'w') as f:
        f.write(capture_code)
    print(f"🐍 Código de captura guardado: results/scapy_feature_extractor.py")

    # Resumen de requirements
    with open('results/feature_requirements.md', 'w') as f:
        f.write(summary)
    print(f"📋 Resumen de features guardado: results/feature_requirements.md")

    print(f"\n🎯 LISTA DEFINITIVA DE FEATURES PARA SCAPY:")
    print("=" * 60)
    for i, feature in enumerate(sorted(all_features), 1):
        models_using = len([m for m in model_features.values() if feature in m['features']])
        priority = "🔴" if models_using >= 2 else "🔵"
        print(f"{priority} {i:2d}. {feature:<15} (usado por {models_using} modelo{'s' if models_using != 1 else ''})")

    print(f"\n📁 ARCHIVOS GENERADOS:")
    print(f"   🐍 results/scapy_feature_extractor.py - Código completo de captura")
    print(f"   📋 results/feature_requirements.md - Documentación detallada")

    return 0


if __name__ == "__main__":
    exit(main())