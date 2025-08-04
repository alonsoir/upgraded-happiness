#!/usr/bin/env python3
"""
EXTRACTOR SIMPLIFICADO DE FEATURES PARA SCAPY
Basado en el análisis exacto de los modelos entrenados
Solo captura las features realmente necesarias
"""

from scapy.all import *
import pandas as pd
import numpy as np
from collections import defaultdict
import time
import joblib
import json


class MinimalFeatureExtractor:
    """
    Extractor mínimo optimizado para los 3 modelos entrenados
    """

    def __init__(self):
        self.flows = defaultdict(lambda: {
            'packets': [],
            'first_time': None,
            'last_time': None,
            # Contadores por dirección
            'src_packets': 0,
            'dst_packets': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            # Info del protocolo
            'protocol': None,
            'service_port': None,
            'tcp_flags': set(),
            # Para state mapping
            'connection_state': 'INT'
        })

        # Mapeo de flags TCP a estados
        self.tcp_state_map = {
            frozenset([2]): 'INT',  # SYN
            frozenset([18]): 'CON',  # SYN+ACK
            frozenset([16]): 'CON',  # ACK
            frozenset([1]): 'FIN',  # FIN
            frozenset([17]): 'FIN',  # FIN+ACK
            frozenset([4]): 'RST',  # RST
        }

    def get_flow_key(self, packet):
        """Genera clave única para el flujo (5-tuple normalizada)"""
        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = dst_port = 0

        # Normalizar dirección (menor primero)
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"

    def is_source_direction(self, packet, flow_key):
        """Determina dirección del paquete en el flujo"""
        if IP not in packet:
            return True

        # Extraer IP origen del flow_key
        flow_src_ip = flow_key.split(':')[0]
        return packet[IP].src == flow_src_ip

    def process_packet(self, packet):
        """Procesa un paquete y actualiza estadísticas del flujo"""
        flow_key = self.get_flow_key(packet)
        if not flow_key:
            return

        flow = self.flows[flow_key]
        current_time = time.time()

        # Timestamps del flujo
        if flow['first_time'] is None:
            flow['first_time'] = current_time
        flow['last_time'] = current_time

        # Determinar dirección
        is_source = self.is_source_direction(packet, flow_key)
        packet_size = len(packet)

        # Actualizar contadores por dirección
        if is_source:
            flow['src_packets'] += 1  # spkts
            flow['src_bytes'] += packet_size  # sbytes
        else:
            flow['dst_packets'] += 1  # dpkts
            flow['dst_bytes'] += packet_size  # dbytes

        # Información del protocolo
        if IP in packet:
            flow['protocol'] = packet[IP].proto  # proto

        # Información del servicio (puerto de destino)
        if TCP in packet:
            if not flow['service_port']:
                flow['service_port'] = packet[TCP].dport  # service
            flow['tcp_flags'].add(packet[TCP].flags)
        elif UDP in packet:
            if not flow['service_port']:
                flow['service_port'] = packet[UDP].dport

    def extract_features_for_models(self, flow_key):
        """
        Extrae SOLO las features necesarias para los 3 modelos entrenados
        CON ENCODING CORRECTO para modelos ML
        """
        flow = self.flows[flow_key]
        features = {}

        # === FEATURES CRÍTICAS (todos los modelos) ===

        # 1. STATE - La más importante (65-71% importancia)
        # CODIFICAR COMO NÚMERO (como en entrenamiento)
        if flow['tcp_flags']:
            flags_set = frozenset(flow['tcp_flags'])
            state_str = self.tcp_state_map.get(flags_set, 'INT')
        else:
            state_str = 'INT'  # Default para UDP

        # Mapear estados a números (mismo orden que LabelEncoder)
        state_encoding = {
            'CON': 0,
            'FIN': 1,
            'INT': 2,
            'RST': 3
        }
        features['state'] = state_encoding.get(state_str, 2)  # Default INT=2

        # 2. SPKTS - Paquetes fuente a destino
        features['spkts'] = float(flow['src_packets'])

        # 3. DPKTS - Paquetes destino a fuente
        features['dpkts'] = float(flow['dst_packets'])

        # 4. DBYTES - Bytes destino a fuente (importante para web/interno)
        features['dbytes'] = float(flow['dst_bytes'])

        # === FEATURES ESPECÍFICAS DEL MODELO DE ATAQUES ===

        # 5. ID - Identificador del flujo (12% importancia en modelo ataques)
        features['id'] = float(abs(hash(flow_key)) % 100000)

        # 6. SERVICE - Puerto de servicio (7% importancia)
        # CODIFICAR COMO NÚMERO
        service_port = flow['service_port'] or 0
        features['service'] = float(service_port)

        # 7. PROTO - Protocolo
        # CODIFICAR COMO NÚMERO (6=TCP, 17=UDP)
        features['proto'] = float(flow['protocol'] or 6)  # Default TCP

        # === FEATURES ADICIONALES (menos críticas) ===

        # Para compatibilidad con modelos más complejos
        features['sbytes'] = float(flow['src_bytes'])

        # Timing básico
        duration = flow['last_time'] - flow['first_time'] if flow['last_time'] != flow['first_time'] else 0.001
        features['dur'] = float(duration)

        # Rate básico
        total_bytes = flow['src_bytes'] + flow['dst_bytes']
        features['rate'] = float(total_bytes / duration if duration > 0 else 0)

        return features

    def capture_flows(self, interface="en0", duration=60, packet_filter=""):
        """
        Captura paquetes y construye flujos
        """
        print(f"🔍 Capturando en {interface} por {duration}s...")
        print(f"🎯 Extrayendo features para modelos de ML...")

        def packet_handler(pkt):
            self.process_packet(pkt)

        # Filtro optimizado para TCP/UDP
        if not packet_filter:
            packet_filter = "tcp or udp"

        sniff(
            iface=interface,
            prn=packet_handler,
            timeout=duration,
            filter=packet_filter,
            store=False
        )

        print(f"📊 Procesados {len(self.flows)} flujos únicos")
        return len(self.flows)

    def get_features_dataframe(self):
        """
        Convierte flujos a DataFrame con features para ML
        """
        if not self.flows:
            print("⚠️ No hay flujos capturados")
            return pd.DataFrame()

        features_list = []
        for flow_key in self.flows:
            features = self.extract_features_for_models(flow_key)
            features['flow_id'] = flow_key
            features_list.append(features)

        df = pd.DataFrame(features_list)

        # Mostrar resumen
        print(f"📋 Features extraídas: {len(df.columns) - 1} (+ flow_id)")
        print(f"🔢 Flujos procesados: {len(df)}")
        print(f"📊 Features disponibles: {list(df.columns[:-1])}")  # Sin flow_id

        return df


class NetworkClassifier:
    """
    Clasificador que usa los 3 modelos en cascada
    """

    def __init__(self, models_dir="models"):
        """Carga los 3 modelos entrenados con metadatos"""
        self.models = {}
        self.scalers = {}
        self.feature_names = {}

        # Cargar modelos y scalers
        model_configs = [
            ('attack', 'rf_production_final'),
            ('web', 'web_normal_detector'),
            ('internal', 'internal_normal_detector')
        ]

        for model_name, file_prefix in model_configs:
            try:
                model_path = f"{models_dir}/{file_prefix}.joblib"
                scaler_path = f"{models_dir}/{file_prefix}_scaler.joblib"
                metadata_path = f"{models_dir}/{file_prefix}_metadata.json"

                self.models[model_name] = joblib.load(model_path)
                self.scalers[model_name] = joblib.load(scaler_path)

                # Cargar nombres de features en orden correcto
                try:
                    with open(metadata_path, 'r') as f:
                        import json
                        metadata = json.load(f)
                        self.feature_names[model_name] = metadata.get('feature_names', [])
                        print(f"✅ {model_name} model loaded ({len(self.feature_names[model_name])} features)")
                except:
                    print(f"⚠️ {model_name} metadata not found, using default order")
                    self.feature_names[model_name] = []

            except Exception as e:
                print(f"❌ Error loading {model_name}: {e}")

    def prepare_features_for_model(self, features_row, model_name):
        """
        Prepara features en el orden correcto para el modelo específico
        """
        if model_name not in self.feature_names or not self.feature_names[model_name]:
            # Si no tenemos metadatos, usar orden por defecto
            feature_values = []
            for col in features_row.index:
                if col != 'flow_id':
                    feature_values.append(features_row[col])
            return np.array(feature_values).reshape(1, -1)

        # Usar orden específico del modelo
        expected_features = self.feature_names[model_name]
        feature_values = []

        for feature_name in expected_features:
            if feature_name in features_row.index:
                feature_values.append(features_row[feature_name])
            else:
                # Feature faltante, usar valor por defecto
                print(f"⚠️ Feature {feature_name} faltante para modelo {model_name}, usando 0")
                feature_values.append(0.0)

        return np.array(feature_values).reshape(1, -1)

    def classify_traffic(self, features_df):
        """
        Clasifica tráfico usando sistema de 3 capas
        """
        results = []

        for idx, row in features_df.iterrows():

            # CAPA 1: ¿Es ataque?
            if 'attack' in self.models:
                try:
                    feature_data = self.prepare_features_for_model(row, 'attack')
                    X_scaled = self.scalers['attack'].transform(feature_data)
                    attack_prob = self.models['attack'].predict_proba(X_scaled)[0]

                    if attack_prob[1] > 0.5:  # Es ataque
                        results.append({
                            'flow_id': row['flow_id'],
                            'classification': 'ATAQUE',
                            'confidence': attack_prob[1],
                            'layer': 1
                        })
                        continue
                except Exception as e:
                    print(f"⚠️ Error en modelo attack: {e}")

            # CAPA 2: ¿Es tráfico web normal?
            if 'web' in self.models:
                try:
                    feature_data = self.prepare_features_for_model(row, 'web')
                    X_scaled = self.scalers['web'].transform(feature_data)
                    web_prob = self.models['web'].predict_proba(X_scaled)[0]

                    if web_prob[0] > 0.5:  # Es web normal
                        results.append({
                            'flow_id': row['flow_id'],
                            'classification': 'WEB_NORMAL',
                            'confidence': web_prob[0],
                            'layer': 2
                        })
                        continue
                except Exception as e:
                    print(f"⚠️ Error en modelo web: {e}")

            # CAPA 3: ¿Es tráfico interno normal?
            if 'internal' in self.models:
                try:
                    feature_data = self.prepare_features_for_model(row, 'internal')
                    X_scaled = self.scalers['internal'].transform(feature_data)
                    internal_prob = self.models['internal'].predict_proba(X_scaled)[0]

                    if internal_prob[0] > 0.5:  # Es interno normal
                        results.append({
                            'flow_id': row['flow_id'],
                            'classification': 'INTERNO_NORMAL',
                            'confidence': internal_prob[0],
                            'layer': 3
                        })
                    else:
                        results.append({
                            'flow_id': row['flow_id'],
                            'classification': 'ANOMALO_DESCONOCIDO',
                            'confidence': 1 - internal_prob[0],
                            'layer': 3
                        })
                except Exception as e:
                    print(f"⚠️ Error en modelo internal: {e}")
                    results.append({
                        'flow_id': row['flow_id'],
                        'classification': 'ERROR_CLASIFICACION',
                        'confidence': 0.0,
                        'layer': 0
                    })
            else:
                results.append({
                    'flow_id': row['flow_id'],
                    'classification': 'NO_CLASIFICADO',
                    'confidence': 0.0,
                    'layer': 0
                })

        return pd.DataFrame(results)


def main():
    """Ejemplo de uso completo"""
    print("🚀 CAPTURA Y CLASIFICACIÓN DE TRÁFICO EN TIEMPO REAL")
    print("=" * 70)

    # 1. Capturar tráfico
    extractor = MinimalFeatureExtractor()
    extractor.capture_flows(duration=30)  # 30 segundos

    # 2. Extraer features
    features_df = extractor.get_features_dataframe()

    if len(features_df) == 0:
        print("❌ No se capturó tráfico")
        return

    print(f"\n📊 Features capturadas:")
    print(features_df.head())

    # 3. Clasificar con modelos
    classifier = NetworkClassifier()

    if classifier.models:
        results = classifier.classify_traffic(features_df)

        print(f"\n🎯 RESULTADOS DE CLASIFICACIÓN:")
        print("=" * 50)

        # Resumen por tipo
        summary = results['classification'].value_counts()
        for classification, count in summary.items():
            pct = (count / len(results)) * 100
            print(f"   {classification}: {count} ({pct:.1f}%)")

        # Mostrar algunos ejemplos
        print(f"\n📋 Ejemplos de clasificación:")
        for _, row in results.head(5).iterrows():
            print(f"   {row['classification']:<20} | Confianza: {row['confidence']:.3f} | Capa: {row['layer']}")

        # Guardar resultados
        results.to_csv('traffic_classification_results.csv', index=False)
        features_df.to_csv('captured_features.csv', index=False)

        print(f"\n💾 Archivos guardados:")
        print(f"   📊 captured_features.csv - Features extraídas")
        print(f"   🎯 traffic_classification_results.csv - Resultados de clasificación")

    else:
        print("⚠️ No se pudieron cargar los modelos")
        features_df.to_csv('captured_features.csv', index=False)
        print("💾 Features guardadas en captured_features.csv")


if __name__ == "__main__":
    main()