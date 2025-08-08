"""
🧪 PROTOTIPO EXPERIMENTAL - SISTEMA TRICAPA v3.1
===============================================

Archivo migrado desde core/ el 2025-08-08 08:33:54

⚠️  VERSIÓN EXPERIMENTAL:
- Integra modelos ML tricapa desde models/production/
- Preparado para evolución hacia v3.1
- NO usar en producción sin validación

🚀 ROADMAP v3.1:
- Protobuf unificado (.proto v3.1)
- Pipeline refactorizado con colas
- Multi-model orchestration
- Dashboard + no-gui modes

"""

#!/usr/bin/env python3
"""
scapy_to_ml_features.py

Pipeline completo: Captura con Scapy → Cálculo de Features → Predicción ML para ddos y ransomware.
"""

from scapy.all import *
import numpy as np
import pandas as pd
from collections import defaultdict
import time
import joblib
from dataclasses import dataclass
from typing import Dict, List
import threading
import queue


@dataclass
class FlowKey:
    """Clave única para identificar un flujo de red"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))


class FlowTracker:
    """Rastrea y calcula features para flujos de red"""

    def __init__(self, flow_timeout=60):
        self.flows = defaultdict(list)  # FlowKey -> [packets]
        self.flow_stats = defaultdict(dict)  # FlowKey -> stats
        self.flow_timeout = flow_timeout
        self.last_cleanup = time.time()

    def extract_flow_key(self, packet):
        """Extrae la clave del flujo desde un paquete"""
        if IP in packet:
            # TCP o UDP
            if TCP in packet:
                return FlowKey(
                    packet[IP].src, packet[IP].dst,
                    packet[TCP].sport, packet[TCP].dport,
                    6  # TCP
                )
            elif UDP in packet:
                return FlowKey(
                    packet[IP].src, packet[IP].dst,
                    packet[UDP].sport, packet[UDP].dport,
                    17  # UDP
                )
            else:
                # ICMP u otros
                return FlowKey(
                    packet[IP].src, packet[IP].dst,
                    0, 0, packet[IP].proto
                )
        return None

    def add_packet(self, packet):
        """Agrega un paquete al flujo correspondiente"""
        flow_key = self.extract_flow_key(packet)
        if flow_key:
            # Agregar timestamp al paquete para cálculos
            packet.timestamp = time.time()
            self.flows[flow_key].append(packet)

            # Limpiar flujos antiguos cada 60 segundos
            if time.time() - self.last_cleanup > 60:
                self.cleanup_old_flows()

    def cleanup_old_flows(self):
        """Limpia flujos antiguos que han expirado"""
        current_time = time.time()
        expired_flows = []

        for flow_key, packets in self.flows.items():
            if packets and (current_time - packets[-1].timestamp) > self.flow_timeout:
                expired_flows.append(flow_key)

        for flow_key in expired_flows:
            del self.flows[flow_key]
            if flow_key in self.flow_stats:
                del self.flow_stats[flow_key]

        self.last_cleanup = current_time

    def calculate_flow_features(self, flow_key):
        """Calcula las 82+ features para un flujo"""
        packets = self.flows.get(flow_key, [])
        if len(packets) < 2:
            return None

        # Separar paquetes forward/backward
        fwd_packets = []
        bwd_packets = []

        # Definir dirección: primer paquete determina forward
        first_packet = packets[0]
        fwd_src = first_packet[IP].src if IP in first_packet else None
        fwd_dst = first_packet[IP].dst if IP in first_packet else None

        for pkt in packets:
            if IP in pkt:
                if pkt[IP].src == fwd_src and pkt[IP].dst == fwd_dst:
                    fwd_packets.append(pkt)
                else:
                    bwd_packets.append(pkt)

        features = {}

        # =====================================================================
        # INFORMACIÓN BÁSICA
        # =====================================================================
        features['source_port'] = flow_key.src_port
        features['destination_port'] = flow_key.dst_port
        features['protocol'] = flow_key.protocol

        # Duración del flujo
        if len(packets) >= 2:
            features['flow_duration'] = (packets[-1].timestamp - packets[0].timestamp) * 1_000_000  # microsegundos
        else:
            features['flow_duration'] = 0

        # =====================================================================
        # ESTADÍSTICAS DE PAQUETES
        # =====================================================================
        features['total_fwd_packets'] = len(fwd_packets)
        features['total_backward_packets'] = len(bwd_packets)

        # Bytes totales
        fwd_bytes = sum(len(pkt) for pkt in fwd_packets)
        bwd_bytes = sum(len(pkt) for pkt in bwd_packets)
        features['total_length_fwd_packets'] = fwd_bytes
        features['total_length_bwd_packets'] = bwd_bytes

        # =====================================================================
        # ESTADÍSTICAS DE LONGITUD - FORWARD
        # =====================================================================
        if fwd_packets:
            fwd_lengths = [len(pkt) for pkt in fwd_packets]
            features['fwd_packet_length_max'] = max(fwd_lengths)
            features['fwd_packet_length_min'] = min(fwd_lengths)
            features['fwd_packet_length_mean'] = np.mean(fwd_lengths)
            features['fwd_packet_length_std'] = np.std(fwd_lengths)
        else:
            features['fwd_packet_length_max'] = 0
            features['fwd_packet_length_min'] = 0
            features['fwd_packet_length_mean'] = 0
            features['fwd_packet_length_std'] = 0

        # =====================================================================
        # ESTADÍSTICAS DE LONGITUD - BACKWARD
        # =====================================================================
        if bwd_packets:
            bwd_lengths = [len(pkt) for pkt in bwd_packets]
            features['bwd_packet_length_max'] = max(bwd_lengths)
            features['bwd_packet_length_min'] = min(bwd_lengths)
            features['bwd_packet_length_mean'] = np.mean(bwd_lengths)
            features['bwd_packet_length_std'] = np.std(bwd_lengths)
        else:
            features['bwd_packet_length_max'] = 0
            features['bwd_packet_length_min'] = 0
            features['bwd_packet_length_mean'] = 0
            features['bwd_packet_length_std'] = 0

        # =====================================================================
        # VELOCIDAD DE FLUJO
        # =====================================================================
        duration_seconds = features['flow_duration'] / 1_000_000
        if duration_seconds > 0:
            features['flow_bytes_s'] = (fwd_bytes + bwd_bytes) / duration_seconds
            features['flow_packets_s'] = len(packets) / duration_seconds
        else:
            features['flow_bytes_s'] = 0
            features['flow_packets_s'] = 0

        # =====================================================================
        # TIEMPOS INTER-LLEGADA (IAT)
        # =====================================================================
        if len(packets) >= 2:
            iats = []
            for i in range(1, len(packets)):
                iat = (packets[i].timestamp - packets[i - 1].timestamp) * 1_000_000  # microsegundos
                iats.append(iat)

            features['flow_iat_mean'] = np.mean(iats)
            features['flow_iat_std'] = np.std(iats)
            features['flow_iat_max'] = max(iats)
            features['flow_iat_min'] = min(iats)
        else:
            features['flow_iat_mean'] = 0
            features['flow_iat_std'] = 0
            features['flow_iat_max'] = 0
            features['flow_iat_min'] = 0

        # =====================================================================
        # FLAGS TCP (si es TCP)
        # =====================================================================
        tcp_flags = {
            'fin_flag_count': 0,
            'syn_flag_count': 0,
            'rst_flag_count': 0,
            'psh_flag_count': 0,
            'ack_flag_count': 0,
            'urg_flag_count': 0,
        }

        fwd_psh = bwd_psh = fwd_urg = bwd_urg = 0

        for pkt in packets:
            if TCP in pkt:
                flags = pkt[TCP].flags
                if flags & 0x01: tcp_flags['fin_flag_count'] += 1  # FIN
                if flags & 0x02: tcp_flags['syn_flag_count'] += 1  # SYN
                if flags & 0x04: tcp_flags['rst_flag_count'] += 1  # RST
                if flags & 0x08: tcp_flags['psh_flag_count'] += 1  # PSH
                if flags & 0x10: tcp_flags['ack_flag_count'] += 1  # ACK
                if flags & 0x20: tcp_flags['urg_flag_count'] += 1  # URG

                # Separar por dirección
                if pkt in fwd_packets:
                    if flags & 0x08: fwd_psh += 1
                    if flags & 0x20: fwd_urg += 1
                else:
                    if flags & 0x08: bwd_psh += 1
                    if flags & 0x20: bwd_urg += 1

        features.update(tcp_flags)
        features['fwd_psh_flags'] = fwd_psh
        features['bwd_psh_flags'] = bwd_psh
        features['fwd_urg_flags'] = fwd_urg
        features['bwd_urg_flags'] = bwd_urg

        # =====================================================================
        # HEADERS
        # =====================================================================
        fwd_header_lengths = []
        bwd_header_lengths = []

        for pkt in fwd_packets:
            if IP in pkt:
                header_len = pkt[IP].ihl * 4  # IP header
                if TCP in pkt:
                    header_len += pkt[TCP].dataofs * 4  # TCP header
                elif UDP in pkt:
                    header_len += 8  # UDP header fijo
                fwd_header_lengths.append(header_len)

        for pkt in bwd_packets:
            if IP in pkt:
                header_len = pkt[IP].ihl * 4
                if TCP in pkt:
                    header_len += pkt[TCP].dataofs * 4
                elif UDP in pkt:
                    header_len += 8
                bwd_header_lengths.append(header_len)

        features['fwd_header_length'] = np.mean(fwd_header_lengths) if fwd_header_lengths else 0
        features['bwd_header_length'] = np.mean(bwd_header_lengths) if bwd_header_lengths else 0

        # =====================================================================
        # ESTADÍSTICAS ADICIONALES
        # =====================================================================

        # Paquetes por segundo por dirección
        if duration_seconds > 0:
            features['fwd_packets_s'] = len(fwd_packets) / duration_seconds
            features['bwd_packets_s'] = len(bwd_packets) / duration_seconds
        else:
            features['fwd_packets_s'] = 0
            features['bwd_packets_s'] = 0

        # Longitudes generales
        all_lengths = [len(pkt) for pkt in packets]
        if all_lengths:
            features['min_packet_length'] = min(all_lengths)
            features['max_packet_length'] = max(all_lengths)
            features['packet_length_mean'] = np.mean(all_lengths)
            features['packet_length_std'] = np.std(all_lengths)
            features['packet_length_variance'] = np.var(all_lengths)
        else:
            features['min_packet_length'] = 0
            features['max_packet_length'] = 0
            features['packet_length_mean'] = 0
            features['packet_length_std'] = 0
            features['packet_length_variance'] = 0

        # Ratios
        total_bytes = fwd_bytes + bwd_bytes
        if fwd_bytes > 0:
            features['down_up_ratio'] = bwd_bytes / fwd_bytes
        else:
            features['down_up_ratio'] = 0

        features['average_packet_size'] = total_bytes / len(packets) if packets else 0
        features['avg_fwd_segment_size'] = fwd_bytes / len(fwd_packets) if fwd_packets else 0
        features['avg_bwd_segment_size'] = bwd_bytes / len(bwd_packets) if bwd_packets else 0

        # =====================================================================
        # RELLENAR FEATURES FALTANTES CON 0
        # =====================================================================

        # Estas requieren análisis más complejo, las simplificamos por ahora
        additional_features = [
            'fwd_iat_total', 'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min',
            'bwd_iat_total', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min',
            'cwe_flag_count', 'ece_flag_count',
            'fwd_avg_bytes_bulk', 'fwd_avg_packets_bulk', 'fwd_avg_bulk_rate',
            'bwd_avg_bytes_bulk', 'bwd_avg_packets_bulk', 'bwd_avg_bulk_rate',
            'subflow_fwd_packets', 'subflow_fwd_bytes', 'subflow_bwd_packets', 'subflow_bwd_bytes',
            'init_win_bytes_forward', 'init_win_bytes_backward',
            'act_data_pkt_fwd', 'min_seg_size_forward',
            'active_mean', 'active_std', 'active_max', 'active_min',
            'idle_mean', 'idle_std', 'idle_max', 'idle_min',
            'similar_http', 'inbound'
        ]

        for feature in additional_features:
            if feature not in features:
                features[feature] = 0

        return features


class MLPredictor:
    """Predictor ML en tiempo real"""

    def __init__(self, model_paths):
        self.models = {}
        for model_name, path in model_paths.items():
            try:
                self.models[model_name] = joblib.load(path)
                print(f"✅ Cargado modelo {model_name}: {path}")
            except Exception as e:
                print(f"❌ Error cargando {model_name}: {e}")

    def predict(self, features_dict):
        """Predice usando todos los modelos cargados"""
        # Convertir a formato compatible (lista de 82 features en orden)
        feature_order = [
            'source_port', 'destination_port', 'protocol', 'flow_duration',
            'total_fwd_packets', 'total_backward_packets', 'total_length_fwd_packets',
            'total_length_bwd_packets', 'fwd_packet_length_max', 'fwd_packet_length_min',
            'fwd_packet_length_mean', 'fwd_packet_length_std', 'bwd_packet_length_max',
            'bwd_packet_length_min', 'bwd_packet_length_mean', 'bwd_packet_length_std',
            'flow_bytes_s', 'flow_packets_s', 'flow_iat_mean', 'flow_iat_std',
            # ... agregar todas las 82 features en el orden correcto
        ]

        # Por simplicidad, usar las features que tenemos
        feature_vector = []
        for feature in feature_order[:len(features_dict)]:
            feature_vector.append(features_dict.get(feature, 0))

        # Rellenar hasta 82 features si faltan
        while len(feature_vector) < 82:
            feature_vector.append(0)

        predictions = {}
        for model_name, model in self.models.items():
            try:
                pred = model.predict([feature_vector])[0]
                prob = model.predict_proba([feature_vector])[0] if hasattr(model, 'predict_proba') else None
                predictions[model_name] = {
                    'prediction': pred,
                    'probability': prob
                }
            except Exception as e:
                print(f"Error en predicción {model_name}: {e}")

        return predictions


class RealTimeNetworkMLMonitor:
    """Monitor ML de red en tiempo real"""

    def __init__(self, models_dir="./models"):
        self.flow_tracker = FlowTracker(flow_timeout=120)  # 2 minutos timeout

        # Cargar modelos entrenados
        model_paths = {
            'ddos_rf': f'{models_dir}/ddos_random_forest.joblib',
            'ddos_lgb': f'{models_dir}/ddos_lightgbm.joblib',
            'ransomware_rf': f'{models_dir}/ransomware_random_forest.joblib',
            'ransomware_lgb': f'{models_dir}/ransomware_lightgbm.joblib',
        }

        self.predictor = MLPredictor(model_paths)
        self.alert_queue = queue.Queue()

    def packet_handler(self, packet):
        """Manejador de paquetes capturados"""
        try:
            # Agregar paquete al tracker
            self.flow_tracker.add_packet(packet)

            # Extraer clave del flujo
            flow_key = self.flow_tracker.extract_flow_key(packet)
            if not flow_key:
                return

            # Solo procesar flujos con suficientes paquetes
            packets_in_flow = len(self.flow_tracker.flows.get(flow_key, []))

            # Evaluar cada 10 paquetes para flujos activos
            if packets_in_flow > 0 and packets_in_flow % 10 == 0:
                features = self.flow_tracker.calculate_flow_features(flow_key)

                if features:
                    predictions = self.predictor.predict(features)

                    # Generar alertas si hay detecciones
                    for model_name, result in predictions.items():
                        if result['prediction'] == 1:  # Ataque detectado
                            alert = {
                                'timestamp': time.time(),
                                'flow_key': flow_key,
                                'model': model_name,
                                'prediction': result['prediction'],
                                'probability': result.get('probability'),
                                'features': features
                            }

                            self.alert_queue.put(alert)
                            print(
                                f"🚨 ALERTA {model_name}: {flow_key.src_ip}:{flow_key.src_port} → {flow_key.dst_ip}:{flow_key.dst_port}")

        except Exception as e:
            print(f"Error procesando paquete: {e}")

    def start_monitoring(self, interface="en0", filter_expr=""):
        """Inicia el monitoreo en tiempo real"""
        print(f"🎯 Iniciando monitoreo ML en tiempo real en {interface}")
        print(f"🤖 Modelos cargados: {list(self.predictor.models.keys())}")

        try:
            # Sniffing con scapy
            sniff(
                iface=interface,
                prn=self.packet_handler,
                filter=filter_expr,
                store=0  # No almacenar paquetes en memoria
            )
        except KeyboardInterrupt:
            print("\n🛑 Deteniendo monitoreo...")
        except Exception as e:
            print(f"❌ Error en captura: {e}")


def main():
    """Función principal - Monitor en tiempo real"""
    monitor = RealTimeNetworkMLMonitor(models_dir="./models")

    # Configuración de captura
    interface = "en0"  # Cambiar según tu interfaz
    filter_expr = "tcp or udp"  # Solo TCP/UDP

    print("=" * 60)
    print("🚀 UPGRADED HAPPINESS - MONITOR ML TIEMPO REAL")
    print("=" * 60)

    monitor.start_monitoring(interface=interface, filter_expr=filter_expr)


if __name__ == "__main__":
    main()