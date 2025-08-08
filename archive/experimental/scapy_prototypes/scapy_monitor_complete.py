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
🚀 UPGRADED HAPPINESS - MONITOR COMPLETO CON PIPELINE DE 3 NIVELES

INTEGRACIÓN COMPLETA:
- Scapy para captura de paquetes
- Feature extraction de 82 características
- Pipeline ML de 3 niveles:
  * Nivel 1: ¿HAY ATAQUE? (23 features)
  * Nivel 2: ¿QUÉ TIPO? (82 features)
  * Nivel 3: ¿ANOMALÍAS SUTILES? (4 features)

Autor: Alonso Isidoro, Claude
Fecha: Agosto 7, 2025
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
import sys
from pathlib import Path

# Importar nuestro pipeline completo
sys.path.append(str(Path(__file__).parent))
from complete_ml_pipeline import CompleteMlPipeline


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


class AdvancedFlowTracker:
    """Tracker de flujos con cálculo de 82+ features optimizado"""

    def __init__(self, flow_timeout=60):
        self.flows = defaultdict(list)  # FlowKey -> [packets]
        self.flow_stats = defaultdict(dict)  # FlowKey -> stats
        self.flow_timeout = flow_timeout
        self.last_cleanup = time.time()

        # Nombres de features en el orden correcto (82 features)
        self.feature_names_82 = [
            ' Source Port', ' Destination Port', ' Protocol', ' Flow Duration',
            ' Total Fwd Packets', ' Total Backward Packets', ' Total Length of Fwd Packets',
            ' Total Length of Bwd Packets', ' Fwd Packet Length Max', ' Fwd Packet Length Min',
            ' Fwd Packet Length Mean', ' Fwd Packet Length Std', ' Bwd Packet Length Max',
            ' Bwd Packet Length Min', ' Bwd Packet Length Mean', ' Bwd Packet Length Std',
            ' Flow Bytes/s', ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std',
            ' Flow IAT Max', ' Flow IAT Min', ' Fwd IAT Total', ' Fwd IAT Mean',
            ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min', ' Bwd IAT Total',
            ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min',
            ' Fwd PSH Flags', ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags',
            ' FIN Flag Count', ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count',
            ' ACK Flag Count', ' URG Flag Count', ' CWE Flag Count', ' ECE Flag Count',
            ' Fwd Header Length', ' Bwd Header Length', ' Fwd Header Length.1',
            ' Fwd Packets/s', ' Bwd Packets/s', ' Min Packet Length', ' Max Packet Length',
            ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
            ' Down/Up Ratio', ' Average Packet Size', ' Avg Fwd Segment Size',
            ' Avg Bwd Segment Size', ' Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk',
            ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk',
            ' Bwd Avg Bulk Rate', ' Subflow Fwd Packets', ' Subflow Fwd Bytes',
            ' Subflow Bwd Packets', ' Subflow Bwd Bytes', ' Init_Win_bytes_forward',
            ' Init_Win_bytes_backward', ' act_data_pkt_fwd', ' min_seg_size_forward',
            ' Active Mean', ' Active Std', ' Active Max', ' Active Min',
            ' Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min',
            ' SimillarHTTP', ' Inbound'
        ]

    def extract_flow_key(self, packet):
        """Extrae la clave del flujo desde un paquete"""
        if IP in packet:
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
                return FlowKey(
                    packet[IP].src, packet[IP].dst,
                    0, 0, packet[IP].proto
                )
        return None

    def add_packet(self, packet):
        """Agrega un paquete al flujo correspondiente"""
        flow_key = self.extract_flow_key(packet)
        if flow_key:
            packet.timestamp = time.time()
            self.flows[flow_key].append(packet)

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

    def calculate_82_features(self, flow_key):
        """Calcula exactamente 82 features en el formato esperado por los modelos"""
        packets = self.flows.get(flow_key, [])
        if len(packets) < 2:
            return None

        # Separar paquetes forward/backward
        fwd_packets = []
        bwd_packets = []

        first_packet = packets[0]
        fwd_src = first_packet[IP].src if IP in first_packet else None
        fwd_dst = first_packet[IP].dst if IP in first_packet else None

        for pkt in packets:
            if IP in pkt:
                if pkt[IP].src == fwd_src and pkt[IP].dst == fwd_dst:
                    fwd_packets.append(pkt)
                else:
                    bwd_packets.append(pkt)

        # Array de 82 features en orden exacto
        features = np.zeros(82)

        try:
            # 0-3: Información básica
            features[0] = flow_key.src_port
            features[1] = flow_key.dst_port
            features[2] = flow_key.protocol
            features[3] = (packets[-1].timestamp - packets[0].timestamp) * 1_000_000 if len(packets) >= 2 else 0

            # 4-7: Estadísticas de paquetes
            features[4] = len(fwd_packets)
            features[5] = len(bwd_packets)

            fwd_bytes = sum(len(pkt) for pkt in fwd_packets)
            bwd_bytes = sum(len(pkt) for pkt in bwd_packets)
            features[6] = fwd_bytes
            features[7] = bwd_bytes

            # 8-11: Longitud forward
            if fwd_packets:
                fwd_lengths = [len(pkt) for pkt in fwd_packets]
                features[8] = max(fwd_lengths)
                features[9] = min(fwd_lengths)
                features[10] = np.mean(fwd_lengths)
                features[11] = np.std(fwd_lengths)

            # 12-15: Longitud backward
            if bwd_packets:
                bwd_lengths = [len(pkt) for pkt in bwd_packets]
                features[12] = max(bwd_lengths)
                features[13] = min(bwd_lengths)
                features[14] = np.mean(bwd_lengths)
                features[15] = np.std(bwd_lengths)

            # 16-17: Velocidad de flujo
            duration_seconds = features[3] / 1_000_000
            if duration_seconds > 0:
                features[16] = (fwd_bytes + bwd_bytes) / duration_seconds  # Flow Bytes/s
                features[17] = len(packets) / duration_seconds  # Flow Packets/s

            # 18-21: Flow IAT
            if len(packets) >= 2:
                iats = []
                for i in range(1, len(packets)):
                    iat = (packets[i].timestamp - packets[i - 1].timestamp) * 1_000_000
                    iats.append(iat)

                features[18] = np.mean(iats)  # Flow IAT Mean
                features[19] = np.std(iats)  # Flow IAT Std
                features[20] = max(iats)  # Flow IAT Max
                features[21] = min(iats)  # Flow IAT Min

            # 22-27: Forward IAT
            if len(fwd_packets) >= 2:
                fwd_iats = []
                for i in range(1, len(fwd_packets)):
                    iat = (fwd_packets[i].timestamp - fwd_packets[i - 1].timestamp) * 1_000_000
                    fwd_iats.append(iat)

                features[22] = sum(fwd_iats)  # Fwd IAT Total
                features[23] = np.mean(fwd_iats)  # Fwd IAT Mean
                features[24] = np.std(fwd_iats)  # Fwd IAT Std
                features[25] = max(fwd_iats)  # Fwd IAT Max
                features[26] = min(fwd_iats)  # Fwd IAT Min

            # 28-32: Backward IAT
            if len(bwd_packets) >= 2:
                bwd_iats = []
                for i in range(1, len(bwd_packets)):
                    iat = (bwd_packets[i].timestamp - bwd_packets[i - 1].timestamp) * 1_000_000
                    bwd_iats.append(iat)

                features[27] = sum(bwd_iats)  # Bwd IAT Total
                features[28] = np.mean(bwd_iats)  # Bwd IAT Mean
                features[29] = np.std(bwd_iats)  # Bwd IAT Std
                features[30] = max(bwd_iats)  # Bwd IAT Max
                features[31] = min(bwd_iats)  # Bwd IAT Min

            # 32-43: Flags TCP
            tcp_flag_counts = np.zeros(12)  # 32-43
            fwd_psh = bwd_psh = fwd_urg = bwd_urg = 0

            for pkt in packets:
                if TCP in pkt:
                    flags = pkt[TCP].flags
                    if flags & 0x01: tcp_flag_counts[4] += 1  # FIN (36)
                    if flags & 0x02: tcp_flag_counts[5] += 1  # SYN (37)
                    if flags & 0x04: tcp_flag_counts[6] += 1  # RST (38)
                    if flags & 0x08: tcp_flag_counts[7] += 1  # PSH (39)
                    if flags & 0x10: tcp_flag_counts[8] += 1  # ACK (40)
                    if flags & 0x20: tcp_flag_counts[9] += 1  # URG (41)

                    if pkt in fwd_packets:
                        if flags & 0x08: fwd_psh += 1
                        if flags & 0x20: fwd_urg += 1
                    else:
                        if flags & 0x08: bwd_psh += 1
                        if flags & 0x20: bwd_urg += 1

            features[32] = fwd_psh  # Fwd PSH Flags
            features[33] = bwd_psh  # Bwd PSH Flags
            features[34] = fwd_urg  # Fwd URG Flags
            features[35] = bwd_urg  # Bwd URG Flags
            features[36:42] = tcp_flag_counts[4:10]  # FIN, SYN, RST, PSH, ACK, URG
            # features[42:44] CWE, ECE flags - simplificado a 0

            # 44-46: Headers
            fwd_header_lens = []
            bwd_header_lens = []

            for pkt in fwd_packets:
                if IP in pkt:
                    header_len = pkt[IP].ihl * 4
                    if TCP in pkt:
                        header_len += pkt[TCP].dataofs * 4
                    elif UDP in pkt:
                        header_len += 8
                    fwd_header_lens.append(header_len)

            for pkt in bwd_packets:
                if IP in pkt:
                    header_len = pkt[IP].ihl * 4
                    if TCP in pkt:
                        header_len += pkt[TCP].dataofs * 4
                    elif UDP in pkt:
                        header_len += 8
                    bwd_header_lens.append(header_len)

            features[44] = np.mean(fwd_header_lens) if fwd_header_lens else 0
            features[45] = np.mean(bwd_header_lens) if bwd_header_lens else 0
            features[46] = features[44]  # Duplicate

            # 47-48: Packets/s por dirección
            if duration_seconds > 0:
                features[47] = len(fwd_packets) / duration_seconds
                features[48] = len(bwd_packets) / duration_seconds

            # 49-53: Estadísticas generales de longitud
            all_lengths = [len(pkt) for pkt in packets]
            if all_lengths:
                features[49] = min(all_lengths)  # Min Packet Length
                features[50] = max(all_lengths)  # Max Packet Length
                features[51] = np.mean(all_lengths)  # Packet Length Mean
                features[52] = np.std(all_lengths)  # Packet Length Std
                features[53] = np.var(all_lengths)  # Packet Length Variance

            # 54-56: Ratios y tamaños promedio
            if fwd_bytes > 0:
                features[54] = bwd_bytes / fwd_bytes  # Down/Up Ratio

            total_bytes = fwd_bytes + bwd_bytes
            features[55] = total_bytes / len(packets) if packets else 0  # Average Packet Size
            features[56] = fwd_bytes / len(fwd_packets) if fwd_packets else 0  # Avg Fwd Segment Size
            features[57] = bwd_bytes / len(bwd_packets) if bwd_packets else 0  # Avg Bwd Segment Size

            # 58-81: Features restantes - simplificadas a 0 por ahora
            # (Bulk transfer, subflows, ventana TCP, actividad, etc.)
            # Estas requieren análisis más complejo que implementaremos gradualmente

        except Exception as e:
            print(f"Error calculando features: {e}")
            return None

        return features


class CompleteMlMonitor:
    """Monitor ML completo con pipeline de 3 niveles"""

    def __init__(self):
        self.flow_tracker = AdvancedFlowTracker(flow_timeout=120)
        self.ml_pipeline = CompleteMlPipeline()
        self.alert_queue = queue.Queue()
        self.stats = {
            'packets_processed': 0,
            'flows_analyzed': 0,
            'alerts_generated': 0,
            'start_time': time.time()
        }

    def packet_handler(self, packet):
        """Manejador de paquetes con pipeline completo"""
        try:
            self.stats['packets_processed'] += 1

            # Agregar al tracker
            self.flow_tracker.add_packet(packet)

            # Obtener clave del flujo
            flow_key = self.flow_tracker.extract_flow_key(packet)
            if not flow_key:
                return

            # Analizar flujos con suficientes paquetes
            packets_in_flow = len(self.flow_tracker.flows.get(flow_key, []))

            # Evaluar cada 15 paquetes (balance entre detección temprana y precisión)
            if packets_in_flow > 10 and packets_in_flow % 15 == 0:
                self.analyze_flow(flow_key)

        except Exception as e:
            print(f"Error procesando paquete: {e}")

    def analyze_flow(self, flow_key):
        """Analiza un flujo usando el pipeline completo de 3 niveles"""
        try:
            # Calcular 82 features
            features_82 = self.flow_tracker.calculate_82_features(flow_key)
            if features_82 is None:
                return

            self.stats['flows_analyzed'] += 1

            # Usar pipeline completo de 3 niveles
            results = self.ml_pipeline.predict_complete(
                features_82,
                self.flow_tracker.feature_names_82
            )

            # Procesar resultados
            classification = results['final_classification']
            confidence = results['confidence']

            # Generar alertas para detecciones
            if classification != 'NORMAL':
                alert = {
                    'timestamp': time.time(),
                    'flow_key': flow_key,
                    'classification': classification,
                    'confidence': confidence,
                    'level1_attack_prob': results.get('level1_attack_probability', 0),
                    'level2_predictions': results.get('level2_attack_types', {}),
                    'level3_validation': results.get('level3_normal_validation', {}),
                    'alerts': results.get('alerts', []),
                    'processing_time_ms': results.get('processing_time_ms', 0)
                }

                self.alert_queue.put(alert)
                self.stats['alerts_generated'] += 1

                # Mostrar alerta en consola
                self.display_alert(alert)

        except Exception as e:
            print(f"Error analizando flujo: {e}")

    def display_alert(self, alert):
        """Muestra alertas en formato legible"""
        flow_key = alert['flow_key']
        classification = alert['classification']
        confidence = alert['confidence']

        # Emoji según tipo de ataque
        emoji_map = {
            'DDOS': '⚡',
            'RANSOMWARE': '🦠',
            'INTERNAL_ANOMALY': '🏠',
            'WEB_ANOMALY': '🌐',
            'UNKNOWN_ATTACK': '❓'
        }

        emoji = emoji_map.get(classification, '🚨')

        print(f"\n{emoji} ALERTA: {classification}")
        print(f"   📍 Flujo: {flow_key.src_ip}:{flow_key.src_port} → {flow_key.dst_ip}:{flow_key.dst_port}")
        print(f"   📈 Confianza: {confidence:.2%}")
        print(f"   ⏱️ Tiempo procesamiento: {alert['processing_time_ms']:.1f}ms")

        if alert['alerts']:
            print(f"   💬 Detalles: {', '.join(alert['alerts'])}")

    def display_stats(self):
        """Muestra estadísticas del monitor"""
        runtime = time.time() - self.stats['start_time']

        print(f"\n📊 ESTADÍSTICAS ({runtime:.0f}s runtime):")
        print(f"   📦 Paquetes procesados: {self.stats['packets_processed']:,}")
        print(f"   🔍 Flujos analizados: {self.stats['flows_analyzed']:,}")
        print(f"   🚨 Alertas generadas: {self.stats['alerts_generated']:,}")
        print(f"   📈 Tasa paquetes: {self.stats['packets_processed'] / max(runtime, 1):.1f} pkt/s")

    def start_monitoring(self, interface="en0", filter_expr="tcp or udp"):
        """Inicia monitoreo con pipeline completo"""
        print("=" * 70)
        print("🚀 UPGRADED HAPPINESS - MONITOR COMPLETO (3 NIVELES)")
        print("=" * 70)

        # Mostrar estadísticas del pipeline
        pipeline_stats = self.ml_pipeline.get_pipeline_stats()
        print(f"🎯 Pipeline: {pipeline_stats['models_loaded']} modelos cargados")
        print(f"📋 Modelos: {', '.join(pipeline_stats['models_list'])}")

        print(f"\n🔍 Iniciando captura en {interface}")
        print(f"🎯 Filtro: {filter_expr}")
        print("⏯️  Presiona Ctrl+C para detener\n")

        try:
            # Thread para mostrar estadísticas cada 30 segundos
            def stats_updater():
                while True:
                    time.sleep(30)
                    self.display_stats()

            stats_thread = threading.Thread(target=stats_updater, daemon=True)
            stats_thread.start()

            # Captura principal
            sniff(
                iface=interface,
                prn=self.packet_handler,
                filter=filter_expr,
                store=0
            )

        except KeyboardInterrupt:
            print(f"\n🛑 Deteniendo monitor...")
            self.display_stats()
            print("✅ Monitor detenido correctamente")

        except Exception as e:
            print(f"❌ Error en captura: {e}")


def main():
    """Función principal"""
    try:
        monitor = CompleteMlMonitor()

        # Configuración
        interface = "en0"  # Cambiar según tu interfaz
        filter_expr = "tcp or udp"  # Solo TCP/UDP

        monitor.start_monitoring(interface=interface, filter_expr=filter_expr)

    except Exception as e:
        print(f"❌ Error inicializando: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()