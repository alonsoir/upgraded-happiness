#!/usr/bin/env python3
"""
Production Ready ML Sniffer
Desactiva el modelo de ataque roto y usa detección híbrida
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
import numpy as np
import joblib
import signal
import sys
import time
import threading
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime
import warnings

warnings.filterwarnings('ignore')


@dataclass
class FlowStats:
    """Estadísticas completas de un flujo de red"""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    server_port: int = 0
    client_port: int = 0

    spkts: int = 0
    dpkts: int = 0
    sbytes: int = 0
    dbytes: int = 0

    start_time: float = 0.0
    last_time: float = 0.0
    src_timestamps: List[float] = field(default_factory=list)
    dst_timestamps: List[float] = field(default_factory=list)

    tcp_flags_history: List[int] = field(default_factory=list)
    src_windows: List[int] = field(default_factory=list)
    dst_windows: List[int] = field(default_factory=list)

    current_state: str = "NEW"
    last_classification: str = "UNKNOWN"
    last_classification_time: float = 0.0


class ProductionMLSniffer:
    def __init__(self, window_seconds=20, classification_interval=10, debug_mode=False):
        """
        Production-ready sniffer que usa detección híbrida:
        - Modelos ML para web_normal e internal_normal (funcionan bien)
        - Reglas heurísticas para detección de ataques (modelo roto)
        """
        self.window_seconds = window_seconds
        self.classification_interval = classification_interval
        self.debug_mode = debug_mode
        self.running = False

        # Puertos conocidos normales
        self.normal_ports = {
            20, 21,  # FTP
            22,  # SSH
            23,  # Telnet
            25,  # SMTP
            53,  # DNS
            80,  # HTTP
            110,  # POP3
            143,  # IMAP
            443,  # HTTPS
            993,  # IMAPS
            995,  # POP3S
            1433,  # SQL Server
            3306,  # MySQL
            5432,  # PostgreSQL
            8080, 8443  # HTTP alternativo
        }

        # Puertos sospechosos comunes
        self.suspicious_ports = {
            1337, 31337, 4444, 5555, 6666, 8888, 9999,
            # Backdoors comunes
            12345, 54321, 65535,
            # Trojanos comunes
            1243, 1999, 6969, 7000, 10000
        }

        # Estructuras de datos
        self.flows = defaultdict(FlowStats)
        self.global_stats = defaultdict(lambda: defaultdict(int))
        self.classification_stats = defaultdict(int)

        # Solo modelos que funcionan bien
        self.models = {}
        self.scalers = {}
        self.available_models = []

        # Threads
        self.classifier_thread = None
        self.cleanup_thread = None
        self.stats_thread = None

        signal.signal(signal.SIGINT, self._signal_handler)
        self._load_working_models()

    def _load_working_models(self):
        """Carga solo los modelos que funcionan correctamente"""
        print("🔍 CARGANDO MODELOS DE PRODUCCIÓN...")
        print("=" * 50)
        print("⚠️  DESACTIVANDO modelo de ataque (fundamentalmente roto)")
        print("✅ USANDO detección híbrida:")
        print("   - ML para web_normal e internal_normal")
        print("   - Reglas heurísticas para ataques")

        working_models = {
            "web_normal": "models/web_normal_detector.joblib",
            "internal_normal": "models/internal_normal_detector.joblib"
        }

        for model_name, model_path in working_models.items():
            if os.path.exists(model_path):
                try:
                    print(f"\n📥 Cargando {model_name}...")
                    self.models[model_name] = joblib.load(model_path)

                    # Buscar scaler
                    scaler_path = model_path.replace('.joblib', '_scaler.joblib')
                    if os.path.exists(scaler_path):
                        self.scalers[model_name] = joblib.load(scaler_path)
                        print(f"   ✅ Scaler encontrado")

                    self.available_models.append(model_name)
                    print(f"   ✅ {model_name} cargado correctamente")

                except Exception as e:
                    print(f"   ❌ Error cargando {model_name}: {e}")
            else:
                print(f"   ❌ {model_name}: archivo no encontrado")

        print(f"\n✅ Sistema híbrido inicializado con {len(self.models)} modelos ML + reglas heurísticas")

    def _signal_handler(self, signum, frame):
        print(f"\n🛑 Parando sistema...")
        self.running = False
        sys.exit(0)

    def _determine_server_port(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> tuple:
        """Determina puerto servidor vs cliente"""
        if dst_port in self.normal_ports and src_port not in self.normal_ports:
            return dst_port, src_port
        elif src_port in self.normal_ports and dst_port not in self.normal_ports:
            return src_port, dst_port
        elif dst_port < 1024 and src_port >= 1024:
            return dst_port, src_port
        elif src_port < 1024 and dst_port >= 1024:
            return src_port, dst_port
        else:
            return min(src_port, dst_port), max(src_port, dst_port)

    def _is_private_ip(self, ip: str) -> bool:
        """Determina si una IP es privada"""
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                return False

            first, second = int(octets[0]), int(octets[1])

            return (first == 10 or
                    (first == 172 and 16 <= second <= 31) or
                    (first == 192 and second == 168) or
                    first == 127)
        except:
            return False

    def _get_flow_key(self, packet) -> Optional[str]:
        """Genera clave única para el flujo"""
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst

        if packet.haslayer(TCP):
            src_port, dst_port = packet[TCP].sport, packet[TCP].dport
            protocol = 6
        elif packet.haslayer(UDP):
            src_port, dst_port = packet[UDP].sport, packet[UDP].dport
            protocol = 17
        else:
            src_port, dst_port = 0, 0
            protocol = ip_layer.proto

        if (src_ip, src_port) <= (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

    def _process_packet(self, packet):
        """Procesa un paquete y actualiza estadísticas del flujo"""
        flow_key = self._get_flow_key(packet)
        if not flow_key:
            return

        current_time = time.time()
        flow = self.flows[flow_key]
        is_source = packet[IP].src == flow_key.split(':')[0]

        # Inicializar flujo nuevo
        if flow.start_time == 0:
            self._initialize_flow(flow, packet, flow_key, current_time, is_source)

        # Actualizar estadísticas básicas
        self._update_basic_stats(flow, packet, is_source, current_time)

        # Procesar TCP
        if packet.haslayer(TCP):
            self._process_tcp_layer(flow, packet, is_source)

    def _initialize_flow(self, flow, packet, flow_key, current_time, is_source):
        """Inicializa un nuevo flujo"""
        flow.start_time = current_time
        flow.last_time = current_time

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            if is_source:
                flow.src_ip, flow.dst_ip = ip_layer.src, ip_layer.dst
            else:
                flow.src_ip, flow.dst_ip = ip_layer.dst, ip_layer.src

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            if is_source:
                flow.src_port, flow.dst_port = tcp_layer.sport, tcp_layer.dport
            else:
                flow.src_port, flow.dst_port = tcp_layer.dport, tcp_layer.sport
            flow.protocol = 6
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            if is_source:
                flow.src_port, flow.dst_port = udp_layer.sport, udp_layer.dport
            else:
                flow.src_port, flow.dst_port = udp_layer.dport, udp_layer.sport
            flow.protocol = 17

        flow.server_port, flow.client_port = self._determine_server_port(
            flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port
        )

    def _update_basic_stats(self, flow, packet, is_source, current_time):
        """Actualiza estadísticas básicas del flujo"""
        flow.last_time = current_time
        packet_size = len(packet)

        if is_source:
            flow.spkts += 1
            flow.sbytes += packet_size
            flow.src_timestamps.append(current_time)
        else:
            flow.dpkts += 1
            flow.dbytes += packet_size
            flow.dst_timestamps.append(current_time)

    def _process_tcp_layer(self, flow, packet, is_source):
        """Procesa información específica de TCP"""
        tcp_layer = packet[TCP]
        flow.tcp_flags_history.append(tcp_layer.flags)

        if is_source:
            flow.src_windows.append(tcp_layer.window)
        else:
            flow.dst_windows.append(tcp_layer.window)

        # Actualizar estado del flujo
        if tcp_layer.flags & 0x10:  # ACK
            flow.current_state = "ESTABLISHED"
        elif tcp_layer.flags & 0x02:  # SYN
            flow.current_state = "SYN"

    def _heuristic_attack_detection(self, flow: FlowStats) -> tuple:
        """
        Detección de ataques basada en reglas heurísticas
        Returns: (is_attack, confidence, reasons)
        """
        reasons = []
        suspicion_score = 0.0

        # 1. Puerto sospechoso
        if flow.server_port in self.suspicious_ports:
            suspicion_score += 0.4
            reasons.append(f"Puerto sospechoso: {flow.server_port}")

        # 2. Puerto muy alto (> 50000)
        elif flow.server_port > 50000:
            suspicion_score += 0.2
            reasons.append(f"Puerto muy alto: {flow.server_port}")

        # 3. Muchos paquetes, pocos bytes (posible escaneo)
        if flow.spkts + flow.dpkts > 20 and flow.sbytes + flow.dbytes < 500:
            suspicion_score += 0.3
            reasons.append("Ratio paquetes/bytes sospechoso (posible escaneo)")

        # 4. Conexión muy corta con muchos paquetes
        duration = flow.last_time - flow.start_time
        if duration < 1.0 and flow.spkts + flow.dpkts > 10:
            suspicion_score += 0.2
            reasons.append("Muchos paquetes en tiempo muy corto")

        # 5. Solo paquetes salientes (posible backdoor)
        if flow.spkts > 10 and flow.dpkts == 0:
            suspicion_score += 0.4
            reasons.append("Solo tráfico saliente (posible backdoor)")

        # 6. Conexión a IP privada desde externa con puerto raro
        if (not self._is_private_ip(flow.src_ip) and
                self._is_private_ip(flow.dst_ip) and
                flow.server_port not in self.normal_ports and
                flow.server_port > 1024):
            suspicion_score += 0.3
            reasons.append("Conexión externa a IP privada en puerto no estándar")

        # 7. Ventanas TCP muy pequeñas (< 100)
        if flow.src_windows and flow.dst_windows:
            avg_win = (np.mean(flow.src_windows) + np.mean(flow.dst_windows)) / 2
            if avg_win < 100:
                suspicion_score += 0.2
                reasons.append(f"Ventanas TCP muy pequeñas: {avg_win:.1f}")

        # Determinar si es ataque
        is_attack = suspicion_score >= 0.5
        confidence = min(suspicion_score, 0.95)  # Máximo 95% confianza

        return is_attack, confidence, reasons

    def _classify_flow(self, flow_key: str) -> Dict:
        """Clasifica un flujo usando detección híbrida"""
        try:
            flow = self.flows[flow_key]

            results = {
                'flow_id': flow_key,
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'final_classification': 'UNKNOWN',
                'confidence': 0.0,
                'layer': 0,
                'method': 'UNKNOWN'
            }

            if self.debug_mode:
                print(f"\n🔬 ANÁLISIS HÍBRIDO: {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}")
                print(f"   Servidor: {flow.server_port}, Cliente: {flow.client_port}")

            # PASO 1: Detección heurística de ataques (reemplaza modelo roto)
            is_attack, attack_confidence, attack_reasons = self._heuristic_attack_detection(flow)

            if is_attack:
                results['final_classification'] = 'ATAQUE'
                results['confidence'] = attack_confidence
                results['layer'] = 1
                results['method'] = 'HEURISTIC'

                if self.debug_mode:
                    print(f"   🚨 ATAQUE detectado por heurística (confianza: {attack_confidence:.3f})")
                    for reason in attack_reasons:
                        print(f"      - {reason}")

                return results

            if self.debug_mode:
                print(f"   ✅ No es ataque (puntuación: {attack_confidence:.3f})")

            # PASO 2: Clasificación ML para tráfico normal
            # Preparar features básicas para modelos que funcionan
            features = {
                'state': 2 if flow.current_state == "ESTABLISHED" else 5,
                'spkts': flow.spkts,
                'dpkts': flow.dpkts,
                'dbytes': flow.dbytes
            }

            feature_values = [features['state'], features['spkts'], features['dpkts'], features['dbytes']]
            feature_array = np.array(feature_values).reshape(1, -1)

            # CAPA 2: Detector web normal
            if 'web_normal' in self.available_models:
                if self.debug_mode:
                    print(f"   🔍 Probando detector web normal...")

                web_features = feature_array.copy()
                if 'web_normal' in self.scalers:
                    web_features = self.scalers['web_normal'].transform(web_features)

                web_proba = self.models['web_normal'].predict_proba(web_features)[0]
                web_pred = self.models['web_normal'].predict(web_features)[0]

                if self.debug_mode:
                    print(f"      Probabilidades: {web_proba}")
                    print(f"      Predicción: {web_pred}")

                if web_pred == 1:  # Es tráfico web normal
                    results['final_classification'] = 'WEB_NORMAL'
                    results['confidence'] = max(web_proba)
                    results['layer'] = 2
                    results['method'] = 'ML'
                    return results

            # CAPA 3: Detector interno normal
            if 'internal_normal' in self.available_models:
                if self.debug_mode:
                    print(f"   🔍 Probando detector interno normal...")

                internal_features = feature_array.copy()
                if 'internal_normal' in self.scalers:
                    internal_features = self.scalers['internal_normal'].transform(internal_features)

                internal_proba = self.models['internal_normal'].predict_proba(internal_features)[0]
                internal_pred = self.models['internal_normal'].predict(internal_features)[0]

                if self.debug_mode:
                    print(f"      Probabilidades: {internal_proba}")
                    print(f"      Predicción: {internal_pred}")

                if internal_pred == 1:  # Es tráfico interno normal
                    results['final_classification'] = 'INTERNO_NORMAL'
                    results['confidence'] = max(internal_proba)
                    results['layer'] = 3
                    results['method'] = 'ML'
                else:
                    results['final_classification'] = 'ANOMALO_DESCONOCIDO'
                    results['confidence'] = 1.0 - max(internal_proba)
                    results['layer'] = 3
                    results['method'] = 'ML'
            else:
                # Sin clasificador interno, usar reglas simples
                if flow.server_port in self.normal_ports:
                    results['final_classification'] = 'TRAFICO_NORMAL'
                    results['confidence'] = 0.7
                    results['layer'] = 3
                    results['method'] = 'RULE'
                else:
                    results['final_classification'] = 'DESCONOCIDO'
                    results['confidence'] = 0.5
                    results['layer'] = 3
                    results['method'] = 'RULE'

            return results

        except Exception as e:
            print(f"❌ Error clasificando flujo {flow_key}: {e}")
            return {
                'flow_id': flow_key,
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'final_classification': 'ERROR',
                'confidence': 0.0,
                'layer': 0,
                'method': 'ERROR'
            }

    def _classification_worker(self):
        """Worker thread que clasifica flujos periódicamente"""
        while self.running:
            try:
                current_time = time.time()

                flows_to_classify = []
                for flow_key, flow in self.flows.items():
                    time_since_last = current_time - flow.last_classification_time
                    if (time_since_last >= self.classification_interval and
                            flow.spkts + flow.dpkts >= 3):
                        flows_to_classify.append(flow_key)

                if flows_to_classify:
                    if self.debug_mode:
                        flows_to_classify = flows_to_classify[:3]  # Limitar en debug

                    print(f"\n🎯 Clasificando {len(flows_to_classify)} flujos (método híbrido)...")

                    for flow_key in flows_to_classify:
                        result = self._classify_flow(flow_key)

                        self.classification_stats[result['final_classification']] += 1
                        self.flows[flow_key].last_classification = result['final_classification']
                        self.flows[flow_key].last_classification_time = current_time

                        confidence_str = f"{result['confidence']:.3f}"
                        method_str = result['method']

                        print(f"\n🎯 RESULTADO: {result['final_classification']:<18} | "
                              f"Conf: {confidence_str} | Capa: {result['layer']} | "
                              f"Método: {method_str} | {result['timestamp']}")

                        if result['final_classification'] == 'ATAQUE':
                            print(f"   🚨 ALERTA DE ATAQUE DETECTADA (método heurístico)! 🚨")

                time.sleep(1)

            except Exception as e:
                print(f"❌ Error en clasificador: {e}")
                time.sleep(1)

    def _cleanup_worker(self):
        """Worker thread para limpieza de flujos antiguos"""
        while self.running:
            try:
                current_time = time.time()
                cutoff_time = current_time - self.window_seconds

                old_flows = [k for k, v in self.flows.items()
                             if v.last_time < cutoff_time]

                for flow_key in old_flows:
                    del self.flows[flow_key]

                if old_flows:
                    print(f"🧹 Limpiados {len(old_flows)} flujos antiguos")

                time.sleep(30)

            except Exception as e:
                print(f"❌ Error en limpieza: {e}")
                time.sleep(30)

    def _stats_worker(self):
        """Worker thread para mostrar estadísticas periódicas"""
        while self.running:
            try:
                time.sleep(20)

                print(f"\n📊 ESTADÍSTICAS HÍBRIDAS ({datetime.now().strftime('%H:%M:%S')})")
                print(f"   Flujos activos: {len(self.flows)}")
                print(f"   Métodos disponibles: Heurístico + {', '.join(self.available_models)} ML")

                if self.classification_stats:
                    total_classifications = sum(self.classification_stats.values())
                    print(f"   Clasificaciones totales: {total_classifications}")
                    for classification, count in self.classification_stats.items():
                        percentage = (count / total_classifications) * 100
                        print(f"     {classification}: {count} ({percentage:.1f}%)")

            except Exception as e:
                print(f"❌ Error en estadísticas: {e}")
                time.sleep(20)

    def start_capture(self, interface=None):
        """Inicia la captura y clasificación en tiempo real"""
        print(f"\n🚀 INICIANDO PRODUCTION ML SNIFFER")
        print(f"   🎯 MÉTODO HÍBRIDO:")
        print(f"      - Heurísticas para detección de ataques")
        print(f"      - ML para clasificación de tráfico normal")
        print(f"   Modelos ML disponibles: {', '.join(self.available_models)}")
        print(f"   Ventana de flujo: {self.window_seconds}s")
        print(f"   Debug mode: {'ON' if self.debug_mode else 'OFF'}")
        print(f"   Presiona Ctrl+C para parar\n")

        self.running = True

        self.classifier_thread = threading.Thread(target=self._classification_worker, daemon=True)
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.stats_thread = threading.Thread(target=self._stats_worker, daemon=True)

        self.classifier_thread.start()
        self.cleanup_thread.start()
        self.stats_thread.start()

        try:
            scapy.sniff(
                iface=interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            print("\n🛑 Captura interrumpida por usuario")
        finally:
            self.running = False
            print("\n📊 ESTADÍSTICAS FINALES:")
            for classification, count in self.classification_stats.items():
                print(f"   {classification}: {count}")


def main():
    """Función principal"""
    print("🚀 Production Ready ML Sniffer v1.0")
    print("===================================")

    # Permitir modo debug como argumento
    debug_mode = len(sys.argv) > 1 and sys.argv[1] == "--debug"

    sniffer = ProductionMLSniffer(
        window_seconds=20,
        classification_interval=10,
        debug_mode=debug_mode
    )

    try:
        sniffer.start_capture()
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()