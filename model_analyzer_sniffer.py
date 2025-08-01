#!/usr/bin/env python3
"""
Model Feature Analyzer Sniffer
Analiza qué features específicas están causando clasificaciones incorrectas
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
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime
import warnings

warnings.filterwarnings('ignore')


@dataclass
class FlowStats:
    """Estadísticas de flujo simplificadas"""
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
    src_seq_nums: List[int] = field(default_factory=list)
    dst_seq_nums: List[int] = field(default_factory=list)

    current_state: str = "NEW"
    last_classification_time: float = 0.0


class ModelFeatureAnalyzer:
    def __init__(self):
        self.running = False
        self.flows = defaultdict(FlowStats)
        self.global_stats = defaultdict(lambda: defaultdict(int))

        # Puertos conocidos
        self.well_known_ports = {
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
            1433, 3306, 5432, 6379, 8080, 8443
        }

        # Modelos
        self.models = {}
        self.scalers = {}

        # Casos de prueba para análisis
        self.test_cases = []

        signal.signal(signal.SIGINT, self._signal_handler)
        self._load_attack_model()

    def _load_attack_model(self):
        """Carga solo el modelo de ataque para análisis"""
        try:
            model_path = "models/rf_production_final.joblib"
            scaler_path = "models/rf_production_final_scaler.joblib"

            self.models['attack'] = joblib.load(model_path)
            if os.path.exists(scaler_path):
                self.scalers['attack'] = joblib.load(scaler_path)

            print("✅ Modelo de ataque cargado para análisis")

        except Exception as e:
            print(f"❌ Error cargando modelo: {e}")
            sys.exit(1)

    def _signal_handler(self, signum, frame):
        print(f"\n🛑 Parando análisis...")
        self.running = False
        sys.exit(0)

    def _determine_server_port(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> tuple:
        """Determina puerto servidor vs cliente"""
        if dst_port in self.well_known_ports and src_port not in self.well_known_ports:
            return dst_port, src_port
        elif src_port in self.well_known_ports and dst_port not in self.well_known_ports:
            return src_port, dst_port
        elif dst_port < 1024 and src_port >= 1024:
            return dst_port, src_port
        elif src_port < 1024 and dst_port >= 1024:
            return src_port, dst_port
        else:
            return min(src_port, dst_port), max(src_port, dst_port)

    def _get_flow_key(self, packet) -> Optional[str]:
        """Genera clave de flujo"""
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
            return None

        if (src_ip, src_port) <= (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

    def _process_packet(self, packet):
        """Procesa paquetes para análisis"""
        flow_key = self._get_flow_key(packet)
        if not flow_key:
            return

        current_time = time.time()
        flow = self.flows[flow_key]

        # Inicializar flujo
        if flow.start_time == 0:
            flow.start_time = current_time

            if packet.haslayer(IP):
                ip_layer = packet[IP]
                is_source = packet[IP].src == flow_key.split(':')[0]

                if is_source:
                    flow.src_ip, flow.dst_ip = ip_layer.src, ip_layer.dst
                else:
                    flow.src_ip, flow.dst_ip = ip_layer.dst, ip_layer.src

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                is_source = packet[IP].src == flow.src_ip
                if is_source:
                    flow.src_port, flow.dst_port = tcp_layer.sport, tcp_layer.dport
                else:
                    flow.src_port, flow.dst_port = tcp_layer.dport, tcp_layer.sport
                flow.protocol = 6

            flow.server_port, flow.client_port = self._determine_server_port(
                flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port
            )

        # Actualizar estadísticas básicas
        flow.last_time = current_time
        packet_size = len(packet)
        is_source = packet[IP].src == flow.src_ip

        if is_source:
            flow.spkts += 1
            flow.sbytes += packet_size
            flow.src_timestamps.append(current_time)
        else:
            flow.dpkts += 1
            flow.dbytes += packet_size
            flow.dst_timestamps.append(current_time)

        # TCP info
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            flow.tcp_flags_history.append(tcp_layer.flags)

            if is_source:
                flow.src_windows.append(tcp_layer.window)
            else:
                flow.dst_windows.append(tcp_layer.window)

            # Estado TCP
            if tcp_layer.flags & 0x10:  # ACK
                flow.current_state = "ESTABLISHED"
            elif tcp_layer.flags & 0x02:  # SYN
                flow.current_state = "SYN"

    def _create_synthetic_test_cases(self):
        """Crea casos de prueba sintéticos para análisis"""
        print("\n🧪 CREANDO CASOS DE PRUEBA SINTÉTICOS...")

        test_cases = [
            {
                'name': 'HTTPS_NORMAL_GOOGLE',
                'service': 443,
                'state': 2,  # ESTABLISHED
                'spkts': 10, 'dpkts': 8,
                'sload': 1000, 'sloss': 0, 'dloss': 0,
                'swin': 2048, 'dwin': 2048,
                'smean': 100, 'dmean': 100,
                'trans_depth': 0, 'response_body_len': 0,
                'is_ftp_login': 0, 'is_sm_ips_ports': 0,
                'expected': 'NORMAL'
            },
            {
                'name': 'HTTP_NORMAL_WEB',
                'service': 80,
                'state': 2,  # ESTABLISHED
                'spkts': 5, 'dpkts': 5,
                'sload': 500, 'sloss': 0, 'dloss': 0,
                'swin': 1024, 'dwin': 1024,
                'smean': 50, 'dmean': 50,
                'trans_depth': 3, 'response_body_len': 1500,
                'is_ftp_login': 0, 'is_sm_ips_ports': 0,
                'expected': 'NORMAL'
            },
            {
                'name': 'SSH_NORMAL',
                'service': 22,
                'state': 2,  # ESTABLISHED
                'spkts': 20, 'dpkts': 15,
                'sload': 200, 'sloss': 0, 'dloss': 0,
                'swin': 512, 'dwin': 512,
                'smean': 200, 'dmean': 150,
                'trans_depth': 0, 'response_body_len': 0,
                'is_ftp_login': 0, 'is_sm_ips_ports': 0,
                'expected': 'NORMAL'
            },
            {
                'name': 'SUSPICIOUS_HIGH_PORT',
                'service': 31337,  # Puerto sospechoso
                'state': 2,
                'spkts': 100, 'dpkts': 50,
                'sload': 10000, 'sloss': 5, 'dloss': 3,
                'swin': 64, 'dwin': 64,
                'smean': 10, 'dmean': 20,
                'trans_depth': 0, 'response_body_len': 0,
                'is_ftp_login': 0, 'is_sm_ips_ports': 1,
                'expected': 'ATTACK'
            },
            {
                'name': 'FTP_WITH_LOGIN',
                'service': 21,
                'state': 2,
                'spkts': 15, 'dpkts': 12,
                'sload': 300, 'sloss': 0, 'dloss': 0,
                'swin': 1024, 'dwin': 1024,
                'smean': 500, 'dmean': 400,
                'trans_depth': 0, 'response_body_len': 0,
                'is_ftp_login': 1, 'is_sm_ips_ports': 0,
                'expected': 'DEPENDS'
            }
        ]

        return test_cases

    def _create_features_vector(self, test_case):
        """Crea vector de features completo para un caso de prueba"""
        # Lista de features en el orden esperado por el modelo
        features = [
            test_case.get('id', 12345),
            test_case['service'],
            test_case['state'],
            test_case['spkts'],
            test_case['dpkts'],
            test_case['sload'],
            test_case['sloss'],
            test_case['dloss'],
            test_case['swin'],
            test_case['dwin'],
            test_case['smean'],
            test_case['dmean'],
            test_case['trans_depth'],
            test_case['response_body_len'],
            test_case.get('ct_srv_src', 1),
            test_case.get('ct_state_ttl', 10),
            test_case.get('ct_dst_ltm', 1.0),
            test_case.get('ct_src_dport_ltm', 5),
            test_case.get('ct_dst_src_ltm', 5),
            test_case['is_ftp_login'],
            test_case.get('ct_ftp_cmd', 0),
            test_case.get('ct_flw_http_mthd', 0),
            test_case.get('ct_src_ltm', 1.0),
            test_case.get('ct_srv_dst', 1),
            test_case['is_sm_ips_ports']
        ]

        return np.array(features).reshape(1, -1)

    def _analyze_feature_importance(self, features, prediction, probabilities):
        """Analiza qué features contribuyen más a la predicción"""
        feature_names = [
            'id', 'service', 'state', 'spkts', 'dpkts', 'sload', 'sloss', 'dloss',
            'swin', 'dwin', 'smean', 'dmean', 'trans_depth', 'response_body_len',
            'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
            'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd',
            'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
        ]

        # Análisis simple: features que pueden ser problemáticas
        problematic_features = []

        flat_features = features.flatten()

        # Detectar features sospechosas
        if flat_features[1] > 10000:  # service port muy alto
            problematic_features.append(f"service={flat_features[1]} (puerto muy alto)")

        if flat_features[5] > 50000:  # sload muy alto
            problematic_features.append(f"sload={flat_features[5]:.1f} (carga muy alta)")

        if flat_features[6] > 0 or flat_features[7] > 0:  # pérdidas
            problematic_features.append(f"sloss={flat_features[6]}, dloss={flat_features[7]} (pérdidas)")

        if flat_features[8] < 100 or flat_features[9] < 100:  # ventanas pequeñas
            problematic_features.append(f"swin={flat_features[8]}, dwin={flat_features[9]} (ventanas pequeñas)")

        if flat_features[10] < 10 or flat_features[11] < 10:  # tiempos muy rápidos
            problematic_features.append(f"smean={flat_features[10]:.1f}, dmean={flat_features[11]:.1f} (muy rápido)")

        if flat_features[24] == 1:  # IPs/puertos similares
            problematic_features.append("is_sm_ips_ports=1 (IPs/puertos similares)")

        return problematic_features

    def run_synthetic_analysis(self):
        """Ejecuta análisis con casos sintéticos"""
        print("🔬 ANÁLISIS DEL MODELO CON CASOS SINTÉTICOS")
        print("=" * 50)

        test_cases = self._create_synthetic_test_cases()

        for test_case in test_cases:
            print(f"\n🧪 Probando: {test_case['name']}")
            print(f"   Esperado: {test_case['expected']}")

            # Crear vector de features
            features = self._create_features_vector(test_case)

            # Aplicar scaler si existe
            if 'attack' in self.scalers:
                features_scaled = self.scalers['attack'].transform(features)
            else:
                features_scaled = features

            # Predecir
            probabilities = self.models['attack'].predict_proba(features_scaled)[0]
            prediction = self.models['attack'].predict(features_scaled)[0]

            # Mostrar resultados
            result = "ATAQUE" if prediction == 1 else "NORMAL"
            confidence = max(probabilities)

            print(f"   📊 Resultado: {result} (confianza: {confidence:.3f})")
            print(f"   📈 Probabilidades: [Normal: {probabilities[0]:.3f}, Ataque: {probabilities[1]:.3f}]")

            # Analizar features problemáticas
            problematic = self._analyze_feature_importance(features, prediction, probabilities)
            if problematic:
                print(f"   ⚠️  Features problemáticas:")
                for feature in problematic:
                    print(f"      - {feature}")
            else:
                print(f"   ✅ No se detectaron features problemáticas obvias")

            # Evaluar si el resultado es correcto
            if test_case['expected'] == 'NORMAL' and result == 'ATAQUE':
                print(f"   ❌ FALSO POSITIVO - El modelo es demasiado agresivo")
            elif test_case['expected'] == 'ATTACK' and result == 'NORMAL':
                print(f"   ❌ FALSO NEGATIVO - El modelo no detectó ataque")
            elif test_case['expected'] == 'DEPENDS':
                print(f"   🤔 Resultado ambiguo - Depende del contexto")
            else:
                print(f"   ✅ Resultado correcto")

    def run_live_analysis(self, duration=30):
        """Ejecuta análisis en tiempo real"""
        print(f"\n📡 INICIANDO ANÁLISIS EN TIEMPO REAL ({duration}s)")
        print("=" * 50)

        self.running = True

        def analyze_flows():
            while self.running:
                time.sleep(10)
                current_time = time.time()

                flows_to_analyze = []
                for flow_key, flow in self.flows.items():
                    if (current_time - flow.last_classification_time > 10 and
                            flow.spkts + flow.dpkts >= 3):
                        flows_to_analyze.append(flow_key)

                if flows_to_analyze:
                    print(f"\n🔍 Analizando {len(flows_to_analyze)} flujos en tiempo real...")

                    for flow_key in flows_to_analyze[:3]:  # Limitar a 3
                        flow = self.flows[flow_key]
                        flow.last_classification_time = current_time

                        # Crear vector de features del flujo real
                        duration_flow = max(flow.last_time - flow.start_time, 0.001)

                        real_case = {
                            'id': abs(hash(flow_key)) % 65536,
                            'service': flow.server_port,
                            'state': 2 if flow.current_state == "ESTABLISHED" else 5,
                            'spkts': flow.spkts,
                            'dpkts': flow.dpkts,
                            'sload': (flow.sbytes * 8) / duration_flow,
                            'sloss': 0, 'dloss': 0,
                            'swin': np.mean(flow.src_windows) if flow.src_windows else 0,
                            'dwin': np.mean(flow.dst_windows) if flow.dst_windows else 0,
                            'smean': 100, 'dmean': 100,  # Simplificado
                            'trans_depth': 0,
                            'response_body_len': 0,
                            'is_ftp_login': 0,
                            'is_sm_ips_ports': 0
                        }

                        print(f"\n📊 Flujo: {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}")
                        print(f"   Servidor: {flow.server_port}, Cliente: {flow.client_port}")

                        # Análisis
                        features = self._create_features_vector(real_case)
                        if 'attack' in self.scalers:
                            features_scaled = self.scalers['attack'].transform(features)
                        else:
                            features_scaled = features

                        probabilities = self.models['attack'].predict_proba(features_scaled)[0]
                        prediction = self.models['attack'].predict(features_scaled)[0]

                        result = "ATAQUE" if prediction == 1 else "NORMAL"
                        confidence = max(probabilities)

                        print(f"   🎯 Predicción: {result} (confianza: {confidence:.3f})")

                        # Análisis específico para puertos conocidos
                        if flow.server_port in [80, 443, 22, 21, 25] and result == "ATAQUE":
                            print(f"   ⚠️  POSIBLE FALSO POSITIVO - Puerto {flow.server_port} clasificado como ataque")
                            problematic = self._analyze_feature_importance(features, prediction, probabilities)
                            if problematic:
                                for feature in problematic:
                                    print(f"      - {feature}")

        # Iniciar análisis en thread separado
        analysis_thread = threading.Thread(target=analyze_flows, daemon=True)
        analysis_thread.start()

        # Capturar paquetes
        try:
            scapy.sniff(
                prn=self._process_packet,
                timeout=duration,
                store=False
            )
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False


def main():
    """Función principal"""
    print("🔬 Model Feature Analyzer v1.0")
    print("==============================")

    analyzer = ModelFeatureAnalyzer()

    # 1. Análisis sintético
    analyzer.run_synthetic_analysis()

    # 2. Análisis en tiempo real
    print(f"\n" + "=" * 50)
    input("Presiona Enter para iniciar análisis en tiempo real...")
    analyzer.run_live_analysis(duration=30)

    print("\n✅ Análisis completado")


if __name__ == "__main__":
    main()