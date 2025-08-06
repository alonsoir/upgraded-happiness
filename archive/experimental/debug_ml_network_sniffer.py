#!/usr/bin/env python3
"""
Debug ML Network Sniffer
Muestra exactamente qué features se están enviando a cada modelo
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
import pandas as pd
import numpy as np
import joblib
import signal
import sys
import time
import threading
import os
import glob
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import warnings

warnings.filterwarnings('ignore')


@dataclass
class FlowStats:
    """Estadísticas completas de un flujo de red"""
    # Identificación
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    flow_id: str = ""

    # Contadores básicos
    spkts: int = 0
    dpkts: int = 0
    sbytes: int = 0
    dbytes: int = 0

    # Timestamps y duración
    start_time: float = 0.0
    last_time: float = 0.0
    src_timestamps: List[float] = field(default_factory=list)
    dst_timestamps: List[float] = field(default_factory=list)

    # TCP específico
    tcp_flags_history: List[int] = field(default_factory=list)
    src_windows: List[int] = field(default_factory=list)
    dst_windows: List[int] = field(default_factory=list)
    src_seq_nums: List[int] = field(default_factory=list)
    dst_seq_nums: List[int] = field(default_factory=list)

    # HTTP específico
    http_methods: List[str] = field(default_factory=list)
    http_responses: List[int] = field(default_factory=list)
    response_bodies: List[int] = field(default_factory=list)
    transaction_depth: int = 0

    # FTP específico
    ftp_commands: List[str] = field(default_factory=list)
    ftp_login_attempts: int = 0

    # Estado actual
    current_state: str = "NEW"
    last_classification: str = "UNKNOWN"
    last_classification_time: float = 0.0


class DebugMLSniffer:
    def __init__(self, window_seconds=10, classification_interval=10, debug_mode=True):
        """
        Args:
            window_seconds: Ventana de tiempo para mantener estadísticas de flujo
            classification_interval: Intervalo entre clasificaciones (segundos)
            debug_mode: Mostrar información detallada de debug
        """
        self.window_seconds = window_seconds
        self.classification_interval = classification_interval
        self.debug_mode = debug_mode
        self.running = False

        # Estructuras de datos
        self.flows = defaultdict(FlowStats)
        self.global_stats = defaultdict(lambda: defaultdict(int))
        self.classification_stats = defaultdict(int)

        # Modelos ML
        self.models = {}
        self.scalers = {}
        self.feature_lists = {}
        self.available_models = []

        # Debug counters
        self.debug_count = 0

        # Threads
        self.classifier_thread = None
        self.cleanup_thread = None
        self.stats_thread = None

        # Configurar señal para parada limpia
        signal.signal(signal.SIGINT, self._signal_handler)

        self._detect_and_load_models()

    def _detect_and_load_models(self):
        """Detecta correctamente modelos (no scalers)"""
        print("🔍 DETECTANDO MODELOS CORRECTOS...")
        print("=" * 50)

        # Mapeo explícito para evitar confusiones
        model_mappings = {
            "attack": [
                "models/rf_production_final.joblib",
                "models/rf_production.joblib",
                "models/rf_unsw_baseline.joblib"
            ],
            "web_normal": [
                "models/web_normal_detector.joblib"
            ],
            "internal_normal": [
                "models/internal_normal_detector.joblib"
            ]
        }

        models_found = {}

        print("📁 Buscando modelos específicos...")
        for model_name, possible_paths in model_mappings.items():
            for path in possible_paths:
                if os.path.exists(path):
                    # Verificar que NO sea un scaler
                    if "scaler" not in path.lower():
                        models_found[model_name] = path
                        print(f"   ✅ {model_name}: {path}")
                        break

            if model_name not in models_found:
                print(f"   ❌ {model_name}: no encontrado")

        if not models_found:
            print("❌ No se encontraron modelos válidos!")
            sys.exit(1)

        # Cargar modelos encontrados
        print(f"\n🚀 CARGANDO {len(models_found)} MODELOS...")
        for model_name, model_path in models_found.items():
            self._load_single_model(model_name, model_path)

        print(f"\n✅ Sistema inicializado con {len(self.models)} modelos")

        if self.debug_mode:
            print(f"\n🐛 DEBUG MODE ACTIVADO")
            print(f"   Se mostrarán features detalladas para cada clasificación")

    def _load_single_model(self, model_name: str, model_path: str):
        """Carga un modelo individual con su scaler correspondiente"""
        try:
            print(f"   📥 Cargando {model_name} desde {model_path}...")

            # Cargar modelo
            model_data = joblib.load(model_path)

            # Extraer modelo y metadatos
            if isinstance(model_data, dict):
                # Formato con metadatos
                self.models[model_name] = model_data.get('model', model_data.get('estimator'))
                self.scalers[model_name] = model_data.get('scaler')
                self.feature_lists[model_name] = model_data.get('feature_names', [])

                print(f"      ✅ Modelo: {type(self.models[model_name]).__name__}")
                print(f"      ✅ Scaler: {'Incluido' if self.scalers[model_name] else 'No'}")
                print(f"      ✅ Features: {len(self.feature_lists[model_name])}")

                if self.debug_mode and self.feature_lists[model_name]:
                    print(f"      🐛 Lista de features esperadas:")
                    for i, feat in enumerate(self.feature_lists[model_name]):
                        print(f"         {i + 1:2d}. {feat}")

            else:
                # Solo el modelo
                self.models[model_name] = model_data
                self.scalers[model_name] = None
                self.feature_lists[model_name] = []

                print(f"      ✅ Modelo: {type(self.models[model_name]).__name__}")

                # Buscar scaler correspondiente
                base_name = os.path.basename(model_path).replace('.joblib', '')
                scaler_patterns = [
                    f"models/{base_name}_scaler.joblib",
                    f"models/{model_name}_scaler.joblib",
                    f"models/{model_name}_detector_scaler.joblib"
                ]

                for scaler_path in scaler_patterns:
                    if os.path.exists(scaler_path):
                        self.scalers[model_name] = joblib.load(scaler_path)
                        print(f"      ✅ Scaler encontrado: {scaler_path}")
                        break

                if not self.scalers[model_name]:
                    print(f"      ⚠️  Sin scaler - usando normalización básica")

            # Verificar que es un modelo válido
            if not hasattr(self.models[model_name], 'predict'):
                raise ValueError(f"El objeto cargado no es un modelo ML válido")

            self.available_models.append(model_name)

        except Exception as e:
            print(f"      ❌ Error cargando {model_name}: {e}")

    def _signal_handler(self, signum, frame):
        """Maneja Ctrl+C para parada limpia"""
        print(f"\n🛑 Señal recibida ({signum}). Parando sistema...")
        self.running = False
        sys.exit(0)

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

        # Normalizar flujo bidireccional
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

    def _is_source_direction(self, packet, flow_key: str) -> bool:
        """Determina dirección del paquete en el flujo"""
        if not packet.haslayer(IP):
            return True

        packet_src = packet[IP].src
        flow_src = flow_key.split(':')[0]
        return packet_src == flow_src

    def _process_packet(self, packet):
        """Procesa un paquete y actualiza estadísticas del flujo"""
        flow_key = self._get_flow_key(packet)
        if not flow_key:
            return

        current_time = time.time()
        flow = self.flows[flow_key]
        is_source = self._is_source_direction(packet, flow_key)

        # Inicializar flujo nuevo
        if flow.start_time == 0:
            self._initialize_flow(flow, packet, flow_key, current_time, is_source)

        # Actualizar estadísticas básicas
        self._update_basic_stats(flow, packet, is_source, current_time)

        # Procesar capas específicas
        self._process_tcp_layer(flow, packet, is_source)
        self._process_http_layer(flow, packet)
        self._process_ftp_layer(flow, packet)

        # Actualizar estadísticas globales
        self._update_global_stats(flow, current_time)

    def _initialize_flow(self, flow, packet, flow_key, current_time, is_source):
        """Inicializa un nuevo flujo"""
        flow.flow_id = flow_key
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
        else:
            flow.protocol = packet[IP].proto if packet.haslayer(IP) else 0

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
        if not packet.haslayer(TCP):
            return

        tcp_layer = packet[TCP]
        flow.tcp_flags_history.append(tcp_layer.flags)

        # Ventanas TCP
        if is_source:
            flow.src_windows.append(tcp_layer.window)
            if hasattr(tcp_layer, 'seq'):
                flow.src_seq_nums.append(tcp_layer.seq)
        else:
            flow.dst_windows.append(tcp_layer.window)
            if hasattr(tcp_layer, 'seq'):
                flow.dst_seq_nums.append(tcp_layer.seq)

        # Actualizar estado del flujo
        flow.current_state = self._determine_tcp_state(tcp_layer.flags)

    def _process_http_layer(self, flow, packet):
        """Procesa información HTTP"""
        try:
            if packet.haslayer(HTTPRequest):
                http_req = packet[HTTPRequest]
                if hasattr(http_req, 'Method'):
                    method = http_req.Method.decode('utf-8', errors='ignore')
                    flow.http_methods.append(method)
                    flow.transaction_depth += 1

            if packet.haslayer(HTTPResponse):
                http_resp = packet[HTTPResponse]
                if hasattr(http_resp, 'Status_Code'):
                    status = int(http_resp.Status_Code.decode('utf-8', errors='ignore'))
                    flow.http_responses.append(status)

                if hasattr(http_resp, 'Content_Length'):
                    length = int(http_resp.Content_Length.decode('utf-8', errors='ignore'))
                    flow.response_bodies.append(length)
                elif packet.haslayer(scapy.Raw):
                    # Estimar tamaño del body
                    body_size = len(packet[scapy.Raw])
                    flow.response_bodies.append(body_size)
        except Exception:
            pass

    def _process_ftp_layer(self, flow, packet):
        """Procesa información FTP"""
        if flow.src_port != 21 and flow.dst_port != 21:
            return

        try:
            if packet.haslayer(scapy.Raw):
                payload = bytes(packet[scapy.Raw]).decode('utf-8', errors='ignore')

                # Comandos FTP comunes
                ftp_commands = ['USER', 'PASS', 'LIST', 'RETR', 'STOR', 'PWD', 'CWD', 'QUIT']
                for cmd in ftp_commands:
                    if payload.upper().startswith(cmd):
                        flow.ftp_commands.append(cmd)
                        if cmd in ['USER', 'PASS']:
                            flow.ftp_login_attempts += 1
                        break
        except Exception:
            pass

    def _update_global_stats(self, flow, current_time):
        """Actualiza estadísticas globales para features de contexto"""
        # Contadores por servicio
        self.global_stats[f"srv_src_{flow.src_ip}"][flow.dst_port] += 1
        self.global_stats[f"srv_dst_{flow.dst_ip}"][flow.dst_port] += 1

        # Contadores por estado
        self.global_stats["state_ttl"][flow.current_state] += 1

        # Timestamps para cálculos temporales
        self.global_stats[f"dst_ltm_{flow.dst_ip}"]["last_time"] = current_time
        self.global_stats[f"src_ltm_{flow.src_ip}"]["last_time"] = current_time

        # Contadores de correlación
        self.global_stats[f"src_dport_{flow.src_ip}"][flow.dst_port] += 1
        self.global_stats[f"dst_src_{flow.dst_ip}"][flow.src_ip] += 1

        # Contadores de protocolos de aplicación
        if flow.http_methods:
            for method in set(flow.http_methods):
                self.global_stats["http_methods"][method] += 1

        if flow.ftp_commands:
            for cmd in set(flow.ftp_commands):
                self.global_stats["ftp_commands"][cmd] += 1

    def _determine_tcp_state(self, flags):
        """Determina estado TCP basado en flags"""
        if flags & 0x02:  # SYN
            if flags & 0x10:  # SYN+ACK
                return "SYN_ACK"
            return "SYN"
        elif flags & 0x01:  # FIN
            return "FIN"
        elif flags & 0x04:  # RST
            return "RST"
        elif flags & 0x10:  # ACK
            return "ESTABLISHED"
        else:
            return "OTHER"

    def _extract_all_features(self, flow_key: str) -> Dict:
        """Extrae las 26 features completas para un flujo"""
        flow = self.flows[flow_key]
        current_time = time.time()
        duration = max(flow.last_time - flow.start_time, 0.001)

        features = {}

        # 1-4: Features básicas críticas
        features['state'] = self._encode_tcp_state(flow.current_state)
        features['spkts'] = flow.spkts
        features['dpkts'] = flow.dpkts
        features['dbytes'] = flow.dbytes

        # 5-6: Features básicas adicionales
        features['id'] = abs(hash(flow_key)) % 65536
        features['service'] = flow.dst_port

        # 7-13: Features calculadas de flujo
        features['sload'] = (flow.sbytes * 8) / duration if duration > 0 else 0
        features['sloss'] = self._calculate_packet_loss(flow.src_seq_nums)
        features['dloss'] = self._calculate_packet_loss(flow.dst_seq_nums)
        features['swin'] = np.mean(flow.src_windows) if flow.src_windows else 0
        features['dwin'] = np.mean(flow.dst_windows) if flow.dst_windows else 0
        features['smean'] = self._calculate_inter_arrival_time(flow.src_timestamps)
        features['dmean'] = self._calculate_inter_arrival_time(flow.dst_timestamps)

        # 14-15: Features de aplicación
        features['trans_depth'] = flow.transaction_depth
        features['response_body_len'] = sum(flow.response_bodies) if flow.response_bodies else 0

        # 16-17: Features de detección específica
        features['is_ftp_login'] = 1 if flow.ftp_login_attempts > 0 else 0
        features['is_sm_ips_ports'] = self._detect_similar_ips_ports(flow)

        # 18-26: Features de contexto global
        features['ct_srv_src'] = len(self.global_stats[f"srv_src_{flow.src_ip}"])
        features['ct_srv_dst'] = len(self.global_stats[f"srv_dst_{flow.dst_ip}"])
        features['ct_state_ttl'] = self.global_stats["state_ttl"][flow.current_state]
        features['ct_dst_ltm'] = self._time_since_last(f"dst_ltm_{flow.dst_ip}", current_time)
        features['ct_src_ltm'] = self._time_since_last(f"src_ltm_{flow.src_ip}", current_time)
        features['ct_src_dport_ltm'] = self.global_stats[f"src_dport_{flow.src_ip}"][flow.dst_port]
        features['ct_dst_src_ltm'] = self.global_stats[f"dst_src_{flow.dst_ip}"][flow.src_ip]
        features['ct_flw_http_mthd'] = len(set(flow.http_methods))
        features['ct_ftp_cmd'] = len(set(flow.ftp_commands))

        return features

    def _encode_tcp_state(self, state: str) -> int:
        """Codifica estado TCP como entero"""
        state_map = {
            'SYN': 0, 'SYN_ACK': 1, 'ESTABLISHED': 2,
            'FIN': 3, 'RST': 4, 'OTHER': 5, 'NEW': 5
        }
        return state_map.get(state, 5)

    def _calculate_packet_loss(self, seq_nums: List[int]) -> int:
        """Calcula pérdidas de paquetes aproximadas"""
        if len(seq_nums) < 2:
            return 0

        gaps = 0
        for i in range(1, len(seq_nums)):
            expected = seq_nums[i - 1] + 1460  # MSS típico
            if seq_nums[i] > expected + 1460:  # Gap significativo
                gaps += 1

        return gaps

    def _calculate_inter_arrival_time(self, timestamps: List[float]) -> float:
        """Calcula tiempo inter-arrival promedio en milisegundos"""
        if len(timestamps) < 2:
            return 0

        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        return np.mean(intervals) * 1000 if intervals else 0

    def _detect_similar_ips_ports(self, flow: FlowStats) -> int:
        """Detecta IPs/puertos similares (heurística)"""
        # Misma subnet /24
        src_parts = flow.src_ip.split('.')
        dst_parts = flow.dst_ip.split('.')
        same_subnet = src_parts[:3] == dst_parts[:3]

        # Puertos consecutivos
        port_similar = abs(flow.src_port - flow.dst_port) < 10

        return 1 if (same_subnet or port_similar) else 0

    def _time_since_last(self, key: str, current_time: float) -> float:
        """Tiempo desde última actividad"""
        if "last_time" in self.global_stats[key]:
            return current_time - self.global_stats[key]["last_time"]
        return 0

    def _prepare_model_features(self, all_features: Dict, model_name: str) -> np.ndarray:
        """Prepara features específicas para cada modelo"""
        model_features = self.feature_lists[model_name]

        if not model_features:
            # Features por defecto si no hay metadatos
            if model_name == "attack":
                model_features = ['id', 'service', 'state', 'spkts', 'dpkts', 'sload', 'sloss', 'dloss',
                                  'swin', 'dwin', 'smean', 'dmean', 'trans_depth', 'response_body_len',
                                  'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
                                  'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd',
                                  'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports']
            else:  # web_normal, internal_normal
                model_features = ['state', 'spkts', 'dpkts', 'dbytes']

        # Extraer features para el modelo
        feature_values = []
        for feature in model_features:
            value = all_features.get(feature, 0)
            feature_values.append(value)

        if self.debug_mode:
            print(f"\n🐛 DEBUG - Features para modelo {model_name}:")
            for i, (feat_name, feat_value) in enumerate(zip(model_features, feature_values)):
                print(f"   {i + 1:2d}. {feat_name:<20} = {feat_value}")

        return np.array(feature_values).reshape(1, -1)

    def _classify_flow(self, flow_key: str) -> Dict:
        """Clasifica un flujo usando los modelos disponibles en cascada"""
        try:
            self.debug_count += 1

            # Extraer todas las features
            all_features = self._extract_all_features(flow_key)

            results = {
                'flow_id': flow_key,
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'final_classification': 'UNKNOWN',
                'confidence': 0.0,
                'layer': 0
            }

            if self.debug_mode:
                print(f"\n🐛 DEBUG #{self.debug_count} - Clasificando flujo: {flow_key[:50]}...")
                print(
                    f"   Flujo: {self.flows[flow_key].src_ip}:{self.flows[flow_key].src_port} → {self.flows[flow_key].dst_ip}:{self.flows[flow_key].dst_port}")
                print(f"   Paquetes: src={self.flows[flow_key].spkts}, dst={self.flows[flow_key].dpkts}")
                print(f"   Bytes: src={self.flows[flow_key].sbytes}, dst={self.flows[flow_key].dbytes}")
                print(f"   Estado: {self.flows[flow_key].current_state}")

            # CAPA 1: Detector de ataques (si disponible)
            if 'attack' in self.available_models:
                if self.debug_mode:
                    print(f"\n🔍 CAPA 1 - Probando detector de ataques...")

                attack_features = self._prepare_model_features(all_features, 'attack')
                original_features = attack_features.copy()

                if self.scalers['attack']:
                    attack_features = self.scalers['attack'].transform(attack_features)
                    if self.debug_mode:
                        print(f"   🔄 Features escaladas aplicadas")

                attack_proba = self.models['attack'].predict_proba(attack_features)[0]
                attack_pred = self.models['attack'].predict(attack_features)[0]

                if self.debug_mode:
                    print(f"   📊 Probabilidades: {attack_proba}")
                    print(f"   🎯 Predicción: {attack_pred} ({'ATAQUE' if attack_pred == 1 else 'NO ATAQUE'})")
                    print(f"   💪 Confianza: {max(attack_proba):.3f}")

                if attack_pred == 1:  # Es ataque
                    results['final_classification'] = 'ATAQUE'
                    results['confidence'] = max(attack_proba)
                    results['layer'] = 1

                    if self.debug_mode:
                        print(f"   ⚠️  CLASIFICADO COMO ATAQUE")
                        # Analizar por qué se clasificó como ataque
                        print(f"   🔍 Análisis del flujo:")
                        print(f"      - Puerto destino: {self.flows[flow_key].dst_port}")
                        print(f"      - Protocolo: {self.flows[flow_key].protocol}")
                        print(
                            f"      - Duración: {self.flows[flow_key].last_time - self.flows[flow_key].start_time:.2f}s")

                    return results

            # Si llegamos aquí, NO es ataque
            if self.debug_mode:
                print(f"   ✅ NO es ataque, continuando a capa 2...")

            # CAPA 2: Detector web normal (si disponible)
            if 'web_normal' in self.available_models:
                if self.debug_mode:
                    print(f"\n🔍 CAPA 2 - Probando detector web normal...")

                web_features = self._prepare_model_features(all_features, 'web_normal')
                if self.scalers['web_normal']:
                    web_features = self.scalers['web_normal'].transform(web_features)

                web_proba = self.models['web_normal'].predict_proba(web_features)[0]
                web_pred = self.models['web_normal'].predict(web_features)[0]

                if self.debug_mode:
                    print(f"   📊 Probabilidades: {web_proba}")
                    print(f"   🎯 Predicción: {web_pred} ({'WEB NORMAL' if web_pred == 1 else 'NO WEB NORMAL'})")

                if web_pred == 1:  # Es tráfico web normal
                    results['final_classification'] = 'WEB_NORMAL'
                    results['confidence'] = max(web_proba)
                    results['layer'] = 2
                    return results

            # CAPA 3: Detector interno normal (si disponible)
            if 'internal_normal' in self.available_models:
                if self.debug_mode:
                    print(f"\n🔍 CAPA 3 - Probando detector interno normal...")

                internal_features = self._prepare_model_features(all_features, 'internal_normal')
                if self.scalers['internal_normal']:
                    internal_features = self.scalers['internal_normal'].transform(internal_features)

                internal_proba = self.models['internal_normal'].predict_proba(internal_features)[0]
                internal_pred = self.models['internal_normal'].predict(internal_features)[0]

                if self.debug_mode:
                    print(f"   📊 Probabilidades: {internal_proba}")
                    print(
                        f"   🎯 Predicción: {internal_pred} ({'INTERNO NORMAL' if internal_pred == 1 else 'NO INTERNO NORMAL'})")

                if internal_pred == 1:  # Es tráfico interno normal
                    results['final_classification'] = 'INTERNO_NORMAL'
                    results['confidence'] = max(internal_proba)
                    results['layer'] = 3
                else:
                    results['final_classification'] = 'ANOMALO_DESCONOCIDO'
                    results['confidence'] = 1.0 - max(internal_proba)
                    results['layer'] = 3
            else:
                # Sin modelo de internal_normal, clasificar como desconocido
                results['final_classification'] = 'SIN_CLASIFICAR'
                results['confidence'] = 0.5
                results['layer'] = 3

            return results

        except Exception as e:
            print(f"❌ Error clasificando flujo {flow_key}: {e}")
            if self.debug_mode:
                import traceback
                traceback.print_exc()
            return {
                'flow_id': flow_key,
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'final_classification': 'ERROR',
                'confidence': 0.0,
                'layer': 0
            }

    def _classification_worker(self):
        """Worker thread que clasifica flujos periódicamente"""
        while self.running:
            try:
                current_time = time.time()

                # Clasificar flujos que tengan suficiente actividad
                flows_to_classify = []
                for flow_key, flow in self.flows.items():
                    # Clasificar si ha pasado el intervalo y tiene suficientes paquetes
                    time_since_last = current_time - flow.last_classification_time
                    if (time_since_last >= self.classification_interval and
                            flow.spkts + flow.dpkts >= 3):  # Mínimo 3 paquetes
                        flows_to_classify.append(flow_key)

                if flows_to_classify:
                    # En debug mode, solo clasificar los primeros 3 flujos para no saturar
                    if self.debug_mode:
                        flows_to_classify = flows_to_classify[:3]

                    print(f"\n🎯 Clasificando {len(flows_to_classify)} flujos...")

                    for flow_key in flows_to_classify:
                        result = self._classify_flow(flow_key)

                        # Actualizar estadísticas
                        self.classification_stats[result['final_classification']] += 1
                        self.flows[flow_key].last_classification = result['final_classification']
                        self.flows[flow_key].last_classification_time = current_time

                        # Mostrar resultado
                        confidence_str = f"{result['confidence']:.3f}"
                        print(f"\n🎯 RESULTADO: {result['final_classification']:<18} | "
                              f"Conf: {confidence_str} | Capa: {result['layer']} | "
                              f"{result['timestamp']}")

                        # Alerta especial para ataques
                        if result['final_classification'] == 'ATAQUE':
                            print(f"   🚨 ALERTA DE ATAQUE DETECTADA! 🚨")
                            if self.debug_mode:
                                print(f"   🔍 REVISAR: ¿Es realmente un ataque este flujo?")

                time.sleep(1)  # Check cada segundo

            except Exception as e:
                print(f"❌ Error en clasificador: {e}")
                time.sleep(1)

    def _cleanup_worker(self):
        """Worker thread para limpieza de flujos antiguos"""
        while self.running:
            try:
                current_time = time.time()
                cutoff_time = current_time - self.window_seconds

                # Limpiar flujos antiguos
                old_flows = [k for k, v in self.flows.items()
                             if v.last_time < cutoff_time]

                for flow_key in old_flows:
                    del self.flows[flow_key]

                if old_flows:
                    print(f"🧹 Limpiados {len(old_flows)} flujos antiguos")

                time.sleep(30)  # Limpiar cada 30 segundos

            except Exception as e:
                print(f"❌ Error en limpieza: {e}")
                time.sleep(30)

    def _stats_worker(self):
        """Worker thread para mostrar estadísticas periódicas"""
        while self.running:
            try:
                time.sleep(20)  # Estadísticas cada 20 segundos

                print(f"\n📊 ESTADÍSTICAS ({datetime.now().strftime('%H:%M:%S')})")
                print(f"   Flujos activos: {len(self.flows)}")
                print(f"   Modelos activos: {', '.join(self.available_models)}")

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
        print(f"\n🚀 INICIANDO DEBUG ML SNIFFER")
        print(f"   Modelos disponibles: {', '.join(self.available_models)}")
        print(f"   Ventana de flujo: {self.window_seconds}s")
        print(f"   Intervalo de clasificación: {self.classification_interval}s")
        print(f"   Debug mode: {'ON' if self.debug_mode else 'OFF'}")
        print(f"   Interfaz: {interface if interface else 'auto'}")
        print(f"   Presiona Ctrl+C para parar\n")

        if not self.available_models:
            print("❌ No hay modelos disponibles. No se puede iniciar.")
            return

        self.running = True

        # Iniciar threads de trabajo
        self.classifier_thread = threading.Thread(target=self._classification_worker, daemon=True)
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.stats_thread = threading.Thread(target=self._stats_worker, daemon=True)

        self.classifier_thread.start()
        self.cleanup_thread.start()
        self.stats_thread.start()

        # Iniciar captura de paquetes
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
    print("🐛 Debug ML Network Sniffer v1.0")
    print("=================================")

    sniffer = DebugMLSniffer(
        window_seconds=20,  # Ventana de 20 segundos
        classification_interval=10,  # Clasificar cada 10 segundos
        debug_mode=True  # MODO DEBUG ACTIVADO
    )

    try:
        sniffer.start_capture()
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()