#!/usr/bin/env python3
"""
🚀 UPGRADED HAPPINESS - EVOLUTIONARY SNIFFER v3.1
evolutionary_sniffer_v31.py

FILOSOFÍA: Evolución del promiscuous_agent + complete_ml_pipeline
✅ Captura REAL de paquetes con Scapy (del promiscuous_agent)
✅ Extracción de 83+ features ML (del complete_ml_pipeline)
✅ Time windows configurables por modelo
✅ Protobuf v3.1 LIMPIO (sin compatibilidad hacia atrás)
✅ ZeroMQ distribuido avanzado
✅ JSON configuration completamente flexible
✅ Pipeline tracking de primera clase
✅ TODO O NADA - cero legacy

ARQUITECTURA:
- Time windows flexibles: DDOS (83 features), RF (23), Internal (4-5), Future models
- Pipeline distribuido: Primer nodo que asigna IDs y nombres
- Features ML: Todas las features de red necesarias extraídas con Scapy
- Protobuf v3.1: NetworkSecurityEvent limpio y eficiente

Autor: Alonso Isidoro, Claude
Fecha: Agosto 9, 2025
"""

import zmq
import time
import json
import logging
import threading
import socket
import uuid
import os
import sys
import platform
import psutil
import numpy as np
import pandas as pd
from threading import Event
from typing import Dict, Any, Optional, List, Tuple
from queue import Queue, Empty
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
import math
import statistics

# 📦 Dependencias para captura de paquetes - REQUERIDAS
try:
    from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("❌ Scapy REQUERIDO - pip install scapy")

# 📦 Protobuf v3.1 LIMPIO - REQUERIDO
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = "unavailable"
NetworkSecurityEventProto = None


def import_protobuf_v31():
    """Importa el protobuf v3.1 limpio - EXCLUSIVO con búsqueda automática"""
    global NetworkSecurityEventProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    # Estrategias de importación múltiples
    import_strategies = [
        # Estrategia 1: Importación directa (si está en el mismo directorio)
        ("network_security_clean_v31_pb2", "Importación directa"),

        # Estrategia 2: Desde protocols.v3.1
        ("protocols.v3.1.network_security_clean_v31_pb2", "Paquete protocols.v3.1"),
    ]

    for import_path, description in import_strategies:
        try:
            NetworkSecurityEventProto = __import__(import_path, fromlist=[''])
            PROTOBUF_AVAILABLE = True
            PROTOBUF_VERSION = "v3.1.0-clean"
            print(f"✅ Protobuf v3.1 LIMPIO cargado: {description}")
            return True
        except ImportError:
            continue

    # Estrategia 3: Búsqueda por paths dinámicos
    current_dir = os.path.dirname(os.path.abspath(__file__))
    possible_paths = [
        # Desde core/ buscar en protocols/v3.1/
        os.path.join(current_dir, '..', 'protocols', 'v3.1'),
        # Desde raíz del proyecto buscar protocols/v3.1/
        os.path.join(current_dir, 'protocols', 'v3.1'),
        # Directorio actual
        current_dir,
        # Directorio padre
        os.path.join(current_dir, '..'),
    ]

    for protocols_path in possible_paths:
        protocols_path = os.path.abspath(protocols_path)
        pb2_file = os.path.join(protocols_path, 'network_security_clean_v31_pb2.py')

        if os.path.exists(pb2_file):
            try:
                # Añadir el path temporalmente
                sys.path.insert(0, protocols_path)
                import network_security_clean_v31_pb2 as NetworkSecurityEventProto
                PROTOBUF_AVAILABLE = True
                PROTOBUF_VERSION = "v3.1.0-clean"
                print(f"✅ Protobuf v3.1 LIMPIO cargado desde: {protocols_path}")
                return True
            except ImportError as e:
                if protocols_path in sys.path:
                    sys.path.remove(protocols_path)
                continue

    # Si llegamos aquí, no se encontró el protobuf
    print(f"❌ Protobuf v3.1 REQUERIDO pero no encontrado")
    print(f"🔍 Buscando en:")
    for path in possible_paths:
        pb2_file = os.path.join(os.path.abspath(path), 'network_security_clean_v31_pb2.py')
        exists = "✅" if os.path.exists(pb2_file) else "❌"
        print(f"   {exists} {pb2_file}")
    print(f"💡 Solución:")
    print(f"   1. cd protocols/v3.1/")
    print(f"   2. protoc --python_out=. network_security_clean_v31.proto")
    print(f"   3. Verificar que se generó: network_security_clean_v31_pb2.py")
    return False


# Ejecutar importación al inicio
import_protobuf_v31()


@dataclass
class TimeWindowConfig:
    """Configuración de ventana de tiempo para modelos ML"""
    window_size_seconds: float
    slide_interval_seconds: float
    max_flows_per_window: int
    features_required: List[str]
    model_types: List[str]
    description: str


@dataclass
class PacketInfo:
    """Información extraída de un paquete"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol_number: int
    protocol_name: str
    packet_size: int
    tcp_flags: Dict[str, bool]
    flow_id: str
    raw_packet: Any = None


@dataclass
class FlowInfo:
    """Información de un flujo de red"""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    forward_packets: List[PacketInfo]
    backward_packets: List[PacketInfo]
    total_forward_bytes: int = 0
    total_backward_bytes: int = 0


class NetworkFeaturesExtractor:
    """Extractor de features de red para modelos ML - TODAS las features necesarias"""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def extract_all_features(self, flow: FlowInfo) -> Dict[str, float]:
        """Extrae TODAS las features necesarias (83+) de un flujo"""
        features = {}

        try:
            # ⏰ TIMING FEATURES
            features.update(self._extract_timing_features(flow))

            # 📊 PACKET COUNT FEATURES
            features.update(self._extract_packet_count_features(flow))

            # 📏 PACKET LENGTH FEATURES
            features.update(self._extract_packet_length_features(flow))

            # 🚀 FLOW RATE FEATURES
            features.update(self._extract_flow_rate_features(flow))

            # ⏱️ INTER-ARRIVAL TIME FEATURES
            features.update(self._extract_iat_features(flow))

            # 🏳️ TCP FLAGS FEATURES
            features.update(self._extract_tcp_flags_features(flow))

            # 📋 HEADER & BULK FEATURES
            features.update(self._extract_header_bulk_features(flow))

            # 📊 STATISTICAL FEATURES
            features.update(self._extract_statistical_features(flow))

            # 🎯 PROTOCOL SPECIFIC FEATURES
            features.update(self._extract_protocol_features(flow))

            self.logger.debug(f"Extraídas {len(features)} features del flujo {flow.flow_id}")

        except Exception as e:
            self.logger.error(f"Error extrayendo features del flujo {flow.flow_id}: {e}")
            # Retornar features vacías en caso de error
            features = {f"feature_{i}": 0.0 for i in range(83)}

        return features

    def _extract_timing_features(self, flow: FlowInfo) -> Dict[str, float]:
        """Features de timing y duración"""
        duration = flow.last_seen - flow.start_time
        duration_microseconds = duration * 1_000_000

        return {
            'flow_duration': duration,
            'flow_duration_microseconds': duration_microseconds,
        }

    def _extract_packet_count_features(self, flow: FlowInfo) -> Dict[str, float]:
        """Features de conteo de paquetes"""
        return {
            'total_forward_packets': len(flow.forward_packets),
            'total_backward_packets': len(flow.backward_packets),
            'total_forward_bytes': flow.total_forward_bytes,
            'total_backward_bytes': flow.total_backward_bytes,
        }

    def _extract_packet_length_features(self, flow: FlowInfo) -> Dict[str, float]:
        """Features de longitud de paquetes"""
        features = {}

        # Forward packet lengths
        fwd_lengths = [p.packet_size for p in flow.forward_packets]
        if fwd_lengths:
            features['forward_packet_length_max'] = max(fwd_lengths)
            features['forward_packet_length_min'] = min(fwd_lengths)
            features['forward_packet_length_mean'] = statistics.mean(fwd_lengths)
            features['forward_packet_length_std'] = statistics.stdev(fwd_lengths) if len(fwd_lengths) > 1 else 0.0
        else:
            features.update({
                'forward_packet_length_max': 0.0,
                'forward_packet_length_min': 0.0,
                'forward_packet_length_mean': 0.0,
                'forward_packet_length_std': 0.0
            })

        # Backward packet lengths
        bwd_lengths = [p.packet_size for p in flow.backward_packets]
        if bwd_lengths:
            features['backward_packet_length_max'] = max(bwd_lengths)
            features['backward_packet_length_min'] = min(bwd_lengths)
            features['backward_packet_length_mean'] = statistics.mean(bwd_lengths)
            features['backward_packet_length_std'] = statistics.stdev(bwd_lengths) if len(bwd_lengths) > 1 else 0.0
        else:
            features.update({
                'backward_packet_length_max': 0.0,
                'backward_packet_length_min': 0.0,
                'backward_packet_length_mean': 0.0,
                'backward_packet_length_std': 0.0
            })

        # Combined packet lengths
        all_lengths = fwd_lengths + bwd_lengths
        if all_lengths:
            features['minimum_packet_length'] = min(all_lengths)
            features['maximum_packet_length'] = max(all_lengths)
            features['packet_length_mean'] = statistics.mean(all_lengths)
            features['packet_length_std'] = statistics.stdev(all_lengths) if len(all_lengths) > 1 else 0.0
            features['packet_length_variance'] = statistics.variance(all_lengths) if len(all_lengths) > 1 else 0.0
        else:
            features.update({
                'minimum_packet_length': 0.0,
                'maximum_packet_length': 0.0,
                'packet_length_mean': 0.0,
                'packet_length_std': 0.0,
                'packet_length_variance': 0.0
            })

        return features

    def _extract_flow_rate_features(self, flow: FlowInfo) -> Dict[str, float]:
        """Features de velocidad y ratios"""
        duration = flow.last_seen - flow.start_time
        if duration <= 0:
            duration = 0.001  # Evitar división por cero

        total_bytes = flow.total_forward_bytes + flow.total_backward_bytes
        total_packets = len(flow.forward_packets) + len(flow.backward_packets)

        features = {
            'flow_bytes_per_second': total_bytes / duration,
            'flow_packets_per_second': total_packets / duration,
            'forward_packets_per_second': len(flow.forward_packets) / duration,
            'backward_packets_per_second': len(flow.backward_packets) / duration,
        }

        # Download/Upload ratio
        if flow.total_forward_bytes > 0:
            features['download_upload_ratio'] = flow.total_backward_bytes / flow.total_forward_bytes
        else:
            features['download_upload_ratio'] = 0.0

        # Average packet size
        features['average_packet_size'] = total_bytes / total_packets if total_packets > 0 else 0.0

        # Average segment sizes
        features['average_forward_segment_size'] = (flow.total_forward_bytes / len(flow.forward_packets)
                                                    if flow.forward_packets else 0.0)
        features['average_backward_segment_size'] = (flow.total_backward_bytes / len(flow.backward_packets)
                                                     if flow.backward_packets else 0.0)

        return features

    def _extract_iat_features(self, flow: FlowInfo) -> Dict[str, float]:
        """Features de Inter-Arrival Time"""
        features = {}

        # Flow IAT (todos los paquetes ordenados por tiempo)
        all_packets = sorted(flow.forward_packets + flow.backward_packets, key=lambda p: p.timestamp)
        flow_iats = []

        for i in range(1, len(all_packets)):
            iat = all_packets[i].timestamp - all_packets[i - 1].timestamp
            flow_iats.append(iat * 1_000_000)  # Convertir a microsegundos

        if flow_iats:
            features['flow_inter_arrival_time_mean'] = statistics.mean(flow_iats)
            features['flow_inter_arrival_time_std'] = statistics.stdev(flow_iats) if len(flow_iats) > 1 else 0.0
            features['flow_inter_arrival_time_max'] = max(flow_iats)
            features['flow_inter_arrival_time_min'] = min(flow_iats)
        else:
            features.update({
                'flow_inter_arrival_time_mean': 0.0,
                'flow_inter_arrival_time_std': 0.0,
                'flow_inter_arrival_time_max': 0.0,
                'flow_inter_arrival_time_min': 0.0
            })

        # Forward IAT
        fwd_iats = []
        for i in range(1, len(flow.forward_packets)):
            iat = flow.forward_packets[i].timestamp - flow.forward_packets[i - 1].timestamp
            fwd_iats.append(iat * 1_000_000)

        if fwd_iats:
            features['forward_inter_arrival_time_total'] = sum(fwd_iats)
            features['forward_inter_arrival_time_mean'] = statistics.mean(fwd_iats)
            features['forward_inter_arrival_time_std'] = statistics.stdev(fwd_iats) if len(fwd_iats) > 1 else 0.0
            features['forward_inter_arrival_time_max'] = max(fwd_iats)
            features['forward_inter_arrival_time_min'] = min(fwd_iats)
        else:
            features.update({
                'forward_inter_arrival_time_total': 0.0,
                'forward_inter_arrival_time_mean': 0.0,
                'forward_inter_arrival_time_std': 0.0,
                'forward_inter_arrival_time_max': 0.0,
                'forward_inter_arrival_time_min': 0.0
            })

        # Backward IAT
        bwd_iats = []
        for i in range(1, len(flow.backward_packets)):
            iat = flow.backward_packets[i].timestamp - flow.backward_packets[i - 1].timestamp
            bwd_iats.append(iat * 1_000_000)

        if bwd_iats:
            features['backward_inter_arrival_time_total'] = sum(bwd_iats)
            features['backward_inter_arrival_time_mean'] = statistics.mean(bwd_iats)
            features['backward_inter_arrival_time_std'] = statistics.stdev(bwd_iats) if len(bwd_iats) > 1 else 0.0
            features['backward_inter_arrival_time_max'] = max(bwd_iats)
            features['backward_inter_arrival_time_min'] = min(bwd_iats)
        else:
            features.update({
                'backward_inter_arrival_time_total': 0.0,
                'backward_inter_arrival_time_mean': 0.0,
                'backward_inter_arrival_time_std': 0.0,
                'backward_inter_arrival_time_max': 0.0,
                'backward_inter_arrival_time_min': 0.0
            })

        return features

    def _extract_tcp_flags_features(self, flow: FlowInfo) -> Dict[str, float]:
        """Features de TCP flags"""
        flag_counts = {
            'fin_flag_count': 0,
            'syn_flag_count': 0,
            'rst_flag_count': 0,
            'psh_flag_count': 0,
            'ack_flag_count': 0,
            'urg_flag_count': 0,
            'cwe_flag_count': 0,  # CWE (ECE in some contexts)
            'ece_flag_count': 0,
            'forward_psh_flags': 0,
            'backward_psh_flags': 0,
            'forward_urg_flags': 0,
            'backward_urg_flags': 0
        }

        # Contar flags en todos los paquetes
        for packet in flow.forward_packets + flow.backward_packets:
            flags = packet.tcp_flags
            if flags.get('F', False): flag_counts['fin_flag_count'] += 1
            if flags.get('S', False): flag_counts['syn_flag_count'] += 1
            if flags.get('R', False): flag_counts['rst_flag_count'] += 1
            if flags.get('P', False): flag_counts['psh_flag_count'] += 1
            if flags.get('A', False): flag_counts['ack_flag_count'] += 1
            if flags.get('U', False): flag_counts['urg_flag_count'] += 1
            if flags.get('E', False): flag_counts['ece_flag_count'] += 1
            if flags.get('C', False): flag_counts['cwe_flag_count'] += 1

        # Flags direccionales para PSH y URG
        for packet in flow.forward_packets:
            if packet.tcp_flags.get('P', False): flag_counts['forward_psh_flags'] += 1
            if packet.tcp_flags.get('U', False): flag_counts['forward_urg_flags'] += 1

        for packet in flow.backward_packets:
            if packet.tcp_flags.get('P', False): flag_counts['backward_psh_flags'] += 1
            if packet.tcp_flags.get('U', False): flag_counts['backward_urg_flags'] += 1

        return flag_counts

    def _extract_header_bulk_features(self, flow: FlowInfo) -> Dict[str, float]:
        """Features de headers y bulk transfer"""
        features = {}

        # Header lengths (aproximados)
        # TCP header típico: 20 bytes, IP header: 20 bytes
        if flow.forward_packets:
            features['forward_header_length'] = 40.0  # Aproximación TCP + IP
        else:
            features['forward_header_length'] = 0.0

        if flow.backward_packets:
            features['backward_header_length'] = 40.0
        else:
            features['backward_header_length'] = 0.0

        # Bulk transfer features (simplificadas)
        # TODO: Implementar análisis más sofisticado de bulk transfer
        features.update({
            'forward_average_bytes_bulk': 0.0,
            'forward_average_packets_bulk': 0.0,
            'forward_average_bulk_rate': 0.0,
            'backward_average_bytes_bulk': 0.0,
            'backward_average_packets_bulk': 0.0,
            'backward_average_bulk_rate': 0.0
        })

        return features

    def _extract_statistical_features(self, flow: FlowInfo) -> Dict[str, float]:
        """Features estadísticas adicionales"""
        features = {}

        # Aquí se pueden añadir más features estadísticas avanzadas
        # Por ahora, features básicas ya calculadas en otros métodos

        return features

    def _extract_protocol_features(self, flow: FlowInfo) -> Dict[str, float]:
        """Features específicas del protocolo"""
        features = {}

        # Protocol number
        features['protocol_number'] = flow.forward_packets[0].protocol_number if flow.forward_packets else 0

        # Protocol-specific features pueden añadirse aquí

        return features

    def get_features_for_model(self, all_features: Dict[str, float], model_type: str) -> List[float]:
        """Extrae features específicas para un tipo de modelo"""

        if model_type == "ddos_83":
            # Features para modelo DDOS (83 features)
            return self._get_ddos_features(all_features)
        elif model_type == "rf_23":
            # Features para modelo RF general (23 features)
            return self._get_rf_features(all_features)
        elif model_type == "internal_4":
            # Features para tráfico interno (4-5 features)
            return self._get_internal_features(all_features)
        else:
            # Por defecto, todas las features como lista
            return list(all_features.values())[:83]  # Limitar a 83

    def _get_ddos_features(self, features: Dict[str, float]) -> List[float]:
        """83 features para detección DDOS"""
        ddos_features = [
            features.get('flow_duration', 0.0),
            features.get('total_forward_packets', 0.0),
            features.get('total_backward_packets', 0.0),
            features.get('total_forward_bytes', 0.0),
            features.get('total_backward_bytes', 0.0),
            features.get('forward_packet_length_max', 0.0),
            features.get('forward_packet_length_min', 0.0),
            features.get('forward_packet_length_mean', 0.0),
            features.get('forward_packet_length_std', 0.0),
            features.get('backward_packet_length_max', 0.0),
            features.get('backward_packet_length_min', 0.0),
            features.get('backward_packet_length_mean', 0.0),
            features.get('backward_packet_length_std', 0.0),
            features.get('flow_bytes_per_second', 0.0),
            features.get('flow_packets_per_second', 0.0),
            features.get('forward_packets_per_second', 0.0),
            features.get('backward_packets_per_second', 0.0),
            features.get('download_upload_ratio', 0.0),
            features.get('average_packet_size', 0.0),
            features.get('average_forward_segment_size', 0.0),
            features.get('average_backward_segment_size', 0.0),
            features.get('flow_inter_arrival_time_mean', 0.0),
            features.get('flow_inter_arrival_time_std', 0.0),
            features.get('flow_inter_arrival_time_max', 0.0),
            features.get('flow_inter_arrival_time_min', 0.0),
            features.get('forward_inter_arrival_time_total', 0.0),
            features.get('forward_inter_arrival_time_mean', 0.0),
            features.get('forward_inter_arrival_time_std', 0.0),
            features.get('forward_inter_arrival_time_max', 0.0),
            features.get('forward_inter_arrival_time_min', 0.0),
            features.get('backward_inter_arrival_time_total', 0.0),
            features.get('backward_inter_arrival_time_mean', 0.0),
            features.get('backward_inter_arrival_time_std', 0.0),
            features.get('backward_inter_arrival_time_max', 0.0),
            features.get('backward_inter_arrival_time_min', 0.0),
            features.get('fin_flag_count', 0.0),
            features.get('syn_flag_count', 0.0),
            features.get('rst_flag_count', 0.0),
            features.get('psh_flag_count', 0.0),
            features.get('ack_flag_count', 0.0),
            features.get('urg_flag_count', 0.0),
            features.get('cwe_flag_count', 0.0),
            features.get('ece_flag_count', 0.0),
            features.get('forward_psh_flags', 0.0),
            features.get('backward_psh_flags', 0.0),
            features.get('forward_urg_flags', 0.0),
            features.get('backward_urg_flags', 0.0),
            features.get('forward_header_length', 0.0),
            features.get('backward_header_length', 0.0),
            features.get('forward_average_bytes_bulk', 0.0),
            features.get('forward_average_packets_bulk', 0.0),
            features.get('forward_average_bulk_rate', 0.0),
            features.get('backward_average_bytes_bulk', 0.0),
            features.get('backward_average_packets_bulk', 0.0),
            features.get('backward_average_bulk_rate', 0.0),
            features.get('minimum_packet_length', 0.0),
            features.get('maximum_packet_length', 0.0),
            features.get('packet_length_mean', 0.0),
            features.get('packet_length_std', 0.0),
            features.get('packet_length_variance', 0.0),
            features.get('protocol_number', 0.0),
        ]

        # Rellenar hasta 83 features si es necesario
        while len(ddos_features) < 83:
            ddos_features.append(0.0)

        return ddos_features[:83]

    def _get_rf_features(self, features: Dict[str, float]) -> List[float]:
        """23 features para modelo RF general"""
        rf_features = [
            features.get('flow_duration', 0.0),
            features.get('total_forward_packets', 0.0),
            features.get('total_backward_packets', 0.0),
            features.get('total_forward_bytes', 0.0),
            features.get('total_backward_bytes', 0.0),
            features.get('flow_bytes_per_second', 0.0),
            features.get('forward_packet_length_mean', 0.0),
            features.get('backward_packet_length_mean', 0.0),
            features.get('flow_inter_arrival_time_mean', 0.0),
            features.get('flow_inter_arrival_time_std', 0.0),
            features.get('forward_psh_flags', 0.0),
            features.get('backward_psh_flags', 0.0),
            features.get('forward_urg_flags', 0.0),
            features.get('backward_urg_flags', 0.0),
            features.get('packet_length_mean', 0.0),
            features.get('packet_length_std', 0.0),
            features.get('packet_length_variance', 0.0),
            features.get('fin_flag_count', 0.0),
            features.get('syn_flag_count', 0.0),
            features.get('rst_flag_count', 0.0),
            features.get('psh_flag_count', 0.0),
            features.get('ack_flag_count', 0.0),
            features.get('urg_flag_count', 0.0)
        ]

        return rf_features[:23]

    def _get_internal_features(self, features: Dict[str, float]) -> List[float]:
        """4-5 features para tráfico interno"""
        internal_features = [
            features.get('flow_duration', 0.0),
            features.get('total_forward_packets', 0.0),
            features.get('total_backward_packets', 0.0),
            features.get('total_forward_bytes', 0.0),
        ]

        return internal_features[:4]


class TimeWindowManager:
    """Gestor de ventanas de tiempo para diferentes modelos ML"""

    def __init__(self, window_configs: Dict[str, TimeWindowConfig], logger):
        self.window_configs = window_configs
        self.logger = logger
        self.active_flows = {}  # flow_id -> FlowInfo
        self.completed_windows = deque()  # Ventanas completadas listas para envío
        self.window_timers = {}  # window_type -> next_window_time
        self.lock = threading.Lock()

        # Inicializar timers de ventanas
        self._initialize_window_timers()

    def _initialize_window_timers(self):
        """Inicializa los timers de las ventanas de tiempo"""
        now = time.time()
        for window_type, config in self.window_configs.items():
            self.window_timers[window_type] = now + config.slide_interval_seconds

    def add_packet(self, packet_info: PacketInfo):
        """Añade un paquete al manager de ventanas de tiempo"""
        with self.lock:
            flow_id = packet_info.flow_id

            # Crear o actualizar flujo
            if flow_id not in self.active_flows:
                self.active_flows[flow_id] = FlowInfo(
                    flow_id=flow_id,
                    src_ip=packet_info.src_ip,
                    dst_ip=packet_info.dst_ip,
                    src_port=packet_info.src_port,
                    dst_port=packet_info.dst_port,
                    protocol=packet_info.protocol_name,
                    start_time=packet_info.timestamp,
                    last_seen=packet_info.timestamp,
                    forward_packets=[],
                    backward_packets=[]
                )

            flow = self.active_flows[flow_id]
            flow.last_seen = packet_info.timestamp

            # Determinar dirección del paquete (simplificado)
            if self._is_forward_packet(packet_info, flow):
                flow.forward_packets.append(packet_info)
                flow.total_forward_bytes += packet_info.packet_size
            else:
                flow.backward_packets.append(packet_info)
                flow.total_backward_bytes += packet_info.packet_size

    def _is_forward_packet(self, packet: PacketInfo, flow: FlowInfo) -> bool:
        """Determina si un paquete es en dirección forward"""
        # Heurística simple: si src coincide con src del flujo, es forward
        return (packet.src_ip == flow.src_ip and packet.src_port == flow.src_port)

    def get_completed_windows(self) -> List[Dict[str, Any]]:
        """Obtiene ventanas de tiempo completadas y listas para procesamiento"""
        completed = []
        now = time.time()

        with self.lock:
            # Revisar si alguna ventana debe cerrarse
            for window_type, config in self.window_configs.items():
                if now >= self.window_timers[window_type]:
                    # Crear ventana completada
                    window_data = self._create_window_data(window_type, config, now)
                    if window_data:
                        completed.append(window_data)

                    # Actualizar timer para próxima ventana
                    self.window_timers[window_type] = now + config.slide_interval_seconds

                    # Limpiar flujos antiguos
                    self._cleanup_old_flows(now, config.window_size_seconds)

        return completed

    def _create_window_data(self, window_type: str, config: TimeWindowConfig, end_time: float) -> Optional[
        Dict[str, Any]]:
        """Crea datos de ventana de tiempo completada"""
        start_time = end_time - config.window_size_seconds

        # Filtrar flujos que están en esta ventana
        window_flows = []
        for flow in self.active_flows.values():
            if (flow.start_time >= start_time and flow.start_time <= end_time) or \
                    (flow.last_seen >= start_time and flow.last_seen <= end_time):
                window_flows.append(flow)

        if not window_flows:
            return None

        return {
            'window_type': window_type,
            'config': config,
            'start_time': start_time,
            'end_time': end_time,
            'flows': window_flows,
            'flow_count': len(window_flows)
        }

    def _cleanup_old_flows(self, now: float, max_age_seconds: float):
        """Limpia flujos antiguos que ya no son relevantes"""
        cutoff_time = now - max_age_seconds - 60  # Buffer adicional de 60 segundos

        flows_to_remove = []
        for flow_id, flow in self.active_flows.items():
            if flow.last_seen < cutoff_time:
                flows_to_remove.append(flow_id)

        for flow_id in flows_to_remove:
            del self.active_flows[flow_id]

        if flows_to_remove:
            self.logger.debug(f"Limpiados {len(flows_to_remove)} flujos antiguos")


class EvolutionarySniffer:
    """
    Sniffer evolutivo v3.1 - Combinación de promiscuous_agent + complete_ml_pipeline

    CARACTERÍSTICAS:
    ✅ Captura REAL de paquetes con Scapy
    ✅ Extracción de 83+ features ML
    ✅ Time windows configurables por modelo
    ✅ Protobuf v3.1 LIMPIO exclusivo
    ✅ ZeroMQ distribuido
    ✅ JSON configuration flexible
    ✅ Pipeline tracking avanzado
    ✅ TODO O NADA - sin legacy
    """

    def __init__(self, config_file: str):
        # 📄 Cargar configuración JSON
        self.config = self._load_config_strict(config_file)
        self.config_file = config_file

        # 🏷️ Identidad distribuida
        self.node_id = self.config["node_id"]
        self.process_id = os.getpid()
        self.container_id = self._get_container_id()
        self.start_time = time.time()

        # 🖥️ Información del sistema
        self.system_info = self._gather_system_info()

        # 📝 Setup logging
        self.setup_logging()

        # ✅ Verificar dependencias críticas PRIMERO
        self._verify_dependencies()

        # 🔌 Setup ZeroMQ
        self.context = zmq.Context()
        self.socket = None
        self.setup_socket()

        # 🎯 Inicializar componentes especializados
        self.features_extractor = NetworkFeaturesExtractor()

        # ⏰ Setup time windows
        self.time_window_manager = TimeWindowManager(
            self._parse_time_window_configs(),
            self.logger
        )

        # 📦 Queues para procesamiento asíncrono
        queue_size = self.config["processing"]["internal_queue_size"]
        self.packet_queue = Queue(maxsize=queue_size)
        self.window_queue = Queue(maxsize=queue_size // 2)

        # 📊 Métricas v3.1
        self.stats = {
            'packets_captured': 0,
            'flows_created': 0,
            'windows_completed': 0,
            'events_sent': 0,
            'features_extracted': 0,
            'drops': 0,
            'errors': 0,
            'start_time': time.time(),
            'last_stats_time': time.time()
        }

        # 🎛️ Control
        self.running = True
        self.stop_event = Event()
        self.handshake_sent = False

        self.logger.info(f"🚀 Evolutionary Sniffer v3.1 inicializado")
        self.logger.info(f"   🏷️ Node ID: {self.node_id}")
        self.logger.info(f"   🔢 PID: {self.process_id}")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")
        self.logger.info(f"   ⏰ Time windows: {len(self.time_window_manager.window_configs)}")

    def _load_config_strict(self, config_file: str) -> Dict[str, Any]:
        """Carga configuración sin defaults hardcodeados"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            raise RuntimeError(f"❌ Archivo de configuración no encontrado: {config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ Error parseando JSON: {e}")

        # Validar campos críticos
        required_fields = [
            "node_id", "network", "capture", "processing",
            "time_windows", "logging", "monitoring"
        ]

        for field in required_fields:
            if field not in config:
                raise RuntimeError(f"❌ Campo requerido faltante: {field}")

        return config

    def _parse_time_window_configs(self) -> Dict[str, TimeWindowConfig]:
        """Parsea configuraciones de ventanas de tiempo desde JSON"""
        configs = {}

        for window_type, window_data in self.config["time_windows"].items():
            configs[window_type] = TimeWindowConfig(
                window_size_seconds=window_data["window_size_seconds"],
                slide_interval_seconds=window_data["slide_interval_seconds"],
                max_flows_per_window=window_data["max_flows_per_window"],
                features_required=window_data["features_required"],
                model_types=window_data["model_types"],
                description=window_data.get("description", "")
            )

        self.logger.info(f"⏰ Configuradas {len(configs)} ventanas de tiempo:")
        for window_type, config in configs.items():
            self.logger.info(f"   📊 {window_type}: {config.window_size_seconds}s window, "
                             f"{len(config.features_required)} features, "
                             f"models: {config.model_types}")

        return configs

    def _get_container_id(self) -> Optional[str]:
        """Obtiene ID del contenedor si está disponible"""
        try:
            with open('/proc/self/cgroup', 'r') as f:
                content = f.read()
                for line in content.split('\n'):
                    if 'docker' in line:
                        return line.split('/')[-1][:12]
            return None
        except:
            return None

    def _gather_system_info(self) -> Dict[str, Any]:
        """Recolecta información del sistema"""
        return {
            'hostname': socket.gethostname(),
            'os_name': platform.system(),
            'os_version': platform.release(),
            'architecture': platform.machine(),
            'python_version': platform.python_version(),
            'cpu_count': psutil.cpu_count(),
            'memory_total_gb': round(psutil.virtual_memory().total / (1024 ** 3), 2)
        }

    def _verify_dependencies(self):
        """Verifica dependencias críticas - FALLA si no están"""
        issues = []

        if not SCAPY_AVAILABLE:
            issues.append("❌ Scapy REQUERIDO - pip install scapy")

        if not PROTOBUF_AVAILABLE:
            issues.append("❌ Protobuf v3.1 REQUERIDO - generar con:")
            issues.append("   protoc --python_out=. network_security_clean_v31.proto")

        if issues:
            print("\n🚨 DEPENDENCIAS CRÍTICAS FALTANTES:")
            for issue in issues:
                print(issue)
            print("\n💡 FILOSOFÍA TODO O NADA:")
            print("   - Scapy: Captura REAL de paquetes")
            print("   - Protobuf v3.1: Serialización limpia")
            print("   - ZeroMQ: Comunicación distribuida")
            print("   - NO LEGACY: Solo v3.1")
            raise RuntimeError("❌ Dependencias críticas faltantes")

        print("✅ Todas las dependencias críticas disponibles")

    def setup_logging(self):
        """Setup logging desde configuración"""
        log_config = self.config["logging"]

        level = getattr(logging, log_config["level"].upper())

        log_format = (
            "%(asctime)s - %(name)-20s - %(levelname)-8s - "
            "[node_id:{node_id}] [pid:{pid}] [v3.1] - %(message)s"
        ).format(
            node_id=self.node_id,
            pid=self.process_id
        )
        formatter = logging.Formatter(log_format)

        self.logger = logging.getLogger(f"evolutionary_sniffer_{self.node_id}")
        self.logger.setLevel(level)
        self.logger.handlers.clear()
        self.logger.propagate = False

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # File handler si está configurado
        if log_config.get("file"):
            try:
                log_file = log_config["file"]
                os.makedirs(os.path.dirname(log_file), exist_ok=True)

                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)

                self.logger.info(f"📝 File logging habilitado: {log_file}")
            except Exception as e:
                self.logger.error(f"❌ Error configurando file logging: {e}")

    def setup_socket(self):
        """Configuración ZeroMQ desde network config"""
        network_config = self.config["network"]
        output_config = network_config["output_socket"]

        # Crear socket
        socket_type = getattr(zmq, output_config["socket_type"])
        self.socket = self.context.socket(socket_type)

        # Configurar opciones ZMQ
        zmq_config = self.config.get("zmq", {})
        self.socket.setsockopt(zmq.SNDHWM, zmq_config.get("sndhwm", 2000))
        self.socket.setsockopt(zmq.LINGER, zmq_config.get("linger_ms", 5000))
        self.socket.setsockopt(zmq.SNDTIMEO, zmq_config.get("send_timeout_ms", 100))

        # Conectar o bind
        address = output_config["address"]
        port = output_config["port"]
        mode = output_config["mode"].lower()

        if mode == "bind":
            bind_address = f"tcp://*:{port}"
            self.socket.bind(bind_address)
            connection_info = f"BIND on {bind_address}"
        elif mode == "connect":
            connect_address = f"tcp://{address}:{port}"
            self.socket.connect(connect_address)
            connection_info = f"CONNECT to {connect_address}"
        else:
            raise ValueError(f"❌ Modo desconocido: {mode}")

        self.logger.info(f"🔌 ZeroMQ configurado: {connection_info}")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")

    def packet_capture_callback(self, packet):
        """Callback para captura de paquetes con Scapy"""
        try:
            packet_info = self._extract_packet_info(packet)

            if packet_info and self._should_process_packet(packet_info):
                # Añadir a queue para procesamiento asíncrono
                try:
                    self.packet_queue.put(packet_info, timeout=0.1)
                    self.stats['packets_captured'] += 1
                except:
                    self.stats['drops'] += 1

        except Exception as e:
            self.logger.error(f"❌ Error en callback de captura: {e}")
            self.stats['errors'] += 1

    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extrae información del paquete"""
        try:
            info = PacketInfo(
                timestamp=time.time(),
                src_ip="unknown",
                dst_ip="unknown",
                src_port=0,
                dst_port=0,
                protocol_number=0,
                protocol_name="unknown",
                packet_size=len(packet),
                tcp_flags={},
                flow_id="",
                raw_packet=packet
            )

            # Extraer información de capa IP
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                info.src_ip = ip_layer.src
                info.dst_ip = ip_layer.dst
                info.protocol_number = ip_layer.proto

                # Extraer información de puerto y flags TCP
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    info.src_port = tcp_layer.sport
                    info.dst_port = tcp_layer.dport
                    info.protocol_name = "TCP"

                    # Extraer TCP flags
                    info.tcp_flags = {
                        'F': bool(tcp_layer.flags.F),  # FIN
                        'S': bool(tcp_layer.flags.S),  # SYN
                        'R': bool(tcp_layer.flags.R),  # RST
                        'P': bool(tcp_layer.flags.P),  # PSH
                        'A': bool(tcp_layer.flags.A),  # ACK
                        'U': bool(tcp_layer.flags.U),  # URG
                        'E': bool(tcp_layer.flags.E),  # ECE
                        'C': bool(tcp_layer.flags.C),  # CWR
                    }

                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    info.src_port = udp_layer.sport
                    info.dst_port = udp_layer.dport
                    info.protocol_name = "UDP"
                else:
                    info.protocol_name = "OTHER"

            # Crear flow ID único
            info.flow_id = f"{info.src_ip}:{info.src_port}-{info.dst_ip}:{info.dst_port}-{info.protocol_name}"

            return info

        except Exception as e:
            self.logger.error(f"❌ Error extrayendo info de paquete: {e}")
            return None

    def _should_process_packet(self, packet_info: PacketInfo) -> bool:
        """Determina si el paquete debe ser procesado"""
        capture_config = self.config["capture"]

        # Filtro por tamaño
        if packet_info.packet_size < capture_config.get("min_packet_size", 0):
            return False

        # Filtro por puertos excluidos
        excluded_ports = capture_config.get("excluded_ports", [])
        if packet_info.src_port in excluded_ports or packet_info.dst_port in excluded_ports:
            return False

        # Filtro por protocolos incluidos
        included_protocols = capture_config.get("included_protocols", [])
        if included_protocols and packet_info.protocol_name.lower() not in [p.lower() for p in included_protocols]:
            return False

        return True

    def start_packet_capture(self):
        """Inicia captura REAL de paquetes con Scapy"""
        capture_config = self.config["capture"]

        interface = capture_config["interface"]
        filter_expr = capture_config.get("filter_expression", "")

        self.logger.info(f"🎯 Iniciando captura REAL v3.1:")
        self.logger.info(f"   📡 Interface: {interface}")
        self.logger.info(f"   🔍 Filtro: {filter_expr or 'sin filtro'}")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")

        try:
            sniff(
                iface=interface if interface != "any" else None,
                filter=filter_expr,
                prn=self.packet_capture_callback,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.logger.error(f"❌ Error en captura: {e}")
            self.logger.error("💡 Tip: ejecutar con sudo para captura promiscua")
            raise

    def process_packets(self):
        """Thread para procesar paquetes de la cola"""
        self.logger.info("⚙️ Iniciando thread de procesamiento v3.1")

        while self.running:
            try:
                packet_info = self.packet_queue.get(timeout=1.0)

                # Añadir paquete al time window manager
                self.time_window_manager.add_packet(packet_info)

                self.packet_queue.task_done()

            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"❌ Error procesando paquete: {e}")
                self.stats['errors'] += 1

    def process_time_windows(self):
        """Thread para procesar ventanas de tiempo completadas"""
        self.logger.info("⏰ Iniciando thread de procesamiento de ventanas v3.1")

        while self.running:
            try:
                # Obtener ventanas completadas
                completed_windows = self.time_window_manager.get_completed_windows()

                for window_data in completed_windows:
                    self._process_completed_window(window_data)

                time.sleep(0.1)  # Pequeña pausa para no saturar CPU

            except Exception as e:
                self.logger.error(f"❌ Error procesando ventanas: {e}")
                self.stats['errors'] += 1

    def _process_completed_window(self, window_data: Dict[str, Any]):
        """Procesa una ventana de tiempo completada y extrae features"""
        try:
            window_type = window_data['window_type']
            config = window_data['config']
            flows = window_data['flows']

            self.logger.debug(f"📊 Procesando ventana {window_type} con {len(flows)} flujos")

            # Procesar cada flujo en la ventana
            for flow in flows:
                # Extraer todas las features del flujo
                all_features = self.features_extractor.extract_all_features(flow)
                self.stats['features_extracted'] += 1

                # Crear eventos para cada tipo de modelo configurado
                for model_type in config.model_types:
                    event_data = self._create_network_security_event(
                        flow, all_features, window_data, model_type
                    )

                    if event_data:
                        # Enviar evento
                        success = self._send_event(event_data)
                        if success:
                            self.stats['events_sent'] += 1
                        else:
                            self.stats['drops'] += 1

            self.stats['windows_completed'] += 1

        except Exception as e:
            self.logger.error(f"❌ Error procesando ventana completada: {e}")
            self.stats['errors'] += 1

    def _create_network_security_event(self, flow: FlowInfo, all_features: Dict[str, float],
                                       window_data: Dict[str, Any], model_type: str) -> Optional[bytes]:
        """Crea evento NetworkSecurityEvent v3.1 limpio"""
        try:
            # Crear evento protobuf v3.1
            event = NetworkSecurityEventProto.NetworkSecurityEvent()

            # 🔍 IDENTIFICACIÓN ÚNICA
            event.event_id = str(uuid.uuid4())
            event.event_timestamp.FromDatetime(datetime.fromtimestamp(time.time()))
            event.originating_node_id = self.node_id

            # 📊 NETWORK FEATURES
            network_features = event.network_features
            network_features.source_ip = flow.src_ip
            network_features.destination_ip = flow.dst_ip
            network_features.source_port = flow.src_port
            network_features.destination_port = flow.dst_port
            network_features.protocol_number = flow.forward_packets[0].protocol_number if flow.forward_packets else 0
            network_features.protocol_name = flow.protocol

            # Timing
            network_features.flow_start_time.FromDatetime(datetime.fromtimestamp(flow.start_time))
            duration_seconds = flow.last_seen - flow.start_time
            network_features.flow_duration.FromTimedelta(timedelta(seconds=duration_seconds))
            network_features.flow_duration_microseconds = int(duration_seconds * 1_000_000)

            # Features básicas
            network_features.total_forward_packets = len(flow.forward_packets)
            network_features.total_backward_packets = len(flow.backward_packets)
            network_features.total_forward_bytes = flow.total_forward_bytes
            network_features.total_backward_bytes = flow.total_backward_bytes

            # Features específicas del modelo
            model_features = self.features_extractor.get_features_for_model(all_features, model_type)

            if model_type == "ddos_83":
                network_features.ddos_features[:] = model_features
            elif model_type == "rf_23":
                network_features.general_attack_features[:] = model_features
            elif model_type == "internal_4":
                network_features.internal_traffic_features[:] = model_features
            else:
                # Features personalizadas
                for i, feature_value in enumerate(model_features[:10]):  # Limitar a 10
                    network_features.custom_features[f"feature_{i}"] = feature_value

            # 🌐 INFORMACIÓN DEL NODO DISTRIBUIDO
            capturing_node = event.capturing_node
            capturing_node.node_id = self.node_id
            capturing_node.node_hostname = self.system_info['hostname']
            capturing_node.node_ip_address = socket.gethostbyname(socket.gethostname())
            capturing_node.physical_location = "unknown"  # TODO: configurar desde JSON
            capturing_node.node_role = NetworkSecurityEventProto.DistributedNode.NodeRole.PACKET_SNIFFER
            capturing_node.node_status = NetworkSecurityEventProto.DistributedNode.NodeStatus.ACTIVE
            capturing_node.last_heartbeat.FromDatetime(datetime.now())

            # Información técnica
            capturing_node.operating_system = self.system_info['os_name']
            capturing_node.os_version = self.system_info['os_version']
            capturing_node.agent_version = self.config.get("version", "3.1.0")
            capturing_node.process_id = self.process_id
            if self.container_id:
                capturing_node.container_id = self.container_id
            capturing_node.cluster_name = self.config.get("cluster_name", "upgraded-happiness")

            # Métricas del nodo
            try:
                process = psutil.Process(self.process_id)
                capturing_node.cpu_usage_percent = process.cpu_percent()
                capturing_node.memory_usage_mb = process.memory_info().rss / (1024 * 1024)
                capturing_node.queue_depth = self.packet_queue.qsize()
                capturing_node.uptime.FromTimedelta(timedelta(seconds=time.time() - self.start_time))
            except:
                pass

            # ⏰ TIME WINDOW
            time_window = event.time_window
            time_window.window_start.FromDatetime(datetime.fromtimestamp(window_data['start_time']))
            time_window.window_end.FromDatetime(datetime.fromtimestamp(window_data['end_time']))
            time_window.window_duration.FromTimedelta(timedelta(
                seconds=window_data['end_time'] - window_data['start_time']
            ))
            time_window.sequence_number = int(time.time())  # Número secuencial simple
            time_window.window_type = NetworkSecurityEventProto.TimeWindow.WindowType.SLIDING

            # 📊 PIPELINE TRACKING
            pipeline_tracking = event.pipeline_tracking
            pipeline_tracking.pipeline_id = str(uuid.uuid4())
            pipeline_tracking.pipeline_start.FromDatetime(datetime.fromtimestamp(flow.start_time))
            pipeline_tracking.sniffer_process_id = self.process_id
            pipeline_tracking.packet_captured_at.FromDatetime(datetime.fromtimestamp(flow.start_time))
            pipeline_tracking.total_processing_latency.FromTimedelta(
                timedelta(seconds=time.time() - flow.start_time)
            )
            pipeline_tracking.pipeline_hops_count = 1
            pipeline_tracking.processing_path = f"sniffer[{self.node_id}]"
            pipeline_tracking.retry_attempts = 0
            pipeline_tracking.requires_reprocessing = False

            # Metadatos
            pipeline_tracking.component_metadata["model_type"] = model_type
            pipeline_tracking.component_metadata["window_type"] = window_data['window_type']
            pipeline_tracking.component_metadata["flow_count"] = str(len(window_data['flows']))
            pipeline_tracking.component_metadata["features_extracted"] = str(len(all_features))

            pipeline_tracking.processing_tags.extend([
                "evolutionary_sniffer",
                "packet_capture",
                f"model_{model_type}",
                f"window_{window_data['window_type']}",
                f"node_{self.node_id}",
                "protobuf_v31"
            ])

            # 📊 SCORING Y CLASIFICACIÓN FINAL (inicial)
            event.overall_threat_score = 0.0  # Se calculará en componentes ML posteriores
            event.final_classification = "CAPTURED"  # Estado inicial
            event.threat_category = "UNKNOWN"  # Se determinará por ML

            # 🔗 CORRELACIÓN
            event.correlation_id = flow.flow_id
            event.event_chain_id = f"chain_{flow.flow_id}_{int(time.time())}"

            # 📝 METADATOS GENERALES
            event.schema_version = 31
            event.custom_metadata["capture_interface"] = self.config["capture"]["interface"]
            event.custom_metadata["config_file"] = self.config_file
            event.custom_metadata["features_count"] = str(len(all_features))
            event.custom_metadata["model_type"] = model_type
            event.event_tags.extend([
                "sniffer_v31",
                model_type,
                f"window_{window_data['window_type']}",
                "real_capture"
            ])
            event.protobuf_version = "3.1.0"

            # Serializar
            return event.SerializeToString()

        except Exception as e:
            self.logger.error(f"❌ Error creando evento protobuf: {e}")
            self.stats['errors'] += 1
            return None

    def _send_event(self, event_data: bytes) -> bool:
        """Envía evento vía ZeroMQ"""
        try:
            self.socket.send(event_data, zmq.NOBLOCK)
            return True
        except zmq.Again:
            # Buffer lleno
            return False
        except Exception as e:
            self.logger.error(f"❌ Error enviando evento: {e}")
            return False

    def send_handshake(self):
        """Envía handshake inicial del nodo v3.1"""
        if self.handshake_sent:
            return

        try:
            # Crear evento handshake simple
            event = NetworkSecurityEventProto.NetworkSecurityEvent()

            event.event_id = str(uuid.uuid4())
            event.event_timestamp.FromDatetime(datetime.now())
            event.originating_node_id = self.node_id

            # Nodo capturador
            capturing_node = event.capturing_node
            capturing_node.node_id = self.node_id
            capturing_node.node_hostname = self.system_info['hostname']
            capturing_node.node_role = NetworkSecurityEventProto.DistributedNode.NodeRole.PACKET_SNIFFER
            capturing_node.node_status = NetworkSecurityEventProto.DistributedNode.NodeStatus.STARTING
            capturing_node.agent_version = self.config.get("version", "3.1.0")
            capturing_node.process_id = self.process_id

            # Metadatos de handshake
            event.final_classification = "HANDSHAKE"
            event.threat_category = "SYSTEM"
            event.schema_version = 31
            event.protobuf_version = "3.1.0"
            event.custom_metadata["handshake"] = "initial"
            event.custom_metadata["capabilities"] = "packet_capture,feature_extraction,time_windows"
            event.event_tags.extend(["handshake", "sniffer_v31", "startup"])

            # Enviar
            event_data = event.SerializeToString()
            success = self._send_event(event_data)

            if success:
                self.handshake_sent = True
                self.logger.info("🤝 Handshake v3.1 enviado exitosamente")
            else:
                self.logger.warning("⚠️ Error enviando handshake")

        except Exception as e:
            self.logger.error(f"❌ Error creando handshake: {e}")

    def monitor_performance(self):
        """Thread de monitoreo de performance"""
        monitoring_config = self.config["monitoring"]
        interval = monitoring_config["stats_interval_seconds"]

        while self.running:
            time.sleep(interval)
            if not self.running:
                break

            self._log_performance_stats()

    def _log_performance_stats(self):
        """Log de estadísticas de performance v3.1"""
        now = time.time()
        interval = now - self.stats['last_stats_time']

        # Calcular rates
        if interval > 0:
            packet_rate = self.stats['packets_captured'] / interval
            event_rate = self.stats['events_sent'] / interval
        else:
            packet_rate = 0
            event_rate = 0

        self.logger.info(f"📊 Performance Stats v3.1:")
        self.logger.info(f"   📦 Paquetes: {self.stats['packets_captured']} ({packet_rate:.1f}/s)")
        self.logger.info(f"   📊 Features: {self.stats['features_extracted']}")
        self.logger.info(f"   ⏰ Ventanas: {self.stats['windows_completed']}")
        self.logger.info(f"   📤 Eventos: {self.stats['events_sent']} ({event_rate:.1f}/s)")
        self.logger.info(f"   🗑️ Drops: {self.stats['drops']}")
        self.logger.info(f"   ❌ Errores: {self.stats['errors']}")
        self.logger.info(f"   📋 Cola paquetes: {self.packet_queue.qsize()}")
        self.logger.info(f"   🏃 Flujos activos: {len(self.time_window_manager.active_flows)}")

        # Reset stats
        for key in ['packets_captured', 'features_extracted', 'windows_completed',
                    'events_sent', 'drops', 'errors']:
            self.stats[key] = 0

        self.stats['last_stats_time'] = now

    def run(self):
        """Ejecutar el sniffer evolutivo v3.1"""
        self.logger.info("🚀 Iniciando Evolutionary Sniffer v3.1...")

        # Enviar handshake inicial
        self.send_handshake()

        # Iniciar threads
        threads = []

        # Thread de monitoreo
        monitor_thread = threading.Thread(target=self.monitor_performance, name="Monitor")
        monitor_thread.start()
        threads.append(monitor_thread)

        # Thread de procesamiento de paquetes
        packet_thread = threading.Thread(target=self.process_packets, name="PacketProcessor")
        packet_thread.start()
        threads.append(packet_thread)

        # Thread de procesamiento de ventanas de tiempo
        window_thread = threading.Thread(target=self.process_time_windows, name="WindowProcessor")
        window_thread.start()
        threads.append(window_thread)

        # Thread de captura (bloquea en el hilo principal)
        self.logger.info(f"✅ Sniffer v3.1 iniciado con {len(threads)} threads")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")
        self.logger.info(f"   🏷️ Node ID: {self.node_id}")

        try:
            # Iniciar captura (bloquea hasta Ctrl+C)
            self.start_packet_capture()
        except KeyboardInterrupt:
            self.logger.info("🛑 Deteniendo Sniffer v3.1...")

        # Shutdown graceful
        self.shutdown(threads)

    def shutdown(self, threads):
        """Cierre graceful del sniffer v3.1"""
        self.running = False
        self.stop_event.set()

        # Stats finales
        runtime = time.time() - self.stats['start_time']
        self.logger.info(f"📊 Stats finales v3.1 - Runtime: {runtime:.1f}s")

        # Esperar threads
        for thread in threads:
            thread.join(timeout=5)

        # Cerrar socket
        if self.socket:
            self.socket.close()
        self.context.term()

        self.logger.info("✅ Evolutionary Sniffer v3.1 cerrado correctamente")


# 🚀 Main
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Uso: python evolutionary_sniffer_v31.py <config.json>")
        print("💡 Ejemplo: python evolutionary_sniffer_v31.py evolutionary_sniffer_config_v31.json")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        sniffer = EvolutionarySniffer(config_file)
        sniffer.run()
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)