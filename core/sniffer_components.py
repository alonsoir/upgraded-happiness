#!/usr/bin/env python3
"""
core/sniffer_components.py
🧩 Componentes separados para el Evolutionary Sniffer
- TimeWindowManager
- NetworkFeaturesExtractor
- Dataclasses compartidas
"""

import time
import threading
import logging
import statistics
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from collections import deque
from datetime import datetime, timedelta


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
    """Extractor de features de red para modelos ML"""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def extract_all_features(self, flow: FlowInfo) -> Dict[str, float]:
        """Extrae TODAS las features necesarias de un flujo"""
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
            'cwe_flag_count': 0,
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

        # Flags direccionales
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
        if flow.forward_packets:
            features['forward_header_length'] = 40.0  # TCP + IP header típico
        else:
            features['forward_header_length'] = 0.0

        if flow.backward_packets:
            features['backward_header_length'] = 40.0
        else:
            features['backward_header_length'] = 0.0

        # Bulk transfer features (simplificadas)
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
        return {}

    def _extract_protocol_features(self, flow: FlowInfo) -> Dict[str, float]:
        """Features específicas del protocolo"""
        features = {}

        # Protocol number
        features['protocol_number'] = flow.forward_packets[0].protocol_number if flow.forward_packets else 0

        return features

    def get_features_for_model(self, all_features: Dict[str, float], model_type: str) -> List[float]:
        """Extrae features específicas para un tipo de modelo"""

        if model_type == "ddos_83":
            return self._get_ddos_features(all_features)
        elif model_type == "rf_23":
            return self._get_rf_features(all_features)
        elif model_type == "internal_4":
            return self._get_internal_features(all_features)
        else:
            return list(all_features.values())[:83]

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

            # Determinar dirección del paquete
            if self._is_forward_packet(packet_info, flow):
                flow.forward_packets.append(packet_info)
                flow.total_forward_bytes += packet_info.packet_size
            else:
                flow.backward_packets.append(packet_info)
                flow.total_backward_bytes += packet_info.packet_size

    def _is_forward_packet(self, packet: PacketInfo, flow: FlowInfo) -> bool:
        """Determina si un paquete es en dirección forward"""
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

    def _create_window_data(self, window_type: str, config: TimeWindowConfig, end_time: float) -> Optional[Dict[str, Any]]:
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