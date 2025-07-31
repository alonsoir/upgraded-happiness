#!/usr/bin/env python3
"""
Enhanced Network Feature Extractor for ML Models
Extracts all 26 required features for the 3-layer anomaly detection system
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP
import pandas as pd
import numpy as np
from collections import defaultdict, deque
import time
import threading
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class FlowStats:
    """Estadísticas completas de un flujo de red"""
    # Básicos
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0

    # Contadores de paquetes y bytes
    spkts: int = 0
    dpkts: int = 0
    sbytes: int = 0
    dbytes: int = 0

    # Timestamps para cálculos temporales
    start_time: float = 0.0
    last_time: float = 0.0
    src_timestamps: List[float] = field(default_factory=list)
    dst_timestamps: List[float] = field(default_factory=list)

    # TCP específico
    tcp_flags: List[int] = field(default_factory=list)
    tcp_windows: List[int] = field(default_factory=list)
    src_windows: List[int] = field(default_factory=list)
    dst_windows: List[int] = field(default_factory=list)

    # Pérdidas y retransmisiones
    src_seq_nums: List[int] = field(default_factory=list)
    dst_seq_nums: List[int] = field(default_factory=list)
    retransmissions: int = 0

    # HTTP específico
    http_methods: List[str] = field(default_factory=list)
    http_responses: List[int] = field(default_factory=list)
    response_body_lengths: List[int] = field(default_factory=list)

    # FTP específico
    ftp_commands: List[str] = field(default_factory=list)
    ftp_login_attempts: int = 0


class EnhancedNetworkExtractor:
    def __init__(self, window_size: int = 300):
        """
        Args:
            window_size: Ventana de tiempo en segundos para mantener estadísticas
        """
        self.window_size = window_size
        self.flows = defaultdict(FlowStats)
        self.connection_stats = defaultdict(lambda: defaultdict(int))
        self.global_stats = defaultdict(int)
        self.capture_start = time.time()

        # Limpeza periódica de estadísticas antiguas
        self.cleanup_thread = threading.Thread(target=self._periodic_cleanup, daemon=True)
        self.cleanup_thread.start()

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

        # Normalizar flujo (menor IP:puerto primero)
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

    def _is_source_direction(self, packet, flow_key: str) -> bool:
        """Determina si el paquete va en dirección source->dest"""
        if not packet.haslayer(IP):
            return True

        ip_layer = packet[IP]
        src_ip = ip_layer.src

        # Extraer primera IP del flow_key
        first_ip = flow_key.split(':')[0]
        return src_ip == first_ip

    def process_packet(self, packet):
        """Procesa un paquete y actualiza estadísticas"""
        flow_key = self._get_flow_key(packet)
        if not flow_key:
            return

        current_time = time.time()
        flow = self.flows[flow_key]
        is_source = self._is_source_direction(packet, flow_key)

        # Inicializar flujo si es nuevo
        if flow.start_time == 0:
            flow.start_time = current_time
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                if is_source:
                    flow.src_ip, flow.dst_ip = ip_layer.src, ip_layer.dst
                else:
                    flow.src_ip, flow.dst_ip = ip_layer.dst, ip_layer.src

                if packet.haslayer(TCP):
                    if is_source:
                        flow.src_port, flow.dst_port = packet[TCP].sport, packet[TCP].dport
                    else:
                        flow.src_port, flow.dst_port = packet[TCP].dport, packet[TCP].sport
                    flow.protocol = 6
                elif packet.haslayer(UDP):
                    if is_source:
                        flow.src_port, flow.dst_port = packet[UDP].sport, packet[UDP].dport
                    else:
                        flow.src_port, flow.dst_port = packet[UDP].dport, packet[UDP].sport
                    flow.protocol = 17
                else:
                    flow.protocol = ip_layer.proto

        flow.last_time = current_time
        packet_size = len(packet)

        # Actualizar contadores básicos
        if is_source:
            flow.spkts += 1
            flow.sbytes += packet_size
            flow.src_timestamps.append(current_time)
        else:
            flow.dpkts += 1
            flow.dbytes += packet_size
            flow.dst_timestamps.append(current_time)

        # Procesar TCP
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            flow.tcp_flags.append(tcp_layer.flags)

            if is_source:
                flow.src_windows.append(tcp_layer.window)
                if hasattr(tcp_layer, 'seq'):
                    flow.src_seq_nums.append(tcp_layer.seq)
            else:
                flow.dst_windows.append(tcp_layer.window)
                if hasattr(tcp_layer, 'seq'):
                    flow.dst_seq_nums.append(tcp_layer.seq)

        # Procesar HTTP
        if packet.haslayer(HTTP):
            try:
                http_layer = packet[HTTP]
                if hasattr(http_layer, 'Method'):
                    flow.http_methods.append(http_layer.Method.decode())
                if hasattr(http_layer, 'Status_Code'):
                    flow.http_responses.append(int(http_layer.Status_Code))
                if hasattr(http_layer, 'Content_Length'):
                    flow.response_body_lengths.append(int(http_layer.Content_Length))
            except:
                pass

        # Procesar FTP (puerto 21 o contenido FTP)
        if (flow.src_port == 21 or flow.dst_port == 21 or
                (packet.haslayer(scapy.Raw) and b'FTP' in bytes(packet[scapy.Raw]))):
            try:
                if packet.haslayer(scapy.Raw):
                    payload = bytes(packet[scapy.Raw]).decode('utf-8', errors='ignore')
                    # Buscar comandos FTP comunes
                    ftp_commands = ['USER', 'PASS', 'LIST', 'RETR', 'STOR', 'PWD', 'CWD']
                    for cmd in ftp_commands:
                        if cmd in payload.upper():
                            flow.ftp_commands.append(cmd)
                            if cmd in ['USER', 'PASS']:
                                flow.ftp_login_attempts += 1
                            break
            except:
                pass

        # Actualizar estadísticas globales
        self._update_connection_stats(flow, current_time)

    def _update_connection_stats(self, flow: FlowStats, current_time: float):
        """Actualiza contadores de conexión globales"""
        service = flow.dst_port
        state = self._get_tcp_state(flow)

        self.connection_stats[f"ct_srv_src_{flow.src_ip}"][service] += 1
        self.connection_stats[f"ct_srv_dst_{flow.dst_ip}"][service] += 1
        self.connection_stats[f"ct_state_ttl"][state] += 1
        self.connection_stats[f"ct_dst_ltm_{flow.dst_ip}"]["last_time"] = current_time
        self.connection_stats[f"ct_src_ltm_{flow.src_ip}"]["last_time"] = current_time
        self.connection_stats[f"ct_src_dport_ltm_{flow.src_ip}"][flow.dst_port] += 1
        self.connection_stats[f"ct_dst_src_ltm_{flow.dst_ip}"][flow.src_ip] += 1

        # HTTP method counting
        if flow.http_methods:
            for method in flow.http_methods:
                self.connection_stats[f"ct_flw_http_mthd"][method] += 1

        # FTP command counting
        if flow.ftp_commands:
            for cmd in flow.ftp_commands:
                self.connection_stats[f"ct_ftp_cmd"][cmd] += 1

    def _get_tcp_state(self, flow: FlowStats) -> str:
        """Determina el estado TCP del flujo"""
        if not flow.tcp_flags:
            return "UNKNOWN"

        flags = flow.tcp_flags[-1] if flow.tcp_flags else 0

        if flags & 0x02:  # SYN
            return "SYN"
        elif flags & 0x10:  # ACK
            return "ESTABLISHED"
        elif flags & 0x01:  # FIN
            return "FIN"
        elif flags & 0x04:  # RST
            return "RST"
        else:
            return "OTHER"

    def _calculate_load(self, bytes_count: int, duration: float) -> float:
        """Calcula load (bits por segundo)"""
        if duration <= 0:
            return 0
        return (bytes_count * 8) / duration

    def _calculate_loss(self, seq_nums: List[int]) -> int:
        """Calcula pérdidas basado en números de secuencia"""
        if len(seq_nums) < 2:
            return 0

        expected_next = seq_nums[0]
        losses = 0

        for i in range(1, len(seq_nums)):
            if seq_nums[i] != expected_next:
                losses += 1
            expected_next = seq_nums[i] + 1460  # MSS típico

        return losses

    def _calculate_mean_iat(self, timestamps: List[float]) -> float:
        """Calcula tiempo inter-arrival promedio"""
        if len(timestamps) < 2:
            return 0

        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        return np.mean(intervals) * 1000  # en milisegundos

    def _is_small_ips_ports(self, flow: FlowStats) -> bool:
        """Detecta si usa IPs/puertos similares (heurística)"""
        # Heurística simple: puertos consecutivos o IPs en misma subnet
        src_parts = flow.src_ip.split('.')
        dst_parts = flow.dst_ip.split('.')

        # Misma subnet /24
        same_subnet = src_parts[0:3] == dst_parts[0:3]

        # Puertos similares (diferencia < 10)
        port_diff = abs(flow.src_port - flow.dst_port) < 10

        return same_subnet or port_diff

    def extract_features(self, flow_key: str) -> Dict:
        """Extrae todas las 26 features para un flujo"""
        flow = self.flows[flow_key]
        current_time = time.time()
        duration = max(flow.last_time - flow.start_time, 0.001)

        # Features básicas
        features = {
            'id': hash(flow_key) % 65536,  # Simular ID de paquete
            'service': flow.dst_port,
            'state': self._encode_state(self._get_tcp_state(flow)),
            'spkts': flow.spkts,
            'dpkts': flow.dpkts,
            'dbytes': flow.dbytes,
        }

        # Features calculadas de carga y pérdida
        features['sload'] = self._calculate_load(flow.sbytes, duration)
        features['sloss'] = self._calculate_loss(flow.src_seq_nums)
        features['dloss'] = self._calculate_loss(flow.dst_seq_nums)

        # Features de ventana TCP
        features['swin'] = np.mean(flow.src_windows) if flow.src_windows else 0
        features['dwin'] = np.mean(flow.dst_windows) if flow.dst_windows else 0

        # Features de tiempo inter-arrival
        features['smean'] = self._calculate_mean_iat(flow.src_timestamps)
        features['dmean'] = self._calculate_mean_iat(flow.dst_timestamps)

        # Features de protocolo específico
        features['trans_depth'] = len(flow.http_methods)
        features['response_body_len'] = sum(flow.response_body_lengths)
        features['is_ftp_login'] = 1 if flow.ftp_login_attempts > 0 else 0
        features['is_sm_ips_ports'] = 1 if self._is_small_ips_ports(flow) else 0

        # Features de contadores de conexión
        features['ct_srv_src'] = len(self.connection_stats[f"ct_srv_src_{flow.src_ip}"])
        features['ct_srv_dst'] = len(self.connection_stats[f"ct_srv_dst_{flow.dst_ip}"])
        features['ct_state_ttl'] = self.connection_stats[f"ct_state_ttl"][self._get_tcp_state(flow)]

        # Features de tiempo y correlación
        features['ct_dst_ltm'] = self._time_since_last(f"ct_dst_ltm_{flow.dst_ip}", current_time)
        features['ct_src_ltm'] = self._time_since_last(f"ct_src_ltm_{flow.src_ip}", current_time)
        features['ct_src_dport_ltm'] = self.connection_stats[f"ct_src_dport_ltm_{flow.src_ip}"][flow.dst_port]
        features['ct_dst_src_ltm'] = self.connection_stats[f"ct_dst_src_ltm_{flow.dst_ip}"][flow.src_ip]

        # Features de protocolos de aplicación
        features['ct_flw_http_mthd'] = len(set(flow.http_methods))
        features['ct_ftp_cmd'] = len(set(flow.ftp_commands))

        return features

    def _encode_state(self, state: str) -> int:
        """Codifica estado TCP como número"""
        state_map = {
            'SYN': 0, 'ESTABLISHED': 1, 'FIN': 2,
            'RST': 3, 'OTHER': 4, 'UNKNOWN': 5
        }
        return state_map.get(state, 5)

    def _time_since_last(self, key: str, current_time: float) -> float:
        """Calcula tiempo desde última actividad"""
        if "last_time" in self.connection_stats[key]:
            return current_time - self.connection_stats[key]["last_time"]
        return 0

    def _periodic_cleanup(self):
        """Limpia estadísticas antiguas periódicamente"""
        while True:
            time.sleep(60)  # Limpiar cada minuto
            current_time = time.time()
            cutoff_time = current_time - self.window_size

            # Remover flujos antiguos
            old_flows = [k for k, v in self.flows.items()
                         if v.last_time < cutoff_time]
            for flow_key in old_flows:
                del self.flows[flow_key]

    def get_all_features_dataframe(self) -> pd.DataFrame:
        """Extrae features de todos los flujos activos"""
        features_list = []

        for flow_key in list(self.flows.keys()):
            try:
                features = self.extract_features(flow_key)
                features['flow_id'] = flow_key
                features_list.append(features)
            except Exception as e:
                print(f"Error extrayendo features para {flow_key}: {e}")
                continue

        if not features_list:
            return pd.DataFrame()

        return pd.DataFrame(features_list)


def capture_and_extract(interface: str = None, duration: int = 30) -> pd.DataFrame:
    """
    Captura tráfico y extrae todas las features necesarias

    Args:
        interface: Interfaz de red (None = auto)
        duration: Duración de captura en segundos

    Returns:
        DataFrame con todas las 26 features extraídas
    """
    extractor = EnhancedNetworkExtractor()

    print(f"🚀 Iniciando captura avanzada por {duration}s...")
    print("🔍 Extrayendo las 26 features completas...")

    def packet_handler(packet):
        extractor.process_packet(packet)

    # Capturar tráfico
    scapy.sniff(
        iface=interface,
        prn=packet_handler,
        timeout=duration,
        store=False
    )

    # Extraer features finales
    df = extractor.get_all_features_dataframe()

    print(f"✅ Captura completada: {len(df)} flujos procesados")
    print(f"📊 Features extraídas: {len(df.columns) - 1} (sin flow_id)")

    return df


if __name__ == "__main__":
    # Ejemplo de uso
    df = capture_and_extract(duration=30)

    if not df.empty:
        print("\n📋 Features disponibles:")
        feature_cols = [col for col in df.columns if col != 'flow_id']
        for i, col in enumerate(feature_cols, 1):
            print(f"   {i:2d}. {col}")

        print(f"\n📊 Muestra de datos:")
        print(df[feature_cols].head())

        # Guardar resultados
        df.to_csv('complete_network_features.csv', index=False)
        print(f"\n💾 Guardado: complete_network_features.csv")
    else:
        print("❌ No se capturaron flujos válidos")