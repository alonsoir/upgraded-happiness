#!/usr/bin/env python3
"""
Promiscuous Agent v2 - Capturador de tráfico normal con ventanas temporales
Diseñado para generar datos compatibles con advanced-trainer.py
"""

import os
import time
import json
import csv
import signal
import sys
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Dict, Optional, Set, Tuple
import threading
import queue
import psutil
import logging

# Networking
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS

# GeoIP enrichment
from geoip_enricher_v2 import GeoIPEnricher


# -----------------------------------------------------------------------------
# 📊 ESTRUCTURA DE DATOS PARA FLUJOS
# -----------------------------------------------------------------------------
@dataclass
class FlowMetrics:
    """Métricas por flujo de red compatibles con UNSW-NB15"""

    # Identificación del flujo
    flow_key: str
    start_time: float
    last_seen: float

    # Features básicas (UNSW-NB15 compatible)
    dur: float = 0.0
    proto: int = 0  # 6=TCP, 17=UDP, 1=ICMP
    service: str = "unknown"
    state: str = "INT"  # Estado de conexión

    # Contadores de paquetes y bytes
    spkts: int = 0  # Source packets
    dpkts: int = 0  # Destination packets
    sbytes: int = 0  # Source bytes
    dbytes: int = 0  # Destination bytes

    # TTL
    sttl: int = 0  # Source TTL
    dttl: int = 0  # Destination TTL

    # Rates y loads (calculados)
    rate: float = 0.0
    sload: float = 0.0
    dload: float = 0.0

    # Losses (simulado - difícil de detectar sin estado completo)
    sloss: int = 0
    dloss: int = 0

    # Intervalos entre paquetes
    sinpkt: float = 0.0
    dinpkt: float = 0.0

    # IPs para geolocalización
    src_ip: str = ""
    dst_ip: str = ""

    # Puertos
    src_port: int = 0
    dst_port: int = 0

    # Timestamps para intervalos
    src_packet_times: list = None
    dst_packet_times: list = None

    def __post_init__(self):
        if self.src_packet_times is None:
            self.src_packet_times = deque(maxlen=10)
        if self.dst_packet_times is None:
            self.dst_packet_times = deque(maxlen=10)


# -----------------------------------------------------------------------------
# 🕵️ FLOW TRACKER CON VENTANAS TEMPORALES
# -----------------------------------------------------------------------------
class FlowTracker:
    """Rastreador de flujos con ventanas temporales adaptativas"""

    def __init__(self, config):
        self.config = config
        self.flows: Dict[str, FlowMetrics] = {}
        self.lock = threading.RLock()

        # Configuración de ventanas
        self.min_window = config.get('min_window', 1.0)
        self.base_window = config.get('base_window', 10.0)
        self.max_window = config.get('max_window', 60.0)

        # Queue para exportación
        self.export_queue = queue.Queue(maxsize=10000)

        # Contadores
        self.stats = {
            'packets_processed': 0,
            'flows_active': 0,
            'flows_exported': 0,
            'protocols_seen': set(),
            'countries_seen': set(),
            'hours_covered': set(),
            'unique_ips': set()
        }

        # Logger
        self.logger = logging.getLogger(__name__)

        # Thread de limpieza
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()

    def _generate_flow_key(self, packet) -> Optional[str]:
        """Genera clave única para el flujo"""
        try:
            if not packet.haslayer(IP):
                return None

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto

            src_port = dst_port = 0

            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            # Normalizar flujo (menor IP primero para bidireccionalidad)
            if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
            else:
                return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"

        except Exception as e:
            self.logger.error(f"Error generando flow key: {e}")
            return None

    def _determine_service(self, packet) -> str:
        """Determina el servicio basado en puertos conocidos"""
        port_services = {
            80: 'http', 443: 'https', 53: 'dns', 22: 'ssh',
            25: 'smtp', 110: 'pop3', 143: 'imap', 21: 'ftp',
            23: 'telnet', 993: 'imaps', 995: 'pop3s'
        }

        try:
            if packet.haslayer(TCP):
                dport = packet[TCP].dport
                sport = packet[TCP].sport
            elif packet.haslayer(UDP):
                dport = packet[UDP].dport
                sport = packet[UDP].sport
            else:
                return "unknown"

            # Priorizar puerto destino, luego origen
            return port_services.get(dport, port_services.get(sport, "unknown"))

        except:
            return "unknown"

    def _determine_state(self, packet, flow: FlowMetrics) -> str:
        """Determina estado de conexión TCP"""
        if not packet.haslayer(TCP):
            return "INT"  # Intermediate state para no-TCP

        tcp_layer = packet[TCP]
        flags = tcp_layer.flags

        # Estados basados en flags TCP
        if flags & 0x02:  # SYN
            if flags & 0x10:  # SYN+ACK
                return "CON"  # Connected
            else:
                return "REQ"  # Request
        elif flags & 0x01:  # FIN
            return "FIN"  # Finished
        elif flags & 0x04:  # RST
            return "RST"  # Reset
        elif flags & 0x10:  # ACK
            return "CON"  # Connected/Established
        else:
            return "INT"  # Intermediate

    def _calculate_intervals(self, times_deque) -> float:
        """Calcula intervalo promedio entre paquetes"""
        if len(times_deque) < 2:
            return 0.0

        intervals = []
        times_list = list(times_deque)
        for i in range(1, len(times_list)):
            intervals.append(times_list[i] - times_list[i - 1])

        return sum(intervals) / len(intervals) if intervals else 0.0

    def process_packet(self, packet):
        """Procesa un paquete y actualiza métricas del flujo"""
        try:
            flow_key = self._generate_flow_key(packet)
            if not flow_key:
                return

            current_time = time.time()
            packet_size = len(packet)

            with self.lock:
                # Crear o actualizar flujo
                if flow_key not in self.flows:
                    # Nuevo flujo
                    ip_layer = packet[IP]
                    flow = FlowMetrics(
                        flow_key=flow_key,
                        start_time=current_time,
                        last_seen=current_time,
                        src_ip=ip_layer.src,
                        dst_ip=ip_layer.dst,
                        proto=ip_layer.proto,
                        sttl=ip_layer.ttl,
                        service=self._determine_service(packet)
                    )

                    if packet.haslayer(TCP):
                        flow.src_port = packet[TCP].sport
                        flow.dst_port = packet[TCP].dport
                    elif packet.haslayer(UDP):
                        flow.src_port = packet[UDP].sport
                        flow.dst_port = packet[UDP].dport

                    self.flows[flow_key] = flow
                else:
                    flow = self.flows[flow_key]

                # Actualizar métricas
                flow.last_seen = current_time
                flow.dur = current_time - flow.start_time

                # Determinar dirección del paquete
                ip_layer = packet[IP]
                is_src_to_dst = (ip_layer.src == flow.src_ip)

                if is_src_to_dst:
                    flow.spkts += 1
                    flow.sbytes += packet_size
                    flow.src_packet_times.append(current_time)
                    if ip_layer.ttl > 0:
                        flow.sttl = ip_layer.ttl
                else:
                    flow.dpkts += 1
                    flow.dbytes += packet_size
                    flow.dst_packet_times.append(current_time)
                    if ip_layer.ttl > 0:
                        flow.dttl = ip_layer.ttl

                # Actualizar estado
                flow.state = self._determine_state(packet, flow)

                # Calcular rates y loads
                if flow.dur > 0:
                    flow.rate = (flow.spkts + flow.dpkts) / flow.dur
                    flow.sload = flow.sbytes / flow.dur
                    flow.dload = flow.dbytes / flow.dur

                # Calcular intervalos
                flow.sinpkt = self._calculate_intervals(flow.src_packet_times)
                flow.dinpkt = self._calculate_intervals(flow.dst_packet_times)

                # Actualizar estadísticas globales
                self.stats['packets_processed'] += 1
                self.stats['protocols_seen'].add(flow.proto)
                self.stats['unique_ips'].add(flow.src_ip)
                self.stats['unique_ips'].add(flow.dst_ip)
                self.stats['hours_covered'].add(
                    datetime.fromtimestamp(current_time).hour
                )

                # Verificar si el flujo debe ser exportado
                self._check_flow_export(flow_key, flow)

        except Exception as e:
            self.logger.error(f"Error procesando paquete: {e}")

    def _check_flow_export(self, flow_key: str, flow: FlowMetrics):
        """Verifica si un flujo debe ser exportado"""
        current_time = time.time()
        age = current_time - flow.start_time
        idle_time = current_time - flow.last_seen

        should_export = False
        reason = ""

        # Condiciones de exportación
        if flow.state in ['FIN', 'RST']:
            should_export = True
            reason = f"connection_closed_{flow.state}"
        elif age >= self.max_window:
            should_export = True
            reason = "max_window_reached"
        elif idle_time >= self.base_window and age >= self.min_window:
            should_export = True
            reason = "idle_timeout"
        elif flow.spkts + flow.dpkts >= 100:  # Muchos paquetes
            should_export = True
            reason = "high_packet_count"

        if should_export:
            try:
                # Calcular features derivadas antes de exportar
                self._calculate_derived_features(flow)

                # Enviar a queue de exportación
                export_data = {
                    'flow': asdict(flow),
                    'export_reason': reason,
                    'export_time': current_time
                }

                self.export_queue.put_nowait(export_data)

                # Limpiar flujo
                del self.flows[flow_key]
                self.stats['flows_exported'] += 1

            except queue.Full:
                self.logger.warning("Export queue full, dropping flow")

    def _calculate_derived_features(self, flow: FlowMetrics):
        """Calcula features derivadas antes de exportar"""
        # Packet imbalance
        total_pkts = flow.spkts + flow.dpkts
        if total_pkts > 0:
            flow.packet_imbalance = flow.spkts / total_pkts

        # Byte imbalance
        total_bytes = flow.sbytes + flow.dbytes
        if total_bytes > 0:
            flow.byte_imbalance = flow.sbytes / total_bytes

        # Loss ratio (simulado - en captura real es difícil detectar)
        if flow.spkts > 0:
            flow.loss_ratio = flow.sloss / flow.spkts
        else:
            flow.loss_ratio = 0.0

    def _cleanup_worker(self):
        """Worker thread para limpiar flujos obsoletos"""
        while True:
            try:
                time.sleep(30)  # Limpieza cada 30 segundos
                current_time = time.time()

                with self.lock:
                    expired_flows = []

                    for flow_key, flow in self.flows.items():
                        age = current_time - flow.start_time
                        idle_time = current_time - flow.last_seen

                        # Marcar flujos muy viejos o inactivos para limpieza
                        if age > self.max_window * 2 or idle_time > self.max_window:
                            expired_flows.append(flow_key)

                    # Exportar y limpiar flujos expirados
                    for flow_key in expired_flows:
                        flow = self.flows[flow_key]
                        self._calculate_derived_features(flow)

                        try:
                            export_data = {
                                'flow': asdict(flow),
                                'export_reason': 'cleanup_expired',
                                'export_time': current_time
                            }
                            self.export_queue.put_nowait(export_data)
                        except queue.Full:
                            pass

                        del self.flows[flow_key]
                        self.stats['flows_exported'] += 1

                self.stats['flows_active'] = len(self.flows)

            except Exception as e:
                self.logger.error(f"Error en cleanup worker: {e}")

    def get_stats(self) -> Dict:
        """Retorna estadísticas del tracker"""
        with self.lock:
            stats = self.stats.copy()
            stats['flows_active'] = len(self.flows)
            # Convertir sets a listas para JSON serialization
            stats['protocols_seen'] = list(self.stats['protocols_seen'])
            stats['countries_seen'] = list(self.stats['countries_seen'])
            stats['hours_covered'] = list(self.stats['hours_covered'])
            stats['unique_ips_count'] = len(self.stats['unique_ips'])
            # No incluir el set completo de IPs por privacidad
            del stats['unique_ips']
            return stats

    def should_stop_capture(self) -> Tuple[bool, str]:
        """Determina si deberíamos parar la captura basado en criterios de calidad"""
        with self.lock:
            # Criterios mínimos para un dataset representativo
            min_flows = 10000  # Mínimo 10K flujos
            min_protocols = 3  # TCP, UDP, ICMP como mínimo
            min_countries = 10  # Al menos 10 países diferentes
            min_hours = 12  # Al menos 12 horas del día cubiertas
            min_unique_ips = 1000  # Al menos 1K IPs únicas

            flows_ok = self.stats['flows_exported'] >= min_flows
            protocols_ok = len(self.stats['protocols_seen']) >= min_protocols
            countries_ok = len(self.stats['countries_seen']) >= min_countries
            hours_ok = len(self.stats['hours_covered']) >= min_hours
            ips_ok = len(self.stats['unique_ips']) >= min_unique_ips

            # Calcular score de calidad (0-100)
            quality_score = (
                    (min(self.stats['flows_exported'] / min_flows, 1.0) * 25) +
                    (min(len(self.stats['protocols_seen']) / min_protocols, 1.0) * 15) +
                    (min(len(self.stats['countries_seen']) / min_countries, 1.0) * 25) +
                    (min(len(self.stats['hours_covered']) / min_hours, 1.0) * 15) +
                    (min(len(self.stats['unique_ips']) / min_unique_ips, 1.0) * 20)
            )

            # Criterios de parada
            if quality_score >= 80.0:
                return True, f"✅ Dataset de alta calidad alcanzado (score: {quality_score:.1f}%)"
            elif flows_ok and protocols_ok and countries_ok and hours_ok and ips_ok:
                return True, f"✅ Criterios mínimos cumplidos (score: {quality_score:.1f}%)"
            elif self.stats['flows_exported'] >= 100000:  # Hard limit
                return True, f"⚠️ Límite máximo de flujos alcanzado (100K) - score: {quality_score:.1f}%"
            else:
                missing = []
                if not flows_ok:
                    missing.append(f"flujos: {self.stats['flows_exported']}/{min_flows}")
                if not protocols_ok:
                    missing.append(f"protocolos: {len(self.stats['protocols_seen'])}/{min_protocols}")
                if not countries_ok:
                    missing.append(f"países: {len(self.stats['countries_seen'])}/{min_countries}")
                if not hours_ok:
                    missing.append(f"horas: {len(self.stats['hours_covered'])}/{min_hours}")
                if not ips_ok:
                    missing.append(f"IPs: {len(self.stats['unique_ips'])}/{min_unique_ips}")

                return False, f"📊 Progreso (score: {quality_score:.1f}%) - Falta: {', '.join(missing)}"


# -----------------------------------------------------------------------------
# 📤 EXPORTADOR DE DATOS
# -----------------------------------------------------------------------------
class FlowExporter:
    """Exporta flujos a CSV compatible con advanced-trainer.py"""

    def __init__(self, config, geo_enricher: GeoIPEnricher, flow_tracker=None):
        self.config = config
        self.geo_enricher = geo_enricher
        self.flow_tracker = flow_tracker  # Reference para actualizar stats
        self.output_file = config.get('output_file', 'normal_traffic.csv')
        self.batch_size = config.get('batch_size', 100)

        self.logger = logging.getLogger(__name__)
        self.flows_written = 0
        self.csv_file = None
        self.csv_writer = None

        # Headers compatibles con UNSW-NB15
        self.headers = [
            'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
            'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
            'packet_imbalance', 'byte_imbalance', 'loss_ratio',
            'hour', 'day_of_week', 'is_weekend',
            'src_country', 'src_asn', 'country_risk', 'distance_km',
            'conn_state_abnormal', 'high_port_activity',
            'label'  # Siempre 0 para tráfico normal
        ]

        self._init_csv()

    def _init_csv(self):
        """Inicializa archivo CSV"""
        try:
            self.csv_file = open(self.output_file, 'w', newline='', encoding='utf-8')
            self.csv_writer = csv.DictWriter(self.csv_file, fieldnames=self.headers)
            self.csv_writer.writeheader()
            self.logger.info(f"CSV inicializado: {self.output_file}")
        except Exception as e:
            self.logger.error(f"Error inicializando CSV: {e}")
            raise

    def process_flow(self, flow_data: Dict):
        """Procesa y exporta un flujo"""
        try:
            flow = flow_data['flow']

            # Enriquecimiento geográfico
            geo_data = self.geo_enricher.enrich_ip(flow['src_ip'])

            # Características temporales
            dt = datetime.fromtimestamp(flow['start_time'])

            # Mapeo de servicio a número (simplificado)
            service_map = {
                'http': 1, 'https': 2, 'dns': 3, 'ssh': 4, 'smtp': 5,
                'ftp': 6, 'telnet': 7, 'unknown': 0
            }

            # Mapeo de estado a número
            state_map = {
                'INT': 0, 'CON': 1, 'REQ': 2, 'FIN': 3, 'RST': 4
            }

            # Construir row compatible con UNSW-NB15
            row = {
                'dur': round(flow['dur'], 6),
                'proto': flow['proto'],
                'service': service_map.get(flow['service'], 0),
                'state': state_map.get(flow['state'], 0),
                'spkts': flow['spkts'],
                'dpkts': flow['dpkts'],
                'sbytes': flow['sbytes'],
                'dbytes': flow['dbytes'],
                'rate': round(flow['rate'], 6),
                'sttl': flow['sttl'],
                'dttl': flow['dttl'],
                'sload': round(flow['sload'], 6),
                'dload': round(flow['dload'], 6),
                'sloss': flow['sloss'],
                'dloss': flow['dloss'],
                'sinpkt': round(flow['sinpkt'], 6),
                'dinpkt': round(flow['dinpkt'], 6),
                'packet_imbalance': round(flow.get('packet_imbalance', 0.5), 6),
                'byte_imbalance': round(flow.get('byte_imbalance', 0.5), 6),
                'loss_ratio': round(flow.get('loss_ratio', 0.0), 6),
                'hour': dt.hour,
                'day_of_week': dt.weekday(),
                'is_weekend': 1 if dt.weekday() >= 5 else 0,
                'src_country': geo_data.country_code,
                'src_asn': geo_data.asn,
                'country_risk': geo_data.risk_score,
                'distance_km': round(geo_data.distance_km, 2),
                'conn_state_abnormal': 1 if flow['state'] in ['RST'] else 0,
                'high_port_activity': 1 if (flow['src_port'] > 1024 or flow['dst_port'] > 1024) else 0,
                'label': 0  # Tráfico normal
            }

            # Escribir al CSV
            self.csv_writer.writerow(row)
            self.flows_written += 1

            # Actualizar estadísticas del tracker si está disponible
            if self.flow_tracker and geo_data.country_code != "UNKNOWN":
                with self.flow_tracker.lock:
                    self.flow_tracker.stats['countries_seen'].add(geo_data.country_code)

            # Flush periódico
            if self.flows_written % self.batch_size == 0:
                self.csv_file.flush()
                self.logger.info(f"Flujos exportados: {self.flows_written}")

                # Log estadísticas de progreso cada 1000 flujos
                if self.flow_tracker and self.flows_written % 1000 == 0:
                    should_stop, status = self.flow_tracker.should_stop_capture()
                    self.logger.info(f"Estado del dataset: {status}")
                    if should_stop:
                        self.logger.info("🎯 ¡Dataset listo para advanced-trainer.py!")

        except Exception as e:
            self.logger.error(f"Error procesando flujo para export: {e}")

    def close(self):
        """Cierra archivo CSV"""
        if self.csv_file:
            self.csv_file.close()
            self.logger.info(f"CSV cerrado. Total flujos: {self.flows_written}")


# -----------------------------------------------------------------------------
# 🚀 AGENTE PRINCIPAL
# -----------------------------------------------------------------------------
class PromiscuousAgentV2:
    """Agente principal de captura de tráfico normal"""

    def __init__(self, config_file: str = "promiscuous_agent_v2_config.json"):
        self.running = False

        # Logger primero (antes de cargar config)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        # Cargar configuración
        self.config = self._load_config(config_file)

        # Componentes
        self.geo_enricher = GeoIPEnricher(self.config.get('geoip', {}))
        self.flow_tracker = FlowTracker(self.config.get('flow_tracker', {}))
        self.flow_exporter = FlowExporter(
            self.config.get('exporter', {}),
            self.geo_enricher,
            self.flow_tracker  # Pasar referencia del tracker
        )

        # Thread de exportación
        self.export_thread = threading.Thread(target=self._export_worker, daemon=True)

        # Manejador de señales
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _load_config(self, config_file: str) -> Dict:
        """Carga configuración desde archivo JSON"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.warning(f"Config file not found: {config_file}, using defaults")
            return self._default_config()
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            return self._default_config()

    def _default_config(self) -> Dict:
        """Configuración por defecto"""
        return {
            "interface": "eth0",
            "filter": "not port 22",  # Evitar SSH del propio agente
            "flow_tracker": {
                "min_window": 1.0,
                "base_window": 10.0,
                "max_window": 60.0
            },
            "exporter": {
                "output_file": "normal_traffic.csv",
                "batch_size": 100
            },
            "geoip": {
                "city_db": "GeoLite2-City.mmdb",
                "country_db": "GeoLite2-Country.mmdb",
                "hq_coords": [37.3891, -5.9845]  # Sevilla
            }
        }

    def _stats_worker(self):
        """Worker thread para mostrar estadísticas periódicas"""
        while self.running:
            try:
                time.sleep(30)  # Estadísticas cada 30 segundos

                if not self.running:
                    break

                stats = self.flow_tracker.get_stats()
                should_stop, status = self.flow_tracker.should_stop_capture()

                self.logger.info("=" * 60)
                self.logger.info("📊 ESTADÍSTICAS DE CAPTURA")
                self.logger.info("=" * 60)
                self.logger.info(f"Paquetes procesados: {stats['packets_processed']:,}")
                self.logger.info(f"Flujos exportados: {stats['flows_exported']:,}")
                self.logger.info(f"Flujos activos: {stats['flows_active']:,}")
                self.logger.info(f"Protocolos detectados: {len(stats['protocols_seen'])} {stats['protocols_seen']}")
                self.logger.info(
                    f"Países detectados: {len(stats['countries_seen'])} {stats['countries_seen'][:10]}{'...' if len(stats['countries_seen']) > 10 else ''}")
                self.logger.info(f"Horas cubiertas: {len(stats['hours_covered'])}/24 {sorted(stats['hours_covered'])}")
                self.logger.info(f"IPs únicas: {stats['unique_ips_count']:,}")
                self.logger.info(f"Estado: {status}")

                if should_stop and "alta calidad" in status:
                    self.logger.info("🎉 ¡DATASET COMPLETO! Listo para usar con advanced-trainer.py")
                    self.logger.info("💡 Puedes parar la captura con Ctrl+C")

                self.logger.info("=" * 60)

            except Exception as e:
                self.logger.error(f"Error en stats worker: {e}")

    def _export_worker(self):
        """Worker thread para exportar flujos"""
        while self.running:
            try:
                # Obtener flujo de la queue (timeout 1s)
                flow_data = self.flow_tracker.export_queue.get(timeout=1.0)
                self.flow_exporter.process_flow(flow_data)
                self.flow_tracker.export_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error en export worker: {e}")

    def _signal_handler(self, signum, frame):
        """Manejador de señales para shutdown limpio"""
        self.logger.info(f"Recibida señal {signum}, iniciando shutdown...")
        self.stop()

    def start(self):
        """Inicia la captura de tráfico"""
        self.logger.info("Iniciando Promiscuous Agent v2...")
        self.logger.info(f"Configuración: {json.dumps(self.config, indent=2)}")

        self.running = True

        # Iniciar thread de exportación
        self.export_thread.start()

        # Thread de estadísticas periódicas
        self.stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
        self.stats_thread.start()

        # Verificar interfaz
        interface = self.config.get('interface', 'auto')

        # Auto-detectar interfaz principal en macOS/Linux
        if interface == 'auto' or interface == 'any':
            interface = self._detect_main_interface()
            self.logger.info(f"Interfaz auto-detectada: {interface}")
        elif interface and interface not in psutil.net_if_addrs():
            self.logger.warning(f"Interface {interface} no encontrada")
            interface = self._detect_main_interface()
            self.logger.info(f"Usando interfaz alternativa: {interface}")

        # En macOS, None captura en todas las interfaces
        if interface == 'all':
            interface = None
            self.logger.info("Capturando en todas las interfaces disponibles")

        # Iniciar captura
        try:
            self.logger.info(f"Iniciando captura en interfaz: {interface}")
            self.logger.info(f"Filtro BPF: {self.config.get('filter', 'none')}")

            scapy.sniff(
                iface=interface,
                filter=self.config.get('filter'),
                prn=self.flow_tracker.process_packet,
                stop_filter=lambda x: not self.running
            )

        except PermissionError:
            self.logger.error("Error de permisos. Ejecutar como root/administrador")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Error en captura: {e}")
            sys.exit(1)

    def stop(self):
        """Detiene la captura"""
        self.logger.info("Deteniendo captura...")
        self.running = False

        # Estadísticas finales
        stats = self.flow_tracker.get_stats()
        self.logger.info(f"Estadísticas finales: {stats}")

        # Cerrar exportador
        self.flow_exporter.close()

        self.logger.info("Promiscuous Agent v2 detenido")

    def _detect_main_interface(self) -> Optional[str]:
        """Auto-detecta la interfaz de red principal"""
        try:
            import platform
            system = platform.system().lower()

            # Obtener interfaces con estadísticas
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()

            # Candidatos por sistema operativo
            if system == 'darwin':  # macOS
                preferred_prefixes = ['en0', 'en1', 'en5']  # WiFi y Ethernet principales
            elif system == 'linux':
                preferred_prefixes = ['eth0', 'ens', 'enp', 'wlan0', 'wlp']
            else:
                preferred_prefixes = ['eth0', 'en0', 'wlan0']

            # Buscar interfaz activa con IP
            active_interfaces = []

            for interface_name, addresses in interfaces.items():
                # Saltar loopback, túneles y bridges
                if (interface_name.startswith(('lo', 'utun', 'bridge', 'docker', 'veth')) or
                        'loopback' in interface_name.lower()):
                    continue

                # Verificar si está UP y tiene IP
                if interface_name in stats and stats[interface_name].isup:
                    has_ipv4 = any(addr.family == 2 for addr in addresses)  # AF_INET = 2
                    if has_ipv4:
                        # Priorizar por prefijo conocido
                        priority = 0
                        for i, prefix in enumerate(preferred_prefixes):
                            if interface_name.startswith(prefix):
                                priority = len(preferred_prefixes) - i
                                break

                        active_interfaces.append((priority, interface_name))

            if active_interfaces:
                # Ordenar por prioridad (mayor = mejor)
                active_interfaces.sort(reverse=True)
                selected = active_interfaces[0][1]
                self.logger.info(f"Interfaces activas encontradas: {[name for _, name in active_interfaces]}")
                return selected

            # Fallback: primera interfaz activa
            for interface_name in interfaces:
                if (interface_name in stats and
                        stats[interface_name].isup and
                        not interface_name.startswith(('lo', 'utun', 'bridge'))):
                    return interface_name

            return None

        except Exception as e:
            self.logger.error(f"Error detectando interfaz: {e}")
            return None


# -----------------------------------------------------------------------------
# 🏁 EJECUCIÓN
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Promiscuous Agent v2 - Normal Traffic Capture")
    parser.add_argument("--config", "-c", default="promiscuous_agent_v2_config.json",
                        help="Archivo de configuración JSON")
    parser.add_argument("--interface", "-i",
                        help="Interfaz de red: 'auto', 'all', 'en0', 'eth0', etc.")
    parser.add_argument("--output", "-o",
                        help="Archivo de salida CSV (override config)")
    parser.add_argument("--filter", "-f",
                        help="Filtro BPF personalizado (override config)")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="Listar interfaces disponibles y salir")
    parser.add_argument("--create-config", action="store_true",
                        help="Crear archivo de configuración por defecto y salir")
    args = parser.parse_args()

    # Crear configuración por defecto si se solicita
    if args.create_config:
        config_file = "promiscuous_agent_v2_config.json"
        default_config = {
            "interface": "auto",
            "filter": "not port 22 and not port 443",
            "flow_tracker": {
                "min_window": 1.0,
                "base_window": 10.0,
                "max_window": 60.0
            },
            "exporter": {
                "output_file": "normal_traffic.csv",
                "batch_size": 100
            },
            "geoip": {
                "city_db": "geodata/GeoLite2-City.mmdb",
                "country_db": "geodata/GeoLite2-Country.mmdb",
                "asn_db": "geodata/GeoLite2-ASN-Test.mmdb",
                "cache_size": 10000,
                "hq_coords": [37.3891, -5.9845],
                "use_ipapi_fallback": True,
                "ipapi_token": None
            }
        }

        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)

        print(f"✅ Archivo de configuración creado: {config_file}")
        print("💡 Edítalo según tus necesidades y ejecuta el agente")
        sys.exit(0)

    # Listar interfaces si se solicita
    if args.list_interfaces:
        print("🌐 Interfaces de red disponibles:")
        print("=" * 50)

        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for name, addresses in interfaces.items():
            status = "UP" if name in stats and stats[name].isup else "DOWN"
            ipv4_addr = next((addr.address for addr in addresses if addr.family == 2), "No IP")
            print(f"  {name:12} - {status:4} - {ipv4_addr}")

        print("\n💡 Usar:")
        print("  --interface auto    # Auto-detectar interfaz principal")
        print("  --interface all     # Capturar en todas las interfaces")
        print("  --interface en0     # Interfaz específica")
        sys.exit(0)

    # Crear y ejecutar agente
    # Si no existe promiscuous_agent_v2_config.json, crearlo automáticamente
    if args.config == "promiscuous_agent_v2_config.json" and not os.path.exists("promiscuous_agent_v2_config.json"):
        print("⚠️  promiscuous_agent_v2_config.json no encontrado, creando configuración por defecto...")
        default_config = {
            "interface": "auto",
            "filter": "not port 22 and not port 443",
            "flow_tracker": {
                "min_window": 1.0,
                "base_window": 10.0,
                "max_window": 60.0
            },
            "exporter": {
                "output_file": "normal_traffic.csv",
                "batch_size": 100
            },
            "geoip": {
                "city_db": "geodata/GeoLite2-City.mmdb",
                "country_db": "geodata/GeoLite2-Country.mmdb",
                "asn_db": "geodata/GeoLite2-ASN-Test.mmdb",
                "cache_size": 10000,
                "hq_coords": [37.3891, -5.9845],
                "use_ipapi_fallback": True,
                "ipapi_token": None
            }
        }

        with open("promiscuous_agent_v2_config.json", 'w') as f:
            json.dump(default_config, f, indent=2)
        print("✅ promiscuous_agent_v2_config.json creado automáticamente")

    agent = PromiscuousAgentV2(args.config)

    # Overrides de línea de comandos
    if args.interface:
        agent.config['interface'] = args.interface
    if args.output:
        agent.config['exporter']['output_file'] = args.output
    if args.filter:
        agent.config['filter'] = args.filter

    # Iniciar captura
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()