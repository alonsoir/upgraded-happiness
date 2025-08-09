#!/usr/bin/env python3
"""
geoip_enricher_v31.py - Enriquecedor GeoIP v3.1.0 TRIPARTITO CLEAN
🌍 Enhanced GeoIP Enricher para Upgraded-Happiness (VERTICAL SCALING v3.1.0)
🎯 NUEVO: Enriquecimiento TRIPARTITO (sniffer_node_geo + source_ip_geo + destination_ip_geo)
🏠 NUEVO: sniffer_node_geo calculado UNA SOLA VEZ (IP pública del cluster)
📦 ACTUALIZADO: Protobuf v3.1.0 CLEAN con campos modernos únicamente
🔧 MANTENIDO: Lookup real MaxMind + IPAPI SIN hardcodeos
🔄 CONSERVADO: Backpressure + ZMQ + VerticalScaling del v3.0.0
🚫 ELIMINADO: Compatibilidad hacia atrás + campos legacy
"""

import zmq
import json
import time
import logging
import threading
import sys
import os
import socket
import psutil
import math
import urllib.request
import urllib.error
import ipaddress
from queue import Queue, Empty
from datetime import datetime
from pathlib import Path
from collections import deque, defaultdict
from typing import Dict, Any, Optional, Tuple, List
from threading import Event

# 📦 Protobuf v3.1.0 - REQUERIDO - Importación robusta
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = "unavailable"
NetworkSecurityEventProto = None


def import_protobuf_module():
    """Importa el módulo protobuf v3.1.0 con múltiples estrategias"""
    global NetworkSecurityEventProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    # Estrategia 1: Importación relativa desde protocols.v3.1
    import_strategies = [
        ("protocols.v3.1.network_security_clean_v31_pb2", "Paquete protocols.v3.1"),
        ("protocols.network_security_clean_v31_pb2", "Paquete protocols"),
        ("network_security_clean_v31_pb2", "Importación directa"),
    ]

    for import_path, description in import_strategies:
        try:
            NetworkSecurityEventProto = __import__(import_path, fromlist=[''])
            PROTOBUF_AVAILABLE = True
            PROTOBUF_VERSION = "v3.1.0"
            print(f"✅ Protobuf v3.1 cargado: {description} ({import_path})")
            return True
        except ImportError:
            continue

    # Estrategia 2: Añadir path dinámico y importar
    current_dir = os.path.dirname(os.path.abspath(__file__))
    possible_paths = [
        os.path.join(current_dir, '..', 'protocols', 'v3.1'),
        os.path.join(current_dir, 'protocols', 'v3.1'),
        os.path.join(os.getcwd(), 'protocols', 'v3.1'),
    ]

    for protocols_path in possible_paths:
        protocols_path = os.path.abspath(protocols_path)
        pb2_file = os.path.join(protocols_path, 'network_security_clean_v31_pb2.py')

        if os.path.exists(pb2_file):
            try:
                sys.path.insert(0, protocols_path)
                import network_security_clean_v31_pb2 as NetworkSecurityEventProto
                PROTOBUF_AVAILABLE = True
                PROTOBUF_VERSION = "v3.1.0"
                print(f"✅ Protobuf v3.1 cargado desde path: {protocols_path}")
                return True
            except ImportError as e:
                sys.path.remove(protocols_path)
                continue

    return False


# Ejecutar importación al inicio
import_protobuf_module()

# 🌍 MaxMind GeoIP2 para lookup real
try:
    import geoip2.database
    import geoip2.errors

    MAXMIND_AVAILABLE = True
except ImportError:
    print("⚠️ MaxMind geoip2 no disponible - install: pip install geoip2")
    MAXMIND_AVAILABLE = False

# 📦 Cache LRU para optimización
try:
    from functools import lru_cache

    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False


class PublicIPDiscovery:
    """Descubrimiento y cache de IP pública - v3.1.0 (MANTENIDO del v3.0.0)"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config.get("ip_handling", {}).get("public_ip_discovery", {})
        self.enabled = self.config.get("enabled", False)
        self.services = self.config.get("services", ["https://api.ipify.org"])
        self.timeout = self.config.get("timeout", 10)
        self.cache_duration = self.config.get("cache_duration", 3600)

        # Cache
        self._cached_public_ip = None
        self._cache_timestamp = 0

        self.logger = logging.getLogger("PublicIPDiscovery")

    def get_public_ip(self) -> Optional[str]:
        """Obtiene IP pública con cache"""
        if not self.enabled:
            return None

        # 🗄️ Verificar cache
        now = time.time()
        if (self._cached_public_ip and
                (now - self._cache_timestamp) < self.cache_duration):
            self.logger.debug(f"🗄️ IP pública desde cache: {self._cached_public_ip}")
            return self._cached_public_ip

        # 🌐 Obtener IP pública de servicios
        for service in self.services:
            try:
                ip = self._fetch_public_ip(service)
                if ip:
                    self._cached_public_ip = ip
                    self._cache_timestamp = now
                    self.logger.info(f"✅ IP pública obtenida de {service}: {ip}")
                    return ip
            except Exception as e:
                self.logger.warning(f"❌ Error obteniendo IP de {service}: {e}")
                continue

        self.logger.error("❌ No se pudo obtener IP pública de ningún servicio")
        return None

    def _fetch_public_ip(self, service_url: str) -> Optional[str]:
        """Obtiene IP pública de un servicio específico"""
        try:
            request = urllib.request.Request(service_url)
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                ip = response.read().decode("utf-8").strip()
                # Validar que es una IP válida
                ipaddress.ip_address(ip)
                return ip
        except (urllib.error.URLError, urllib.error.HTTPError,
                ValueError, OSError) as e:
            raise Exception(f"Error fetching from {service_url}: {e}")


class IPAddressHandler:
    """Manejo avanzado de direcciones IP - v3.1.0 (MANTENIDO del v3.0.0)"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config.get("ip_handling", {})
        self.private_ranges = []

        # Configurar rangos de IPs privadas
        for range_str in self.config.get("private_ip_ranges", []):
            try:
                self.private_ranges.append(ipaddress.ip_network(range_str))
            except ValueError as e:
                logging.error(f"❌ Error parseando rango IP privada {range_str}: {e}")

        # Discovery de IP pública
        self.public_ip_discovery = PublicIPDiscovery(config)
        self.logger = logging.getLogger("IPAddressHandler")

    def is_private_ip(self, ip_str: str) -> bool:
        """Verifica si una IP es privada"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in self.private_ranges)
        except ValueError:
            return False

    def resolve_ip_for_lookup(self, ip_str: str, ip_type: str = "unknown") -> Optional[str]:
        """Resuelve qué IP usar para lookup (privada → pública)"""
        if self.is_private_ip(ip_str):
            # Si es IP privada, obtener IP pública
            public_ip = self.public_ip_discovery.get_public_ip()
            if public_ip:
                self.logger.debug(f"🌐 Resolviendo IP pública {public_ip} para {ip_type} privada {ip_str}")
                return public_ip
            else:
                self.logger.warning(f"⚠️ No se pudo obtener IP pública para {ip_type} privada {ip_str}")
                return None
        else:
            # IP pública directa
            return ip_str


class VerticalScalingManager:
    """Gestor de escalado vertical - v3.1.0 (MANTENIDO del v3.0.0)"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.hardware_profile = config.get("monitoring", {}).get("vertical_scaling_metrics", {}).get("hardware_profile",
                                                                                                     "unknown")

        # 🖥️ Información del hardware
        self.cpu_count = psutil.cpu_count()
        self.memory_total = psutil.virtual_memory().total
        self.memory_total_gb = self.memory_total / (1024 ** 3)

        # 📊 Métricas verticales
        self.vertical_metrics = {
            'cpu_per_core': [0.0] * self.cpu_count,
            'memory_pressure': 0.0,
            'cache_efficiency': 0.0,
            'batch_performance': 0.0,
            'hardware_utilization': 0.0,
            'last_update': time.time()
        }

        # 🔧 Optimizaciones específicas
        self.vertical_config = config.get("processing", {}).get("vertical_scaling", {})
        self.leave_cores_for_system = self.vertical_config.get("leave_cores_for_system", 2)
        self.recommended_threads = min(self.cpu_count - self.leave_cores_for_system,
                                       config.get("processing", {}).get("threads", 4))

        logging.info(f"🏗️ Vertical Scaling Manager v3.1.0 inicializado:")
        logging.info(f"   💻 Hardware: {self.hardware_profile}")
        logging.info(f"   🖥️ CPU cores: {self.cpu_count} (usando {self.recommended_threads})")
        logging.info(f"   🧠 RAM total: {self.memory_total_gb:.1f}GB")

    def update_vertical_metrics(self):
        """Actualiza métricas específicas de escalado vertical"""
        try:
            # 💻 CPU por core
            cpu_percents = psutil.cpu_percent(percpu=True)
            if len(cpu_percents) == self.cpu_count:
                self.vertical_metrics['cpu_per_core'] = cpu_percents

            # 🧠 Presión de memoria
            memory = psutil.virtual_memory()
            self.vertical_metrics['memory_pressure'] = memory.percent / 100.0

            # 🖥️ Utilización de hardware total
            avg_cpu = sum(cpu_percents) / len(cpu_percents) / 100.0
            memory_usage = memory.percent / 100.0
            self.vertical_metrics['hardware_utilization'] = (avg_cpu + memory_usage) / 2.0

            self.vertical_metrics['last_update'] = time.time()

        except Exception as e:
            logging.error(f"❌ Error actualizando métricas verticales: {e}")

    def get_cpu_aware_delay(self, base_delay_ms: int) -> float:
        """Calcula delay adaptativo basado en CPU"""
        try:
            avg_cpu = sum(self.vertical_metrics['cpu_per_core']) / len(self.vertical_metrics['cpu_per_core'])

            if avg_cpu > 80.0:  # CPU alta
                return base_delay_ms * 1.5  # Delay mayor
            elif avg_cpu > 60.0:  # CPU media
                return base_delay_ms * 1.2
            else:  # CPU baja
                return base_delay_ms * 0.8  # Delay menor

        except:
            return base_delay_ms

    def get_memory_pressure_factor(self) -> float:
        """Factor de presión de memoria para ajustar caches"""
        memory_pressure = self.vertical_metrics.get('memory_pressure', 0.0)

        if memory_pressure > 0.9:  # 90%+ memoria usada
            return 0.5  # Reducir caches agresivamente
        elif memory_pressure > 0.8:  # 80%+ memoria usada
            return 0.7  # Reducir caches moderadamente
        elif memory_pressure > 0.6:  # 60%+ memoria usada
            return 0.9  # Reducir caches ligeramente
        else:
            return 1.0  # Sin reducción


class DistributedGeoIPEnricherVerticalV31:
    """
    GeoIP Enricher distribuido v3.1.0 TRIPARTITO CLEAN
    🎯 NUEVO: Enriquecimiento TRIPARTITO (sniffer_node_geo + source_ip_geo + destination_ip_geo)
    🏠 NUEVO: sniffer_node_geo calculado UNA SOLA VEZ
    📦 ACTUALIZADO: Protobuf v3.1.0 CLEAN sin compatibilidad hacia atrás
    🔧 MANTENIDO: MaxMind + IPAPI + VerticalScaling del v3.0.0
    🚫 ELIMINADO: Campos legacy + compatibilidad hacia atrás
    """

    def __init__(self, config_file: str):
        # 📄 Cargar configuración
        self.config = self._load_config_strict(config_file)
        self.config_file = config_file

        # 🏷️ Identidad distribuida
        self.node_id = self.config["node_id"]
        self.process_id = os.getpid()
        self.container_id = self._get_container_id()
        self.start_time = time.time()

        # 🖥️ Información del sistema
        self.system_info = self._gather_system_info()

        # 🏗️ Gestor de escalado vertical (MANTENIDO)
        self.vertical_manager = VerticalScalingManager(self.config)

        # 📝 Setup logging desde configuración (PRIMERO)
        self.setup_logging()

        # 🌐 Handler de IPs con discovery público (MANTENIDO)
        self.ip_handler = IPAddressHandler(self.config)

        # 🔌 Setup ZeroMQ con optimizaciones verticales (MANTENIDO)
        self.context = zmq.Context()
        self.input_socket = None
        self.output_socket = None
        self.setup_sockets_vertical()

        # 🔄 Backpressure desde configuración (MANTENIDO)
        self.backpressure_config = self.config["backpressure"]
        self.vertical_backpressure = self.backpressure_config.get("vertical_optimizations", {})

        # 📦 Colas internas optimizadas para hardware (MANTENIDO)
        self.setup_internal_queues_vertical()

        # 🌍 Configuración GeoIP con optimizaciones verticales (MANTENIDO)
        self.geoip_config = self.config["geoip"]
        self.vertical_geoip = self.geoip_config.get("vertical_optimizations", {})

        # 🗄️ Setup cache GeoIP optimizado (MANTENIDO)
        self.setup_geoip_cache_vertical()

        # 🏠 NUEVO v3.1.0: Cache para sniffer_node_geo (UNA SOLA VEZ)
        self._sniffer_geo_cached = None
        self._sniffer_geo_calculated = False

        # 📊 Métricas distribuidas v3.1.0
        self.stats = {
            'received': 0,
            'enriched': 0,
            'sent': 0,
            'failed_lookups': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'buffer_errors': 0,
            'processing_errors': 0,
            'backpressure_activations': 0,
            'queue_overflows': 0,
            'protobuf_errors': 0,
            'pipeline_latency_total': 0.0,
            'batch_processed': 0,
            'vertical_optimizations_applied': 0,
            'cpu_aware_delays': 0,
            'memory_pressure_reductions': 0,
            # 🆕 Estadísticas v3.1.0 TRIPARTITO
            'sniffer_node_geo_enriched': 0,
            'source_ip_geo_enriched': 0,
            'destination_ip_geo_enriched': 0,
            'tripartite_enrichment_success': 0,
            'public_ip_discoveries': 0,
            'v31_events_processed': 0,
            'maxmind_lookups': 0,
            'api_lookups': 0,
            'ipapi_lookups': 0,
            'lookup_failures': 0,
            'sniffer_geo_cache_hits': 0,
            'private_ip_resolutions': 0,
            'network_features_read': 0,
            'geo_enrichment_written': 0,
            'start_time': time.time(),
            'last_stats_time': time.time()
        }

        # 🎛️ Control
        self.running = True
        self.stop_event = Event()

        # 📈 Batch processing inteligente (MANTENIDO)
        self.batch_config = self.config.get("processing", {}).get("batch_processing", {})
        self.batch_queue = Queue(maxsize=self.batch_config.get("batch_size", 50))

        # ✅ Verificar dependencias críticas
        self._verify_dependencies()

        # 📝 Log configuración v3.1.0
        self._log_v31_configuration()

        # 🌐 Log información del proveedor API (MANTENIDO)
        self._log_api_provider_info()

        self.logger.info(f"🌍 Distributed GeoIP Enricher VERTICAL v3.1.0 TRIPARTITO CLEAN inicializado")
        self.logger.info(f"   🏷️ Node ID: {self.node_id}")
        self.logger.info(f"   🔢 PID: {self.process_id}")
        self.logger.info(f"   📄 Config: {config_file}")
        self.logger.info(f"   🏗️ Escalado vertical: ✅")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")
        self.logger.info(f"   🌍 MaxMind: {'✅' if MAXMIND_AVAILABLE else '❌'}")
        self.logger.info(f"   🌐 IPAPI: {'✅' if self.geoip_config.get('api', {}).get('enabled') else '❌'}")
        self.logger.info(f"   🖥️ Hardware profile: {self.vertical_manager.hardware_profile}")
        self.logger.info(f"   🎯 Enriquecimiento TRIPARTITO: sniffer + source + destination ✅")
        self.logger.info(f"   🏠 Sniffer geo: calculado UNA SOLA VEZ ✅")
        self.logger.info(f"   🚫 Compatibilidad hacia atrás: ELIMINADA ✅")

    def _calculate_sniffer_geo_once(self) -> Optional[Dict[str, Any]]:
        """
        🏠 NUEVO v3.1.0: Calcula geolocalización del sniffer UNA SOLA VEZ
        Esta información se cachea porque el nodo no se mueve físicamente
        """
        if self._sniffer_geo_calculated:
            self.stats['sniffer_geo_cache_hits'] += 1
            return self._sniffer_geo_cached

        try:
            # 1. Obtener IP pública del cluster
            public_ip = self.ip_handler.public_ip_discovery.get_public_ip()
            if not public_ip:
                self.logger.error("❌ No se pudo obtener IP pública para sniffer_node_geo")
                self._sniffer_geo_calculated = True
                return None

            # 2. Lookup geolocalización de la IP pública del cluster
            sniffer_geoip = self.get_complete_geoip_info(public_ip)
            if sniffer_geoip and sniffer_geoip.get('latitude') is not None:
                self._sniffer_geo_cached = sniffer_geoip
                self._sniffer_geo_calculated = True

                self.logger.info(f"🏠 Sniffer node geo calculado UNA VEZ:")
                self.logger.info(f"   🌐 IP pública cluster: {public_ip}")
                self.logger.info(
                    f"   📍 Ubicación: {sniffer_geoip.get('city', 'N/A')}, {sniffer_geoip.get('country', 'N/A')}")
                self.logger.info(
                    f"   🗺️ Coordenadas: {sniffer_geoip['latitude']:.4f}, {sniffer_geoip['longitude']:.4f}")

                return sniffer_geoip
            else:
                self.logger.error(f"❌ No se pudo geoposicionar IP pública del cluster: {public_ip}")
                self._sniffer_geo_calculated = True
                return None

        except Exception as e:
            self.logger.error(f"❌ Error calculando sniffer_node_geo: {e}")
            self._sniffer_geo_calculated = True
            return None

    def _load_config_strict(self, config_file: str) -> Dict[str, Any]:
        """Carga configuración SIN proporcionar defaults"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            raise RuntimeError(f"❌ Archivo de configuración no encontrado: {config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ Error parseando JSON: {e}")

        # ✅ Validar campos críticos
        required_fields = [
            "node_id", "network", "zmq", "backpressure", "processing",
            "geoip", "logging", "monitoring", "distributed"
        ]

        for field in required_fields:
            if field not in config:
                raise RuntimeError(f"❌ Campo requerido faltante en config: {field}")

        return config

    def _get_container_id(self) -> Optional[str]:
        """Obtiene ID del contenedor si está ejecutándose en uno"""
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
            'cpu_count': psutil.cpu_count(),
            'memory_total_gb': round(psutil.virtual_memory().total / (1024 ** 3), 2),
            'cpu_freq_max': psutil.cpu_freq().max if psutil.cpu_freq() else 0,
            'load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
        }

    def _verify_dependencies(self):
        """Verifica que las dependencias críticas estén disponibles"""
        issues = []

        if not PROTOBUF_AVAILABLE:
            issues.append("❌ Protobuf network_security_clean_v31_pb2 no disponible")

        if not MAXMIND_AVAILABLE:
            issues.append("⚠️ MaxMind geoip2 no disponible - install: pip install geoip2")

        if not CACHE_AVAILABLE:
            issues.append("⚠️ LRU Cache no disponible - rendimiento reducido")

        if issues:
            for issue in issues:
                print(issue)
            if not PROTOBUF_AVAILABLE:
                raise RuntimeError("❌ Protobuf v3.1 es crítico para el funcionamiento")

    def setup_logging(self):
        """Setup logging dual (consola + archivo) - MANTENIDO del v3.0.0"""
        log_config = self.config["logging"]
        level = getattr(logging, log_config["level"].upper())

        log_format = f"%(asctime)s | {self.node_id} | PID:{self.process_id} | %(levelname)-8s | %(name)-20s | %(message)s"
        formatter = logging.Formatter(log_format)

        self.logger = logging.getLogger(f"geoip_enricher_{self.node_id}")
        self.logger.setLevel(level)

        # Limpiar handlers existentes
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        # 🖥️ Handler de consola
        handlers_config = log_config.get("handlers", {})
        console_config = handlers_config.get("console", {})

        if console_config.get("enabled", True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            console_handler.setLevel(getattr(logging, console_config.get("level", "INFO").upper()))
            self.logger.addHandler(console_handler)

        # 📁 Handler de archivo
        file_config = handlers_config.get("file", {})
        if file_config.get("enabled", False):
            log_file = file_config.get("path", "logs/geoip_enricher_v31.log")

            # Crear directorio si no existe
            log_dir = os.path.dirname(log_file)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(getattr(logging, file_config.get("level", "DEBUG").upper()))
            self.logger.addHandler(file_handler)

        self.logger.propagate = False

    def _log_v31_configuration(self):
        """Log configuración específica v3.1.0"""
        processing_config = self.config.get("processing", {})
        self.logger.info("🎯 Configuración de enriquecimiento v3.1.0 TRIPARTITO:")
        self.logger.info(f"   🏠 sniffer_node_geo: ✅ (calculado una vez)")
        self.logger.info(f"   🎯 source_ip_geo: ✅ (atacantes externos)")
        self.logger.info(f"   📍 destination_ip_geo: ✅ (máquinas internas)")
        self.logger.info(f"   🌐 IP pública discovery: {'✅' if self.ip_handler.public_ip_discovery.enabled else '❌'}")
        self.logger.info(f"   📦 Protobuf version: {PROTOBUF_VERSION}")
        self.logger.info(f"   🌍 GeoIP method: {self.geoip_config.get('lookup_method', 'unknown')}")
        self.logger.info(f"   ⚡ Performance mode: {self.geoip_config.get('performance_mode', 'speed')}")
        self.logger.info(f"   🚫 Compatibilidad hacia atrás: ELIMINADA")

        # 🔑 Log variables de entorno
        ipapi_token = os.environ.get("IPAPI_TOKEN")
        if ipapi_token:
            self.logger.info(f"   🔑 IPAPI_TOKEN: ✅ Configurada desde variable de entorno")
        else:
            self.logger.info(f"   🔑 IPAPI_TOKEN: ❌ No configurada (plan gratuito)")

    def _log_api_provider_info(self):
        """Log información del proveedor de API configurado - MANTENIDO"""
        api_config = self.geoip_config.get("api", {})
        if api_config.get("enabled", False):
            provider = api_config.get("provider", "unknown")
            has_key = bool(api_config.get("api_key"))

            self.logger.info(f"🌐 Proveedor API configurado: {provider}")
            self.logger.info(f"   🔑 API Key: {'✅ Configurada' if has_key else '❌ No configurada'}")
            self.logger.info(f"   ⏱️ Timeout: {api_config.get('timeout_seconds', 5)}s")

    def setup_sockets_vertical(self):
        """Configuración ZMQ - MANTENIDO del v3.0.0"""
        network_config = self.config["network"]
        zmq_config = self.config["zmq"]
        vertical_opts = zmq_config.get("vertical_scaling_optimizations", {})

        try:
            # 🔧 Configurar contexto ZMQ
            if vertical_opts.get("io_threads"):
                self.context = zmq.Context(vertical_opts["io_threads"])

            # 📥 Socket de entrada (PULL) - CONNECT al evolutionary_sniffer_v31
            input_config = network_config["input_socket"]
            self.input_socket = self.context.socket(zmq.PULL)
            self.input_socket.setsockopt(zmq.RCVHWM, zmq_config["rcvhwm"])
            self.input_socket.setsockopt(zmq.RCVTIMEO, zmq_config["recv_timeout_ms"])

            # 🔧 Optimizaciones verticales
            if vertical_opts.get("tcp_keepalive"):
                self.input_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                if vertical_opts.get("tcp_keepalive_idle"):
                    self.input_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, vertical_opts["tcp_keepalive_idle"])

            if vertical_opts.get("immediate"):
                self.input_socket.setsockopt(zmq.IMMEDIATE, 1)

            # CONNECT al puerto del evolutionary_sniffer_v31
            input_address = f"tcp://{input_config['address']}:{input_config['port']}"
            self.input_socket.connect(input_address)

            # 📤 Socket de salida (PUSH) - BIND para ml_detector
            output_config = network_config["output_socket"]
            self.output_socket = self.context.socket(zmq.PUSH)
            self.output_socket.setsockopt(zmq.SNDHWM, zmq_config["sndhwm"])
            self.output_socket.setsockopt(zmq.LINGER, zmq_config["linger_ms"])
            self.output_socket.setsockopt(zmq.SNDTIMEO, zmq_config["send_timeout_ms"])

            if vertical_opts.get("immediate"):
                self.output_socket.setsockopt(zmq.IMMEDIATE, 1)

            # BIND para que ml_detector se conecte
            output_address = f"tcp://*:{output_config['port']}"
            self.output_socket.bind(output_address)

            self.logger.info(f"🔌 Sockets ZMQ VERTICAL v3.1.0 configurados:")
            self.logger.info(f"   📥 Input: CONNECT to {input_address}")
            self.logger.info(f"   📤 Output: BIND on {output_address}")

        except Exception as e:
            raise RuntimeError(f"❌ Error configurando sockets ZMQ: {e}")

    def setup_internal_queues_vertical(self):
        """Configuración de colas internas - MANTENIDO del v3.0.0"""
        proc_config = self.config["processing"]
        memory_factor = self.vertical_manager.get_memory_pressure_factor()

        base_protobuf_size = proc_config["protobuf_queue_size"]
        base_internal_size = proc_config["internal_queue_size"]

        adjusted_protobuf_size = int(base_protobuf_size * memory_factor)
        adjusted_internal_size = int(base_internal_size * memory_factor)

        self.protobuf_queue = Queue(maxsize=adjusted_protobuf_size)
        self.enriched_queue = Queue(maxsize=adjusted_internal_size)

        self.logger.info(f"📋 Colas internas VERTICAL v3.1.0 configuradas")

    def setup_geoip_cache_vertical(self):
        """Configura cache GeoIP - MANTENIDO del v3.0.0"""
        geoip_config = self.config["geoip"]
        vertical_opts = geoip_config.get("vertical_optimizations", {})
        performance_mode = geoip_config.get("performance_mode", "speed")

        if geoip_config.get("cache_enabled", False) and CACHE_AVAILABLE:
            base_cache_size = geoip_config.get("cache_size", 1000)

            if vertical_opts.get("optimized_for_32gb_ram"):
                base_cache_size = min(base_cache_size, 20000)

            memory_factor = self.vertical_manager.get_memory_pressure_factor()

            if performance_mode == "speed":
                final_cache_size = int(base_cache_size * memory_factor * 1.5)
            else:
                final_cache_size = int(base_cache_size * memory_factor * 0.5)

            @lru_cache(maxsize=final_cache_size)
            def cached_lookup(ip_address: str) -> Optional[Dict[str, Any]]:
                return self._direct_geoip_lookup(ip_address)

            self.cached_geoip_lookup = cached_lookup
            self.cache_enabled = True
            self.logger.info(f"🗄️ Cache GeoIP v3.1.0 habilitado: {final_cache_size} entradas")
        else:
            self.cache_enabled = False

    # ============================================================
    # 🌍 MÉTODOS DE LOOKUP GEOIP - MANTENIDOS del v3.0.0
    # ============================================================

    def get_complete_geoip_info(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Obtiene información geográfica completa - MANTENIDO del v3.0.0"""
        if not ip_address or ip_address == 'unknown':
            return None

        try:
            if self.cache_enabled:
                result = self.cached_geoip_lookup(ip_address)
                if result:
                    self.stats['cache_hits'] += 1
                    return result
                else:
                    self.stats['cache_misses'] += 1
            else:
                self.stats['cache_misses'] += 1
                return self._direct_geoip_lookup(ip_address)

        except Exception as e:
            self.logger.warning(f"❌ Error lookup GeoIP completo para {ip_address}: {e}")
            self.stats['lookup_failures'] += 1
            return None

    def _direct_geoip_lookup(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Lookup directo - MANTENIDO del v3.0.0"""
        geoip_config = self.config["geoip"]
        lookup_method = geoip_config.get("lookup_method", "maxmind")
        fallback_method = geoip_config.get("fallback_method", "ipapi")

        # Intentar método primario
        if lookup_method == "maxmind":
            result = self._maxmind_lookup(ip_address)
            if result and result.get('latitude') is not None:
                return result
        elif lookup_method == "ipapi" or lookup_method == "api":
            result = self._api_lookup(ip_address)
            if result and result.get('latitude') is not None:
                return result

        # Intentar fallback
        if fallback_method and fallback_method != lookup_method:
            if fallback_method == "maxmind":
                result = self._maxmind_lookup(ip_address)
                if result and result.get('latitude') is not None:
                    return result
            elif fallback_method == "ipapi" or fallback_method == "api":
                result = self._api_lookup(ip_address)
                if result and result.get('latitude') is not None:
                    return result

        self.stats['lookup_failures'] += 1
        return None

    def _maxmind_lookup(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Lookup MaxMind - MANTENIDO del v3.0.0"""
        if not MAXMIND_AVAILABLE:
            return None

        try:
            maxmind_config = self.geoip_config.get("maxmind", {})
            if not maxmind_config.get("enabled", False):
                return None

            db_path = maxmind_config.get("database_path", "geodata/GeoLite2-City.mmdb")

            with geoip2.database.Reader(db_path) as reader:
                response = reader.city(ip_address)
                self.stats['maxmind_lookups'] += 1

                return {
                    'latitude': float(response.location.latitude) if response.location.latitude else None,
                    'longitude': float(response.location.longitude) if response.location.longitude else None,
                    'city': response.city.name or '',
                    'country': response.country.name or '',
                    'country_code': response.country.iso_code or '',
                    'region': response.subdivisions.most_specific.name or '',
                    'timezone': response.location.time_zone or '',
                    'lookup_method': 'maxmind',
                    'accuracy_radius': response.location.accuracy_radius,
                    'postal_code': response.postal.code or ''
                }

        except geoip2.errors.AddressNotFoundError:
            return None
        except FileNotFoundError:
            self.logger.error(f"❌ MaxMind database no encontrada: {maxmind_config.get('database_path')}")
            return None
        except Exception as e:
            return None

    def _api_lookup(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Lookup API - MANTENIDO del v3.0.0 + ENV variable support"""
        try:
            api_config = self.geoip_config.get("api", {})
            if not api_config.get("enabled", False):
                return None

            provider = api_config.get("provider", "ipgeolocation").lower()
            timeout = api_config.get("timeout_seconds", 5.0)
            max_retries = api_config.get("max_retries", 1)

            # 🔑 NUEVO v3.1.0: Leer API key desde variable de entorno
            api_key = os.environ.get("IPAPI_TOKEN")
            if not api_key:
                # Fallback: leer desde config (para compatibilidad)
                api_key = api_config.get("api_key")
                if api_key and api_key.startswith("$ENV:"):
                    # Si config indica variable de entorno, intentar leerla
                    env_var = api_key.replace("$ENV:", "")
                    api_key = os.environ.get(env_var)

            if provider == "ipapi":
                base_url = api_config.get("base_url", "https://ipapi.co")
                if api_key and api_key.strip():
                    url = f"{base_url}/{ip_address}/json/?key={api_key}"
                    self.logger.debug(f"🔑 Usando IPAPI con API key para {ip_address}")
                else:
                    url = f"{base_url}/{ip_address}/json/"
                    self.logger.debug(f"🆓 Usando IPAPI plan gratuito para {ip_address}")
            else:
                if not api_key or not api_key.strip():
                    self.logger.warning(f"❌ API key requerida para proveedor {provider}")
                    return None
                url = api_config.get("url", "").format(api_key=api_key, ip=ip_address)

            for attempt in range(max_retries + 1):
                try:
                    request = urllib.request.Request(url)
                    request.add_header('User-Agent', 'GeoIP-Enricher-v3.1.0')

                    with urllib.request.urlopen(request, timeout=timeout) as response:
                        raw_data = response.read().decode('utf-8')
                        data = json.loads(raw_data)

                        if provider == "ipapi":
                            if data.get('error'):
                                raise Exception(f"IPAPI error: {data.get('reason', 'Unknown error')}")

                            result = {
                                'latitude': float(data.get('latitude')) if data.get('latitude') else None,
                                'longitude': float(data.get('longitude')) if data.get('longitude') else None,
                                'city': data.get('city', ''),
                                'country': data.get('country_name', ''),
                                'country_code': data.get('country_code', data.get('country', '')),
                                'region': data.get('region', ''),
                                'timezone': data.get('timezone', ''),
                                'lookup_method': 'ipapi',
                                'isp': data.get('org', ''),
                                'organization': data.get('org', ''),
                                'postal_code': data.get('postal', ''),
                            }

                            self.stats['ipapi_lookups'] += 1
                        else:
                            result = {
                                'latitude': float(data.get('latitude')) if data.get('latitude') else None,
                                'longitude': float(data.get('longitude')) if data.get('longitude') else None,
                                'city': data.get('city', ''),
                                'country': data.get('country_name', ''),
                                'country_code': data.get('country_code2', ''),
                                'region': data.get('state_prov', ''),
                                'timezone': data.get('time_zone', {}).get('name', '') if isinstance(
                                    data.get('time_zone'), dict) else data.get('time_zone', ''),
                                'lookup_method': 'api',
                                'isp': data.get('isp', ''),
                                'organization': data.get('organization', '')
                            }

                        if result.get('latitude') is not None and result.get('longitude') is not None:
                            self.stats['api_lookups'] += 1
                            return result
                        else:
                            return None

                except urllib.error.HTTPError as e:
                    if e.code == 429:  # Rate limit
                        if attempt < max_retries:
                            time.sleep(2 ** attempt)
                            continue
                    elif e.code == 403:
                        break
                    else:
                        if attempt < max_retries:
                            time.sleep(1)
                            continue

                except Exception as e:
                    if attempt < max_retries:
                        time.sleep(1)
                        continue
                    break

            return None

        except Exception as e:
            return None

    # ============================================================
    # 🎯 ENRIQUECIMIENTO TRIPARTITO v3.1.0 - NUEVO
    # ============================================================

    def enrich_protobuf_event_v31_tripartite(self, protobuf_data: bytes) -> Optional[bytes]:
        """
        🎯 NUEVO v3.1.0: Enriquecimiento TRIPARTITO CLEAN
        🏠 sniffer_node_geo: Calculado UNA SOLA VEZ
        🎯 source_ip_geo: Atacante externo (PRIORIDAD)
        📍 destination_ip_geo: Máquina interna destino
        """
        if not PROTOBUF_AVAILABLE:
            raise RuntimeError("❌ Protobuf v3.1 no disponible")

        try:
            # 📦 Deserializar evento protobuf v3.1.0
            event = NetworkSecurityEventProto.NetworkSecurityEvent()
            event.ParseFromString(protobuf_data)

            self.stats['v31_events_processed'] += 1

            # 📖 Leer network features (validar que existan)
            if not hasattr(event, 'network_features') or not event.network_features:
                self.logger.error("❌ Event sin network_features válidas")
                return None

            # 📊 Extraer IPs de network_features
            source_ip = event.network_features.source_ip  # IP atacante externa
            destination_ip = event.network_features.destination_ip  # IP destino interna

            if not source_ip or not destination_ip:
                self.logger.error(f"❌ IPs faltantes: source_ip={source_ip}, destination_ip={destination_ip}")
                return None

            self.stats['network_features_read'] += 1
            self.logger.debug(f"📖 Network features leídas: source_ip={source_ip}, destination_ip={destination_ip}")

            # 🌍 Inicializar GeoEnrichment si no existe
            if not hasattr(event, 'geo_enrichment') or not event.geo_enrichment:
                event.geo_enrichment.CopyFrom(NetworkSecurityEventProto.GeoEnrichment())

            # ============================================================
            # 🏠 1. SNIFFER_NODE_GEO - Calculado UNA SOLA VEZ
            # ============================================================

            sniffer_geoip = self._calculate_sniffer_geo_once()
            if sniffer_geoip:
                # Llenar sniffer_node_geo
                sniffer_geo = event.geo_enrichment.sniffer_node_geo
                sniffer_geo.latitude = sniffer_geoip['latitude']
                sniffer_geo.longitude = sniffer_geoip['longitude']
                sniffer_geo.country_name = sniffer_geoip.get('country', '')
                sniffer_geo.country_code = sniffer_geoip.get('country_code', '')
                sniffer_geo.region_name = sniffer_geoip.get('region', '')
                sniffer_geo.city_name = sniffer_geoip.get('city', '')
                sniffer_geo.timezone = sniffer_geoip.get('timezone', '')
                sniffer_geo.isp_name = sniffer_geoip.get('isp', '')
                sniffer_geo.organization_name = sniffer_geoip.get('organization', '')

                # Marcar como enriquecido
                event.geo_enrichment.sniffer_node_enriched = True
                self.stats['sniffer_node_geo_enriched'] += 1

                self.logger.debug(
                    f"✅ sniffer_node_geo enriquecido: {sniffer_geoip['city']}, {sniffer_geoip['country']}")
            else:
                event.geo_enrichment.sniffer_node_enriched = False

            # ============================================================
            # 🎯 2. SOURCE_IP_GEO - Atacante externo (PRIORIDAD ALTA)
            # ============================================================

            source_ip_to_lookup = self.ip_handler.resolve_ip_for_lookup(source_ip, "source_ip")
            if source_ip_to_lookup:
                source_geoip = self.get_complete_geoip_info(source_ip_to_lookup)
                if source_geoip and source_geoip.get('latitude') is not None:
                    # Llenar source_ip_geo
                    source_geo = event.geo_enrichment.source_ip_geo
                    source_geo.latitude = source_geoip['latitude']
                    source_geo.longitude = source_geoip['longitude']
                    source_geo.country_name = source_geoip.get('country', '')
                    source_geo.country_code = source_geoip.get('country_code', '')
                    source_geo.region_name = source_geoip.get('region', '')
                    source_geo.city_name = source_geoip.get('city', '')
                    source_geo.timezone = source_geoip.get('timezone', '')
                    source_geo.isp_name = source_geoip.get('isp', '')
                    source_geo.organization_name = source_geoip.get('organization', '')

                    # TODO: Análisis de amenazas (ThreatLevel)
                    source_geo.threat_level = NetworkSecurityEventProto.GeoLocationInfo.ThreatLevel.UNKNOWN

                    event.geo_enrichment.source_ip_enriched = True
                    self.stats['source_ip_geo_enriched'] += 1

                    self.logger.debug(
                        f"✅ source_ip_geo enriquecido: {source_ip} → {source_geoip['city']}, {source_geoip['country']}")
                else:
                    event.geo_enrichment.source_ip_enriched = False
                    self.logger.warning(f"❌ No se pudo geoposicionar source_ip: {source_ip}")
            else:
                event.geo_enrichment.source_ip_enriched = False

            # ============================================================
            # 📍 3. DESTINATION_IP_GEO - Máquina interna destino
            # ============================================================

            destination_ip_to_lookup = self.ip_handler.resolve_ip_for_lookup(destination_ip, "destination_ip")
            if destination_ip_to_lookup:
                # Si destination_ip es privada y resuelve a misma IP pública que sniffer, usar sniffer geo
                if (self.ip_handler.is_private_ip(destination_ip) and
                        sniffer_geoip and
                        destination_ip_to_lookup == self.ip_handler.public_ip_discovery.get_public_ip()):

                    # Usar geo del sniffer para destination_ip (misma ubicación física)
                    dest_geo = event.geo_enrichment.destination_ip_geo
                    dest_geo.CopyFrom(event.geo_enrichment.sniffer_node_geo)

                    event.geo_enrichment.destination_ip_enriched = True
                    self.stats['destination_ip_geo_enriched'] += 1

                    self.logger.debug(f"✅ destination_ip_geo enriquecido usando sniffer geo: {destination_ip}")
                else:
                    # Lookup independiente para destination_ip
                    dest_geoip = self.get_complete_geoip_info(destination_ip_to_lookup)
                    if dest_geoip and dest_geoip.get('latitude') is not None:
                        dest_geo = event.geo_enrichment.destination_ip_geo
                        dest_geo.latitude = dest_geoip['latitude']
                        dest_geo.longitude = dest_geoip['longitude']
                        dest_geo.country_name = dest_geoip.get('country', '')
                        dest_geo.country_code = dest_geoip.get('country_code', '')
                        dest_geo.region_name = dest_geoip.get('region', '')
                        dest_geo.city_name = dest_geoip.get('city', '')
                        dest_geo.timezone = dest_geoip.get('timezone', '')
                        dest_geo.isp_name = dest_geoip.get('isp', '')
                        dest_geo.organization_name = dest_geoip.get('organization', '')
                        dest_geo.threat_level = NetworkSecurityEventProto.GeoLocationInfo.ThreatLevel.LOW  # Interno

                        event.geo_enrichment.destination_ip_enriched = True
                        self.stats['destination_ip_geo_enriched'] += 1

                        self.logger.debug(f"✅ destination_ip_geo enriquecido independiente: {destination_ip}")
                    else:
                        event.geo_enrichment.destination_ip_enriched = False
            else:
                event.geo_enrichment.destination_ip_enriched = False

            # ============================================================
            # 📊 METADATOS DE ENRIQUECIMIENTO v3.1.0
            # ============================================================

            # Estado general del enriquecimiento
            total_enriched = sum([
                event.geo_enrichment.sniffer_node_enriched,
                event.geo_enrichment.source_ip_enriched,
                event.geo_enrichment.destination_ip_enriched
            ])

            event.geo_enrichment.enrichment_complete = (total_enriched >= 2)  # Al menos 2 de 3

            if total_enriched == 3:
                self.stats['tripartite_enrichment_success'] += 1

            # Versión del enricher
            event.geo_enrichment.enricher_version = "3.1.0_tripartite_clean"
            event.geo_enrichment.geoip_method = self.geoip_config.get("lookup_method", "maxmind")

            # Timestamp del enriquecimiento
            current_time_ms = int(time.time() * 1000)
            event.geo_enrichment.enrichment_timestamp.FromMilliseconds(current_time_ms)

            # Latencia de lookup
            event.geo_enrichment.total_lookup_latency_ms = 0.0  # TODO: medir latencia real

            # Cache hits/misses
            event.geo_enrichment.cache_hits = self.stats.get('cache_hits', 0)
            event.geo_enrichment.cache_misses = self.stats.get('cache_misses', 0)

            self.stats['geo_enrichment_written'] += 1

            # 🔄 Serializar evento enriquecido
            return event.SerializeToString()

        except Exception as e:
            self.stats['protobuf_errors'] += 1
            self.logger.error(f"❌ Error enriquecimiento v3.1.0 TRIPARTITO: {e}")
            return None

    # ================================================================
    # 🔄 MÉTODOS DE THREADING - MANTENIDOS del v3.0.0
    # ================================================================

    def receive_protobuf_events_vertical(self):
        """Thread de recepción - MANTENIDO del v3.0.0"""
        self.logger.info("📡 Iniciando thread de recepción protobuf VERTICAL v3.1.0...")

        consecutive_errors = 0
        queue_full_count = 0

        while self.running:
            try:
                # 📊 Actualizar métricas verticales periódicamente
                if time.time() % 5 < 0.1:
                    self.vertical_manager.update_vertical_metrics()

                # 📨 Recibir evento protobuf desde evolutionary_sniffer_v31
                protobuf_data = self.input_socket.recv(zmq.NOBLOCK)
                self.stats['received'] += 1
                consecutive_errors = 0

                # 🔍 Verificar presión según hardware
                current_queue_usage = self.protobuf_queue.qsize() / self.protobuf_queue.maxsize
                cpu_pressure = sum(self.vertical_manager.vertical_metrics['cpu_per_core']) / len(
                    self.vertical_manager.vertical_metrics['cpu_per_core'])

                # 📋 Añadir a cola
                try:
                    queue_config = self.config["processing"].get("queue_overflow_handling", {})
                    queue_timeout = queue_config.get("max_queue_wait_ms", 100) / 1000.0
                    self.protobuf_queue.put(protobuf_data, timeout=queue_timeout)
                    queue_full_count = 0
                except:
                    self.stats['queue_overflows'] += 1

            except zmq.Again:
                continue
            except zmq.ZMQError as e:
                consecutive_errors += 1
                if consecutive_errors % 10 == 0:
                    self.logger.error(f"❌ Error ZMQ recepción v3.1.0 ({consecutive_errors}): {e}")
                time.sleep(0.1)

    def process_protobuf_events_vertical(self):
        """Thread de procesamiento v3.1.0"""
        self.logger.info("⚙️ Iniciando thread de procesamiento VERTICAL v3.1.0 TRIPARTITO...")

        queue_timeout = self.config["processing"]["queue_timeout_seconds"]

        while self.running:
            try:
                protobuf_data = self.protobuf_queue.get(timeout=queue_timeout)
                start_time = time.time()

                # 🌍 Enriquecer con lógica TRIPARTITA v3.1.0
                enriched_protobuf = self.enrich_protobuf_event_v31_tripartite(protobuf_data)

                if enriched_protobuf:
                    processing_time = (time.time() - start_time) * 1000
                    self.stats['pipeline_latency_total'] += processing_time
                    self.stats['enriched'] += 1

                    try:
                        self.enriched_queue.put(enriched_protobuf, timeout=queue_timeout)
                    except:
                        self.stats['queue_overflows'] += 1

                self.protobuf_queue.task_done()

            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"❌ Error procesamiento v3.1.0 TRIPARTITO: {e}")
                self.stats['processing_errors'] += 1

    def send_event_with_backpressure_vertical(self, enriched_data: bytes) -> bool:
        """Envío con backpressure - MANTENIDO del v3.0.0"""
        bp_config = self.backpressure_config
        vertical_opts = self.vertical_backpressure
        max_retries = bp_config["max_retries"]

        for attempt in range(max_retries + 1):
            try:
                self.output_socket.send(enriched_data, zmq.NOBLOCK)
                return True

            except zmq.Again:
                self.stats['buffer_errors'] += 1
                if attempt == max_retries:
                    return False

                if not self._apply_backpressure_vertical(attempt):
                    return False
                continue

            except zmq.ZMQError as e:
                self.logger.error(f"❌ Error ZMQ envío v3.1.0: {e}")
                return False

        return False

    def _apply_backpressure_vertical(self, attempt: int) -> bool:
        """Aplica backpressure adaptativo - MANTENIDO del v3.0.0"""
        bp_config = self.backpressure_config
        vertical_opts = self.vertical_backpressure

        if not bp_config["enabled"]:
            return False

        if attempt >= bp_config["max_retries"]:
            return False

        delays = bp_config["retry_delays_ms"]
        base_delay_ms = delays[attempt] if attempt < len(delays) else delays[-1]

        if vertical_opts.get("cpu_aware_backpressure", False):
            adapted_delay = self.vertical_manager.get_cpu_aware_delay(base_delay_ms)
            self.stats['cpu_aware_delays'] += 1
        else:
            adapted_delay = base_delay_ms

        time.sleep(adapted_delay / 1000.0)
        self.stats['backpressure_activations'] += 1
        return True

    def send_enriched_events(self):
        """Thread de envío v3.1.0"""
        self.logger.info("📤 Iniciando thread de envío vertical v3.1.0...")
        queue_timeout = self.config["processing"]["queue_timeout_seconds"]

        while self.running:
            try:
                enriched_protobuf = self.enriched_queue.get(timeout=queue_timeout)
                success = self.send_event_with_backpressure_vertical(enriched_protobuf)
                if success:
                    self.stats['sent'] += 1
                self.enriched_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"❌ Error envío v3.1.0: {e}")

    def monitor_performance_vertical(self):
        """Thread de monitoreo v3.1.0"""
        monitoring_config = self.config["monitoring"]
        interval = monitoring_config["stats_interval_seconds"]

        while self.running:
            time.sleep(interval)
            if not self.running:
                break

            self.vertical_manager.update_vertical_metrics()
            self._log_performance_stats_v31_tripartite()

    def _log_performance_stats_v31_tripartite(self):
        """Log de estadísticas v3.1.0 TRIPARTITO"""
        now = time.time()
        interval = now - self.stats['last_stats_time']

        # 📊 Rates
        recv_rate = self.stats['received'] / interval if interval > 0 else 0
        enrich_rate = self.stats['enriched'] / interval if interval > 0 else 0
        send_rate = self.stats['sent'] / interval if interval > 0 else 0

        # 📊 Estadísticas TRIPARTITO
        tripartite_success_rate = 0.0
        if self.stats['enriched'] > 0:
            tripartite_success_rate = (self.stats['tripartite_enrichment_success'] / self.stats['enriched']) * 100

        # 🖥️ Métricas verticales
        vertical_metrics = self.vertical_manager.vertical_metrics
        cpu_avg = sum(vertical_metrics['cpu_per_core']) / len(vertical_metrics['cpu_per_core'])

        self.logger.info(f"📊 GeoIP Enricher VERTICAL v3.1.0 TRIPARTITO Stats:")
        self.logger.info(f"   📨 Recibidos: {self.stats['received']} ({recv_rate:.1f}/s)")
        self.logger.info(f"   🌍 Enriquecidos: {self.stats['enriched']} ({enrich_rate:.1f}/s)")
        self.logger.info(f"   📤 Enviados: {self.stats['sent']} ({send_rate:.1f}/s)")
        self.logger.info(f"   🏠 Sniffer node geo: {self.stats['sniffer_node_geo_enriched']}")
        self.logger.info(f"   🎯 Source IP geo: {self.stats['source_ip_geo_enriched']}")
        self.logger.info(f"   📍 Destination IP geo: {self.stats['destination_ip_geo_enriched']}")
        self.logger.info(
            f"   🎯🏠📍 Enriquecimiento TRIPARTITO completo: {self.stats['tripartite_enrichment_success']} ({tripartite_success_rate:.1f}%)")
        self.logger.info(f"   📦 Eventos v3.1 procesados: {self.stats['v31_events_processed']}")
        self.logger.info(f"   🗄️ Sniffer geo cache hits: {self.stats['sniffer_geo_cache_hits']}")
        self.logger.info(f"   🌍 MaxMind lookups: {self.stats['maxmind_lookups']}")
        self.logger.info(f"   🌐 IPAPI lookups: {self.stats['ipapi_lookups']}")
        self.logger.info(f"   🖥️ CPU promedio: {cpu_avg:.1f}%")

        # Reset stats
        for key in ['received', 'enriched', 'sent', 'failed_lookups', 'cache_hits', 'cache_misses',
                    'buffer_errors', 'backpressure_activations', 'queue_overflows', 'protobuf_errors',
                    'sniffer_node_geo_enriched', 'source_ip_geo_enriched', 'destination_ip_geo_enriched',
                    'tripartite_enrichment_success', 'v31_events_processed', 'maxmind_lookups', 'ipapi_lookups']:
            self.stats[key] = 0

        self.stats['pipeline_latency_total'] = 0.0
        self.stats['last_stats_time'] = now

    def run(self):
        """Ejecutar el enriquecedor v3.1.0 TRIPARTITO"""
        self.logger.info("🚀 Iniciando Distributed GeoIP Enricher VERTICAL v3.1.0 TRIPARTITO CLEAN...")

        threads = []

        # Thread de recepción
        recv_thread = threading.Thread(target=self.receive_protobuf_events_vertical, name="V31Receiver")
        threads.append(recv_thread)

        # Threads de procesamiento
        num_threads = self.vertical_manager.recommended_threads
        for i in range(num_threads):
            proc_thread = threading.Thread(target=self.process_protobuf_events_vertical, name=f"V31Processor-{i}")
            threads.append(proc_thread)

        # Threads de envío
        num_send_threads = self.config["processing"].get("send_threads", 2)
        for i in range(num_send_threads):
            send_thread = threading.Thread(target=self.send_enriched_events, name=f"V31Sender-{i}")
            threads.append(send_thread)

        # Thread de monitoreo
        monitor_thread = threading.Thread(target=self.monitor_performance_vertical, name="V31Monitor")
        threads.append(monitor_thread)

        # 🚀 Iniciar todos los threads
        for thread in threads:
            thread.start()

        self.logger.info(f"✅ GeoIP Enricher VERTICAL v3.1.0 TRIPARTITO iniciado con {len(threads)} threads")
        self.logger.info(f"   🎯 Enriquecimiento: TRIPARTITO (sniffer + source + destination)")
        self.logger.info(f"   🏠 Sniffer geo: calculado UNA SOLA VEZ")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")
        self.logger.info(f"   🌍 MaxMind: {'✅' if MAXMIND_AVAILABLE else '❌'}")
        self.logger.info(f"   🌐 IPAPI: {'✅' if self.geoip_config.get('api', {}).get('enabled') else '❌'}")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("🛑 Deteniendo GeoIP Enricher v3.1.0 TRIPARTITO...")

        self.shutdown(threads)

    def shutdown(self, threads):
        """Cierre graceful v3.1.0"""
        self.running = False
        self.stop_event.set()

        runtime = time.time() - self.stats['start_time']
        total_v31_events = self.stats.get('v31_events_processed', 0)
        total_tripartite = self.stats.get('tripartite_enrichment_success', 0)

        self.logger.info(f"📊 Stats finales v3.1.0 TRIPARTITO - Runtime: {runtime:.1f}s")
        self.logger.info(f"   📦 Total eventos v3.1 procesados: {total_v31_events}")
        self.logger.info(f"   🎯🏠📍 Total enriquecimiento TRIPARTITO: {total_tripartite}")

        for thread in threads:
            thread.join(timeout=5)

        if self.input_socket:
            self.input_socket.close()
        if self.output_socket:
            self.output_socket.close()
        self.context.term()

        self.logger.info("✅ Distributed GeoIP Enricher v3.1.0 TRIPARTITO cerrado correctamente")


# 🚀 Main
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Uso: python geoip_enricher_v31.py <config.json>")
        print("💡 Ejemplo: python geoip_enricher_v31.py geoip_enricher_config_v31.json")
        print()
        print("🔑 Variables de entorno opcionales:")
        print("   export IPAPI_TOKEN='tu_token_ipapi_aqui'  # Para plan pago IPAPI")
        print("   # Si no se configura, se usará plan gratuito (1000 requests/mes)")
        sys.exit(1)

    config_file = sys.argv[1]

    # 🔑 Verificar variables de entorno
    ipapi_token = os.environ.get("IPAPI_TOKEN")
    if ipapi_token:
        print(f"✅ Variable IPAPI_TOKEN configurada (longitud: {len(ipapi_token)} chars)")
    else:
        print("ℹ️ Variable IPAPI_TOKEN no configurada - usando plan gratuito IPAPI")

    try:
        enricher = DistributedGeoIPEnricherVerticalV31(config_file)
        enricher.run()
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)