#!/usr/bin/env python3
"""
geoip_enricher_v3.py - Enriquecedor GeoIP optimizado para escalado vertical v3.0.0
🌍 Enhanced GeoIP Enricher para Upgraded-Happiness (VERTICAL SCALING v3.0.0)
🚨 BUG FIX CRÍTICO: source_ip → target_ip para geoposicionar atacantes
🌐 NUEVO: Discovery automático de IP pública
🎯 NUEVO: Enriquecimiento dual (source_ip + target_ip)
📦 ACTUALIZADO: Protobuf v3.0.0 con nuevos campos
📝 MEJORADO: Logging dual (consola + archivo)
🔧 MODIFICADO: Lookup real MaxMind SIN hardcodeos
- Optimizado para i9 8-cores + 32GB RAM
- Lee configuraciones de escalado vertical desde JSON
- Backpressure adaptativo según CPU y memoria
- Caches optimizadas para hardware específico
- Métricas verticales detalladas
- Batch processing inteligente
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

# 📦 Protobuf v3.0.0 - ACTUALIZADO
try:
    import src.protocols.protobuf.network_event_extended_v3_pb2 as NetworkEventProto

    PROTOBUF_AVAILABLE = True
    PROTOBUF_VERSION = "v3.0.0"
except ImportError:
    try:
        from src.protocols.protobuf import network_event_extended_v3_pb2 as NetworkEventProto

        PROTOBUF_AVAILABLE = True
        PROTOBUF_VERSION = "v3.0.0"
    except ImportError:
        print("⚠️ Protobuf network_event_extended_v3_pb2 no disponible")
        PROTOBUF_AVAILABLE = False
        PROTOBUF_VERSION = "unavailable"

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
    """Descubrimiento y cache de IP pública - v3.0.0"""

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
    """Manejo avanzado de direcciones IP - v3.0.0"""

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

    def resolve_source_ip_for_lookup(self, source_ip: str) -> Optional[str]:
        """Resuelve qué IP usar para lookup de source_ip (nuestra IP)"""
        if self.is_private_ip(source_ip):
            # Si es IP privada, obtener IP pública
            public_ip = self.public_ip_discovery.get_public_ip()
            if public_ip:
                self.logger.debug(f"🌐 Resolviendo IP pública {public_ip} para source_ip privada {source_ip}")
                return public_ip
            else:
                # No se pudo obtener IP pública
                self.logger.warning(f"⚠️ No se pudo obtener IP pública para source_ip privada {source_ip}")
                return None
        else:
            # IP pública directa
            return source_ip

    def resolve_target_ip_for_lookup(self, target_ip: str) -> Optional[str]:
        """Resuelve qué IP usar para lookup de target_ip (atacante)"""
        if self.is_private_ip(target_ip):
            self.logger.warning(f"⚠️ target_ip es privada: {target_ip} - posible error en captura")
            return None
        return target_ip


class VerticalScalingManager:
    """Gestor de escalado vertical con métricas de hardware específicas"""

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

        logging.info(f"🏗️ Vertical Scaling Manager inicializado:")
        logging.info(f"   💻 Hardware: {self.hardware_profile}")
        logging.info(f"   🖥️ CPU cores: {self.cpu_count} (usando {self.recommended_threads})")
        logging.info(f"   🧠 RAM total: {self.memory_total_gb:.1f}GB")
        logging.info(f"   🎯 Cores reservados para sistema: {self.leave_cores_for_system}")

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

    def should_enable_batch_processing(self) -> bool:
        """Determina si habilitar batch processing según recursos"""
        cpu_avg = sum(self.vertical_metrics['cpu_per_core']) / len(self.vertical_metrics['cpu_per_core'])
        memory_ok = self.vertical_metrics['memory_pressure'] < 0.8

        return cpu_avg < 70.0 and memory_ok


class DistributedGeoIPEnricherVertical:
    """
    GeoIP Enricher distribuido optimizado para escalado vertical v3.0.0
    🚨 BUG FIX: Geoposiciona target_ip (atacantes) correctamente
    🌐 NUEVO: Discovery automático de IP pública
    🎯 NUEVO: Enriquecimiento dual (source + target)
    📦 ACTUALIZADO: Protobuf v3.0.0 con campos duales
    📝 MEJORADO: Logging dual (consola + archivo)
    🔧 MODIFICADO: Lookup real MaxMind SIN hardcodeos
    """

    def __init__(self, config_file: str):
        # 📄 Cargar configuración - SIN defaults hardcodeados
        self.config = self._load_config_strict(config_file)
        self.config_file = config_file

        # 🏷️ Identidad distribuida
        self.node_id = self.config["node_id"]
        self.process_id = os.getpid()
        self.container_id = self._get_container_id()
        self.start_time = time.time()

        # 🖥️ Información del sistema
        self.system_info = self._gather_system_info()

        # 🏗️ Gestor de escalado vertical
        self.vertical_manager = VerticalScalingManager(self.config)

        # 📝 Setup logging desde configuración (PRIMERO)
        self.setup_logging()

        # 🌐 NUEVO v3.0.0: Handler de IPs con discovery público
        self.ip_handler = IPAddressHandler(self.config)

        # 🔌 Setup ZeroMQ con optimizaciones verticales
        self.context = zmq.Context()
        self.input_socket = None
        self.output_socket = None
        self.setup_sockets_vertical()

        # 🔄 Backpressure desde configuración con optimizaciones verticales
        self.backpressure_config = self.config["backpressure"]
        self.vertical_backpressure = self.backpressure_config.get("vertical_optimizations", {})

        # 📦 Colas internas optimizadas para hardware
        self.setup_internal_queues_vertical()

        # 🌍 Configuración GeoIP con optimizaciones verticales
        self.geoip_config = self.config["geoip"]
        self.vertical_geoip = self.geoip_config.get("vertical_optimizations", {})

        # 🗄️ Setup cache GeoIP optimizado
        self.setup_geoip_cache_vertical()

        # 📊 Métricas distribuidas con métricas verticales v3.0.0
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
            # 🆕 Estadísticas v3.0.0 específicas
            'source_ip_enriched': 0,
            'target_ip_enriched': 0,
            'dual_enrichment_success': 0,
            'public_ip_discoveries': 0,
            'v3_events_processed': 0,
            'maxmind_lookups': 0,
            'api_lookups': 0,
            'lookup_failures': 0,
            'start_time': time.time(),
            'last_stats_time': time.time()
        }

        # 🎛️ Control
        self.running = True
        self.stop_event = Event()

        # 📈 Batch processing inteligente
        self.batch_config = self.config.get("processing", {}).get("batch_processing", {})
        self.batch_queue = Queue(maxsize=self.batch_config.get("batch_size", 50))

        # ✅ Verificar dependencias críticas
        self._verify_dependencies()

        # 📝 Log configuración v3.0.0
        self._log_v3_configuration()

        self.logger.info(f"🌍 Distributed GeoIP Enricher VERTICAL v3.0.0 inicializado")
        self.logger.info(f"   🏷️ Node ID: {self.node_id}")
        self.logger.info(f"   🔢 PID: {self.process_id}")
        self.logger.info(f"   📄 Config: {config_file}")
        self.logger.info(f"   🏗️ Escalado vertical: ✅")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")
        self.logger.info(f"   🌍 MaxMind: {'✅' if MAXMIND_AVAILABLE else '❌'}")
        self.logger.info(f"   🖥️ Hardware profile: {self.vertical_manager.hardware_profile}")
        self.logger.info(f"   🚨 Bug fix aplicado: target_ip geoposicionado ✅")

    def _log_v3_configuration(self):
        """Log configuración específica v3.0.0"""
        processing_config = self.config.get("processing", {})
        self.logger.info("🎯 Configuración de enriquecimiento v3.0.0:")
        self.logger.info(f"   🏠 source_ip: {'✅' if processing_config.get('geolocate_source_ip') else '❌'}")
        self.logger.info(f"   🎯 target_ip: {'✅' if processing_config.get('geolocate_target_ip') else '❌'}")
        self.logger.info(
            f"   ⭐ Prioridad: {'target_ip' if processing_config.get('prioritize_target_ip') else 'source_ip'}")
        self.logger.info(f"   🌐 IP pública discovery: {'✅' if self.ip_handler.public_ip_discovery.enabled else '❌'}")
        self.logger.info(f"   📦 Protobuf version: {PROTOBUF_VERSION}")
        self.logger.info(f"   🌍 GeoIP method: {self.geoip_config.get('lookup_method', 'unknown')}")
        self.logger.info(f"   ⚡ Performance mode: {self.geoip_config.get('performance_mode', 'speed')}")

        if self.ip_handler.public_ip_discovery.enabled:
            services = self.ip_handler.public_ip_discovery.services
            self.logger.info(f"   🔗 Servicios IP discovery: {len(services)} configurados")
            for service in services:
                self.logger.debug(f"     - {service}")

    def _load_config_strict(self, config_file: str) -> Dict[str, Any]:
        """Carga configuración SIN proporcionar defaults"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            raise RuntimeError(f"❌ Archivo de configuración no encontrado: {config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ Error parseando JSON: {e}")

        # ✅ Validar campos críticos incluyendo verticales
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
        """Recolecta información del sistema con detalles verticales"""
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
            issues.append("❌ Protobuf network_event_extended_v3_pb2 no disponible")

        if not MAXMIND_AVAILABLE:
            issues.append("⚠️ MaxMind geoip2 no disponible - install: pip install geoip2")

        if not CACHE_AVAILABLE:
            issues.append("⚠️ LRU Cache no disponible - rendimiento reducido")

        if issues:
            for issue in issues:
                print(issue)
            if not PROTOBUF_AVAILABLE:
                raise RuntimeError("❌ Protobuf v3 es crítico para el funcionamiento")

    def setup_logging(self):
        """Setup logging dual (consola + archivo) con formato de una línea"""
        log_config = self.config["logging"]

        # 📝 Configurar nivel
        level = getattr(logging, log_config["level"].upper())

        # 🏷️ Formato compacto de una línea
        log_format = f"%(asctime)s | {self.node_id} | PID:{self.process_id} | %(levelname)-8s | %(name)-20s | %(message)s"
        formatter = logging.Formatter(log_format)

        # 🔧 Setup logger principal
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
            self.logger.debug("🖥️ Console logging habilitado")

        # 📁 Handler de archivo
        file_config = handlers_config.get("file", {})
        if file_config.get("enabled", False):
            log_file = file_config.get("path", "logs/geoip_enricher.log")

            # Crear directorio si no existe
            log_dir = os.path.dirname(log_file)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(getattr(logging, file_config.get("level", "DEBUG").upper()))
            self.logger.addHandler(file_handler)
            self.logger.info(f"📁 File logging habilitado: {log_file}")

        self.logger.propagate = False
        self.logger.info("📝 Logging dual configurado correctamente (consola + archivo, formato de una línea)")

    def setup_sockets_vertical(self):
        """Configuración ZMQ con optimizaciones verticales"""
        network_config = self.config["network"]
        zmq_config = self.config["zmq"]
        vertical_opts = zmq_config.get("vertical_scaling_optimizations", {})

        try:
            # 🔧 Configurar contexto ZMQ con optimizaciones verticales
            if vertical_opts.get("io_threads"):
                self.context = zmq.Context(vertical_opts["io_threads"])

            # 📥 Socket de entrada (PULL) - CONNECT al promiscuous_agent
            input_config = network_config["input_socket"]
            self.input_socket = self.context.socket(zmq.PULL)
            self.input_socket.setsockopt(zmq.RCVHWM, zmq_config["rcvhwm"])
            self.input_socket.setsockopt(zmq.RCVTIMEO, zmq_config["recv_timeout_ms"])

            # 🔧 Optimizaciones verticales para input
            if vertical_opts.get("tcp_keepalive"):
                self.input_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                if vertical_opts.get("tcp_keepalive_idle"):
                    self.input_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, vertical_opts["tcp_keepalive_idle"])

            if vertical_opts.get("immediate"):
                self.input_socket.setsockopt(zmq.IMMEDIATE, 1)

            # CONNECT al puerto del promiscuous_agent
            input_address = f"tcp://{input_config['address']}:{input_config['port']}"
            self.input_socket.connect(input_address)

            # 📤 Socket de salida (PUSH) - BIND para ml_detector
            output_config = network_config["output_socket"]
            self.output_socket = self.context.socket(zmq.PUSH)
            self.output_socket.setsockopt(zmq.SNDHWM, zmq_config["sndhwm"])
            self.output_socket.setsockopt(zmq.LINGER, zmq_config["linger_ms"])
            self.output_socket.setsockopt(zmq.SNDTIMEO, zmq_config["send_timeout_ms"])

            # 🔧 Optimizaciones verticales para output
            if vertical_opts.get("immediate"):
                self.output_socket.setsockopt(zmq.IMMEDIATE, 1)

            # BIND para que ml_detector se conecte
            output_address = f"tcp://*:{output_config['port']}"
            self.output_socket.bind(output_address)

            self.logger.info(f"🔌 Sockets ZMQ VERTICAL v3.0.0 configurados:")
            self.logger.info(f"   📥 Input: CONNECT to {input_address}")
            self.logger.info(f"   📤 Output: BIND on {output_address}")
            self.logger.info(f"   🌊 RCVHWM: {zmq_config['rcvhwm']}, SNDHWM: {zmq_config['sndhwm']}")
            self.logger.info(f"   🏗️ IO Threads: {vertical_opts.get('io_threads', 1)}")
            self.logger.info(f"   ⚡ TCP Optimizations: {'✅' if vertical_opts.get('tcp_keepalive') else '❌'}")

        except Exception as e:
            raise RuntimeError(f"❌ Error configurando sockets ZMQ verticales: {e}")

    def setup_internal_queues_vertical(self):
        """Configuración de colas internas optimizadas para hardware"""
        proc_config = self.config["processing"]

        # 📊 Ajustar tamaños según memoria disponible
        memory_factor = self.vertical_manager.get_memory_pressure_factor()

        base_protobuf_size = proc_config["protobuf_queue_size"]
        base_internal_size = proc_config["internal_queue_size"]

        adjusted_protobuf_size = int(base_protobuf_size * memory_factor)
        adjusted_internal_size = int(base_internal_size * memory_factor)

        # 📋 Cola principal para eventos protobuf sin procesar
        self.protobuf_queue = Queue(maxsize=adjusted_protobuf_size)

        # 📋 Cola para eventos enriquecidos listos para envío
        self.enriched_queue = Queue(maxsize=adjusted_internal_size)

        self.logger.info(f"📋 Colas internas VERTICAL v3.0.0 configuradas:")
        self.logger.info(f"   📦 Protobuf queue: {adjusted_protobuf_size} (factor: {memory_factor:.2f})")
        self.logger.info(f"   🌍 Enriched queue: {adjusted_internal_size}")
        self.logger.info(
            f"   🧠 Memory pressure: {self.vertical_manager.vertical_metrics['memory_pressure'] * 100:.1f}%")

    def setup_geoip_cache_vertical(self):
        """Configura cache GeoIP optimizado para escalado vertical"""
        geoip_config = self.config["geoip"]
        vertical_opts = geoip_config.get("vertical_optimizations", {})
        performance_mode = geoip_config.get("performance_mode", "speed")

        if geoip_config.get("cache_enabled", False) and CACHE_AVAILABLE:
            # 📊 Ajustar cache size según memoria y optimizaciones
            base_cache_size = geoip_config.get("cache_size", 1000)

            if vertical_opts.get("optimized_for_32gb_ram"):
                # Optimizar para 32GB RAM
                base_cache_size = min(base_cache_size, 20000)  # No exceder 20K entradas

            memory_factor = self.vertical_manager.get_memory_pressure_factor()

            # Ajustar según performance mode
            if performance_mode == "speed":
                final_cache_size = int(base_cache_size * memory_factor * 1.5)  # Cache más grande
            else:  # precision
                final_cache_size = int(base_cache_size * memory_factor * 0.5)  # Cache más pequeño

            # 🗄️ Crear cache LRU optimizado
            @lru_cache(maxsize=final_cache_size)
            def cached_lookup(ip_address: str) -> Optional[Dict[str, Any]]:
                return self._direct_geoip_lookup(ip_address)

            self.cached_geoip_lookup = cached_lookup
            self.cache_enabled = True

            self.logger.info(f"🗄️ Cache GeoIP VERTICAL v3.0.0 habilitado:")
            self.logger.info(f"   📊 Cache size: {final_cache_size} entradas")
            self.logger.info(f"   🧠 Memory factor: {memory_factor:.2f}")
            self.logger.info(f"   ⚡ Performance mode: {performance_mode}")
            self.logger.info(f"   🏗️ 32GB optimized: {'✅' if vertical_opts.get('optimized_for_32gb_ram') else '❌'}")
        else:
            self.cache_enabled = False
            self.logger.info("🗄️ Cache GeoIP deshabilitado")

    # ============================================================
    # 🆕 NUEVOS MÉTODOS PARA LOOKUP REAL COMPLETO v3.0.0
    # ============================================================

    def get_complete_geoip_info(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        🌍 NUEVO v3.0.0: Obtiene información geográfica completa
        Devuelve diccionario completo o None si falla completamente
        """
        if not ip_address or ip_address == 'unknown':
            return None

        try:
            # 🗄️ Verificar cache si está habilitado
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
        """
        🔧 MODIFICADO v3.0.0: Lookup directo con información completa
        SIN hardcodeos - usa MaxMind primary, API fallback
        """
        geoip_config = self.config["geoip"]
        lookup_method = geoip_config.get("lookup_method", "maxmind")
        fallback_method = geoip_config.get("fallback_method", "api")

        # 🎯 Intentar método primario
        if lookup_method == "maxmind":
            result = self._maxmind_lookup(ip_address)
            if result and result.get('latitude') is not None:
                return result
        elif lookup_method == "api":
            result = self._api_lookup(ip_address)
            if result and result.get('latitude') is not None:
                return result

        # 🔄 Intentar método de fallback
        if fallback_method and fallback_method != lookup_method:
            self.logger.debug(f"🔄 Trying fallback method {fallback_method} for {ip_address}")
            if fallback_method == "maxmind":
                result = self._maxmind_lookup(ip_address)
                if result and result.get('latitude') is not None:
                    return result
            elif fallback_method == "api":
                result = self._api_lookup(ip_address)
                if result and result.get('latitude') is not None:
                    return result

        # ❌ Lookup fallido completamente
        self.logger.warning(f"❌ No se pudo geoposicionar {ip_address} con ningún método")
        self.stats['lookup_failures'] += 1
        return None

    def _maxmind_lookup(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """🌍 NUEVO: Lookup usando MaxMind GeoLite2-City database"""
        if not MAXMIND_AVAILABLE:
            return None

        try:
            maxmind_config = self.geoip_config.get("maxmind", {})
            if not maxmind_config.get("enabled", False):
                return None

            db_path = maxmind_config.get("database_path", "data/GeoLite2-City.mmdb")

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
            self.logger.debug(f"🔍 MaxMind: IP {ip_address} no encontrada en database")
            return None
        except FileNotFoundError:
            self.logger.error(f"❌ MaxMind database no encontrada: {maxmind_config.get('database_path')}")
            return None
        except Exception as e:
            self.logger.warning(f"❌ MaxMind lookup error para {ip_address}: {e}")
            return None

    def _api_lookup(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """🌐 NUEVO: Lookup usando API externa (ipgeolocation.io, etc.)"""
        try:
            api_config = self.geoip_config.get("api", {})
            if not api_config.get("enabled", False):
                return None

            api_key = api_config.get("api_key")
            if not api_key:
                self.logger.debug("🔑 API key no configurada para lookup API")
                return None

            url = api_config.get("url", "").format(api_key=api_key, ip=ip_address)
            timeout = api_config.get("timeout_seconds", 5.0)

            request = urllib.request.Request(url)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.loads(response.read().decode('utf-8'))

                self.stats['api_lookups'] += 1

                return {
                    'latitude': float(data.get('latitude')) if data.get('latitude') else None,
                    'longitude': float(data.get('longitude')) if data.get('longitude') else None,
                    'city': data.get('city', ''),
                    'country': data.get('country_name', ''),
                    'country_code': data.get('country_code2', ''),
                    'region': data.get('state_prov', ''),
                    'timezone': data.get('time_zone', {}).get('name', '') if isinstance(data.get('time_zone'),
                                                                                        dict) else data.get('time_zone',
                                                                                                            ''),
                    'lookup_method': 'api',
                    'isp': data.get('isp', ''),
                    'organization': data.get('organization', '')
                }

        except urllib.error.URLError as e:
            self.logger.warning(f"❌ API lookup URL error para {ip_address}: {e}")
            return None
        except json.JSONDecodeError as e:
            self.logger.warning(f"❌ API lookup JSON error para {ip_address}: {e}")
            return None
        except Exception as e:
            self.logger.warning(f"❌ API lookup error para {ip_address}: {e}")
            return None

    def _apply_geoip_to_event(self, event, geoip_info: Dict[str, Any], ip_type: str):
        """🔧 NUEVO: Aplica información geográfica completa al evento"""
        prefix = f"{ip_type}_"

        # 📍 Coordenadas (CRÍTICAS)
        setattr(event, f"{prefix}latitude", geoip_info.get('latitude'))
        setattr(event, f"{prefix}longitude", geoip_info.get('longitude'))
        setattr(event, f"{prefix}ip_enriched", True)

        # 🌍 Información geográfica adicional
        setattr(event, f"{prefix}city", geoip_info.get('city', ''))
        setattr(event, f"{prefix}country", geoip_info.get('country', ''))
        setattr(event, f"{prefix}country_code", geoip_info.get('country_code', ''))
        setattr(event, f"{prefix}region", geoip_info.get('region', ''))
        setattr(event, f"{prefix}timezone", geoip_info.get('timezone', ''))

        # 🔍 Metadatos del lookup
        setattr(event, f"{prefix}lookup_method", geoip_info.get('lookup_method', 'unknown'))

        # 📊 Información adicional si está disponible
        if geoip_info.get('accuracy_radius'):
            setattr(event, f"{prefix}accuracy_radius", geoip_info.get('accuracy_radius'))
        if geoip_info.get('postal_code'):
            setattr(event, f"{prefix}postal_code", geoip_info.get('postal_code'))
        if geoip_info.get('isp'):
            setattr(event, f"{prefix}isp", geoip_info.get('isp'))

    # ============================================================
    # 🔧 MODIFICACIÓN PRINCIPAL: ENRIQUECIMIENTO SIN HARDCODEOS
    # ============================================================

    def enrich_protobuf_event_vertical_v3(self, protobuf_data: bytes) -> Optional[bytes]:
        """
        🚨 VERSIÓN v3.0.0 MODIFICADA - Enriquece tanto source_ip como target_ip
        BUG FIX CRÍTICO: Geoposiciona target_ip (atacante) correctamente
        🔧 MODIFICADO: Usa lookup real completo SIN hardcodeos
        NUEVO: Usa campos duales v3.0.0 del protobuf
        """
        if not PROTOBUF_AVAILABLE:
            raise RuntimeError("❌ Protobuf v3 no disponible")

        try:
            # 📦 Deserializar evento protobuf v3.0.0
            event = NetworkEventProto.NetworkEvent()
            event.ParseFromString(protobuf_data)

            # 📊 Contabilizar evento v3 procesado
            self.stats['v3_events_processed'] += 1

            # 🔧 Configuración de procesamiento v3.0.0
            processing_config = self.config.get("processing", {})
            geolocate_source = processing_config.get("geolocate_source_ip", True)
            geolocate_target = processing_config.get("geolocate_target_ip", True)
            prioritize_target = processing_config.get("prioritize_target_ip", True)

            # 🌍 Variables para información completa
            source_geoip_info = None
            target_geoip_info = None
            primary_geoip_info = None
            enrichment_success = False

            # 🎯 CORRECCIÓN CRÍTICA: Geoposicionar target_ip (atacante) PRIMERO con lookup real
            if geolocate_target and event.target_ip and event.target_ip != 'unknown':
                target_ip_to_lookup = self.ip_handler.resolve_target_ip_for_lookup(event.target_ip)
                if target_ip_to_lookup:
                    target_geoip_info = self.get_complete_geoip_info(target_ip_to_lookup)
                    if target_geoip_info and target_geoip_info.get('latitude') is not None:
                        self.stats['target_ip_enriched'] += 1
                        self.logger.debug(
                            f"✅ target_ip geoposicionada: {event.target_ip} → lat:{target_geoip_info['latitude']}, lon:{target_geoip_info['longitude']}, city:{target_geoip_info.get('city', 'N/A')}")
                        enrichment_success = True
                    else:
                        self.logger.warning(f"❌ No se pudo geoposicionar target_ip: {event.target_ip}")
                else:
                    self.logger.warning(f"⚠️ target_ip no válida para lookup: {event.target_ip}")

            # 🏠 Geoposicionar source_ip (nuestra IP) con lookup real
            if geolocate_source and event.source_ip and event.source_ip != 'unknown':
                source_ip_to_lookup = self.ip_handler.resolve_source_ip_for_lookup(event.source_ip)
                if source_ip_to_lookup:
                    source_geoip_info = self.get_complete_geoip_info(source_ip_to_lookup)
                    if source_geoip_info and source_geoip_info.get('latitude') is not None:
                        self.stats['source_ip_enriched'] += 1
                        self.logger.debug(
                            f"✅ source_ip geoposicionada: {event.source_ip} → lat:{source_geoip_info['latitude']}, lon:{source_geoip_info['longitude']}, city:{source_geoip_info.get('city', 'N/A')}")
                        enrichment_success = True

                        # Si obtuvimos IP pública, contabilizar
                        if source_ip_to_lookup != event.source_ip:
                            self.stats['public_ip_discoveries'] += 1
                    else:
                        self.logger.warning(f"❌ No se pudo geoposicionar source_ip: {event.source_ip}")
                else:
                    self.logger.warning(f"⚠️ No se pudo resolver IP pública para source_ip privada: {event.source_ip}")

            # 🎯 Determinar información primaria según prioridad
            if prioritize_target and target_geoip_info:
                primary_geoip_info = target_geoip_info
                self.logger.debug("🎯 Usando target_ip como coordenadas primarias")
            elif source_geoip_info:
                primary_geoip_info = source_geoip_info
                self.logger.debug("🏠 Usando source_ip como coordenadas primarias")
            elif target_geoip_info:
                primary_geoip_info = target_geoip_info
                self.logger.debug("🎯 Fallback a target_ip como coordenadas primarias")

            # ✅ Aplicar información SOLO si existe - SIN hardcodeos
            if primary_geoip_info and primary_geoip_info.get('latitude') is not None:
                event.latitude = primary_geoip_info['latitude']
                event.longitude = primary_geoip_info['longitude']
                event.geoip_enriched = True
                event.enrichment_node = self.node_id
                event.enrichment_timestamp = int(time.time() * 1000)

                # ============================================================
                # 🆕 CAMPOS NUEVOS v3.0.0 - ENRIQUECIMIENTO DUAL COMPLETO
                # ============================================================

                # 🏠 APLICAR INFORMACIÓN COMPLETA PARA SOURCE IP
                if source_geoip_info:
                    self._apply_geoip_to_event(event, source_geoip_info, "source")

                # 🎯 APLICAR INFORMACIÓN COMPLETA PARA TARGET IP
                if target_geoip_info:
                    self._apply_geoip_to_event(event, target_geoip_info, "target")

                # 🔍 ESTADO DE ENRIQUECIMIENTO v3.0.0
                event.geoip_primary_source = "target" if (prioritize_target and target_geoip_info) else "source"
                event.dual_enrichment_success = bool(source_geoip_info and target_geoip_info)

                # 🌐 DISCOVERY DE IP PÚBLICA v3.0.0
                if (source_geoip_info and
                        hasattr(event, 'source_ip') and
                        self.ip_handler.is_private_ip(event.source_ip)):

                    public_ip = self.ip_handler.public_ip_discovery.get_public_ip()
                    if public_ip:
                        event.public_ip_discovered = True
                        event.original_source_ip = event.source_ip
                        event.discovered_public_ip = public_ip
                        event.ip_discovery_service = "discovery_service"  # TODO: detectar servicio usado
                        event.ip_discovery_timestamp = int(time.time() * 1000)

                # Contabilizar enriquecimiento dual exitoso
                if source_geoip_info and target_geoip_info:
                    self.stats['dual_enrichment_success'] += 1

            else:
                # ❌ Enrichment fallido completamente - SIN hardcodeos
                self.stats['failed_lookups'] += 1
                event.geoip_enriched = False
                # NO asignar coordenadas por defecto - dejar sin coordenadas
                # El dashboard debe manejar eventos sin coordenadas

            # 🔧 METADATOS DE ENRIQUECIMIENTO v3.0.0
            event.geoip_enricher_version = "3.0.0"
            event.geoip_method = self.geoip_config.get("lookup_method", "maxmind")
            event.protobuf_schema_version = "v3.0.0"

            # 📊 MÉTRICAS DE RENDIMIENTO v3.0.0
            processing_time = time.time() * 1000 - event.timestamp  # Rough estimate
            event.geoip_lookup_latency_ms = max(0.0, processing_time)

            # 🆔 Información específica del pipeline
            event.geoip_enricher_pid = self.process_id
            event.geoip_enricher_timestamp = int(time.time() * 1000)

            # 📊 Métricas del pipeline
            if event.promiscuous_timestamp > 0:
                pipeline_latency = event.geoip_enricher_timestamp - event.promiscuous_timestamp
                event.processing_latency_ms = float(pipeline_latency)

            # 🎯 Path del pipeline
            if event.pipeline_path:
                event.pipeline_path += "->geoip_v3.0.0"
            else:
                event.pipeline_path = "promiscuous->geoip_v3.0.0"

            event.pipeline_hops += 1

            # 🏷️ Tags v3.0.0
            event.component_tags.append(f"geoip_enricher_v3_{self.node_id}")
            event.component_metadata["geoip_version"] = "3.0.0"
            event.component_metadata["dual_ip_enrichment"] = "true"
            event.component_metadata["bug_fix_applied"] = "target_ip_prioritized"
            event.component_metadata["protobuf_version"] = PROTOBUF_VERSION
            event.component_metadata["lookup_real"] = "true"
            event.component_metadata["no_hardcoded_coords"] = "true"

            # 🔄 Estado del componente
            event.component_status = "healthy_v3"

            # 🔄 Serializar evento enriquecido
            return event.SerializeToString()

        except Exception as e:
            self.stats['protobuf_errors'] += 1
            self.logger.error(f"❌ Error enriquecimiento v3.0.0: {e}")
            return None

    # ================================================================
    # 🔄 RESTO DE MÉTODOS SIN CAMBIOS IMPORTANTES (Threading, etc.)
    # ================================================================

    def lookup_geoip_coordinates_vertical(self, ip_address: str) -> Optional[Tuple[float, float]]:
        """🔧 ACTUALIZADO: Mantener compatibilidad con método legacy"""
        geoip_info = self.get_complete_geoip_info(ip_address)
        if geoip_info and geoip_info.get('latitude') is not None:
            return (geoip_info['latitude'], geoip_info['longitude'])
        return None

    def receive_protobuf_events_vertical(self):
        """Thread de recepción con optimizaciones verticales"""
        self.logger.info("📡 Iniciando thread de recepción protobuf VERTICAL v3.0.0...")

        consecutive_errors = 0
        queue_full_count = 0

        while self.running:
            try:
                # 📊 Actualizar métricas verticales periódicamente
                if time.time() % 5 < 0.1:  # Cada ~5 segundos
                    self.vertical_manager.update_vertical_metrics()

                # 📨 Recibir evento protobuf
                protobuf_data = self.input_socket.recv(zmq.NOBLOCK)
                self.stats['received'] += 1
                consecutive_errors = 0

                # 🔍 Verificar presión según hardware
                current_queue_usage = self.protobuf_queue.qsize() / self.protobuf_queue.maxsize
                cpu_pressure = sum(self.vertical_manager.vertical_metrics['cpu_per_core']) / len(
                    self.vertical_manager.vertical_metrics['cpu_per_core'])

                if current_queue_usage > 0.8 or cpu_pressure > 75.0:
                    queue_full_count += 1
                    if queue_full_count % 20 == 0:
                        self.logger.warning(
                            f"🔴 Presión VERTICAL: Cola {current_queue_usage * 100:.1f}%, CPU {cpu_pressure:.1f}%")

                # 📋 Añadir a cola con estrategia vertical
                try:
                    queue_config = self.config["processing"].get("queue_overflow_handling", {})
                    queue_timeout = queue_config.get("max_queue_wait_ms", 100) / 1000.0

                    self.protobuf_queue.put(protobuf_data, timeout=queue_timeout)
                    queue_full_count = 0

                except:
                    self.stats['queue_overflows'] += 1

                    # 🔄 Aplicar estrategias verticales de overflow
                    if cpu_pressure > 80.0:  # CPU muy alta
                        # Descartar evento para aliviar presión
                        self.stats['vertical_optimizations_applied'] += 1
                        self.logger.debug("🔧 Evento descartado por alta presión de CPU")

                    if queue_config.get("log_drops", True) and self.stats['queue_overflows'] % 50 == 0:
                        self.logger.warning(
                            f"⚠️ {self.stats['queue_overflows']} eventos descartados por presión vertical")

            except zmq.Again:
                continue
            except zmq.ZMQError as e:
                consecutive_errors += 1
                if consecutive_errors % 10 == 0:
                    self.logger.error(f"❌ Error ZMQ recepción vertical ({consecutive_errors}): {e}")
                time.sleep(0.1)

    def process_protobuf_events_vertical(self):
        """Thread de procesamiento con optimizaciones verticales"""
        self.logger.info("⚙️ Iniciando thread de procesamiento VERTICAL v3.0.0...")

        queue_timeout = self.config["processing"]["queue_timeout_seconds"]

        while self.running:
            try:
                # 📋 Obtener evento protobuf de la cola
                protobuf_data = self.protobuf_queue.get(timeout=queue_timeout)

                # 🔄 Medir latencia de procesamiento
                start_time = time.time()

                # 🌍 Enriquecer con optimizaciones verticales v3.0.0
                enriched_protobuf = self.enrich_protobuf_event_vertical_v3(protobuf_data)

                if enriched_protobuf:
                    # 📊 Métricas de latencia
                    processing_time = (time.time() - start_time) * 1000  # ms
                    self.stats['pipeline_latency_total'] += processing_time

                    self.stats['enriched'] += 1

                    # 📋 Añadir a cola de eventos enriquecidos
                    try:
                        self.enriched_queue.put(enriched_protobuf, timeout=queue_timeout)
                    except:
                        self.stats['queue_overflows'] += 1

                self.protobuf_queue.task_done()

            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"❌ Error procesamiento vertical v3.0.0: {e}")
                self.stats['processing_errors'] += 1

    def send_event_with_backpressure_vertical(self, enriched_data: bytes) -> bool:
        """Envío con backpressure adaptativo vertical v3.0.0"""
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

                # 🔄 Aplicar backpressure vertical adaptativo
                if not self._apply_backpressure_vertical(attempt):
                    return False

                continue

            except zmq.ZMQError as e:
                self.logger.error(f"❌ Error ZMQ envío vertical: {e}")
                return False

        return False

    def _apply_backpressure_vertical(self, attempt: int) -> bool:
        """Aplica backpressure adaptativo según CPU y memoria v3.0.0"""
        bp_config = self.backpressure_config
        vertical_opts = self.vertical_backpressure

        if not bp_config["enabled"]:
            return False

        if attempt >= bp_config["max_retries"]:
            return False

        # 🔄 Delay base desde configuración
        delays = bp_config["retry_delays_ms"]
        base_delay_ms = delays[attempt] if attempt < len(delays) else delays[-1]

        # 🔧 Aplicar adaptaciones verticales
        if vertical_opts.get("cpu_aware_backpressure", False):
            adapted_delay = self.vertical_manager.get_cpu_aware_delay(base_delay_ms)
            self.stats['cpu_aware_delays'] += 1
        else:
            adapted_delay = base_delay_ms

        time.sleep(adapted_delay / 1000.0)
        self.stats['backpressure_activations'] += 1

        return True

    def send_enriched_events(self):
        """Thread de envío estándar v3.0.0"""
        self.logger.info("📤 Iniciando thread de envío vertical v3.0.0...")
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
                self.logger.error(f"❌ Error envío vertical: {e}")

    def monitor_performance_vertical(self):
        """Thread de monitoreo con métricas verticales v3.0.0"""
        monitoring_config = self.config["monitoring"]
        interval = monitoring_config["stats_interval_seconds"]

        while self.running:
            time.sleep(interval)
            if not self.running:
                break

            # 📊 Actualizar métricas verticales
            self.vertical_manager.update_vertical_metrics()
            self._log_performance_stats_vertical_v3()
            self._check_performance_alerts_vertical()

    def _log_performance_stats_vertical_v3(self):
        """Log de estadísticas con métricas verticales v3.0.0"""
        now = time.time()
        interval = now - self.stats['last_stats_time']

        # 📊 Rates
        recv_rate = self.stats['received'] / interval if interval > 0 else 0
        enrich_rate = self.stats['enriched'] / interval if interval > 0 else 0
        send_rate = self.stats['sent'] / interval if interval > 0 else 0

        # 📊 Latencia promedio
        avg_latency = 0.0
        if self.stats['enriched'] > 0:
            avg_latency = self.stats['pipeline_latency_total'] / self.stats['enriched']

        # 📊 Cache hit rate
        total_lookups = self.stats['cache_hits'] + self.stats['cache_misses']
        cache_hit_rate = (self.stats['cache_hits'] / total_lookups * 100) if total_lookups > 0 else 0

        # 🖥️ Métricas verticales
        vertical_metrics = self.vertical_manager.vertical_metrics
        cpu_avg = sum(vertical_metrics['cpu_per_core']) / len(vertical_metrics['cpu_per_core'])

        # 🎯 Estadísticas v3.0.0
        dual_success_rate = 0.0
        if self.stats['enriched'] > 0:
            dual_success_rate = (self.stats['dual_enrichment_success'] / self.stats['enriched']) * 100

        self.logger.info(f"📊 GeoIP Enricher VERTICAL v3.0.0 Stats:")
        self.logger.info(f"   📨 Recibidos: {self.stats['received']} ({recv_rate:.1f}/s)")
        self.logger.info(f"   🌍 Enriquecidos: {self.stats['enriched']} ({enrich_rate:.1f}/s)")
        self.logger.info(f"   📤 Enviados: {self.stats['sent']} ({send_rate:.1f}/s)")
        self.logger.info(f"   🏠 Source IP enriquecidas: {self.stats['source_ip_enriched']}")
        self.logger.info(f"   🎯 Target IP enriquecidas: {self.stats['target_ip_enriched']}")
        self.logger.info(
            f"   🎯➕🏠 Enriquecimiento dual: {self.stats['dual_enrichment_success']} ({dual_success_rate:.1f}%)")
        self.logger.info(f"   🌐 Discoveries IP pública: {self.stats['public_ip_discoveries']}")
        self.logger.info(f"   📦 Eventos v3 procesados: {self.stats['v3_events_processed']}")
        self.logger.info(f"   🌍 MaxMind lookups: {self.stats['maxmind_lookups']}")
        self.logger.info(f"   🌐 API lookups: {self.stats['api_lookups']}")
        self.logger.info(f"   ❌ Lookup failures: {self.stats['lookup_failures']}")
        self.logger.info(f"   🗄️ Cache: {cache_hit_rate:.1f}% hit rate")
        self.logger.info(f"   ⏱️ Latencia promedio: {avg_latency:.1f}ms")
        self.logger.info(f"   🖥️ CPU promedio: {cpu_avg:.1f}%")
        self.logger.info(f"   🧠 Memory pressure: {vertical_metrics['memory_pressure'] * 100:.1f}%")
        self.logger.info(f"   🏗️ Hardware utilization: {vertical_metrics['hardware_utilization'] * 100:.1f}%")
        self.logger.info(f"   📋 Colas: protobuf={self.protobuf_queue.qsize()}, enriched={self.enriched_queue.qsize()}")
        self.logger.info(f"   🔧 Optimizaciones verticales: {self.stats['vertical_optimizations_applied']}")
        self.logger.info(f"   🔄 Delays adaptativos: {self.stats['cpu_aware_delays']}")

        # Reset stats
        for key in ['received', 'enriched', 'sent', 'failed_lookups', 'cache_hits', 'cache_misses',
                    'buffer_errors', 'backpressure_activations', 'queue_overflows', 'protobuf_errors',
                    'vertical_optimizations_applied', 'cpu_aware_delays', 'source_ip_enriched',
                    'target_ip_enriched', 'dual_enrichment_success', 'public_ip_discoveries', 'v3_events_processed',
                    'maxmind_lookups', 'api_lookups', 'lookup_failures']:
            self.stats[key] = 0

        self.stats['pipeline_latency_total'] = 0.0
        self.stats['last_stats_time'] = now

    def _check_performance_alerts_vertical(self):
        """Alertas de performance verticales"""
        monitoring_config = self.config["monitoring"]
        alerts = monitoring_config.get("alerts", {})
        vertical_metrics = self.vertical_manager.vertical_metrics

        # 🚨 Alertas específicas de escalado vertical
        cpu_avg = sum(vertical_metrics['cpu_per_core']) / len(vertical_metrics['cpu_per_core'])
        if cpu_avg > alerts.get("max_cpu_sustained_percent", 80.0):
            self.logger.warning(f"🚨 ALERTA VERTICAL: CPU sostenido alto ({cpu_avg:.1f}%)")

        memory_pressure = vertical_metrics['memory_pressure'] * 100
        memory_threshold = alerts.get("max_memory_usage_mb", 1024) / (
                self.vertical_manager.memory_total_gb * 1024) * 100
        if memory_pressure > memory_threshold:
            self.logger.warning(f"🚨 ALERTA VERTICAL: Presión de memoria alta ({memory_pressure:.1f}%)")

        hardware_util = vertical_metrics['hardware_utilization'] * 100
        if hardware_util > 85.0:
            self.logger.warning(f"🚨 ALERTA VERTICAL: Utilización de hardware alta ({hardware_util:.1f}%)")

    def run(self):
        """Ejecutar el enriquecedor vertical v3.0.0"""
        self.logger.info("🚀 Iniciando Distributed GeoIP Enricher VERTICAL v3.0.0...")

        threads = []

        # Thread de recepción vertical
        recv_thread = threading.Thread(target=self.receive_protobuf_events_vertical, name="VerticalReceiver")
        threads.append(recv_thread)

        # Threads de procesamiento vertical
        num_threads = self.vertical_manager.recommended_threads
        for i in range(num_threads):
            proc_thread = threading.Thread(target=self.process_protobuf_events_vertical, name=f"VerticalProcessor-{i}")
            threads.append(proc_thread)

        # Threads de envío
        num_send_threads = self.config["processing"].get("send_threads", 2)
        for i in range(num_send_threads):
            send_thread = threading.Thread(target=self.send_enriched_events, name=f"VerticalSender-{i}")
            threads.append(send_thread)

        # Thread de monitoreo vertical
        monitor_thread = threading.Thread(target=self.monitor_performance_vertical, name="VerticalMonitor")
        threads.append(monitor_thread)

        # 🚀 Iniciar todos los threads
        for thread in threads:
            thread.start()

        self.logger.info(f"✅ GeoIP Enricher VERTICAL v3.0.0 iniciado con {len(threads)} threads")
        self.logger.info(f"   📡 Recepción: 1 thread")
        self.logger.info(
            f"   ⚙️ Procesamiento: {num_threads} threads (optimizado para {self.vertical_manager.cpu_count} cores)")
        self.logger.info(f"   📤 Envío: {num_send_threads} threads")
        self.logger.info(f"   🖥️ Hardware: {self.vertical_manager.hardware_profile}")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")
        self.logger.info(f"   🌍 MaxMind: {'✅' if MAXMIND_AVAILABLE else '❌'}")
        self.logger.info(f"   🚨 Bug fix: target_ip geoposicionamiento ✅")
        self.logger.info(f"   🌐 IP discovery: {'✅' if self.ip_handler.public_ip_discovery.enabled else '❌'}")
        self.logger.info(f"   🔧 Lookup real: ✅ SIN hardcodeos")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("🛑 Deteniendo GeoIP Enricher VERTICAL v3.0.0...")

        self.shutdown(threads)

    def shutdown(self, threads):
        """Cierre graceful vertical v3.0.0"""
        self.running = False
        self.stop_event.set()

        runtime = time.time() - self.stats['start_time']
        total_v3_events = self.stats.get('v3_events_processed', 0)
        total_dual_success = self.stats.get('dual_enrichment_success', 0)
        total_maxmind = self.stats.get('maxmind_lookups', 0)
        total_api = self.stats.get('api_lookups', 0)
        total_failures = self.stats.get('lookup_failures', 0)

        self.logger.info(f"📊 Stats finales VERTICAL v3.0.0 - Runtime: {runtime:.1f}s")
        self.logger.info(f"   📦 Total eventos v3 procesados: {total_v3_events}")
        self.logger.info(f"   🎯➕🏠 Total enriquecimiento dual exitoso: {total_dual_success}")
        self.logger.info(f"   🌍 Total MaxMind lookups: {total_maxmind}")
        self.logger.info(f"   🌐 Total API lookups: {total_api}")
        self.logger.info(f"   ❌ Total lookup failures: {total_failures}")

        for thread in threads:
            thread.join(timeout=5)

        if self.input_socket:
            self.input_socket.close()
        if self.output_socket:
            self.output_socket.close()
        self.context.term()

        self.logger.info("✅ Distributed GeoIP Enricher VERTICAL v3.0.0 cerrado correctamente")


# 🚀 Main
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Uso: python geoip_enricher_v3.py <config.json>")
        print("💡 Ejemplo: python geoip_enricher_v3.py geoip_enricher_config_v3.json")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        enricher = DistributedGeoIPEnricherVertical(config_file)
        enricher.run()
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)