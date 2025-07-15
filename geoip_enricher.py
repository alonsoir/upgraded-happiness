# geoip_enricher.py - Enriquecedor distribuido con protobuf nativo y alta concurrencia

import zmq
import json
import time
import logging
import threading
import sys
import os
import socket
import psutil
from queue import Queue, Empty
from typing import Dict, Any, Optional, Tuple
from threading import Event

# 📦 Protobuf - importar el esquema actualizado
try:
    # Intentar desde directorio actual primero
    import network_event_extended_v2_pb2 as NetworkEventProto

    PROTOBUF_AVAILABLE = True
except ImportError:
    try:
        # Fallback: estructura de directorios existente
        import src.protocols.protobuf.network_event_extended_v2_pb2 as NetworkEventProto

        PROTOBUF_AVAILABLE = True
    except ImportError:
        print("⚠️ Protobuf no disponible - generar con: protoc --python_out=. network_event_extended_v2.proto")
        PROTOBUF_AVAILABLE = False

# 📦 Cache para lookup GeoIP (opcional)
try:
    from functools import lru_cache

    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False


class DistributedGeoIPEnricher:
    """
    GeoIP Enricher distribuido completamente configurable desde JSON
    - Protobuf nativo para entrada y salida
    - Manejo de múltiples productores (promiscuous_agents)
    - Colas internas robustas para alta concurrencia
    - Backpressure configurable
    - PIDs de componentes para tracking distribuido
    - Sin valores hardcodeados
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

        # 📝 Setup logging desde configuración (PRIMERO)
        self.setup_logging()

        # 🔌 Setup ZeroMQ desde configuración
        self.context = zmq.Context()
        self.input_socket = None
        self.output_socket = None
        self.setup_sockets()

        # 🔄 Backpressure desde configuración
        self.backpressure_config = self.config["backpressure"]

        # 📦 Colas internas para procesamiento asíncrono de alta carga
        self.setup_internal_queues()

        # 📊 Métricas distribuidas
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
            'start_time': time.time(),
            'last_stats_time': time.time()
        }

        # 🎛️ Control
        self.running = True
        self.stop_event = Event()

        # ✅ Verificar dependencias críticas
        self._verify_dependencies()

        # 🗄️ Setup cache GeoIP si está habilitado
        self.setup_geoip_cache()

        self.logger.info(f"🚀 Distributed GeoIP Enricher inicializado")
        self.logger.info(f"   🏷️ Node ID: {self.node_id}")
        self.logger.info(f"   🔢 PID: {self.process_id}")
        self.logger.info(f"   📄 Config: {config_file}")

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
            "node_id", "zmq", "backpressure", "processing",
            "geoip", "logging", "monitoring", "distributed"
        ]

        for field in required_fields:
            if field not in config:
                raise RuntimeError(f"❌ Campo requerido faltante en config: {field}")

        # ✅ Validar subcampos críticos
        self._validate_config_structure(config)

        return config

    def _validate_config_structure(self, config: Dict[str, Any]):
        """Valida estructura de configuración"""
        # ZMQ fields
        zmq_required = ["input_port", "output_port", "rcvhwm", "sndhwm", "recv_timeout_ms", "send_timeout_ms",
                        "linger_ms"]
        for field in zmq_required:
            if field not in config["zmq"]:
                raise RuntimeError(f"❌ Campo ZMQ faltante: zmq.{field}")

        # Processing fields
        proc_required = ["threads", "internal_queue_size", "protobuf_queue_size", "queue_timeout_seconds"]
        for field in proc_required:
            if field not in config["processing"]:
                raise RuntimeError(f"❌ Campo processing faltante: processing.{field}")

        # GeoIP fields
        geoip_required = ["lookup_method", "cache_enabled", "performance_mode"]
        for field in geoip_required:
            if field not in config["geoip"]:
                raise RuntimeError(f"❌ Campo geoip faltante: geoip.{field}")

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
            'memory_total_gb': round(psutil.virtual_memory().total / (1024 ** 3), 2)
        }

    def _verify_dependencies(self):
        """Verifica que las dependencias críticas estén disponibles"""
        issues = []

        if not PROTOBUF_AVAILABLE:
            issues.append("❌ Protobuf no disponible - generar código Python")

        if issues:
            for issue in issues:
                print(issue)
            raise RuntimeError("❌ Dependencias críticas faltantes")

    def setup_logging(self):
        """Setup logging desde configuración con node_id y PID"""
        log_config = self.config["logging"]

        # 📝 Configurar nivel
        level = getattr(logging, log_config["level"].upper())

        # 🏷️ Formato con node_id y PID
        log_format = log_config["format"].format(
            node_id=self.node_id,
            pid=self.process_id
        )
        formatter = logging.Formatter(log_format)

        # 🔧 Configurar handler
        if log_config.get("file"):
            handler = logging.FileHandler(log_config["file"])
        else:
            handler = logging.StreamHandler()

        handler.setFormatter(formatter)

        # 📋 Setup logger
        self.logger = logging.getLogger(f"geoip_enricher_{self.node_id}")
        self.logger.setLevel(level)
        self.logger.addHandler(handler)
        self.logger.propagate = False

    def setup_sockets(self):
        """Configuración ZMQ desde archivo de configuración"""
        zmq_config = self.config["zmq"]

        try:
            # 📥 Socket de entrada (PULL) - recibe de múltiples promiscuous_agents
            self.input_socket = self.context.socket(zmq.PULL)
            self.input_socket.setsockopt(zmq.RCVHWM, zmq_config["rcvhwm"])
            self.input_socket.setsockopt(zmq.RCVTIMEO, zmq_config["recv_timeout_ms"])

            input_port = zmq_config["input_port"]
            input_address = f"tcp://*:{input_port}"  # BIND para recibir de múltiples productores
            self.input_socket.bind(input_address)

            # 📤 Socket de salida (PUSH) - envía al ml_detector
            self.output_socket = self.context.socket(zmq.PUSH)
            self.output_socket.setsockopt(zmq.SNDHWM, zmq_config["sndhwm"])
            self.output_socket.setsockopt(zmq.LINGER, zmq_config["linger_ms"])
            self.output_socket.setsockopt(zmq.SNDTIMEO, zmq_config["send_timeout_ms"])

            output_port = zmq_config["output_port"]
            output_address = f"tcp://*:{output_port}"
            self.output_socket.bind(output_address)

            self.logger.info(f"🔌 Sockets ZMQ configurados:")
            self.logger.info(f"   📥 Input: {input_address} (BIND para múltiples productores)")
            self.logger.info(f"   📤 Output: {output_address} (BIND para consumers)")
            self.logger.info(f"   🌊 RCVHWM: {zmq_config['rcvhwm']}, SNDHWM: {zmq_config['sndhwm']}")

        except Exception as e:
            raise RuntimeError(f"❌ Error configurando sockets ZMQ: {e}")

    def setup_internal_queues(self):
        """Configuración de colas internas para alta concurrencia"""
        proc_config = self.config["processing"]

        # 📋 Cola principal para eventos protobuf sin procesar
        self.protobuf_queue = Queue(maxsize=proc_config["protobuf_queue_size"])

        # 📋 Cola para eventos enriquecidos listos para envío
        self.enriched_queue = Queue(maxsize=proc_config["internal_queue_size"])

        self.logger.info(f"📋 Colas internas configuradas:")
        self.logger.info(f"   📦 Protobuf queue: {proc_config['protobuf_queue_size']}")
        self.logger.info(f"   🌍 Enriched queue: {proc_config['internal_queue_size']}")

    def setup_geoip_cache(self):
        """Configura cache GeoIP si está habilitado"""
        geoip_config = self.config["geoip"]

        if geoip_config.get("cache_enabled", False) and CACHE_AVAILABLE:
            cache_size = geoip_config.get("cache_size", 1000)

            # 🗄️ Crear cache LRU para coordenadas
            @lru_cache(maxsize=cache_size)
            def cached_lookup(ip_address: str) -> Optional[Tuple[float, float]]:
                return self._direct_geoip_lookup(ip_address)

            self.cached_geoip_lookup = cached_lookup
            self.cache_enabled = True

            self.logger.info(f"🗄️ Cache GeoIP habilitado: {cache_size} entradas")
        else:
            self.cache_enabled = False
            self.logger.info("🗄️ Cache GeoIP deshabilitado")

    def receive_protobuf_events(self):
        """Thread de recepción de eventos protobuf"""
        self.logger.info("📡 Iniciando thread de recepción protobuf...")

        while self.running:
            try:
                # 📨 Recibir evento protobuf
                protobuf_data = self.input_socket.recv(zmq.NOBLOCK)
                self.stats['received'] += 1

                # 📋 Añadir a cola de protobuf para procesamiento
                try:
                    queue_timeout = self.config["processing"]["queue_timeout_seconds"]
                    self.protobuf_queue.put(protobuf_data, timeout=queue_timeout)
                except:
                    self.stats['queue_overflows'] += 1
                    self.logger.warning("⚠️ Protobuf queue lleno - evento descartado")

            except zmq.Again:
                # Sin datos disponibles - continuar
                continue
            except zmq.ZMQError as e:
                self.logger.error(f"❌ Error ZMQ recepción: {e}")
                time.sleep(0.1)

    def process_protobuf_events(self):
        """Thread de procesamiento de eventos protobuf"""
        self.logger.info("⚙️ Iniciando thread de procesamiento protobuf...")

        queue_timeout = self.config["processing"]["queue_timeout_seconds"]

        while self.running:
            try:
                # 📋 Obtener evento protobuf de la cola
                protobuf_data = self.protobuf_queue.get(timeout=queue_timeout)

                # 🔄 Medir latencia de procesamiento
                start_time = time.time()

                # 🌍 Enriquecer evento con GeoIP
                enriched_protobuf = self.enrich_protobuf_event(protobuf_data)

                if enriched_protobuf:
                    # 📊 Actualizar métricas de latencia
                    processing_time = (time.time() - start_time) * 1000  # ms
                    self.stats['pipeline_latency_total'] += processing_time

                    self.stats['enriched'] += 1

                    # 📋 Añadir a cola de eventos enriquecidos
                    try:
                        self.enriched_queue.put(enriched_protobuf, timeout=queue_timeout)
                    except:
                        self.stats['queue_overflows'] += 1
                        self.logger.warning("⚠️ Enriched queue lleno - evento descartado")
                else:
                    self.stats['processing_errors'] += 1

                self.protobuf_queue.task_done()

            except Empty:
                # Timeout normal - continuar
                continue
            except Exception as e:
                self.logger.error(f"❌ Error procesando protobuf: {e}")
                self.stats['processing_errors'] += 1

    def send_enriched_events(self):
        """Thread de envío de eventos enriquecidos"""
        self.logger.info("📤 Iniciando thread de envío...")

        queue_timeout = self.config["processing"]["queue_timeout_seconds"]

        while self.running:
            try:
                # 📋 Obtener evento enriquecido
                enriched_protobuf = self.enriched_queue.get(timeout=queue_timeout)

                # 📤 Enviar con backpressure
                success = self.send_event_with_backpressure(enriched_protobuf)

                if success:
                    self.stats['sent'] += 1

                self.enriched_queue.task_done()

            except Empty:
                # Timeout normal - continuar
                continue
            except Exception as e:
                self.logger.error(f"❌ Error enviando evento: {e}")

    def enrich_protobuf_event(self, protobuf_data: bytes) -> Optional[bytes]:
        """Enriquece evento protobuf con información GeoIP"""
        if not PROTOBUF_AVAILABLE:
            raise RuntimeError("❌ Protobuf no disponible")

        try:
            # 📦 Deserializar evento protobuf
            event = NetworkEventProto.NetworkEvent()
            event.ParseFromString(protobuf_data)

            # 🌍 Realizar lookup GeoIP
            coordinates = self.lookup_geoip_coordinates(event.source_ip)

            if coordinates:
                # ✅ Enriquecimiento exitoso
                event.latitude = coordinates[0]
                event.longitude = coordinates[1]
                event.geoip_enriched = True
                event.enrichment_node = self.node_id
                event.enrichment_timestamp = int(time.time() * 1000)

                # 🆔 Añadir PID del enriquecedor
                event.geoip_enricher_pid = self.process_id
                event.geoip_enricher_timestamp = int(time.time() * 1000)

                # 📊 Actualizar métricas del pipeline
                if event.promiscuous_timestamp > 0:
                    pipeline_latency = event.geoip_enricher_timestamp - event.promiscuous_timestamp
                    event.processing_latency_ms = float(pipeline_latency)

                # 🎯 Actualizar path del pipeline
                if event.pipeline_path:
                    event.pipeline_path += "->geoip"
                else:
                    event.pipeline_path = "promiscuous->geoip"

                event.pipeline_hops += 1

                # 🏷️ Añadir tag del componente
                event.component_tags.append(f"geoip_enricher_{self.node_id}")

            else:
                # ❌ Lookup fallido
                self.stats['failed_lookups'] += 1
                event.geoip_enriched = False

                # 🔧 Aplicar coordenadas por defecto si está configurado
                geoip_config = self.config["geoip"]
                if geoip_config.get("use_default_coordinates_on_failure", False):
                    default_coords = geoip_config["default_coordinates"]
                    event.latitude = default_coords[0]
                    event.longitude = default_coords[1]
                    event.geoip_enriched = True

                    # 🏷️ Marcar como enriquecimiento por defecto
                    event.component_metadata["geoip_source"] = "default"

            # 🔄 Actualizar estado del componente en el evento
            event.component_status = "healthy"  # TODO: calcular basado en métricas

            # 🔄 Serializar evento enriquecido
            return event.SerializeToString()

        except Exception as e:
            self.stats['protobuf_errors'] += 1
            self.logger.error(f"❌ Error enriqueciendo protobuf: {e}")
            return None

    def lookup_geoip_coordinates(self, ip_address: str) -> Optional[Tuple[float, float]]:
        """Lookup de coordenadas GeoIP con cache opcional"""
        if not ip_address or ip_address == 'unknown':
            return None

        try:
            if self.cache_enabled:
                # 🗄️ Usar cache LRU
                result = self.cached_geoip_lookup(ip_address)
                if result:
                    self.stats['cache_hits'] += 1
                else:
                    self.stats['cache_misses'] += 1
                return result
            else:
                # 🔍 Lookup directo
                self.stats['cache_misses'] += 1
                return self._direct_geoip_lookup(ip_address)

        except Exception as e:
            self.logger.error(f"❌ Error lookup GeoIP para {ip_address}: {e}")
            return None

    def _direct_geoip_lookup(self, ip_address: str) -> Optional[Tuple[float, float]]:
        """Lookup directo de GeoIP según configuración"""
        geoip_config = self.config["geoip"]
        lookup_method = geoip_config["lookup_method"]

        if lookup_method == "mock":
            # 🎭 Mock para testing
            return tuple(geoip_config["mock_coordinates"])

        elif lookup_method == "maxmind":
            # 🌍 MaxMind GeoIP
            # TODO: Implementar con geoip2
            # import geoip2.database
            # reader = geoip2.database.Reader(geoip_config["maxmind"]["database_path"])
            # response = reader.city(ip_address)
            # return (response.location.latitude, response.location.longitude)

            # Por ahora mock
            return tuple(geoip_config["mock_coordinates"])

        elif lookup_method == "api":
            # 🌐 API externa
            # TODO: Implementar HTTP API lookup
            # import requests
            # url = geoip_config["api"]["url"].format(ip=ip_address)
            # response = requests.get(url, timeout=geoip_config["api"]["timeout_seconds"])
            # data = response.json()
            # return (data['latitude'], data['longitude'])

            # Por ahora mock
            return tuple(geoip_config["mock_coordinates"])

        else:
            self.logger.error(f"❌ Método de lookup desconocido: {lookup_method}")
            return None

    def send_event_with_backpressure(self, enriched_data: bytes) -> bool:
        """Envío robusto con backpressure configurable"""
        bp_config = self.backpressure_config
        max_retries = bp_config["max_retries"]

        for attempt in range(max_retries + 1):
            try:
                # 🚀 Intento de envío
                self.output_socket.send(enriched_data, zmq.NOBLOCK)
                return True

            except zmq.Again:
                # 🔴 Buffer lleno
                self.stats['buffer_errors'] += 1

                if attempt == max_retries:
                    # 🗑️ Último intento fallido
                    return False

                # 🔄 Aplicar backpressure
                if not self._apply_backpressure(attempt):
                    return False

                continue

            except zmq.ZMQError as e:
                self.logger.error(f"❌ Error ZMQ envío: {e}")
                return False

        return False

    def _apply_backpressure(self, attempt: int) -> bool:
        """Aplica backpressure según configuración"""
        bp_config = self.backpressure_config

        if not bp_config["enabled"]:
            return False

        if attempt >= bp_config["max_retries"]:
            return False

        # 🔄 Aplicar delay configurado
        delays = bp_config["retry_delays_ms"]
        delay_ms = delays[attempt] if attempt < len(delays) else delays[-1]

        time.sleep(delay_ms / 1000.0)
        self.stats['backpressure_activations'] += 1
        return True

    def monitor_performance(self):
        """Thread de monitoreo de performance distribuida"""
        monitoring_config = self.config["monitoring"]
        interval = monitoring_config["stats_interval_seconds"]

        while self.running:
            time.sleep(interval)
            if not self.running:
                break

            self._log_performance_stats()
            self._check_performance_alerts()

    def _log_performance_stats(self):
        """Log de estadísticas de performance distribuida"""
        now = time.time()
        interval = now - self.stats['last_stats_time']

        # 📊 Calcular rates
        recv_rate = self.stats['received'] / interval if interval > 0 else 0
        enrich_rate = self.stats['enriched'] / interval if interval > 0 else 0
        send_rate = self.stats['sent'] / interval if interval > 0 else 0

        # 📊 Calcular latencia promedio
        avg_latency = 0.0
        if self.stats['enriched'] > 0:
            avg_latency = self.stats['pipeline_latency_total'] / self.stats['enriched']

        # 📊 Cache hit rate
        total_lookups = self.stats['cache_hits'] + self.stats['cache_misses']
        cache_hit_rate = (self.stats['cache_hits'] / total_lookups * 100) if total_lookups > 0 else 0

        self.logger.info(f"📊 GeoIP Enricher Stats:")
        self.logger.info(f"   📨 Recibidos: {self.stats['received']} ({recv_rate:.1f}/s)")
        self.logger.info(f"   🌍 Enriquecidos: {self.stats['enriched']} ({enrich_rate:.1f}/s)")
        self.logger.info(f"   📤 Enviados: {self.stats['sent']} ({send_rate:.1f}/s)")
        self.logger.info(f"   🗄️ Cache: {cache_hit_rate:.1f}% hit rate")
        self.logger.info(f"   ⏱️ Latencia promedio: {avg_latency:.1f}ms")
        self.logger.info(f"   📋 Colas: protobuf={self.protobuf_queue.qsize()}, enriched={self.enriched_queue.qsize()}")
        self.logger.info(f"   🔄 Backpressure: {self.stats['backpressure_activations']} activaciones")
        self.logger.info(
            f"   ❌ Errores: lookup={self.stats['failed_lookups']}, protobuf={self.stats['protobuf_errors']}")

        # 🔄 Reset stats para próximo intervalo
        for key in ['received', 'enriched', 'sent', 'failed_lookups', 'cache_hits', 'cache_misses',
                    'buffer_errors', 'backpressure_activations', 'queue_overflows', 'protobuf_errors']:
            self.stats[key] = 0

        self.stats['pipeline_latency_total'] = 0.0
        self.stats['last_stats_time'] = now

    def _check_performance_alerts(self):
        """Verifica alertas de performance distribuida"""
        monitoring_config = self.config["monitoring"]
        alerts = monitoring_config.get("alerts", {})

        # 🚨 Alert de colas llenas
        protobuf_usage = self.protobuf_queue.qsize() / self.config["processing"]["protobuf_queue_size"]
        enriched_usage = self.enriched_queue.qsize() / self.config["processing"]["internal_queue_size"]

        max_queue_usage = alerts.get("max_queue_usage_percent", 100) / 100.0

        if protobuf_usage > max_queue_usage:
            self.logger.warning(f"🚨 ALERTA: Protobuf queue llena ({protobuf_usage * 100:.1f}%)")

        if enriched_usage > max_queue_usage:
            self.logger.warning(f"🚨 ALERTA: Enriched queue llena ({enriched_usage * 100:.1f}%)")

        # 🚨 Alert de tasa de fallo GeoIP
        total_lookups = self.stats['enriched'] + self.stats['failed_lookups']
        if total_lookups > 0:
            failure_rate = (self.stats['failed_lookups'] / total_lookups) * 100
            max_failure_rate = alerts.get("max_geoip_failure_rate_percent", 100)

            if failure_rate > max_failure_rate:
                self.logger.warning(f"🚨 ALERTA: Tasa de fallo GeoIP alta ({failure_rate:.1f}%)")

    def run(self):
        """Ejecutar el enriquecedor distribuido"""
        self.logger.info("🚀 Iniciando Distributed GeoIP Enricher...")

        # 🧵 Crear threads según configuración
        threads = []

        # Thread de recepción protobuf
        recv_thread = threading.Thread(target=self.receive_protobuf_events, name="ProtobufReceiver")
        threads.append(recv_thread)

        # Threads de procesamiento protobuf
        num_processing_threads = self.config["processing"]["threads"]
        for i in range(num_processing_threads):
            proc_thread = threading.Thread(target=self.process_protobuf_events, name=f"ProtobufProcessor-{i}")
            threads.append(proc_thread)

        # Threads de envío
        num_send_threads = self.config["processing"].get("send_threads", 1)
        for i in range(num_send_threads):
            send_thread = threading.Thread(target=self.send_enriched_events, name=f"Sender-{i}")
            threads.append(send_thread)

        # Thread de monitoreo
        monitor_thread = threading.Thread(target=self.monitor_performance, name="Monitor")
        threads.append(monitor_thread)

        # 🚀 Iniciar todos los threads
        for thread in threads:
            thread.start()

        self.logger.info(f"✅ GeoIP Enricher iniciado con {len(threads)} threads")
        self.logger.info(f"   📡 Recepción: 1 thread")
        self.logger.info(f"   ⚙️ Procesamiento: {num_processing_threads} threads")
        self.logger.info(f"   📤 Envío: {num_send_threads} threads")

        try:
            # 🔄 Mantener vivo el proceso principal
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("🛑 Deteniendo GeoIP Enricher...")

        # 🛑 Cierre graceful
        self.shutdown(threads)

    def shutdown(self, threads):
        """Cierre graceful del enriquecedor"""
        self.running = False
        self.stop_event.set()

        # 📊 Stats finales
        runtime = time.time() - self.stats['start_time']
        self.logger.info(f"📊 Stats finales - Runtime: {runtime:.1f}s")
        self.logger.info(f"   Total enriquecidos: {self.stats['enriched']}")

        # 🧵 Esperar threads
        for thread in threads:
            thread.join(timeout=5)

        # 🔌 Cerrar sockets
        if self.input_socket:
            self.input_socket.close()
        if self.output_socket:
            self.output_socket.close()
        self.context.term()

        self.logger.info("✅ Distributed GeoIP Enricher cerrado correctamente")


# 🚀 Main
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Uso: python geoip_enricher.py <config.json>")
        print("💡 Ejemplo: python geoip_enricher.py geoip_config.json")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        enricher = DistributedGeoIPEnricher(config_file)
        enricher.run()
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        sys.exit(1)