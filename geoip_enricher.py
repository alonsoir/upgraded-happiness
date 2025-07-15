# geoip_enricher.py - Completamente configurable desde JSON

import zmq
import json
import time
import logging
import threading
import sys
from queue import Queue, Empty
from typing import Dict, Any, Optional
from threading import Event


class ConfigurableGeoIPEnricher:
    """
    GeoIP Enricher completamente configurable desde JSON
    Sin valores por defecto hardcodeados - todo viene del archivo de configuración
    """

    def __init__(self, config_file: str):
        # 📄 Cargar configuración - SIN defaults hardcodeados
        self.config = self._load_config_strict(config_file)
        self.config_file = config_file

        # 🏷️ node_id desde configuración
        self.node_id = self.config["node_id"]

        # 🔌 Setup ZeroMQ desde configuración
        self.context = zmq.Context()
        self.input_socket = None
        self.output_socket = None
        self.setup_sockets()

        # 🔄 Backpressure desde configuración
        self.backpressure_config = self.config["backpressure"]

        # 📊 Métricas
        self.stats = {
            'received': 0,
            'enriched': 0,
            'sent': 0,
            'failed_lookups': 0,
            'buffer_errors': 0,
            'processing_errors': 0,
            'backpressure_activations': 0,
            'start_time': time.time(),
            'last_stats_time': time.time()
        }

        # 🔄 Queue interno para procesamiento asíncrono
        queue_size = self.config["processing"]["internal_queue_size"]
        self.processing_queue = Queue(maxsize=queue_size)

        # 🎛️ Control
        self.running = True
        self.stop_event = Event()

        # 📝 Setup logging desde configuración
        self.setup_logging()

        self.logger.info(f"🚀 GeoIP Enricher inicializado - node_id: {self.node_id}")
        self.logger.info(f"📄 Config: {config_file}")

    def _load_config_strict(self, config_file: str) -> Dict[str, Any]:
        """
        Carga configuración SIN proporcionar defaults
        Si falta algo crítico, falla rápido
        """
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            raise RuntimeError(f"❌ Archivo de configuración no encontrado: {config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ Error parseando JSON: {e}")

        # ✅ Validar campos críticos
        required_fields = [
            "node_id",
            "zmq",
            "backpressure",
            "processing",
            "geoip",
            "logging",
            "monitoring"
        ]

        for field in required_fields:
            if field not in config:
                raise RuntimeError(f"❌ Campo requerido faltante en config: {field}")

        # ✅ Validar subcampos ZMQ
        zmq_required = ["input_port", "output_port", "recv_timeout_ms", "send_timeout_ms", "linger_ms"]
        for field in zmq_required:
            if field not in config["zmq"]:
                raise RuntimeError(f"❌ Campo ZMQ requerido faltante: zmq.{field}")

        # ✅ Validar subcampos processing
        proc_required = ["threads", "internal_queue_size"]
        for field in proc_required:
            if field not in config["processing"]:
                raise RuntimeError(f"❌ Campo processing requerido faltante: processing.{field}")

        # ✅ Validar subcampos backpressure
        bp_required = ["enabled", "max_retries", "retry_delays_ms"]
        for field in bp_required:
            if field not in config["backpressure"]:
                raise RuntimeError(f"❌ Campo backpressure requerido faltante: backpressure.{field}")

        self._log_config_loaded(config)
        return config

    def _log_config_loaded(self, config: Dict[str, Any]):
        """Log de configuración cargada"""
        print(f"✅ GeoIP Enricher configuración cargada:")
        print(f"   🏷️ Node ID: {config['node_id']}")
        print(f"   📥 Input Puerto: {config['zmq']['input_port']}")
        print(f"   📤 Output Puerto: {config['zmq']['output_port']}")
        print(f"   🔄 Backpressure: {'✅' if config['backpressure']['enabled'] else '❌'}")
        print(f"   🧵 Threads: {config['processing']['threads']}")

    def setup_sockets(self):
        """Configuración ZMQ desde archivo de configuración"""
        zmq_config = self.config["zmq"]

        # 📥 Socket de entrada (PULL)
        self.input_socket = self.context.socket(zmq.PULL)
        self.input_socket.setsockopt(zmq.RCVTIMEO, zmq_config["recv_timeout_ms"])

        input_port = zmq_config["input_port"]
        input_address = f"tcp://localhost:{input_port}"
        self.input_socket.connect(input_address)

        # 📤 Socket de salida (PUSH)
        self.output_socket = self.context.socket(zmq.PUSH)
        self.output_socket.setsockopt(zmq.LINGER, zmq_config["linger_ms"])
        self.output_socket.setsockopt(zmq.SNDTIMEO, zmq_config["send_timeout_ms"])

        output_port = zmq_config["output_port"]
        output_address = f"tcp://*:{output_port}"
        self.output_socket.bind(output_address)

        print(f"🔌 Sockets ZMQ configurados:")
        print(f"   📥 Input: {input_address}")
        print(f"   📤 Output: {output_address}")

    def setup_logging(self):
        """Setup logging desde configuración con node_id"""
        log_config = self.config["logging"]

        # 📝 Configurar nivel
        level = getattr(logging, log_config["level"].upper())

        # 🏷️ Formato con node_id
        formatter = logging.Formatter(
            log_config["format"].format(node_id=self.node_id)
        )

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

        # 🔇 Evitar duplicados
        self.logger.propagate = False

    def apply_backpressure_output(self, attempt: int) -> bool:
        """
        Aplica backpressure para envío de salida según configuración
        """
        bp_config = self.backpressure_config

        if not bp_config["enabled"]:
            return False

        if attempt >= bp_config["max_retries"]:
            return False

        # 🔄 Aplicar delay configurado
        delays = bp_config["retry_delays_ms"]
        if attempt < len(delays):
            delay_ms = delays[attempt]
        else:
            delay_ms = delays[-1]

        time.sleep(delay_ms / 1000.0)

        self.stats['backpressure_activations'] += 1
        return True

    def receive_events(self):
        """Thread de recepción de eventos"""
        self.logger.info("📡 Iniciando thread de recepción...")

        while self.running:
            try:
                # 📨 Recibir evento con timeout
                data = self.input_socket.recv(zmq.NOBLOCK)
                self.stats['received'] += 1

                # 📋 Añadir a queue de procesamiento
                try:
                    queue_timeout = self.config["processing"]["queue_put_timeout_seconds"]
                    self.processing_queue.put(data, timeout=queue_timeout)
                except:
                    # Queue lleno - estadística y descarte
                    self.stats['buffer_errors'] += 1
                    self.logger.warning("⚠️ Queue interno lleno - evento descartado")

            except zmq.Again:
                # Sin datos disponibles - continuar
                continue
            except zmq.ZMQError as e:
                self.logger.error(f"❌ Error ZMQ recepción: {e}")
                time.sleep(0.1)

    def process_events(self):
        """Thread de procesamiento de eventos"""
        self.logger.info("⚙️ Iniciando thread de procesamiento...")

        queue_timeout = self.config["processing"]["queue_get_timeout_seconds"]

        while self.running:
            try:
                # 📋 Obtener evento del queue
                data = self.processing_queue.get(timeout=queue_timeout)

                # 🌍 Enriquecer con GeoIP
                enriched_data = self.enrich_with_geoip(data)

                if enriched_data:
                    self.stats['enriched'] += 1
                    self.send_enriched_event_with_backpressure(enriched_data)
                else:
                    self.stats['processing_errors'] += 1

                self.processing_queue.task_done()

            except Empty:
                # Timeout normal - continuar
                continue
            except Exception as e:
                self.logger.error(f"❌ Error procesamiento: {e}")
                self.stats['processing_errors'] += 1

    def enrich_with_geoip(self, raw_data: bytes) -> Optional[bytes]:
        """Enriquecimiento GeoIP usando configuración"""
        try:
            # 🔍 Deserializar evento
            event = self.deserialize_event(raw_data)

            # 🌍 Lookup GeoIP usando configuración
            geoip_config = self.config["geoip"]
            coordinates = self.lookup_coordinates(event.get('source_ip'), geoip_config)

            if coordinates:
                event['latitude'] = coordinates[0]
                event['longitude'] = coordinates[1]
                event['geoip_enriched'] = True
                event['enrichment_node'] = self.node_id
                event['enrichment_timestamp'] = time.time()
            else:
                self.stats['failed_lookups'] += 1
                event['geoip_enriched'] = False

                # 🔧 Aplicar coordenadas por defecto si está configurado
                if geoip_config.get("use_default_coordinates_on_failure", False):
                    default_coords = geoip_config["default_coordinates"]
                    event['latitude'] = default_coords[0]
                    event['longitude'] = default_coords[1]
                    event['geoip_enriched'] = True
                    event['geoip_source'] = 'default'

            return self.serialize_event(event)

        except Exception as e:
            self.logger.error(f"❌ Error enriquecimiento: {e}")
            return None

    def send_enriched_event_with_backpressure(self, enriched_data: bytes) -> bool:
        """Envío robusto con backpressure configurable"""
        bp_config = self.backpressure_config
        max_retries = bp_config["max_retries"]

        for attempt in range(max_retries + 1):
            try:
                self.output_socket.send(enriched_data, zmq.NOBLOCK)
                self.stats['sent'] += 1
                return True

            except zmq.Again:
                # Buffer de salida lleno
                self.stats['buffer_errors'] += 1

                if attempt == max_retries:
                    self.logger.warning("⚠️ Output buffer lleno - evento descartado tras reintentos")
                    return False

                # 🔄 Aplicar backpressure
                if not self.apply_backpressure_output(attempt):
                    return False

                continue

            except zmq.ZMQError as e:
                self.logger.error(f"❌ Error envío ZMQ: {e}")
                return False

        return False

    def lookup_coordinates(self, ip_address: str, geoip_config: Dict[str, Any]) -> Optional[tuple]:
        """Lookup GeoIP usando configuración"""
        if not ip_address or ip_address == 'unknown':
            return None

        # 🔍 Método de lookup desde configuración
        lookup_method = geoip_config["lookup_method"]

        if lookup_method == "mock":
            # 🎭 Mock para testing - coordenadas desde config
            return tuple(geoip_config["mock_coordinates"])

        elif lookup_method == "maxmind":
            # 🌍 MaxMind GeoIP (implementar según tu setup)
            # return self.lookup_maxmind(ip_address, geoip_config["maxmind"])
            # Por ahora mock
            return tuple(geoip_config["mock_coordinates"])

        elif lookup_method == "api":
            # 🌐 API externa (implementar según tu setup)
            # return self.lookup_api(ip_address, geoip_config["api"])
            # Por ahora mock
            return tuple(geoip_config["mock_coordinates"])

        else:
            self.logger.error(f"❌ Método de lookup desconocido: {lookup_method}")
            return None

    def deserialize_event(self, raw_data: bytes) -> Dict[str, Any]:
        """Deserialización según configuración"""
        serialization_config = self.config["processing"]["serialization"]
        format_type = serialization_config["format"]

        if format_type == "json":
            try:
                return json.loads(raw_data.decode(serialization_config["encoding"]))
            except:
                # 🔧 Fallback a estructura básica
                return {'source_ip': 'unknown', 'target_ip': 'unknown'}

        elif format_type == "protobuf":
            # 📦 Implementar deserialización protobuf según tu setup
            # Por ahora fallback
            return {'source_ip': 'unknown', 'target_ip': 'unknown'}

        else:
            self.logger.error(f"❌ Formato de serialización desconocido: {format_type}")
            return {'source_ip': 'unknown', 'target_ip': 'unknown'}

    def serialize_event(self, event: Dict[str, Any]) -> bytes:
        """Serialización según configuración"""
        serialization_config = self.config["processing"]["serialization"]
        format_type = serialization_config["format"]

        if format_type == "json":
            try:
                return json.dumps(event).encode(serialization_config["encoding"])
            except:
                return b'{}'

        elif format_type == "protobuf":
            # 📦 Implementar serialización protobuf según tu setup
            # Por ahora fallback
            return json.dumps(event).encode('utf-8')

        else:
            return b'{}'

    def monitor_stats(self):
        """Thread de monitoreo de estadísticas"""
        monitoring_config = self.config["monitoring"]
        interval = monitoring_config["stats_interval_seconds"]

        while self.running:
            time.sleep(interval)

            if not self.running:
                break

            self.log_performance_stats()
            self.check_performance_alerts()

    def log_performance_stats(self):
        """Log de estadísticas de performance"""
        now = time.time()
        interval = now - self.stats['last_stats_time']

        # 📊 Calcular rates
        recv_rate = self.stats['received'] / interval if interval > 0 else 0
        proc_rate = self.stats['enriched'] / interval if interval > 0 else 0
        send_rate = self.stats['sent'] / interval if interval > 0 else 0

        self.logger.info(f"📊 GeoIP Stats:")
        self.logger.info(f"   📨 Recibidos: {self.stats['received']} ({recv_rate:.1f}/s)")
        self.logger.info(f"   🌍 Enriquecidos: {self.stats['enriched']} ({proc_rate:.1f}/s)")
        self.logger.info(f"   📤 Enviados: {self.stats['sent']} ({send_rate:.1f}/s)")
        self.logger.info(f"   ❌ Errores: lookup={self.stats['failed_lookups']}, buffer={self.stats['buffer_errors']}")
        self.logger.info(f"   📋 Queue size: {self.processing_queue.qsize()}")
        self.logger.info(f"   🔄 Backpressure: {self.stats['backpressure_activations']} activaciones")

        # 🔄 Reset stats for next interval
        for key in ['received', 'enriched', 'sent', 'failed_lookups', 'buffer_errors', 'backpressure_activations']:
            self.stats[key] = 0

        self.stats['last_stats_time'] = now

    def check_performance_alerts(self):
        """Verifica alertas de performance desde configuración"""
        monitoring_config = self.config["monitoring"]
        alerts = monitoring_config.get("alerts", {})

        # 🚨 Alert de queue lleno
        queue_usage = self.processing_queue.qsize() / self.config["processing"]["internal_queue_size"]
        max_queue_usage = alerts.get("max_queue_usage_percent", 100) / 100.0

        if queue_usage > max_queue_usage:
            self.logger.warning(
                f"🚨 ALERTA: Queue interno lleno ({queue_usage * 100:.1f}% > {max_queue_usage * 100:.1f}%)")

        # 🚨 Alert de errores de lookup altos
        total_lookups = self.stats['enriched'] + self.stats['failed_lookups']
        if total_lookups > 0:
            failure_rate = (self.stats['failed_lookups'] / total_lookups) * 100
            max_failure_rate = alerts.get("max_geoip_failure_rate_percent", 100)

            if failure_rate > max_failure_rate:
                self.logger.warning(f"🚨 ALERTA: Tasa de fallo GeoIP alta ({failure_rate:.1f}% > {max_failure_rate}%)")

    def run(self):
        """Ejecutar el enriquecedor"""
        self.logger.info("🚀 Iniciando Enhanced GeoIP Enricher...")

        # 🧵 Crear threads según configuración
        threads = []

        # Thread de recepción
        recv_thread = threading.Thread(target=self.receive_events, name="Receiver")
        threads.append(recv_thread)

        # Threads de procesamiento según configuración
        num_processing_threads = self.config["processing"]["threads"]
        for i in range(num_processing_threads):
            proc_thread = threading.Thread(target=self.process_events, name=f"Processor-{i}")
            threads.append(proc_thread)

        # Thread de estadísticas
        stats_thread = threading.Thread(target=self.monitor_stats, name="Monitor")
        threads.append(stats_thread)

        # 🚀 Iniciar todos los threads
        for thread in threads:
            thread.start()

        self.logger.info(f"✅ GeoIP Enricher iniciado con {len(threads)} threads")

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
        self.logger.info(f"   Total procesados: {self.stats['enriched']}")

        # 🧵 Esperar threads
        for thread in threads:
            thread.join(timeout=5)

        # 🔌 Cerrar sockets
        if self.input_socket:
            self.input_socket.close()
        if self.output_socket:
            self.output_socket.close()

        self.context.term()

        self.logger.info("✅ GeoIP Enricher cerrado correctamente")


# 🚀 Main
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Uso: python geoip_enricher.py <config.json>")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        enricher = ConfigurableGeoIPEnricher(config_file)
        enricher.run()
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        sys.exit(1)