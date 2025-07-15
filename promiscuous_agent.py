# promiscuous_agent.py - Completamente configurable desde JSON con backpressure

import zmq
import time
import json
import logging
import threading
import socket
import uuid
from threading import Event
from typing import Dict, Any, Optional
import sys


class ConfigurablePromiscuousAgent:
    """
    Promiscuous Agent completamente configurable desde JSON
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
        self.socket = None
        self.setup_socket()

        # 🔄 Backpressure desde configuración
        self.backpressure_config = self.config["backpressure"]

        # 📊 Métricas
        self.stats = {
            'captured': 0,
            'sent': 0,
            'dropped': 0,
            'filtered': 0,
            'buffer_full_errors': 0,
            'send_timeouts': 0,
            'backpressure_activations': 0,
            'start_time': time.time(),
            'last_stats_time': time.time()
        }

        # 🎛️ Control
        self.stop_event = Event()
        self.running = True

        # 📝 Setup logging desde configuración
        self.setup_logging()

        self.logger.info(f"🚀 Promiscuous Agent inicializado - node_id: {self.node_id}")
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

        # ✅ Validar campos críticos - SIN proporcionar defaults
        required_fields = [
            "node_id",
            "zmq",
            "backpressure",
            "capture",
            "logging",
            "monitoring"
        ]

        for field in required_fields:
            if field not in config:
                raise RuntimeError(f"❌ Campo requerido faltante en config: {field}")

        # ✅ Validar subcampos ZMQ
        zmq_required = ["output_port", "linger_ms", "send_timeout_ms", "sndhwm"]
        for field in zmq_required:
            if field not in config["zmq"]:
                raise RuntimeError(f"❌ Campo ZMQ requerido faltante: zmq.{field}")

        # ✅ Validar subcampos backpressure
        bp_required = ["enabled", "max_retries", "retry_delays_ms", "drop_threshold_percent", "activation_threshold"]
        for field in bp_required:
            if field not in config["backpressure"]:
                raise RuntimeError(f"❌ Campo backpressure requerido faltante: backpressure.{field}")

        self._log_config_loaded(config)
        return config

    def _log_config_loaded(self, config: Dict[str, Any]):
        """Log de configuración cargada"""
        print(f"✅ Configuración cargada:")
        print(f"   🏷️ Node ID: {config['node_id']}")
        print(f"   🔌 Puerto ZMQ: {config['zmq']['output_port']}")
        print(f"   🔄 Backpressure: {'✅' if config['backpressure']['enabled'] else '❌'}")
        print(f"   📡 Interface: {config['capture']['interface']}")

    def setup_socket(self):
        """Configuración ZMQ desde archivo de configuración"""
        zmq_config = self.config["zmq"]

        self.socket = self.context.socket(zmq.PUSH)

        # 🔧 Configurar ZMQ desde JSON
        self.socket.setsockopt(zmq.LINGER, zmq_config["linger_ms"])
        self.socket.setsockopt(zmq.SNDHWM, zmq_config["sndhwm"])
        self.socket.setsockopt(zmq.SNDTIMEO, zmq_config["send_timeout_ms"])

        # 🔌 BIND del socket
        port = zmq_config["output_port"]
        bind_address = f"tcp://*:{port}"
        self.socket.bind(bind_address)

        print(f"🔌 Socket ZMQ configurado:")
        print(f"   📡 Bind: {bind_address}")
        print(f"   ⏱️ Timeout: {zmq_config['send_timeout_ms']}ms")

    def setup_logging(self):
        """Setup logging desde configuración"""
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
        self.logger = logging.getLogger(f"promiscuous_agent_{self.node_id}")
        self.logger.setLevel(level)
        self.logger.addHandler(handler)

        # 🔇 Evitar duplicados
        self.logger.propagate = False

    def apply_backpressure(self, attempt: int) -> bool:
        """
        Aplica backpressure según configuración
        Returns: True si debe continuar reintentando, False si debe descartar
        """
        bp_config = self.backpressure_config

        if not bp_config["enabled"]:
            # Sin backpressure - descartar inmediatamente
            return False

        if attempt >= bp_config["max_retries"]:
            # Máximo de reintentos alcanzado
            self.stats['dropped'] += 1
            return False

        # 🔄 Aplicar delay configurado
        delays = bp_config["retry_delays_ms"]
        if attempt < len(delays):
            delay_ms = delays[attempt]
        else:
            # Usar último delay si se excede la lista
            delay_ms = delays[-1]

        time.sleep(delay_ms / 1000.0)  # Convertir a segundos

        self.stats['backpressure_activations'] += 1
        return True

    def should_activate_backpressure(self) -> bool:
        """
        Determina si activar backpressure basado en métricas
        """
        bp_config = self.backpressure_config

        if not bp_config["enabled"]:
            return False

        # 📊 Calcular tasa de errores de buffer
        total_attempts = self.stats['sent'] + self.stats['buffer_full_errors']
        if total_attempts == 0:
            return False

        error_rate = (self.stats['buffer_full_errors'] / total_attempts) * 100

        # 🚨 Activar si excede threshold
        if error_rate >= bp_config["drop_threshold_percent"]:
            return True

        # 🔢 Activar si muchos errores absolutos
        if self.stats['buffer_full_errors'] >= bp_config["activation_threshold"]:
            return True

        return False

    def send_event_with_backpressure(self, event_data: bytes) -> bool:
        """
        Envío con backpressure configurable
        """
        bp_config = self.backpressure_config
        max_retries = bp_config["max_retries"]

        for attempt in range(max_retries + 1):  # +1 para incluir intento inicial
            try:
                # 🚀 Intento de envío
                self.socket.send(event_data, zmq.NOBLOCK)
                self.stats['sent'] += 1
                return True

            except zmq.Again:
                # 🔴 Buffer lleno
                self.stats['buffer_full_errors'] += 1

                if attempt == max_retries:
                    # 🗑️ Último intento fallido - descartar
                    self.stats['dropped'] += 1
                    self.logger.warning(f"⚠️ Evento descartado tras {max_retries} intentos")
                    return False

                # 🔄 Aplicar backpressure
                if not self.apply_backpressure(attempt):
                    return False

                continue

            except zmq.ZMQError as e:
                self.logger.error(f"❌ Error ZMQ: {e}")
                self.stats['dropped'] += 1
                return False

        return False

    def capture_and_send_packet(self, packet_data: bytes):
        """
        Simula captura y envío de paquete
        En implementación real, aquí iría la lógica de captura de red
        """
        self.stats['captured'] += 1

        # 🎯 Aplicar filtros desde configuración
        if self.should_filter_packet(packet_data):
            self.stats['filtered'] += 1
            return

        # 📤 Enviar con backpressure
        success = self.send_event_with_backpressure(packet_data)

        if not success:
            # Log solo si backpressure está habilitado y falló
            if self.backpressure_config["enabled"]:
                self.logger.warning("⚠️ Backpressure activo - evento descartado")

    def should_filter_packet(self, packet_data: bytes) -> bool:
        """
        Aplica filtros desde configuración
        """
        capture_config = self.config["capture"]

        # 🎯 Aplicar filtros configurados
        # En implementación real, aquí iría lógica de filtrado basada en:
        # - capture_config["excluded_ports"]
        # - capture_config["included_protocols"]
        # - capture_config["filter_rules"]

        # Por ahora, filtro simulado
        return len(packet_data) < capture_config.get("min_packet_size", 0)

    def monitor_performance(self):
        """
        Thread de monitoreo de performance
        """
        monitoring_config = self.config["monitoring"]
        interval = monitoring_config["stats_interval_seconds"]

        while self.running:
            time.sleep(interval)

            if not self.running:
                break

            self.log_performance_stats()
            self.check_performance_alerts()

    def log_performance_stats(self):
        """
        Log de estadísticas de performance
        """
        now = time.time()
        interval = now - self.stats['last_stats_time']

        # 📊 Calcular rates
        capture_rate = self.stats['captured'] / interval if interval > 0 else 0
        send_rate = self.stats['sent'] / interval if interval > 0 else 0
        drop_rate = self.stats['dropped'] / interval if interval > 0 else 0

        self.logger.info(f"📊 Performance Stats:")
        self.logger.info(f"   📡 Capturados: {self.stats['captured']} ({capture_rate:.1f}/s)")
        self.logger.info(f"   📤 Enviados: {self.stats['sent']} ({send_rate:.1f}/s)")
        self.logger.info(f"   🗑️ Descartados: {self.stats['dropped']} ({drop_rate:.1f}/s)")
        self.logger.info(f"   🔄 Backpressure: {self.stats['backpressure_activations']} activaciones")
        self.logger.info(f"   🚫 Filtrados: {self.stats['filtered']}")

        # 🔄 Reset stats for next interval
        for key in ['captured', 'sent', 'dropped', 'filtered', 'backpressure_activations']:
            self.stats[key] = 0

        self.stats['last_stats_time'] = now

    def check_performance_alerts(self):
        """
        Verifica alertas de performance desde configuración
        """
        monitoring_config = self.config["monitoring"]
        alerts = monitoring_config.get("alerts", {})

        # 🚨 Alert de drop rate alto
        total_events = self.stats['sent'] + self.stats['dropped']
        if total_events > 0:
            drop_percentage = (self.stats['dropped'] / total_events) * 100

            max_drop_rate = alerts.get("max_drop_rate_percent", 100)  # Sin alerta por defecto
            if drop_percentage > max_drop_rate:
                self.logger.warning(f"🚨 ALERTA: Drop rate alto ({drop_percentage:.1f}% > {max_drop_rate}%)")

        # 🚨 Alert de backpressure frecuente
        max_bp_activations = alerts.get("max_backpressure_activations", float('inf'))
        if self.stats['backpressure_activations'] > max_bp_activations:
            self.logger.warning(
                f"🚨 ALERTA: Backpressure muy frecuente ({self.stats['backpressure_activations']} > {max_bp_activations})")

    def simulate_packet_capture(self):
        """
        Simula captura de paquetes para testing
        En implementación real, esto sería reemplazado por captura real de red
        """
        capture_config = self.config["capture"]
        max_pps = capture_config["max_packets_per_second"]

        packet_interval = 1.0 / max_pps if max_pps > 0 else 0.1

        self.logger.info(f"🎯 Iniciando simulación de captura - {max_pps} pps")

        packet_count = 0
        while self.running:
            # 📦 Simular packet data
            packet_data = f"packet_{packet_count}_{self.node_id}".encode('utf-8')

            # 📡 Procesar packet
            self.capture_and_send_packet(packet_data)

            packet_count += 1

            # ⏱️ Rate limiting
            time.sleep(packet_interval)

    def run(self):
        """
        Ejecutar el agent
        """
        self.logger.info("🚀 Iniciando Enhanced Promiscuous Agent...")

        # 🧵 Iniciar threads
        threads = []

        # Thread de monitoreo
        monitor_thread = threading.Thread(target=self.monitor_performance, name="Monitor")
        monitor_thread.start()
        threads.append(monitor_thread)

        # Thread de captura (simulada)
        capture_thread = threading.Thread(target=self.simulate_packet_capture, name="Capture")
        capture_thread.start()
        threads.append(capture_thread)

        self.logger.info(f"✅ Agent iniciado con {len(threads)} threads")

        try:
            # 🔄 Mantener vivo
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("🛑 Deteniendo Agent...")

        # 🛑 Cierre graceful
        self.shutdown(threads)

    def shutdown(self, threads):
        """
        Cierre graceful
        """
        self.running = False
        self.stop_event.set()

        # 📊 Stats finales
        runtime = time.time() - self.stats['start_time']
        self.logger.info(f"📊 Stats finales - Runtime: {runtime:.1f}s")

        # 🧵 Esperar threads
        for thread in threads:
            thread.join(timeout=5)

        # 🔌 Cerrar socket
        if self.socket:
            self.socket.close()

        self.context.term()

        self.logger.info("✅ Promiscuous Agent cerrado correctamente")


# 🚀 Main
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Uso: python promiscuous_agent.py <config.json>")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        agent = ConfigurablePromiscuousAgent(config_file)
        agent.run()
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        sys.exit(1)