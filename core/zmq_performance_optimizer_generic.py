#!/usr/bin/env python3
"""
🚀 ZMQ PERFORMANCE OPTIMIZER v3.1 GENERIC
zmq_performance_optimizer_v31_generic.py

Script GENÉRICO para optimizar configuración ZMQ de CUALQUIER componente del pipeline
- Funciona con evolutionary_sniffer, geoip_enricher, ml_detector, dashboard, etc.
- Detecta automáticamente puertos y tipos de socket desde JSON
- Crea consumers apropriados (PULL para PUSH, SUB para PUB)
- Genera consejos específicos por tipo de componente
- Útil para drenar cuando migras el siguiente componente

Autor: Alonso Isidoro, Claude
Fecha: Agosto 21, 2025
Versión: 3.1.0-generic-components
"""

import zmq
import json
import time
import threading
import sys
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path


class GenericComponentZMQAnalyzer:
    """Analizador ZMQ genérico para cualquier componente del pipeline"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = {}
        self.component_info = {}
        self.network_config = {}
        self.zmq_config = {}
        self.load_and_analyze_config()

    def load_and_analyze_config(self):
        """Cargar y analizar configuración del componente"""
        print(f"📋 Analizando configuración: {self.config_file}")

        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)

            # Extraer información del componente
            self.component_info = self.config.get("component", {})
            self.network_config = self.config.get("network", {})
            self.zmq_config = self.config.get("zmq", {})

            # Info básica
            component_name = self.component_info.get("name", "unknown")
            component_version = self.component_info.get("version", "unknown")
            component_type = self.config.get("component_type", "unknown")
            node_id = self.config.get("node_id", "unknown")

            print(f"✅ Componente detectado:")
            print(f"   📛 Nombre: {component_name}")
            print(f"   🔢 Versión: {component_version}")
            print(f"   🎯 Tipo: {component_type}")
            print(f"   🆔 Node ID: {node_id}")

            # Analizar sockets
            self.analyze_network_config()

        except FileNotFoundError:
            raise RuntimeError(f"❌ Config file not found: {self.config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ Invalid JSON: {e}")

    def analyze_network_config(self):
        """Analizar configuración de red del componente"""
        if not self.network_config:
            print("⚠️ No network config found")
            return

        print(f"\n🔌 Configuración de red detectada:")

        # Input socket
        input_socket = self.network_config.get("input_socket", {})
        if input_socket:
            input_address = input_socket.get("address", "localhost")
            input_port = input_socket.get("port", "unknown")
            input_type = input_socket.get("socket_type", "unknown")
            input_mode = input_socket.get("mode", "unknown")
            print(f"   📥 Input: {input_address}:{input_port} ({input_type}, {input_mode})")

        # Output socket
        output_socket = self.network_config.get("output_socket", {})
        if output_socket:
            output_address = output_socket.get("address", "localhost")
            output_port = output_socket.get("port", "unknown")
            output_type = output_socket.get("socket_type", "unknown")
            output_mode = output_socket.get("mode", "unknown")
            print(f"   📤 Output: {output_address}:{output_port} ({output_type}, {output_mode})")

    def get_consumer_config(self) -> List[Tuple[int, str, str]]:
        """Obtener configuración para crear consumers
        Returns: Lista de (puerto, tipo_socket_consumer, descripción)
        """
        consumers = []

        # Para output sockets, crear consumer apropriado
        output_socket = self.network_config.get("output_socket", {})
        if output_socket:
            port = output_socket.get("port")
            socket_type = output_socket.get("socket_type", "").upper()

            if socket_type == "PUSH":
                # Para PUSH, crear PULL consumer
                consumers.append((port, "PULL", f"Draining PUSH messages from port {port}"))
            elif socket_type == "PUB":
                # Para PUB, crear SUB consumer
                consumers.append((port, "SUB", f"Subscribing to PUB messages from port {port}"))
            elif socket_type == "REP":
                # Para REP, crear REQ consumer (menos común)
                consumers.append((port, "REQ", f"Requesting from REP on port {port}"))

        return consumers

    def get_component_specific_advice(self) -> List[str]:
        """Generar consejos específicos según el tipo de componente"""
        component_type = self.config.get("component_type", "unknown")
        component_name = self.component_info.get("name", "")
        advice = []

        # Consejos generales primero
        advice.extend([
            f"📊 Consejos para {component_name} ({component_type}):",
            ""
        ])

        # Consejos específicos por tipo
        if "sniffer" in component_type or "sniffer" in component_name:
            advice.extend([
                "🔬 SNIFFER ESPECÍFICO:",
                "   • Aumentar capture_buffer_size si hay packet drops",
                "   • Considerar pinning a CPU cores específicos",
                "   • Monitorear interface utilization",
                "   • Usar high-performance interfaces (no tun/tap para prod)",
                "   • Configurar kernel bypass si está disponible",
                ""
            ])

        elif "geoip" in component_type or "enricher" in component_type:
            advice.extend([
                "🌍 GEOIP ENRICHER ESPECÍFICO:",
                "   • Optimizar cache_size según memoria disponible",
                "   • Considerar pre-loading de IPs comunes",
                "   • Configurar timeout de API apropiado",
                "   • Monitorear cache hit rate (target >80%)",
                "   • Balancear entre MaxMind y API calls",
                ""
            ])

        elif "ml_detector" in component_type or "tricapa" in component_type:
            advice.extend([
                "🧠 ML DETECTOR ESPECÍFICO:",
                "   • Ajustar worker threads según CPU cores",
                "   • Optimizar model loading (joblib vs pickle)",
                "   • Configurar model cache apropiadamente",
                "   • Monitorear inference latency (<50ms target)",
                "   • Considerar model quantization para speed",
                "   • Usar batch processing si es posible",
                ""
            ])

        elif "dashboard" in component_type:
            advice.extend([
                "📊 DASHBOARD ESPECÍFICO:",
                "   • Usar SUB sockets para múltiples publishers",
                "   • Configurar message filtering si es necesario",
                "   • Optimizar refresh rates (no <100ms)",
                "   • Considerar websocket buffering",
                "   • Limitar historial en memoria",
                ""
            ])

        # Consejos ZMQ específicos según configuración
        zmq_advice = self.get_zmq_specific_advice()
        advice.extend(zmq_advice)

        return advice

    def get_zmq_specific_advice(self) -> List[str]:
        """Consejos específicos de configuración ZMQ"""
        advice = ["🔧 CONFIGURACIÓN ZMQ:"]

        # Analizar HWM
        rcvhwm = self.zmq_config.get("rcvhwm", 1000)
        sndhwm = self.zmq_config.get("sndhwm", 1000)

        if rcvhwm < 1000:
            advice.append(f"   ⚠️ rcvhwm muy bajo ({rcvhwm}) - considerar aumentar a 2000+")
        if sndhwm < 1000:
            advice.append(f"   ⚠️ sndhwm muy bajo ({sndhwm}) - considerar aumentar a 2000+")

        # Analizar timeouts
        recv_timeout = self.zmq_config.get("recv_timeout_ms", 1000)
        send_timeout = self.zmq_config.get("send_timeout_ms", 1000)

        if recv_timeout > 5000:
            advice.append(f"   ⚠️ recv_timeout muy alto ({recv_timeout}ms) - considerar reducir")
        if send_timeout > 1000:
            advice.append(f"   ⚠️ send_timeout muy alto ({send_timeout}ms) - considerar reducir")

        # Detectar patrón PUB/SUB
        output_socket = self.network_config.get("output_socket", {})
        if output_socket.get("socket_type") == "PUB":
            advice.extend([
                "   📡 Patrón PUB detectado:",
                "     • Configurar tcp_keepalive=true",
                "     • Usar immediate=false para mejor throughput",
                "     • Considerar conflate=false (no perder eventos)",
                "     • Aumentar sndhwm para múltiples suscriptores"
            ])

        advice.append("")
        return advice

    def suggest_optimizations(self) -> Dict[str, Any]:
        """Sugerir optimizaciones específicas para este componente"""
        component_type = self.config.get("component_type", "unknown")

        optimizations = {}

        # ZMQ optimizations básicas
        zmq_opts = {
            "rcvhwm": max(self.zmq_config.get("rcvhwm", 1000), 2000),
            "sndhwm": max(self.zmq_config.get("sndhwm", 1000), 2000),
            "recv_timeout_ms": 100,
            "send_timeout_ms": 100,
            "linger_ms": 0,
            "recv_buffer_size": 262144,
            "send_buffer_size": 262144
        }

        # Optimizaciones específicas por componente
        if "sniffer" in component_type:
            zmq_opts.update({
                "rcvhwm": 5000,  # Sniffer necesita más buffer
                "io_threads": 2,
                "tcp_nodelay": True
            })
        elif "ml_detector" in component_type:
            zmq_opts.update({
                "sndhwm": 3000,  # ML detector puede generar muchos eventos
                "immediate": False,  # Mejor para PUB
                "conflate": False
            })
        elif "dashboard" in component_type:
            zmq_opts.update({
                "rcvhwm": 1000,  # Dashboard no necesita tanto buffer
                "recv_timeout_ms": 500
            })

        optimizations["zmq"] = zmq_opts

        # Processing optimizations
        processing_opts = {
            "queue_timeout_seconds": 1.0,
            "max_processing_time": 5.0
        }

        if "ml_detector" in component_type:
            processing_opts.update({
                "threads": min(4, max(2, self.get_cpu_cores() - 1)),
                "internal_queue_size": 500,
                "protobuf_queue_size": 1000
            })
        elif "enricher" in component_type:
            processing_opts.update({
                "threads": min(3, max(2, self.get_cpu_cores() - 2)),
                "internal_queue_size": 1000,
                "cache_size": 10000
            })

        optimizations["processing"] = processing_opts

        return optimizations

    def get_cpu_cores(self) -> int:
        """Obtener número de CPU cores"""
        try:
            import psutil
            return psutil.cpu_count()
        except:
            return 4  # Default fallback


class GenericZMQConsumer:
    """Consumer ZMQ genérico que se adapta al tipo de socket"""

    def __init__(self, port: int, socket_type: str, description: str):
        self.port = port
        self.socket_type = socket_type.upper()
        self.description = description
        self.context = None
        self.socket = None
        self.running = False
        self.stats = {
            'messages_received': 0,
            'bytes_received': 0,
            'start_time': time.time(),
            'last_message_time': 0,
            'message_rate_history': [],
            'errors': 0
        }

    def setup_socket(self):
        """Configurar socket según el tipo"""
        self.context = zmq.Context()

        if self.socket_type == "PULL":
            self.socket = self.context.socket(zmq.PULL)
            self.socket.connect(f"tcp://localhost:{self.port}")
        elif self.socket_type == "SUB":
            self.socket = self.context.socket(zmq.SUB)
            self.socket.connect(f"tcp://localhost:{self.port}")
            self.socket.setsockopt(zmq.SUBSCRIBE, b"")  # Subscribe to all messages
        elif self.socket_type == "REQ":
            self.socket = self.context.socket(zmq.REQ)
            self.socket.connect(f"tcp://localhost:{self.port}")
        else:
            raise ValueError(f"Unsupported socket type: {self.socket_type}")

        # Configuración común
        self.socket.setsockopt(zmq.RCVHWM, 10000)
        self.socket.setsockopt(zmq.RCVTIMEO, 100)
        self.socket.setsockopt(zmq.LINGER, 0)

        print(f"🔌 Consumer {self.socket_type} conectado a puerto {self.port}")

    def consume_messages(self):
        """Consumir mensajes del socket"""
        print(f"📥 {self.description}")
        print(f"🚀 Consumer iniciado: {self.socket_type} en puerto {self.port}")

        self.setup_socket()
        self.running = True

        last_stats_time = time.time()

        try:
            while self.running:
                try:
                    if self.socket_type == "REQ":
                        # Para REQ, enviar request primero
                        self.socket.send(b"status")
                        message = self.socket.recv()
                    else:
                        # Para PULL y SUB
                        message = self.socket.recv(zmq.NOBLOCK)

                    # Actualizar estadísticas
                    self.stats['messages_received'] += 1
                    self.stats['bytes_received'] += len(message)
                    self.stats['last_message_time'] = time.time()

                    # Log cada 100 mensajes
                    if self.stats['messages_received'] % 100 == 0:
                        self.log_stats()

                    # Log stats cada 30 segundos
                    if time.time() - last_stats_time > 30:
                        self.log_detailed_stats()
                        last_stats_time = time.time()

                except zmq.Again:
                    # No message available
                    time.sleep(0.01)
                except Exception as e:
                    self.stats['errors'] += 1
                    if self.stats['errors'] % 10 == 0:
                        print(f"❌ Consumer error #{self.stats['errors']}: {e}")
                    time.sleep(0.1)

        except KeyboardInterrupt:
            print(f"\n🛑 Stopping {self.socket_type} consumer...")
        finally:
            self.cleanup()

    def log_stats(self):
        """Log estadísticas básicas"""
        elapsed = time.time() - self.stats['start_time']
        if elapsed > 0:
            msg_rate = self.stats['messages_received'] / elapsed
            bytes_rate = self.stats['bytes_received'] / elapsed

            print(f"📊 {self.socket_type}:{self.port} - "
                  f"{self.stats['messages_received']} msgs, "
                  f"{msg_rate:.1f} msg/s, "
                  f"{bytes_rate:.0f} bytes/s")

    def log_detailed_stats(self):
        """Log estadísticas detalladas"""
        elapsed = time.time() - self.stats['start_time']
        if elapsed > 0:
            msg_rate = self.stats['messages_received'] / elapsed
            bytes_rate = self.stats['bytes_received'] / elapsed
            avg_msg_size = self.stats['bytes_received'] / max(1, self.stats['messages_received'])

            print(f"\n📈 STATS DETALLADAS {self.socket_type}:{self.port}:")
            print(f"   📨 Total mensajes: {self.stats['messages_received']}")
            print(f"   📦 Total bytes: {self.stats['bytes_received']:,}")
            print(f"   ⚡ Rate mensajes: {msg_rate:.1f} msg/s")
            print(f"   🚀 Rate bytes: {bytes_rate:.0f} bytes/s")
            print(f"   📏 Tamaño promedio: {avg_msg_size:.0f} bytes")
            print(f"   ❌ Errores: {self.stats['errors']}")

            # Verificar si hay flujo reciente
            time_since_last = time.time() - self.stats['last_message_time']
            if time_since_last > 30:
                print(f"   ⚠️ Sin mensajes desde hace {time_since_last:.0f}s")

    def cleanup(self):
        """Limpiar recursos"""
        self.running = False
        if self.socket:
            self.socket.close()
        if self.context:
            self.context.term()

        print(f"✅ Consumer {self.socket_type}:{self.port} terminado")
        print(f"   📊 Total procesado: {self.stats['messages_received']} mensajes")


class GenericZMQPerformanceTuner:
    """Tuner de performance genérico para cualquier componente"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.analyzer = GenericComponentZMQAnalyzer(config_file)

    def optimize_config(self):
        """Optimizar configuración del componente"""
        print(f"\n🔧 Optimizando configuración de {self.config_file}...")

        # Obtener optimizaciones sugeridas
        optimizations = self.analyzer.suggest_optimizations()

        # Crear backup
        backup_file = f"{self.config_file}.backup.{int(time.time())}"
        with open(backup_file, 'w') as f:
            json.dump(self.analyzer.config, f, indent=2)
        print(f"📝 Backup creado: {backup_file}")

        # Aplicar optimizaciones
        config = self.analyzer.config.copy()

        # Actualizar sección ZMQ
        if "zmq" not in config:
            config["zmq"] = {}

        zmq_opts = optimizations.get("zmq", {})
        print(f"\n📊 Aplicando optimizaciones ZMQ:")
        for key, new_value in zmq_opts.items():
            old_value = config["zmq"].get(key, "not set")
            config["zmq"][key] = new_value
            print(f"   {key}: {old_value} → {new_value}")

        # Actualizar sección processing
        if "processing" not in config:
            config["processing"] = {}

        processing_opts = optimizations.get("processing", {})
        print(f"\n⚙️ Aplicando optimizaciones de procesamiento:")
        for key, new_value in processing_opts.items():
            old_value = config["processing"].get(key, "not set")
            config["processing"][key] = new_value
            print(f"   {key}: {old_value} → {new_value}")

        # Guardar configuración optimizada
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"\n✅ Configuración optimizada guardada en: {self.config_file}")

    def show_advice(self):
        """Mostrar consejos específicos del componente"""
        advice = self.analyzer.get_component_specific_advice()
        print(f"\n💡 CONSEJOS DE PERFORMANCE:")
        print("=" * 60)
        for line in advice:
            print(line)


def create_consumers_for_component(config_file: str) -> List[GenericZMQConsumer]:
    """Crear consumers apropriados para un componente"""
    analyzer = GenericComponentZMQAnalyzer(config_file)
    consumer_configs = analyzer.get_consumer_config()

    if not consumer_configs:
        print("⚠️ No se encontraron sockets de salida para crear consumers")
        return []

    consumers = []
    for port, socket_type, description in consumer_configs:
        if port:
            consumer = GenericZMQConsumer(port, socket_type, description)
            consumers.append(consumer)

    return consumers


def run_consumers(consumers: List[GenericZMQConsumer]):
    """Ejecutar múltiples consumers en threads separados"""
    if not consumers:
        print("❌ No hay consumers para ejecutar")
        return

    threads = []

    print(f"\n🚀 Iniciando {len(consumers)} consumer(s)...")

    for consumer in consumers:
        thread = threading.Thread(
            target=consumer.consume_messages,
            name=f"Consumer-{consumer.socket_type}-{consumer.port}",
            daemon=True
        )
        thread.start()
        threads.append(thread)

    print(f"✅ {len(consumers)} consumer(s) ejecutándose")
    print("\n💡 Consejos mientras consumes:")
    print("   • Ejecuta tu componente en otra terminal")
    print("   • Observa las estadísticas de rate y throughput")
    print("   • Ctrl+C para parar todos los consumers")

    try:
        # Esperar a todos los threads
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\n🛑 Parando todos los consumers...")
        for consumer in consumers:
            consumer.running = False


def main():
    """Función principal genérica"""
    if len(sys.argv) < 2:
        print("❌ Uso: python zmq_performance_optimizer_v31_generic.py <config.json> [action]")
        print("\n📋 Actions disponibles:")
        print("   optimize  - Optimizar configuración ZMQ (default)")
        print("   consume   - Crear consumers para drenar mensajes")
        print("   analyze   - Solo analizar configuración sin cambios")
        print("   advice    - Mostrar consejos específicos del componente")
        print("\n💡 Ejemplos:")
        print("   # Optimizar ml_detector")
        print("   python zmq_performance_optimizer_v31_generic.py ml_detector_config.json optimize")
        print("   # Drenar mensajes del ml_detector mientras migras dashboard")
        print("   python zmq_performance_optimizer_v31_generic.py ml_detector_config.json consume")
        print("   # Analizar sniffer")
        print("   python zmq_performance_optimizer_v31_generic.py sniffer_config.json analyze")
        sys.exit(1)

    config_file = sys.argv[1]
    action = sys.argv[2] if len(sys.argv) > 2 else "optimize"

    if not Path(config_file).exists():
        print(f"❌ Config file not found: {config_file}")
        sys.exit(1)

    print("🚀 ZMQ PERFORMANCE OPTIMIZER v3.1 GENERIC")
    print("=" * 60)
    print(f"📁 Config: {config_file}")
    print(f"🎯 Action: {action}")
    print("=" * 60)

    try:
        if action == "consume":
            print("🔧 Creando consumers para drenar mensajes...")
            consumers = create_consumers_for_component(config_file)
            if consumers:
                run_consumers(consumers)
            else:
                print("❌ No se pudieron crear consumers")

        elif action == "analyze":
            print("🔍 Analizando configuración del componente...")
            analyzer = GenericComponentZMQAnalyzer(config_file)
            tuner = GenericZMQPerformanceTuner(config_file)
            tuner.show_advice()

        elif action == "advice":
            print("💡 Generando consejos específicos...")
            tuner = GenericZMQPerformanceTuner(config_file)
            tuner.show_advice()

        else:  # optimize (default)
            print("🔧 Optimizando configuración del componente...")
            tuner = GenericZMQPerformanceTuner(config_file)
            tuner.optimize_config()
            tuner.show_advice()

            print(f"\n🚀 Siguientes pasos:")
            print(f"   1. Revisar cambios en: {config_file}")
            print(f"   2. Crear consumer: python {sys.argv[0]} {config_file} consume")
            print(f"   3. Ejecutar componente optimizado en otra terminal")
            print(f"   4. Monitorear performance y ajustar según necesidad")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n✅ OPERACIÓN COMPLETADA!")


if __name__ == "__main__":
    main()