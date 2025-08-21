#!/usr/bin/env python3
"""
🚀 ZMQ PERFORMANCE OPTIMIZER v3.1 GENERIC + SCHEDULER FIREWALL ADAPTED - TOPOLOGY FIXED
zmq_performance_optimizer_v31_generic_scheduler.py

Script GENÉRICO para optimizar configuración ZMQ de CUALQUIER componente del pipeline
+ ESPECÍFICAMENTE ADAPTADO para scheduler_firewall con ETCD crypto
+ 🔧 FIX CRÍTICO: Corregida topología para no conflictuar con componentes activos

- Funciona con evolutionary_sniffer, geoip_enricher, ml_detector, dashboard, etc.
- NUEVO: Detecta automáticamente scheduler_firewall + ETCD crypto
- NUEVO: Crea consumers/producers específicos para scheduler (SUB/PUSH/PULL)
- 🔧 CORREGIDO: Respeta bind/connect según topología real del pipeline
- NUEVO: Consejos específicos para decision engine con crypto obligatorio
- Detecta automáticamente puertos y tipos de socket desde JSON
- Útil para drenar cuando migras el siguiente componente

Autor: Alonso Isidoro, Claude
Fecha: Agosto 21, 2025
Versión: 3.1.0-generic-components-scheduler-firewall-topology-fixed
"""

import zmq
import json
import time
import threading
import sys
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path


class GenericComponentZMQAnalyzer:
    """Analizador ZMQ genérico para cualquier componente del pipeline + SCHEDULER FIREWALL"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = {}
        self.component_info = {}
        self.network_config = {}
        self.zmq_config = {}
        self.is_scheduler_firewall = False
        self.etcd_crypto_enabled = False
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
            component_role = self.component_info.get("role", "unknown")
            node_id = self.config.get("node_id", "unknown")

            # 🔥 NUEVO: Detectar scheduler_firewall específicamente
            self.is_scheduler_firewall = (
                    "scheduler" in component_name.lower() or
                    "scheduler" in component_role.lower() or
                    "firewall_scheduler" in component_role.lower() or
                    self._has_scheduler_network_pattern()
            )

            # 🔐 NUEVO: Detectar ETCD crypto
            crypto_config = self.config.get("crypto", {})
            etcd_crypto_config = self.config.get("etcd_crypto", {})
            self.etcd_crypto_enabled = (
                    crypto_config.get("enabled", False) and
                    crypto_config.get("use_etcd_pipeline_key", False) and
                    bool(etcd_crypto_config)
            )

            print(f"✅ Componente detectado:")
            print(f"   📛 Nombre: {component_name}")
            print(f"   🔢 Versión: {component_version}")
            print(f"   🎯 Tipo: {component_type}")
            print(f"   🎭 Role: {component_role}")
            print(f"   🆔 Node ID: {node_id}")

            # 🔥 NUEVO: Info específica scheduler
            if self.is_scheduler_firewall:
                print(f"   🔥 SCHEDULER FIREWALL DETECTADO!")
                print(f"   🔐 ETCD crypto: {'✅ ENABLED' if self.etcd_crypto_enabled else '❌ DISABLED'}")

            # Analizar sockets
            self.analyze_network_config()

        except FileNotFoundError:
            raise RuntimeError(f"❌ Config file not found: {self.config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ Invalid JSON: {e}")

    def _has_scheduler_network_pattern(self) -> bool:
        """Detectar patrón de red específico del scheduler firewall"""
        if not self.network_config:
            return False

        # Scheduler tiene estos 3 sockets específicos
        has_ml_events_input = bool(self.network_config.get("ml_events_input"))
        has_firewall_commands_output = bool(self.network_config.get("firewall_commands_output"))
        has_firewall_responses_input = bool(self.network_config.get("firewall_responses_input"))

        return has_ml_events_input and has_firewall_commands_output and has_firewall_responses_input

    def analyze_network_config(self):
        """Analizar configuración de red del componente"""
        if not self.network_config:
            print("⚠️ No network config found")
            return

        print(f"\n🔌 Configuración de red detectada:")

        if self.is_scheduler_firewall:
            # 🔥 ANÁLISIS ESPECÍFICO SCHEDULER FIREWALL
            print(f"   🔥 SCHEDULER FIREWALL PATTERN DETECTED:")

            # ML Events Input (SUB del ml_detector)
            ml_events = self.network_config.get("ml_events_input", {})
            if ml_events:
                address = ml_events.get("address", "localhost")
                port = ml_events.get("port", "unknown")
                socket_type = ml_events.get("socket_type", "unknown")
                mode = ml_events.get("mode", "unknown")
                print(f"   📥 ML Events Input: {address}:{port} ({socket_type}, {mode})")
                print(f"       🧠 Recibe del ml_detector tricapa V3.1.2")

            # Firewall Commands Output (PUSH al firewall_agent)
            fw_commands = self.network_config.get("firewall_commands_output", {})
            if fw_commands:
                address = fw_commands.get("address", "localhost")
                port = fw_commands.get("port", "unknown")
                socket_type = fw_commands.get("socket_type", "unknown")
                mode = fw_commands.get("mode", "unknown")
                print(f"   📤 Firewall Commands: {address}:{port} ({socket_type}, {mode})")
                print(f"       🛡️ Envía al simple_firewall_agent")

            # Firewall Responses Input (PULL del firewall_agent)
            fw_responses = self.network_config.get("firewall_responses_input", {})
            if fw_responses:
                address = fw_responses.get("address", "localhost")
                port = fw_responses.get("port", "unknown")
                socket_type = fw_responses.get("socket_type", "unknown")
                mode = fw_responses.get("mode", "unknown")
                print(f"   📥 Firewall Responses: {address}:{port} ({socket_type}, {mode})")
                print(f"       🔄 Recibe respuestas del firewall_agent")

            if self.etcd_crypto_enabled:
                print(f"   🔐 ETCD CRYPTO: ✅ ENABLED en todos los canales")
        else:
            # Análisis genérico para otros componentes
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
        """🔧 CONFIGURACIÓN CORREGIDA para scheduler firewall
        Returns: Lista de (puerto, tipo_socket_consumer, descripción)
        """
        consumers = []

        if self.is_scheduler_firewall:
            # 🔥 CONSUMERS CORREGIDOS SCHEDULER FIREWALL

            # 1. Consumer para firewall commands (BIND PULL para drenar PUSH del scheduler)
            fw_commands = self.network_config.get("firewall_commands_output", {})
            if fw_commands and fw_commands.get("socket_type") == "PUSH":
                port = fw_commands.get("port")
                if port:
                    consumers.append((port, "PULL", f"🛡️ Draining firewall commands from scheduler (port {port})"))

            # 2. Producer para firewall responses (CONNECT PUSH para enviar al BIND PULL del scheduler)
            fw_responses = self.network_config.get("firewall_responses_input", {})
            if fw_responses and fw_responses.get("socket_type") == "PULL":
                port = fw_responses.get("port")
                if port:
                    consumers.append(
                        (port, "PUSH_PRODUCER", f"🔄 Simulating firewall responses to scheduler (port {port})"))

            # 3. 🔧 CORREGIDO: Monitor para ML events (CONNECT SUB al BIND PUB del ml_detector)
            ml_events = self.network_config.get("ml_events_input", {})
            if ml_events and ml_events.get("socket_type") == "SUB":
                port = ml_events.get("port")
                if port:
                    consumers.append((port, "SUB_MONITOR", f"🧠 Monitoring ML events from ml_detector (port {port})"))
        else:
            # Lógica genérica para otros componentes
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

        if self.is_scheduler_firewall:
            # 🔥 CONSEJOS ESPECÍFICOS SCHEDULER FIREWALL + ETCD
            advice.extend([
                f"🔥 CONSEJOS ESPECÍFICOS SCHEDULER FIREWALL + ETCD:",
                "",
                "🎯 DECISION ENGINE OPTIMIZATION:",
                "   • Optimizar decision_timeout_ms (target <50ms por decisión)",
                "   • Configurar max_decisions_per_second según capacidad HW",
                "   • Usar cache_decisions=false para máxima seguridad",
                "   • Monitorear queue utilization (target <70%)",
                "   • Ajustar worker threads según CPU cores disponibles",
                "",
                "🔐 ETCD CRYPTO PERFORMANCE:",
                f"   • ETCD crypto: {'✅ ENABLED' if self.etcd_crypto_enabled else '❌ DISABLED'}",
                "   • Pipeline key rotativo mejora seguridad vs performance",
                "   • Monitorear crypto_operations_per_second",
                "   • Verificar connectivity a ETCD cluster (latency <5ms)",
                "   • Track pipeline_key_usage para detectar anomalías",
                "",
                "🛡️ FIREWALL INTEGRATION:",
                "   • Configurar rate limits específicos por tipo de amenaza",
                "   • Balancear dry_run vs production rules",
                "   • Monitorear response latency del firewall_agent",
                "   • Implementar fallback behavior para casos edge",
                "   • Verificar firewall agent capacity (max concurrent rules)",
                "",
                "📊 MONITORING ESPECÍFICO:",
                "   • Track decision_latency_ms distribution",
                "   • Monitor rule_applications_per_minute",
                "   • Alert en crypto_failures_per_minute >5",
                "   • Track firewall_response_success_rate >95%",
                "   • Monitor ETCD connectivity health",
                "",
            ])
        else:
            # Consejos generales primero
            advice.extend([
                f"📊 Consejos para {component_name} ({component_type}):",
                ""
            ])

        # Consejos específicos por tipo (mantener la lógica original)
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

        if self.is_scheduler_firewall:
            # 🔥 ZMQ ESPECÍFICO SCHEDULER FIREWALL
            ml_events_hwm = self.network_config.get("ml_events_input", {}).get("high_water_mark", 500)
            fw_commands_hwm = self.network_config.get("firewall_commands_output", {}).get("high_water_mark", 200)
            fw_responses_hwm = self.network_config.get("firewall_responses_input", {}).get("high_water_mark", 200)

            advice.extend([
                f"   📥 ML Events HWM: {ml_events_hwm} (recomendado: 1000+ para burst handling)",
                f"   📤 FW Commands HWM: {fw_commands_hwm} (recomendado: 500+ para command buffering)",
                f"   📥 FW Responses HWM: {fw_responses_hwm} (recomendado: 300+ para response buffering)",
                "   🎯 Scheduler específico:",
                "     • Usar tcp_keepalive=true para conexiones estables",
                "     • Configurar linger_ms=0 para shutdown rápido",
                "     • recv_timeout_ms=100 para decision engine responsivo",
                "     • send_timeout_ms=50 para firewall commands rápidos",
            ])
        else:
            # Analizar HWM genérico
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
        if not self.is_scheduler_firewall:
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

        if self.is_scheduler_firewall:
            # 🔥 OPTIMIZACIONES ESPECÍFICAS SCHEDULER FIREWALL
            zmq_opts = {
                "context_io_threads": 2,  # Scheduler maneja 3 sockets
                "max_sockets": 32,
                "tcp_keepalive": True,
                "tcp_keepalive_idle": 300,
                "immediate": False,
                "linger_ms": 0,
                "recv_timeout_ms": 100,  # Decisiones rápidas
                "send_timeout_ms": 50,  # Comandos firewall rápidos
                "recv_buffer_size": 131072,
                "send_buffer_size": 262144,
                "max_message_size": 50000
            }

            # Optimizar HWM específicos por socket
            network_updates = {
                "ml_events_input": {
                    "high_water_mark": max(1000,
                                           self.network_config.get("ml_events_input", {}).get("high_water_mark", 500))
                },
                "firewall_commands_output": {
                    "high_water_mark": max(500, self.network_config.get("firewall_commands_output", {}).get(
                        "high_water_mark", 200))
                },
                "firewall_responses_input": {
                    "high_water_mark": max(300, self.network_config.get("firewall_responses_input", {}).get(
                        "high_water_mark", 200))
                }
            }
            optimizations["network_updates"] = network_updates

            # Processing optimizado para decision engine
            processing_opts = {
                "threads": {
                    "ml_events_consumers": 2,  # Más para handle burst
                    "firewall_command_producers": 2,
                    "firewall_response_consumers": 1
                },
                "internal_queues": {
                    "ml_events_queue_size": 500,
                    "firewall_commands_queue_size": 1000,
                    "firewall_responses_queue_size": 200
                },
                "decision_engine": {
                    "max_decisions_per_second": min(100, max(50, self.get_cpu_cores() * 20)),
                    "decision_timeout_ms": 50,
                    "batch_processing": False,
                    "cache_decisions": False
                }
            }
        else:
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

        optimizations["zmq"] = zmq_opts
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
    """🔧 Consumer ZMQ genérico CORREGIDO para respetar topología SCHEDULER FIREWALL"""

    def __init__(self, port: int, socket_type: str, description: str):
        self.port = port
        self.socket_type = socket_type.upper()
        self.description = description
        self.context = None
        self.socket = None
        self.running = False
        self.stats = {
            'messages_received': 0,
            'messages_sent': 0,
            'bytes_received': 0,
            'bytes_sent': 0,
            'start_time': time.time(),
            'last_message_time': 0,
            'message_rate_history': [],
            'errors': 0
        }

    def setup_socket(self):
        """🔧 CONFIGURACIÓN CORREGIDA - Respeta topología existente"""
        self.context = zmq.Context()

        if self.socket_type == "PULL":
            # Para drenar comandos del scheduler (scheduler hace PUSH, nosotros PULL)
            self.socket = self.context.socket(zmq.PULL)
            # 🔧 CORREGIDO: BIND porque actuamos como el firewall_agent que recibe
            self.socket.bind(f"tcp://*:{self.port}")
            print(f"🔌 PULL consumer BIND en puerto {self.port}")

        elif self.socket_type == "SUB":
            self.socket = self.context.socket(zmq.SUB)
            self.socket.connect(f"tcp://localhost:{self.port}")
            self.socket.setsockopt(zmq.SUBSCRIBE, b"")  # Subscribe to all messages
            print(f"🔌 SUB consumer CONNECT a puerto {self.port}")

        elif self.socket_type == "REQ":
            self.socket = self.context.socket(zmq.REQ)
            self.socket.connect(f"tcp://localhost:{self.port}")
            print(f"🔌 REQ consumer CONNECT a puerto {self.port}")

        elif self.socket_type == "PUSH_PRODUCER":
            # Simular respuestas del firewall agent hacia scheduler
            self.socket = self.context.socket(zmq.PUSH)
            # 🔧 CORRECTO: CONNECT porque scheduler hace BIND como PULL en este puerto
            self.socket.connect(f"tcp://localhost:{self.port}")
            print(f"🔌 PUSH_PRODUCER CONNECT a puerto {self.port}")

        elif self.socket_type == "SUB_MONITOR":
            # 🔧 NUEVO: Monitorear eventos ML (CONNECT como SUB al ml_detector que hace BIND como PUB)
            self.socket = self.context.socket(zmq.SUB)
            self.socket.connect(f"tcp://localhost:{self.port}")
            self.socket.setsockopt(zmq.SUBSCRIBE, b"")  # Subscribe to all messages
            print(f"🔌 SUB_MONITOR CONNECT a puerto {self.port} para monitorear ML events")

        else:
            raise ValueError(f"Unsupported socket type: {self.socket_type}")

        # Configuración común
        if "PRODUCER" not in self.socket_type and "MONITOR" not in self.socket_type:
            self.socket.setsockopt(zmq.RCVHWM, 10000)
            self.socket.setsockopt(zmq.RCVTIMEO, 100)
        else:
            self.socket.setsockopt(zmq.SNDHWM, 10000)
            self.socket.setsockopt(zmq.SNDTIMEO, 100)

        self.socket.setsockopt(zmq.LINGER, 0)

        print(
            f"🔌 {self.socket_type} {'producer' if 'PRODUCER' in self.socket_type else 'consumer'} conectado a puerto {self.port}")

    def consume_messages(self):
        """Consumir mensajes del socket o producir si es producer"""
        print(f"📥 {self.description}")
        print(
            f"🚀 {'Producer' if 'PRODUCER' in self.socket_type else 'Consumer'} iniciado: {self.socket_type} en puerto {self.port}")

        self.setup_socket()
        self.running = True

        last_stats_time = time.time()

        try:
            if "PRODUCER" in self.socket_type:
                self._run_producer()
            else:
                self._run_consumer()
        except KeyboardInterrupt:
            print(f"\n🛑 Stopping {self.socket_type}...")
        finally:
            self.cleanup()

    def _run_consumer(self):
        """🔧 EJECUTAR CONSUMER CORREGIDO"""
        last_stats_time = time.time()

        while self.running:
            try:
                if self.socket_type == "REQ":
                    # Para REQ, enviar request primero
                    self.socket.send(b"status")
                    message = self.socket.recv()
                elif self.socket_type in ["PULL", "SUB", "SUB_MONITOR"]:
                    # Para PULL, SUB y SUB_MONITOR
                    message = self.socket.recv(zmq.NOBLOCK)
                else:
                    message = self.socket.recv(zmq.NOBLOCK)

                # Actualizar estadísticas
                self.stats['messages_received'] += 1
                self.stats['bytes_received'] += len(message)
                self.stats['last_message_time'] = time.time()

                # Log específico para SUB_MONITOR
                if self.socket_type == "SUB_MONITOR" and self.stats['messages_received'] % 10 == 0:
                    try:
                        # Intentar parsear como JSON para ver eventos ML
                        msg_data = json.loads(message.decode('utf-8'))
                        risk_score = msg_data.get('risk_score', 'N/A')
                        source_ip = msg_data.get('source_ip', 'N/A')
                        print(f"🧠 ML Event monitored: risk={risk_score}, src={source_ip}")
                    except:
                        print(f"🧠 ML Event monitored: {len(message)} bytes")

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

    def _run_producer(self):
        """Ejecutar como producer para testing del scheduler"""
        last_stats_time = time.time()
        message_count = 0

        while self.running:
            try:
                # Generar mensaje de prueba según el tipo
                if self.socket_type == "PUSH_PRODUCER":
                    # Simular respuesta de firewall agent
                    test_message = {
                        "command_id": f"test_cmd_{message_count}",
                        "node_id": "test_firewall_agent",
                        "success": True,
                        "message": "Test firewall response",
                        "timestamp": int(time.time() * 1000)
                    }
                    message_bytes = json.dumps(test_message).encode('utf-8')
                else:
                    message_bytes = f"test_message_{message_count}".encode('utf-8')

                # Enviar mensaje
                self.socket.send(message_bytes, zmq.NOBLOCK)

                # Actualizar estadísticas
                self.stats['messages_sent'] += 1
                self.stats['bytes_sent'] += len(message_bytes)
                message_count += 1

                # Log cada 100 mensajes
                if self.stats['messages_sent'] % 100 == 0:
                    self.log_stats()

                # Log stats cada 30 segundos
                if time.time() - last_stats_time > 30:
                    self.log_detailed_stats()
                    last_stats_time = time.time()

                # Rate limiting para no saturar
                time.sleep(0.1)  # 10 msg/s

            except zmq.Again:
                time.sleep(0.01)
            except Exception as e:
                self.stats['errors'] += 1
                if self.stats['errors'] % 10 == 0:
                    print(f"❌ Producer error #{self.stats['errors']}: {e}")
                time.sleep(0.1)

    def log_stats(self):
        """Log estadísticas básicas"""
        elapsed = time.time() - self.stats['start_time']
        if elapsed > 0:
            if "PRODUCER" in self.socket_type:
                msg_rate = self.stats['messages_sent'] / elapsed
                bytes_rate = self.stats['bytes_sent'] / elapsed
                print(f"📊 {self.socket_type}:{self.port} - "
                      f"{self.stats['messages_sent']} msgs sent, "
                      f"{msg_rate:.1f} msg/s, "
                      f"{bytes_rate:.0f} bytes/s")
            else:
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
            if "PRODUCER" in self.socket_type:
                msg_rate = self.stats['messages_sent'] / elapsed
                bytes_rate = self.stats['bytes_sent'] / elapsed
                avg_msg_size = self.stats['bytes_sent'] / max(1, self.stats['messages_sent'])

                print(f"\n📈 PRODUCER STATS {self.socket_type}:{self.port}:")
                print(f"   📤 Total enviados: {self.stats['messages_sent']}")
                print(f"   📦 Total bytes: {self.stats['bytes_sent']:,}")
                print(f"   ⚡ Rate mensajes: {msg_rate:.1f} msg/s")
                print(f"   🚀 Rate bytes: {bytes_rate:.0f} bytes/s")
                print(f"   📏 Tamaño promedio: {avg_msg_size:.0f} bytes")
            else:
                msg_rate = self.stats['messages_received'] / elapsed
                bytes_rate = self.stats['bytes_received'] / elapsed
                avg_msg_size = self.stats['bytes_received'] / max(1, self.stats['messages_received'])

                print(f"\n📈 CONSUMER STATS {self.socket_type}:{self.port}:")
                print(f"   📨 Total mensajes: {self.stats['messages_received']}")
                print(f"   📦 Total bytes: {self.stats['bytes_received']:,}")
                print(f"   ⚡ Rate mensajes: {msg_rate:.1f} msg/s")
                print(f"   🚀 Rate bytes: {bytes_rate:.0f} bytes/s")
                print(f"   📏 Tamaño promedio: {avg_msg_size:.0f} bytes")

                # Verificar si hay flujo reciente
                time_since_last = time.time() - self.stats['last_message_time']
                if time_since_last > 30:
                    print(f"   ⚠️ Sin mensajes desde hace {time_since_last:.0f}s")

            print(f"   ❌ Errores: {self.stats['errors']}")

    def cleanup(self):
        """Limpiar recursos"""
        self.running = False
        if self.socket:
            self.socket.close()
        if self.context:
            self.context.term()

        print(f"✅ {self.socket_type}:{self.port} terminado")
        if "PRODUCER" in self.socket_type:
            print(f"   📊 Total enviado: {self.stats['messages_sent']} mensajes")
        else:
            print(f"   📊 Total procesado: {self.stats['messages_received']} mensajes")


class GenericZMQPerformanceTuner:
    """Tuner de performance genérico para cualquier componente + SCHEDULER FIREWALL"""

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

        # 🔥 NUEVO: Actualizar network específico para scheduler
        if self.analyzer.is_scheduler_firewall and "network_updates" in optimizations:
            network_updates = optimizations["network_updates"]
            print(f"\n🔥 Aplicando optimizaciones específicas SCHEDULER FIREWALL:")
            for socket_name, updates in network_updates.items():
                if socket_name in config.get("network", {}):
                    for key, new_value in updates.items():
                        old_value = config["network"][socket_name].get(key, "not set")
                        config["network"][socket_name][key] = new_value
                        print(f"   {socket_name}.{key}: {old_value} → {new_value}")

        # Actualizar sección processing
        if "processing" not in config:
            config["processing"] = {}

        processing_opts = optimizations.get("processing", {})
        print(f"\n⚙️ Aplicando optimizaciones de procesamiento:")
        for key, new_value in processing_opts.items():
            if isinstance(new_value, dict) and key in config["processing"]:
                # Merge nested dictionaries
                for subkey, subvalue in new_value.items():
                    if isinstance(config["processing"][key], dict):
                        old_value = config["processing"][key].get(subkey, "not set")
                        config["processing"][key][subkey] = subvalue
                        print(f"   {key}.{subkey}: {old_value} → {subvalue}")
                    else:
                        config["processing"][key] = new_value
                        print(f"   {key}: new section → {new_value}")
            else:
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
        print("⚠️ No se encontraron sockets para crear consumers/producers")
        return []

    consumers = []
    for port, socket_type, description in consumer_configs:
        if port:
            consumer = GenericZMQConsumer(port, socket_type, description)
            consumers.append(consumer)

    return consumers


def run_consumers(consumers: List[GenericZMQConsumer]):
    """Ejecutar múltiples consumers/producers en threads separados"""
    if not consumers:
        print("❌ No hay consumers para ejecutar")
        return

    threads = []

    print(f"\n🚀 Iniciando {len(consumers)} consumer(s)/producer(s)...")

    for consumer in consumers:
        thread = threading.Thread(
            target=consumer.consume_messages,
            name=f"{'Producer' if 'PRODUCER' in consumer.socket_type else 'Consumer'}-{consumer.socket_type}-{consumer.port}",
            daemon=True
        )
        thread.start()
        threads.append(thread)

    print(f"✅ {len(consumers)} consumer(s)/producer(s) ejecutándose")

    # Detectar si hay scheduler firewall
    has_scheduler = any("🔥" in consumer.description or "🛡️" in consumer.description for consumer in consumers)

    if has_scheduler:
        print("\n💡 SCHEDULER FIREWALL TESTING:")
        print("   🔥 Producer simula: firewall responses")
        print("   🛡️ Consumer drena: firewall commands del scheduler")
        print("   🧠 Monitor observa: eventos ML del ml_detector")
        print("   📊 Ejecuta scheduler en otra terminal para ver flujo completo")
    else:
        print("\n💡 Consejos mientras consumes:")
        print("   • Ejecuta tu componente en otra terminal")
        print("   • Observa las estadísticas de rate y throughput")

    print("   • Ctrl+C para parar todos los consumers/producers")

    try:
        # Esperar a todos los threads
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\n🛑 Parando todos los consumers/producers...")
        for consumer in consumers:
            consumer.running = False


def main():
    """Función principal genérica + SCHEDULER FIREWALL"""
    if len(sys.argv) < 2:
        print("❌ Uso: python zmq_performance_optimizer_v31_generic_scheduler.py <config.json> [action]")
        print("\n📋 Actions disponibles:")
        print("   optimize  - Optimizar configuración ZMQ (default)")
        print("   consume   - Crear consumers/producers para testing")
        print("   analyze   - Solo analizar configuración sin cambios")
        print("   advice    - Mostrar consejos específicos del componente")
        print("\n💡 Ejemplos:")
        print("   # Optimizar scheduler_firewall con ETCD")
        print("   python script.py scheduler_firewall_etcd_config_dev.json optimize")
        print("   # Testing completo del scheduler (producers + consumer)")
        print("   python script.py scheduler_firewall_etcd_config_dev.json consume")
        print("   # Optimizar ml_detector")
        print("   python script.py ml_detector_config.json optimize")
        print("   # Drenar mensajes del ml_detector mientras migras dashboard")
        print("   python script.py ml_detector_config.json consume")
        sys.exit(1)

    config_file = sys.argv[1]
    action = sys.argv[2] if len(sys.argv) > 2 else "optimize"

    if not Path(config_file).exists():
        print(f"❌ Config file not found: {config_file}")
        sys.exit(1)

    print("🚀 ZMQ PERFORMANCE OPTIMIZER v3.1 GENERIC + SCHEDULER FIREWALL - TOPOLOGY FIXED")
    print("=" * 70)
    print(f"📁 Config: {config_file}")
    print(f"🎯 Action: {action}")
    print("=" * 70)

    try:
        if action == "consume":
            print("🔧 Creando consumers/producers para testing...")
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
            print(f"   2. Testing completo: python {sys.argv[0]} {config_file} consume")
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