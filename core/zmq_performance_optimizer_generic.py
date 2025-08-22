#!/usr/bin/env python3
"""
🚀 ZMQ PERFORMANCE OPTIMIZER v3.1 GENERIC COMPLETO - TODO O NADA + ETCD CRYPTO
zmq_performance_optimizer_v31_generic_complete.py

Script GENÉRICO COMPLETO para optimizar configuración ZMQ de CUALQUIER componente del pipeline
+ SOPORTE COMPLETO para scheduler_firewall, simple_firewall_agent_v31_etcd, sniffer, geoip_enricher
+ 🔧 FIX CRÍTICO: Topología detectada 100% desde JSON - SIN HARDCODES
+ 🔥 NUEVO: Soporte DUAL COMMUNICATION para simple_firewall_agent_v31_etcd
+ 🔧 RESUELTO: Conflictos de puertos 5571 y 5560 con cleanup automático
+ 📋 FILOSOFÍA: TODO O NADA - Si no está en JSON y es crítico, se avisa y se cierra

- Detecta automáticamente tipo de componente desde JSON
- Crea consumers/producers según topología real
- Resuelve conflictos de puertos automáticamente
- Soporte completo ETCD crypto
- Sin fallbacks, sin hardcodes, control total desde JSON

Autor: Alonso Isidoro, Claude
Fecha: Agosto 22, 2025
Versión: 3.1.0-generic-complete-todo-o-nada
"""

import zmq
import json
import time
import threading
import sys
import os
import subprocess
import signal
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path


class ComponentJSONAnalyzer:
    """Analizador COMPLETO de componentes desde JSON - TODO O NADA"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = {}
        self.component_type = "unknown"
        self.component_info = {}
        self.network_config = {}
        self.zmq_config = {}
        self.etcd_crypto_enabled = False
        self.load_and_analyze_config()

    def load_and_analyze_config(self):
        """Cargar y analizar configuración del componente - CRÍTICO: TODO desde JSON"""
        print(f"📋 Analizando configuración: {self.config_file}")

        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)

            # Extraer información del componente - OBLIGATORIO en JSON
            self.component_info = self.config.get("component", {})
            if not self.component_info:
                raise RuntimeError("❌ CRITICAL: 'component' section missing in JSON - TODO O NADA philosophy")

            self.network_config = self.config.get("network", {})
            if not self.network_config:
                print("⚠️  WARNING: 'network' section missing - limited functionality")

            self.zmq_config = self.config.get("zmq", {})

            # 🔥 DETECCIÓN AUTOMÁTICA DE TIPO DE COMPONENTE desde JSON
            self.component_type = self._detect_component_type()

            # Info básica extraída del JSON
            component_name = self.component_info.get("name", "unknown")
            component_version = self.component_info.get("version", "unknown")
            component_mode = self.component_info.get("mode", "unknown")
            node_id = self.config.get("node_id", "unknown")

            # 🔐 DETECCIÓN ETCD CRYPTO desde JSON
            crypto_config = self.config.get("crypto", {})
            etcd_crypto_config = self.config.get("etcd_crypto", {})
            self.etcd_crypto_enabled = (
                    crypto_config.get("enabled", False) and
                    crypto_config.get("use_etcd_pipeline_key", False) and
                    bool(etcd_crypto_config)
            )

            print(f"✅ Componente detectado desde JSON:")
            print(f"   📛 Nombre: {component_name}")
            print(f"   🔢 Versión: {component_version}")
            print(f"   🎯 Tipo detectado: {self.component_type}")
            print(f"   🎭 Modo: {component_mode}")
            print(f"   🆔 Node ID: {node_id}")
            print(f"   🔐 ETCD crypto: {'✅ ENABLED' if self.etcd_crypto_enabled else '❌ DISABLED'}")

            # Analizar configuración de red específica
            self.analyze_network_topology()

        except FileNotFoundError:
            raise RuntimeError(f"❌ CRITICAL: Config file not found: {self.config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ CRITICAL: Invalid JSON: {e}")

    def _detect_component_type(self) -> str:
        """🔥 DETECCIÓN AUTOMÁTICA DE TIPO DE COMPONENTE - 100% desde JSON"""
        component_name = self.component_info.get("name", "").lower()
        component_role = self.component_info.get("role", "").lower()
        component_description = self.component_info.get("description", "").lower()

        # 🔥 SIMPLE FIREWALL AGENT V3.1 ETCD con DUAL COMMUNICATION
        if "simple_firewall_agent" in component_name and "etcd" in component_name:
            # Verificar DUAL COMMUNICATION en network
            if self._has_dual_communication_pattern():
                return "simple_firewall_agent_v31_etcd"

        # 🔥 SCHEDULER FIREWALL con ETCD
        if "scheduler" in component_name and "firewall" in component_name:
            if self._has_scheduler_firewall_pattern():
                return "scheduler_firewall_etcd"

        # 🔥 EVOLUTIONARY SNIFFER V3.1 ETCD
        if "evolutionary_sniffer" in component_name:
            if self._has_sniffer_pattern():
                return "evolutionary_sniffer_v31_etcd"

        # 🔥 GEOIP ENRICHER V3.1 ETCD
        if "geoip_enricher" in component_name:
            if self._has_geoip_enricher_pattern():
                return "geoip_enricher_v31_etcd"

        # 🔥 ML DETECTOR TRICAPA V3.1 ETCD
        if "ml_detector" in component_name or "lightweight_ml_detector" in component_name:
            return "ml_detector_tricapa_v31_etcd"

        # 🔥 DASHBOARD
        if "dashboard" in component_name:
            return "dashboard_v31"

        print(f"⚠️  WARNING: Component type not recognized from JSON - using 'generic'")
        return "generic"

    def _has_dual_communication_pattern(self) -> bool:
        """Detectar patrón DUAL COMMUNICATION del simple_firewall_agent_v31_etcd"""
        if not self.network_config:
            return False

        # Verificar los 4 sockets específicos del DUAL COMMUNICATION
        scheduler_commands = self.network_config.get("scheduler_commands")
        scheduler_responses = self.network_config.get("scheduler_responses")
        dashboard_commands = self.network_config.get("dashboard_commands")
        dashboard_responses = self.network_config.get("dashboard_responses")

        return all([scheduler_commands, scheduler_responses, dashboard_commands, dashboard_responses])

    def _has_scheduler_firewall_pattern(self) -> bool:
        """Detectar patrón del scheduler firewall (3 sockets específicos)"""
        if not self.network_config:
            return False

        ml_events_input = self.network_config.get("ml_events_input")
        firewall_commands_output = self.network_config.get("firewall_commands_output")
        firewall_responses_input = self.network_config.get("firewall_responses_input")

        return all([ml_events_input, firewall_commands_output, firewall_responses_input])

    def _has_sniffer_pattern(self) -> bool:
        """Detectar patrón del evolutionary sniffer (output socket PUSH)"""
        if not self.network_config:
            return False

        output_socket = self.network_config.get("output_socket")
        if output_socket:
            return output_socket.get("socket_type") == "PUSH"

        return False

    def _has_geoip_enricher_pattern(self) -> bool:
        """Detectar patrón del geoip enricher (input PULL + output PUSH)"""
        if not self.network_config:
            return False

        input_socket = self.network_config.get("input_socket")
        output_socket = self.network_config.get("output_socket")

        if input_socket and output_socket:
            input_is_pull = input_socket.get("socket_type") == "PULL"
            output_is_push = output_socket.get("socket_type") == "PUSH"
            return input_is_pull and output_is_push

        return False

    def analyze_network_topology(self):
        """Analizar topología de red específica del componente detectado"""
        if not self.network_config:
            print("⚠️  No network config found")
            return

        print(f"\n🔌 Topología de red analizada para {self.component_type}:")

        if self.component_type == "simple_firewall_agent_v31_etcd":
            self._analyze_dual_communication_topology()
        elif self.component_type == "scheduler_firewall_etcd":
            self._analyze_scheduler_firewall_topology()
        elif self.component_type == "evolutionary_sniffer_v31_etcd":
            self._analyze_sniffer_topology()
        elif self.component_type == "geoip_enricher_v31_etcd":
            self._analyze_geoip_enricher_topology()
        else:
            self._analyze_generic_topology()

    def _analyze_dual_communication_topology(self):
        """Analizar topología DUAL COMMUNICATION del simple_firewall_agent_v31_etcd"""
        print(f"   🔥 DUAL COMMUNICATION PATTERN DETECTED:")

        # Scheduler communication (PUSH/PULL pattern)
        scheduler_commands = self.network_config.get("scheduler_commands", {})
        if scheduler_commands:
            addr = scheduler_commands.get("address", "localhost")
            port = scheduler_commands.get("port", "unknown")
            socket_type = scheduler_commands.get("socket_type", "unknown")
            mode = scheduler_commands.get("mode", "unknown")
            print(f"   📥 Scheduler Commands: {addr}:{port} ({socket_type}, {mode})")

        scheduler_responses = self.network_config.get("scheduler_responses", {})
        if scheduler_responses:
            addr = scheduler_responses.get("address", "localhost")
            port = scheduler_responses.get("port", "unknown")
            socket_type = scheduler_responses.get("socket_type", "unknown")
            mode = scheduler_responses.get("mode", "unknown")
            print(f"   📤 Scheduler Responses: {addr}:{port} ({socket_type}, {mode})")

        # Dashboard communication (PUB/SUB pattern)
        dashboard_commands = self.network_config.get("dashboard_commands", {})
        if dashboard_commands:
            addr = dashboard_commands.get("address", "localhost")
            port = dashboard_commands.get("port", "unknown")
            socket_type = dashboard_commands.get("socket_type", "unknown")
            mode = dashboard_commands.get("mode", "unknown")
            print(f"   📥 Dashboard Commands: {addr}:{port} ({socket_type}, {mode})")

        dashboard_responses = self.network_config.get("dashboard_responses", {})
        if dashboard_responses:
            addr = dashboard_responses.get("address", "localhost")
            port = dashboard_responses.get("port", "unknown")
            socket_type = dashboard_responses.get("socket_type", "unknown")
            mode = dashboard_responses.get("mode", "unknown")
            print(f"   📤 Dashboard Responses: {addr}:{port} ({socket_type}, {mode})")

        if self.etcd_crypto_enabled:
            print(f"   🔐 ETCD CRYPTO: ✅ ENABLED en todos los 4 canales DUAL")

    def _analyze_scheduler_firewall_topology(self):
        """Analizar topología del scheduler firewall"""
        print(f"   🔥 SCHEDULER FIREWALL PATTERN:")

        ml_events = self.network_config.get("ml_events_input", {})
        if ml_events:
            addr = ml_events.get("address", "localhost")
            port = ml_events.get("port", "unknown")
            socket_type = ml_events.get("socket_type", "unknown")
            mode = ml_events.get("mode", "unknown")
            print(f"   📥 ML Events Input: {addr}:{port} ({socket_type}, {mode})")

        fw_commands = self.network_config.get("firewall_commands_output", {})
        if fw_commands:
            addr = fw_commands.get("address", "localhost")
            port = fw_commands.get("port", "unknown")
            socket_type = fw_commands.get("socket_type", "unknown")
            mode = fw_commands.get("mode", "unknown")
            print(f"   📤 Firewall Commands: {addr}:{port} ({socket_type}, {mode})")

        fw_responses = self.network_config.get("firewall_responses_input", {})
        if fw_responses:
            addr = fw_responses.get("address", "localhost")
            port = fw_responses.get("port", "unknown")
            socket_type = fw_responses.get("socket_type", "unknown")
            mode = fw_responses.get("mode", "unknown")
            print(f"   📥 Firewall Responses: {addr}:{port} ({socket_type}, {mode})")

    def _analyze_sniffer_topology(self):
        """Analizar topología del evolutionary sniffer"""
        print(f"   🔬 SNIFFER PATTERN:")

        output_socket = self.network_config.get("output_socket", {})
        if output_socket:
            addr = output_socket.get("address", "localhost")
            port = output_socket.get("port", "unknown")
            socket_type = output_socket.get("socket_type", "unknown")
            mode = output_socket.get("mode", "unknown")
            print(f"   📤 Output: {addr}:{port} ({socket_type}, {mode})")
            print(f"       🎯 Envía eventos NetworkSecurityEvent v3.1 hacia geoip_enricher")

    def _analyze_geoip_enricher_topology(self):
        """Analizar topología del geoip enricher"""
        print(f"   🌍 GEOIP ENRICHER PATTERN:")

        input_socket = self.network_config.get("input_socket", {})
        if input_socket:
            addr = input_socket.get("address", "localhost")
            port = input_socket.get("port", "unknown")
            socket_type = input_socket.get("socket_type", "unknown")
            mode = input_socket.get("mode", "unknown")
            print(f"   📥 Input: {addr}:{port} ({socket_type}, {mode})")
            print(f"       🎯 Recibe del evolutionary_sniffer")

        output_socket = self.network_config.get("output_socket", {})
        if output_socket:
            addr = output_socket.get("address", "localhost")
            port = output_socket.get("port", "unknown")
            socket_type = output_socket.get("socket_type", "unknown")
            mode = output_socket.get("mode", "unknown")
            print(f"   📤 Output: {addr}:{port} ({socket_type}, {mode})")
            print(f"       🎯 Envía hacia ml_detector")

    def _analyze_generic_topology(self):
        """Analizar topología genérica"""
        print(f"   📊 GENERIC PATTERN:")

        for socket_name, socket_config in self.network_config.items():
            if isinstance(socket_config, dict):
                addr = socket_config.get("address", "localhost")
                port = socket_config.get("port", "unknown")
                socket_type = socket_config.get("socket_type", "unknown")
                mode = socket_config.get("mode", "unknown")
                print(f"   🔌 {socket_name}: {addr}:{port} ({socket_type}, {mode})")

    def get_consumer_producer_config(self) -> List[Tuple[int, str, str, str]]:
        """
        🔧 CONFIGURACIÓN CORREGIDA para crear consumers/producers apropiados
        Returns: Lista de (puerto, tipo_socket, modo, descripción)
        """
        configs = []

        if self.component_type == "simple_firewall_agent_v31_etcd":
            configs.extend(self._get_dual_communication_config())
        elif self.component_type == "scheduler_firewall_etcd":
            configs.extend(self._get_scheduler_firewall_config())
        elif self.component_type == "evolutionary_sniffer_v31_etcd":
            configs.extend(self._get_sniffer_config())
        elif self.component_type == "geoip_enricher_v31_etcd":
            configs.extend(self._get_geoip_enricher_config())
        else:
            configs.extend(self._get_generic_config())

        return configs

    def _get_dual_communication_config(self) -> List[Tuple[int, str, str, str]]:
        """Configuración para simple_firewall_agent_v31_etcd DUAL COMMUNICATION"""
        configs = []

        # 1. Producer para scheduler commands (simular scheduler enviando comandos)
        scheduler_commands = self.network_config.get("scheduler_commands", {})
        if scheduler_commands:
            port = scheduler_commands.get("port")
            if port:
                configs.append((port, "PUSH_PRODUCER", "connect",
                                f"🔥 Producing firewall commands TO agent (port {port})"))

        # 2. Consumer para scheduler responses (drenar respuestas del agent)
        scheduler_responses = self.network_config.get("scheduler_responses", {})
        if scheduler_responses:
            port = scheduler_responses.get("port")
            if port:
                configs.append((port, "PULL", "bind",
                                f"🔄 Draining firewall responses FROM agent (port {port})"))

        # 3. Producer para dashboard commands (simular dashboard enviando comandos)
        dashboard_commands = self.network_config.get("dashboard_commands", {})
        if dashboard_commands:
            port = dashboard_commands.get("port")
            if port:
                configs.append((port, "PUB_PRODUCER", "bind",
                                f"📊 Publishing dashboard commands TO agent (port {port})"))

        # 4. Consumer para dashboard responses (drenar respuestas del agent)
        dashboard_responses = self.network_config.get("dashboard_responses", {})
        if dashboard_responses:
            port = dashboard_responses.get("port")
            if port:
                configs.append((port, "SUB", "connect",
                                f"📈 Subscribing dashboard responses FROM agent (port {port})"))

        return configs

    def _get_scheduler_firewall_config(self) -> List[Tuple[int, str, str, str]]:
        """🔧 CONFIGURACIÓN CORREGIDA para scheduler_firewall_etcd - LÓGICA OPUESTA"""
        configs = []

        # 1. ML Events Input (puerto 5580)
        # Scheduler: SUB CONNECT → Consumer: PUB BIND (para que scheduler se conecte)
        ml_events = self.network_config.get("ml_events_input", {})
        if ml_events:
            port = ml_events.get("port")
            scheduler_mode = ml_events.get("mode", "connect")

            if port:
                # LÓGICA CORREGIDA: Hacemos lo OPUESTO al scheduler
                if scheduler_mode == "connect":
                    our_mode = "bind"  # Scheduler se conecta, nosotros hacemos bind
                else:
                    our_mode = "connect"  # Scheduler hace bind, nosotros nos conectamos

                configs.append((port, "PUB_PRODUCER", our_mode,
                                f"🧠 ML Simulator - PUB {our_mode.upper()} to scheduler SUB {scheduler_mode.upper()} (port {port})"))

        # 2. Firewall Commands Output (puerto 5582)
        # Scheduler: PUSH CONNECT → Consumer: PULL BIND (para que scheduler se conecte)
        fw_commands = self.network_config.get("firewall_commands_output", {})
        if fw_commands:
            port = fw_commands.get("port")
            scheduler_mode = fw_commands.get("mode", "connect")

            if port:
                # LÓGICA CORREGIDA: Hacemos lo OPUESTO al scheduler
                if scheduler_mode == "connect":
                    our_mode = "bind"  # Scheduler se conecta, nosotros hacemos bind
                else:
                    our_mode = "connect"  # Scheduler hace bind, nosotros nos conectamos

                configs.append((port, "PULL", our_mode,
                                f"🛡️ Firewall Simulator - PULL {our_mode.upper()} from scheduler PUSH {scheduler_mode.upper()} (port {port})"))

        # 3. Firewall Responses Input (puerto 5581)
        # Scheduler: PULL BIND → Consumer: PUSH CONNECT (para conectarnos al scheduler)
        fw_responses = self.network_config.get("firewall_responses_input", {})
        if fw_responses:
            port = fw_responses.get("port")
            scheduler_mode = fw_responses.get("mode", "bind")

            if port:
                # LÓGICA CORREGIDA: Hacemos lo OPUESTO al scheduler
                if scheduler_mode == "bind":
                    our_mode = "connect"  # Scheduler hace bind, nosotros nos conectamos
                else:
                    our_mode = "bind"  # Scheduler se conecta, nosotros hacemos bind

                configs.append((port, "PUSH_PRODUCER", our_mode,
                                f"🔄 Response Simulator - PUSH {our_mode.upper()} to scheduler PULL {scheduler_mode.upper()} (port {port})"))

        return configs

    def _get_sniffer_config(self) -> List[Tuple[int, str, str, str]]:
        """Configuración para evolutionary_sniffer_v31_etcd"""
        configs = []

        # Consumer para output del sniffer (drenar eventos que envía)
        output_socket = self.network_config.get("output_socket", {})
        if output_socket:
            port = output_socket.get("port")
            mode = output_socket.get("mode", "bind")
            if port:
                # El sniffer hace PUSH en modo BIND, nosotros hacemos PULL en modo CONNECT
                opposite_mode = "connect" if mode == "bind" else "bind"
                configs.append((port, "PULL", opposite_mode,
                                f"🔬 Draining sniffer events FROM port {port}"))

        return configs

    def _get_geoip_enricher_config(self) -> List[Tuple[int, str, str, str]]:
        """Configuración para geoip_enricher_v31_etcd"""
        configs = []

        # Producer para input del enricher (simular sniffer enviando eventos)
        input_socket = self.network_config.get("input_socket", {})
        if input_socket:
            port = input_socket.get("port")
            mode = input_socket.get("mode", "connect")
            if port:
                # El enricher hace PULL en modo CONNECT, nosotros hacemos PUSH en modo BIND
                opposite_mode = "bind" if mode == "connect" else "connect"
                configs.append((port, "PUSH_PRODUCER", opposite_mode,
                                f"🌍 Producing events TO geoip enricher (port {port})"))

        # Consumer para output del enricher (drenar eventos enriquecidos)
        output_socket = self.network_config.get("output_socket", {})
        if output_socket:
            port = output_socket.get("port")
            mode = output_socket.get("mode", "bind")
            if port:
                # El enricher hace PUSH en modo BIND, nosotros hacemos PULL en modo CONNECT
                opposite_mode = "connect" if mode == "bind" else "bind"
                configs.append((port, "PULL", opposite_mode,
                                f"🌍 Draining enriched events FROM geoip enricher (port {port})"))

        return configs

    def _get_generic_config(self) -> List[Tuple[int, str, str, str]]:
        """Configuración genérica para componentes no reconocidos"""
        configs = []

        for socket_name, socket_config in self.network_config.items():
            if isinstance(socket_config, dict):
                port = socket_config.get("port")
                socket_type = socket_config.get("socket_type", "").upper()
                mode = socket_config.get("mode", "connect")

                if port and socket_type:
                    # Crear consumer/producer apropiado según el tipo
                    if socket_type == "PUSH":
                        opposite_mode = "connect" if mode == "bind" else "bind"
                        configs.append((port, "PULL", opposite_mode,
                                        f"📊 Draining {socket_type} messages from {socket_name} (port {port})"))
                    elif socket_type == "PUB":
                        opposite_mode = "connect" if mode == "bind" else "bind"
                        configs.append((port, "SUB", opposite_mode,
                                        f"📊 Subscribing {socket_type} messages from {socket_name} (port {port})"))
                    elif socket_type in ["PULL", "SUB"]:
                        # Para estos, crear producer
                        producer_type = "PUSH_PRODUCER" if socket_type == "PULL" else "PUB_PRODUCER"
                        opposite_mode = "bind" if mode == "connect" else "connect"
                        configs.append((port, producer_type, opposite_mode,
                                        f"📊 Producing to {socket_type} {socket_name} (port {port})"))

        return configs


class PortConflictResolver:
    """🔧 Resolvedor de conflictos de puertos - TODO O NADA"""

    @staticmethod
    def check_port_usage(port: int) -> List[Dict]:
        """Verificar qué procesos están usando un puerto"""
        processes = []

        try:
            # Usar lsof para encontrar procesos
            result = subprocess.run(['lsof', '-i', f':{port}'],
                                    capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        processes.append({
                            'pid': parts[1],
                            'process': parts[0],
                            'user': parts[2] if len(parts) > 2 else 'unknown'
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fallback con netstat
            try:
                result = subprocess.run(['netstat', '-tulpn'],
                                        capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if f':{port}' in line:
                            # Parsear netstat output aproximadamente
                            processes.append({
                                'pid': 'unknown',
                                'process': 'unknown',
                                'user': 'unknown',
                                'line': line.strip()
                            })
            except:
                pass

        return processes

    @staticmethod
    def kill_processes_on_port(port: int, force: bool = False) -> bool:
        """Matar procesos en un puerto específico"""
        processes = PortConflictResolver.check_port_usage(port)

        if not processes:
            print(f"✅ Puerto {port} está libre")
            return True

        print(f"⚠️  Puerto {port} está ocupado por {len(processes)} proceso(s):")
        for proc in processes:
            if 'line' in proc:
                print(f"   📝 {proc['line']}")
            else:
                print(f"   🔍 PID: {proc['pid']}, Process: {proc['process']}, User: {proc['user']}")

        if force:
            killed = []
            for proc in processes:
                if proc['pid'] != 'unknown':
                    try:
                        pid = int(proc['pid'])
                        print(f"🔪 Killing process {proc['process']} (PID: {pid})")
                        os.kill(pid, signal.SIGTERM)
                        time.sleep(1)

                        # Verificar si aún existe
                        try:
                            os.kill(pid, 0)  # Signal 0 solo verifica existencia
                            print(f"💥 Force killing PID {pid}")
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass

                        killed.append(pid)
                    except (ValueError, ProcessLookupError, PermissionError) as e:
                        print(f"❌ Error killing PID {proc['pid']}: {e}")

            if killed:
                print(f"✅ Killed {len(killed)} process(es)")
                time.sleep(2)  # Dar tiempo para cleanup

                # Verificar que el puerto esté libre
                remaining = PortConflictResolver.check_port_usage(port)
                if not remaining:
                    print(f"✅ Puerto {port} ahora está libre")
                    return True
                else:
                    print(f"⚠️  Aún hay {len(remaining)} proceso(s) en puerto {port}")
                    return False

        return False

    @staticmethod
    def resolve_port_conflicts(ports: List[int], auto_kill: bool = False) -> Dict[int, bool]:
        """Resolver conflictos en múltiples puertos"""
        results = {}

        for port in ports:
            print(f"\n🔍 Verificando puerto {port}...")

            processes = PortConflictResolver.check_port_usage(port)
            if not processes:
                print(f"✅ Puerto {port} está libre")
                results[port] = True
                continue

            if auto_kill:
                success = PortConflictResolver.kill_processes_on_port(port, force=True)
                results[port] = success
            else:
                print(f"⚠️  Puerto {port} ocupado. Use --auto-kill para liberar automáticamente")
                results[port] = False

        return results


class GenericZMQConsumerProducer:
    """🔧 Consumer/Producer ZMQ genérico CORREGIDO - TODO O NADA"""

    def __init__(self, port: int, socket_type: str, mode: str, description: str):
        self.port = port
        self.socket_type = socket_type.upper()
        self.mode = mode.lower()
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
            'errors': 0
        }

    def setup_socket(self):
        """🔧 CONFIGURACIÓN CORREGIDA - Debug mejorado"""
        self.context = zmq.Context()

        print(f"🔍 Setting up {self.socket_type} socket on port {self.port} with mode {self.mode}")

        if self.socket_type == "PULL":
            self.socket = self.context.socket(zmq.PULL)
            if self.mode == "bind":
                self.socket.bind(f"tcp://*:{self.port}")
                print(f"✅ PULL consumer BIND en puerto {self.port}")
            else:
                self.socket.connect(f"tcp://localhost:{self.port}")
                print(f"✅ PULL consumer CONNECT a puerto {self.port}")

        elif self.socket_type == "SUB":
            self.socket = self.context.socket(zmq.SUB)
            if self.mode == "bind":
                self.socket.bind(f"tcp://*:{self.port}")
                print(f"✅ SUB consumer BIND en puerto {self.port}")
            else:
                self.socket.connect(f"tcp://localhost:{self.port}")
                print(f"✅ SUB consumer CONNECT a puerto {self.port}")
            self.socket.setsockopt(zmq.SUBSCRIBE, b"")  # Subscribe to all

        elif self.socket_type == "PUSH_PRODUCER":
            self.socket = self.context.socket(zmq.PUSH)
            if self.mode == "bind":
                self.socket.bind(f"tcp://*:{self.port}")
                print(f"✅ PUSH producer BIND en puerto {self.port}")
            else:
                self.socket.connect(f"tcp://localhost:{self.port}")
                print(f"✅ PUSH producer CONNECT a puerto {self.port}")

        elif self.socket_type == "PUB_PRODUCER":
            self.socket = self.context.socket(zmq.PUB)
            if self.mode == "bind":
                self.socket.bind(f"tcp://*:{self.port}")
                print(f"✅ PUB producer BIND en puerto {self.port}")
            else:
                self.socket.connect(f"tcp://localhost:{self.port}")
                print(f"✅ PUB producer CONNECT a puerto {self.port}")

        else:
            raise ValueError(f"❌ Unsupported socket type: {self.socket_type}")

        # Configuración común optimizada
        if "PRODUCER" in self.socket_type:
            self.socket.setsockopt(zmq.SNDHWM, 1000)
            self.socket.setsockopt(zmq.SNDTIMEO, 1000)
        else:
            self.socket.setsockopt(zmq.RCVHWM, 1000)
            self.socket.setsockopt(zmq.RCVTIMEO, 1000)

        self.socket.setsockopt(zmq.LINGER, 0)  # CRÍTICO para evitar conflictos

        print(f"✅ {self.socket_type} configurado correctamente")

    def run(self):
        """Ejecutar consumer o producer"""
        print(f"📥 {self.description}")
        print(
            f"🚀 {'Producer' if 'PRODUCER' in self.socket_type else 'Consumer'} iniciado: {self.socket_type} en puerto {self.port}")

        self.setup_socket()
        self.running = True

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
        """Ejecutar como consumer"""
        last_stats_time = time.time()

        while self.running:
            try:
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
                time.sleep(0.01)
            except Exception as e:
                self.stats['errors'] += 1
                if self.stats['errors'] % 10 == 0:
                    print(f"❌ Consumer error #{self.stats['errors']}: {e}")
                time.sleep(0.1)

    def _run_producer(self):
        """Ejecutar como producer"""
        last_stats_time = time.time()
        message_count = 0

        # Wait para PUB sockets
        if self.socket_type == "PUB_PRODUCER":
            time.sleep(1)  # Dar tiempo para que subscribers se conecten

        while self.running:
            try:
                # Generar mensaje de prueba según el tipo y componente
                test_message = self._generate_test_message(message_count)
                message_bytes = json.dumps(test_message).encode('utf-8')

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

                # Rate limiting
                time.sleep(0.1)  # 10 msg/s

            except zmq.Again:
                time.sleep(0.01)
            except Exception as e:
                self.stats['errors'] += 1
                if self.stats['errors'] % 10 == 0:
                    print(f"❌ Producer error #{self.stats['errors']}: {e}")
                time.sleep(0.1)

    def _generate_test_message(self, count: int) -> Dict:
        """Generar mensaje de prueba apropiado"""
        base_message = {
            "message_id": f"test_msg_{count}",
            "timestamp": int(time.time() * 1000),
            "node_id": f"test_producer_{self.port}",
            "count": count
        }

        # Personalizar según puerto/tipo
        if self.port == 5582:  # Scheduler commands
            base_message.update({
                "command_type": "BLOCK_IP",
                "target_ip": f"192.168.1.{(count % 254) + 1}",
                "duration": 300,
                "reason": "Test command from optimizer",
                "priority": "MEDIUM"
            })
        elif self.port == 5581:  # Scheduler responses
            base_message.update({
                "command_id": f"cmd_{count}",
                "success": True,
                "message": "Test firewall response",
                "execution_time_ms": 50
            })
        elif self.port == 5580:  # Dashboard commands o ML events
            base_message.update({
                "source": "test_dashboard",
                "event_type": "manual_command",
                "data": {"test": True, "count": count}
            })
        elif self.port == 5584:  # Dashboard responses
            base_message.update({
                "response_type": "status_update",
                "agent_status": "active",
                "rules_count": count % 10
            })
        elif self.port == 5571:  # Sniffer events
            base_message.update({
                "event_type": "network_security_event",
                "source_ip": f"10.0.0.{(count % 254) + 1}",
                "destination_ip": f"10.0.1.{(count % 254) + 1}",
                "risk_score": (count % 100) / 100.0,
                "features": {"flow_duration": count * 0.1}
            })
        elif self.port == 5560:  # Enriched events
            base_message.update({
                "event_type": "enriched_network_event",
                "source_ip": f"10.0.0.{(count % 254) + 1}",
                "geo_enrichment": {
                    "source_geo": {"country": "US", "city": "TestCity"},
                    "enrichment_timestamp": int(time.time() * 1000)
                }
            })

        return base_message

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

                # Verificar flujo reciente
                time_since_last = time.time() - self.stats['last_message_time']
                if self.stats['last_message_time'] > 0 and time_since_last > 30:
                    print(f"   ⚠️ Sin mensajes desde hace {time_since_last:.0f}s")

            print(f"   ❌ Errores: {self.stats['errors']}")

    def cleanup(self):
        """Limpiar recursos"""
        self.running = False
        if self.socket:
            self.socket.setsockopt(zmq.LINGER, 0)  # CRÍTICO
            self.socket.close()
        if self.context:
            self.context.term()

        print(f"✅ {self.socket_type}:{self.port} terminado")
        if "PRODUCER" in self.socket_type:
            print(f"   📊 Total enviado: {self.stats['messages_sent']} mensajes")
        else:
            print(f"   📊 Total procesado: {self.stats['messages_received']} mensajes")


class ComponentOptimizer:
    """Optimizador de configuración específico por componente"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.analyzer = ComponentJSONAnalyzer(config_file)

    def optimize_config(self):
        """Optimizar configuración del componente"""
        print(f"\n🔧 Optimizando configuración de {self.config_file}...")

        # Obtener optimizaciones sugeridas
        optimizations = self._get_optimizations_for_component()

        # Crear backup
        backup_file = f"{self.config_file}.backup.{int(time.time())}"
        with open(backup_file, 'w') as f:
            json.dump(self.analyzer.config, f, indent=2)
        print(f"📝 Backup creado: {backup_file}")

        # Aplicar optimizaciones
        config = self.analyzer.config.copy()

        # Actualizar ZMQ
        if "zmq" not in config:
            config["zmq"] = {}

        zmq_opts = optimizations.get("zmq", {})
        print(f"\n📊 Aplicando optimizaciones ZMQ:")
        for key, new_value in zmq_opts.items():
            old_value = config["zmq"].get(key, "not set")
            config["zmq"][key] = new_value
            print(f"   {key}: {old_value} → {new_value}")

        # Actualizar network específico
        if "network_updates" in optimizations:
            network_updates = optimizations["network_updates"]
            print(f"\n🔌 Aplicando optimizaciones de red:")
            for socket_name, updates in network_updates.items():
                if socket_name in config.get("network", {}):
                    for key, new_value in updates.items():
                        old_value = config["network"][socket_name].get(key, "not set")
                        config["network"][socket_name][key] = new_value
                        print(f"   {socket_name}.{key}: {old_value} → {new_value}")

        # Actualizar processing
        if "processing" not in config:
            config["processing"] = {}

        processing_opts = optimizations.get("processing", {})
        print(f"\n⚙️ Aplicando optimizaciones de procesamiento:")
        for key, new_value in processing_opts.items():
            if isinstance(new_value, dict) and key in config["processing"]:
                if not isinstance(config["processing"][key], dict):
                    config["processing"][key] = {}
                for subkey, subvalue in new_value.items():
                    old_value = config["processing"][key].get(subkey, "not set")
                    config["processing"][key][subkey] = subvalue
                    print(f"   {key}.{subkey}: {old_value} → {subvalue}")
            else:
                old_value = config["processing"].get(key, "not set")
                config["processing"][key] = new_value
                print(f"   {key}: {old_value} → {new_value}")

        # Guardar configuración optimizada
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"\n✅ Configuración optimizada guardada en: {self.config_file}")

    def _get_optimizations_for_component(self) -> Dict[str, Any]:
        """Obtener optimizaciones específicas por tipo de componente"""

        component_type = self.analyzer.component_type
        optimizations = {"zmq": {}, "processing": {}, "network_updates": {}}

        if component_type == "simple_firewall_agent_v31_etcd":
            # ZMQ optimizado para DUAL COMMUNICATION + ETCD crypto
            optimizations["zmq"] = {
                "context_io_threads": 2,  # Para 4 sockets
                "max_sockets": 64,
                "tcp_keepalive": True,
                "tcp_keepalive_idle": 60,
                "immediate": True,
                "linger_ms": 0,  # CRÍTICO para evitar conflictos
                "recv_timeout_ms": 1000,
                "send_timeout_ms": 1000
            }

            # Network optimizado para DUAL COMMUNICATION
            optimizations["network_updates"] = {
                "scheduler_commands": {"high_water_mark": 500},
                "scheduler_responses": {"high_water_mark": 500},
                "dashboard_commands": {"high_water_mark": 500},
                "dashboard_responses": {"high_water_mark": 500}
            }

            # Processing optimizado para DUAL + crypto
            optimizations["processing"] = {
                "threads": {
                    "scheduler_commands_consumer": 1,
                    "dashboard_commands_consumer": 1,
                    "command_processor": 1,
                    "cleanup_thread": 1
                },
                "command_queue_size": 200,
                "max_concurrent_commands": 2
            }

        elif component_type == "scheduler_firewall_etcd":
            # ZMQ optimizado para decision engine + ETCD crypto
            optimizations["zmq"] = {
                "context_io_threads": 2,
                "max_sockets": 32,
                "tcp_keepalive": True,
                "immediate": False,
                "linger_ms": 0,
                "recv_timeout_ms": 100,  # Decisiones rápidas
                "send_timeout_ms": 50,
                "recv_buffer_size": 131072,
                "send_buffer_size": 262144
            }

            # Network optimizado para scheduler
            optimizations["network_updates"] = {
                "ml_events_input": {"high_water_mark": 1000},
                "firewall_commands_output": {"high_water_mark": 500},
                "firewall_responses_input": {"high_water_mark": 300}
            }

            # Processing optimizado para decision engine
            optimizations["processing"] = {
                "threads": {
                    "ml_events_consumers": 2,
                    "firewall_command_producers": 2,
                    "firewall_response_consumers": 1
                },
                "decision_engine": {
                    "max_decisions_per_second": 100,
                    "decision_timeout_ms": 50
                }
            }

        elif component_type == "evolutionary_sniffer_v31_etcd":
            # ZMQ optimizado para captura de paquetes + ETCD crypto
            optimizations["zmq"] = {
                "sndhwm": 10000,
                "linger_ms": 0,
                "send_timeout_ms": 100,
                "io_threads": 2,
                "tcp_keepalive": True,
                "immediate": True,
                "send_buffer_size": 1048576
            }

            # Processing optimizado para sniffer
            optimizations["processing"] = {
                "internal_queue_size": 1000,
                "processing_threads": 3,
                "window_processing_threads": 2,
                "max_packets_per_second": 2000,
                "batch_size": 10
            }

        elif component_type == "geoip_enricher_v31_etcd":
            # ZMQ optimizado para enriquecimiento + ETCD crypto
            optimizations["zmq"] = {
                "rcvhwm": 2000,
                "sndhwm": 2000,
                "recv_timeout_ms": 1000,
                "send_timeout_ms": 100,
                "linger_ms": 0,  # CRÍTICO para evitar conflictos
                "io_threads": 1,
                "tcp_keepalive": True,
                "immediate": True
            }

            # Processing optimizado para geoip
            optimizations["processing"] = {
                "threads": 3,
                "send_threads": 1,
                "internal_queue_size": 1000,
                "protobuf_queue_size": 500,
                "worker_threads": 4,
                "max_events_per_batch": 100
            }

        # ZMQ base común para todos los componentes
        base_zmq = {
            "max_message_size": 1048576,
            "recv_buffer_size": 262144,
            "send_buffer_size": 262144
        }
        optimizations["zmq"].update(base_zmq)

        return optimizations

    def show_advice(self):
        """Mostrar consejos específicos del componente"""
        component_type = self.analyzer.component_type

        print(f"\n💡 CONSEJOS DE PERFORMANCE PARA {component_type.upper()}:")
        print("=" * 70)

        if component_type == "simple_firewall_agent_v31_etcd":
            advice = [
                "🔥 SIMPLE FIREWALL AGENT V3.1 ETCD + DUAL COMMUNICATION:",
                "",
                "🎯 DUAL COMMUNICATION OPTIMIZATION:",
                "   • Monitorear latencia de comandos del scheduler (<100ms)",
                "   • Verificar throughput del dashboard para oversight humano",
                "   • Balancear processing entre scheduler y dashboard threads",
                "   • Configurar rate limiting apropiado para dual sources",
                "",
                "🔐 ETCD CRYPTO PERFORMANCE:",
                "   • Monitorear crypto_operations_per_second en 4 canales",
                "   • Verificar connectivity a ETCD cluster (latency <5ms)",
                "   • Track dual_channel_crypto_health",
                "   • Alert en crypto_failures_per_minute >5",
                "",
                "🛡️ FIREWALL SAFETY + PERFORMANCE:",
                "   • Configurar command_timeout_seconds apropiado",
                "   • Monitorear rule_application_success_rate >98%",
                "   • Verificar dry_run behavior en production",
                "   • Track command_origin (scheduler vs dashboard)",
                "",
                "📊 MONITORING DUAL ESPECÍFICO:",
                "   • Track scheduler_commands_per_minute",
                "   • Track dashboard_commands_per_minute",
                "   • Monitor dual_response_routing_health",
                "   • Alert en max_queue_usage_percent >50%"
            ]

        elif component_type == "scheduler_firewall_etcd":
            advice = [
                "🔥 SCHEDULER FIREWALL ETCD + DECISION ENGINE:",
                "",
                "🎯 DECISION ENGINE OPTIMIZATION:",
                "   • Optimizar decision_timeout_ms (target <50ms)",
                "   • Configurar max_decisions_per_second según CPU",
                "   • Monitorear queue utilization (target <70%)",
                "   • Usar cache_decisions=false para seguridad",
                "",
                "🔐 ETCD CRYPTO INTEGRATION:",
                "   • Pipeline key rotativo mejora seguridad",
                "   • Monitorear crypto_operations en 3 canales",
                "   • Track pipeline_key_usage para anomalías",
                "   • Verificar ETCD connectivity health",
                "",
                "🛡️ FIREWALL PIPELINE INTEGRATION:",
                "   • Configurar fallback behavior para edge cases",
                "   • Monitorear response latency del firewall_agent",
                "   • Track rule_applications_per_minute",
                "   • Balancear rate limits por tipo de amenaza"
            ]

        elif component_type == "evolutionary_sniffer_v31_etcd":
            advice = [
                "🔬 EVOLUTIONARY SNIFFER V3.1 ETCD:",
                "",
                "📡 PACKET CAPTURE OPTIMIZATION:",
                "   • Aumentar capture_buffer_size si hay drops",
                "   • Monitorear interface utilization",
                "   • Configurar kernel bypass si disponible",
                "   • Pin a CPU cores específicos",
                "",
                "🧠 FEATURE EXTRACTION:",
                "   • Optimizar time_windows según modelos ML",
                "   • Cache flow states para performance",
                "   • Ajustar max_flows_in_memory según RAM",
                "   • Monitorear feature_extraction_rate",
                "",
                "🔐 ETCD CRYPTO + OUTPUT:",
                "   • Puerto 5571 debe estar libre (bind mode)",
                "   • Monitorear encrypted_events_per_second",
                "   • Verificar protobuf v3.1 serialization",
                "   • Track pipeline connectivity a geoip_enricher"
            ]

        elif component_type == "geoip_enricher_v31_etcd":
            advice = [
                "🌍 GEOIP ENRICHER V3.1 ETCD + TRIPARTITO:",
                "",
                "🎯 TRIPARTITE ENRICHMENT:",
                "   • Cache sniffer_geo_permanently para performance",
                "   • Optimizar private_ip_resolution strategy",
                "   • Monitorear tripartite_success_rate >75%",
                "   • Track cache_hit_rate para geoip lookups",
                "",
                "🌐 GEOIP LOOKUP OPTIMIZATION:",
                "   • MaxMind como primary, IPAPI como fallback",
                "   • Configurar cache_size según memoria disponible",
                "   • Monitor API rate limits (1000 req/min IPAPI)",
                "   • Verificar database path y updates",
                "",
                "🔐 ETCD CRYPTO + PIPELINE:",
                "   • Puerto 5571 input debe conectar a sniffer",
                "   • Puerto 5560 output debe estar libre (bind mode)",
                "   • Monitorear crypto overhead en enrichment",
                "   • Track enriched_events_per_second hacia ML"
            ]

        else:
            advice = [
                f"📊 GENERIC COMPONENT OPTIMIZATION:",
                "",
                "🔧 ZMQ PERFORMANCE:",
                "   • Ajustar HWM según throughput esperado",
                "   • Configurar timeouts apropiados",
                "   • Usar linger_ms=0 para cleanup rápido",
                "   • Monitorear queue utilization",
                "",
                "🔐 ETCD CRYPTO (si habilitado):",
                "   • Verificar pipeline_key availability",
                "   • Monitorear crypto_operations_per_second",
                "   • Track ETCD connectivity health",
                "   • Alert en crypto failures"
            ]

        for line in advice:
            print(line)


def create_consumers_producers_for_component(config_file: str) -> List[GenericZMQConsumerProducer]:
    """Crear consumers/producers apropiados para un componente"""
    analyzer = ComponentJSONAnalyzer(config_file)
    configs = analyzer.get_consumer_producer_config()

    if not configs:
        print("⚠️ No se encontraron sockets para crear consumers/producers")
        return []

    consumers_producers = []
    for port, socket_type, mode, description in configs:
        if port:
            cp = GenericZMQConsumerProducer(port, socket_type, mode, description)
            consumers_producers.append(cp)

    return consumers_producers


def run_consumers_producers(consumers_producers: List[GenericZMQConsumerProducer]):
    """Ejecutar múltiples consumers/producers en threads separados"""
    if not consumers_producers:
        print("❌ No hay consumers/producers para ejecutar")
        return

    threads = []

    print(f"\n🚀 Iniciando {len(consumers_producers)} consumer(s)/producer(s)...")

    for cp in consumers_producers:
        thread = threading.Thread(
            target=cp.run,
            name=f"{'Producer' if 'PRODUCER' in cp.socket_type else 'Consumer'}-{cp.socket_type}-{cp.port}",
            daemon=True
        )
        thread.start()
        threads.append(thread)

    print(f"✅ {len(consumers_producers)} consumer(s)/producer(s) ejecutándose")

    # Detectar tipo de testing
    has_dual_comm = any("🔥" in cp.description for cp in consumers_producers)
    has_scheduler = any("🛡️" in cp.description for cp in consumers_producers)
    has_sniffer = any("🔬" in cp.description for cp in consumers_producers)
    has_geoip = any("🌍" in cp.description for cp in consumers_producers)

    print(f"\n💡 TESTING SETUP:")
    if has_dual_comm:
        print("   🔥 DUAL COMMUNICATION: Testing simple_firewall_agent_v31_etcd")
        print("   📊 Simulando scheduler + dashboard communication")
    elif has_scheduler:
        print("   🛡️ SCHEDULER FIREWALL: Testing decision engine")
        print("   🧠 Simulando ML events + firewall responses")
    elif has_sniffer:
        print("   🔬 EVOLUTIONARY SNIFFER: Testing packet capture output")
        print("   📡 Drenando eventos NetworkSecurityEvent v3.1")
    elif has_geoip:
        print("   🌍 GEOIP ENRICHER: Testing tripartite enrichment")
        print("   🎯 Simulando sniffer input + drenando ML output")

    print("   • Ejecuta tu componente en otra terminal para ver flujo completo")
    print("   • Observa las estadísticas de rate y throughput")
    print("   • Ctrl+C para parar todos los consumers/producers")

    try:
        # Esperar a todos los threads
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\n🛑 Parando todos los consumers/producers...")
        for cp in consumers_producers:
            cp.running = False


def main():
    """Función principal COMPLETA - TODO O NADA"""
    if len(sys.argv) < 2:
        print("❌ Uso: python zmq_performance_optimizer_v31_generic_complete.py <config.json> [action] [options]")
        print("\n📋 Actions disponibles:")
        print("   optimize     - Optimizar configuración ZMQ (default)")
        print("   consume      - Crear consumers/producers para testing")
        print("   analyze      - Solo analizar configuración sin cambios")
        print("   advice       - Mostrar consejos específicos del componente")
        print("   resolve      - Resolver conflictos de puertos")
        print("\n🔧 Options:")
        print("   --auto-kill  - Matar procesos automáticamente en conflictos")
        print("   --force      - Forzar operaciones sin confirmación")
        print("\n💡 Ejemplos:")
        print("   # Optimizar simple_firewall_agent_v31_etcd")
        print("   python script.py simple_firewall_agent_v31_etcd_config_dev.json optimize")
        print("   # Testing DUAL COMMUNICATION completo")
        print("   python script.py simple_firewall_agent_v31_etcd_config_dev.json consume")
        print("   # Resolver conflictos de puertos automáticamente")
        print("   python script.py evolutionary_sniffer_config_v31_etcd.json resolve --auto-kill")
        print("   # Optimizar scheduler_firewall")
        print("   python script.py scheduler_firewall_etcd_config_dev.json optimize")
        print("   # Testing geoip_enricher")
        print("   python script.py geoip_enricher_config_v31_etcd.json consume")
        sys.exit(1)

    config_file = sys.argv[1]
    action = sys.argv[2] if len(sys.argv) > 2 else "optimize"
    auto_kill = "--auto-kill" in sys.argv
    force = "--force" in sys.argv

    if not Path(config_file).exists():
        print(f"❌ Config file not found: {config_file}")
        sys.exit(1)

    print("🚀 ZMQ PERFORMANCE OPTIMIZER v3.1 GENERIC COMPLETO - TODO O NADA")
    print("=" * 80)
    print(f"📁 Config: {config_file}")
    print(f"🎯 Action: {action}")
    if auto_kill:
        print(f"⚔️ Auto-kill: ENABLED")
    if force:
        print(f"💪 Force: ENABLED")
    print("=" * 80)

    try:
        if action == "resolve":
            print("🔧 Resolviendo conflictos de puertos...")

            # Detectar puertos desde JSON
            analyzer = ComponentJSONAnalyzer(config_file)
            ports_to_check = []

            for port, socket_type, mode, description in analyzer.get_consumer_producer_config():
                if port:
                    ports_to_check.append(port)

            if not ports_to_check:
                print("⚠️ No se encontraron puertos en la configuración")
                return

            print(f"🔍 Verificando puertos: {ports_to_check}")
            results = PortConflictResolver.resolve_port_conflicts(ports_to_check, auto_kill)

            all_clear = all(results.values())
            if all_clear:
                print(f"\n✅ Todos los puertos están libres!")
            else:
                failed_ports = [port for port, success in results.items() if not success]
                print(f"\n❌ Puertos aún con problemas: {failed_ports}")
                if not auto_kill:
                    print("💡 Usa --auto-kill para liberar automáticamente")

        elif action == "consume":
            print("🔧 Creando consumers/producers para testing...")

            # Resolver conflictos de puertos primero si auto_kill está habilitado
            if auto_kill:
                analyzer = ComponentJSONAnalyzer(config_file)
                ports_to_check = [port for port, _, _, _ in analyzer.get_consumer_producer_config() if port]
                if ports_to_check:
                    print("🔍 Resolviendo conflictos de puertos automáticamente...")
                    PortConflictResolver.resolve_port_conflicts(ports_to_check, auto_kill=True)

            consumers_producers = create_consumers_producers_for_component(config_file)
            if consumers_producers:
                run_consumers_producers(consumers_producers)
            else:
                print("❌ No se pudieron crear consumers/producers")

        elif action == "analyze":
            print("🔍 Analizando configuración del componente...")
            analyzer = ComponentJSONAnalyzer(config_file)
            optimizer = ComponentOptimizer(config_file)
            optimizer.show_advice()

        elif action == "advice":
            print("💡 Generando consejos específicos...")
            optimizer = ComponentOptimizer(config_file)
            optimizer.show_advice()

        else:  # optimize (default)
            print("🔧 Optimizando configuración del componente...")
            optimizer = ComponentOptimizer(config_file)
            optimizer.optimize_config()
            optimizer.show_advice()

            print(f"\n🚀 Siguientes pasos:")
            print(f"   1. Revisar cambios en: {config_file}")
            print(f"   2. Resolver conflictos: python {sys.argv[0]} {config_file} resolve --auto-kill")
            print(f"   3. Testing completo: python {sys.argv[0]} {config_file} consume")
            print(f"   4. Ejecutar componente optimizado en otra terminal")
            print(f"   5. Monitorear performance y ajustar según necesidad")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n✅ OPERACIÓN COMPLETADA - TODO O NADA!")


if __name__ == "__main__":
    main()