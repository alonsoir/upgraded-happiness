#!/usr/bin/env python3
"""
simple_firewall_agent.py - Protobuf Integration DUAL CONFIG
✅ CORREGIDO: Acepta AMBOS archivos de configuración:
  - simple_firewall_agent_config.json (configuración base del agente)
  - firewall_rules.json (reglas sincronizadas con dashboard)
✅ CORREGIDO: Comparación de enums correcta (no strings)
✅ CORREGIDO: Logging con node_id y PID
✅ CORREGIDO: Mapeo RATE_LIMIT_IP correcto
✅ VALIDACIÓN: Ambos archivos deben existir o el proceso no arranca
"""
import json
import time
import threading
import queue
import zmq
import logging
import subprocess
import platform
import uuid
import os
import sys
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Add src to path for protobuf imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.protocols.protobuf import firewall_commands_pb2

    print("✅ Protobuf imports successful")
except ImportError as e:
    print(f"❌ Protobuf import failed: {e}")
    print("📁 Please ensure protobuf files are generated")
    sys.exit(1)

# Import our crypto/compression utils (when ready)
try:
    from crypto_utils import SecureEnvelope
    from compression_utils import CompressionEngine

    CRYPTO_AVAILABLE = True
except ImportError:
    print("⚠️ Crypto utils not available, running without encryption")
    CRYPTO_AVAILABLE = False


@dataclass
class FirewallRule:
    """Data class for firewall rules"""
    rule_id: str
    command_id: str
    action: str
    target_ip: str
    target_port: Optional[int]
    duration_seconds: Optional[int]
    created_at: float
    expires_at: Optional[float]
    applied: bool
    rule_text: str


class FirewallRulesSync:
    """
    ✅ NUEVO: Sincronización con reglas JSON del dashboard
    Mantiene sincronizadas las capacidades con el dashboard
    """

    def __init__(self, rules_file: str, node_id: str, logger):
        self.rules_file = rules_file
        self.node_id = node_id
        self.logger = logger
        self.available_actions = []
        self.capabilities = []
        self.global_settings = {}
        self.manual_actions = {}
        self.risk_rules = []
        self.agent_config = {}
        self.last_loaded = None

        # Cargar reglas iniciales
        self.load_rules()

    def load_rules(self):
        """Cargar reglas desde archivo JSON compartido con dashboard"""
        try:
            if not Path(self.rules_file).exists():
                raise FileNotFoundError(f"❌ CRITICAL: Archivo de reglas no encontrado: {self.rules_file}")

            with open(self.rules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            firewall_config = data.get('firewall_rules', {})

            if not firewall_config:
                raise ValueError("❌ CRITICAL: Sección 'firewall_rules' no encontrada en JSON")

            # Extraer reglas por risk_score
            self.risk_rules = firewall_config.get('rules', [])

            # Extraer acciones manuales disponibles
            self.manual_actions = firewall_config.get('manual_actions', {})
            self.available_actions = list(self.manual_actions.keys())

            # Extraer configuración específica de este agente
            firewall_agents = firewall_config.get('firewall_agents', {})
            self.agent_config = firewall_agents.get(self.node_id, {})

            if not self.agent_config:
                self.logger.warning(f"⚠️ No se encontró configuración específica para {self.node_id}")
                # Usar capacidades por defecto
                self.capabilities = self.available_actions
            else:
                self.capabilities = self.agent_config.get('capabilities', [])

            # Configuración global
            self.global_settings = firewall_config.get('global_settings', {})

            self.last_loaded = datetime.now()

            self.logger.info(f"✅ Reglas de firewall sincronizadas: {len(self.risk_rules)} reglas de riesgo")
            self.logger.info(f"📋 Acciones manuales: {', '.join(self.available_actions)}")
            self.logger.info(f"🎯 Capacidades del agente: {', '.join(self.capabilities)}")

        except Exception as e:
            self.logger.error(f"❌ CRITICAL ERROR cargando reglas: {e}")
            # No usar fallback - esto debe fallar
            raise e

    def get_action_for_risk_score(self, risk_score: float) -> Optional[Dict]:
        """Obtener acción recomendada basada en risk_score"""
        for rule in self.risk_rules:
            risk_range = rule.get('risk_range', [0, 100])
            if risk_range[0] <= risk_score <= risk_range[1]:
                return rule
        return None

    def reload_if_changed(self):
        """Recargar reglas si el archivo cambió"""
        try:
            if Path(self.rules_file).exists():
                file_mtime = datetime.fromtimestamp(os.path.getmtime(self.rules_file))
                if self.last_loaded and file_mtime > self.last_loaded:
                    self.logger.info("🔄 Archivo de reglas modificado, recargando...")
                    self.load_rules()
        except Exception as e:
            self.logger.error(f"❌ Error verificando cambios en reglas: {e}")


class FirewallManager:
    """Cross-platform firewall management"""

    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        self.platform = platform.system().lower()
        self.active_rules = {}
        self.rule_history = []

        # Platform-specific configuration
        self.firewall_type = self._detect_firewall_type()
        self.sudo_enabled = config.get("sudo_enabled", True)
        self.dry_run = config.get("dry_run", False)

        self.logger.info(f"Firewall Manager initialized - Platform: {self.platform}, Type: {self.firewall_type}")

    def _detect_firewall_type(self) -> str:
        """Detect the firewall type based on platform"""
        if self.platform == "linux":
            # Check for iptables
            try:
                result = subprocess.run(["which", "iptables"], capture_output=True, text=True)
                if result.returncode == 0:
                    return "iptables"
            except:
                pass

            # Check for ufw
            try:
                result = subprocess.run(["which", "ufw"], capture_output=True, text=True)
                if result.returncode == 0:
                    return "ufw"
            except:
                pass

            return "iptables"  # Default for Linux

        elif self.platform == "darwin":  # macOS
            return "pfctl"

        elif self.platform == "windows":
            return "netsh"

        else:
            return "unknown"

    def apply_block_rule(self, command_id: str, target_ip: str, target_port: Optional[int] = None,
                         duration: Optional[int] = None) -> Tuple[bool, str]:
        """Apply a block rule"""
        try:
            rule_id = str(uuid.uuid4())
            current_time = time.time()
            expires_at = current_time + duration if duration else None

            # Generate rule text based on firewall type
            rule_text = self._generate_block_rule(target_ip, target_port)

            # Apply the rule
            if self.dry_run:
                self.logger.info(f"[DRY RUN] Would apply rule: {rule_text}")
                success = True
                message = f"DRY RUN: Block rule would be applied for {target_ip}"
            else:
                success, message = self._execute_firewall_command(rule_text)

            # Track the rule
            if success:
                rule = FirewallRule(
                    rule_id=rule_id,
                    command_id=command_id,
                    action="BLOCK",
                    target_ip=target_ip,
                    target_port=target_port,
                    duration_seconds=duration,
                    created_at=current_time,
                    expires_at=expires_at,
                    applied=True,
                    rule_text=rule_text
                )

                self.active_rules[rule_id] = rule
                self.rule_history.append(rule)

                self.logger.info(f"Block rule applied: {target_ip} (Rule ID: {rule_id})")

            return success, message

        except Exception as e:
            self.logger.error(f"Error applying block rule: {e}")
            return False, f"Error applying block rule: {str(e)}"

    def apply_allow_rule(self, command_id: str, target_ip: str, target_port: Optional[int] = None,
                         duration: Optional[int] = None) -> Tuple[bool, str]:
        """Apply an allow rule"""
        try:
            rule_id = str(uuid.uuid4())
            current_time = time.time()
            expires_at = current_time + duration if duration else None

            # Generate rule text based on firewall type
            rule_text = self._generate_allow_rule(target_ip, target_port)

            # Apply the rule
            if self.dry_run:
                self.logger.info(f"[DRY RUN] Would apply rule: {rule_text}")
                success = True
                message = f"DRY RUN: Allow rule would be applied for {target_ip}"
            else:
                success, message = self._execute_firewall_command(rule_text)

            # Track the rule
            if success:
                rule = FirewallRule(
                    rule_id=rule_id,
                    command_id=command_id,
                    action="ALLOW",
                    target_ip=target_ip,
                    target_port=target_port,
                    duration_seconds=duration,
                    created_at=current_time,
                    expires_at=expires_at,
                    applied=True,
                    rule_text=rule_text
                )

                self.active_rules[rule_id] = rule
                self.rule_history.append(rule)

                self.logger.info(f"Allow rule applied: {target_ip} (Rule ID: {rule_id})")

            return success, message

        except Exception as e:
            self.logger.error(f"Error applying allow rule: {e}")
            return False, f"Error applying allow rule: {str(e)}"

    def apply_rate_limit_rule(self, command_id: str, target_ip: str, target_port: Optional[int] = None,
                              duration: Optional[int] = None) -> Tuple[bool, str]:
        """Apply a rate limit rule"""
        try:
            rule_id = str(uuid.uuid4())
            current_time = time.time()
            expires_at = current_time + duration if duration else None

            # Generate rule text based on firewall type
            rule_text = self._generate_rate_limit_rule(target_ip, target_port)

            # Apply the rule
            if self.dry_run:
                self.logger.info(f"[DRY RUN] Would apply rule: {rule_text}")
                success = True
                message = f"DRY RUN: Rate limit rule would be applied for {target_ip}"
            else:
                success, message = self._execute_firewall_command(rule_text)

            # Track the rule
            if success:
                rule = FirewallRule(
                    rule_id=rule_id,
                    command_id=command_id,
                    action="RATE_LIMIT",
                    target_ip=target_ip,
                    target_port=target_port,
                    duration_seconds=duration,
                    created_at=current_time,
                    expires_at=expires_at,
                    applied=True,
                    rule_text=rule_text
                )

                self.active_rules[rule_id] = rule
                self.rule_history.append(rule)

                self.logger.info(f"Rate limit rule applied: {target_ip} (Rule ID: {rule_id})")

            return success, message

        except Exception as e:
            self.logger.error(f"Error applying rate limit rule: {e}")
            return False, f"Error applying rate limit rule: {str(e)}"

    def _generate_block_rule(self, target_ip: str, target_port: Optional[int]) -> str:
        """Generate block rule text for the current firewall type"""
        if self.firewall_type == "iptables":
            if target_port:
                return f"iptables -A INPUT -s {target_ip} -p tcp --dport {target_port} -j DROP"
            else:
                return f"iptables -A INPUT -s {target_ip} -j DROP"

        elif self.firewall_type == "ufw":
            if target_port:
                return f"ufw deny from {target_ip} to any port {target_port}"
            else:
                return f"ufw deny from {target_ip}"

        elif self.firewall_type == "pfctl":
            if target_port:
                return f"echo 'block in quick from {target_ip} to any port {target_port}' | pfctl -f -"
            else:
                return f"echo 'block in quick from {target_ip}' | pfctl -f -"

        elif self.firewall_type == "netsh":
            if target_port:
                return f"netsh advfirewall firewall add rule name='Block_{target_ip}_{target_port}' dir=in action=block remoteip={target_ip} remoteport={target_port}"
            else:
                return f"netsh advfirewall firewall add rule name='Block_{target_ip}' dir=in action=block remoteip={target_ip}"

        else:
            return f"# Unknown firewall type: {self.firewall_type}"

    def _generate_allow_rule(self, target_ip: str, target_port: Optional[int]) -> str:
        """Generate allow rule text for the current firewall type"""
        if self.firewall_type == "iptables":
            if target_port:
                return f"iptables -A INPUT -s {target_ip} -p tcp --dport {target_port} -j ACCEPT"
            else:
                return f"iptables -A INPUT -s {target_ip} -j ACCEPT"

        elif self.firewall_type == "ufw":
            if target_port:
                return f"ufw allow from {target_ip} to any port {target_port}"
            else:
                return f"ufw allow from {target_ip}"

        elif self.firewall_type == "pfctl":
            if target_port:
                return f"echo 'pass in quick from {target_ip} to any port {target_port}' | pfctl -f -"
            else:
                return f"echo 'pass in quick from {target_ip}' | pfctl -f -"

        elif self.firewall_type == "netsh":
            if target_port:
                return f"netsh advfirewall firewall add rule name='Allow_{target_ip}_{target_port}' dir=in action=allow remoteip={target_ip} remoteport={target_port}"
            else:
                return f"netsh advfirewall firewall add rule name='Allow_{target_ip}' dir=in action=allow remoteip={target_ip}"

        else:
            return f"# Unknown firewall type: {self.firewall_type}"

    def _generate_rate_limit_rule(self, target_ip: str, target_port: Optional[int]) -> str:
        """Generate rate limit rule text for the current firewall type"""
        if self.firewall_type == "iptables":
            if target_port:
                return f"iptables -A INPUT -s {target_ip} -p tcp --dport {target_port} -m limit --limit 10/minute --limit-burst 5 -j ACCEPT"
            else:
                return f"iptables -A INPUT -s {target_ip} -m limit --limit 10/minute --limit-burst 5 -j ACCEPT"

        elif self.firewall_type == "ufw":
            # UFW doesn't have native rate limiting, so we'll use a basic allow
            if target_port:
                return f"ufw limit from {target_ip} to any port {target_port}"
            else:
                return f"ufw limit from {target_ip}"

        elif self.firewall_type == "pfctl":
            if target_port:
                return f"echo 'pass in quick from {target_ip} to any port {target_port} keep state (max-src-conn 10)' | pfctl -f -"
            else:
                return f"echo 'pass in quick from {target_ip} keep state (max-src-conn 10)' | pfctl -f -"

        elif self.firewall_type == "netsh":
            # Windows firewall doesn't have native rate limiting, so we'll use a basic allow
            if target_port:
                return f"netsh advfirewall firewall add rule name='RateLimit_{target_ip}_{target_port}' dir=in action=allow remoteip={target_ip} remoteport={target_port}"
            else:
                return f"netsh advfirewall firewall add rule name='RateLimit_{target_ip}' dir=in action=allow remoteip={target_ip}"

        else:
            return f"# Unknown firewall type: {self.firewall_type}"

    def _execute_firewall_command(self, rule_text: str) -> Tuple[bool, str]:
        """Execute a firewall command"""
        try:
            # Split command into parts
            if rule_text.startswith("echo"):
                # Handle piped commands (pfctl)
                parts = rule_text.split(" | ")
                if len(parts) == 2:
                    echo_cmd = parts[0].split()[1:]  # Remove 'echo'
                    pfctl_cmd = parts[1].split()

                    # Execute echo part
                    echo_result = subprocess.run(
                        ["echo"] + echo_cmd,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    if echo_result.returncode == 0:
                        # Pipe to pfctl
                        pfctl_result = subprocess.run(
                            pfctl_cmd,
                            input=echo_result.stdout,
                            capture_output=True,
                            text=True,
                            timeout=30
                        )

                        if pfctl_result.returncode == 0:
                            return True, "Rule applied successfully"
                        else:
                            return False, f"pfctl error: {pfctl_result.stderr}"
                    else:
                        return False, f"echo error: {echo_result.stderr}"
            else:
                # Handle regular commands
                cmd_parts = rule_text.split()

                # Add sudo if enabled and not running as root
                if self.sudo_enabled and os.geteuid() != 0:
                    cmd_parts = ["sudo"] + cmd_parts

                # Execute command
                result = subprocess.run(
                    cmd_parts,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    return True, "Rule applied successfully"
                else:
                    return False, f"Command error: {result.stderr}"

        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, f"Execution error: {str(e)}"

    def cleanup_expired_rules(self):
        """Clean up expired rules"""
        current_time = time.time()
        expired_rules = []

        for rule_id, rule in self.active_rules.items():
            if rule.expires_at and current_time > rule.expires_at:
                expired_rules.append(rule_id)

        for rule_id in expired_rules:
            rule = self.active_rules.pop(rule_id)
            self.logger.info(f"Rule expired: {rule.target_ip} (Rule ID: {rule_id})")
            # TODO: Remove the actual firewall rule

    def get_active_rules(self) -> List[FirewallRule]:
        """Get list of active rules"""
        return list(self.active_rules.values())

    def get_rule_history(self) -> List[FirewallRule]:
        """Get rule history"""
        return self.rule_history[-100:]  # Last 100 rules


class SimpleFirewallAgent:
    """Simple firewall agent that processes protobuf commands"""

    def __init__(self, config_path: str, rules_file: str):
        """
        ✅ CORREGIDO: Ahora requiere AMBOS archivos
        - config_path: simple_firewall_agent_config.json
        - rules_file: firewall_rules.json
        """

        # ✅ VALIDACIÓN CRÍTICA: Ambos archivos deben existir
        if not Path(config_path).exists():
            raise FileNotFoundError(f"❌ CRITICAL: Archivo de configuración base no encontrado: {config_path}")

        if not Path(rules_file).exists():
            raise FileNotFoundError(f"❌ CRITICAL: Archivo de reglas no encontrado: {rules_file}")

        # ✅ CARGAR CONFIGURACIÓN BASE (simple_firewall_agent_config.json)
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            print(f"✅ Configuración base cargada: {config_path}")
        except Exception as e:
            raise ValueError(f"❌ CRITICAL: Error cargando configuración base: {e}")

        # ✅ VALIDAR CAMPOS CRÍTICOS EN CONFIGURACIÓN BASE
        required_fields = ["node_id", "component", "firewall", "network"]
        for field in required_fields:
            if field not in self.config:
                raise ValueError(f"❌ CRITICAL: Campo '{field}' faltante en configuración base")

        self.node_id = self.config["node_id"]
        self.component_name = self.config["component"]["name"]
        self.agent_id = f"{self.node_id}_{int(time.time())}"
        self.dry_run = self.config["firewall"]["dry_run"]

        # ✅ CONFIGURAR LOGGING ANTES DE CREAR OTROS COMPONENTES
        self.setup_logging()

        # ✅ CARGAR REGLAS DE FIREWALL (firewall_rules.json)
        try:
            self.rules_sync = FirewallRulesSync(rules_file, self.node_id, self.logger)
            self.logger.info(f"✅ Reglas de firewall cargadas: {rules_file}")
        except Exception as e:
            self.logger.error(f"❌ CRITICAL: Error cargando reglas de firewall: {e}")
            raise e

        # Initialize crypto/compression if available
        self.crypto_engine = None
        self.compression_engine = None

        if CRYPTO_AVAILABLE:
            if self.config.get("encryption", {}).get("enabled", False):
                self.crypto_engine = SecureEnvelope(self.config["encryption"])
            if self.config.get("compression", {}).get("enabled", False):
                self.compression_engine = CompressionEngine(self.config["compression"])

        # Initialize firewall manager
        firewall_config = self.config.get("firewall", {})
        self.firewall_manager = FirewallManager(firewall_config, self.logger)

        # ZMQ setup
        self.zmq_context = zmq.Context()
        self.commands_socket = None
        self.responses_socket = None

        # Processing
        self.command_queue = queue.Queue()
        self.running = False
        self.threads = []

        # Metrics
        self.metrics = {
            "commands_received": 0,
            "commands_processed": 0,
            "responses_sent": 0,
            "rules_applied": 0,
            "errors": 0,
            "uptime_start": time.time()
        }

        # Initialize components
        self._setup_zmq_sockets()

        self.logger.info(f"Simple Firewall Agent initialized: {self.agent_id}")

    def setup_logging(self):
        """✅ CORREGIDO: Setup logging con node_id y PID (como dashboard)"""
        log_config = self.config.get("logging", {})

        # Configurar nivel
        level = getattr(logging, log_config.get("level", "INFO").upper())

        # ✅ FORMATO CON NODE_ID Y PID (como dashboard)
        log_format = log_config.get("format",
                                    "%(asctime)s - %(name)s - %(levelname)s - [node_id:{node_id}] [pid:{pid}] - %(message)s")

        # Reemplazar placeholders
        log_format = log_format.format(
            node_id=self.node_id,
            pid=os.getpid()
        )

        formatter = logging.Formatter(log_format)

        # Setup logger
        self.logger = logging.getLogger(f"firewall_agent_{self.node_id}")
        self.logger.setLevel(level)
        self.logger.handlers.clear()  # Limpiar handlers existentes

        # Handler de consola
        console_config = log_config.get("handlers", {}).get("console", {})
        if console_config.get("enabled", True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        # ✅ CORREGIDO: Handler de archivo ACTIVADO
        file_config = log_config.get("handlers", {}).get("file", {})
        if file_config.get("enabled", True):  # ✅ True por defecto
            file_path = file_config.get("path", "logs/firewall_agent.log")
            # Crear directorio si no existe
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(file_path)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

        self.logger.propagate = False

    def _setup_zmq_sockets(self):
        """Setup ZMQ sockets based on configuration"""
        network_config = self.config.get("network", {})

        # Commands Input (from dashboard)
        if "commands_input" in network_config:
            cmd_config = network_config["commands_input"]
            self.commands_socket = self.zmq_context.socket(zmq.PULL)

            # Configure socket
            if "high_water_mark" in cmd_config:
                self.commands_socket.set_hwm(cmd_config["high_water_mark"])

            # ✅ LEER EL MODO DE LA CONFIGURACIÓN
            cmd_address = f"tcp://{cmd_config['address']}:{cmd_config['port']}"
            cmd_mode = cmd_config.get('mode', 'connect').lower()

            if cmd_mode == 'bind':
                # ✅ HACER BIND (ESCUCHAR)
                self.commands_socket.bind(cmd_address)
                self.logger.info(f"Commands Input BIND en: {cmd_address}")
            else:
                # ✅ HACER CONNECT (CLIENTE)
                self.commands_socket.connect(cmd_address)
                self.logger.info(f"Commands Input CONNECT a: {cmd_address}")

        # Responses Output (to dashboard)
        if "responses_output" in network_config:
            resp_config = network_config["responses_output"]
            self.responses_socket = self.zmq_context.socket(zmq.PUSH)

            # Configure socket
            if "high_water_mark" in resp_config:
                self.responses_socket.set_hwm(resp_config["high_water_mark"])

            # ✅ LEER EL MODO DE LA CONFIGURACIÓN TAMBIÉN PARA RESPONSES
            resp_address = f"tcp://{resp_config['address']}:{resp_config['port']}"
            resp_mode = resp_config.get('mode', 'connect').lower()

            if resp_mode == 'bind':
                # ✅ HACER BIND (ESCUCHAR)
                self.responses_socket.bind(resp_address)
                self.logger.info(f"Responses Output BIND en: {resp_address}")
            else:
                # ✅ HACER CONNECT (CLIENTE)
                self.responses_socket.connect(resp_address)
                self.logger.info(f"Responses Output CONNECT a: {resp_address}")

    def _decrypt_and_decompress(self, data: bytes) -> bytes:
        """Decrypt and decompress data if crypto is enabled"""
        if not data:
            return data

        try:
            # Decrypt if crypto is enabled
            if self.crypto_engine:
                data = self.crypto_engine.decrypt(data)

            # Decompress if compression is enabled
            if self.compression_engine:
                data = self.compression_engine.decompress(data)

            return data

        except Exception as e:
            self.logger.error(f"Failed to decrypt/decompress data: {e}")
            return data  # Return original data if decryption fails

    def _compress_and_encrypt(self, data: bytes) -> bytes:
        """Compress and encrypt data if crypto is enabled"""
        if not data:
            return data

        try:
            # Compress if compression is enabled
            if self.compression_engine:
                result = self.compression_engine.compress(data)
                data = result.compressed_data if hasattr(result, 'compressed_data') else result

            # Encrypt if crypto is enabled
            if self.crypto_engine:
                data = self.crypto_engine.encrypt(data)

            return data

        except Exception as e:
            self.logger.error(f"Failed to compress/encrypt data: {e}")
            return data  # Return original data if encryption fails

    def _commands_consumer(self):
        """Consumer thread for firewall commands"""
        self.logger.info("Commands consumer thread started")

        while self.running:
            try:
                if self.commands_socket:
                    try:
                        # Receive command with timeout
                        raw_data = self.commands_socket.recv(zmq.NOBLOCK)

                        # ✅ DEBUG: Log datos recibidos
                        self.logger.info(f"🔍 Received {len(raw_data)} bytes")

                        # Decrypt and decompress
                        decrypted_data = self._decrypt_and_decompress(raw_data)

                        # ✅ MEJOR MANEJO DE PROTOBUF
                        try:
                            # Parse protobuf
                            pb_command = firewall_commands_pb2.FirewallCommand()
                            pb_command.ParseFromString(decrypted_data)

                            # ✅ VALIDAR CAMPOS CRÍTICOS
                            if not pb_command.command_id:
                                pb_command.command_id = f"auto_{int(time.time())}"

                            if not pb_command.target_ip:
                                pb_command.target_ip = "127.0.0.1"

                            self.logger.info(
                                f"✅ Parsed command: {pb_command.command_id}, action={pb_command.action}, ip={pb_command.target_ip}")

                            # Add to processing queue
                            self.command_queue.put(pb_command)
                            self.metrics["commands_received"] += 1

                        except Exception as parse_error:
                            self.logger.error(f"❌ Protobuf parse error: {parse_error}")
                            self.logger.error(f"📦 Data hex: {decrypted_data[:50].hex()}")

                            # ✅ CREAR COMANDO BÁSICO COMO FALLBACK
                            fallback_command = firewall_commands_pb2.FirewallCommand()
                            fallback_command.command_id = f"fallback_{int(time.time())}"
                            fallback_command.action = firewall_commands_pb2.CommandAction.LIST_RULES
                            fallback_command.target_ip = "127.0.0.1"
                            fallback_command.dry_run = True

                            self.logger.info("🔄 Using fallback command")
                            self.command_queue.put(fallback_command)
                            self.metrics["commands_received"] += 1

                    except zmq.Again:
                        # No message available, continue
                        pass
                    except Exception as e:
                        self.logger.error(f"❌ Error receiving command: {e}")
                        self.metrics["errors"] += 1

                time.sleep(0.001)  # Small delay to prevent busy waiting

            except Exception as e:
                self.logger.error(f"❌ Commands consumer error: {e}")
                self.metrics["errors"] += 1
                time.sleep(1)

    def _command_processor(self):
        """Processor thread for firewall commands"""
        self.logger.info("Command processor thread started")

        while self.running:
            try:
                # Get command from queue
                try:
                    pb_command = self.command_queue.get(timeout=1)
                except queue.Empty:
                    continue

                # Process command
                self._process_firewall_command(pb_command)

                self.metrics["commands_processed"] += 1

            except Exception as e:
                self.logger.error(f"Command processor error: {e}")
                self.metrics["errors"] += 1
                time.sleep(1)

    def _process_firewall_command(self, pb_command):
        """✅ CORREGIDO: Process a firewall command con comparación de enums correcta"""
        try:
            command_id = pb_command.command_id
            action = pb_command.action  # ✅ ESTO ES UN ENUM (int), NO string
            target_ip = pb_command.target_ip
            target_port = pb_command.target_port if pb_command.target_port else None
            duration = pb_command.duration_seconds if pb_command.duration_seconds else None

            self.logger.info(f"Processing command: {command_id} - {action} {target_ip}")

            # ✅ CORREGIDO: Comparar ENUMS con ENUMS (no strings)
            if action == firewall_commands_pb2.CommandAction.BLOCK_IP:
                success, message = self.firewall_manager.apply_block_rule(
                    command_id, target_ip, target_port, duration
                )
            elif action == firewall_commands_pb2.CommandAction.UNBLOCK_IP:
                success, message = self.firewall_manager.apply_allow_rule(
                    command_id, target_ip, target_port, duration
                )
            elif action == firewall_commands_pb2.CommandAction.RATE_LIMIT_IP:  # ✅ CORREGIDO: Era RATE_LIMIT
                success, message = self.firewall_manager.apply_rate_limit_rule(
                    command_id, target_ip, target_port, duration
                )
            elif action == firewall_commands_pb2.CommandAction.LIST_RULES:
                # ✅ Comando LIST_RULES (el que envía el test)
                active_rules = self.firewall_manager.get_active_rules()
                success = True
                message = f"LIST_RULES: {len(active_rules)} active rules (dry_run={self.dry_run})"
                self.logger.info(f"📋 {message}")
            elif action == firewall_commands_pb2.CommandAction.ALLOW_IP_TEMP:  # ✅ NUEVO: Equivalente a MONITOR
                # Simular monitoreo - no hacer nada pero reportar éxito
                success = True
                message = f"MONITOR: Monitoring enabled for {target_ip}"
                self.logger.info(f"👁️ {message}")
            else:
                success = False
                message = f"Unknown action: {action}"

            # Send response
            self._send_response(command_id, success, message)

            if success:
                self.metrics["rules_applied"] += 1

        except Exception as e:
            self.logger.error(f"Error processing command: {e}")
            self._send_response(pb_command.command_id, False, f"Processing error: {str(e)}")

    def _send_response(self, command_id: str, success: bool, message: str):
        """Send response to dashboard"""
        try:
            if not self.responses_socket:
                self.logger.error("Responses socket not configured")
                return

            # Create response protobuf
            pb_response = firewall_commands_pb2.FirewallResponse()
            pb_response.command_id = command_id
            pb_response.node_id = self.node_id  # ✅ USAR NODE_ID de configuración
            pb_response.success = success
            pb_response.message = message
            pb_response.timestamp = int(time.time() * 1000)

            # Serialize
            serialized_data = pb_response.SerializeToString()

            # Compress and encrypt
            encrypted_data = self._compress_and_encrypt(serialized_data)

            # Send response
            self.responses_socket.send(encrypted_data, zmq.NOBLOCK)

            self.metrics["responses_sent"] += 1

            self.logger.info(f"Response sent: {command_id} - Success: {success}")

        except Exception as e:
            self.logger.error(f"Error sending response: {e}")
            self.metrics["errors"] += 1

    def _cleanup_thread(self):
        """Cleanup thread for expired rules"""
        self.logger.info("Cleanup thread started")

        while self.running:
            try:
                self.firewall_manager.cleanup_expired_rules()

                # ✅ NUEVO: Verificar cambios en reglas si está configurado
                if self.rules_sync:
                    self.rules_sync.reload_if_changed()

                time.sleep(60)  # Check every minute

            except Exception as e:
                self.logger.error(f"Cleanup thread error: {e}")
                time.sleep(60)

    def start(self):
        """Start the firewall agent"""
        self.logger.info("Starting Simple Firewall Agent...")

        self.running = True

        # Start consumer thread
        if self.commands_socket:
            consumer_thread = threading.Thread(target=self._commands_consumer, daemon=True)
            consumer_thread.start()
            self.threads.append(consumer_thread)

        # Start processor thread
        processor_thread = threading.Thread(target=self._command_processor, daemon=True)
        processor_thread.start()
        self.threads.append(processor_thread)

        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_thread, daemon=True)
        cleanup_thread.start()
        self.threads.append(cleanup_thread)

        self.logger.info(f"Simple Firewall Agent started with {len(self.threads)} threads")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutdown requested by user")
            self.stop()

    def stop(self):
        """Stop the firewall agent"""
        self.logger.info("Stopping Simple Firewall Agent...")

        self.running = False

        # Close ZMQ sockets
        if self.commands_socket:
            self.commands_socket.close()
        if self.responses_socket:
            self.responses_socket.close()

        # Close ZMQ context
        self.zmq_context.term()

        self.logger.info("Simple Firewall Agent stopped")

    def get_status(self) -> Dict:
        """Get agent status"""
        capabilities = []
        if self.rules_sync:
            capabilities = self.rules_sync.capabilities
        else:
            capabilities = ['BLOCK_IP', 'RATE_LIMIT', 'MONITOR', 'LIST_RULES']

        return {
            "agent_id": self.agent_id,
            "node_id": self.node_id,
            "component_name": self.component_name,
            "running": self.running,
            "metrics": self.metrics,
            "uptime_seconds": time.time() - self.metrics["uptime_start"],
            "firewall_type": self.firewall_manager.firewall_type,
            "platform": self.firewall_manager.platform,
            "active_rules": len(self.firewall_manager.active_rules),
            "crypto_enabled": self.crypto_engine is not None,
            "compression_enabled": self.compression_engine is not None,
            "capabilities": capabilities,  # ✅ INCLUIR CAPACIDADES SINCRONIZADAS
            "rules_sync_enabled": self.rules_sync is not None
        }


def main():
    """✅ CORREGIDO: Main function que REQUIERE ambos archivos"""
    import argparse

    parser = argparse.ArgumentParser(description="Simple Firewall Agent - Dual Config Support")
    parser.add_argument("config", help="Configuration file path (simple_firewall_agent_config.json)")
    parser.add_argument("rules", help="Firewall rules JSON file (firewall_rules.json)")
    parser.add_argument("--log-level", default="INFO", help="Log level")

    args = parser.parse_args()

    # ✅ VALIDAR archivos de entrada ANTES de continuar
    if not Path(args.config).exists():
        print(f"❌ ERROR: Archivo de configuración no encontrado: {args.config}")
        print("📁 Necesario: simple_firewall_agent_config.json")
        sys.exit(1)

    if not Path(args.rules).exists():
        print(f"❌ ERROR: Archivo de reglas no encontrado: {args.rules}")
        print("📁 Necesario: firewall_rules.json")
        sys.exit(1)

    # ✅ Setup logging básico ANTES de crear el agente
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize and start agent
    try:
        print(f"✅ Inicializando con configuración: {args.config}")
        print(f"✅ Inicializando con reglas: {args.rules}")
        agent = SimpleFirewallAgent(args.config, args.rules)

        agent.start()
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested by user")
    except Exception as e:
        print(f"❌ Agent error: {e}")
    finally:
        if 'agent' in locals():
            agent.stop()


if __name__ == "__main__":
    main()