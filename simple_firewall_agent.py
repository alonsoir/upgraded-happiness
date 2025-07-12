#!/usr/bin/env python3
"""
Simple Firewall Agent para Upgraded-Happiness
ACTUALIZADO: Arquitectura 3 puertos compatible con dashboard
Puerto 5562: Comandos del dashboard → firewall
Puerto 5563: Confirmaciones firewall → dashboard
"""

import zmq
import json
import time
import logging
import threading
import argparse
import os
import sys
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from simple_system_detection import SimpleSystemDetector

# Configurar logging básico (se reconfigurará desde JSON)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Importar protobuf - USAR ESTRUCTURAS REALES
try:
    from src.protocols.protobuf import firewall_commands_pb2
    from src.protocols.protobuf import network_event_extended_fixed_pb2
    PROTOBUF_AVAILABLE = True
    logger.info("✅ Protobuf importado desde src.protocols.protobuf")
except ImportError:
    try:
        import firewall_commands_pb2
        import network_event_extended_fixed_pb2
        PROTOBUF_AVAILABLE = True
        logger.info("✅ Protobuf importado desde directorio local")
    except ImportError:
        PROTOBUF_AVAILABLE = False
        logger.error("❌ Protobuf no disponible")


@dataclass
class FirewallCommandResult:
    """Resultado de la ejecución de un comando"""
    command_id: str
    success: bool
    executed: bool
    simulated: bool
    firewall_command: str
    message: str
    execution_time: float
    error_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None


class SimpleFirewallAgent:
    """Agente de firewall con arquitectura 3 puertos"""

    def __init__(self, config_file=None):
        """Inicializar agente desde configuración JSON actualizada"""
        self.config = self._load_config(config_file)
        self.config_file = config_file

        # Configurar logging desde JSON PRIMERO
        self._setup_logging()

        # Configuración de red actualizada para 3 puertos
        network_config = self.config['network']
        self.commands_input_port = network_config['commands_input_port']
        self.confirmations_output_port = network_config['confirmations_output_port']
        self.bind_address = network_config['bind_address']
        self.socket_timeout = network_config['socket_timeout']

        # Configuración de firewall desde JSON
        self.display_only = not self.config['firewall']['enable_firewall_modifications']
        self.nuclear_enabled = self.config['firewall']['nuclear_option']['enabled']
        self.dry_run_mode = self.config['firewall']['dry_run_mode']
        self.supported_actions = self.config['firewall']['supported_actions']
        self.default_chain = self.config['firewall']['default_chain']
        self.backup_rules = self.config['firewall']['backup_rules']
        self.max_rules_per_request = self.config['firewall']['max_rules_per_request']

        # Configuración de seguridad desde JSON
        self.validate_requests = self.config['security']['validate_requests']
        self.allowed_sources = self.config['security']['allowed_sources']
        self.rate_limiting = self.config['security']['rate_limiting']
        self.authentication = self.config['security']['authentication']

        self.running = False

        # Detección del sistema
        self.detector = SimpleSystemDetector()
        self.system_info = self.detector.get_system_summary()

        # ZeroMQ setup desde configuración
        zmq_threads = self.config['network']['zmq_context_threads']
        self.context = zmq.Context(zmq_threads)
        self.command_socket = None
        self.confirmation_socket = None

        # Estadísticas
        self.stats = {
            'commands_received': 0,
            'commands_executed': 0,
            'commands_simulated': 0,
            'confirmations_sent': 0,
            'batches_received': 0,
            'batches_processed': 0,
            'protobuf_commands': 0,
            'json_commands': 0,
            'start_time': time.time()
        }

        # Log de comandos ejecutados
        self.command_history = []

        # Rate limiting si está habilitado
        if self.rate_limiting['enabled']:
            self.request_times = []
            self.max_requests_per_minute = self.rate_limiting['max_requests_per_minute']

        # Estado de persistencia
        if self.config['persistence']['save_state']:
            self.state_file = self.config['persistence']['state_file']
            self.auto_save_interval = self.config['persistence']['auto_save_interval']
            self._load_state()

        logger.info("SimpleFirewallAgent inicializado para arquitectura 3 puertos")
        logger.info("Config file: %s", config_file or 'default config')
        logger.info("Node: %s", self.system_info['node_id'])
        logger.info("Firewall: %s (%s)", self.system_info['firewall_type'], self.system_info['firewall_status'])
        logger.info("Display-only mode: %s", self.display_only)
        logger.info("Nuclear option: %s", self.nuclear_enabled)
        logger.info("Commands input port: %d", self.commands_input_port)
        logger.info("Confirmations output port: %d", self.confirmations_output_port)
        logger.info("Protobuf available: %s", PROTOBUF_AVAILABLE)

    def _load_config(self, config_file):
        """Cargar configuración desde archivo JSON actualizada para 3 puertos"""
        default_config = {
            "agent_info": {
                "name": "simple_firewall_agent",
                "version": "1.0.0",
                "description": "Agente de firewall que escucha comandos del dashboard"
            },
            "network": {
                "commands_input_port": 5562,
                "confirmations_output_port": 5563,
                "bind_address": "*",
                "zmq_context_threads": 1,
                "socket_timeout": 5000,
                "max_connections": 100
            },
            "firewall": {
                "enable_firewall_modifications": False,
                "nuclear_option": {
                    "enabled": False,
                    "description": "PELIGRO: Permite aplicar cambios reales en el firewall del sistema"
                },
                "dry_run_mode": True,
                "supported_actions": [
                    "block_ip", "unblock_ip", "block_port", "unblock_port",
                    "list_rules", "flush_rules"
                ],
                "default_chain": "INPUT",
                "backup_rules": True,
                "max_rules_per_request": 50
            },
            "security": {
                "validate_requests": True,
                "allowed_sources": ["127.0.0.1", "localhost"],
                "rate_limiting": {
                    "enabled": True,
                    "max_requests_per_minute": 30
                },
                "authentication": {
                    "enabled": False,
                    "token_required": False
                }
            },
            "logging": {
                "level": "INFO",
                "file": "logs/firewall_agent.log",
                "max_size_mb": 10,
                "backup_count": 5,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "console_output": True
            },
            "monitoring": {
                "health_check_interval": 30,
                "metrics_enabled": True,
                "report_status": True
            },
            "persistence": {
                "save_state": True,
                "state_file": "data/firewall_agent_state.json",
                "auto_save_interval": 60
            }
        }

        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)

                # Merge recursivo de configuraciones
                self._merge_config(default_config, user_config)
                logger.info(f"📄 Configuración cargada desde {config_file}")

            except Exception as e:
                logger.error(f"❌ Error cargando configuración: {e}")
                logger.info("⚠️ Usando configuración por defecto")
        else:
            if config_file:
                logger.warning(f"⚠️ Archivo de configuración no encontrado: {config_file}")
            logger.info("⚠️ Usando configuración por defecto")

        return default_config

    def _merge_config(self, base, update):
        """Merge recursivo de configuraciones"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def _setup_logging(self):
        """Configurar logging desde configuración JSON"""
        log_config = self.config.get('logging', {})

        # Configurar nivel
        level = getattr(logging, log_config.get('level', 'INFO').upper())
        logger.setLevel(level)

        # Limpiar handlers existentes
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        # Formatter desde configuración
        formatter = logging.Formatter(
            log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )

        # Console handler si está habilitado
        if log_config.get('console_output', True):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        # File handler si se especifica archivo
        if log_config.get('file'):
            # Crear directorio si no existe
            log_file = log_config['file']
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=log_config.get('max_size_mb', 10) * 1024 * 1024,
                backupCount=log_config.get('backup_count', 5)
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    def _load_state(self):
        """Cargar estado persistente si existe"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                self.stats.update(state.get('stats', {}))
                logger.info(f"📄 Estado cargado desde {self.state_file}")
            except Exception as e:
                logger.warning(f"⚠️ Error cargando estado: {e}")

    def _save_state(self):
        """Guardar estado persistente"""
        if not self.config['persistence']['save_state']:
            return

        try:
            # Crear directorio si no existe
            state_dir = os.path.dirname(self.state_file)
            if state_dir and not os.path.exists(state_dir):
                os.makedirs(state_dir, exist_ok=True)

            state = {
                'stats': self.stats,
                'last_saved': time.time(),
                'config_file': self.config_file
            }

            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)

        except Exception as e:
            logger.error(f"❌ Error guardando estado: {e}")

    def _check_rate_limit(self):
        """Verificar rate limiting si está habilitado"""
        if not self.rate_limiting['enabled']:
            return True

        now = time.time()
        # Limpiar requests antiguos (más de 1 minuto)
        self.request_times = [t for t in self.request_times if now - t < 60]

        if len(self.request_times) >= self.max_requests_per_minute:
            logger.warning("⚠️ Rate limit exceeded")
            return False

        self.request_times.append(now)
        return True

    def start(self):
        """Inicia el agente de firewall usando arquitectura 3 puertos"""
        try:
            # Socket para recibir comandos del dashboard (puerto 5562)
            self.command_socket = self.context.socket(zmq.PULL)
            commands_bind_addr = f"tcp://{self.bind_address}:{self.commands_input_port}"
            self.command_socket.bind(commands_bind_addr)
            self.command_socket.setsockopt(zmq.RCVTIMEO, self.socket_timeout)

            # Socket para enviar confirmaciones al dashboard (puerto 5563)
            self.confirmation_socket = self.context.socket(zmq.PUSH)
            confirmations_addr = f"tcp://localhost:{self.confirmations_output_port}"
            self.confirmation_socket.connect(confirmations_addr)

            self.running = True

            print(f"\n🔥 Simple Firewall Agent Started (3 PUERTOS)")
            print(f"📄 Config: {self.config_file or 'default'}")
            print(f"📡 Comandos desde dashboard: {commands_bind_addr}")
            print(f"📤 Confirmaciones hacia dashboard: {confirmations_addr}")
            print(f"🖥️  System: {self.system_info['os_name']} {self.system_info['os_version']}")
            print(f"🛡️  Firewall: {self.system_info['firewall_type']} ({self.system_info['firewall_status']})")
            print(f"⚠️  Mode: {'DISPLAY-ONLY (Safe)' if self.display_only else 'LIVE (Dangerous)'}")
            print(f"💣 Nuclear: {'✅ ENABLED' if self.nuclear_enabled else '❌ DISABLED'}")
            print(f"📦 Protobuf: {'✅ Available' if PROTOBUF_AVAILABLE else '❌ Not available'}")
            print(f"🆔 Node ID: {self.system_info['node_id']}")
            print(f"🔒 Security: Validation={self.validate_requests}, RateLimit={self.rate_limiting['enabled']}")
            print("🏗️ Arquitectura: Dashboard(5562) → Firewall → Dashboard(5563)")
            print("=" * 70)

            # Thread de auto-guardado si está habilitado
            if self.config['persistence']['save_state']:
                save_thread = threading.Thread(target=self._auto_save_loop, daemon=True)
                save_thread.start()

            # Main loop
            self.listen_for_commands()

        except Exception as e:
            logger.error("Error starting firewall agent: %s", e)
            raise
        finally:
            self.cleanup()

    def _auto_save_loop(self):
        """Loop de auto-guardado de estado"""
        while self.running:
            try:
                time.sleep(self.auto_save_interval)
                self._save_state()
            except Exception as e:
                logger.error(f"Error en auto-save: {e}")

    def listen_for_commands(self):
        """Loop principal - escucha comandos desde dashboard (puerto 5562)"""
        logger.info("Listening for firewall commands from dashboard (port %d)...", self.commands_input_port)

        try:
            while self.running:
                try:
                    # Verificar rate limiting
                    if not self._check_rate_limit():
                        time.sleep(1)
                        continue

                    # Recibir comando del dashboard
                    if self.command_socket.poll(1000):  # 1 segundo timeout
                        message = self.command_socket.recv()
                        self.process_command_message(message)

                except zmq.Again:
                    continue  # Timeout - continuar
                except Exception as e:
                    logger.error("Error receiving command: %s", e)
                    time.sleep(1)

        except KeyboardInterrupt:
            print("\n\n🛑 Stopping firewall agent...")
            self.running = False

    def process_command_message(self, message: bytes):
        """Procesa un mensaje de comando recibido del dashboard"""
        try:
            self.stats['commands_received'] += 1

            # Intentar parsear como protobuf PRIMERO
            if PROTOBUF_AVAILABLE:
                try:
                    # Intentar como comando individual protobuf
                    command = firewall_commands_pb2.FirewallCommand()
                    command.ParseFromString(message)

                    self.stats['protobuf_commands'] += 1
                    logger.info("Received PROTOBUF COMMAND from dashboard: %s", command.command_id)

                    # Procesar comando individual
                    result = self.process_protobuf_command(command)
                    self.display_command_result_protobuf(command, result)

                    # Enviar confirmación al dashboard (puerto 5563)
                    self.send_confirmation_to_dashboard(command, result)

                    return

                except Exception as e:
                    logger.debug("Error parsing command protobuf: %s", e)

            # Fallback a JSON
            try:
                command_json = json.loads(message.decode('utf-8'))
                self.stats['json_commands'] += 1
                logger.info("Received JSON command from dashboard: %s", command_json.get('command_id', 'unknown'))

                # Procesar comando JSON
                result = self.process_json_command(command_json)
                self.display_command_result_json(command_json, result)

                # Enviar confirmación al dashboard (puerto 5563)
                self.send_json_confirmation_to_dashboard(command_json, result)

            except json.JSONDecodeError as e:
                logger.error("Invalid message format (not protobuf or JSON): %s", e)
            except Exception as e:
                logger.error("Error processing JSON command: %s", e)

        except Exception as e:
            logger.error("Error processing command message: %s", e)

    def process_protobuf_command(self, command: firewall_commands_pb2.FirewallCommand) -> FirewallCommandResult:
        """Procesa un comando protobuf individual"""

        # Validar comando usando configuración
        if not self.validate_protobuf_command(command):
            return FirewallCommandResult(
                command_id=command.command_id,
                success=False,
                executed=False,
                simulated=False,
                firewall_command="",
                message="Invalid command rejected",
                execution_time=0.0
            )

        # Ejecutar comando basado en configuración
        if self.display_only or command.dry_run or self.dry_run_mode:
            return self.simulate_protobuf_command(command)
        elif self.nuclear_enabled:
            return self.apply_real_protobuf_command(command)
        else:
            # Nuclear no habilitado - simular aunque no sea dry_run
            logger.warning("Real execution requested but nuclear option disabled - simulating")
            return self.simulate_protobuf_command(command)

    def validate_protobuf_command(self, command: firewall_commands_pb2.FirewallCommand) -> bool:
        """Valida un comando protobuf antes de ejecutarlo"""

        if not self.validate_requests:
            return True  # Validación deshabilitada

        # Validaciones básicas
        if not command.target_ip:
            logger.warning("Command missing target_ip")
            return False

        # Validar acción usando configuración
        action_name = firewall_commands_pb2.CommandAction.Name(command.action).lower()
        if action_name not in self.supported_actions:
            logger.warning("Unsupported action: %s", action_name)
            return False

        if command.duration_seconds < 0:
            logger.warning("Invalid duration")
            return False

        # Validar IP format (básico)
        if command.target_ip and command.target_ip != "":
            try:
                parts = command.target_ip.split('.')
                if len(parts) != 4 or not all(0 <= int(p) <= 255 for p in parts):
                    raise ValueError("Invalid IP")
            except (ValueError, AttributeError):
                logger.warning("Invalid IP format: %s", command.target_ip)
                return False

        return True

    def simulate_protobuf_command(self, command: firewall_commands_pb2.FirewallCommand) -> FirewallCommandResult:
        """Simula la ejecución de un comando protobuf"""

        # Generar comando específico del SO
        firewall_cmd = self.generate_firewall_command_from_protobuf(command)

        result = FirewallCommandResult(
            command_id=command.command_id,
            success=True,
            executed=False,
            simulated=True,
            firewall_command=firewall_cmd,
            message="SIMULATED: Would execute firewall command",
            execution_time=0.001  # Simulación es instantánea
        )

        return result

    def apply_real_protobuf_command(self, command: firewall_commands_pb2.FirewallCommand) -> FirewallCommandResult:
        """Aplica comando protobuf real al firewall (¡PELIGROSO!)"""

        # IMPORTANTE: Este método REALMENTE modifica el firewall
        action_name = firewall_commands_pb2.CommandAction.Name(command.action)
        logger.warning("APPLYING REAL FIREWALL COMMAND: %s %s", action_name, command.target_ip)

        firewall_cmd = self.generate_firewall_command_from_protobuf(command)

        try:
            import subprocess
            start_time = time.time()

            # Ejecutar comando real
            result = subprocess.run(
                firewall_cmd.split(),
                capture_output=True,
                text=True,
                timeout=10
            )

            execution_time = time.time() - start_time

            if result.returncode == 0:
                cmd_result = FirewallCommandResult(
                    command_id=command.command_id,
                    success=True,
                    executed=True,
                    simulated=False,
                    firewall_command=firewall_cmd,
                    message=f"Successfully executed: {firewall_cmd}",
                    execution_time=execution_time,
                    stdout=result.stdout,
                    stderr=result.stderr
                )
            else:
                cmd_result = FirewallCommandResult(
                    command_id=command.command_id,
                    success=False,
                    executed=False,
                    simulated=False,
                    firewall_command=firewall_cmd,
                    message=f"Command failed: {result.stderr}",
                    execution_time=execution_time,
                    error_code=result.returncode
                )

            return cmd_result

        except subprocess.TimeoutExpired:
            return FirewallCommandResult(
                command_id=command.command_id,
                success=False,
                executed=False,
                simulated=False,
                firewall_command=firewall_cmd,
                message="Command timed out",
                execution_time=0.0
            )
        except Exception as e:
            return FirewallCommandResult(
                command_id=command.command_id,
                success=False,
                executed=False,
                simulated=False,
                firewall_command=firewall_cmd,
                message=f"Execution error: {str(e)}",
                execution_time=0.0
            )

    def process_json_command(self, command_data: Dict) -> FirewallCommandResult:
        """Procesa comando JSON (compatibilidad hacia atrás)"""

        # Convertir JSON a estructura similar a protobuf para procesamiento
        command_id = command_data.get('command_id', 'unknown')
        action_str = command_data.get('action', 'BLOCK_IP').upper()
        target_ip = command_data.get('target_ip', '')
        target_port = command_data.get('target_port', 0)
        duration_seconds = command_data.get('duration_seconds', 3600)
        reason = command_data.get('reason', 'JSON command')
        priority = command_data.get('priority', 'MEDIUM')
        dry_run = command_data.get('dry_run', True)

        # Validar comando JSON usando configuración
        if not target_ip:
            return FirewallCommandResult(
                command_id=command_id,
                success=False,
                executed=False,
                simulated=False,
                firewall_command="",
                message="Invalid JSON command: missing target_ip",
                execution_time=0.0
            )

        # Validar acción usando configuración
        if self.validate_requests and action_str.lower() not in self.supported_actions:
            return FirewallCommandResult(
                command_id=command_id,
                success=False,
                executed=False,
                simulated=False,
                firewall_command="",
                message=f"Unsupported action: {action_str}",
                execution_time=0.0
            )

        # Generar comando específico del SO
        firewall_cmd = self.generate_firewall_command_from_json(command_data)

        if self.display_only or dry_run or self.dry_run_mode:
            result = FirewallCommandResult(
                command_id=command_id,
                success=True,
                executed=False,
                simulated=True,
                firewall_command=firewall_cmd,
                message="SIMULATED: Would execute firewall command (JSON)",
                execution_time=0.001
            )
        elif self.nuclear_enabled:
            # Ejecutar comando real desde JSON
            result = self.execute_real_command_from_json(command_data, firewall_cmd)
        else:
            logger.warning("Real execution requested but nuclear option disabled - simulating")
            result = FirewallCommandResult(
                command_id=command_id,
                success=True,
                executed=False,
                simulated=True,
                firewall_command=firewall_cmd,
                message="SIMULATED: Nuclear option disabled",
                execution_time=0.001
            )

        # Guardar en historial
        self.command_history.append({
            'command_json': command_data,
            'result': asdict(result),
            'timestamp': time.time(),
            'protocol': 'json'
        })

        return result

    def execute_real_command_from_json(self, command_data: Dict, firewall_cmd: str) -> FirewallCommandResult:
        """Ejecuta comando real desde JSON"""
        command_id = command_data.get('command_id', 'unknown')

        try:
            import subprocess
            start_time = time.time()

            result = subprocess.run(
                firewall_cmd.split(),
                capture_output=True,
                text=True,
                timeout=10
            )

            execution_time = time.time() - start_time

            if result.returncode == 0:
                return FirewallCommandResult(
                    command_id=command_id,
                    success=True,
                    executed=True,
                    simulated=False,
                    firewall_command=firewall_cmd,
                    message=f"Successfully executed: {firewall_cmd}",
                    execution_time=execution_time,
                    stdout=result.stdout,
                    stderr=result.stderr
                )
            else:
                return FirewallCommandResult(
                    command_id=command_id,
                    success=False,
                    executed=False,
                    simulated=False,
                    firewall_command=firewall_cmd,
                    message=f"Command failed: {result.stderr}",
                    execution_time=execution_time,
                    error_code=result.returncode
                )

        except Exception as e:
            return FirewallCommandResult(
                command_id=command_id,
                success=False,
                executed=False,
                simulated=False,
                firewall_command=firewall_cmd,
                message=f"Execution error: {str(e)}",
                execution_time=0.0
            )

    def send_confirmation_to_dashboard(self, command: firewall_commands_pb2.FirewallCommand, result: FirewallCommandResult):
        """Envía confirmación JSON al dashboard (puerto 5563)"""
        if not self.confirmation_socket:
            return

        try:
            # Crear confirmación en formato JSON para el dashboard
            confirmation = {
                'command_id': command.command_id,
                'status': 'success' if result.success else 'error',
                'message': result.message,
                'target_ip': command.target_ip,
                'action': firewall_commands_pb2.CommandAction.Name(command.action).lower(),
                'executed_at': time.time(),
                'duration': f"{command.duration_seconds}s",
                'rules_applied': [result.firewall_command] if result.firewall_command else [],
                'execution_time': result.execution_time,
                'simulated': result.simulated,
                'node_id': self.system_info['node_id'],
                'firewall_type': self.system_info['firewall_type'],
                'timestamp': time.time()
            }

            # Enviar confirmación como JSON
            message = json.dumps(confirmation).encode('utf-8')
            self.confirmation_socket.send(message)

            self.stats['confirmations_sent'] += 1
            logger.info(f"📤 Confirmación enviada al dashboard (puerto {self.confirmations_output_port}): {command.command_id}")

        except Exception as e:
            logger.error(f"Error enviando confirmación: {e}")

    def send_json_confirmation_to_dashboard(self, command_data: Dict, result: FirewallCommandResult):
        """Envía confirmación JSON al dashboard para comandos JSON"""
        if not self.confirmation_socket:
            return

        try:
            # Crear confirmación en formato JSON
            confirmation = {
                'command_id': result.command_id,
                'status': 'success' if result.success else 'error',
                'message': result.message,
                'target_ip': command_data.get('target_ip', 'unknown'),
                'action': command_data.get('action', 'unknown').lower(),
                'executed_at': time.time(),
                'duration': f"{command_data.get('duration_seconds', 3600)}s",
                'rules_applied': [result.firewall_command] if result.firewall_command else [],
                'execution_time': result.execution_time,
                'simulated': result.simulated,
                'node_id': self.system_info['node_id'],
                'firewall_type': self.system_info['firewall_type'],
                'timestamp': time.time()
            }

            # Enviar confirmación como JSON
            message = json.dumps(confirmation).encode('utf-8')
            self.confirmation_socket.send(message)

            self.stats['confirmations_sent'] += 1
            logger.info(f"📤 Confirmación JSON enviada al dashboard (puerto {self.confirmations_output_port}): {result.command_id}")

        except Exception as e:
            logger.error(f"Error enviando confirmación JSON: {e}")

    def generate_firewall_command_from_protobuf(self, command: firewall_commands_pb2.FirewallCommand) -> str:
        """Genera el comando específico del firewall desde protobuf"""

        firewall_type = self.system_info['firewall_type']
        action_name = firewall_commands_pb2.CommandAction.Name(command.action)
        target_ip = command.target_ip
        target_port = command.target_port if command.target_port > 0 else None

        return self._generate_firewall_command_by_type(firewall_type, action_name, target_ip, target_port)

    def generate_firewall_command_from_json(self, command_data: Dict) -> str:
        """Genera el comando específico del firewall desde JSON"""

        firewall_type = self.system_info['firewall_type']
        action = command_data.get('action', 'BLOCK_IP')
        target_ip = command_data.get('target_ip', '')
        target_port = command_data.get('target_port')

        return self._generate_firewall_command_by_type(firewall_type, action, target_ip, target_port)

    def _generate_firewall_command_by_type(self, firewall_type: str, action: str, target_ip: str,
                                           target_port: Optional[int]) -> str:
        """Genera el comando específico del firewall según el SO"""

        if firewall_type == 'ufw':
            return self._generate_ufw_command(action, target_ip, target_port)
        elif firewall_type == 'iptables':
            return self._generate_iptables_command(action, target_ip, target_port)
        elif firewall_type == 'firewalld':
            return self._generate_firewalld_command(action, target_ip, target_port)
        elif firewall_type == 'windows_firewall':
            return self._generate_windows_command(action, target_ip, target_port)
        elif firewall_type == 'pf':
            return self._generate_pf_command(action, target_ip, target_port)
        else:
            return f"# Unknown firewall type: {firewall_type}"

    def _generate_ufw_command(self, action: str, ip: str, port: Optional[int]) -> str:
        """Genera comando UFW"""
        if action in ['BLOCK_IP', 'BLOCK_PORT']:
            return f"ufw deny from {ip}"
        elif action == 'RATE_LIMIT_IP':
            return f"ufw limit from {ip}"
        elif action in ['ALLOW_IP_TEMP', 'ALLOW']:
            return f"ufw allow from {ip}"
        elif action in ['UNBLOCK_IP', 'UNBLOCK_PORT']:
            return f"ufw delete deny from {ip}"
        elif action == 'FLUSH_RULES':
            return "ufw --force reset"
        elif action == 'LIST_RULES':
            return "ufw status numbered"
        else:
            return f"# Unknown UFW action: {action}"

    def _generate_iptables_command(self, action: str, ip: str, port: Optional[int]) -> str:
        """Genera comando iptables usando cadena de configuración"""
        chain = self.default_chain

        if action in ['BLOCK_IP', 'BLOCK_PORT']:
            return f"iptables -A {chain} -s {ip} -j DROP"
        elif action == 'RATE_LIMIT_IP':
            return f"iptables -A {chain} -s {ip} -m limit --limit 10/min -j ACCEPT"
        elif action in ['ALLOW_IP_TEMP', 'ALLOW']:
            return f"iptables -A {chain} -s {ip} -j ACCEPT"
        elif action in ['UNBLOCK_IP', 'UNBLOCK_PORT']:
            return f"iptables -D {chain} -s {ip} -j DROP"
        elif action == 'FLUSH_RULES':
            return "iptables -F"
        elif action == 'LIST_RULES':
            return "iptables -L -n"
        else:
            return f"# Unknown iptables action: {action}"

    def _generate_firewalld_command(self, action: str, ip: str, port: Optional[int]) -> str:
        """Genera comando firewalld"""
        if action in ['BLOCK_IP', 'BLOCK_PORT']:
            return f"firewall-cmd --add-rich-rule='rule family=ipv4 source address={ip} drop'"
        elif action in ['ALLOW_IP_TEMP', 'ALLOW']:
            return f"firewall-cmd --add-rich-rule='rule family=ipv4 source address={ip} accept'"
        elif action == 'LIST_RULES':
            return "firewall-cmd --list-all"
        else:
            return f"# firewalld action {action} not implemented"

    def _generate_windows_command(self, action: str, ip: str, port: Optional[int]) -> str:
        """Genera comando Windows Firewall"""
        if action in ['BLOCK_IP', 'BLOCK_PORT']:
            return f"netsh advfirewall firewall add rule name='Block_{ip}' dir=in action=block remoteip={ip}"
        elif action in ['ALLOW_IP_TEMP', 'ALLOW']:
            return f"netsh advfirewall firewall add rule name='Allow_{ip}' dir=in action=allow remoteip={ip}"
        elif action == 'LIST_RULES':
            return "netsh advfirewall firewall show rule name=all"
        else:
            return f"# Windows firewall action {action} not implemented"

    def _generate_pf_command(self, action: str, ip: str, port: Optional[int]) -> str:
        """Genera comando pf (macOS)"""
        if action in ['BLOCK_IP', 'BLOCK_PORT']:
            return f"echo 'block in from {ip}' | pfctl -f -"
        elif action in ['ALLOW_IP_TEMP', 'ALLOW']:
            return f"echo 'pass in from {ip}' | pfctl -f -"
        elif action == 'LIST_RULES':
            return "pfctl -s rules"
        else:
            return f"# pf action {action} not implemented"

    def display_command_result_protobuf(self, command: firewall_commands_pb2.FirewallCommand,
                                        result: FirewallCommandResult):
        """Muestra el resultado de un comando protobuf en pantalla"""

        timestamp = time.strftime("%H:%M:%S", time.localtime())
        action_name = firewall_commands_pb2.CommandAction.Name(command.action)
        priority_name = firewall_commands_pb2.CommandPriority.Name(command.priority)

        if result.simulated:
            status_icon = "🔍"
            status_text = "SIMULATED (3 PUERTOS)"
            color = "\033[96m"  # Cyan
        elif result.success:
            status_icon = "✅"
            status_text = "EXECUTED (3 PUERTOS)"
            color = "\033[92m"  # Green
        else:
            status_icon = "❌"
            status_text = "FAILED (3 PUERTOS)"
            color = "\033[91m"  # Red

        reset_color = "\033[0m"

        print(f"\n{color}[{timestamp}] {status_icon} {status_text}{reset_color}")
        print(f"🎯 Action: {action_name}")
        print(f"🔗 Target: {command.target_ip}" + (f":{command.target_port}" if command.target_port > 0 else ""))
        print(f"⏱️  Duration: {command.duration_seconds}s")
        print(f"📝 Reason: {command.reason}")
        print(f"⚡ Priority: {priority_name}")
        print(f"🔧 Command: {result.firewall_command}")
        print(f"🔒 Dry Run: {command.dry_run}")
        print(f"📤 Confirmación enviada a dashboard (puerto {self.confirmations_output_port})")

        if command.rate_limit_rule:
            print(f"⚖️  Rate Limit: {command.rate_limit_rule}")

        if not result.simulated:
            print(f"⏱️  Execution Time: {result.execution_time:.3f}s")

        print("─" * 70)

    def display_command_result_json(self, command_data: Dict, result: FirewallCommandResult):
        """Muestra el resultado de un comando JSON en pantalla"""

        timestamp = time.strftime("%H:%M:%S", time.localtime())

        if result.simulated:
            status_icon = "🔍"
            status_text = "SIMULATED JSON (3 PUERTOS)"
            color = "\033[95m"  # Magenta
        elif result.success:
            status_icon = "✅"
            status_text = "EXECUTED JSON (3 PUERTOS)"
            color = "\033[92m"  # Green
        else:
            status_icon = "❌"
            status_text = "FAILED JSON (3 PUERTOS)"
            color = "\033[91m"  # Red

        reset_color = "\033[0m"

        print(f"\n{color}[{timestamp}] {status_icon} {status_text}{reset_color}")
        print(f"🎯 Action: {command_data.get('action', 'unknown')}")
        print(f"🔗 Target: {command_data.get('target_ip', 'unknown')}")
        print(f"⏱️  Duration: {command_data.get('duration_seconds', 0)}s")
        print(f"📝 Reason: {command_data.get('reason', 'N/A')}")
        print(f"⚡ Priority: {command_data.get('priority', 'N/A')}")
        print(f"🔧 Command: {result.firewall_command}")
        print(f"📤 Confirmación enviada a dashboard (puerto {self.confirmations_output_port})")

        if not result.simulated:
            print(f"⏱️  Execution Time: {result.execution_time:.3f}s")

        print("─" * 70)

    def get_statistics(self) -> Dict:
        """Retorna estadísticas del agente"""
        uptime = time.time() - self.stats['start_time']

        return {
            'uptime_seconds': uptime,
            'commands_received': self.stats['commands_received'],
            'commands_executed': self.stats['commands_executed'],
            'commands_simulated': self.stats['commands_simulated'],
            'confirmations_sent': self.stats['confirmations_sent'],
            'protobuf_commands': self.stats['protobuf_commands'],
            'json_commands': self.stats['json_commands'],
            'command_history_size': len(self.command_history),
            'system_info': self.system_info,
            'display_only_mode': self.display_only,
            'nuclear_enabled': self.nuclear_enabled,
            'protobuf_available': PROTOBUF_AVAILABLE,
            'config_file': self.config_file,
            'architecture': '3_ports',
            'configuration': {
                'commands_input_port': self.commands_input_port,
                'confirmations_output_port': self.confirmations_output_port,
                'dry_run_mode': self.dry_run_mode,
                'rate_limiting_enabled': self.rate_limiting['enabled'],
                'validation_enabled': self.validate_requests,
                'supported_actions': self.supported_actions
            }
        }

    def print_statistics(self):
        """Imprime estadísticas en pantalla"""
        stats = self.get_statistics()

        print("\n📊 Firewall Agent Statistics (3 PUERTOS)")
        print("═" * 60)
        print(f"📄 Config file: {stats['config_file'] or 'default'}")
        print(f"🏗️ Architecture: {stats['architecture']}")
        print(f"⏱️  Uptime: {stats['uptime_seconds']:.0f}s")
        print(f"📨 Commands Received: {stats['commands_received']}")
        print(f"✅ Commands Executed: {stats['commands_executed']}")
        print(f"🔍 Commands Simulated: {stats['commands_simulated']}")
        print(f"📤 Confirmations Sent: {stats['confirmations_sent']}")
        print(f"📦 Protobuf Commands: {stats['protobuf_commands']}")
        print(f"📄 JSON Commands: {stats['json_commands']}")
        print(f"📜 History Size: {stats['command_history_size']}")
        print(f"🔒 Display-Only Mode: {stats['display_only_mode']}")
        print(f"💣 Nuclear Enabled: {stats['nuclear_enabled']}")
        print(f"📦 Protobuf Available: {stats['protobuf_available']}")
        print(f"📡 Commands Input Port: {stats['configuration']['commands_input_port']}")
        print(f"📤 Confirmations Output Port: {stats['configuration']['confirmations_output_port']}")

    def cleanup(self):
        """Limpia recursos y guarda estado"""
        # Guardar estado final
        if self.config['persistence']['save_state']:
            self._save_state()

        if self.command_socket:
            self.command_socket.close()
        if self.confirmation_socket:
            self.confirmation_socket.close()
        if self.context:
            self.context.term()


def main():
    """Función principal actualizada para 3 puertos"""
    import sys
    import argparse

    # Configurar logging básico hasta cargar configuración
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Argumentos de línea de comandos
    parser = argparse.ArgumentParser(description='Simple Firewall Agent (3 Puertos)')
    parser.add_argument('config_file', nargs='?',
                        default='simple_firewall_agent_config.json',
                        help='Archivo de configuración JSON')
    parser.add_argument('--apply-real', action='store_true',
                        help='DANGEROUS: Forzar modo real (ignora configuración JSON)')

    args = parser.parse_args()

    # Crear agente con configuración JSON actualizada
    try:
        agent = SimpleFirewallAgent(config_file=args.config_file)
    except Exception as e:
        print(f"❌ Error inicializando agente: {e}")
        return 1

    # Override nuclear si se especifica en línea de comandos
    if args.apply_real:
        print("\n⚠️  WARNING: REAL MODE FORCED!")
        print("🚨 Ignorando configuración JSON - aplicará reglas reales!")
        confirm = input("Type 'CONFIRM' to proceed: ")
        if confirm != 'CONFIRM':
            print("❌ Aborted")
            return 1
        agent.display_only = False
        agent.nuclear_enabled = True

    # Mostrar configuración cargada
    print(f"\n🔧 Configuración 3 puertos cargada desde: {args.config_file}")
    print(f"   📡 Puerto comandos (dashboard→firewall): {agent.commands_input_port}")
    print(f"   📤 Puerto confirmaciones (firewall→dashboard): {agent.confirmations_output_port}")
    print(f"   🔒 Dry run mode: {agent.dry_run_mode}")
    print(f"   💣 Nuclear habilitado: {agent.nuclear_enabled}")
    print(f"   🔍 Display only: {agent.display_only}")
    print(f"   🔧 Validación: {agent.validate_requests}")
    print(f"   ⚡ Rate limiting: {agent.rate_limiting['enabled']}")
    print(f"   📝 Logging: {agent.config['logging']['level']}")

    if not PROTOBUF_AVAILABLE:
        print("\n⚠️  WARNING: Protobuf not available!")
        print("🔄 Will fall back to JSON mode")

    try:
        agent.start()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        logger.error("Error fatal: %s", e)
        return 1
    finally:
        agent.print_statistics()

    return 0


if __name__ == "__main__":
    sys.exit(main())