#!/usr/bin/env python3
"""
Simple Firewall Agent para Upgraded-Happiness
ACTUALIZADO: Display-Only por DEFECTO - NO toca el firewall del host
Usa archivos de configuración JSON
Puerto 5561 (entrada) - Puerto 5560 (salida confirmaciones)
"""

import zmq
import json
import time
import logging
import threading
import argparse
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from simple_system_detection import SimpleSystemDetector

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
    """Agente de firewall simple con soporte protobuf real"""

    def __init__(self, port=5561, display_only=True):
        self.port = port
        self.display_only = display_only
        self.running = False

        # Detección del sistema
        self.detector = SimpleSystemDetector()
        self.system_info = self.detector.get_system_summary()

        # ZeroMQ setup
        self.context = zmq.Context()
        self.command_socket = None
        self.response_socket = None

        # Estadísticas
        self.stats = {
            'commands_received': 0,
            'commands_executed': 0,
            'commands_simulated': 0,
            'batches_received': 0,
            'batches_processed': 0,
            'protobuf_commands': 0,
            'json_commands': 0,
            'start_time': time.time()
        }

        # Log de comandos ejecutados
        self.command_history = []

        logger.info("SimpleFirewallAgent initialized (PROTOBUF REAL)")
        logger.info("Node: %s", self.system_info['node_id'])
        logger.info("Firewall: %s (%s)", self.system_info['firewall_type'], self.system_info['firewall_status'])
        logger.info("Display-only mode: %s", self.display_only)
        logger.info("Protobuf available: %s", PROTOBUF_AVAILABLE)

    def start(self):
        """Inicia el agente de firewall"""
        try:
            # Configurar sockets ZeroMQ
            self.command_socket = self.context.socket(zmq.PULL)
            self.command_socket.bind(f"tcp://*:{self.port}")

            # Socket para respuestas/confirmaciones
            self.response_socket = self.context.socket(zmq.PUSH)
            self.response_socket.connect("tcp://localhost:5560")

            self.running = True

            print(f"\n🔥 Simple Firewall Agent Started (PROTOBUF REAL)")
            print(f"📡 Listening on port {self.port}")
            print(f"📤 Responses to port 5560")
            print(f"🖥️  System: {self.system_info['os_name']} {self.system_info['os_version']}")
            print(f"🛡️  Firewall: {self.system_info['firewall_type']} ({self.system_info['firewall_status']})")
            print(f"⚠️  Mode: {'DISPLAY-ONLY (Safe)' if self.display_only else 'LIVE (Dangerous)'}")
            print(f"📦 Protobuf: {'✅ Available' if PROTOBUF_AVAILABLE else '❌ Not available'}")
            print(f"🆔 Node ID: {self.system_info['node_id']}")
            print("=" * 70)

            # Main loop
            self.listen_for_commands()

        except Exception as e:
            logger.error("Error starting firewall agent: %s", e)
            raise
        finally:
            self.cleanup()

    def listen_for_commands(self):
        """Loop principal - escucha comandos entrantes (protobuf primero)"""
        logger.info("Listening for firewall commands (protobuf batch & individual)...")

        try:
            while self.running:
                try:
                    # Recibir comando (con timeout)
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
        """Procesa un mensaje de comando recibido (protobuf o JSON)"""
        try:
            self.stats['commands_received'] += 1

            # Intentar parsear como FirewallCommandBatch PRIMERO
            if PROTOBUF_AVAILABLE:
                try:
                    batch = firewall_commands_pb2.FirewallCommandBatch()
                    batch.ParseFromString(message)

                    self.stats['batches_received'] += 1
                    self.stats['protobuf_commands'] += 1
                    logger.info("Received PROTOBUF BATCH: %s (%d commands)",
                                batch.batch_id, len(batch.commands))

                    # Procesar lote de comandos
                    batch_result = self.process_command_batch(batch)
                    self.display_batch_result(batch, batch_result)

                    # Enviar respuesta del lote
                    self.send_batch_response(batch, batch_result)

                    return

                except Exception as e:
                    logger.debug("Error parsing batch protobuf: %s", e)

                # Intentar parsear como comando individual
                try:
                    command = firewall_commands_pb2.FirewallCommand()
                    command.ParseFromString(message)

                    self.stats['protobuf_commands'] += 1
                    logger.info("Received PROTOBUF COMMAND: %s", command.command_id)

                    # Procesar comando individual
                    result = self.process_protobuf_command(command)
                    self.display_command_result_protobuf(command, result)

                    # Enviar confirmación
                    self.send_command_confirmation(command, result)

                    return

                except Exception as e:
                    logger.debug("Error parsing command protobuf: %s", e)

            # Fallback a JSON
            try:
                command_json = json.loads(message.decode('utf-8'))
                self.stats['json_commands'] += 1
                logger.info("Received JSON command: %s", command_json.get('command_id', 'unknown'))

                # Procesar comando JSON
                result = self.process_json_command(command_json)
                self.display_command_result_json(command_json, result)

            except json.JSONDecodeError as e:
                logger.error("Invalid message format (not protobuf or JSON): %s", e)
            except Exception as e:
                logger.error("Error processing JSON command: %s", e)

        except Exception as e:
            logger.error("Error processing command message: %s", e)

    def process_command_batch(self, batch: firewall_commands_pb2.FirewallCommandBatch) -> Dict:
        """Procesa un lote de comandos protobuf"""

        start_time = time.time()
        results = []
        successful_commands = 0
        failed_commands = 0

        logger.info("Processing batch %s with %d commands", batch.batch_id, len(batch.commands))

        # Validar que el lote sea para este nodo
        if batch.target_node_id != self.system_info['node_id'] and batch.target_node_id != 'unknown':
            logger.warning("Batch target node %s != this node %s",
                           batch.target_node_id, self.system_info['node_id'])

        # Validar SO
        if batch.so_identifier != self.system_info['firewall_type'] and batch.so_identifier != 'unknown':
            logger.warning("Batch SO %s != this system %s",
                           batch.so_identifier, self.system_info['firewall_type'])

        # Procesar cada comando del lote
        for command in batch.commands:
            # Aplicar dry_run_all si está configurado
            if batch.dry_run_all:
                command.dry_run = True

            # Procesar comando individual
            result = self.process_protobuf_command(command)
            results.append(result)

            if result.success:
                successful_commands += 1
            else:
                failed_commands += 1

        execution_time = time.time() - start_time

        # Actualizar estadísticas
        self.stats['batches_processed'] += 1
        self.stats['commands_executed'] += successful_commands
        self.stats['commands_simulated'] += len([r for r in results if r.simulated])

        # Crear resultado del lote
        batch_result = {
            'batch_id': batch.batch_id,
            'success': failed_commands == 0,
            'total_commands': len(batch.commands),
            'successful_commands': successful_commands,
            'failed_commands': failed_commands,
            'execution_time': execution_time,
            'generated_by': batch.generated_by,
            'dry_run_all': batch.dry_run_all,
            'results': results
        }

        # Guardar en historial
        self.command_history.append({
            'batch': {
                'batch_id': batch.batch_id,
                'target_node_id': batch.target_node_id,
                'so_identifier': batch.so_identifier,
                'generated_by': batch.generated_by,
                'command_count': len(batch.commands)
            },
            'result': batch_result,
            'timestamp': time.time(),
            'protocol': 'protobuf_batch'
        })

        return batch_result

    def process_protobuf_command(self, command: firewall_commands_pb2.FirewallCommand) -> FirewallCommandResult:
        """Procesa un comando protobuf individual"""

        # Validar comando
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

        # Ejecutar comando
        if self.display_only or command.dry_run:
            return self.simulate_protobuf_command(command)
        else:
            return self.apply_real_protobuf_command(command)

    def validate_protobuf_command(self, command: firewall_commands_pb2.FirewallCommand) -> bool:
        """Valida un comando protobuf antes de ejecutarlo"""

        # Validaciones básicas
        if not command.target_ip:
            logger.warning("Command missing target_ip")
            return False

        # Validar acción usando enum
        if command.action not in [
            firewall_commands_pb2.BLOCK_IP,
            firewall_commands_pb2.UNBLOCK_IP,
            firewall_commands_pb2.BLOCK_PORT,
            firewall_commands_pb2.UNBLOCK_PORT,
            firewall_commands_pb2.RATE_LIMIT_IP,
            firewall_commands_pb2.ALLOW_IP_TEMP,
            firewall_commands_pb2.FLUSH_RULES,
            firewall_commands_pb2.LIST_RULES,
            firewall_commands_pb2.BACKUP_RULES,
            firewall_commands_pb2.RESTORE_RULES
        ]:
            logger.warning("Unknown action: %s", command.action)
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

        # Validar comando JSON
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

        # Generar comando específico del SO
        firewall_cmd = self.generate_firewall_command_from_json(command_data)

        if self.display_only or dry_run:
            result = FirewallCommandResult(
                command_id=command_id,
                success=True,
                executed=False,
                simulated=True,
                firewall_command=firewall_cmd,
                message="SIMULATED: Would execute firewall command (JSON)",
                execution_time=0.001
            )
        else:
            # Ejecutar comando real desde JSON
            result = self.execute_real_command_from_json(command_data, firewall_cmd)

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
        """Genera comando iptables"""
        if action in ['BLOCK_IP', 'BLOCK_PORT']:
            return f"iptables -A INPUT -s {ip} -j DROP"
        elif action == 'RATE_LIMIT_IP':
            return f"iptables -A INPUT -s {ip} -m limit --limit 10/min -j ACCEPT"
        elif action in ['ALLOW_IP_TEMP', 'ALLOW']:
            return f"iptables -A INPUT -s {ip} -j ACCEPT"
        elif action in ['UNBLOCK_IP', 'UNBLOCK_PORT']:
            return f"iptables -D INPUT -s {ip} -j DROP"
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

    def display_batch_result(self, batch: firewall_commands_pb2.FirewallCommandBatch, batch_result: Dict):
        """Muestra el resultado de un lote de comandos"""

        timestamp = time.strftime("%H:%M:%S", time.localtime())

        if batch_result['success']:
            status_icon = "✅"
            status_text = "BATCH SUCCESS"
            color = "\033[92m"  # Green
        else:
            status_icon = "❌"
            status_text = "BATCH FAILED"
            color = "\033[91m"  # Red

        reset_color = "\033[0m"

        print(f"\n{color}[{timestamp}] {status_icon} {status_text} (PROTOBUF){reset_color}")
        print(f"📦 Batch ID: {batch.batch_id}")
        print(f"🎯 Target Node: {batch.target_node_id}")
        print(f"🖥️  SO: {batch.so_identifier}")
        print(f"👤 Generated by: {batch.generated_by}")
        print(f"📋 Commands: {batch_result['total_commands']}")
        print(f"✅ Successful: {batch_result['successful_commands']}")
        print(f"❌ Failed: {batch_result['failed_commands']}")
        print(f"⏱️  Total Time: {batch_result['execution_time']:.3f}s")
        print(f"🔒 Dry Run All: {batch.dry_run_all}")
        print(f"📝 Description: {batch.description}")
        print("═" * 70)

    def display_command_result_protobuf(self, command: firewall_commands_pb2.FirewallCommand,
                                        result: FirewallCommandResult):
        """Muestra el resultado de un comando protobuf en pantalla"""

        timestamp = time.strftime("%H:%M:%S", time.localtime())
        action_name = firewall_commands_pb2.CommandAction.Name(command.action)
        priority_name = firewall_commands_pb2.CommandPriority.Name(command.priority)

        if result.simulated:
            status_icon = "🔍"
            status_text = "SIMULATED (PROTOBUF)"
            color = "\033[96m"  # Cyan
        elif result.success:
            status_icon = "✅"
            status_text = "EXECUTED (PROTOBUF)"
            color = "\033[92m"  # Green
        else:
            status_icon = "❌"
            status_text = "FAILED (PROTOBUF)"
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

        if command.rate_limit_rule:
            print(f"⚖️  Rate Limit: {command.rate_limit_rule}")

        if command.extra_params:
            print(f"🔧 Extra Params: {dict(command.extra_params)}")

        if not result.simulated:
            print(f"⏱️  Execution Time: {result.execution_time:.3f}s")

        print("─" * 70)

    def display_command_result_json(self, command_data: Dict, result: FirewallCommandResult):
        """Muestra el resultado de un comando JSON en pantalla"""

        timestamp = time.strftime("%H:%M:%S", time.localtime())

        if result.simulated:
            status_icon = "🔍"
            status_text = "SIMULATED (JSON)"
            color = "\033[95m"  # Magenta
        elif result.success:
            status_icon = "✅"
            status_text = "EXECUTED (JSON)"
            color = "\033[92m"  # Green
        else:
            status_icon = "❌"
            status_text = "FAILED (JSON)"
            color = "\033[91m"  # Red

        reset_color = "\033[0m"

        print(f"\n{color}[{timestamp}] {status_icon} {status_text}{reset_color}")
        print(f"🎯 Action: {command_data.get('action', 'unknown')}")
        print(f"🔗 Target: {command_data.get('target_ip', 'unknown')}")
        print(f"⏱️  Duration: {command_data.get('duration_seconds', 0)}s")
        print(f"📝 Reason: {command_data.get('reason', 'N/A')}")
        print(f"⚡ Priority: {command_data.get('priority', 'N/A')}")
        print(f"🔧 Command: {result.firewall_command}")

        if not result.simulated:
            print(f"⏱️  Execution Time: {result.execution_time:.3f}s")

        print("─" * 70)

    def send_batch_response(self, batch: firewall_commands_pb2.FirewallCommandBatch, batch_result: Dict):
        """Envía respuesta de lote procesado de vuelta al puerto 5560"""
        if not self.response_socket or not PROTOBUF_AVAILABLE:
            return

        try:
            # Crear respuesta usando FirewallResponse
            response = firewall_commands_pb2.FirewallResponse()
            response.batch_id = batch.batch_id
            response.node_id = self.system_info['node_id']
            response.timestamp = int(time.time() * 1000)
            response.success = batch_result['success']
            response.message = f"Batch processed: {batch_result['successful_commands']}/{batch_result['total_commands']} successful"
            response.execution_time = batch_result['execution_time']
            response.total_commands = batch_result['total_commands']
            response.successful_commands = batch_result['successful_commands']
            response.failed_commands = batch_result['failed_commands']

            # Enviar respuesta
            message = response.SerializeToString()
            self.response_socket.send(message)

            logger.info(f"📤 Sent batch response for {batch.batch_id} to port 5560")

        except Exception as e:
            logger.error(f"Error sending batch response: {e}")

    def send_command_confirmation(self, command: firewall_commands_pb2.FirewallCommand, result: FirewallCommandResult):
        """Envía confirmación de comando ejecutado usando NetworkEvent"""
        if not self.response_socket or not PROTOBUF_AVAILABLE:
            return

        try:
            # Crear evento de confirmación usando NetworkEvent
            confirmation = network_event_extended_fixed_pb2.NetworkEvent()
            confirmation.event_id = f"fw_confirm_{command.command_id}"
            confirmation.event_type = "firewall_command_result"
            confirmation.agent_id = self.system_info['node_id']
            confirmation.source_ip = command.target_ip
            confirmation.description = f"Firewall command {firewall_commands_pb2.CommandAction.Name(command.action)} - {result.message}"
            confirmation.timestamp = int(time.time() * 1000)

            # Usar anomaly_score para indicar si fue exitoso (1.0 = éxito, 0.0 = fallo)
            confirmation.anomaly_score = 1.0 if result.success else 0.0

            # Usar risk_score para indicar si fue simulado (0.5 = simulado, 1.0 = real)
            confirmation.risk_score = 0.5 if result.simulated else 1.0

            # Agregar información del sistema
            confirmation.so_identifier = self.system_info['firewall_type']
            confirmation.node_hostname = self.system_info['node_id']
            confirmation.os_version = self.system_info['os_version']
            confirmation.firewall_status = self.system_info['firewall_status']
            confirmation.agent_version = "firewall_agent_1.0"

            # Enviar confirmación
            message = confirmation.SerializeToString()
            self.response_socket.send(message)

            logger.info(f"📤 Sent confirmation for command {command.command_id} to port 5560")

        except Exception as e:
            logger.error(f"Error sending confirmation: {e}")

    def get_statistics(self) -> Dict:
        """Retorna estadísticas del agente"""
        uptime = time.time() - self.stats['start_time']

        return {
            'uptime_seconds': uptime,
            'commands_received': self.stats['commands_received'],
            'commands_executed': self.stats['commands_executed'],
            'commands_simulated': self.stats['commands_simulated'],
            'batches_received': self.stats['batches_received'],
            'batches_processed': self.stats['batches_processed'],
            'protobuf_commands': self.stats['protobuf_commands'],
            'json_commands': self.stats['json_commands'],
            'command_history_size': len(self.command_history),
            'system_info': self.system_info,
            'display_only_mode': self.display_only,
            'protobuf_available': PROTOBUF_AVAILABLE
        }

    def print_statistics(self):
        """Imprime estadísticas en pantalla"""
        stats = self.get_statistics()

        print("\n📊 Firewall Agent Statistics (PROTOBUF REAL)")
        print("═" * 60)
        print(f"⏱️  Uptime: {stats['uptime_seconds']:.0f}s")
        print(f"📨 Commands Received: {stats['commands_received']}")
        print(f"📦 Batches Received: {stats['batches_received']}")
        print(f"📋 Batches Processed: {stats['batches_processed']}")
        print(f"✅ Commands Executed: {stats['commands_executed']}")
        print(f"🔍 Commands Simulated: {stats['commands_simulated']}")
        print(f"📦 Protobuf Commands: {stats['protobuf_commands']}")
        print(f"📄 JSON Commands: {stats['json_commands']}")
        print(f"📜 History Size: {stats['command_history_size']}")
        print(f"🔒 Display-Only Mode: {stats['display_only_mode']}")
        print(f"📦 Protobuf Available: {stats['protobuf_available']}")

    def cleanup(self):
        """Limpia recursos"""
        if self.command_socket:
            self.command_socket.close()
        if self.response_socket:
            self.response_socket.close()
        if self.context:
            self.context.term()


# Función de utilidad para testing
def create_test_protobuf_batch(target_node_id="test_node", num_commands=3) -> bytes:
    """Crea un lote de comandos de prueba en formato protobuf"""
    if not PROTOBUF_AVAILABLE:
        return b""

    # Crear lote
    batch = firewall_commands_pb2.FirewallCommandBatch()
    batch.batch_id = f'test_batch_{int(time.time())}'
    batch.target_node_id = target_node_id
    batch.so_identifier = 'iptables'
    batch.timestamp = int(time.time() * 1000)
    batch.generated_by = 'test_script'
    batch.dry_run_all = True
    batch.description = 'Test batch from script'
    batch.confidence_score = 0.8
    batch.expected_execution_time = num_commands * 2

    # Crear comandos
    for i in range(num_commands):
        command = batch.commands.add()
        command.command_id = f'test_cmd_{i}_{int(time.time())}'
        command.action = firewall_commands_pb2.BLOCK_IP
        command.target_ip = f'192.168.1.{100 + i}'
        command.target_port = 0
        command.duration_seconds = 3600
        command.reason = f'Test command {i}'
        command.priority = firewall_commands_pb2.HIGH
        command.dry_run = True

    return batch.SerializeToString()


def create_test_json_command(action="BLOCK_IP", target_ip="192.168.1.100") -> str:
    """Crea un comando de prueba en formato JSON (fallback)"""
    command = {
        'command_id': f'test_{int(time.time())}',
        'action': action,
        'target_ip': target_ip,
        'target_port': None,
        'duration_seconds': 3600,
        'reason': 'Test command from script',
        'priority': 'MEDIUM',
        'dry_run': True,
        'timestamp': time.time(),
        'generated_by': 'test_script'
    }

    return json.dumps(command)


def main():
    """Función principal"""
    import sys
    import argparse

    # Configurar logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Argumentos de línea de comandos
    parser = argparse.ArgumentParser(description='Simple Firewall Agent (PROTOBUF REAL)')
    parser.add_argument('--port', type=int, default=5561, help='Port to listen on')
    parser.add_argument('--apply-real', action='store_true',
                        help='DANGEROUS: Apply real firewall rules')

    args = parser.parse_args()

    # Crear y ejecutar agente
    display_only = not args.apply_real

    if args.apply_real:
        print("\n⚠️  WARNING: REAL MODE ENABLED!")
        print("🚨 This will apply actual firewall rules!")
        confirm = input("Type 'CONFIRM' to proceed: ")
        if confirm != 'CONFIRM':
            print("❌ Aborted")
            sys.exit(1)

    if not PROTOBUF_AVAILABLE:
        print("\n⚠️  WARNING: Protobuf not available!")
        print("🔄 Will fall back to JSON mode")

    agent = SimpleFirewallAgent(port=args.port, display_only=display_only)

    try:
        agent.start()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    finally:
        agent.print_statistics()


if __name__ == "__main__":
    main()