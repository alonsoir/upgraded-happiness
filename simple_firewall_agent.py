#!/usr/bin/env python3
"""
Simple Firewall Agent para Upgraded-Happiness
Modo display-only por defecto - muestra comandos sin aplicarlos.
"""

import zmq
import json
import time
import logging
import threading
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from simple_system_detection import SimpleSystemDetector

logger = logging.getLogger(__name__)


@dataclass
class FirewallCommand:
    """Comando de firewall simplificado"""
    command_id: str
    action: str  # BLOCK_IP, RATE_LIMIT, ALLOW
    target_ip: str
    target_port: Optional[int]
    duration_seconds: int
    reason: str
    priority: str  # LOW, MEDIUM, HIGH, CRITICAL
    dry_run: bool
    timestamp: float
    generated_by: str  # rule_engine, human, etc


class SimpleFirewallAgent:
    """Agente de firewall simple con modo display-only"""

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
            'start_time': time.time()
        }

        # Log de comandos ejecutados
        self.command_history = []

        logger.info("SimpleFirewallAgent initialized")
        logger.info("Node: %s", self.system_info['node_id'])
        logger.info("Firewall: %s (%s)", self.system_info['firewall_type'], self.system_info['firewall_status'])
        logger.info("Display-only mode: %s", self.display_only)

    def start(self):
        """Inicia el agente de firewall"""
        try:
            # Configurar sockets ZeroMQ
            self.command_socket = self.context.socket(zmq.PULL)
            self.command_socket.bind(f"tcp://*:{self.port}")

            # Socket para respuestas (opcional, para futuro)
            self.response_socket = self.context.socket(zmq.PUSH)
            self.response_socket.connect("tcp://localhost:5560")

            self.running = True

            print(f"\n🔥 Simple Firewall Agent Started")
            print(f"📡 Listening on port {self.port}")
            print(f"🖥️  System: {self.system_info['os_name']} {self.system_info['os_version']}")
            print(f"🛡️  Firewall: {self.system_info['firewall_type']} ({self.system_info['firewall_status']})")
            print(f"⚠️  Mode: {'DISPLAY-ONLY (Safe)' if self.display_only else 'LIVE (Dangerous)'}")
            print(f"🆔 Node ID: {self.system_info['node_id']}")
            print("=" * 60)

            # Main loop
            self.listen_for_commands()

        except Exception as e:
            logger.error("Error starting firewall agent: %s", e)
            raise
        finally:
            self.cleanup()

    def listen_for_commands(self):
        """Loop principal - escucha comandos entrantes"""
        logger.info("Listening for firewall commands...")

        try:
            while self.running:
                try:
                    # Recibir comando (con timeout)
                    if self.command_socket.poll(1000):  # 1 segundo timeout
                        message = self.command_socket.recv_string()
                        self.process_command_message(message)

                except zmq.Again:
                    continue  # Timeout - continuar
                except Exception as e:
                    logger.error("Error receiving command: %s", e)
                    time.sleep(1)

        except KeyboardInterrupt:
            print("\n\n🛑 Stopping firewall agent...")
            self.running = False

    def process_command_message(self, message: str):
        """Procesa un mensaje de comando recibido"""
        try:
            self.stats['commands_received'] += 1

            # Parsear comando JSON
            command_data = json.loads(message)
            command = FirewallCommand(**command_data)

            logger.info("Received command: %s", command.command_id)

            # Validar comando
            if not self.validate_command(command):
                logger.warning("Invalid command rejected: %s", command.command_id)
                return

            # Procesar comando
            result = self.execute_command(command)

            # Mostrar resultado
            self.display_command_result(command, result)

            # Guardar en historial
            self.command_history.append({
                'command': asdict(command),
                'result': result,
                'timestamp': time.time()
            })

            # Limitar historial
            if len(self.command_history) > 100:
                self.command_history = self.command_history[-50:]  # Mantener últimos 50

        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in command: %s", e)
        except Exception as e:
            logger.error("Error processing command: %s", e)

    def validate_command(self, command: FirewallCommand) -> bool:
        """Valida un comando antes de ejecutarlo"""

        # Validaciones básicas
        if not command.target_ip:
            logger.warning("Command missing target_ip")
            return False

        if command.action not in ['BLOCK_IP', 'RATE_LIMIT', 'ALLOW', 'UNBLOCK_IP']:
            logger.warning("Unknown action: %s", command.action)
            return False

        if command.duration_seconds < 0:
            logger.warning("Invalid duration")
            return False

        # Validar IP format (básico)
        try:
            parts = command.target_ip.split('.')
            if len(parts) != 4 or not all(0 <= int(p) <= 255 for p in parts):
                raise ValueError("Invalid IP")
        except (ValueError, AttributeError):
            logger.warning("Invalid IP format: %s", command.target_ip)
            return False

        return True

    def execute_command(self, command: FirewallCommand) -> Dict:
        """Ejecuta (o simula) un comando de firewall"""

        if self.display_only or command.dry_run:
            return self.simulate_command(command)
        else:
            return self.apply_real_command(command)

    def simulate_command(self, command: FirewallCommand) -> Dict:
        """Simula la ejecución de un comando"""
        self.stats['commands_simulated'] += 1

        # Generar comando específico del SO
        firewall_cmd = self.generate_firewall_command(command)

        return {
            'success': True,
            'executed': False,
            'simulated': True,
            'firewall_command': firewall_cmd,
            'message': "SIMULATED: Would execute firewall command",
            'execution_time': 0.001  # Simulación es instantánea
        }

    def apply_real_command(self, command: FirewallCommand) -> Dict:
        """Aplica comando real al firewall (¡PELIGROSO!)"""
        self.stats['commands_executed'] += 1

        # IMPORTANTE: Este método REALMENTE modifica el firewall
        logger.warning("APPLYING REAL FIREWALL COMMAND: %s %s", command.action, command.target_ip)

        firewall_cmd = self.generate_firewall_command(command)

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
                return {
                    'success': True,
                    'executed': True,
                    'simulated': False,
                    'firewall_command': firewall_cmd,
                    'message': f"Successfully executed: {firewall_cmd}",
                    'execution_time': execution_time,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            else:
                return {
                    'success': False,
                    'executed': False,
                    'simulated': False,
                    'firewall_command': firewall_cmd,
                    'message': f"Command failed: {result.stderr}",
                    'execution_time': execution_time,
                    'error_code': result.returncode
                }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'executed': False,
                'message': "Command timed out",
                'firewall_command': firewall_cmd
            }
        except Exception as e:
            return {
                'success': False,
                'executed': False,
                'message': f"Execution error: {str(e)}",
                'firewall_command': firewall_cmd
            }

    def generate_firewall_command(self, command: FirewallCommand) -> str:
        """Genera el comando específico del firewall según el SO"""

        firewall_type = self.system_info['firewall_type']
        action = command.action
        target_ip = command.target_ip
        target_port = command.target_port

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
        if action == 'BLOCK_IP':
            return f"ufw deny from {ip}"
        elif action == 'RATE_LIMIT':
            return f"ufw limit from {ip}"
        elif action == 'ALLOW':
            return f"ufw allow from {ip}"
        elif action == 'UNBLOCK_IP':
            return f"ufw delete deny from {ip}"
        else:
            return f"# Unknown UFW action: {action}"

    def _generate_iptables_command(self, action: str, ip: str, port: Optional[int]) -> str:
        """Genera comando iptables"""
        if action == 'BLOCK_IP':
            return f"iptables -A INPUT -s {ip} -j DROP"
        elif action == 'RATE_LIMIT':
            return f"iptables -A INPUT -s {ip} -m limit --limit 10/min -j ACCEPT"
        elif action == 'ALLOW':
            return f"iptables -A INPUT -s {ip} -j ACCEPT"
        elif action == 'UNBLOCK_IP':
            return f"iptables -D INPUT -s {ip} -j DROP"
        else:
            return f"# Unknown iptables action: {action}"

    def _generate_firewalld_command(self, action: str, ip: str, port: Optional[int]) -> str:
        """Genera comando firewalld"""
        if action == 'BLOCK_IP':
            return f"firewall-cmd --add-rich-rule='rule family=ipv4 source address={ip} drop'"
        elif action == 'ALLOW':
            return f"firewall-cmd --add-rich-rule='rule family=ipv4 source address={ip} accept'"
        else:
            return f"# firewalld action {action} not implemented"

    def _generate_windows_command(self, action: str, ip: str, port: Optional[int]) -> str:
        """Genera comando Windows Firewall"""
        if action == 'BLOCK_IP':
            return f"netsh advfirewall firewall add rule name='Block_{ip}' dir=in action=block remoteip={ip}"
        elif action == 'ALLOW':
            return f"netsh advfirewall firewall add rule name='Allow_{ip}' dir=in action=allow remoteip={ip}"
        else:
            return f"# Windows firewall action {action} not implemented"

    def _generate_pf_command(self, action: str, ip: str, port: Optional[int]) -> str:
        """Genera comando pf (macOS)"""
        if action == 'BLOCK_IP':
            return f"echo 'block in from {ip}' | pfctl -f -"
        elif action == 'ALLOW':
            return f"echo 'pass in from {ip}' | pfctl -f -"
        else:
            return f"# pf action {action} not implemented"

    def display_command_result(self, command: FirewallCommand, result: Dict):
        """Muestra el resultado de un comando en pantalla"""

        # Header con timestamp
        timestamp = time.strftime("%H:%M:%S", time.localtime())

        if result.get('simulated', False):
            status_icon = "🔍"
            status_text = "SIMULATED"
            color = "\033[96m"  # Cyan
        elif result.get('success', False):
            status_icon = "✅"
            status_text = "EXECUTED"
            color = "\033[92m"  # Green
        else:
            status_icon = "❌"
            status_text = "FAILED"
            color = "\033[91m"  # Red

        reset_color = "\033[0m"

        print(f"\n{color}[{timestamp}] {status_icon} {status_text}{reset_color}")
        print(f"🎯 Action: {command.action}")
        print(f"🔗 Target: {command.target_ip}" + (f":{command.target_port}" if command.target_port else ""))
        print(f"⏱️  Duration: {command.duration_seconds}s")
        print(f"📝 Reason: {command.reason}")
        print(f"⚡ Priority: {command.priority}")
        print(f"🔧 Command: {result.get('firewall_command', 'N/A')}")

        if not result.get('simulated', False):
            exec_time = result.get('execution_time', 0)
            print(f"⏱️  Execution Time: {exec_time:.3f}s")

        print("─" * 60)

    def get_statistics(self) -> Dict:
        """Retorna estadísticas del agente"""
        uptime = time.time() - self.stats['start_time']

        return {
            'uptime_seconds': uptime,
            'commands_received': self.stats['commands_received'],
            'commands_executed': self.stats['commands_executed'],
            'commands_simulated': self.stats['commands_simulated'],
            'command_history_size': len(self.command_history),
            'system_info': self.system_info,
            'display_only_mode': self.display_only
        }

    def print_statistics(self):
        """Imprime estadísticas en pantalla"""
        stats = self.get_statistics()

        print("\n📊 Firewall Agent Statistics")
        print("═" * 40)
        print(f"⏱️  Uptime: {stats['uptime_seconds']:.0f}s")
        print(f"📨 Commands Received: {stats['commands_received']}")
        print(f"✅ Commands Executed: {stats['commands_executed']}")
        print(f"🔍 Commands Simulated: {stats['commands_simulated']}")
        print(f"📜 History Size: {stats['command_history_size']}")
        print(f"🔒 Display-Only Mode: {stats['display_only_mode']}")

    def cleanup(self):
        """Limpia recursos"""
        if self.command_socket:
            self.command_socket.close()
        if self.response_socket:
            self.response_socket.close()
        if self.context:
            self.context.term()


# Función de utilidad para testing
def create_test_command(action="BLOCK_IP", target_ip="192.168.1.100") -> str:
    """Crea un comando de prueba en formato JSON"""
    command = {
        'command_id': f'test_{int(time.time())}',
        'action': action,
        'target_ip': target_ip,
        'target_port': None,
        'duration_seconds': 3600,
        'reason': 'Test command from rule engine',
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
    parser = argparse.ArgumentParser(description='Simple Firewall Agent')
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

    agent = SimpleFirewallAgent(port=args.port, display_only=display_only)

    try:
        agent.start()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    finally:
        agent.print_statistics()


if __name__ == "__main__":
    main()