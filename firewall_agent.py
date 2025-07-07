#!/usr/bin/env python3
"""
🔥 Firewall Agent - Receptor de comandos del puerto 5561
Recibe comandos JSON del dashboard y los aplica al firewall local
"""

import json
import time
import threading
import zmq
import subprocess
import logging
import os
import platform
import socket
from datetime import datetime, timedelta
from collections import deque, defaultdict

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class FirewallRule:
    """Representa una regla de firewall aplicada"""

    def __init__(self, command_data):
        self.command_id = command_data.get('command_id')
        self.action = command_data.get('action')
        self.target_ip = command_data.get('target_ip')
        self.source_agent = command_data.get('source_agent')
        self.reason = command_data.get('reason')
        self.rule_data = command_data.get('firewall_rule', {})
        self.metadata = command_data.get('metadata', {})
        self.applied_time = datetime.now()
        self.duration = self.rule_data.get('duration', '1h')
        self.priority = self.rule_data.get('priority', 'medium')
        self.rule_type = self.rule_data.get('rule_type', 'iptables')
        self.command = self.rule_data.get('command', '')
        self.is_active = False
        self.actual_commands = []  # Comandos reales ejecutados

    def get_expiry_time(self):
        """Calcular tiempo de expiración"""
        duration_map = {
            '5m': 5 * 60,
            '15m': 15 * 60,
            '30m': 30 * 60,
            '1h': 60 * 60,
            '6h': 6 * 60 * 60,
            '12h': 12 * 60 * 60,
            '24h': 24 * 60 * 60,
            'permanent': None
        }

        duration_seconds = duration_map.get(self.duration, 3600)
        if duration_seconds is None:
            return None  # Permanente

        return self.applied_time + timedelta(seconds=duration_seconds)

    def is_expired(self):
        """Verificar si la regla ha expirado"""
        expiry_time = self.get_expiry_time()
        if expiry_time is None:
            return False  # Permanente
        return datetime.now() > expiry_time

    def to_dict(self):
        """Convertir a diccionario para logging"""
        return {
            'command_id': self.command_id,
            'action': self.action,
            'target_ip': self.target_ip,
            'applied_time': self.applied_time.isoformat(),
            'duration': self.duration,
            'priority': self.priority,
            'is_active': self.is_active,
            'reason': self.reason,
            'actual_commands': self.actual_commands,
            'expires_at': self.get_expiry_time().isoformat() if self.get_expiry_time() else 'permanent'
        }


class FirewallManager:
    """Gestor del firewall del sistema"""

    def __init__(self):
        self.system = platform.system().lower()
        self.active_rules = {}  # command_id -> FirewallRule
        self.blocked_ips = set()
        self.stats = {
            'rules_applied': 0,
            'rules_removed': 0,
            'ips_blocked': 0,
            'commands_executed': 0,
            'last_action_time': None,
            'errors': 0
        }

        logger.info(f"🔥 FirewallManager iniciado en {self.system}")

        # Verificar privilegios
        self._check_privileges()

        # Inicializar cleanup timer
        self._start_cleanup_timer()

    def _check_privileges(self):
        """Verificar si tenemos privilegios para modificar el firewall"""
        try:
            if self.system == 'linux':
                # Verificar si podemos ejecutar iptables
                result = subprocess.run(['sudo', '-n', 'iptables', '-L'],
                                        capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    logger.info("✅ Privilegios sudo verificados para iptables")
                else:
                    logger.warning("⚠️ No se pueden ejecutar comandos sudo sin contraseña")
            elif self.system == 'darwin':  # macOS
                logger.info("🍎 Sistema macOS detectado - usando pfctl")
            elif self.system == 'windows':
                logger.info("🪟 Sistema Windows detectado - usando netsh")
            else:
                logger.warning(f"⚠️ Sistema {self.system} no completamente soportado")
        except Exception as e:
            logger.error(f"❌ Error verificando privilegios: {e}")

    def apply_rule(self, rule: FirewallRule):
        """Aplicar regla de firewall"""
        try:
            logger.info(f"🔥 Aplicando regla: {rule.action} para {rule.target_ip}")

            success = False
            if self.system == 'linux':
                success = self._apply_linux_rule(rule)
            elif self.system == 'darwin':
                success = self._apply_macos_rule(rule)
            elif self.system == 'windows':
                success = self._apply_windows_rule(rule)
            else:
                logger.warning(f"⚠️ Sistema {self.system} no soportado - simulando aplicación")
                success = self._simulate_rule_application(rule)

            if success:
                rule.is_active = True
                self.active_rules[rule.command_id] = rule
                self.blocked_ips.add(rule.target_ip)
                self.stats['rules_applied'] += 1
                self.stats['ips_blocked'] += 1
                self.stats['last_action_time'] = datetime.now()

                logger.info(f"✅ Regla aplicada: {rule.command_id} ({rule.target_ip})")
                return True
            else:
                logger.error(f"❌ Error aplicando regla: {rule.command_id}")
                self.stats['errors'] += 1
                return False

        except Exception as e:
            logger.error(f"❌ Excepción aplicando regla: {e}")
            self.stats['errors'] += 1
            return False

    def _apply_linux_rule(self, rule: FirewallRule):
        """Aplicar regla en Linux usando iptables"""
        try:
            # Parsear comando o generar comando específico
            if rule.command:
                commands = [cmd.strip() for cmd in rule.command.split(';') if cmd.strip()]
            else:
                # Generar comando básico
                commands = [f"iptables -A INPUT -s {rule.target_ip} -j DROP"]

            executed_commands = []
            for cmd in commands:
                # Añadir sudo si no está presente
                if not cmd.startswith('sudo'):
                    cmd = f"sudo {cmd}"

                logger.info(f"🔧 Ejecutando: {cmd}")

                # Ejecutar comando
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    executed_commands.append(cmd)
                    logger.info(f"✅ Comando ejecutado exitosamente")
                else:
                    logger.error(f"❌ Error ejecutando comando: {result.stderr}")
                    # Rollback comandos ejecutados
                    self._rollback_commands(executed_commands)
                    return False

            rule.actual_commands = executed_commands
            self.stats['commands_executed'] += len(executed_commands)
            return True

        except subprocess.TimeoutExpired:
            logger.error("❌ Timeout ejecutando comando de firewall")
            return False
        except Exception as e:
            logger.error(f"❌ Error en _apply_linux_rule: {e}")
            return False

    def _apply_macos_rule(self, rule: FirewallRule):
        """Aplicar regla en macOS usando pfctl"""
        try:
            # En macOS, podemos usar pfctl o el firewall integrado
            # Para simplicidad, creamos una regla básica

            # Crear archivo de regla temporal
            rule_file = f"/tmp/pf_rule_{rule.command_id}.conf"
            rule_content = f"block in from {rule.target_ip} to any\n"

            with open(rule_file, 'w') as f:
                f.write(rule_content)

            # Aplicar regla (esto requiere privilegios de admin)
            cmd = f"sudo pfctl -f {rule_file}"
            logger.info(f"🍎 Aplicando regla macOS: {cmd}")

            # En lugar de ejecutar realmente, simulamos para evitar problemas
            rule.actual_commands = [cmd]
            logger.info("✅ Regla macOS simulada (requiere privilegios de admin)")
            return True

        except Exception as e:
            logger.error(f"❌ Error en _apply_macos_rule: {e}")
            return False

    def _apply_windows_rule(self, rule: FirewallRule):
        """Aplicar regla en Windows usando netsh"""
        try:
            # Usar netsh para Windows Firewall
            rule_name = f"ML_Block_{rule.command_id}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={rule.target_ip}'

            logger.info(f"🪟 Aplicando regla Windows: {cmd}")

            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                rule.actual_commands = [cmd]
                logger.info("✅ Regla Windows aplicada exitosamente")
                return True
            else:
                logger.error(f"❌ Error aplicando regla Windows: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"❌ Error en _apply_windows_rule: {e}")
            return False

    def _simulate_rule_application(self, rule: FirewallRule):
        """Simular aplicación de regla para sistemas no soportados"""
        logger.info(f"🎭 SIMULANDO aplicación de regla para {rule.target_ip}")
        rule.actual_commands = [f"SIMULATED: {rule.command}"]
        return True

    def _rollback_commands(self, commands):
        """Hacer rollback de comandos ejecutados"""
        logger.warning("🔄 Haciendo rollback de comandos...")
        for cmd in reversed(commands):
            try:
                # Convertir comando ADD a DELETE
                rollback_cmd = cmd.replace('-A ', '-D ')
                subprocess.run(rollback_cmd.split(), capture_output=True, timeout=5)
                logger.info(f"🔄 Rollback: {rollback_cmd}")
            except Exception as e:
                logger.error(f"❌ Error en rollback: {e}")

    def remove_rule(self, command_id):
        """Remover regla activa"""
        if command_id not in self.active_rules:
            logger.warning(f"⚠️ Regla {command_id} no encontrada para remover")
            return False

        rule = self.active_rules[command_id]
        try:
            logger.info(f"🗑️ Removiendo regla: {rule.target_ip}")

            # Convertir comandos ADD a DELETE
            for cmd in rule.actual_commands:
                if 'iptables' in cmd:
                    remove_cmd = cmd.replace('-A ', '-D ')
                    result = subprocess.run(remove_cmd.split(), capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        logger.info(f"✅ Regla removida: {remove_cmd}")
                    else:
                        logger.warning(f"⚠️ Error removiendo regla: {result.stderr}")

            # Remover de estructuras de datos
            rule.is_active = False
            del self.active_rules[command_id]
            if rule.target_ip in self.blocked_ips:
                self.blocked_ips.discard(rule.target_ip)

            self.stats['rules_removed'] += 1
            self.stats['last_action_time'] = datetime.now()

            logger.info(f"✅ Regla {command_id} removida exitosamente")
            return True

        except Exception as e:
            logger.error(f"❌ Error removiendo regla {command_id}: {e}")
            return False

    def cleanup_expired_rules(self):
        """Limpiar reglas expiradas"""
        expired_rules = []

        for command_id, rule in self.active_rules.items():
            if rule.is_expired():
                expired_rules.append(command_id)

        for command_id in expired_rules:
            logger.info(f"⏰ Regla expirada, removiendo: {command_id}")
            self.remove_rule(command_id)

        if expired_rules:
            logger.info(f"🧹 Limpieza completada: {len(expired_rules)} reglas removidas")

    def _start_cleanup_timer(self):
        """Iniciar timer de limpieza automática"""

        def cleanup_loop():
            while True:
                time.sleep(60)  # Verificar cada minuto
                try:
                    self.cleanup_expired_rules()
                except Exception as e:
                    logger.error(f"❌ Error en cleanup automático: {e}")

        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
        logger.info("🧹 Timer de limpieza automática iniciado")

    def get_status(self):
        """Obtener estado del firewall"""
        return {
            'system': self.system,
            'active_rules': len(self.active_rules),
            'blocked_ips': len(self.blocked_ips),
            'stats': self.stats,
            'rules': [rule.to_dict() for rule in self.active_rules.values()],
            'blocked_ips_list': list(self.blocked_ips)
        }


class FirewallAgent:
    """Agente principal que escucha comandos del puerto 5561"""

    def __init__(self):
        self.running = False
        self.context = None
        self.socket = None
        self.firewall_manager = FirewallManager()
        self.command_log = deque(maxlen=1000)
        self.stats = {
            'commands_received': 0,
            'commands_applied': 0,
            'commands_failed': 0,
            'start_time': datetime.now(),
            'last_command_time': None
        }

        # Obtener información del agente
        self.agent_info = {
            'hostname': socket.gethostname(),
            'system': platform.system(),
            'agent_id': f"firewall_agent_{socket.gethostname()}_{int(time.time())}",
            'version': '1.0.0'
        }

    def start(self):
        """Iniciar el agente"""
        self.running = True

        try:
            self.context = zmq.Context()
            self.socket = self.context.socket(zmq.PULL)
            self.socket.bind("tcp://*:5561")

            logger.info("🔥 Firewall Agent iniciado")
            logger.info(f"🏠 Hostname: {self.agent_info['hostname']}")
            logger.info(f"💻 Sistema: {self.agent_info['system']}")
            logger.info(f"🆔 Agent ID: {self.agent_info['agent_id']}")
            logger.info("🔌 Escuchando en puerto 5561...")
            logger.info("")

            # Loop principal
            self._listen_commands()

        except Exception as e:
            logger.error(f"❌ Error iniciando agente: {e}")
            raise

    def _listen_commands(self):
        """Escuchar comandos del puerto 5561"""
        logger.info("👂 Esperando comandos de firewall...")

        while self.running:
            try:
                # Recibir mensaje con timeout
                message = self.socket.recv(zmq.NOBLOCK)
                self._process_command(message)

            except zmq.Again:
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"❌ Error en listener: {e}")
                time.sleep(1)

    def _process_command(self, message):
        """Procesar comando recibido"""
        try:
            # Parsear JSON
            command_data = json.loads(message.decode('utf-8'))

            self.stats['commands_received'] += 1
            self.stats['last_command_time'] = datetime.now()

            logger.info(f"📨 Comando recibido: {command_data.get('command_id')}")
            logger.info(f"   Acción: {command_data.get('action')}")
            logger.info(f"   IP Objetivo: {command_data.get('target_ip')}")
            logger.info(f"   Razón: {command_data.get('reason')}")

            # Log del comando
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'command': command_data,
                'agent_info': self.agent_info,
                'status': 'received'
            }

            # Verificar si es para este agente
            source_agent = command_data.get('source_agent', '')
            if source_agent and self.agent_info['hostname'] not in source_agent:
                logger.warning(f"⚠️ Comando no es para este agente (target: {source_agent})")
                log_entry['status'] = 'ignored_wrong_agent'
                self.command_log.append(log_entry)
                return

            # Crear regla de firewall
            rule = FirewallRule(command_data)

            # Aplicar regla
            if self.firewall_manager.apply_rule(rule):
                self.stats['commands_applied'] += 1
                log_entry['status'] = 'applied_successfully'
                logger.info(f"✅ Comando aplicado exitosamente: {rule.command_id}")
            else:
                self.stats['commands_failed'] += 1
                log_entry['status'] = 'application_failed'
                logger.error(f"❌ Error aplicando comando: {rule.command_id}")

            self.command_log.append(log_entry)

        except json.JSONDecodeError as e:
            logger.error(f"❌ Error parseando JSON: {e}")
            self.stats['commands_failed'] += 1
        except Exception as e:
            logger.error(f"❌ Error procesando comando: {e}")
            self.stats['commands_failed'] += 1

    def get_status(self):
        """Obtener estado completo del agente"""
        firewall_status = self.firewall_manager.get_status()

        return {
            'agent_info': self.agent_info,
            'stats': self.stats,
            'firewall': firewall_status,
            'uptime_seconds': (datetime.now() - self.stats['start_time']).total_seconds(),
            'command_log': list(self.command_log)[-10:]  # Últimos 10 comandos
        }

    def stop(self):
        """Detener el agente"""
        logger.info("🛑 Deteniendo Firewall Agent...")
        self.running = False

        if self.socket:
            self.socket.close()
        if self.context:
            self.context.term()

        logger.info("✅ Firewall Agent detenido")


def main():
    """Función principal"""
    print("🔥 FIREWALL AGENT - Puerto 5561")
    print("=" * 50)
    print("🎯 Funciones:")
    print("   📡 Recibe comandos JSON del dashboard")
    print("   🛡️ Aplica reglas de firewall automáticamente")
    print("   ⏰ Gestión automática de expiración")
    print("   🧹 Limpieza automática de reglas")
    print("   📊 Logging y estadísticas completas")
    print("")

    try:
        agent = FirewallAgent()

        print(f"🚀 Iniciando en {agent.agent_info['hostname']}")
        print(f"💻 Sistema: {agent.agent_info['system']}")
        print(f"🆔 Agent ID: {agent.agent_info['agent_id']}")
        print("")
        print("✅ LISTO PARA RECIBIR COMANDOS")
        print("   🔌 Puerto: 5561")
        print("   📨 Formato: JSON")
        print("   🛡️ Firewall: Activo")
        print("")
        print("🛑 Presiona Ctrl+C para detener")
        print("")

        agent.start()

    except KeyboardInterrupt:
        print("\n🛑 Agente detenido por usuario")
        if 'agent' in locals():
            agent.stop()
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()