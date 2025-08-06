#!/usr/bin/env python3
"""
simple_firewall_agent.py - ULTRA-SECURE VERSION WITH AUTO-DETECTION - FIXED
✅ SOLUCIÓN C COMPLETA: "SET IT AND FORGET IT"
✅ Auto-detección de entorno y permisos
✅ Auto-protección contra configuraciones peligrosas
✅ Fuerza modo seguro automáticamente
✅ Logging defensivo completo
✅ Validación robusta de comandos
✅ Nunca puede dañar el firewall real
🔧 FIXED: Añadido método reload_if_changed() que faltaba
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
import pwd
import grp
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Add src to path for protobuf imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# 📦 Protobuf Firewall Commands - Importación robusta
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = "unavailable"
firewall_commands_pb2 = None


def import_firewall_protobuf_module():
    """Importa el módulo firewall_commands_pb2 con múltiples estrategias"""
    global firewall_commands_pb2, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    # Estrategia 1: Importación desde diferentes ubicaciones
    import_strategies = [
        ("protocols.current.firewall_commands_pb2", "Paquete protocols.current"),
        ("protocols.firewall_commands_pb2", "Paquete protocols"),
        ("firewall_commands_pb2", "Importación directa"),
    ]

    for import_path, description in import_strategies:
        try:
            firewall_commands_pb2 = __import__(import_path, fromlist=[''])
            PROTOBUF_AVAILABLE = True
            PROTOBUF_VERSION = "v3.0.0"
            print(f"✅ Firewall protobuf cargado: {description} ({import_path})")
            return True
        except ImportError:
            continue

    # Estrategia 2: Añadir path dinámico y importar
    current_dir = os.path.dirname(os.path.abspath(__file__))
    possible_paths = [
        os.path.join(current_dir, '..', 'protocols', 'current'),
        os.path.join(current_dir, 'protocols', 'current'),
        os.path.join(os.getcwd(), 'protocols', 'current'),
    ]

    for protocols_path in possible_paths:
        protocols_path = os.path.abspath(protocols_path)
        pb2_file = os.path.join(protocols_path, 'firewall_commands_pb2.py')

        if os.path.exists(pb2_file):
            try:
                sys.path.insert(0, protocols_path)
                import firewall_commands_pb2
                PROTOBUF_AVAILABLE = True
                PROTOBUF_VERSION = "v3.0.0"
                print(f"✅ Firewall protobuf cargado desde path: {protocols_path}")
                return True
            except ImportError as e:
                print(f"⚠️ Error importando desde {protocols_path}: {e}")
                sys.path.remove(protocols_path)
                continue

    # Si llegamos aquí, no se pudo importar el módulo
    print("❌ No se pudo cargar firewall_commands_pb2")
    print(f"   📁 Directorio actual: {os.getcwd()}")
    print(f"   📁 Script location: {os.path.abspath(__file__)}")
    return False


# Ejecutar importación al inicio
if not import_firewall_protobuf_module():
    print("❌ Firewall protobuf import failed")
    print("📁 Please ensure firewall_commands_pb2.py exists in protocols/current/")
    sys.exit(1)

# Import crypto/compression utils (when ready)
try:
    from crypto_utils import SecureEnvelope
    from compression_utils import CompressionEngine

    CRYPTO_AVAILABLE = True
except ImportError:
    print("⚠️ Crypto utils not available, running without encryption")
    CRYPTO_AVAILABLE = False


@dataclass
class EnvironmentSafety:
    """Información de seguridad del entorno detectado"""
    is_root: bool
    has_sudo: bool
    effective_uid: int
    effective_user: str
    is_container: bool
    container_type: Optional[str]
    firewall_accessible: bool
    firewall_type: str
    platform: str
    safety_level: str  # SAFE, MEDIUM, DANGEROUS
    forced_dry_run: bool
    safety_reasons: List[str]


@dataclass
class SecurityEvent:
    """Evento de seguridad para logging"""
    timestamp: str
    event_type: str
    severity: str
    message: str
    context: Dict
    safety_action: str


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
    is_dry_run: bool


class SecurityMonitor:
    """🔒 Monitor de seguridad que detecta y previene operaciones peligrosas"""

    def __init__(self, logger):
        self.logger = logger
        self.security_events = []
        self.environment_safety = None
        self.last_safety_check = None

    def detect_environment_safety(self) -> EnvironmentSafety:
        """🔍 DETECCIÓN COMPLETA DEL ENTORNO - CORE DE LA SEGURIDAD"""
        safety_reasons = []
        forced_dry_run = False

        # 1. Detectar usuario y permisos
        effective_uid = os.getuid() if hasattr(os, 'getuid') else -1
        is_root = effective_uid == 0

        try:
            effective_user = pwd.getpwuid(effective_uid).pw_name if effective_uid >= 0 else 'unknown'
        except:
            effective_user = 'unknown'

        # 2. Detectar sudo
        has_sudo = self._check_sudo_access()

        # 3. Detectar contenedor
        is_container, container_type = self._detect_container()

        # 4. Detectar firewall
        firewall_accessible, firewall_type = self._detect_firewall()

        # 5. Determinar nivel de seguridad
        if is_root:
            safety_level = "DANGEROUS"
            forced_dry_run = True
            safety_reasons.append("Running as root user")

        elif has_sudo:
            safety_level = "DANGEROUS"
            forced_dry_run = True
            safety_reasons.append("Sudo access detected")

        elif firewall_accessible and not is_container:
            safety_level = "MEDIUM"
            safety_reasons.append("Direct firewall access available")

        else:
            safety_level = "SAFE"

        # 6. Crear objeto de seguridad
        environment_safety = EnvironmentSafety(
            is_root=is_root,
            has_sudo=has_sudo,
            effective_uid=effective_uid,
            effective_user=effective_user,
            is_container=is_container,
            container_type=container_type,
            firewall_accessible=firewall_accessible,
            firewall_type=firewall_type,
            platform=platform.system().lower(),
            safety_level=safety_level,
            forced_dry_run=forced_dry_run,
            safety_reasons=safety_reasons
        )

        self.environment_safety = environment_safety
        self.last_safety_check = datetime.now()

        # 7. Log resultado de detección
        self._log_environment_detection(environment_safety)

        return environment_safety

    def _check_sudo_access(self) -> bool:
        """Verificar si sudo está disponible"""
        try:
            # Verificar si sudo está instalado
            result = subprocess.run(['which', 'sudo'], capture_output=True, timeout=5)
            if result.returncode != 0:
                return False

            # Verificar si el usuario está en sudoers (sin ejecutar comando real)
            result = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=5)
            return result.returncode == 0

        except Exception:
            return False

    def _detect_container(self) -> Tuple[bool, Optional[str]]:
        """Detectar si estamos ejecutando en contenedor"""
        try:
            # 1. Verificar archivos típicos de contenedor
            if Path('/.dockerenv').exists():
                return True, 'docker'

            # 2. Verificar variables de entorno
            container_vars = ['DOCKER_CONTAINER', 'KUBERNETES_SERVICE_HOST', 'container']
            for var in container_vars:
                if var in os.environ:
                    return True, 'kubernetes' if 'KUBERNETES' in var else 'docker'

            # 3. Verificar cgroup
            try:
                with open('/proc/1/cgroup', 'r') as f:
                    cgroup_content = f.read()
                    if 'docker' in cgroup_content or 'kubepods' in cgroup_content:
                        return True, 'docker' if 'docker' in cgroup_content else 'kubernetes'
            except:
                pass

            # 4. Verificar hostname característico
            hostname = os.uname().nodename
            if len(hostname) == 12 and hostname.isalnum():  # Docker style
                return True, 'docker'

            return False, None

        except Exception:
            return False, None

    def _detect_firewall(self) -> Tuple[bool, str]:
        """Detectar tipo y accesibilidad del firewall"""
        platform_name = platform.system().lower()

        if platform_name == 'linux':
            # Verificar iptables
            try:
                result = subprocess.run(['which', 'iptables'], capture_output=True, timeout=5)
                if result.returncode == 0:
                    # Verificar si se puede ejecutar iptables
                    test_result = subprocess.run(['iptables', '--version'], capture_output=True, timeout=5)
                    return test_result.returncode == 0, 'iptables'
            except:
                pass

            # Verificar ufw
            try:
                result = subprocess.run(['which', 'ufw'], capture_output=True, timeout=5)
                if result.returncode == 0:
                    return True, 'ufw'
            except:
                pass

            return False, 'iptables'  # Assume iptables but not accessible

        elif platform_name == 'darwin':
            try:
                result = subprocess.run(['pfctl', '-s', 'info'], capture_output=True, timeout=5)
                return result.returncode == 0, 'pfctl'
            except:
                return False, 'pfctl'

        elif platform_name == 'windows':
            try:
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'],
                                        capture_output=True, timeout=5)
                return result.returncode == 0, 'netsh'
            except:
                return False, 'netsh'

        else:
            return False, 'unknown'

    def _log_environment_detection(self, env_safety: EnvironmentSafety):
        """Log resultado de detección de entorno"""
        self.logger.info("🔍 ENVIRONMENT SAFETY DETECTION COMPLETE:")
        self.logger.info(f"   🔒 Safety Level: {env_safety.safety_level}")
        self.logger.info(f"   👤 User: {env_safety.effective_user} (UID: {env_safety.effective_uid})")
        self.logger.info(f"   🏠 Platform: {env_safety.platform}")
        self.logger.info(f"   📦 Container: {env_safety.is_container} ({env_safety.container_type})")
        self.logger.info(f"   🔥 Firewall: {env_safety.firewall_type} (accessible: {env_safety.firewall_accessible})")
        self.logger.info(f"   ⚠️ Root: {env_safety.is_root}")
        self.logger.info(f"   🔑 Sudo: {env_safety.has_sudo}")
        self.logger.info(f"   🛡️ Forced Dry Run: {env_safety.forced_dry_run}")

        if env_safety.safety_reasons:
            self.logger.warning(f"   📋 Safety Reasons: {', '.join(env_safety.safety_reasons)}")

        # Log evento de seguridad
        security_event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type="environment_detection",
            severity="INFO" if env_safety.safety_level == "SAFE" else "WARNING",
            message=f"Environment safety level: {env_safety.safety_level}",
            context={
                "is_root": env_safety.is_root,
                "has_sudo": env_safety.has_sudo,
                "is_container": env_safety.is_container,
                "firewall_accessible": env_safety.firewall_accessible,
                "forced_dry_run": env_safety.forced_dry_run,
                "reasons": env_safety.safety_reasons
            },
            safety_action="force_dry_run" if env_safety.forced_dry_run else "normal_operation"
        )

        self.security_events.append(security_event)

    def validate_command_safety(self, action: str, target_ip: str, params: Dict) -> Tuple[bool, str, List[str]]:
        """🛡️ Validar seguridad del comando ANTES de ejecutar"""
        issues = []
        allowed = True
        reason = "Command validation passed"

        # 1. Verificar si la acción está permitida
        if action not in ['MONITOR', 'LIST_RULES']:
            allowed = False
            issues.append(f"Action '{action}' not allowed in ultra-secure mode")

        # 2. Validar IP
        if not self._is_valid_ip(target_ip):
            allowed = False
            issues.append(f"Invalid IP address: {target_ip}")

        # 3. Verificar IPs privadas/localhost (si está configurado para bloquear)
        if self._is_dangerous_ip(target_ip):
            allowed = False
            issues.append(f"IP {target_ip} is in blocked range (localhost/private)")

        # 4. Verificar duración
        duration = params.get('duration', 0)
        if duration > 300:  # Max 5 minutos
            allowed = False
            issues.append(f"Duration {duration}s exceeds maximum allowed (300s)")

        # 5. Verificar estado del entorno
        if self.environment_safety and self.environment_safety.forced_dry_run:
            if action not in ['MONITOR', 'LIST_RULES']:
                allowed = False
                issues.append("Environment safety forces dry-run only mode")

        if not allowed:
            reason = f"Command rejected: {'; '.join(issues)}"
            self.logger.warning(f"🚫 COMMAND REJECTED: {reason}")

            # Log evento de seguridad
            security_event = SecurityEvent(
                timestamp=datetime.now().isoformat(),
                event_type="command_rejected",
                severity="WARNING",
                message=f"Rejected {action} command for {target_ip}",
                context={
                    "action": action,
                    "target_ip": target_ip,
                    "params": params,
                    "issues": issues
                },
                safety_action="command_blocked"
            )
            self.security_events.append(security_event)

        return allowed, reason, issues

    def _is_valid_ip(self, ip: str) -> bool:
        """Validar formato de IP"""
        import ipaddress
        try:
            ipaddress.IPv4Address(ip)
            return True
        except:
            return False

    def _is_dangerous_ip(self, ip: str) -> bool:
        """Verificar si la IP está en rangos peligrosos"""
        import ipaddress
        try:
            ip_obj = ipaddress.IPv4Address(ip)

            # Rangos bloqueados
            blocked_ranges = [
                ipaddress.IPv4Network('127.0.0.0/8'),  # localhost
                ipaddress.IPv4Network('10.0.0.0/8'),  # private
                ipaddress.IPv4Network('172.16.0.0/12'),  # private
                ipaddress.IPv4Network('192.168.0.0/16'),  # private
                ipaddress.IPv4Network('169.254.0.0/16')  # link-local
            ]

            for blocked_range in blocked_ranges:
                if ip_obj in blocked_range:
                    return True

            return False
        except:
            return True  # Si no se puede validar, es peligrosa


class FirewallRulesSync:
    """Sincronización con reglas JSON del dashboard - ULTRA SECURE VERSION - FIXED"""

    def __init__(self, rules_file: str, node_id: str, logger, security_monitor: SecurityMonitor):
        self.rules_file = rules_file
        self.node_id = node_id
        self.logger = logger
        self.security_monitor = security_monitor
        self.available_actions = []
        self.capabilities = []
        self.global_settings = {}
        self.manual_actions = {}
        self.risk_rules = []
        self.agent_config = {}
        self.last_loaded = None

        # 🔧 NUEVO: Para tracking de cambios (FIX RELOAD_IF_CHANGED)
        self.last_modified_time = 0
        self.file_size = 0
        self.load_count = 0

        # Cargar reglas iniciales
        self.load_rules()

    def reload_if_changed(self) -> bool:
        """
        🔧 MÉTODO AÑADIDO: Recargar reglas solo si el archivo ha cambiado
        Returns: True si se recargó, False si no hubo cambios
        """
        try:
            # Verificar si el archivo existe
            if not Path(self.rules_file).exists():
                self.logger.warning(f"⚠️ Archivo de reglas no existe: {self.rules_file}")
                return False

            # Obtener información del archivo
            file_stat = os.stat(self.rules_file)
            current_modified_time = file_stat.st_mtime
            current_file_size = file_stat.st_size

            # Verificar si hay cambios
            if (current_modified_time != self.last_modified_time or
                    current_file_size != self.file_size):

                self.logger.info(f"🔄 Cambios detectados en {self.rules_file}, recargando...")
                self.logger.debug(f"   Modificado: {self.last_modified_time} → {current_modified_time}")
                self.logger.debug(f"   Tamaño: {self.file_size} → {current_file_size}")

                # Recargar reglas
                self.load_rules()

                # Actualizar tracking
                self.last_modified_time = current_modified_time
                self.file_size = current_file_size
                self.load_count += 1

                self.logger.info(f"✅ Reglas recargadas exitosamente (recarga #{self.load_count})")
                return True
            else:
                self.logger.debug(f"📋 Sin cambios en {self.rules_file}")
                return False

        except Exception as e:
            self.logger.error(f"❌ Error verificando cambios en reglas: {e}")
            return False

    def force_reload(self) -> bool:
        """🔄 Forzar recarga de reglas sin verificar cambios"""
        try:
            self.logger.info(f"🔄 Forzando recarga de reglas: {self.rules_file}")
            self.load_rules()

            # Actualizar tracking
            if Path(self.rules_file).exists():
                file_stat = os.stat(self.rules_file)
                self.last_modified_time = file_stat.st_mtime
                self.file_size = file_stat.st_size

            self.load_count += 1
            self.logger.info(f"✅ Reglas forzadamente recargadas (recarga #{self.load_count})")
            return True
        except Exception as e:
            self.logger.error(f"❌ Error forzando recarga de reglas: {e}")
            return False

    def get_reload_stats(self) -> Dict[str, Any]:
        """📊 Obtener estadísticas de recarga"""
        return {
            "rules_file": self.rules_file,
            "last_loaded": self.last_loaded.isoformat() if self.last_loaded else None,
            "last_modified_time": self.last_modified_time,
            "file_size": self.file_size,
            "load_count": self.load_count,
            "available_actions_count": len(self.available_actions),
            "capabilities_count": len(self.capabilities),
            "risk_rules_count": len(self.risk_rules)
        }

    def load_rules(self):
        """Cargar reglas con validación de seguridad"""
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

            # 🔒 FILTRAR SOLO ACCIONES SEGURAS
            safe_actions = []
            for action, config in self.manual_actions.items():
                if config.get('safety_level') == 'SAFE' and config.get('enabled', True):
                    safe_actions.append(action)
                else:
                    self.logger.warning(f"🚫 Action {action} disabled due to safety level")

            self.available_actions = safe_actions

            # Extraer configuración específica de este agente
            firewall_agents = firewall_config.get('firewall_agents', {})
            self.agent_config = firewall_agents.get(self.node_id, {})

            if not self.agent_config:
                self.logger.warning(f"⚠️ No se encontró configuración específica para {self.node_id}")
                self.capabilities = self.available_actions
            else:
                # 🔒 USAR SOLO CAPACIDADES SEGURAS
                agent_capabilities = self.agent_config.get('capabilities', [])
                self.capabilities = [cap for cap in agent_capabilities if cap in safe_actions]

            # Configuración global con overrides de seguridad
            self.global_settings = firewall_config.get('global_settings', {})

            # 🔒 FORZAR CONFIGURACIÓN SEGURA
            if self.global_settings.get('force_dry_run_global', False):
                self.logger.info("🔒 Global dry_run forced by configuration")

            self.last_loaded = datetime.now()

            # 🔧 ACTUALIZAR TRACKING DE CAMBIOS
            if Path(self.rules_file).exists():
                file_stat = os.stat(self.rules_file)
                self.last_modified_time = file_stat.st_mtime
                self.file_size = file_stat.st_size

            self.logger.info(f"✅ Reglas de firewall sincronizadas: {len(self.risk_rules)} reglas de riesgo")
            self.logger.info(f"📋 Acciones manuales SEGURAS: {', '.join(self.available_actions)}")
            self.logger.info(f"🎯 Capacidades del agente FILTRADAS: {', '.join(self.capabilities)}")

        except Exception as e:
            self.logger.error(f"❌ CRITICAL ERROR cargando reglas: {e}")
            raise e


class UltraSecureFirewallManager:
    """🔒 Firewall Manager Ultra-Seguro - Nunca puede dañar el firewall real"""

    def __init__(self, config: Dict, logger, security_monitor: SecurityMonitor):
        self.config = config
        self.logger = logger
        self.security_monitor = security_monitor
        self.platform = platform.system().lower()
        self.active_rules = {}
        self.rule_history = []

        # 🔒 FORZAR CONFIGURACIÓN ULTRA-SEGURA
        self.sudo_enabled = False  # NUNCA usar sudo
        self.dry_run = True  # SIEMPRE dry_run
        self.firewall_type = self._detect_firewall_type()

        # 🔒 AUTO-DETECCIÓN DE SEGURIDAD
        env_safety = self.security_monitor.detect_environment_safety()
        if env_safety.forced_dry_run:
            self.dry_run = True
            self.logger.warning("🔒 FORCED DRY_RUN due to environment safety detection")

        self.logger.info(f"🔒 Ultra-Secure Firewall Manager initialized")
        self.logger.info(f"   Platform: {self.platform}, Type: {self.firewall_type}")
        self.logger.info(f"   Dry Run: {self.dry_run}, Sudo: {self.sudo_enabled}")

    def _detect_firewall_type(self) -> str:
        """Detectar tipo de firewall (solo para logging, no para uso real)"""
        env_safety = self.security_monitor.environment_safety
        if env_safety:
            return env_safety.firewall_type
        else:
            return "unknown"

    def apply_monitor_rule(self, command_id: str, target_ip: str, target_port: Optional[int] = None,
                           duration: Optional[int] = None) -> Tuple[bool, str]:
        """Aplicar regla de monitoreo (SEGURO)"""
        try:
            # 🔒 VALIDAR COMANDO
            params = {'duration': duration or 300}
            allowed, reason, issues = self.security_monitor.validate_command_safety(
                'MONITOR', target_ip, params
            )

            if not allowed:
                return False, f"Security validation failed: {reason}"

            rule_id = str(uuid.uuid4())
            current_time = time.time()
            expires_at = current_time + (duration or 300)

            # Generar "regla" de monitoreo (solo logging)
            rule_text = f"MONITOR {target_ip}" + (f":{target_port}" if target_port else "")

            # 🔒 SIEMPRE DRY RUN PARA MONITOR
            self.logger.info(f"🔒 [ULTRA-SAFE MONITOR] {rule_text}")
            success = True
            message = f"ULTRA-SAFE MONITOR: {target_ip} monitored for {duration or 300}s"

            # Registrar la "regla"
            rule = FirewallRule(
                rule_id=rule_id,
                command_id=command_id,
                action="MONITOR",
                target_ip=target_ip,
                target_port=target_port,
                duration_seconds=duration,
                created_at=current_time,
                expires_at=expires_at,
                applied=True,
                rule_text=rule_text,
                is_dry_run=True
            )

            self.active_rules[rule_id] = rule
            self.rule_history.append(rule)

            self.logger.info(f"✅ Monitor rule logged: {target_ip} (Rule ID: {rule_id})")

            return success, message

        except Exception as e:
            self.logger.error(f"❌ Error applying monitor rule: {e}")
            return False, f"Error applying monitor rule: {str(e)}"

    def list_active_rules(self, command_id: str) -> Tuple[bool, str]:
        """Listar reglas activas (SEGURO)"""
        try:
            # 🔒 VALIDAR COMANDO
            allowed, reason, issues = self.security_monitor.validate_command_safety(
                'LIST_RULES', '127.0.0.1', {}
            )

            if not allowed:
                return False, f"Security validation failed: {reason}"

            active_rules = list(self.active_rules.values())
            rule_count = len(active_rules)

            # Generar resumen seguro
            rules_summary = []
            for rule in active_rules[-10:]:  # Solo últimas 10
                summary = f"{rule.action} {rule.target_ip} (expires: {rule.expires_at})"
                rules_summary.append(summary)

            message = f"LIST_RULES: {rule_count} active rules"
            if rules_summary:
                message += f" - Recent: {'; '.join(rules_summary)}"

            self.logger.info(f"📋 {message}")
            return True, message

        except Exception as e:
            self.logger.error(f"❌ Error listing rules: {e}")
            return False, f"Error listing rules: {str(e)}"

    def cleanup_expired_rules(self):
        """Limpiar reglas expiradas"""
        current_time = time.time()
        expired_rules = []

        for rule_id, rule in self.active_rules.items():
            if rule.expires_at and current_time > rule.expires_at:
                expired_rules.append(rule_id)

        for rule_id in expired_rules:
            rule = self.active_rules.pop(rule_id)
            self.logger.info(f"🔄 Rule expired: {rule.target_ip} (Rule ID: {rule_id})")

    def get_active_rules(self) -> List[FirewallRule]:
        """Obtener lista de reglas activas"""
        return list(self.active_rules.values())

    def get_rule_history(self) -> List[FirewallRule]:
        """Obtener historial de reglas"""
        return self.rule_history[-50:]  # Últimas 50


class UltraSecureFirewallAgent:
    """🔒 Firewall Agent Ultra-Seguro - SET IT AND FORGET IT - FIXED"""

    def __init__(self, config_path: str, rules_file: str):
        # ✅ VALIDACIÓN CRÍTICA: Ambos archivos deben existir
        if not Path(config_path).exists():
            raise FileNotFoundError(f"❌ CRITICAL: Archivo de configuración base no encontrado: {config_path}")

        if not Path(rules_file).exists():
            raise FileNotFoundError(f"❌ CRITICAL: Archivo de reglas no encontrado: {rules_file}")

        # ✅ CARGAR CONFIGURACIÓN BASE
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            print(f"✅ Configuración base cargada: {config_path}")
        except Exception as e:
            raise ValueError(f"❌ CRITICAL: Error cargando configuración base: {e}")

        # ✅ VALIDAR CAMPOS CRÍTICOS
        required_fields = ["node_id", "component", "firewall", "network"]
        for field in required_fields:
            if field not in self.config:
                raise ValueError(f"❌ CRITICAL: Campo '{field}' faltante en configuración base")

        self.node_id = self.config["node_id"]
        self.component_name = self.config["component"]["name"]
        self.agent_id = f"{self.node_id}_{int(time.time())}"

        # 🔒 FORZAR MODO ULTRA-SEGURO INDEPENDIENTEMENTE DE CONFIGURACIÓN
        self.dry_run = True
        self.ultra_secure_mode = True

        # ✅ CONFIGURAR LOGGING ANTES DE CREAR OTROS COMPONENTES
        self.setup_logging()

        # ✅ VERIFICAR PROTOBUF DISPONIBLE
        if not PROTOBUF_AVAILABLE:
            self.logger.error("❌ CRITICAL: Protobuf module not available")
            raise RuntimeError("Firewall protobuf module is required")

        # 🔒 INICIALIZAR MONITOR DE SEGURIDAD
        self.security_monitor = SecurityMonitor(self.logger)

        # 🔍 AUTO-DETECCIÓN DE ENTORNO
        env_safety = self.security_monitor.detect_environment_safety()

        # 🔒 APLICAR OVERRIDES DE SEGURIDAD AUTOMÁTICOS
        if env_safety.forced_dry_run:
            self.dry_run = True
            self.logger.warning("🔒 DRY_RUN FORCED by environment safety detection")

        # ✅ CARGAR REGLAS DE FIREWALL CON FILTRADO DE SEGURIDAD
        try:
            self.rules_sync = FirewallRulesSync(rules_file, self.node_id, self.logger, self.security_monitor)
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

        # 🔒 Initialize ULTRA-SECURE firewall manager
        firewall_config = self.config.get("firewall", {})
        self.firewall_manager = UltraSecureFirewallManager(firewall_config, self.logger, self.security_monitor)

        # ZMQ setup
        self.zmq_context = zmq.Context()
        self.commands_socket = None
        self.responses_socket = None

        # Processing
        self.command_queue = queue.Queue()
        self.running = False
        self.threads = []

        # Metrics con información de seguridad
        self.metrics = {
            "commands_received": 0,
            "commands_processed": 0,
            "commands_rejected": 0,
            "responses_sent": 0,
            "rules_applied": 0,
            "errors": 0,
            "uptime_start": time.time(),
            "security_events": 0,
            "ultra_secure_mode": True,
            "forced_dry_run": env_safety.forced_dry_run,
            "environment_safety_level": env_safety.safety_level
        }

        # Initialize components
        self._setup_zmq_sockets()

        self.logger.info(f"🔒 ULTRA-SECURE Firewall Agent initialized: {self.agent_id}")
        self.logger.info(f"🔒 Environment Safety Level: {env_safety.safety_level}")
        self.logger.info(f"🔒 Forced Dry Run: {env_safety.forced_dry_run}")

    def setup_logging(self):
        """Setup logging ultra-seguro con marcadores de seguridad"""
        log_config = self.config.get("logging", {})

        # Configurar nivel
        level = getattr(logging, log_config.get("level", "INFO").upper())

        # 🔒 FORMATO CON MARCADORES DE SEGURIDAD
        log_format = log_config.get("format",
                                    "%(asctime)s - %(name)s - %(levelname)s - [node_id:{node_id}] [pid:{pid}] [ULTRA_SECURE] - %(message)s")

        # Reemplazar placeholders
        log_format = log_format.format(
            node_id=self.node_id,
            pid=os.getpid()
        )

        formatter = logging.Formatter(log_format)

        # Setup logger
        self.logger = logging.getLogger(f"firewall_agent_{self.node_id}_SECURE")
        self.logger.setLevel(level)
        self.logger.handlers.clear()

        # Handler de consola
        console_config = log_config.get("handlers", {}).get("console", {})
        if console_config.get("enabled", True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        # Handler de archivo SEGURO
        file_config = log_config.get("handlers", {}).get("file", {})
        if file_config.get("enabled", True):
            file_path = file_config.get("path", "logs/firewall_agent_ultra_secure.log")
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(file_path)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

        # 🔒 Handler de eventos de seguridad
        security_config = log_config.get("handlers", {}).get("security_log", {})
        if security_config.get("enabled", True):
            security_path = security_config.get("path", "logs/firewall_security_events.log")
            Path(security_path).parent.mkdir(parents=True, exist_ok=True)
            security_handler = logging.FileHandler(security_path)
            security_formatter = logging.Formatter(
                "%(asctime)s - SECURITY - %(levelname)s - [node_id:{node_id}] [pid:{pid}] - %(message)s".format(
                    node_id=self.node_id, pid=os.getpid()
                )
            )
            security_handler.setFormatter(security_formatter)

            # Logger separado para eventos de seguridad
            self.security_logger = logging.getLogger(f"security_{self.node_id}")
            self.security_logger.addHandler(security_handler)
            self.security_logger.setLevel(logging.INFO)

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

            cmd_address = f"tcp://{cmd_config['address']}:{cmd_config['port']}"
            cmd_mode = cmd_config.get('mode', 'connect').lower()

            if cmd_mode == 'bind':
                self.commands_socket.bind(cmd_address)
                self.logger.info(f"🔒 Commands Input BIND en: {cmd_address}")
            else:
                self.commands_socket.connect(cmd_address)
                self.logger.info(f"🔒 Commands Input CONNECT a: {cmd_address}")

        # Responses Output (to dashboard)
        if "responses_output" in network_config:
            resp_config = network_config["responses_output"]
            self.responses_socket = self.zmq_context.socket(zmq.PUSH)

            # Configure socket
            if "high_water_mark" in resp_config:
                self.responses_socket.set_hwm(resp_config["high_water_mark"])

            resp_address = f"tcp://{resp_config['address']}:{resp_config['port']}"
            resp_mode = resp_config.get('mode', 'connect').lower()

            if resp_mode == 'bind':
                self.responses_socket.bind(resp_address)
                self.logger.info(f"🔒 Responses Output BIND en: {resp_address}")
            else:
                self.responses_socket.connect(resp_address)
                self.logger.info(f"🔒 Responses Output CONNECT a: {resp_address}")

    def _commands_consumer(self):
        """Consumer thread para comandos firewall con validación ultra-segura"""
        self.logger.info("🔒 ULTRA-SECURE Commands consumer thread started")

        while self.running:
            try:
                if self.commands_socket:
                    try:
                        raw_data = self.commands_socket.recv(zmq.NOBLOCK)
                        self.logger.info(f"🔍 Received {len(raw_data)} bytes for security validation")

                        # Decrypt and decompress
                        decrypted_data = self._decrypt_and_decompress(raw_data)

                        try:
                            pb_command = firewall_commands_pb2.FirewallCommand()
                            pb_command.ParseFromString(decrypted_data)

                            # 🔒 VALIDACIÓN DE SEGURIDAD INMEDIATA
                            if not pb_command.command_id:
                                pb_command.command_id = f"auto_secure_{int(time.time())}"

                            if not pb_command.target_ip:
                                pb_command.target_ip = "127.0.0.1"

                            # 🔒 FORZAR DRY_RUN
                            pb_command.dry_run = True

                            self.logger.info(
                                f"🔒 SECURITY CHECK: {pb_command.command_id}, action={pb_command.action}, ip={pb_command.target_ip}")

                            # 🔒 PRE-VALIDACIÓN DE COMANDO
                            params = {
                                'duration': pb_command.duration_seconds,
                                'dry_run': True  # Siempre
                            }

                            action_name = self._get_action_name(pb_command.action)
                            allowed, reason, issues = self.security_monitor.validate_command_safety(
                                action_name, pb_command.target_ip, params
                            )

                            if allowed:
                                self.command_queue.put(pb_command)
                                self.metrics["commands_received"] += 1
                                self.logger.info(f"✅ Command passed security validation")
                            else:
                                self.metrics["commands_rejected"] += 1
                                self.security_logger.warning(f"🚫 COMMAND REJECTED: {reason}")

                                # Enviar respuesta de rechazo
                                self._send_response(pb_command.command_id, False,
                                                    f"Security validation failed: {reason}")

                        except Exception as parse_error:
                            self.logger.error(f"❌ Protobuf parse error: {parse_error}")

                            # 🔒 COMANDO FALLBACK ULTRA-SEGURO
                            fallback_command = firewall_commands_pb2.FirewallCommand()
                            fallback_command.command_id = f"fallback_secure_{int(time.time())}"
                            fallback_command.action = firewall_commands_pb2.CommandAction.LIST_RULES
                            fallback_command.target_ip = "127.0.0.1"
                            fallback_command.dry_run = True

                            self.logger.info("🔒 Using ultra-secure fallback command")
                            self.command_queue.put(fallback_command)
                            self.metrics["commands_received"] += 1

                    except zmq.Again:
                        pass
                    except Exception as e:
                        self.logger.error(f"❌ Error receiving command: {e}")
                        self.metrics["errors"] += 1

                time.sleep(0.001)

            except Exception as e:
                self.logger.error(f"❌ Commands consumer error: {e}")
                self.metrics["errors"] += 1
                time.sleep(1)

    def _get_action_name(self, action_enum: int) -> str:
        """Convertir enum de acción a string"""
        action_map = {
            firewall_commands_pb2.CommandAction.BLOCK_IP: "BLOCK_IP",
            firewall_commands_pb2.CommandAction.UNBLOCK_IP: "UNBLOCK_IP",
            firewall_commands_pb2.CommandAction.RATE_LIMIT_IP: "RATE_LIMIT_IP",
            firewall_commands_pb2.CommandAction.LIST_RULES: "LIST_RULES",
            firewall_commands_pb2.CommandAction.ALLOW_IP_TEMP: "MONITOR"
        }
        return action_map.get(action_enum, "UNKNOWN")

    def _command_processor(self):
        """Processor thread ultra-seguro para comandos firewall"""
        self.logger.info("🔒 ULTRA-SECURE Command processor thread started")

        while self.running:
            try:
                try:
                    pb_command = self.command_queue.get(timeout=1)
                except queue.Empty:
                    continue

                # 🔒 PROCESAR COMANDO CON MÁXIMA SEGURIDAD
                self._process_ultra_secure_firewall_command(pb_command)
                self.metrics["commands_processed"] += 1

            except Exception as e:
                self.logger.error(f"❌ Command processor error: {e}")
                self.metrics["errors"] += 1
                time.sleep(1)

    def _process_ultra_secure_firewall_command(self, pb_command):
        """🔒 Procesar comando firewall con ultra-seguridad"""
        try:
            command_id = pb_command.command_id
            action = pb_command.action
            target_ip = pb_command.target_ip
            target_port = pb_command.target_port if pb_command.target_port else None
            duration = pb_command.duration_seconds if pb_command.duration_seconds else None

            action_name = self._get_action_name(action)
            self.logger.info(f"🔒 PROCESSING ULTRA-SECURE: {command_id} - {action_name} {target_ip}")

            # 🔒 SOLO ACCIONES ULTRA-SEGURAS PERMITIDAS
            if action == firewall_commands_pb2.CommandAction.LIST_RULES:
                success, message = self.firewall_manager.list_active_rules(command_id)

            elif action == firewall_commands_pb2.CommandAction.ALLOW_IP_TEMP:  # MONITOR
                success, message = self.firewall_manager.apply_monitor_rule(
                    command_id, target_ip, target_port, duration
                )

            elif action_name == "MONITOR":  # Alias adicional
                success, message = self.firewall_manager.apply_monitor_rule(
                    command_id, target_ip, target_port, duration
                )

            else:
                # 🔒 TODAS LAS DEMÁS ACCIONES SON RECHAZADAS
                success = False
                message = f"ULTRA-SECURE MODE: Action {action_name} not allowed. Only MONITOR and LIST_RULES permitted."
                self.security_logger.warning(f"🚫 BLOCKED ACTION: {action_name} for {target_ip}")

            # Send response
            self._send_response(command_id, success, message)

            if success:
                self.metrics["rules_applied"] += 1
            else:
                self.metrics["commands_rejected"] += 1

        except Exception as e:
            self.logger.error(f"❌ Error processing ultra-secure command: {e}")
            self._send_response(pb_command.command_id, False, f"Processing error: {str(e)}")

    def _send_response(self, command_id: str, success: bool, message: str):
        """Enviar respuesta al dashboard"""
        try:
            if not self.responses_socket:
                self.logger.error("❌ Responses socket not configured")
                return

            # 🔒 CREAR RESPUESTA CON MARCADORES DE SEGURIDAD
            pb_response = firewall_commands_pb2.FirewallResponse()
            pb_response.command_id = command_id
            pb_response.node_id = self.node_id
            pb_response.success = success
            pb_response.message = f"[ULTRA-SECURE] {message}"
            pb_response.timestamp = int(time.time() * 1000)

            # Serialize
            serialized_data = pb_response.SerializeToString()

            # Compress and encrypt
            encrypted_data = self._compress_and_encrypt(serialized_data)

            # Send response
            self.responses_socket.send(encrypted_data, zmq.NOBLOCK)

            self.metrics["responses_sent"] += 1

            self.logger.info(f"🔒 ULTRA-SECURE Response sent: {command_id} - Success: {success}")

        except Exception as e:
            self.logger.error(f"❌ Error sending response: {e}")
            self.metrics["errors"] += 1

    def _decrypt_and_decompress(self, data: bytes) -> bytes:
        """Decrypt and decompress data if crypto is enabled"""
        if not data:
            return data

        try:
            if self.crypto_engine:
                data = self.crypto_engine.decrypt(data)
            if self.compression_engine:
                data = self.compression_engine.decompress(data)
            return data
        except Exception as e:
            self.logger.error(f"❌ Failed to decrypt/decompress data: {e}")
            return data

    def _compress_and_encrypt(self, data: bytes) -> bytes:
        """Compress and encrypt data if crypto is enabled"""
        if not data:
            return data

        try:
            if self.compression_engine:
                result = self.compression_engine.compress(data)
                data = result.compressed_data if hasattr(result, 'compressed_data') else result
            if self.crypto_engine:
                data = self.crypto_engine.encrypt(data)
            return data
        except Exception as e:
            self.logger.error(f"❌ Failed to compress/encrypt data: {e}")
            return data

    def _cleanup_thread(self):
        """🔧 FIXED: Cleanup thread ultra-seguro con manejo robusto de errores"""
        self.logger.info("🔒 ULTRA-SECURE Cleanup thread started")

        while self.running:
            try:
                # 🧹 Limpiar reglas expiradas
                try:
                    self.firewall_manager.cleanup_expired_rules()
                except Exception as e:
                    self.logger.error(f"❌ Error cleaning expired rules: {e}")

                # 🔧 FIXED: VERIFICAR CAMBIOS EN REGLAS CON VALIDACIÓN ROBUSTA
                try:
                    if self.rules_sync:
                        # ✅ USAR EL MÉTODO QUE AHORA SÍ EXISTE
                        if hasattr(self.rules_sync, 'reload_if_changed'):
                            changed = self.rules_sync.reload_if_changed()
                            if changed:
                                self.logger.info("🔄 Rules configuration reloaded due to file changes")
                        else:
                            # Fallback si por alguna razón no existe el método
                            self.logger.warning("⚠️ reload_if_changed method not available, skipping rules reload")

                except Exception as e:
                    self.logger.error(f"❌ Error reloading rules: {e}")

                # 🔒 RE-VERIFICAR SEGURIDAD DEL ENTORNO PERIÓDICAMENTE
                try:
                    if hasattr(self.security_monitor, 'last_safety_check') and self.security_monitor.last_safety_check:
                        time_since_check = (datetime.now() - self.security_monitor.last_safety_check).total_seconds()
                        if time_since_check > 300:  # Cada 5 minutos
                            self.logger.info("🔍 Periodic environment safety re-check")
                            env_safety = self.security_monitor.detect_environment_safety()
                            if env_safety.forced_dry_run and not self.dry_run:
                                self.dry_run = True
                                self.logger.warning("🔒 DRY_RUN re-enabled due to environment change")

                except Exception as e:
                    self.logger.error(f"❌ Error in environment safety check: {e}")

                # 📊 Log periódico de estadísticas
                try:
                    if hasattr(self.rules_sync, 'get_reload_stats'):
                        stats = self.rules_sync.get_reload_stats()
                        self.logger.debug(
                            f"📊 Rules stats: {stats['load_count']} reloads, {stats['available_actions_count']} actions")
                except Exception as e:
                    self.logger.error(f"❌ Error logging stats: {e}")

                time.sleep(60)

            except Exception as e:
                self.logger.error(f"❌ Cleanup thread error: {e}")
                # 🛡️ NO detener el thread por errores individuales
                time.sleep(60)

    def start(self):
        """Iniciar el agente firewall ultra-seguro"""
        self.logger.info("🔒 Starting ULTRA-SECURE Firewall Agent...")

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

        self.logger.info(f"🔒 ULTRA-SECURE Firewall Agent started with {len(self.threads)} threads")
        self.logger.info("🔒 SAFETY GUARANTEES ACTIVE:")
        self.logger.info("   ✅ Never runs real firewall commands")
        self.logger.info("   ✅ Auto-detects dangerous environments")
        self.logger.info("   ✅ Forces dry_run mode when needed")
        self.logger.info("   ✅ Blocks dangerous IP ranges")
        self.logger.info("   ✅ Comprehensive security logging")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("🛑 Shutdown requested by user")
            self.stop()

    def stop(self):
        """Detener el agente firewall ultra-seguro"""
        self.logger.info("🔒 Stopping ULTRA-SECURE Firewall Agent...")

        self.running = False

        # Close ZMQ sockets
        if self.commands_socket:
            self.commands_socket.close()
        if self.responses_socket:
            self.responses_socket.close()

        # Close ZMQ context
        self.zmq_context.term()

        self.logger.info("🔒 ULTRA-SECURE Firewall Agent stopped safely")

    def get_status(self) -> Dict:
        """Obtener estado del agente con información de seguridad"""
        env_safety = self.security_monitor.environment_safety

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
            "capabilities": self.rules_sync.capabilities if self.rules_sync else ["MONITOR", "LIST_RULES"],
            "rules_sync_enabled": self.rules_sync is not None,
            # 🔒 INFORMACIÓN DE SEGURIDAD
            "ultra_secure_mode": self.ultra_secure_mode,
            "forced_dry_run": self.dry_run,
            "environment_safety": {
                "level": env_safety.safety_level if env_safety else "UNKNOWN",
                "is_root": env_safety.is_root if env_safety else False,
                "has_sudo": env_safety.has_sudo if env_safety else False,
                "is_container": env_safety.is_container if env_safety else False,
                "firewall_accessible": env_safety.firewall_accessible if env_safety else False,
                "safety_reasons": env_safety.safety_reasons if env_safety else []
            },
            "security_events_count": len(self.security_monitor.security_events),
            "last_safety_check": self.security_monitor.last_safety_check.isoformat() if self.security_monitor.last_safety_check else None
        }


def main():
    """Main function ULTRA-SEGURA"""
    import argparse

    parser = argparse.ArgumentParser(description="ULTRA-SECURE Firewall Agent - Set it and forget it - FIXED")
    parser.add_argument("config", help="Configuration file path (simple_firewall_agent_config.json)")
    parser.add_argument("rules", help="Firewall rules JSON file (firewall_rules_dashboard.json)")
    parser.add_argument("--log-level", default="INFO", help="Log level")

    args = parser.parse_args()

    # ✅ VALIDAR archivos de entrada
    if not Path(args.config).exists():
        print(f"❌ ERROR: Archivo de configuración no encontrado: {args.config}")
        print("📁 Necesario: simple_firewall_agent_config.json")
        sys.exit(1)

    if not Path(args.rules).exists():
        print(f"❌ ERROR: Archivo de reglas no encontrado: {args.rules}")
        print("📁 Necesario: firewall_rules_dashboard.json")
        sys.exit(1)

    print("🔒 ULTRA-SECURE FIREWALL AGENT - Starting with maximum safety - FIXED")

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - [ULTRA_SECURE] - %(message)s'
    )

    try:
        print(f"✅ Inicializando con configuración: {args.config}")
        print(f"✅ Inicializando con reglas: {args.rules}")
        print("🔒 Modo ULTRA-SEGURO activado")
        print("🔧 FIXED: Método reload_if_changed añadido")

        agent = UltraSecureFirewallAgent(args.config, args.rules)
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