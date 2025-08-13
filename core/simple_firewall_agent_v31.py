#!/usr/bin/env python3
"""
simple_firewall_agent_v31.py - MIGRATED TO PROTOBUF V3.1 WITH DUAL COMMUNICATION
✅ MIGRACIÓN COMPLETA A PROTOBUF V3.1 - TODO O NADA
✅ ARQUITECTURA DUAL: Scheduler (PUSH/PULL) + Dashboard (PUB/SUB)
✅ RESPUESTAS INDEPENDIENTES para control humano
✅ Compatibilidad total con scheduler_firewall_v31.py
✅ Ultra-seguridad mantenida
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

# Add protocols path for protobuf imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'protocols', 'current'))

# 📦 Protobuf V3.1 - Importación exclusiva (TODO O NADA)
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = "unavailable"
NetworkEventProto = None
FirewallCommandsProto = None


def import_agent_protobuf_v31():
    """Importa protobuf V3.1 EXCLUSIVO para agent - TODO O NADA"""
    global NetworkEventProto, FirewallCommandsProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    print("🔍 Agent: Buscando protobuf V3.1 EXCLUSIVO...")

    # 1. IMPORTAR FIREWALL COMMANDS V3.1
    firewall_imported = False
    firewall_strategies = [
        ("firewall_commands_v31_pb2", "Importación directa"),
        ("protocols.v3.1.firewall_commands_v31_pb2", "Paquete protocols.v3.1"),
    ]

    for import_path, description in firewall_strategies:
        try:
            FirewallCommandsProto = __import__(import_path, fromlist=[''])
            firewall_imported = True
            print(f"✅ FirewallCommands v3.1 cargado: {description}")
            break
        except ImportError:
            continue

    # 2. IMPORTAR NETWORK EVENT (ML Detector events)
    network_imported = False
    network_strategies = [
        ("network_security_clean_v31_pb2", "Importación directa v3.1"),
        ("protocols.v3.1.network_security_clean_v31_pb2", "Paquete protocols.v3.1"),
        ("network_event_extended_v3_pb2", "Importación directa v3.0"),
        ("protocols.v3.1.network_event_extended_v3_pb2", "Paquete protocols.v3.1 v3.0"),
    ]

    for import_path, description in network_strategies:
        try:
            NetworkEventProto = __import__(import_path, fromlist=[''])
            network_imported = True
            print(f"✅ NetworkEvent cargado: {description}")
            break
        except ImportError:
            continue

    # 3. ESTRATEGIA DE BÚSQUEDA POR PATHS DINÁMICOS
    if not firewall_imported or not network_imported:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        possible_paths = [
            os.path.join(current_dir, '..', 'protocols', 'v3.1'),
            os.path.join(current_dir, 'protocols', 'v3.1'),
            current_dir,
            os.path.join(current_dir, '..'),
        ]

        for protocols_path in possible_paths:
            protocols_path = os.path.abspath(protocols_path)

            # Buscar FirewallCommands V3.1
            if not firewall_imported:
                firewall_pb2_file = os.path.join(protocols_path, 'firewall_commands_v31_pb2.py')
                if os.path.exists(firewall_pb2_file):
                    try:
                        sys.path.insert(0, protocols_path)
                        import firewall_commands_v31_pb2 as FirewallCommandsProto
                        firewall_imported = True
                        print(f"✅ FirewallCommands v3.1 cargado desde: {protocols_path}")
                    except ImportError as e:
                        if protocols_path in sys.path:
                            sys.path.remove(protocols_path)

            # Buscar NetworkEvent
            if not network_imported:
                # Prioridad 1: V3.1 limpio
                network_v31_file = os.path.join(protocols_path, 'network_security_clean_v31_pb2.py')
                network_v3_file = os.path.join(protocols_path, 'network_event_extended_v3_pb2.py')

                if os.path.exists(network_v31_file):
                    try:
                        if protocols_path not in sys.path:
                            sys.path.insert(0, protocols_path)
                        import network_security_clean_v31_pb2 as NetworkEventProto
                        network_imported = True
                        print(f"✅ NetworkEvent v3.1 limpio cargado desde: {protocols_path}")
                    except ImportError:
                        pass

                # Fallback: V3.0 compatible
                elif os.path.exists(network_v3_file):
                    try:
                        if protocols_path not in sys.path:
                            sys.path.insert(0, protocols_path)
                        import network_event_extended_v3_pb2 as NetworkEventProto
                        network_imported = True
                        print(f"✅ NetworkEvent v3.0 cargado desde: {protocols_path}")
                    except ImportError:
                        pass

    # 4. VERIFICACIÓN FINAL - TODO O NADA
    if firewall_imported and network_imported:
        PROTOBUF_AVAILABLE = True
        PROTOBUF_VERSION = "v3.1.0"
        print(f"🎯 Agent: Protobuf V3.1 COMPLETO cargado exitosamente")

        # Verificar que FirewallCommand tiene los campos nativos
        try:
            test_command = FirewallCommandsProto.FirewallCommand()
            fields = [field.name for field in test_command.DESCRIPTOR.fields]

            if 'node_id' in fields and 'timestamp' in fields:
                print(f"✅ Verificado: FirewallCommand V3.1 tiene node_id y timestamp nativos")
                print(f"📋 Campos disponibles: {fields}")
                return True
            else:
                print(f"❌ ERROR: FirewallCommand no tiene campos V3.1 requeridos")
                print(f"📋 Campos encontrados: {fields}")
                print(f"📋 Campos requeridos: node_id, timestamp")
                return False

        except Exception as e:
            print(f"❌ ERROR verificando campos V3.1: {e}")
            return False
    else:
        # FALLO TOTAL - Mostrar lo que falta
        print(f"❌ Agent: Protobuf V3.1 REQUERIDO pero NO ENCONTRADO")
        print(f"📋 Estado:")
        print(f"   FirewallCommands V3.1: {'✅' if firewall_imported else '❌'}")
        print(f"   NetworkEvent: {'✅' if network_imported else '❌'}")
        print(f"📁 Archivos requeridos:")
        print(f"   • firewall_commands_v31_pb2.py")
        print(f"   • network_security_clean_v31_pb2.py (o network_event_extended_v3_pb2.py)")
        print(f"📍 Ubicaciones buscadas:")
        for path in [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'protocols', 'v3.1'),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'protocols', 'v3.1'),
        ]:
            print(f"   • {os.path.abspath(path)}")
        print(f"🔧 SOLUCIÓN: Instalar protobuf V3.1 o compilar .proto files")
        return False


# Ejecutar importación V3.1 EXCLUSIVA
if not import_agent_protobuf_v31():
    print(f"💥 FATAL: Agent requiere protobuf V3.1 para funcionar")
    print(f"🛑 PARAR EJECUCIÓN - Sin V3.1 no hay agent")
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
    origin: str  # NEW: 'scheduler' or 'dashboard'


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

    def validate_command_safety(self, action: str, target_ip: str, params: Dict, origin: str = "unknown") -> Tuple[
        bool, str, List[str]]:
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

        # 6. NEW: Log origen del comando
        self.logger.info(f"🔍 Command validation from {origin}: {action} {target_ip}")

        if not allowed:
            reason = f"Command rejected: {'; '.join(issues)}"
            self.logger.warning(f"🚫 COMMAND REJECTED FROM {origin}: {reason}")

            # Log evento de seguridad
            security_event = SecurityEvent(
                timestamp=datetime.now().isoformat(),
                event_type="command_rejected",
                severity="WARNING",
                message=f"Rejected {action} command for {target_ip} from {origin}",
                context={
                    "action": action,
                    "target_ip": target_ip,
                    "params": params,
                    "origin": origin,
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
    """Sincronización con reglas JSON - RELEASE-1.0.0 Single Source of Truth"""

    def __init__(self, rules_file: str, node_id: str, logger, security_monitor: SecurityMonitor):
        self.rules_file = rules_file
        self.node_id = node_id
        self.logger = logger
        self.security_monitor = security_monitor
        self.available_actions = []
        self.capabilities = []
        self.blocked_capabilities = []
        self.global_settings = {}
        self.manual_actions = {}
        self.risk_rules = []
        self.agent_config = {}  # Mi configuración específica desde agents_fleet
        self.last_loaded = None

        # Para tracking de cambios
        self.last_modified_time = 0
        self.file_size = 0
        self.load_count = 0

        # Cargar reglas iniciales - TODO O NADA
        self.load_rules()

    def load_rules(self):
        """Cargar reglas - RELEASE-1.0.0 agents_fleet EXCLUSIVO"""
        try:
            if not Path(self.rules_file).exists():
                raise FileNotFoundError(f"❌ CRITICAL: Rules file not found: {self.rules_file}")

            with open(self.rules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            firewall_config = data.get('firewall_rules', {})
            if not firewall_config:
                raise ValueError("❌ CRITICAL: 'firewall_rules' section not found in JSON")

            # 🎯 SINGLE SOURCE: agents_fleet EXCLUSIVO
            agents_fleet = firewall_config.get('agents_fleet', {})
            if not agents_fleet:
                raise ValueError(
                    f"❌ CRITICAL RELEASE-1.0.0: 'agents_fleet' section not found in JSON\n"
                    f"🔧 REQUIRED: JSON must contain 'firewall_rules.agents_fleet' section"
                )

            # ✅ BUSCAR MI CONFIGURACIÓN ESPECÍFICA - TODO O NADA
            if self.node_id not in agents_fleet:
                available_agents = list(agents_fleet.keys())
                raise ValueError(
                    f"❌ CRITICAL TODO O NADA: Agent '{self.node_id}' not found in agents_fleet\n"
                    f"📋 Available agents: {available_agents}\n"
                    f"🔧 REQUIRED: Agent '{self.node_id}' must exist in agents_fleet"
                )

            # ✅ EXTRAER MI CONFIGURACIÓN
            my_config = agents_fleet[self.node_id]

            # VALIDAR ESTRUCTURA OBLIGATORIA
            required_sections = ['network_endpoints', 'capabilities', 'security_profile']
            for section in required_sections:
                if section not in my_config:
                    raise ValueError(f"❌ CRITICAL: Agent {self.node_id} missing '{section}' section")

            # VALIDAR NETWORK ENDPOINTS
            network_endpoints = my_config['network_endpoints']
            required_endpoints = ['scheduler_communication', 'dashboard_communication']
            for endpoint in required_endpoints:
                if endpoint not in network_endpoints:
                    raise ValueError(f"❌ CRITICAL: Agent {self.node_id} missing '{endpoint}' endpoint")

            # VALIDAR CAPABILITIES
            capabilities = my_config['capabilities']
            if 'allowed_actions' not in capabilities:
                raise ValueError(f"❌ CRITICAL: Agent {self.node_id} missing 'allowed_actions'")

            # ✅ GUARDAR MI CONFIGURACIÓN
            self.agent_config = my_config

            # ✅ EXTRAER CAPABILITIES ESPECÍFICAS PARA MÍ
            my_allowed = capabilities.get('allowed_actions', [])
            my_blocked = capabilities.get('blocked_actions', [])

            self.logger.info(f"🎯 Agent {self.node_id} loaded from agents_fleet")
            self.logger.info(f"📍 Location: {my_config.get('location', 'unknown')}")
            self.logger.info(f"🎮 Allowed actions: {my_allowed}")
            self.logger.info(f"🚫 Blocked actions: {my_blocked}")

            # ✅ EXTRAER REGLAS GLOBALES
            self.risk_rules = firewall_config.get('rules', [])
            if not self.risk_rules:
                raise ValueError("❌ CRITICAL: No 'rules' found in JSON")

            # ✅ EXTRAER ACCIONES MANUALES
            self.manual_actions = firewall_config.get('manual_actions', {})
            if not self.manual_actions:
                raise ValueError("❌ CRITICAL: No 'manual_actions' found in JSON")

            # 🔒 FILTRAR ACCIONES SEGURAS PARA MÍ
            safe_actions = []
            for action, config in self.manual_actions.items():
                # Verificar si está bloqueada para mí
                if action in my_blocked:
                    self.logger.warning(f"🚫 Action {action} blocked for me")
                    continue

                # Verificar si está permitida para mí
                if action not in my_allowed:
                    self.logger.warning(f"🚫 Action {action} not in my capabilities")
                    continue

                # Verificar safety level
                if config.get('safety_level') == 'SAFE' and config.get('enabled', True):
                    safe_actions.append(action)
                else:
                    disabled_reason = config.get('disabled_reason', 'safety or enabled=false')
                    self.logger.warning(f"🚫 Action {action} disabled: {disabled_reason}")

            self.available_actions = safe_actions
            self.capabilities = safe_actions
            self.blocked_capabilities = my_blocked

            # ✅ CONFIGURACIÓN GLOBAL
            self.global_settings = firewall_config.get('global_settings', {})

            if self.global_settings.get('security', {}).get('force_dry_run_global', False):
                self.logger.info("🔒 Global dry_run forced by configuration")

            self.last_loaded = datetime.now()

            # ACTUALIZAR TRACKING
            if Path(self.rules_file).exists():
                file_stat = os.stat(self.rules_file)
                self.last_modified_time = file_stat.st_mtime
                self.file_size = file_stat.st_size

            self.logger.info(f"✅ Agent {self.node_id} RELEASE-1.0.0 loaded successfully")
            self.logger.info(f"📋 {len(self.risk_rules)} rules, {len(self.capabilities)} capabilities available")

        except Exception as e:
            self.logger.error(f"❌ CRITICAL ERROR loading rules for agent {self.node_id}: {e}")
            raise e

    def get_my_scheduler_endpoint(self) -> Dict:
        """Obtener MI endpoint del scheduler - GARANTIZADO"""
        if not self.agent_config:
            raise ValueError(f"❌ CRITICAL: No agent config loaded for {self.node_id}")

        network_endpoints = self.agent_config.get('network_endpoints', {})
        scheduler_comm = network_endpoints.get('scheduler_communication', {})

        if not scheduler_comm:
            raise ValueError(f"❌ CRITICAL: No scheduler_communication for {self.node_id}")

        return scheduler_comm

    def get_my_dashboard_endpoint(self) -> Dict:
        """Obtener MI endpoint del dashboard - GARANTIZADO"""
        if not self.agent_config:
            raise ValueError(f"❌ CRITICAL: No agent config loaded for {self.node_id}")

        network_endpoints = self.agent_config.get('network_endpoints', {})
        dashboard_comm = network_endpoints.get('dashboard_communication', {})

        if not dashboard_comm:
            raise ValueError(f"❌ CRITICAL: No dashboard_communication for {self.node_id}")

        return dashboard_comm

    def get_my_capabilities(self) -> Dict:
        """Obtener MIS capabilities - GARANTIZADO"""
        if not self.agent_config:
            raise ValueError(f"❌ CRITICAL: No agent config loaded for {self.node_id}")

        return self.agent_config.get('capabilities', {})

    def get_my_security_profile(self) -> Dict:
        """Obtener MI perfil de seguridad - GARANTIZADO"""
        if not self.agent_config:
            raise ValueError(f"❌ CRITICAL: No agent config loaded for {self.node_id}")

        return self.agent_config.get('security_profile', {})

    def is_action_allowed_for_me(self, action: str) -> Tuple[bool, str]:
        """Verificar si una acción está permitida para MÍ específicamente"""
        # Verificar si está bloqueada para mí
        if action in self.blocked_capabilities:
            return False, f"Action {action} is blocked for agent {self.node_id}"

        # Verificar si está en mis capacidades
        if action not in self.capabilities:
            return False, f"Action {action} not in agent {self.node_id} capabilities"

        return True, "Action allowed for this agent"

    def reload_if_changed(self) -> bool:
        """Recargar reglas si archivo cambió - MANTIENE HOT RELOAD"""
        try:
            if not Path(self.rules_file).exists():
                self.logger.warning(f"⚠️ Rules file missing: {self.rules_file}")
                return False

            file_stat = os.stat(self.rules_file)
            current_modified_time = file_stat.st_mtime
            current_file_size = file_stat.st_size

            if (current_modified_time != self.last_modified_time or
                    current_file_size != self.file_size):

                self.logger.info(f"🔄 Changes detected, reloading agent {self.node_id} config...")

                # Recargar reglas (incluye mi configuración específica)
                self.load_rules()

                self.load_count += 1
                self.logger.info(f"✅ Agent {self.node_id} config reloaded (reload #{self.load_count})")
                return True
            else:
                return False

        except Exception as e:
            self.logger.error(f"❌ Error checking changes for agent {self.node_id}: {e}")
            return False

    def get_reload_stats(self) -> Dict[str, Any]:
        """📊 Obtener estadísticas de recarga"""
        return {
            "rules_file": self.rules_file,
            "node_id": self.node_id,
            "last_loaded": self.last_loaded.isoformat() if self.last_loaded else None,
            "load_count": self.load_count,
            "capabilities_count": len(self.capabilities),
            "blocked_capabilities_count": len(self.blocked_capabilities),
            "risk_rules_count": len(self.risk_rules),
            "agent_location": self.agent_config.get('location', 'unknown'),
            "agent_version": self.agent_config.get('version', 'unknown'),
            "agent_status": self.agent_config.get('status', 'unknown')
        }


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
                           duration: Optional[int] = None, origin: str = "unknown") -> Tuple[bool, str]:
        """Aplicar regla de monitoreo (SEGURO)"""
        try:
            # 🔒 VALIDAR COMANDO
            params = {'duration': duration or 300}
            allowed, reason, issues = self.security_monitor.validate_command_safety(
                'MONITOR', target_ip, params, origin
            )

            if not allowed:
                return False, f"Security validation failed: {reason}"

            rule_id = str(uuid.uuid4())
            current_time = time.time()
            expires_at = current_time + (duration or 300)

            # Generar "regla" de monitoreo (solo logging)
            rule_text = f"MONITOR {target_ip}" + (f":{target_port}" if target_port else "")

            # 🔒 SIEMPRE DRY RUN PARA MONITOR
            self.logger.info(f"🔒 [ULTRA-SAFE MONITOR] [{origin}] {rule_text}")
            success = True
            message = f"ULTRA-SAFE MONITOR: {target_ip} monitored for {duration or 300}s from {origin}"

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
                is_dry_run=True,
                origin=origin  # NEW: Track origin
            )

            self.active_rules[rule_id] = rule
            self.rule_history.append(rule)

            self.logger.info(f"✅ Monitor rule logged: {target_ip} (Rule ID: {rule_id}) from {origin}")

            return success, message

        except Exception as e:
            self.logger.error(f"❌ Error applying monitor rule from {origin}: {e}")
            return False, f"Error applying monitor rule: {str(e)}"

    def list_active_rules(self, command_id: str, origin: str = "unknown") -> Tuple[bool, str]:
        """Listar reglas activas (SEGURO)"""
        try:
            # 🔒 VALIDAR COMANDO
            allowed, reason, issues = self.security_monitor.validate_command_safety(
                'LIST_RULES', '127.0.0.1', {}, origin
            )

            if not allowed:
                return False, f"Security validation failed: {reason}"

            active_rules = list(self.active_rules.values())
            rule_count = len(active_rules)

            # Generar resumen seguro
            rules_summary = []
            for rule in active_rules[-10:]:  # Solo últimas 10
                summary = f"{rule.action} {rule.target_ip} (expires: {rule.expires_at}) [{rule.origin}]"
                rules_summary.append(summary)

            message = f"LIST_RULES: {rule_count} active rules from {origin}"
            if rules_summary:
                message += f" - Recent: {'; '.join(rules_summary)}"

            self.logger.info(f"📋 [{origin}] {message}")
            return True, message

        except Exception as e:
            self.logger.error(f"❌ Error listing rules from {origin}: {e}")
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
            self.logger.info(f"🔄 Rule expired: {rule.target_ip} (Rule ID: {rule_id}) from {rule.origin}")

    def get_active_rules(self) -> List[FirewallRule]:
        """Obtener lista de reglas activas"""
        return list(self.active_rules.values())

    def get_rule_history(self) -> List[FirewallRule]:
        """Obtener historial de reglas"""
        return self.rule_history[-50:]  # Últimas 50


class UltraSecureFirewallAgentV31:
    """🔒 Firewall Agent Ultra-Seguro V3.1 con comunicación DUAL"""

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

        # ✅ VERIFICAR PROTOBUF V3.1 DISPONIBLE
        if not PROTOBUF_AVAILABLE:
            self.logger.error("❌ CRITICAL: Protobuf V3.1 module not available")
            raise RuntimeError("Firewall protobuf V3.1 module is required")

        self.logger.info(f"🎯 Protobuf V3.1 verificado: {PROTOBUF_VERSION}")

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
            self.logger.info(f"✅ Reglas de firewall V3.1 cargadas: {rules_file}")
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

        # 🚀 NEW: ZMQ DUAL SETUP
        self.zmq_context = zmq.Context()

        # SCHEDULER sockets (PUSH/PULL pattern)
        self.scheduler_commands_socket = None
        self.scheduler_responses_socket = None

        # DASHBOARD sockets (PUB/SUB pattern)
        self.dashboard_commands_socket = None
        self.dashboard_responses_socket = None

        # Processing
        self.command_queue = queue.Queue()
        self.running = False
        self.threads = []

        # Metrics con información de seguridad V3.1
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
            "environment_safety_level": env_safety.safety_level,
            "protobuf_version": PROTOBUF_VERSION,
            # NEW: Dual communication metrics
            "scheduler_commands": 0,
            "dashboard_commands": 0,
            "scheduler_responses": 0,
            "dashboard_responses": 0
        }

        # Initialize dual ZMQ components
        self._setup_zmq_sockets()

        self.logger.info(f"🔒 ULTRA-SECURE Firewall Agent V3.1 initialized: {self.agent_id}")
        self.logger.info(f"🔒 Environment Safety Level: {env_safety.safety_level}")
        self.logger.info(f"🔒 Forced Dry Run: {env_safety.forced_dry_run}")
        self.logger.info(f"🔒 Protobuf Version: {PROTOBUF_VERSION}")
        self.logger.info(f"🔒 Dual Communication: Scheduler (PUSH/PULL) + Dashboard (PUB/SUB)")

    def setup_logging(self):
        """Setup logging ultra-seguro con marcadores de seguridad V3.1"""
        log_config = self.config.get("logging", {})

        # Configurar nivel
        level = getattr(logging, log_config.get("level", "INFO").upper())

        # 🔒 FORMATO CON MARCADORES DE SEGURIDAD V3.1
        log_format = log_config.get("format",
                                    "%(asctime)s - %(name)s - %(levelname)s - [node_id:{node_id}] [pid:{pid}] [ULTRA_SECURE_V31] - %(message)s")

        # Reemplazar placeholders
        log_format = log_format.format(
            node_id=self.node_id,
            pid=os.getpid()
        )

        formatter = logging.Formatter(log_format)

        # Setup logger
        self.logger = logging.getLogger(f"firewall_agent_{self.node_id}_SECURE_V31")
        self.logger.setLevel(level)
        self.logger.handlers.clear()

        # Handler de consola
        console_config = log_config.get("handlers", {}).get("console", {})
        if console_config.get("enabled", True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        # Handler de archivo SEGURO V3.1
        file_config = log_config.get("handlers", {}).get("file", {})
        if file_config.get("enabled", True):
            file_path = file_config.get("path", "logs/firewall_agent_ultra_secure_v31.log")
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(file_path)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

        # 🔒 Handler de eventos de seguridad V3.1
        security_config = log_config.get("handlers", {}).get("security_log", {})
        if security_config.get("enabled", True):
            security_path = security_config.get("path", "logs/firewall_security_events_v31.log")
            Path(security_path).parent.mkdir(parents=True, exist_ok=True)
            security_handler = logging.FileHandler(security_path)
            security_formatter = logging.Formatter(
                "%(asctime)s - SECURITY - %(levelname)s - [node_id:{node_id}] [pid:{pid}] [V31] - %(message)s".format(
                    node_id=self.node_id, pid=os.getpid()
                )
            )
            security_handler.setFormatter(security_formatter)

            # Logger separado para eventos de seguridad
            self.security_logger = logging.getLogger(f"security_{self.node_id}_v31")
            self.security_logger.addHandler(security_handler)
            self.security_logger.setLevel(logging.INFO)

        self.logger.propagate = False

    def _setup_zmq_sockets(self):
        """🚀 Setup ZMQ sockets - RELEASE-1.0.0 Fleet-First approach"""
        self.logger.info("🔧 Setting up ZMQ sockets from agents_fleet configuration...")

        try:
            # 🎯 PRIORIDAD 1: Usar configuración del fleet
            try:
                scheduler_endpoint = self.rules_sync.get_my_scheduler_endpoint()
                dashboard_endpoint = self.rules_sync.get_my_dashboard_endpoint()

                self.logger.info(f"✅ Using fleet configuration for ZMQ setup")
                self._setup_scheduler_sockets_from_fleet(scheduler_endpoint)
                self._setup_dashboard_sockets_from_fleet(dashboard_endpoint)

            except Exception as fleet_error:
                self.logger.error(f"❌ CRITICAL: Failed to get fleet endpoints: {fleet_error}")

                # 🔄 FALLBACK: Usar configuración local (para desarrollo)
                self.logger.warning("🔄 Falling back to local network configuration...")
                network_config = self.config.get("network", {})

                if not network_config:
                    raise RuntimeError(
                        f"❌ CRITICAL RELEASE-1.0.0: No ZMQ configuration available\n"
                        f"🔧 REQUIRED: Either fleet endpoints OR local network config\n"
                        f"📋 Fleet error: {fleet_error}"
                    )

                self._setup_scheduler_sockets_from_local(network_config)
                self._setup_dashboard_sockets_from_local(network_config)

            self.logger.info("✅ ZMQ sockets setup complete")

        except Exception as e:
            self.logger.error(f"❌ Error setting up ZMQ sockets: {e}")
            raise RuntimeError(f"ZMQ socket setup failed: {e}")

    def _setup_dashboard_sockets_from_local(self, network_config: Dict):
        """Setup dashboard sockets desde configuración local (fallback)"""
        self.logger.warning("⚠️ Using LOCAL config for dashboard sockets (fallback)")

        # Existing local logic...
        if "dashboard_commands" in network_config:
            cmd_config = network_config["dashboard_commands"]
            self.dashboard_commands_socket = self.zmq_context.socket(zmq.SUB)
            self.dashboard_commands_socket.setsockopt(zmq.SUBSCRIBE, b"")

            cmd_address = f"tcp://{cmd_config['address']}:{cmd_config['port']}"
            cmd_mode = cmd_config.get('mode', 'connect').lower()

            if cmd_mode == 'bind':
                self.dashboard_commands_socket.bind(cmd_address)
                self.logger.info(f"🔒 Dashboard Commands SUB BIND (local): {cmd_address}")
            else:
                self.dashboard_commands_socket.connect(cmd_address)
                self.logger.info(f"🔒 Dashboard Commands SUB CONNECT (local): {cmd_address}")

        if "dashboard_responses" in network_config:
            resp_config = network_config["dashboard_responses"]
            self.dashboard_responses_socket = self.zmq_context.socket(zmq.PUB)

            resp_address = f"tcp://{resp_config['address']}:{resp_config['port']}"
            resp_mode = resp_config.get('mode', 'bind').lower()

            if resp_mode == 'bind':
                self.dashboard_responses_socket.bind(resp_address)
                self.logger.info(f"🔒 Dashboard Responses PUB BIND (local): {resp_address}")
            else:
                self.dashboard_responses_socket.connect(resp_address)
                self.logger.info(f"🔒 Dashboard Responses PUB CONNECT (local): {resp_address}")

    def _setup_scheduler_sockets_from_local(self, network_config: Dict):
        """Setup scheduler sockets desde configuración local (fallback)"""
        self.logger.warning("⚠️ Using LOCAL config for scheduler sockets (fallback)")

        # Existing local logic...
        if "scheduler_commands" in network_config:
            cmd_config = network_config["scheduler_commands"]
            self.scheduler_commands_socket = self.zmq_context.socket(zmq.PULL)

            cmd_address = f"tcp://{cmd_config['address']}:{cmd_config['port']}"
            cmd_mode = cmd_config.get('mode', 'bind').lower()

            if cmd_mode == 'bind':
                self.scheduler_commands_socket.bind(cmd_address)
                self.logger.info(f"🔒 Scheduler Commands BIND (local): {cmd_address}")
            else:
                self.scheduler_commands_socket.connect(cmd_address)
                self.logger.info(f"🔒 Scheduler Commands CONNECT (local): {cmd_address}")

        if "scheduler_responses" in network_config:
            resp_config = network_config["scheduler_responses"]
            self.scheduler_responses_socket = self.zmq_context.socket(zmq.PUSH)

            resp_address = f"tcp://{resp_config['address']}:{resp_config['port']}"
            resp_mode = resp_config.get('mode', 'connect').lower()

            if resp_mode == 'bind':
                self.scheduler_responses_socket.bind(resp_address)
                self.logger.info(f"🔒 Scheduler Responses BIND (local): {resp_address}")
            else:
                self.scheduler_responses_socket.connect(resp_address)
                self.logger.info(f"🔒 Scheduler Responses CONNECT (local): {resp_address}")

    def _setup_scheduler_sockets_from_fleet(self, scheduler_endpoint: Dict):
        """Setup scheduler sockets desde fleet configuration"""
        self.logger.info("🔥 Setting up SCHEDULER sockets from fleet...")

        # SCHEDULER COMMANDS (PULL from scheduler)
        commands_input = scheduler_endpoint.get('commands_input')
        if not commands_input:
            raise ValueError("❌ CRITICAL: Missing scheduler commands_input endpoint")

        self.scheduler_commands_socket = self.zmq_context.socket(zmq.PULL)

        # Parse endpoint
        if commands_input.startswith('tcp://'):
            address_port = commands_input.replace('tcp://', '')
            if ':' in address_port:
                address, port = address_port.split(':')
                port = int(port)
            else:
                raise ValueError(f"❌ Invalid scheduler endpoint format: {commands_input}")
        else:
            raise ValueError(f"❌ Only tcp:// endpoints supported: {commands_input}")

        # Configure socket
        self.scheduler_commands_socket.set_hwm(500)  # Default HWM

        # BIND (agent binds, scheduler connects)
        self.scheduler_commands_socket.bind(commands_input)
        self.logger.info(f"🔒 Scheduler Commands BIND on: {commands_input}")

        # SCHEDULER RESPONSES (PUSH to scheduler)
        responses_output = scheduler_endpoint.get('responses_output')
        if not responses_output:
            raise ValueError("❌ CRITICAL: Missing scheduler responses_output endpoint")

        self.scheduler_responses_socket = self.zmq_context.socket(zmq.PUSH)
        self.scheduler_responses_socket.set_hwm(200)

        # CONNECT (agent connects to scheduler)
        self.scheduler_responses_socket.connect(responses_output)
        self.logger.info(f"🔒 Scheduler Responses CONNECT to: {responses_output}")

    def _setup_dashboard_sockets_from_fleet(self, dashboard_endpoint: Dict):
        """Setup dashboard sockets desde fleet configuration"""
        self.logger.info("🚀 Setting up DASHBOARD sockets from fleet...")

        # DASHBOARD COMMANDS (SUB from dashboard)
        commands_input = dashboard_endpoint.get('commands_input')
        if not commands_input:
            raise ValueError("❌ CRITICAL: Missing dashboard commands_input endpoint")

        self.dashboard_commands_socket = self.zmq_context.socket(zmq.SUB)
        self.dashboard_commands_socket.setsockopt(zmq.SUBSCRIBE, b"")  # Subscribe to all
        self.dashboard_commands_socket.set_hwm(500)

        # CONNECT (agent connects to dashboard)
        self.dashboard_commands_socket.connect(commands_input)
        self.logger.info(f"🔒 Dashboard Commands SUB CONNECT to: {commands_input}")

        # DASHBOARD RESPONSES (PUB to dashboard)
        responses_output = dashboard_endpoint.get('responses_output')
        if not responses_output:
            raise ValueError("❌ CRITICAL: Missing dashboard responses_output endpoint")

        self.dashboard_responses_socket = self.zmq_context.socket(zmq.PUB)
        self.dashboard_responses_socket.set_hwm(200)

        # BIND (agent binds, dashboard connects)
        self.dashboard_responses_socket.bind(responses_output)
        self.logger.info(f"🔒 Dashboard Responses PUB BIND on: {responses_output}")


    def _scheduler_commands_consumer(self):
        """🔥 NEW: Consumer thread para comandos del SCHEDULER con validación ultra-segura V3.1"""
        self.logger.info("🔒 ULTRA-SECURE Scheduler Commands consumer thread V3.1 started")

        while self.running:
            try:
                if self.scheduler_commands_socket:
                    try:
                        raw_data = self.scheduler_commands_socket.recv(zmq.NOBLOCK)
                        self.logger.info(f"🔍 [SCHEDULER] Received {len(raw_data)} bytes for security validation")

                        # Decrypt and decompress
                        decrypted_data = self._decrypt_and_decompress(raw_data)

                        try:
                            # 🚀 USAR PROTOBUF V3.1
                            pb_command = FirewallCommandsProto.FirewallCommand()
                            pb_command.ParseFromString(decrypted_data)

                            # 🔒 VALIDACIÓN DE SEGURIDAD INMEDIATA
                            if not pb_command.command_id:
                                pb_command.command_id = f"auto_scheduler_{int(time.time())}"

                            if not pb_command.target_ip:
                                pb_command.target_ip = "127.0.0.1"

                            # 🔒 FORZAR DRY_RUN
                            pb_command.dry_run = True

                            self.logger.info(
                                f"🔒 SCHEDULER V3.1 CHECK: {pb_command.command_id}, action={pb_command.action}, ip={pb_command.target_ip}")

                            # 🔒 PRE-VALIDACIÓN DE COMANDO CON ORIGEN
                            params = {
                                'duration': pb_command.duration_seconds,
                                'dry_run': True  # Siempre
                            }

                            action_name = self._get_action_name(pb_command.action)
                            allowed, reason, issues = self.security_monitor.validate_command_safety(
                                action_name, pb_command.target_ip, params, "scheduler"
                            )

                            if allowed:
                                # Añadir origen al comando
                                pb_command.origin = "scheduler"  # Custom field tracking
                                self.command_queue.put(('scheduler', pb_command))
                                self.metrics["commands_received"] += 1
                                self.metrics["scheduler_commands"] += 1
                                self.logger.info(f"✅ Scheduler command passed security validation")
                            else:
                                self.metrics["commands_rejected"] += 1
                                self.security_logger.warning(f"🚫 SCHEDULER COMMAND REJECTED: {reason}")

                                # Enviar respuesta de rechazo
                                self._send_scheduler_response(pb_command.command_id, False,
                                                              f"Security validation failed: {reason}")

                        except Exception as parse_error:
                            self.logger.error(f"❌ Scheduler Protobuf V3.1 parse error: {parse_error}")

                    except zmq.Again:
                        pass
                    except Exception as e:
                        self.logger.error(f"❌ Error receiving scheduler command: {e}")
                        self.metrics["errors"] += 1

                time.sleep(0.001)

            except Exception as e:
                self.logger.error(f"❌ Scheduler commands consumer error: {e}")
                self.metrics["errors"] += 1
                time.sleep(1)

    def _dashboard_commands_consumer(self):
        """🚀 NEW: Consumer thread para comandos del DASHBOARD con validación ultra-segura V3.1"""
        self.logger.info("🔒 ULTRA-SECURE Dashboard Commands consumer thread V3.1 started")

        while self.running:
            try:
                if self.dashboard_commands_socket:
                    try:
                        raw_data = self.dashboard_commands_socket.recv(zmq.NOBLOCK)
                        self.logger.info(f"🔍 [DASHBOARD] Received {len(raw_data)} bytes for security validation")

                        # Decrypt and decompress
                        decrypted_data = self._decrypt_and_decompress(raw_data)

                        try:
                            # 🚀 USAR PROTOBUF V3.1
                            pb_command = FirewallCommandsProto.FirewallCommand()
                            pb_command.ParseFromString(decrypted_data)

                            # 🔒 VALIDACIÓN DE SEGURIDAD INMEDIATA
                            if not pb_command.command_id:
                                pb_command.command_id = f"auto_dashboard_{int(time.time())}"

                            if not pb_command.target_ip:
                                pb_command.target_ip = "127.0.0.1"

                            # 🔒 FORZAR DRY_RUN
                            pb_command.dry_run = True

                            self.logger.info(
                                f"🔒 DASHBOARD V3.1 CHECK: {pb_command.command_id}, action={pb_command.action}, ip={pb_command.target_ip}")

                            # 🔒 PRE-VALIDACIÓN DE COMANDO CON ORIGEN
                            params = {
                                'duration': pb_command.duration_seconds,
                                'dry_run': True  # Siempre
                            }

                            action_name = self._get_action_name(pb_command.action)
                            allowed, reason, issues = self.security_monitor.validate_command_safety(
                                action_name, pb_command.target_ip, params, "dashboard"
                            )

                            if allowed:
                                # Añadir origen al comando
                                pb_command.origin = "dashboard"  # Custom field tracking
                                self.command_queue.put(('dashboard', pb_command))
                                self.metrics["commands_received"] += 1
                                self.metrics["dashboard_commands"] += 1
                                self.logger.info(f"✅ Dashboard command passed security validation")
                            else:
                                self.metrics["commands_rejected"] += 1
                                self.security_logger.warning(f"🚫 DASHBOARD COMMAND REJECTED: {reason}")

                                # Enviar respuesta de rechazo
                                self._send_dashboard_response(pb_command.command_id, False,
                                                              f"Security validation failed: {reason}")

                        except Exception as parse_error:
                            self.logger.error(f"❌ Dashboard Protobuf V3.1 parse error: {parse_error}")

                    except zmq.Again:
                        pass
                    except Exception as e:
                        self.logger.error(f"❌ Error receiving dashboard command: {e}")
                        self.metrics["errors"] += 1

                time.sleep(0.001)

            except Exception as e:
                self.logger.error(f"❌ Dashboard commands consumer error: {e}")
                self.metrics["errors"] += 1
                time.sleep(1)

    def _get_action_name(self, action_enum: int) -> str:
        """Convertir enum de acción V3.1 a string"""
        # 🚀 V3.1 action mappings
        action_map = {
            FirewallCommandsProto.CommandAction.BLOCK_IP: "BLOCK_IP",
            FirewallCommandsProto.CommandAction.UNBLOCK_IP: "UNBLOCK_IP",
            FirewallCommandsProto.CommandAction.RATE_LIMIT_IP: "RATE_LIMIT_IP",
            FirewallCommandsProto.CommandAction.LIST_RULES: "LIST_RULES",
            FirewallCommandsProto.CommandAction.ALLOW_IP_TEMP: "MONITOR"
        }
        return action_map.get(action_enum, "UNKNOWN")

    def _command_processor(self):
        """🚀 NEW: Processor thread ultra-seguro para comandos firewall DUAL V3.1"""
        self.logger.info("🔒 ULTRA-SECURE Dual Command processor thread V3.1 started")

        while self.running:
            try:
                try:
                    origin, pb_command = self.command_queue.get(timeout=1)
                except queue.Empty:
                    continue

                # 🔒 PROCESAR COMANDO CON MÁXIMA SEGURIDAD V3.1
                self._process_ultra_secure_firewall_command_v31(origin, pb_command)
                self.metrics["commands_processed"] += 1

            except Exception as e:
                self.logger.error(f"❌ Command processor V3.1 error: {e}")
                self.metrics["errors"] += 1
                time.sleep(1)

    def _process_ultra_secure_firewall_command_v31(self, origin: str, pb_command):
        """🔒 Procesar comando firewall con ultra-seguridad V3.1"""
        try:
            command_id = pb_command.command_id
            action = pb_command.action
            target_ip = pb_command.target_ip
            target_port = pb_command.target_port if pb_command.target_port else None
            duration = pb_command.duration_seconds if pb_command.duration_seconds else None

            action_name = self._get_action_name(action)
            self.logger.info(f"🔒 PROCESSING ULTRA-SECURE V3.1: [{origin}] {command_id} - {action_name} {target_ip}")

            # 🔒 SOLO ACCIONES ULTRA-SEGURAS PERMITIDAS
            if action == FirewallCommandsProto.CommandAction.LIST_RULES:
                success, message = self.firewall_manager.list_active_rules(command_id, origin)

            elif action == FirewallCommandsProto.CommandAction.ALLOW_IP_TEMP:  # MONITOR
                success, message = self.firewall_manager.apply_monitor_rule(
                    command_id, target_ip, target_port, duration, origin
                )

            elif action_name == "MONITOR":  # Alias adicional
                success, message = self.firewall_manager.apply_monitor_rule(
                    command_id, target_ip, target_port, duration, origin
                )

            else:
                # 🔒 TODAS LAS DEMÁS ACCIONES SON RECHAZADAS
                success = False
                message = f"ULTRA-SECURE V3.1 MODE: Action {action_name} not allowed. Only MONITOR and LIST_RULES permitted."
                self.security_logger.warning(f"🚫 BLOCKED ACTION FROM {origin}: {action_name} for {target_ip}")

            # Send response to appropriate destination
            if origin == "scheduler":
                self._send_scheduler_response(command_id, success, message)
                if success:
                    self.metrics["scheduler_responses"] += 1
            elif origin == "dashboard":
                self._send_dashboard_response(command_id, success, message)
                if success:
                    self.metrics["dashboard_responses"] += 1

            if success:
                self.metrics["rules_applied"] += 1
            else:
                self.metrics["commands_rejected"] += 1

        except Exception as e:
            self.logger.error(f"❌ Error processing ultra-secure V3.1 command from {origin}: {e}")
            if origin == "scheduler":
                self._send_scheduler_response(pb_command.command_id, False, f"Processing error: {str(e)}")
            elif origin == "dashboard":
                self._send_dashboard_response(pb_command.command_id, False, f"Processing error: {str(e)}")

    def _send_scheduler_response(self, command_id: str, success: bool, message: str):
        """🔥 NEW: Enviar respuesta al SCHEDULER"""
        try:
            if not self.scheduler_responses_socket:
                self.logger.error("❌ Scheduler responses socket not configured")
                return

            # 🔒 CREAR RESPUESTA V3.1 CON MARCADORES DE SEGURIDAD
            pb_response = FirewallCommandsProto.FirewallResponse()
            pb_response.command_id = command_id
            pb_response.node_id = self.node_id
            pb_response.success = success
            pb_response.message = f"[ULTRA-SECURE-V31-SCHEDULER] {message}"
            pb_response.timestamp = int(time.time() * 1000)

            # Serialize
            serialized_data = pb_response.SerializeToString()

            # Compress and encrypt
            encrypted_data = self._compress_and_encrypt(serialized_data)

            # Send response
            self.scheduler_responses_socket.send(encrypted_data, zmq.NOBLOCK)

            self.metrics["responses_sent"] += 1

            self.logger.info(f"🔒 ULTRA-SECURE V3.1 Response sent to SCHEDULER: {command_id} - Success: {success}")

        except Exception as e:
            self.logger.error(f"❌ Error sending scheduler response: {e}")
            self.metrics["errors"] += 1

    def _send_dashboard_response(self, command_id: str, success: bool, message: str):
        """🚀 NEW: Enviar respuesta al DASHBOARD"""
        try:
            if not self.dashboard_responses_socket:
                self.logger.error("❌ Dashboard responses socket not configured")
                return

            # 🔒 CREAR RESPUESTA V3.1 CON MARCADORES DE SEGURIDAD
            pb_response = FirewallCommandsProto.FirewallResponse()
            pb_response.command_id = command_id
            pb_response.node_id = self.node_id
            pb_response.success = success
            pb_response.message = f"[ULTRA-SECURE-V31-DASHBOARD] {message}"
            pb_response.timestamp = int(time.time() * 1000)

            # Serialize
            serialized_data = pb_response.SerializeToString()

            # Compress and encrypt
            encrypted_data = self._compress_and_encrypt(serialized_data)

            # Send response via PUB socket
            self.dashboard_responses_socket.send(encrypted_data, zmq.NOBLOCK)

            self.metrics["responses_sent"] += 1

            self.logger.info(f"🔒 ULTRA-SECURE V3.1 Response sent to DASHBOARD: {command_id} - Success: {success}")

        except Exception as e:
            self.logger.error(f"❌ Error sending dashboard response: {e}")
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
        """🔧 Cleanup thread ultra-seguro V3.1 con manejo robusto de errores"""
        self.logger.info("🔒 ULTRA-SECURE Cleanup thread V3.1 started")

        while self.running:
            try:
                # 🧹 Limpiar reglas expiradas
                try:
                    self.firewall_manager.cleanup_expired_rules()
                except Exception as e:
                    self.logger.error(f"❌ Error cleaning expired rules: {e}")

                # 🔧 VERIFICAR CAMBIOS EN REGLAS CON VALIDACIÓN ROBUSTA
                try:
                    if self.rules_sync:
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
                            self.logger.info("🔍 Periodic environment safety re-check V3.1")
                            env_safety = self.security_monitor.detect_environment_safety()
                            if env_safety.forced_dry_run and not self.dry_run:
                                self.dry_run = True
                                self.logger.warning("🔒 DRY_RUN re-enabled due to environment change")

                except Exception as e:
                    self.logger.error(f"❌ Error in environment safety check: {e}")

                # 📊 Log periódico de estadísticas V3.1
                try:
                    if hasattr(self.rules_sync, 'get_reload_stats'):
                        stats = self.rules_sync.get_reload_stats()
                        self.logger.debug(
                            f"📊 V3.1 Rules stats: {stats['load_count']} reloads, {stats['available_actions_count']} actions")
                        self.logger.debug(
                            f"📊 V3.1 Dual stats: Scheduler({self.metrics['scheduler_commands']}) Dashboard({self.metrics['dashboard_commands']})")
                except Exception as e:
                    self.logger.error(f"❌ Error logging stats: {e}")

                time.sleep(60)

            except Exception as e:
                self.logger.error(f"❌ Cleanup thread V3.1 error: {e}")
                # 🛡️ NO detener el thread por errores individuales
                time.sleep(60)

    def start(self):
        """🚀 NEW: Iniciar el agente firewall ultra-seguro V3.1 DUAL"""
        self.logger.info("🔒 Starting ULTRA-SECURE Firewall Agent V3.1 DUAL...")

        self.running = True

        # Start SCHEDULER consumer thread
        if self.scheduler_commands_socket:
            scheduler_consumer_thread = threading.Thread(target=self._scheduler_commands_consumer, daemon=True)
            scheduler_consumer_thread.start()
            self.threads.append(scheduler_consumer_thread)

        # Start DASHBOARD consumer thread
        if self.dashboard_commands_socket:
            dashboard_consumer_thread = threading.Thread(target=self._dashboard_commands_consumer, daemon=True)
            dashboard_consumer_thread.start()
            self.threads.append(dashboard_consumer_thread)

        # Start processor thread
        processor_thread = threading.Thread(target=self._command_processor, daemon=True)
        processor_thread.start()
        self.threads.append(processor_thread)

        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_thread, daemon=True)
        cleanup_thread.start()
        self.threads.append(cleanup_thread)

        self.logger.info(f"🔒 ULTRA-SECURE Firewall Agent V3.1 DUAL started with {len(self.threads)} threads")
        self.logger.info("🔒 SAFETY GUARANTEES ACTIVE V3.1:")
        self.logger.info("   ✅ Never runs real firewall commands")
        self.logger.info("   ✅ Auto-detects dangerous environments")
        self.logger.info("   ✅ Forces dry_run mode when needed")
        self.logger.info("   ✅ Blocks dangerous IP ranges")
        self.logger.info("   ✅ Comprehensive security logging")
        self.logger.info("   ✅ Dual communication: Scheduler + Dashboard")
        self.logger.info("   ✅ Independent responses for human control")
        self.logger.info("   ✅ Protobuf V3.1 with native node_id/timestamp")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("🛑 Shutdown requested by user")
            self.stop()

    def stop(self):
        """Detener el agente firewall ultra-seguro V3.1"""
        self.logger.info("🔒 Stopping ULTRA-SECURE Firewall Agent V3.1 DUAL...")

        self.running = False

        # Close ZMQ sockets
        if self.scheduler_commands_socket:
            self.scheduler_commands_socket.close()
        if self.scheduler_responses_socket:
            self.scheduler_responses_socket.close()
        if self.dashboard_commands_socket:
            self.dashboard_commands_socket.close()
        if self.dashboard_responses_socket:
            self.dashboard_responses_socket.close()

        # Close ZMQ context
        self.zmq_context.term()

        self.logger.info("🔒 ULTRA-SECURE Firewall Agent V3.1 DUAL stopped safely")

    def get_status(self) -> Dict:
        """Obtener estado del agente con información de seguridad V3.1"""
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
            # 🔒 INFORMACIÓN DE SEGURIDAD V3.1
            "ultra_secure_mode": self.ultra_secure_mode,
            "forced_dry_run": self.dry_run,
            "protobuf_version": PROTOBUF_VERSION,
            "dual_communication": {
                "scheduler_enabled": self.scheduler_commands_socket is not None,
                "dashboard_enabled": self.dashboard_commands_socket is not None,
                "scheduler_commands": self.metrics["scheduler_commands"],
                "dashboard_commands": self.metrics["dashboard_commands"],
                "scheduler_responses": self.metrics["scheduler_responses"],
                "dashboard_responses": self.metrics["dashboard_responses"]
            },
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
    """Main function ULTRA-SEGURA V3.1"""
    import argparse

    parser = argparse.ArgumentParser(
        description="ULTRA-SECURE Firewall Agent V3.1 - Dual communication with human control")
    parser.add_argument("config", help="Configuration file path (simple_firewall_agent_v31_config.json)")
    parser.add_argument("rules", help="Firewall rules JSON file (firewall_rules_dashboard.json)")
    parser.add_argument("--log-level", default="INFO", help="Log level")

    args = parser.parse_args()

    # ✅ VALIDAR archivos de entrada
    if not Path(args.config).exists():
        print(f"❌ ERROR: Archivo de configuración no encontrado: {args.config}")
        print("📁 Necesario: simple_firewall_agent_v31_config.json")
        sys.exit(1)

    if not Path(args.rules).exists():
        print(f"❌ ERROR: Archivo de reglas no encontrado: {args.rules}")
        print("📁 Necesario: firewall_rules_dashboard.json")
        sys.exit(1)

    print("🔒 ULTRA-SECURE FIREWALL AGENT V3.1 - Dual communication for human control")
    print("🚀 Protobuf V3.1 native support")
    print("🔄 Scheduler (PUSH/PULL) + Dashboard (PUB/SUB)")
    print("🛡️ Independent responses for security oversight")

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - [ULTRA_SECURE_V31] - %(message)s'
    )

    try:
        print(f"✅ Inicializando con configuración V3.1: {args.config}")
        print(f"✅ Inicializando con reglas: {args.rules}")
        print("🔒 Modo ULTRA-SEGURO V3.1 activado")
        print("🎯 TODO O NADA: Protobuf V3.1 verificado")

        agent = UltraSecureFirewallAgentV31(args.config, args.rules)
        agent.start()

    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested by user")
    except Exception as e:
        print(f"❌ Agent V3.1 error: {e}")
    finally:
        if 'agent' in locals():
            agent.stop()


if __name__ == "__main__":
    main()