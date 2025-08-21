#!/usr/bin/env python3
"""
scheduler-firewall-v31-etcd.py - FIREWALL DECISION ENGINE NO-GUI V1.0.0 - V3.1 PROTOBUF + ETCD CRYPTO
✅ JSON-controlled decision engine para upgraded-happiness CON ETCD CRYPTO OBLIGATORIO
✅ Compatible con ML Detector V3.1.2 tricapa (4 modelos)
✅ Configuración conservadora basada en números actuales
✅ Zero hardcoding - Todo desde JSON + ETCD
✅ V3.1 PROTOBUF EXCLUSIVO - con node_id y timestamp nativos
✅ ETCD crypto obligatorio - NO fallbacks si crypto habilitado
✅ Preparado para optimización en tiempo real como "chip inteligente"
✅ Logs enriquecidos con contexto completo
"""
import zmq
import json
import threading
import time
import logging
import queue
import os
import sys
import signal
import psutil
import hashlib
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque

# 🔥 NUEVO: Importar cliente ETCD específico para scheduler firewall - SIN CORE
try:
    from etcd_crypto_client_scheduler_firewall_fixed import (
        setup_scheduler_firewall_crypto,
        get_scheduler_firewall_pipeline_key,
        get_scheduler_firewall_crypto_status
    )
    ETCD_CRYPTO_CLIENT_AVAILABLE = True
    print("✅ ETCD Crypto Client for Scheduler Firewall loaded successfully")
except ImportError as e:
    print(f"❌ CRITICAL: ETCD Crypto Client not available: {e}")
    print("📁 Required: etcd_crypto_client_scheduler_firewall_fixed.py")
    ETCD_CRYPTO_CLIENT_AVAILABLE = False

# Add protocols path for protobuf imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'protocols', 'current'))

# 📦 Protobuf V3.1 - Importación exclusiva (TODO O NADA)
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = "unavailable"
NetworkEventProto = None
FirewallCommandsProto = None


def import_scheduler_protobuf_v31():
    """Importa protobuf V3.1 EXCLUSIVO para scheduler - TODO O NADA - FIXED PATHS"""
    global NetworkEventProto, FirewallCommandsProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    print("🔍 Scheduler ETCD: Buscando protobuf V3.1 EXCLUSIVO...")

    # 1. IMPORTAR FIREWALL COMMANDS V3.1 - RUTAS CORREGIDAS
    firewall_imported = False
    firewall_strategies = [
        ("firewall_commands_v31_pb2", "Importación directa"),
        ("protocols.v3_1.firewall_commands_v31_pb2", "Paquete protocols.v3_1"),
    ]

    for import_path, description in firewall_strategies:
        try:
            FirewallCommandsProto = __import__(import_path, fromlist=[''])
            firewall_imported = True
            print(f"✅ FirewallCommands v3.1 cargado: {description}")
            break
        except ImportError:
            continue

    # 2. IMPORTAR NETWORK EVENT (ML Detector events) - RUTAS CORREGIDAS
    network_imported = False
    network_strategies = [
        ("network_security_clean_v31_pb2", "Importación directa v3.1"),
        ("protocols.v3_1.network_security_clean_v31_pb2", "Paquete protocols.v3_1"),
        ("network_event_extended_v3_pb2", "Importación directa v3.0"),
        ("protocols.v3_1.network_event_extended_v3_pb2", "Paquete protocols.v3_1 v3.0"),
    ]

    for import_path, description in network_strategies:
        try:
            NetworkEventProto = __import__(import_path, fromlist=[''])
            network_imported = True
            print(f"✅ NetworkEvent cargado: {description}")
            break
        except ImportError:
            continue

    # 3. ESTRATEGIA DE BÚSQUEDA POR PATHS DINÁMICOS - RUTAS CORREGIDAS V3_1
    if not firewall_imported or not network_imported:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        possible_paths = [
            os.path.join(current_dir, '..', 'protocols', 'v3_1'),  # CORREGIDO: v3_1
            os.path.join(current_dir, 'protocols', 'v3_1'),       # CORREGIDO: v3_1
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
        print(f"🎯 Scheduler ETCD: Protobuf V3.1 COMPLETO cargado exitosamente")

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
        print(f"❌ Scheduler ETCD: Protobuf V3.1 REQUERIDO pero NO ENCONTRADO")
        print(f"📋 Estado:")
        print(f"   FirewallCommands V3.1: {'✅' if firewall_imported else '❌'}")
        print(f"   NetworkEvent: {'✅' if network_imported else '❌'}")
        print(f"📁 Archivos requeridos:")
        print(f"   • firewall_commands_v31_pb2.py")
        print(f"   • network_security_clean_v31_pb2.py (o network_event_extended_v3_pb2.py)")
        print(f"📍 Ubicaciones buscadas:")
        for path in [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'protocols', 'v3_1'),  # CORREGIDO: v3_1
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'protocols', 'v3_1'),        # CORREGIDO: v3_1
        ]:
            print(f"   • {os.path.abspath(path)}")
        print(f"🔧 SOLUCIÓN: Instalar protobuf V3.1 o compilar .proto files")
        return False


# Ejecutar importación V3.1 EXCLUSIVA
if not import_scheduler_protobuf_v31():
    print(f"💥 FATAL: Scheduler ETCD requiere protobuf V3.1 para funcionar")
    print(f"🛑 PARAR EJECUCIÓN - Sin V3.1 no hay scheduler")
    sys.exit(1)


class SchedulerConfigurationError(Exception):
    """Error de configuración del scheduler"""
    pass


class FirewallSchedulerRulesError(Exception):
    """Error en reglas de firewall del scheduler"""
    pass


class ETCDCryptoError(Exception):
    """Error específico de ETCD crypto"""
    pass


@dataclass
class FirewallDecision:
    """Decisión tomada por el scheduler"""
    event_id: str
    source_ip: str
    target_ip: str
    risk_score: float
    risk_percentage: int
    recommended_action: str
    action_params: Dict[str, Any]
    decision_reason: str
    decision_timestamp: datetime
    firewall_node_id: str
    command_id: str
    dry_run: bool
    priority: str
    rule_applied: Dict[str, Any]


@dataclass
class SchedulerStats:
    """Estadísticas del scheduler"""
    events_received: int = 0
    events_processed: int = 0
    decisions_made: int = 0
    commands_sent: int = 0
    responses_received: int = 0
    errors: int = 0
    monitor_decisions: int = 0
    rate_limit_decisions: int = 0
    block_decisions: int = 0
    uptime_start: float = 0
    last_event_time: Optional[datetime] = None
    last_decision_time: Optional[datetime] = None
    etcd_crypto_operations: int = 0
    etcd_crypto_errors: int = 0


class FirewallSchedulerRulesEngine:
    """Motor de reglas de firewall para scheduler - JSON-controlled"""

    def __init__(self, rules_file: str, logger):
        self.rules_file = rules_file
        self.logger = logger
        self.rules: List[Dict] = []
        self.manual_actions: Dict[str, Dict] = {}
        self.firewall_agents: Dict[str, Dict] = {}
        self.global_settings: Dict[str, Any] = {}
        self.last_loaded: Optional[datetime] = None
        self.last_modified_time = 0
        self.file_size = 0
        self.load_count = 0

        # Validación previa
        if not Path(self.rules_file).exists():
            raise FirewallSchedulerRulesError(f"❌ Rules file not found: {self.rules_file}")

        # Cargar reglas iniciales
        self.load_rules()

    def load_rules(self, force_reload: bool = False):
        """Cargar reglas desde JSON - RELEASE-1.0.0 SINGLE SOURCE EXCLUSIVO"""
        try:
            if not Path(self.rules_file).exists():
                raise FirewallSchedulerRulesError(f"❌ CRITICAL: Rules file not found: {self.rules_file}")

            with open(self.rules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            firewall_config = data.get('firewall_rules', {})
            if not firewall_config:
                raise FirewallSchedulerRulesError("❌ CRITICAL: 'firewall_rules' section not found in JSON")

            # ✅ CARGAR REGLAS PRINCIPALES
            self.rules = firewall_config.get('rules', [])
            if not self.rules:
                raise FirewallSchedulerRulesError("❌ CRITICAL: No 'rules' found in JSON")

            # Filtrar solo reglas enabled
            self.rules = [rule for rule in self.rules if rule.get('enabled', True)]

            # ✅ CARGAR ACCIONES MANUALES
            self.manual_actions = firewall_config.get('manual_actions', {})
            if not self.manual_actions:
                raise FirewallSchedulerRulesError("❌ CRITICAL: No 'manual_actions' found in JSON")

            # 🎯 SINGLE SOURCE OF TRUTH: agents_fleet EXCLUSIVO
            agents_fleet = firewall_config.get('agents_fleet', {})
            if not agents_fleet:
                raise FirewallSchedulerRulesError(
                    "❌ CRITICAL RELEASE-1.0.0: 'agents_fleet' section not found in JSON\n"
                    "🔧 REQUIRED: JSON must contain 'firewall_rules.agents_fleet' with agent configurations\n"
                    "📋 JSON structure must be: firewall_rules.agents_fleet.{node_id}.network_endpoints"
                )

            # ✅ PROCESAR AGENTS FLEET
            self.firewall_agents = {}
            for agent_id, agent_config in agents_fleet.items():

                # VALIDAR ESTRUCTURA OBLIGATORIA
                if not isinstance(agent_config, dict):
                    raise FirewallSchedulerRulesError(f"❌ CRITICAL: Agent {agent_id} config is not dict")

                network_endpoints = agent_config.get('network_endpoints', {})
                if not network_endpoints:
                    raise FirewallSchedulerRulesError(f"❌ CRITICAL: Agent {agent_id} missing 'network_endpoints'")

                scheduler_comm = network_endpoints.get('scheduler_communication', {})
                if not scheduler_comm:
                    raise FirewallSchedulerRulesError(f"❌ CRITICAL: Agent {agent_id} missing 'scheduler_communication'")

                capabilities = agent_config.get('capabilities', {})
                if not capabilities:
                    raise FirewallSchedulerRulesError(f"❌ CRITICAL: Agent {agent_id} missing 'capabilities'")

                # CONVERTIR A FORMATO SCHEDULER
                self.firewall_agents[agent_id] = {
                    'node_id': agent_id,
                    'endpoint': scheduler_comm.get('commands_input'),
                    'capabilities': capabilities.get('allowed_actions', []),
                    'blocked_capabilities': capabilities.get('blocked_actions', []),
                    'max_rules': capabilities.get('max_concurrent_rules', 10),
                    'default_rule_duration': capabilities.get('default_rule_duration', 60),
                    'safety_mode': agent_config.get('security_profile', {}).get('safety_mode', 'ULTRA_SECURE_V31'),
                    'location': agent_config.get('location', 'unknown'),
                    'version': agent_config.get('version', '3.1.0'),
                    'status': agent_config.get('status', 'active')
                }

                # VALIDAR CAMPOS CRÍTICOS
                if not self.firewall_agents[agent_id]['endpoint']:
                    raise FirewallSchedulerRulesError(f"❌ CRITICAL: Agent {agent_id} missing commands_input endpoint")

                if not self.firewall_agents[agent_id]['capabilities']:
                    raise FirewallSchedulerRulesError(f"❌ CRITICAL: Agent {agent_id} has no allowed_actions")

            # VALIDAR QUE TENEMOS AGENTES
            if not self.firewall_agents:
                raise FirewallSchedulerRulesError(
                    "❌ CRITICAL RELEASE-1.0.0: No agents loaded from agents_fleet\n"
                    "🔧 REQUIRED: JSON must contain at least one agent in agents_fleet"
                )

            # ✅ CONFIGURACIÓN GLOBAL
            self.global_settings = firewall_config.get('global_settings', {})

            self.last_loaded = datetime.now()

            # ACTUALIZAR TRACKING
            if Path(self.rules_file).exists():
                file_stat = os.stat(self.rules_file)
                self.last_modified_time = file_stat.st_mtime
                self.file_size = file_stat.st_size

            # LOG ÉXITO
            self.logger.info(f"✅ RELEASE-1.0.0 LOADED: {len(self.rules)} rules, {len(self.firewall_agents)} agents")
            self.logger.info(f"🎯 Agents fleet:")
            for agent_id, agent_info in self.firewall_agents.items():
                endpoint = agent_info['endpoint']
                location = agent_info['location']
                status = agent_info['status']
                capabilities = len(agent_info['capabilities'])
                self.logger.info(f"   🤖 {agent_id}: {endpoint} ({location}, {status}, {capabilities} capabilities)")

            # Validar configuración
            self._validate_rules_configuration()

        except json.JSONDecodeError as e:
            raise FirewallSchedulerRulesError(f"❌ JSON PARSE ERROR: {e}")
        except Exception as e:
            raise FirewallSchedulerRulesError(f"❌ SCHEDULER LOAD ERROR: {e}")

    def _validate_rules_configuration(self):
        """Validar configuración de reglas cargadas"""
        issues = []

        # Validar que hay al menos un agente
        if not self.firewall_agents:
            issues.append("No firewall agents configured")

        # Validar cobertura de risk_score
        risk_coverage = set()
        for rule in self.rules:
            if rule.get('enabled', True):
                risk_range = rule.get('risk_range', [])
                if len(risk_range) >= 2:
                    for risk in range(risk_range[0], risk_range[1] + 1):
                        risk_coverage.add(risk)

        missing_ranges = []
        for risk in range(0, 101):
            if risk not in risk_coverage:
                missing_ranges.append(risk)

        if missing_ranges:
            issues.append(
                f"Risk scores without coverage: {missing_ranges[:10]}{'...' if len(missing_ranges) > 10 else ''}")

        # Validar acciones disponibles
        available_actions = set(self.manual_actions.keys())
        required_actions = {'MONITOR', 'LIST_RULES'}  # Mínimo para modo seguro

        if not required_actions.issubset(available_actions):
            missing_actions = required_actions - available_actions
            issues.append(f"Required actions missing: {missing_actions}")

        # Log issues
        if issues:
            self.logger.warning(f"⚠️ Scheduler rules configuration issues: {issues}")
        else:
            self.logger.info("✅ Scheduler rules configuration validated successfully")

    def get_decision_for_risk_score(self, risk_score: float) -> Optional[Dict]:
        """Obtener decisión basada en risk_score - SCHEDULER ENGINE"""
        try:
            # Convertir risk_score (0.0-1.0) a porcentaje (0-100)
            risk_percentage = int(risk_score * 100)
            risk_percentage = max(0, min(100, risk_percentage))  # Clamp to 0-100

            self.logger.debug(f"🎯 Evaluating risk: {risk_score:.3f} -> {risk_percentage}%")

            # Buscar regla que coincida con el rango de riesgo
            matching_rules = []
            for rule in self.rules:
                if not rule.get('enabled', True):
                    continue

                risk_range = rule.get('risk_range', [])
                if len(risk_range) >= 2 and risk_range[0] <= risk_percentage <= risk_range[1]:
                    matching_rules.append(rule)

            if matching_rules:
                # Si hay múltiples reglas, elegir la de mayor prioridad
                priority_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
                best_rule = max(matching_rules, key=lambda r: priority_order.get(r.get('priority', 'MEDIUM'), 2))

                decision = {
                    'action': best_rule.get('action', 'MONITOR'),
                    'params': best_rule.get('params', {}),
                    'priority': best_rule.get('priority', 'MEDIUM'),
                    'dry_run': best_rule.get('dry_run', True),
                    'description': best_rule.get('description', ''),
                    'rule_range': best_rule.get('risk_range', [0, 100]),
                    'risk_percentage': risk_percentage,
                    'rule_applied': best_rule
                }

                self.logger.info(
                    f"🎯 Decision: risk {risk_percentage}% -> {decision['action']} (rule: {decision['description']})")
                return decision

            # Si no hay regla específica, usar MONITOR por defecto
            self.logger.warning(f"⚠️ No rule for risk {risk_percentage}%, using default MONITOR")
            return self._get_default_monitor_decision(risk_percentage)

        except Exception as e:
            self.logger.error(f"❌ Error getting decision for risk score: {e}")
            return self._get_default_monitor_decision(0)

    def _get_default_monitor_decision(self, risk_percentage: int) -> Dict:
        """Decisión por defecto de monitoreo"""
        return {
            'action': 'MONITOR',
            'params': {'duration': 300, 'log_level': 'info'},
            'priority': 'LOW',
            'dry_run': True,
            'description': 'Default monitoring rule - no specific rule found',
            'rule_range': [0, 100],
            'risk_percentage': risk_percentage,
            'rule_applied': {
                'risk_range': [0, 100],
                'action': 'MONITOR',
                'description': 'Default fallback rule',
                'params': {'duration': 300},
                'priority': 'LOW',
                'dry_run': True,
                'enabled': True
            }
        }

    def get_action_info(self, action: str) -> Optional[Dict]:
        """Obtener información de acción desde manual_actions"""
        return self.manual_actions.get(action)

    def get_default_firewall_agent(self) -> Dict:
        """Obtener primer agente activo - RELEASE-1.0.0 GARANTIZADO"""
        if not self.firewall_agents:
            raise FirewallSchedulerRulesError("❌ CRITICAL: No firewall agents available")

        # Buscar primer agente activo
        for agent_id, agent_dict in self.firewall_agents.items():
            if agent_dict['status'] == 'active':
                self.logger.debug(f"🎯 Selected default agent: {agent_id}")
                return agent_dict

        # Si ninguno activo, ERROR TOTAL
        available_statuses = {aid: ainfo['status'] for aid, ainfo in self.firewall_agents.items()}
        raise FirewallSchedulerRulesError(
            f"❌ CRITICAL: No active agents found\n"
            f"📋 Agent statuses: {available_statuses}\n"
            f"🔧 REQUIRED: At least one agent must have status='active'"
        )

    def get_firewall_agent_by_node_id(self, node_id: str) -> Dict:
        """Obtener agente por node_id - RELEASE-1.0.0 GARANTIZADO"""
        if node_id not in self.firewall_agents:
            available_agents = list(self.firewall_agents.keys())
            raise FirewallSchedulerRulesError(
                f"❌ CRITICAL: Agent {node_id} not found\n"
                f"📋 Available agents: {available_agents}\n"
                f"🔧 REQUIRED: node_id must exist in agents_fleet"
            )

        agent_dict = self.firewall_agents[node_id]

        if agent_dict['status'] != 'active':
            raise FirewallSchedulerRulesError(
                f"❌ CRITICAL: Agent {node_id} is not active (status: {agent_dict['status']})\n"
                f"🔧 REQUIRED: Agent status must be 'active'"
            )

        return agent_dict

    def reload_if_changed(self) -> bool:
        """Recargar reglas si el archivo cambió"""
        try:
            if not Path(self.rules_file).exists():
                self.logger.warning(f"⚠️ Rules file does not exist: {self.rules_file}")
                return False

            file_stat = os.stat(self.rules_file)
            current_modified_time = file_stat.st_mtime
            current_file_size = file_stat.st_size

            if (current_modified_time != self.last_modified_time or
                    current_file_size != self.file_size):

                self.logger.info(f"🔄 Changes detected in {self.rules_file}, reloading...")
                self.load_rules(force_reload=True)
                return True
            else:
                return False

        except Exception as e:
            self.logger.error(f"❌ Error checking rules changes: {e}")
            return False


class SchedulerLogger:
    """Logger específico para scheduler - Basado en dashboard logger"""

    def __init__(self, node_id: str, log_config: dict):
        self.logger = logging.getLogger(f"scheduler_firewall_etcd_{node_id}")
        self.node_id = node_id

        # Configurar logging según JSON
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        log_format = log_config.get('format',
                                    '%(asctime)s - %(name)s - %(levelname)s - [scheduler_etcd:{node_id}] [pid:{pid}] - %(message)s'
                                    )

        # Reemplazar placeholders
        log_format = log_format.replace('{node_id}', node_id).replace('{pid}', str(os.getpid()))

        # Crear formatter
        formatter = logging.Formatter(log_format)

        # Limpiar handlers existentes
        self.logger.handlers.clear()
        self.logger.setLevel(log_level)

        # Handler de consola
        console_config = log_config.get('handlers', {}).get('console', {})
        if console_config.get('enabled', True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            console_handler.setLevel(getattr(logging, console_config.get('level', 'INFO').upper()))
            self.logger.addHandler(console_handler)
            print(f"✅ Scheduler ETCD console logging enabled: {console_config.get('level', 'INFO')}")

        # Handler de archivo
        file_config = log_config.get('handlers', {}).get('file', {})
        if file_config.get('enabled', True):
            file_path = file_config.get('path', 'logs/scheduler_firewall_etcd.log')

            try:
                # Crear directorio si no existe
                Path(file_path).parent.mkdir(parents=True, exist_ok=True)

                # Verificar permisos de escritura
                test_file = Path(file_path).parent / '.write_test'
                test_file.touch()
                test_file.unlink()

                # Configurar handler de archivo
                file_handler = logging.FileHandler(file_path, encoding='utf-8')
                file_handler.setFormatter(formatter)
                file_handler.setLevel(getattr(logging, file_config.get('level', 'INFO').upper()))
                self.logger.addHandler(file_handler)

                print(f"✅ Scheduler ETCD file logging enabled: {file_path} ({file_config.get('level', 'INFO')})")

                # Log inicial
                self.logger.info(f"🚀 Scheduler ETCD Logger started - Node: {node_id} - PID: {os.getpid()}")

            except Exception as e:
                print(f"⚠️ Error configuring scheduler ETCD file logging: {e}")

        # Añadir context al logging
        old_factory = logging.getLogRecordFactory()

        def record_factory(*args, **kwargs):
            record = old_factory(*args, **kwargs)
            record.node_id = self.node_id
            record.pid = os.getpid()
            return record

        logging.setLogRecordFactory(record_factory)

        self.info("✅ Scheduler ETCD Logger configured successfully")

    def info(self, msg, *args, **kwargs):
        self.logger.info(f"[scheduler_etcd:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.logger.warning(f"[scheduler_etcd:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.logger.error(f"[scheduler_etcd:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self.logger.debug(f"[scheduler_etcd:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)


class SchedulerConfig:
    """Configuración del scheduler - JSON-controlled"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = None
        self.load_and_validate_config()

    def load_and_validate_config(self):
        """Cargar y validar configuración del scheduler"""
        if not Path(self.config_file).exists():
            raise SchedulerConfigurationError(f"❌ Config file {self.config_file} not found")

        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
        except json.JSONDecodeError as e:
            raise SchedulerConfigurationError(f"❌ JSON parse error in {self.config_file}: {e}")
        except Exception as e:
            raise SchedulerConfigurationError(f"❌ Error reading {self.config_file}: {e}")

        # 🔥 NUEVO: Validar sección ETCD crypto OBLIGATORIA
        self._validate_etcd_crypto_section()

        # Validar campos requeridos
        self._validate_required_fields()

        # Extraer valores validados
        self._extract_config_values()

        print(f"✅ Scheduler ETCD configuration loaded: {self.config_file}")

    def _validate_etcd_crypto_section(self):
        """Validar sección ETCD crypto OBLIGATORIA"""
        if 'etcd_crypto' not in self.config:
            raise SchedulerConfigurationError(
                "❌ CRITICAL: 'etcd_crypto' section REQUIRED in scheduler config\n"
                "🔧 Add etcd_crypto section with: etcd_host, etcd_port, cluster_name, node_id"
            )

        etcd_crypto = self.config['etcd_crypto']
        required_etcd_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']
        missing_etcd_fields = [field for field in required_etcd_fields if field not in etcd_crypto]

        if missing_etcd_fields:
            raise SchedulerConfigurationError(
                f"❌ CRITICAL: Missing required etcd_crypto fields: {missing_etcd_fields}\n"
                f"🔧 Required fields: {required_etcd_fields}"
            )

        # Validar crypto habilitado
        crypto_config = self.config.get('crypto', {})
        if not crypto_config.get('enabled', False):
            raise SchedulerConfigurationError(
                "❌ CRITICAL: crypto.enabled MUST be true for ETCD scheduler\n"
                "🔧 Set crypto.enabled=true and crypto.use_etcd_pipeline_key=true"
            )

        if not crypto_config.get('use_etcd_pipeline_key', False):
            raise SchedulerConfigurationError(
                "❌ CRITICAL: crypto.use_etcd_pipeline_key MUST be true\n"
                "🔧 Set crypto.use_etcd_pipeline_key=true"
            )

        print("✅ ETCD crypto configuration validated")

    def _validate_required_fields(self):
        """Validar campos requeridos en configuración del scheduler"""
        required_paths = [
            'node_id',
            'component.name',
            'component.version',
            'network.ml_events_input.port',
            'network.ml_events_input.address',
            'network.firewall_commands_output.port',
            'network.firewall_commands_output.address',
            'network.firewall_responses_input.port',
            'network.firewall_responses_input.address',
            'zmq.context_io_threads',
            'processing.threads.ml_events_consumers',
            'processing.internal_queues.ml_events_queue_size',
            'monitoring.stats_interval_seconds',
            'logging.level'
        ]

        for path in required_paths:
            if not self._get_nested_value(path):
                raise SchedulerConfigurationError(f"❌ Required field missing: {path}")

    def _get_nested_value(self, path: str):
        """Obtener valor anidado usando notación de punto"""
        keys = path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None

        return value

    def _extract_config_values(self):
        """Extraer todos los valores de configuración del scheduler"""
        # Node ID y component info
        self.node_id = self.config['node_id']
        component = self.config['component']
        self.component_name = component['name']
        self.version = component['version']
        self.mode = component.get('mode', 'distributed_scheduler')
        self.role = component.get('role', 'firewall_decision_engine')

        # 🔥 NUEVO: ETCD crypto configuration
        etcd_crypto = self.config['etcd_crypto']
        self.etcd_host = etcd_crypto['etcd_host']
        self.etcd_port = etcd_crypto['etcd_port']
        self.etcd_cluster_name = etcd_crypto['cluster_name']
        self.etcd_node_id = etcd_crypto['node_id']

        # Network configuration
        network = self.config['network']

        # ML Events Input (desde ml_detector)
        ml_events = network['ml_events_input']
        self.ml_detector_address = ml_events['address']
        self.ml_detector_port = ml_events['port']
        self.ml_detector_mode = ml_events['mode']
        self.ml_detector_socket_type = ml_events['socket_type']
        self.ml_detector_hwm = ml_events.get('high_water_mark', 500)

        # Firewall Commands Output (hacia firewall_agent)
        fw_commands = network['firewall_commands_output']
        self.firewall_commands_address = fw_commands['address']
        self.firewall_commands_port = fw_commands['port']
        self.firewall_commands_mode = fw_commands['mode']
        self.firewall_commands_socket_type = fw_commands['socket_type']
        self.firewall_commands_hwm = fw_commands.get('high_water_mark', 200)

        # Firewall Responses Input (desde firewall_agent)
        fw_responses = network['firewall_responses_input']
        self.firewall_responses_address = fw_responses['address']
        self.firewall_responses_port = fw_responses['port']
        self.firewall_responses_mode = fw_responses['mode']
        self.firewall_responses_socket_type = fw_responses['socket_type']
        self.firewall_responses_hwm = fw_responses.get('high_water_mark', 200)

        # ZMQ Configuration - Conservadora basada en ml_detector
        zmq_config = self.config['zmq']
        self.zmq_io_threads = zmq_config['context_io_threads']
        self.zmq_max_sockets = zmq_config.get('max_sockets', 32)
        self.zmq_tcp_keepalive = zmq_config.get('tcp_keepalive', True)
        self.zmq_tcp_keepalive_idle = zmq_config.get('tcp_keepalive_idle', 300)
        self.zmq_immediate = zmq_config.get('immediate', False)  # False para mejor throughput
        self.zmq_linger_ms = zmq_config.get('linger_ms', 0)
        self.zmq_recv_timeout_ms = zmq_config.get('recv_timeout_ms', 500)
        self.zmq_send_timeout_ms = zmq_config.get('send_timeout_ms', 250)

        # Processing Configuration - Conservadora
        processing = self.config['processing']
        threads = processing['threads']
        self.ml_events_consumers = threads['ml_events_consumers']
        self.firewall_command_producers = threads.get('firewall_command_producers', 1)
        self.firewall_response_consumers = threads.get('firewall_response_consumers', 1)

        queues = processing['internal_queues']
        self.ml_events_queue_size = queues['ml_events_queue_size']
        self.firewall_commands_queue_size = queues.get('firewall_commands_queue_size', 100)
        self.firewall_responses_queue_size = queues.get('firewall_responses_queue_size', 100)

        # Monitoring
        monitoring = self.config['monitoring']
        self.stats_interval = monitoring['stats_interval_seconds']
        self.detailed_metrics = monitoring.get('detailed_metrics', True)

        # Logging configuration
        self.logging_config = self.config['logging']

        # Security
        self.security_config = self.config.get('security', {})

        # Distributed configuration
        self.distributed_config = self.config.get('distributed', {})

        # Decision engine configuration
        self.decision_config = self.config.get('decision_engine', {})

        # 🔥 NUEVO: ETCD crypto configuration
        self.etcd_crypto_config = self.config.get('crypto', {})


class FirewallSchedulerETCD:
    """Scheduler de Firewall - Decision Engine Principal CON ETCD CRYPTO OBLIGATORIO"""

    def __init__(self, config: SchedulerConfig, firewall_rules_file: str):
        self.config = config
        # 🔥 NUEVO: ETCD crypto en lugar de crypto wrapper local
        self.etcd_crypto_ready = False
        self.pipeline_key = None
        self.logger = SchedulerLogger(config.node_id, config.logging_config)

        # Verificar ETCD crypto client disponible
        if not ETCD_CRYPTO_CLIENT_AVAILABLE:
            self.logger.error("❌ CRITICAL: ETCD Crypto Client not available")
            raise ETCDCryptoError("ETCD Crypto Client required for scheduler operation")

        # Motor de reglas de firewall
        try:
            self.rules_engine = FirewallSchedulerRulesEngine(firewall_rules_file, self.logger)
            self.logger.info(f"✅ Firewall rules engine initialized: {firewall_rules_file}")
        except FirewallSchedulerRulesError as e:
            self.logger.error(f"❌ Error loading firewall rules: {e}")
            raise

        # Verificar protobuf disponible
        if not PROTOBUF_AVAILABLE:
            self.logger.error("❌ CRITICAL: Protobuf V3.1 modules not available")
            raise RuntimeError("Protobuf V3.1 modules are required for scheduler")

        # Estadísticas del scheduler
        self.stats = SchedulerStats(uptime_start=time.time())

        # Crear contexto ZMQ
        self.context = zmq.Context(io_threads=config.zmq_io_threads)

        # Sockets ZMQ (sin crypto wrapper - ETCD manejará crypto transparentemente)
        self.ml_events_socket = None
        self.firewall_commands_socket = None
        self.firewall_responses_socket = None

        # Colas de procesamiento
        self.ml_events_queue = queue.Queue(maxsize=config.ml_events_queue_size)
        self.firewall_commands_queue = queue.Queue(maxsize=config.firewall_commands_queue_size)
        self.firewall_responses_queue = queue.Queue(maxsize=config.firewall_responses_queue_size)

        # Estado del scheduler
        self.running = False
        self.threads = []

        # Decisiones recientes para debugging/logging
        self.recent_decisions = deque(maxlen=100)

        self.logger.info(f"🚀 Firewall Scheduler ETCD initialized: {self.config.node_id}")
        self.logger.info(f"🎯 Mode: {self.config.mode} | Role: {self.config.role}")
        self.logger.info(f"🔐 ETCD Crypto: OBLIGATORIO - Pipeline position 4")

    async def initialize_etcd_crypto(self, scheduler_config_path: str, firewall_rules_path: str) -> bool:
        """Inicializar ETCD crypto OBLIGATORIO"""
        try:
            self.logger.info("🔐 Initializing ETCD crypto for Scheduler Firewall...")

            # Detectar testing mode automáticamente
            testing_mode = os.environ.get("UPGRADED_HAPPINESS_DEV_MODE") == "true"
            if testing_mode:
                self.logger.info("🧪 Dev mode detected - enabling testing mode for ETCD")

            # Setup ETCD crypto usando el cliente específico
            success = await setup_scheduler_firewall_crypto(
                scheduler_config_path, firewall_rules_path, testing_mode
            )

            if not success:
                self.logger.error("❌ ETCD crypto initialization failed")
                return False

            # Obtener pipeline key
            self.pipeline_key = get_scheduler_firewall_pipeline_key()
            if not self.pipeline_key:
                self.logger.error("❌ Failed to get pipeline key from ETCD")
                return False

            self.etcd_crypto_ready = True
            self.logger.info("✅ ETCD crypto initialized successfully")
            self.logger.info(f"🔑 Pipeline key obtained: {self.pipeline_key[:16]}...")

            # Log status de ETCD crypto
            etcd_status = get_scheduler_firewall_crypto_status()
            self.logger.info(f"📊 ETCD Status: ready={etcd_status.get('ready')}, "
                             f"crypto_role={etcd_status.get('crypto_role')}, "
                             f"pipeline_position={etcd_status.get('pipeline_position')}")

            return True

        except Exception as e:
            self.logger.error(f"❌ ETCD crypto initialization error: {e}")
            return False

    def _setup_zmq_sockets(self):
        """Setup ZMQ sockets según configuración JSON - SIN crypto wrapper local"""
        self.logger.info("🔧 Setting up ZMQ sockets for scheduler ETCD...")

        try:
            # ML Events Input Socket (SUB del ml_detector)
            self.logger.info(f"📡 Setting up ML Events input socket...")
            socket_type = getattr(zmq, self.config.ml_detector_socket_type)
            self.ml_events_socket = self.context.socket(socket_type)

            # Configuración conservadora para SUB
            self.ml_events_socket.setsockopt(zmq.RCVHWM, self.config.ml_detector_hwm)
            self.ml_events_socket.setsockopt(zmq.LINGER, self.config.zmq_linger_ms)
            self.ml_events_socket.setsockopt(zmq.RCVTIMEO, self.config.zmq_recv_timeout_ms)

            # Si es SUB, suscribirse a todos los eventos
            if self.config.ml_detector_socket_type == 'SUB':
                self.ml_events_socket.setsockopt(zmq.SUBSCRIBE, b"")  # Todos los eventos

            if self.config.zmq_tcp_keepalive:
                self.ml_events_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                self.ml_events_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, self.config.zmq_tcp_keepalive_idle)

            ml_endpoint = f"tcp://{self.config.ml_detector_address}:{self.config.ml_detector_port}"

            if self.config.ml_detector_mode == 'bind':
                self.ml_events_socket.bind(ml_endpoint)
                self.logger.info(f"🟢 ML Events socket BIND on {ml_endpoint}")
            elif self.config.ml_detector_mode == 'connect':
                self.ml_events_socket.connect(ml_endpoint)
                self.logger.info(f"🟢 ML Events socket CONNECT to {ml_endpoint}")

            # Firewall Commands Output Socket (PUSH al firewall_agent)
            self.logger.info(f"🔥 Setting up Firewall Commands output socket...")
            socket_type = getattr(zmq, self.config.firewall_commands_socket_type)
            self.firewall_commands_socket = self.context.socket(socket_type)

            self.firewall_commands_socket.setsockopt(zmq.SNDHWM, self.config.firewall_commands_hwm)
            self.firewall_commands_socket.setsockopt(zmq.LINGER, self.config.zmq_linger_ms)
            self.firewall_commands_socket.setsockopt(zmq.SNDTIMEO, self.config.zmq_send_timeout_ms)

            if self.config.zmq_tcp_keepalive:
                self.firewall_commands_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                self.firewall_commands_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, self.config.zmq_tcp_keepalive_idle)

            fw_commands_endpoint = f"tcp://{self.config.firewall_commands_address}:{self.config.firewall_commands_port}"

            if self.config.firewall_commands_mode == 'bind':
                self.firewall_commands_socket.bind(fw_commands_endpoint)
                self.logger.info(f"🟢 Firewall Commands socket BIND on {fw_commands_endpoint}")
            elif self.config.firewall_commands_mode == 'connect':
                self.firewall_commands_socket.connect(fw_commands_endpoint)
                self.logger.info(f"🟢 Firewall Commands socket CONNECT to {fw_commands_endpoint}")

            # Firewall Responses Input Socket (PULL del firewall_agent)
            self.logger.info(f"📥 Setting up Firewall Responses input socket...")
            socket_type = getattr(zmq, self.config.firewall_responses_socket_type)
            self.firewall_responses_socket = self.context.socket(socket_type)

            self.firewall_responses_socket.setsockopt(zmq.RCVHWM, self.config.firewall_responses_hwm)
            self.firewall_responses_socket.setsockopt(zmq.LINGER, self.config.zmq_linger_ms)
            self.firewall_responses_socket.setsockopt(zmq.RCVTIMEO, self.config.zmq_recv_timeout_ms)

            if self.config.zmq_tcp_keepalive:
                self.firewall_responses_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                self.firewall_responses_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, self.config.zmq_tcp_keepalive_idle)

            fw_responses_endpoint = f"tcp://{self.config.firewall_responses_address}:{self.config.firewall_responses_port}"

            if self.config.firewall_responses_mode == 'bind':
                self.firewall_responses_socket.bind(fw_responses_endpoint)
                self.logger.info(f"🟢 Firewall Responses socket BIND on {fw_responses_endpoint}")
            elif self.config.firewall_responses_mode == 'connect':
                self.firewall_responses_socket.connect(fw_responses_endpoint)
                self.logger.info(f"🟢 Firewall Responses socket CONNECT to {fw_responses_endpoint}")

            # 🔥 NOTA: NO hay crypto wrapper local - ETCD maneja crypto transparentemente
            self.logger.info("🔐 ETCD crypto integration - no local crypto wrapper needed")
            self.logger.info("   🔓 ML Events: Auto-decryption by ETCD pipeline key")
            self.logger.info("   🔒 Commands: Auto-encryption by ETCD pipeline key")
            self.logger.info("   🔓 Responses: Auto-decryption by ETCD pipeline key")

            self.logger.info("✅ All ZMQ sockets configured for scheduler ETCD")

        except Exception as e:
            self.logger.error(f"❌ Error setting up ZMQ sockets: {e}")
            raise SchedulerConfigurationError(f"ZMQ socket setup error: {e}")

    async def start(self, scheduler_config_path: str, firewall_rules_path: str):
        """Iniciar el scheduler con ETCD crypto"""
        # 🔥 PASO 1: Inicializar ETCD crypto ANTES que nada
        if not await self.initialize_etcd_crypto(scheduler_config_path, firewall_rules_path):
            self.logger.error("❌ Cannot start scheduler without ETCD crypto")
            raise ETCDCryptoError("ETCD crypto initialization failed")

        # 🔥 PASO 2: Setup sockets DESPUÉS de ETCD crypto
        self._setup_zmq_sockets()

        self.running = True
        self.logger.info(f"🚀 Starting Firewall Scheduler ETCD {self.config.version}...")
        self.logger.info(f"📋 Node ID: {self.config.node_id}")
        self.logger.info(f"🏗️ Component: {self.config.component_name}")
        self.logger.info(f"🔧 Mode: {self.config.mode}")
        self.logger.info(f"🎭 Role: {self.config.role}")
        self.logger.info(f"🔐 ETCD Crypto: ✅ ENABLED - Pipeline position 4")
        self.logger.info(f"🖥️ System: {os.uname().sysname} {os.uname().release}")
        self.logger.info(f"🐍 Python: {sys.version.split()[0]}")
        self.logger.info(f"💾 PID: {os.getpid()}")

        # Log información de reglas
        try:
            rules_count = len(self.rules_engine.rules)
            agents_count = len(self.rules_engine.firewall_agents)
            self.logger.info(f"🔥 Firewall Rules: {rules_count} rules, {agents_count} agents")

            # Log agentes disponibles
            for agent_id, agent_info in self.rules_engine.firewall_agents.items():
                endpoint = agent_info.get('endpoint', 'unknown')
                self.logger.info(f"   🤖 Agent: {agent_id} -> {endpoint}")
        except Exception as e:
            self.logger.warning(f"⚠️ Error showing rules info: {e}")

        # Mostrar configuración de red
        self._log_network_configuration()

        # Iniciar threads de procesamiento
        self._start_processing_threads()

        # Iniciar actualizaciones periódicas
        self._start_periodic_updates()

        self.logger.info("🎯 Firewall Scheduler ETCD started successfully")

        # Mantener el programa ejecutándose
        try:
            while self.running:
                time.sleep(1)
                self._update_system_metrics()
        except KeyboardInterrupt:
            self.logger.info("🛑 Shutdown signal received")
            self.stop()

    def _log_network_configuration(self):
        """Mostrar configuración de red detallada del scheduler"""
        self.logger.info("🌐 Scheduler ETCD Network Configuration:")
        self.logger.info("=" * 60)

        # ML Events Input
        self.logger.info(f"📡 ML Events Input (from ml_detector V3.1.2 + ETCD crypto):")
        self.logger.info(f"   └── Port: {self.config.ml_detector_port}")
        self.logger.info(f"   └── Mode: {self.config.ml_detector_mode.upper()}")
        self.logger.info(f"   └── Type: {self.config.ml_detector_socket_type}")
        self.logger.info(f"   └── HWM: {self.config.ml_detector_hwm}")
        self.logger.info(f"   └── Endpoint: tcp://{self.config.ml_detector_address}:{self.config.ml_detector_port}")
        self.logger.info(f"   └── 🔓 ETCD Auto-decrypt: ENABLED")

        # Firewall Commands Output
        self.logger.info(f"🔥 Firewall Commands Output (to firewall_agent + ETCD crypto):")
        self.logger.info(f"   └── Port: {self.config.firewall_commands_port}")
        self.logger.info(f"   └── Mode: {self.config.firewall_commands_mode.upper()}")
        self.logger.info(f"   └── Type: {self.config.firewall_commands_socket_type}")
        self.logger.info(f"   └── HWM: {self.config.firewall_commands_hwm}")
        self.logger.info(
            f"   └── Endpoint: tcp://{self.config.firewall_commands_address}:{self.config.firewall_commands_port}")
        self.logger.info(f"   └── 🔒 ETCD Auto-encrypt: ENABLED")

        # Firewall Responses Input
        self.logger.info(f"📥 Firewall Responses Input (from firewall_agent + ETCD crypto):")
        self.logger.info(f"   └── Port: {self.config.firewall_responses_port}")
        self.logger.info(f"   └── Mode: {self.config.firewall_responses_mode.upper()}")
        self.logger.info(f"   └── Type: {self.config.firewall_responses_socket_type}")
        self.logger.info(f"   └── HWM: {self.config.firewall_responses_hwm}")
        self.logger.info(
            f"   └── Endpoint: tcp://{self.config.firewall_responses_address}:{self.config.firewall_responses_port}")
        self.logger.info(f"   └── 🔓 ETCD Auto-decrypt: ENABLED")

        # ETCD Configuration
        self.logger.info(f"🔐 ETCD Crypto Configuration:")
        self.logger.info(f"   └── ETCD Host: {self.config.etcd_host}:{self.config.etcd_port}")
        self.logger.info(f"   └── Cluster: {self.config.etcd_cluster_name}")
        self.logger.info(f"   └── Node ID: {self.config.etcd_node_id}")
        self.logger.info(f"   └── Pipeline Key: {'✅ READY' if self.etcd_crypto_ready else '❌ NOT READY'}")

        # ZMQ Context
        self.logger.info(f"⚙️ ZMQ Context (Conservative config + ETCD crypto):")
        self.logger.info(f"   └── IO Threads: {self.config.zmq_io_threads}")
        self.logger.info(f"   └── Max Sockets: {self.config.zmq_max_sockets}")
        self.logger.info(f"   └── TCP Keepalive: {self.config.zmq_tcp_keepalive}")
        self.logger.info(f"   └── Immediate: {self.config.zmq_immediate}")

        self.logger.info("=" * 60)

    def _start_processing_threads(self):
        """Iniciar threads de procesamiento según configuración JSON"""
        self.logger.info("🧵 Starting processing threads...")

        # ML Events Consumers
        for i in range(self.config.ml_events_consumers):
            thread = threading.Thread(target=self._ml_events_receiver, args=(i,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
            self.logger.info(f"📡 ML Events Receiver {i} started")

        # Decision Engine Processors
        for i in range(self.config.firewall_command_producers):
            thread = threading.Thread(target=self._decision_processor, args=(i,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
            self.logger.info(f"🎯 Decision Processor {i} started")

        # Firewall Command Senders
        for i in range(self.config.firewall_command_producers):
            thread = threading.Thread(target=self._firewall_command_sender, args=(i,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
            self.logger.info(f"🔥 Firewall Command Sender {i} started")

        # Firewall Response Consumers
        for i in range(self.config.firewall_response_consumers):
            thread = threading.Thread(target=self._firewall_responses_receiver, args=(i,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
            self.logger.info(f"📥 Firewall Responses Receiver {i} started")

        total_threads = (self.config.ml_events_consumers +
                         self.config.firewall_command_producers * 2 +  # *2 porque ahora hay decision + sender
                         self.config.firewall_response_consumers)

        self.logger.info(f"✅ Total threads started: {total_threads}")

    def _ml_events_receiver(self, worker_id: int):
        """Recibir eventos del ML Detector V3.1.2 tricapa - CON ETCD AUTO-DECRYPT"""
        self.logger.info(f"📡 ML Events Receiver {worker_id} started for V3.1.2 tricapa + ETCD")

        while self.running:
            try:
                if self.ml_events_socket:
                    try:
                        # 🔐 ETCD maneja auto-decrypt transparentemente
                        message_bytes = self.ml_events_socket.recv(zmq.NOBLOCK)
                        self.stats.events_received += 1
                        self.stats.etcd_crypto_operations += 1

                        self.logger.debug(
                            f"📨 Worker {worker_id} - Received {len(message_bytes)} bytes from ML Detector V3.1.2 (ETCD decrypted)")

                        # Procesar mensaje
                        event_data = self._parse_ml_event(message_bytes, worker_id)

                        if event_data:
                            # Añadir a cola para procesamiento de decisión
                            if not self.ml_events_queue.full():
                                self.ml_events_queue.put(event_data, timeout=1.0)
                                self.logger.debug(
                                    f"📥 Worker {worker_id} - Event queued: {event_data.get('source_ip')} -> {event_data.get('target_ip')}")
                            else:
                                self.logger.warning(f"⚠️ Worker {worker_id} - ML events queue full, dropping event")
                                self.stats.errors += 1

                    except zmq.Again:
                        # No hay mensajes disponibles
                        pass
                    except Exception as e:
                        self.logger.error(f"❌ Worker {worker_id} - Error receiving ML event: {e}")
                        self.stats.errors += 1
                        self.stats.etcd_crypto_errors += 1

                time.sleep(0.001)  # Pequeña pausa para no saturar CPU

            except Exception as e:
                self.logger.error(f"❌ Worker {worker_id} - ML events receiver error: {e}")
                self.stats.errors += 1
                time.sleep(1)

    def _parse_ml_event(self, message_bytes: bytes, worker_id: int) -> Optional[Dict]:
        """Parser para eventos del ML Detector V3.1.2 - Compatible con protobuf y JSON - POST ETCD DECRYPT"""
        try:
            # 🔍 DEBUG: Log lo que llega (YA descifrado por ETCD)
            self.logger.debug(f"🔍 DEBUG Worker {worker_id} - Received {len(message_bytes)} bytes (ETCD decrypted)")

            # Intentar primero protobuf V3.1.2
            if PROTOBUF_AVAILABLE and NetworkEventProto:
                try:
                    event = NetworkEventProto.NetworkEvent()
                    event.ParseFromString(message_bytes)

                    # Convertir protobuf a dict
                    event_data = self._convert_v3_protobuf_to_dict(event, worker_id)

                    self.logger.debug(f"✅ Worker {worker_id} - Protobuf V3.1.2 parsed successfully")
                    return event_data

                except Exception as pb_error:
                    self.logger.warning(f"🔄 Worker {worker_id} - Protobuf parse failed: {pb_error}")

            # Fallback a JSON
            try:
                message_text = message_bytes.decode('utf-8')
                event_data = json.loads(message_text)
                self.logger.debug(f"✅ Worker {worker_id} - JSON parsed successfully")
                return event_data

            except Exception as json_error:
                self.logger.warning(f"🔄 Worker {worker_id} - JSON parse failed: {json_error}")

            # Ultimo recurso: crear evento básico
            self.logger.warning(f"⚠️ Worker {worker_id} - Using fallback event creation")
            return self._create_fallback_event(message_bytes, worker_id)

        except Exception as e:
            self.logger.error(f"❌ Worker {worker_id} - Error parsing ML event: {e}")
            return None

    def _convert_v3_protobuf_to_dict(self, event, worker_id: int) -> Dict:
        """Convertir protobuf V3.1.2 del ML Detector a diccionario - Compatible con tricapa"""
        current_time = int(time.time() * 1000)

        return {
            # Identificación básica
            'id': getattr(event, 'event_id', '') or str(current_time) + f"_{worker_id}",
            'event_id': getattr(event, 'event_id', ''),
            'timestamp': getattr(event, 'timestamp', current_time),

            # Información de red básica
            'source_ip': getattr(event, 'source_ip', '127.0.0.1'),
            'target_ip': getattr(event, 'target_ip', '127.0.0.1'),
            'src_port': getattr(event, 'src_port', 0),
            'dest_port': getattr(event, 'dest_port', 0),
            'protocol': getattr(event, 'protocol', 'TCP'),
            'packet_size': getattr(event, 'packet_size', 0),

            # ML Detector V3.1.2 scoring tricapa
            'risk_score': float(getattr(event, 'risk_score', 0.5)),
            'anomaly_score': float(getattr(event, 'anomaly_score', 0.0)),

            # Información del nodo
            'node_id': getattr(event, 'node_id', 'unknown'),
            'agent_id': getattr(event, 'agent_id', ''),
            'agent_version': getattr(event, 'agent_version', 'V3.1.2'),

            # Información geográfica (campos planos V3)
            'source_latitude': getattr(event, 'source_latitude', None),
            'source_longitude': getattr(event, 'source_longitude', None),
            'target_latitude': getattr(event, 'target_latitude', None),
            'target_longitude': getattr(event, 'target_longitude', None),
            'source_city': getattr(event, 'source_city', ''),
            'source_country': getattr(event, 'source_country', ''),
            'target_city': getattr(event, 'target_city', ''),
            'target_country': getattr(event, 'target_country', ''),
            'geographic_distance_km': getattr(event, 'geographic_distance_km', 0.0),
            'same_country': getattr(event, 'same_country', False),

            # Enriquecimiento
            'source_ip_enriched': bool(getattr(event, 'source_ip_enriched', False)),
            'target_ip_enriched': bool(getattr(event, 'target_ip_enriched', False)),

            # Información de amenazas
            'target_is_tor_exit': bool(getattr(event, 'target_is_tor_exit', False)),
            'target_is_known_malicious': bool(getattr(event, 'target_is_known_malicious', False)),

            # Clasificación
            'event_type': getattr(event, 'event_type', 'network_event'),
            'attack_type': getattr(event, 'event_type', 'unknown'),

            # Información del sistema
            'ml_detector_version': 'V3.1.2',
            'protobuf_version': '3.1.2',
            'parsing_method': 'protobuf_v3_scheduler_etcd',
            'worker_id': worker_id,
            'scheduler_processing_timestamp': datetime.now().isoformat(),
            'etcd_crypto_processed': True
        }

    def _create_fallback_event(self, message_bytes: bytes, worker_id: int) -> Dict:
        """Crear evento básico cuando falla el parsing"""
        current_time = int(time.time() * 1000)

        return {
            'id': f"fallback_{current_time}_{worker_id}",
            'event_id': f"fallback_{current_time}_{worker_id}",
            'timestamp': current_time,
            'source_ip': '127.0.0.1',
            'target_ip': '127.0.0.1',
            'src_port': 0,
            'dest_port': 80,
            'protocol': 'TCP',
            'packet_size': len(message_bytes),
            'risk_score': 0.1,  # Bajo riesgo por defecto
            'anomaly_score': 0.0,
            'node_id': 'unknown',
            'agent_id': 'fallback',
            'agent_version': 'unknown',
            'event_type': 'parsing_fallback',
            'attack_type': 'unknown',
            'ml_detector_version': 'unknown',
            'parsing_method': 'fallback_creation_etcd',
            'worker_id': worker_id,
            'raw_message_length': len(message_bytes),
            'scheduler_processing_timestamp': datetime.now().isoformat(),
            'etcd_crypto_processed': True
        }

    def _decision_processor(self, worker_id: int):
        """Procesador de decisiones - Core del scheduler"""
        self.logger.info(f"🎯 Decision Processor {worker_id} started - JSON-controlled rules")

        while self.running:
            try:
                try:
                    # Obtener evento de la cola
                    event_data = self.ml_events_queue.get(timeout=1)
                    self.stats.events_processed += 1
                except queue.Empty:
                    continue

                # Procesar decisión usando reglas JSON
                decision = self._make_firewall_decision(event_data, worker_id)

                if decision:
                    # Crear comando de firewall
                    command_created = self._create_firewall_command(decision, worker_id)

                    if command_created:
                        self.stats.decisions_made += 1
                        self.stats.last_decision_time = datetime.now()

                        # Actualizar contadores por tipo de decisión
                        action = decision.recommended_action
                        if action == 'MONITOR':
                            self.stats.monitor_decisions += 1
                        elif action == 'RATE_LIMIT' or action == 'RATE_LIMIT_IP':
                            self.stats.rate_limit_decisions += 1
                        elif action == 'BLOCK_IP':
                            self.stats.block_decisions += 1

                        # Guardar decisión reciente para debugging
                        self.recent_decisions.append(asdict(decision))

                        self.logger.info(
                            f"🎯 Worker {worker_id} - Decision: {decision.risk_percentage}% -> {decision.recommended_action}")
                        self.logger.debug(f"📋 Decision reason: {decision.decision_reason}")

            except Exception as e:
                self.logger.error(f"❌ Worker {worker_id} - Decision processor error: {e}")
                self.stats.errors += 1
                time.sleep(1)

    def _make_firewall_decision(self, event_data: Dict, worker_id: int) -> Optional[FirewallDecision]:
        """Tomar decisión de firewall basada en reglas JSON - CORE LOGIC"""
        try:
            if not isinstance(event_data, dict):
                self.logger.error(
                    f"❌ Worker {worker_id} - event_data is not dict! Type: {type(event_data)}")
                return None

            # Extraer información crítica del evento
            source_ip = event_data.get('source_ip', '127.0.0.1')
            target_ip = event_data.get('target_ip', '127.0.0.1')
            risk_score = float(event_data.get('risk_score', 0.5))
            event_id = event_data.get('id', event_data.get('event_id', f'event_{int(time.time())}'))

            self.logger.debug(
                f"🎯 Worker {worker_id} - Making decision for event: {source_ip} -> {target_ip}, risk: {risk_score:.3f}")

            # Consultar motor de reglas JSON
            rule_decision = self.rules_engine.get_decision_for_risk_score(risk_score)

            if not rule_decision:
                self.logger.warning(f"⚠️ Worker {worker_id} - No decision from rules engine")
                return None

            # Obtener agente firewall responsable
            firewall_agent = self.rules_engine.get_default_firewall_agent()
            if not firewall_agent:
                self.logger.error(f"❌ Worker {worker_id} - No firewall agent available")
                return None

            firewall_node_id = firewall_agent.get('node_id', 'simple_firewall_agent_001')

            # Crear decisión estructurada
            decision = FirewallDecision(
                event_id=event_id,
                source_ip=source_ip,
                target_ip=target_ip,
                risk_score=risk_score,
                risk_percentage=rule_decision['risk_percentage'],
                recommended_action=rule_decision['action'],
                action_params=rule_decision['params'],
                decision_reason=rule_decision['description'],
                decision_timestamp=datetime.now(),
                firewall_node_id=firewall_node_id,
                command_id=f"cmd_{int(time.time())}_{worker_id}",
                dry_run=rule_decision['dry_run'],
                priority=rule_decision['priority'],
                rule_applied=rule_decision['rule_applied']
            )

            self.logger.debug(
                f"✅ Worker {worker_id} - Decision made: {risk_score:.3f} ({rule_decision['risk_percentage']}%) -> {rule_decision['action']}")

            return decision

        except Exception as e:
            self.logger.error(f"❌ Worker {worker_id} - Error making firewall decision: {e}")
            return None

    def _create_firewall_command(self, decision: FirewallDecision, worker_id: int) -> bool:
        """Crear y enviar comando de firewall basado en decisión - V3.1 EXCLUSIVO"""
        try:
            if not PROTOBUF_AVAILABLE or not FirewallCommandsProto:
                self.logger.error(f"❌ Worker {worker_id} - Firewall protobuf V3.1 not available")
                return False

            # Crear comando protobuf V3.1
            pb_command = FirewallCommandsProto.FirewallCommand()

            # ✅ CAMPOS BÁSICOS
            pb_command.command_id = decision.command_id

            # Mapear acción a enum protobuf
            action_mapping = {
                'BLOCK_IP': FirewallCommandsProto.CommandAction.BLOCK_IP,
                'RATE_LIMIT': FirewallCommandsProto.CommandAction.RATE_LIMIT_IP,
                'RATE_LIMIT_IP': FirewallCommandsProto.CommandAction.RATE_LIMIT_IP,
                'MONITOR': FirewallCommandsProto.CommandAction.ALLOW_IP_TEMP,
                'ALLOW_IP_TEMP': FirewallCommandsProto.CommandAction.ALLOW_IP_TEMP,
                'LIST_RULES': FirewallCommandsProto.CommandAction.LIST_RULES
            }

            pb_command.action = action_mapping.get(decision.recommended_action,
                                                   FirewallCommandsProto.CommandAction.LIST_RULES)

            # Configurar IP objetivo
            if decision.recommended_action in ['BLOCK_IP', 'RATE_LIMIT', 'RATE_LIMIT_IP', 'MONITOR', 'ALLOW_IP_TEMP']:
                pb_command.target_ip = decision.target_ip
            else:
                pb_command.target_ip = 'all'

            pb_command.target_port = 0  # No específico

            # Duración desde parámetros de la regla
            duration = decision.action_params.get('duration', 300)
            pb_command.duration_seconds = int(duration)

            # Razón de la decisión
            pb_command.reason = f"Scheduler ETCD decision: {decision.decision_reason} (risk: {decision.risk_percentage}%)"

            # Prioridad
            priority_mapping = {
                'LOW': FirewallCommandsProto.CommandPriority.LOW,
                'MEDIUM': FirewallCommandsProto.CommandPriority.MEDIUM,
                'HIGH': FirewallCommandsProto.CommandPriority.HIGH
            }
            pb_command.priority = priority_mapping.get(decision.priority, FirewallCommandsProto.CommandPriority.MEDIUM)

            # Dry run según regla
            pb_command.dry_run = decision.dry_run

            # Rate limit rule si aplica
            if decision.recommended_action in ['RATE_LIMIT', 'RATE_LIMIT_IP']:
                rate_limit = decision.action_params.get('rate_limit', '10/min')
                pb_command.rate_limit_rule = rate_limit

            # ✅ CAMPOS NATIVOS V3.1 (sin verificación - se asume que existen)
            pb_command.node_id = decision.firewall_node_id
            pb_command.timestamp = int(time.time() * 1000)

            # Extra params para metadata adicional
            pb_command.extra_params["scheduler_node_id"] = self.config.node_id
            pb_command.extra_params["source_ip"] = decision.source_ip
            pb_command.extra_params["event_id"] = decision.event_id
            pb_command.extra_params["worker_id"] = str(worker_id)
            pb_command.extra_params["risk_score"] = str(decision.risk_score)
            pb_command.extra_params["risk_percentage"] = str(decision.risk_percentage)
            pb_command.extra_params["protobuf_version"] = "v3.1"
            pb_command.extra_params["etcd_crypto"] = "enabled"
            pb_command.extra_params["pipeline_position"] = "4"

            # Serializar comando
            command_bytes = pb_command.SerializeToString()

            # Enviar comando
            if not self.firewall_commands_queue.full():
                self.firewall_commands_queue.put({
                    'command_bytes': command_bytes,
                    'decision': decision,
                    'worker_id': worker_id
                }, timeout=1.0)

                self.logger.info(
                    f"🔥 Worker {worker_id} - Command created: {decision.recommended_action} for {decision.target_ip} "
                    f"(V3.1 ETCD, {len(command_bytes)}b)")
                return True
            else:
                self.logger.warning(f"⚠️ Worker {worker_id} - Firewall commands queue full")
                return False

        except AttributeError as attr_error:
            # Error específico de campo no encontrado
            if "node_id" in str(attr_error) or "timestamp" in str(attr_error):
                self.logger.error(f"❌ Worker {worker_id} - V3.1 field missing: {attr_error}")
                self.logger.error(f"🚨 CRITICAL: protobuf V3.1 with node_id/timestamp is REQUIRED")
                self.logger.error(f"📁 Expected file: firewall_commands_v31_pb2.py")
                self.logger.error(f"🛑 Scheduler cannot continue without V3.1")
            else:
                self.logger.error(f"❌ Worker {worker_id} - Attribute error: {attr_error}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Worker {worker_id} - Error creating firewall command: {e}")
            return False

    def _firewall_command_sender(self, worker_id: int):
        """Sender de comandos de firewall - Thread separado - CON ETCD AUTO-ENCRYPT"""
        self.logger.info(f"🔥 Firewall Command Sender {worker_id} started with ETCD auto-encrypt")

        while self.running:
            try:
                try:
                    # Obtener comando de la cola
                    command_data = self.firewall_commands_queue.get(timeout=1)
                except queue.Empty:
                    continue

                # 🔐 ETCD maneja auto-encrypt transparentemente
                try:
                    self.firewall_commands_socket.send(command_data['command_bytes'], zmq.NOBLOCK)
                    self.stats.commands_sent += 1
                    self.stats.etcd_crypto_operations += 1

                    decision = command_data['decision']
                    self.logger.info(
                        f"📤 Worker {worker_id} - Command sent (ETCD encrypted): {decision.command_id} -> {decision.recommended_action}")

                except zmq.Again:
                    # Socket no listo, reencolar
                    self.firewall_commands_queue.put(command_data)
                    time.sleep(0.01)
                except Exception as send_error:
                    self.logger.error(f"❌ Worker {worker_id} - Error sending command: {send_error}")
                    self.stats.errors += 1
                    self.stats.etcd_crypto_errors += 1

            except Exception as e:
                self.logger.error(f"❌ Worker {worker_id} - Command sender error: {e}")
                self.stats.errors += 1
                time.sleep(1)

    def _firewall_responses_receiver(self, worker_id: int):
        """Recibir respuestas del firewall agent - CON ETCD AUTO-DECRYPT"""
        self.logger.info(f"📥 Firewall Responses Receiver {worker_id} started with ETCD auto-decrypt")

        while self.running:
            try:
                if self.firewall_responses_socket:
                    try:
                        # 🔐 ETCD maneja auto-decrypt transparentemente
                        response_bytes = self.firewall_responses_socket.recv(zmq.NOBLOCK)
                        self.stats.responses_received += 1
                        self.stats.etcd_crypto_operations += 1

                        # Parsear respuesta (ya descifrada por ETCD)
                        response_data = self._parse_firewall_response(response_bytes, worker_id)

                        if response_data:
                            command_id = response_data.get('command_id', 'unknown')
                            success = response_data.get('success', False)
                            message = response_data.get('message', 'No message')

                            self.logger.info(f"📥 Worker {worker_id} - Response (ETCD decrypted): {command_id} -> Success: {success}")
                            self.logger.debug(f"📋 Response message: {message}")

                    except zmq.Again:
                        pass
                    except Exception as e:
                        self.logger.error(f"❌ Worker {worker_id} - Error receiving response: {e}")
                        self.stats.errors += 1
                        self.stats.etcd_crypto_errors += 1

                time.sleep(0.001)

            except Exception as e:
                self.logger.error(f"❌ Worker {worker_id} - Responses receiver error: {e}")
                self.stats.errors += 1
                time.sleep(1)

    def _parse_firewall_response(self, response_bytes: bytes, worker_id: int) -> Optional[Dict]:
        """Parser para respuestas del firewall agent - POST ETCD DECRYPT"""
        try:
            # Intentar protobuf primero
            if PROTOBUF_AVAILABLE and FirewallCommandsProto:
                try:
                    pb_response = FirewallCommandsProto.FirewallResponse()
                    pb_response.ParseFromString(response_bytes)

                    return {
                        'command_id': pb_response.command_id,
                        'node_id': pb_response.node_id,
                        'success': pb_response.success,
                        'message': pb_response.message,
                        'timestamp': pb_response.timestamp,
                        'parsing_method': 'protobuf_etcd'
                    }
                except Exception:
                    pass

            # Fallback a JSON
            try:
                response_text = response_bytes.decode('utf-8')
                response_data = json.loads(response_text)
                response_data['parsing_method'] = 'json_etcd'
                return response_data
            except Exception:
                pass

            self.logger.warning(f"⚠️ Worker {worker_id} - Could not parse firewall response (ETCD decrypted)")
            return None

        except Exception as e:
            self.logger.error(f"❌ Worker {worker_id} - Error parsing firewall response: {e}")
            return None

    def _start_periodic_updates(self):
        """Iniciar actualizaciones periódicas"""

        def update_stats():
            while self.running:
                try:
                    self._update_statistics()
                    self._check_rules_changes()
                    time.sleep(self.config.stats_interval)
                except Exception as e:
                    self.logger.error(f"❌ Error in periodic updates: {e}")
                    time.sleep(self.config.stats_interval)

        stats_thread = threading.Thread(target=update_stats)
        stats_thread.daemon = True
        stats_thread.start()
        self.threads.append(stats_thread)

        self.logger.info(f"✅ Periodic updates started (interval: {self.config.stats_interval}s)")

    def _update_statistics(self):
        """Actualizar estadísticas del scheduler"""
        try:
            # Estadísticas básicas
            current_time = time.time()
            uptime = current_time - self.stats.uptime_start

            # Log estadísticas cada 5 minutos
            if hasattr(self, '_last_stats_log'):
                if current_time - self._last_stats_log > 300:  # 5 minutos
                    self._log_scheduler_statistics(uptime)
                    self._last_stats_log = current_time
            else:
                self._last_stats_log = current_time

        except Exception as e:
            self.logger.error(f"❌ Error updating statistics: {e}")

    def _log_scheduler_statistics(self, uptime: float):
        """Log estadísticas periódicas del scheduler"""
        try:
            self.logger.info("📊 SCHEDULER ETCD STATISTICS:")
            self.logger.info(f"   ⏱️ Uptime: {uptime:.0f}s ({uptime / 3600:.1f}h)")
            self.logger.info(f"   📨 Events received: {self.stats.events_received}")
            self.logger.info(f"   🔄 Events processed: {self.stats.events_processed}")
            self.logger.info(f"   🎯 Decisions made: {self.stats.decisions_made}")
            self.logger.info(f"   📤 Commands sent: {self.stats.commands_sent}")
            self.logger.info(f"   📥 Responses received: {self.stats.responses_received}")
            self.logger.info(f"   ❌ Errors: {self.stats.errors}")

            # ETCD crypto stats
            self.logger.info("🔐 ETCD CRYPTO STATISTICS:")
            self.logger.info(f"   🔐 Crypto operations: {self.stats.etcd_crypto_operations}")
            self.logger.info(f"   ❌ Crypto errors: {self.stats.etcd_crypto_errors}")

            # Decisiones por tipo
            self.logger.info("🎯 DECISIONS BY TYPE:")
            self.logger.info(f"   👁️ MONITOR: {self.stats.monitor_decisions}")
            self.logger.info(f"   ⏱️ RATE_LIMIT: {self.stats.rate_limit_decisions}")
            self.logger.info(f"   🚫 BLOCK_IP: {self.stats.block_decisions}")

            # Colas
            self.logger.info("📋 QUEUE STATUS:")
            self.logger.info(f"   📨 ML Events: {self.ml_events_queue.qsize()}/{self.config.ml_events_queue_size}")
            self.logger.info(
                f"   🔥 Commands: {self.firewall_commands_queue.qsize()}/{self.config.firewall_commands_queue_size}")
            self.logger.info(
                f"   📥 Responses: {self.firewall_responses_queue.qsize()}/{self.config.firewall_responses_queue_size}")

            # Última actividad
            if self.stats.last_event_time:
                last_event_ago = (datetime.now() - self.stats.last_event_time).total_seconds()
                self.logger.info(f"   📅 Last event: {last_event_ago:.0f}s ago")

            if self.stats.last_decision_time:
                last_decision_ago = (datetime.now() - self.stats.last_decision_time).total_seconds()
                self.logger.info(f"   🎯 Last decision: {last_decision_ago:.0f}s ago")

        except Exception as e:
            self.logger.error(f"❌ Error logging statistics: {e}")

    def _check_rules_changes(self):
        """Verificar cambios en reglas de firewall"""
        try:
            if self.rules_engine.reload_if_changed():
                self.logger.info("🔄 Firewall rules reloaded due to file changes")
        except Exception as e:
            self.logger.error(f"❌ Error checking rules changes: {e}")

    def _update_system_metrics(self):
        """Actualizar métricas del sistema"""
        try:
            # Aquí se podrían añadir métricas de sistema como CPU, memoria, etc.
            pass
        except Exception as e:
            self.logger.debug(f"Error updating system metrics: {e}")

    def stop(self):
        """Detener el scheduler con cleanup completo"""
        self.logger.info("🛑 Stopping Firewall Scheduler ETCD...")
        self.running = False

        # Log estadísticas finales
        try:
            uptime = time.time() - self.stats.uptime_start
            self.logger.info("📊 FINAL SCHEDULER ETCD STATISTICS:")
            self.logger.info(f"   ⏱️ Total uptime: {uptime:.0f}s ({uptime / 3600:.1f}h)")
            self.logger.info(f"   📨 Total events: {self.stats.events_processed}")
            self.logger.info(f"   🎯 Total decisions: {self.stats.decisions_made}")
            self.logger.info(f"   📤 Total commands: {self.stats.commands_sent}")
            self.logger.info(f"   📥 Total responses: {self.stats.responses_received}")
            self.logger.info(f"   🔐 Total ETCD crypto operations: {self.stats.etcd_crypto_operations}")
            self.logger.info(f"   ❌ Total ETCD crypto errors: {self.stats.etcd_crypto_errors}")
        except Exception as e:
            self.logger.error(f"Error logging final stats: {e}")

        # Cerrar sockets ZMQ
        try:
            if self.ml_events_socket:
                self.ml_events_socket.setsockopt(zmq.LINGER, 0)
                self.ml_events_socket.close()
                self.logger.debug("✅ ML events socket closed")

            if self.firewall_commands_socket:
                self.firewall_commands_socket.setsockopt(zmq.LINGER, 0)
                self.firewall_commands_socket.close()
                self.logger.debug("✅ Firewall commands socket closed")

            if self.firewall_responses_socket:
                self.firewall_responses_socket.setsockopt(zmq.LINGER, 0)
                self.firewall_responses_socket.close()
                self.logger.debug("✅ Firewall responses socket closed")

        except Exception as e:
            self.logger.error(f"⚠️ Error closing sockets: {e}")

        # Terminar contexto ZMQ
        try:
            time.sleep(0.1)
            self.context.term()
            self.logger.debug("✅ ZMQ context terminated")
        except Exception as e:
            self.logger.error(f"⚠️ Error terminating ZMQ context: {e}")

        self.logger.info("✅ Firewall Scheduler ETCD stopped successfully")

    def get_status(self) -> Dict:
        """Obtener estado actual del scheduler"""
        try:
            uptime = time.time() - self.stats.uptime_start

            status = {
                'node_id': self.config.node_id,
                'component_name': self.config.component_name,
                'version': self.config.version,
                'mode': self.config.mode,
                'role': self.config.role,
                'running': self.running,
                'uptime_seconds': uptime,
                'pid': os.getpid(),
                'stats': asdict(self.stats),
                'etcd_crypto': {
                    'ready': self.etcd_crypto_ready,
                    'pipeline_key_available': self.pipeline_key is not None,
                    'pipeline_key_preview': self.pipeline_key[:16] + "..." if self.pipeline_key else None,
                    'crypto_operations': self.stats.etcd_crypto_operations,
                    'crypto_errors': self.stats.etcd_crypto_errors,
                    'etcd_status': get_scheduler_firewall_crypto_status() if ETCD_CRYPTO_CLIENT_AVAILABLE else None
                },
                'queue_status': {
                    'ml_events': {
                        'current': self.ml_events_queue.qsize(),
                        'max': self.config.ml_events_queue_size
                    },
                    'firewall_commands': {
                        'current': self.firewall_commands_queue.qsize(),
                        'max': self.config.firewall_commands_queue_size
                    },
                    'firewall_responses': {
                        'current': self.firewall_responses_queue.qsize(),
                        'max': self.config.firewall_responses_queue_size
                    }
                },
                'rules_engine': {
                    'rules_count': len(self.rules_engine.rules),
                    'agents_count': len(self.rules_engine.firewall_agents),
                    'last_loaded': self.rules_engine.last_loaded.isoformat() if self.rules_engine.last_loaded else None,
                    'load_count': self.rules_engine.load_count
                },
                'recent_decisions': list(self.recent_decisions)[-10:],  # Últimas 10 decisiones
                'threads_count': len(self.threads),
                'protobuf_available': PROTOBUF_AVAILABLE,
                'protobuf_version': PROTOBUF_VERSION,
                'etcd_crypto_client_available': ETCD_CRYPTO_CLIENT_AVAILABLE
            }

            return status
        except Exception as e:
            self.logger.error(f"❌ Error getting scheduler status: {e}")
            return {'error': str(e), 'running': self.running}


def signal_handler(sig, frame):
    """Manejar señales del sistema"""
    print("\n🛑 Shutdown signal received")
    sys.exit(0)


async def main_async():
    """Función principal asíncrona del scheduler ETCD"""
    # Configurar manejo de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("🚀 Firewall Scheduler ETCD - JSON-controlled Decision Engine V3.1")
    print("✅ Compatible with ML Detector V3.1.2 tricapa (4 models)")
    print("🔥 V3.1 PROTOBUF EXCLUSIVO - con node_id y timestamp nativos")
    print("🔐 ETCD CRYPTO OBLIGATORIO - No fallbacks, máxima seguridad")
    print("🎯 Pipeline position 4 - Como chip inteligente de rendimiento")
    print("📊 Performance profile storage for real-time optimization")

    # Verificar argumentos
    if len(sys.argv) != 3:
        print("\n❌ Usage:")
        print("python scheduler-firewall-v31-etcd.py <scheduler_config.json> <firewall_rules.json>")
        print("\n📋 File descriptions:")
        print("   • scheduler_config.json: ZMQ, network, processing, ETCD crypto configuration")
        print("   • firewall_rules.json: Decision rules and firewall agents")
        print("\n✅ Both files are required for operation")
        print("\n🔐 ETCD Requirements:")
        print("   • ETCD cluster running on configured host:port")
        print("   • crypto.enabled=true in scheduler config")
        print("   • etcd_crypto section with cluster configuration")
        sys.exit(1)

    config_file = sys.argv[1]
    firewall_rules_file = sys.argv[2]

    # Validar archivos
    if not Path(config_file).exists():
        print(f"\n❌ ERROR: Scheduler config file not found")
        print(f"📁 File searched: {config_file}")
        print(f"📍 Current directory: {os.getcwd()}")
        print("🔧 Please verify the scheduler configuration file path")
        sys.exit(1)

    if not Path(firewall_rules_file).exists():
        print(f"\n❌ ERROR: Firewall rules file not found")
        print(f"📁 File searched: {firewall_rules_file}")
        print(f"📍 Current directory: {os.getcwd()}")
        print("🔧 Please verify the firewall rules file path")
        sys.exit(1)

    print(f"✅ Configuration files found:")
    print(f"   📋 Scheduler config: {config_file}")
    print(f"   🔥 Firewall rules: {firewall_rules_file}")

    # Verificar ETCD crypto client
    if not ETCD_CRYPTO_CLIENT_AVAILABLE:
        print(f"\n💥 FATAL ERROR: ETCD Crypto Client not available")
        print(f"📁 Required: core/etcd_crypto_client_scheduler_firewall_fixed.py")
        print(f"🔧 Ensure ETCD crypto client is properly installed")
        sys.exit(1)

    try:
        # Cargar configuración del scheduler
        print(f"\n📋 Loading scheduler ETCD configuration...")
        config = SchedulerConfig(config_file)

        # Crear directorios necesarios
        directories = ['logs', 'data']
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            print(f"📁 Directory verified: {directory}")

        # Crear scheduler ETCD
        print(f"\n🔥 Creating firewall scheduler with ETCD crypto integration...")
        scheduler = FirewallSchedulerETCD(config, firewall_rules_file)

        # Iniciar scheduler (incluye inicialización ETCD)
        print(f"\n🔐 Starting scheduler with ETCD crypto...")
        await scheduler.start(config_file, firewall_rules_file)

    except SchedulerConfigurationError as e:
        print(f"\n💥 SCHEDULER CONFIGURATION ERROR:")
        print(f"❌ {e}")
        print(f"🔧 Check file: {config_file}")
        print("📋 Required sections: component, network, zmq, processing, monitoring, logging, etcd_crypto")
        print("🔐 ETCD crypto requirements:")
        print("   • crypto.enabled=true")
        print("   • crypto.use_etcd_pipeline_key=true")
        print("   • etcd_crypto section with cluster details")
        sys.exit(1)
    except FirewallSchedulerRulesError as e:
        print(f"\n💥 FIREWALL RULES ERROR:")
        print(f"❌ {e}")
        print(f"🔧 Check file: {firewall_rules_file}")
        print("📋 Required sections: firewall_rules.rules, firewall_rules.manual_actions, firewall_rules.agents_fleet")
        sys.exit(1)
    except ETCDCryptoError as e:
        print(f"\n💥 ETCD CRYPTO ERROR:")
        print(f"❌ {e}")
        print("🔐 ETCD crypto is MANDATORY for this scheduler")
        print("📋 Verify:")
        print("   • ETCD cluster is running and accessible")
        print("   • ETCD crypto coordinator is active")
        print("   • Network connectivity to ETCD")
        print("   • Pipeline key can be obtained from ETCD")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"\n💥 JSON FORMAT ERROR:")
        print(f"❌ {e}")
        print("🔧 Verify JSON syntax in both files")
        print("📝 Use an online JSON validator to check")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 FATAL ERROR:")
        print(f"❌ {e}")
        print("\n🔍 Debug information:")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    """Función principal del scheduler - Wrapper para asyncio"""
    try:
        # Ejecutar función asíncrona principal
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n🛑 Keyboard interrupt received")
        sys.exit(0)
    except Exception as e:
        print(f"\n💥 Unexpected error in main: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()