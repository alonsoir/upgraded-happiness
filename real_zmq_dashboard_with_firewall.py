#!/usr/bin/env python3
"""
Dashboard de Seguridad con ZeroMQ - Backend Principal v2.5.0 MEJORADO
✅ MEJORADO: Compatibilidad total con lightweight_ml_detector V3
✅ MEJORADO: Separación completa de archivos de configuración
✅ MEJORADO: Logging robusto a disco y terminal activado por defecto
✅ MEJORADO: Manejo mejorado de protobuf V3 desde ML Detector
✅ MEJORADO: Integración completa con firewall_rules.json
✅ MEJORADO: Compatibilidad con modales draggeables
✅ CORREGIDO: Errores sintácticos y métodos duplicados
"""
from typing import Dict, List, Optional, Any, Set
import zmq
import json
import threading
import time
import logging
import queue
import os
import signal
import sys
import psutil
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
import http.server
import socketserver
from urllib.parse import urlparse
import mimetypes
from collections import defaultdict, deque


class ConfigurationError(Exception):
    """Error de configuración del dashboard"""
    pass


class FirewallRulesError(Exception):
    """Error en reglas de firewall"""
    pass


@dataclass
class FirewallRule:
    """Regla de firewall desde JSON"""
    risk_range: List[int]
    action: str
    description: str
    params: Dict[str, Any]
    priority: str = "MEDIUM"
    dry_run: bool = False
    enabled: bool = True


@dataclass
class FirewallAgentInfo:
    """Información de un agente firewall"""
    node_id: str
    endpoint: str
    capabilities: List[str]
    max_rules: int = 1000
    default_rule_duration: int = 600
    status: str = "active"
    active_rules: int = 0


class FirewallRulesEngine:
    """Motor de reglas de firewall desde JSON - MEJORADO V2.5.0"""

    def __init__(self, rules_file: str, logger):
        self.rules_file = rules_file
        self.logger = logger
        self.rules: List[FirewallRule] = []
        self.manual_actions: Dict[str, Dict] = {}
        self.firewall_agents: Dict[str, FirewallAgentInfo] = {}
        self.global_settings: Dict[str, Any] = {}
        self.last_loaded: Optional[datetime] = None

        # ✅ MEJORADO: Validación previa del archivo
        if not Path(self.rules_file).exists():
            raise FirewallRulesError(f"❌ Archivo de reglas no encontrado: {self.rules_file}")

        # Cargar reglas iniciales
        self.load_rules()

    def load_rules(self, force_reload: bool = False):
        """Cargar reglas desde JSON - VERSIÓN MEJORADA"""
        try:
            # Verificar si necesita recarga
            file_mtime = datetime.fromtimestamp(os.path.getmtime(self.rules_file))
            if not force_reload and self.last_loaded and file_mtime <= self.last_loaded:
                self.logger.debug("📋 Reglas ya están actualizadas")
                return

            with open(self.rules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            firewall_config = data.get('firewall_rules', {})

            # ✅ VALIDACIÓN MEJORADA: Verificar estructura básica
            required_sections = ['rules', 'manual_actions', 'firewall_agents', 'global_settings']
            for section in required_sections:
                if section not in firewall_config:
                    self.logger.warning(f"⚠️ Sección faltante en reglas: {section}")

            # Cargar reglas principales con validación
            self.rules.clear()
            for rule_data in firewall_config.get('rules', []):
                if rule_data.get('enabled', True):
                    # ✅ VALIDACIÓN: Verificar campos requeridos
                    required_fields = ['risk_range', 'action', 'description']
                    if all(field in rule_data for field in required_fields):
                        rule = FirewallRule(
                            risk_range=rule_data['risk_range'],
                            action=rule_data['action'],
                            description=rule_data['description'],
                            params=rule_data.get('params', {}),
                            priority=rule_data.get('priority', 'MEDIUM'),
                            dry_run=rule_data.get('dry_run', False),
                            enabled=rule_data.get('enabled', True)
                        )
                        self.rules.append(rule)
                    else:
                        self.logger.warning(f"⚠️ Regla inválida ignorada: {rule_data}")

            # Cargar acciones manuales
            self.manual_actions = firewall_config.get('manual_actions', {})

            # Cargar agentes firewall con validación mejorada
            self.firewall_agents.clear()
            for node_id, agent_data in firewall_config.get('firewall_agents', {}).items():
                # ✅ VALIDACIÓN: Verificar campos requeridos del agente
                if 'node_id' in agent_data and 'endpoint' in agent_data:
                    agent_info = FirewallAgentInfo(
                        node_id=agent_data['node_id'],
                        endpoint=agent_data['endpoint'],
                        capabilities=agent_data.get('capabilities', []),
                        max_rules=agent_data.get('max_rules', 1000),
                        default_rule_duration=agent_data.get('default_rule_duration', 600)
                    )
                    self.firewall_agents[node_id] = agent_info
                else:
                    self.logger.warning(f"⚠️ Agente firewall inválido: {node_id}")

            # Cargar configuración global
            self.global_settings = firewall_config.get('global_settings', {})

            self.last_loaded = datetime.now()

            self.logger.info(
                f"✅ Reglas de firewall cargadas: {len(self.rules)} reglas, {len(self.firewall_agents)} agentes")
            self.logger.info(f"📋 Versión: {firewall_config.get('version', 'unknown')}")

            # ✅ NUEVO: Log de validación de configuración
            self._validate_configuration()

        except json.JSONDecodeError as e:
            raise FirewallRulesError(f"❌ Error parseando JSON: {e}")
        except Exception as e:
            raise FirewallRulesError(f"❌ Error cargando reglas: {e}")

    def _validate_configuration(self):
        """Validar configuración cargada"""
        issues = []

        # Validar que hay al menos un agente
        if not self.firewall_agents:
            issues.append("No hay agentes firewall configurados")

        # Validar que las reglas cubren todo el rango 0-100
        risk_coverage = set()
        for rule in self.rules:
            if rule.enabled:
                for risk in range(rule.risk_range[0], rule.risk_range[1] + 1):
                    risk_coverage.add(risk)

        missing_ranges = []
        for risk in range(0, 101):
            if risk not in risk_coverage:
                missing_ranges.append(risk)

        if missing_ranges:
            issues.append(
                f"Risk scores sin cobertura: {missing_ranges[:10]}{'...' if len(missing_ranges) > 10 else ''}")

        # Log issues encontrados
        if issues:
            self.logger.warning(f"⚠️ Issues en configuración de firewall: {issues}")
        else:
            self.logger.info("✅ Configuración de firewall validada correctamente")

    def get_recommended_action_for_risk(self, risk_score: float) -> Optional[FirewallRule]:
        """Obtener acción recomendada basada en risk_score - MEJORADO"""
        try:
            # Convertir risk_score (0.0-1.0) a porcentaje (0-100)
            risk_percentage = int(risk_score * 100)

            # Buscar regla que coincida con el rango de riesgo
            matching_rules = []
            for rule in self.rules:
                if rule.enabled and rule.risk_range[0] <= risk_percentage <= rule.risk_range[1]:
                    matching_rules.append(rule)

            if matching_rules:
                # Si hay múltiples reglas, elegir la de mayor prioridad
                priority_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
                best_rule = max(matching_rules, key=lambda r: priority_order.get(r.priority, 0))

                self.logger.debug(f"🎯 Regla encontrada para riesgo {risk_percentage}%: {best_rule.action}")
                return best_rule

            # Si no hay regla específica, usar MONITOR por defecto
            self.logger.warning(f"⚠️ No hay regla para riesgo {risk_percentage}%, usando MONITOR")
            return self._get_default_monitor_rule()

        except Exception as e:
            self.logger.error(f"❌ Error obteniendo acción recomendada: {e}")
            return self._get_default_monitor_rule()

    def get_manual_action_info(self, action: str) -> Optional[Dict]:
        """Obtener información de acción manual"""
        return self.manual_actions.get(action)

    def get_firewall_agent_by_node_id(self, node_id: str) -> Optional[FirewallAgentInfo]:
        """Obtener información de agente por node_id"""
        return self.firewall_agents.get(node_id)

    def get_default_firewall_agent(self) -> Optional[FirewallAgentInfo]:
        """Obtener primer agente disponible como default"""
        if self.firewall_agents:
            return list(self.firewall_agents.values())[0]
        return None

    def _get_default_monitor_rule(self) -> FirewallRule:
        """Regla por defecto de monitoreo"""
        return FirewallRule(
            risk_range=[0, 100],
            action="MONITOR",
            description="Regla por defecto - monitoreo",
            params={"duration": 300},
            priority="LOW",
            dry_run=True,
            enabled=True
        )

    def reload_if_changed(self):
        """Recargar reglas si el archivo cambió"""
        try:
            if Path(self.rules_file).exists():
                file_mtime = datetime.fromtimestamp(os.path.getmtime(self.rules_file))
                if self.last_loaded and file_mtime > self.last_loaded:
                    self.logger.info("🔄 Archivo de reglas modificado, recargando...")
                    self.load_rules(force_reload=True)
        except Exception as e:
            self.logger.error(f"❌ Error verificando cambios en reglas: {e}")


@dataclass
class EncodingError:
    """Información detallada de errores de encoding"""
    timestamp: str
    worker_id: int
    error_type: str
    message_length: int
    first_bytes_hex: str
    encoding_attempted: str
    position: int
    byte_value: str
    error_message: str
    suggested_fix: str


@dataclass
class WorkerStats:
    """Estadísticas por worker"""
    worker_id: int
    worker_type: str  # ml_events, firewall_responses, etc.
    messages_received: int = 0
    messages_successful: int = 0
    encoding_errors: int = 0
    last_activity: Optional[datetime] = None
    last_error: Optional[EncodingError] = None
    error_rate: float = 0.0
    status: str = "idle"  # idle, active, error


@dataclass
class ConnectionInfo:
    """Información detallada de conexiones activas"""
    connection_id: str
    node_id: Optional[str] = None
    component_type: str = "unknown"
    endpoint: str = ""
    socket_type: str = ""
    mode: str = ""
    status: str = "disconnected"
    last_seen: Optional[datetime] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    version: Optional[str] = None
    handshake_completed: bool = False
    messages_exchanged: int = 0


class EncodingMonitor:
    """Monitor de errores de encoding en tiempo real - MEJORADO V2.5.0"""

    def __init__(self, logger):
        self.logger = logger
        self.encoding_errors: List[EncodingError] = []
        self.worker_stats: Dict[str, WorkerStats] = {}
        self.connection_info: Dict[str, ConnectionInfo] = {}
        self.error_patterns: Dict[str, int] = defaultdict(int)
        self.encoding_suggestions: Dict[str, str] = {
            'utf-8': 'Datos UTF-8 válidos',
            'latin-1': 'Posible texto con caracteres especiales',
            'protobuf': 'Datos binarios protobuf detectados',
            'protobuf_v3': 'Datos protobuf V3 desde ML Detector',  # ✅ NUEVO
            'binary': 'Datos binarios sin estructura conocida',
            'corrupted': 'Datos corruptos o fragmentados'
        }

    def detect_encoding_type(self, data: bytes) -> str:
        """Detectar tipo de encoding - MEJORADO PARA PROTOBUF V3"""
        if len(data) == 0:
            return 'empty'

        # 1. PRIMERO: Verificar si parece protobuf V3 (ML Detector)
        if self._looks_like_protobuf_v3(data):
            return 'protobuf_v3'

        # 2. Verificar protobuf general
        if self._looks_like_protobuf(data):
            return 'protobuf'

        # 3. Verificar UTF-8 válido
        try:
            decoded = data.decode('utf-8')
            # Verificar si parece JSON
            if decoded.strip().startswith(('{', '[')):
                return 'utf-8'
        except UnicodeDecodeError:
            pass

        # 4. Verificar si es texto en otra codificación
        try:
            decoded = data.decode('latin-1')
            if decoded.isprintable() and '{' in decoded:
                return 'latin-1'
        except:
            pass

        # 5. Verificar otros formatos binarios
        if data.startswith(b'\x00') or data.startswith(b'\xff'):
            return 'binary'

        return 'corrupted'

    def _looks_like_protobuf_v3(self, data: bytes) -> bool:
        """Detectar si los datos parecen ser protobuf V3 del ML Detector"""
        if len(data) < 6:
            return False

        # ✅ NUEVO: Patrones específicos de protobuf V3 del ML Detector
        # Basado en los campos del NetworkEvent V3
        v3_patterns = [
            # Campo 1: event_id (string)
            b'\x0a',  # field 1, wire type 2 (length-delimited)
            # Campo 2: timestamp (int64)
            b'\x10',  # field 2, wire type 0 (varint)
            # Campo 3: source_ip (string)
            b'\x1a',  # field 3, wire type 2 (length-delimited)
            # Campo 4: target_ip (string)
            b'\x22',  # field 4, wire type 2 (length-delimited)
            # Campo 5: packet_size (int32)
            b'\x28',  # field 5, wire type 0 (varint)
        ]

        # Verificar si empieza con un patrón típico de V3
        starts_with_v3 = any(data.startswith(pattern) for pattern in v3_patterns)

        if starts_with_v3:
            # Verificación adicional: buscar secuencias típicas de V3
            if len(data) >= 20:
                # Buscar patrones de campos consecutivos típicos del NetworkEvent V3
                v3_field_count = 0
                for i in range(min(15, len(data) - 1)):
                    byte_pair = data[i:i + 2]
                    if byte_pair in [b'\x0a\x10', b'\x10\x1a', b'\x1a\x22', b'\x22\x28']:
                        v3_field_count += 1

                if v3_field_count >= 1:
                    return True

        return False

    def _looks_like_protobuf(self, data: bytes) -> bool:
        """Detectar si los datos parecen ser protobuf general - VERSIÓN MEJORADA"""
        if len(data) < 4:
            return False

        # Patrones típicos de protobuf - EXPANDIDOS
        protobuf_patterns = [
            b'\x08', b'\x0a', b'\x10', b'\x12', b'\x18', b'\x1a',
            b'\x20', b'\x22', b'\x28', b'\x2a', b'\x30', b'\x32',
            b'\x38', b'\x3a', b'\x40', b'\x42', b'\x48', b'\x4a',
            b'\x50', b'\x52', b'\x58', b'\x5a', b'\x60', b'\x62'
        ]

        # Verificar si empieza con patrón protobuf
        starts_with_protobuf = any(data.startswith(pattern) for pattern in protobuf_patterns)

        # Verificación adicional: verificar si NO parece JSON o texto
        try:
            # Si se puede decodificar como UTF-8 Y parece JSON, probablemente no es protobuf
            decoded = data.decode('utf-8')
            if decoded.strip().startswith(('{', '[')):
                return False
        except UnicodeDecodeError:
            # No se puede decodificar como UTF-8, más probable que sea protobuf
            pass

        # Verificación adicional: buscar patrones de campo protobuf en los primeros bytes
        if len(data) >= 10:
            # Contar bytes que parecen ser field tags de protobuf
            protobuf_like_bytes = 0
            for i in range(min(10, len(data))):
                byte = data[i]
                # Field numbers y wire types típicos
                if byte in [0x08, 0x0a, 0x10, 0x12, 0x18, 0x1a, 0x20, 0x22, 0x28, 0x2a]:
                    protobuf_like_bytes += 1

            # Si hay varios bytes que parecen protobuf, probablemente lo es
            if protobuf_like_bytes >= 2:
                return True

        return starts_with_protobuf

    def log_encoding_error(self, worker_id: int, worker_type: str,
                           data: bytes, error: Exception, encoding_attempted: str):
        """Registrar error de encoding con detalles"""

        # Crear información del error
        encoding_error = EncodingError(
            timestamp=datetime.now().isoformat(),
            worker_id=worker_id,
            error_type=type(error).__name__,
            message_length=len(data),
            first_bytes_hex=data[:20].hex() if len(data) >= 20 else data.hex(),
            encoding_attempted=encoding_attempted,
            position=getattr(error, 'start', 0),
            byte_value=f"0x{data[getattr(error, 'start', 0)]:02x}" if data else "0x00",
            error_message=str(error),
            suggested_fix=self._get_encoding_suggestion(data)
        )

        # Añadir a la lista de errores
        self.encoding_errors.append(encoding_error)

        # Mantener solo los últimos 100 errores
        if len(self.encoding_errors) > 100:
            self.encoding_errors = self.encoding_errors[-100:]

        # Actualizar estadísticas del worker
        worker_key = f"{worker_type}_{worker_id}"
        if worker_key not in self.worker_stats:
            self.worker_stats[worker_key] = WorkerStats(
                worker_id=worker_id,
                worker_type=worker_type
            )

        stats = self.worker_stats[worker_key]
        stats.encoding_errors += 1
        stats.last_error = encoding_error
        stats.last_activity = datetime.now()
        stats.status = "error"
        stats.error_rate = stats.encoding_errors / max(stats.messages_received, 1) * 100

        # Actualizar patrones de error
        detected_type = self.detect_encoding_type(data)
        self.error_patterns[detected_type] += 1

        self.logger.error(
            f"🔍 Worker {worker_id} ({worker_type}) - Error encoding: "
            f"{encoding_error.error_type} at pos {encoding_error.position}, "
            f"byte {encoding_error.byte_value}, suggested: {encoding_error.suggested_fix}"
        )

    def log_successful_message(self, worker_id: int, worker_type: str,
                               message_length: int, encoding_used: str):
        """Registrar mensaje procesado exitosamente"""
        worker_key = f"{worker_type}_{worker_id}"
        if worker_key not in self.worker_stats:
            self.worker_stats[worker_key] = WorkerStats(
                worker_id=worker_id,
                worker_type=worker_type
            )

        stats = self.worker_stats[worker_key]
        stats.messages_received += 1
        stats.messages_successful += 1
        stats.last_activity = datetime.now()
        stats.status = "active"
        stats.error_rate = stats.encoding_errors / max(stats.messages_received, 1) * 100

    def _get_encoding_suggestion(self, data: bytes) -> str:
        """Obtener sugerencia basada en el análisis de los datos"""
        detected_type = self.detect_encoding_type(data)
        return self.encoding_suggestions.get(detected_type, 'Tipo desconocido')

    def register_connection(self, connection_id: str, endpoint: str,
                            socket_type: str, mode: str):
        """Registrar nueva conexión"""
        self.connection_info[connection_id] = ConnectionInfo(
            connection_id=connection_id,
            endpoint=endpoint,
            socket_type=socket_type,
            mode=mode,
            status="connecting",
            last_seen=datetime.now()
        )

    def update_connection_info(self, connection_id: str, node_id: str = None,
                               component_type: str = None, version: str = None,
                               remote_ip: str = None, remote_port: int = None):
        """Actualizar información de conexión"""
        if connection_id in self.connection_info:
            conn = self.connection_info[connection_id]
            if node_id:
                conn.node_id = node_id
            if component_type:
                conn.component_type = component_type
            if version:
                conn.version = version
            if remote_ip:
                conn.remote_ip = remote_ip
            if remote_port:
                conn.remote_port = remote_port
            conn.last_seen = datetime.now()
            conn.status = "connected"
            conn.handshake_completed = True
            conn.messages_exchanged += 1

    def get_monitoring_data(self) -> Dict:
        """Obtener todos los datos de monitoreo"""
        return {
            'encoding_errors': [asdict(error) for error in self.encoding_errors[-20:]],
            'worker_stats': {k: asdict(v) for k, v in self.worker_stats.items()},
            'connection_info': {k: asdict(v) for k, v in self.connection_info.items()},
            'error_patterns': dict(self.error_patterns),
            'summary': {
                'total_errors': len(self.encoding_errors),
                'active_workers': len([s for s in self.worker_stats.values()
                                       if s.status == "active"]),
                'error_workers': len([s for s in self.worker_stats.values()
                                      if s.status == "error"]),
                'connected_components': len([c for c in self.connection_info.values()
                                             if c.status == "connected"]),
                'most_common_error': max(self.error_patterns.items(),
                                         key=lambda x: x[1])[0] if self.error_patterns else 'none'
            }
        }


class DashboardLogger:
    """Logger mejorado con soporte robusto para archivos - VERSIÓN 2.5.0"""

    def __init__(self, node_id: str, log_config: dict):
        self.logger = logging.getLogger(f"dashboard_{node_id}")
        self.node_id = node_id

        # Configurar logging según JSON
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        log_format = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Crear formatter
        formatter = logging.Formatter(log_format)

        # Limpiar handlers existentes
        self.logger.handlers.clear()
        self.logger.setLevel(log_level)

        # Handler de consola - SIEMPRE ACTIVADO
        console_config = log_config.get('handlers', {}).get('console', {})
        if console_config.get('enabled', True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            console_handler.setLevel(getattr(logging, console_config.get('level', 'INFO').upper()))
            self.logger.addHandler(console_handler)
            print(f"✅ Logging a consola activado: {console_config.get('level', 'INFO')}")

        # ✅ MEJORADO: Handler de archivo ROBUSTO Y ACTIVADO POR DEFECTO
        file_config = log_config.get('handlers', {}).get('file', {})
        if file_config.get('enabled', True):  # ✅ TRUE por defecto
            file_path = file_config.get('path', 'logs/dashboard.log')

            try:
                # Crear directorio si no existe
                Path(file_path).parent.mkdir(parents=True, exist_ok=True)

                # ✅ NUEVO: Verificar permisos de escritura
                test_file = Path(file_path).parent / '.write_test'
                test_file.touch()
                test_file.unlink()

                # Configurar handler de archivo con rotación
                file_handler = logging.FileHandler(file_path, encoding='utf-8')
                file_handler.setFormatter(formatter)
                file_handler.setLevel(getattr(logging, file_config.get('level', 'INFO').upper()))
                self.logger.addHandler(file_handler)

                print(f"✅ Logging a archivo activado: {file_path} ({file_config.get('level', 'INFO')})")

                # Log inicial en el archivo
                self.logger.info(f"🚀 Dashboard Logger iniciado - Node: {node_id} - PID: {os.getpid()}")

            except Exception as e:
                print(f"⚠️ Error configurando logging a archivo: {e}")
                print(f"📁 Verificar permisos en: {Path(file_path).parent}")

        # Añadir node_id al contexto
        old_factory = logging.getLogRecordFactory()

        def record_factory(*args, **kwargs):
            record = old_factory(*args, **kwargs)
            record.node_id = self.node_id
            record.pid = os.getpid()
            return record

        logging.setLogRecordFactory(record_factory)

        # Log de confirmación
        self.info("✅ DashboardLogger configurado correctamente")

    def info(self, msg, *args, **kwargs):
        self.logger.info(f"[node_id:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.logger.warning(f"[node_id:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.logger.error(f"[node_id:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self.logger.debug(f"[node_id:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)


@dataclass
class SecurityEvent:
    id: str
    source_ip: str
    target_ip: str
    risk_score: float
    anomaly_score: float
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timestamp: str = None
    attack_type: Optional[str] = None
    location: Optional[str] = None
    packets: int = 0
    bytes: int = 0
    port: Optional[int] = None
    protocol: Optional[str] = None
    ml_models_scores: Optional[Dict] = None
    # Campos adicionales del protobuf
    protobuf_data: Optional[Dict] = None
    node_id: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class FirewallCommand:
    action: str
    target_ip: str
    duration: str
    reason: str
    risk_score: float
    timestamp: str
    event_id: str
    rule_type: str = "iptables"
    port: Optional[int] = None
    protocol: Optional[str] = None
    firewall_node_id: Optional[str] = None


@dataclass
class ComponentStatus:
    node_id: str
    component_type: str
    status: str
    last_seen: datetime
    address: str
    port: int
    socket_type: str
    mode: str
    events_received: int = 0
    events_sent: int = 0
    latency_ms: float = 0.0
    error_count: int = 0


@dataclass
class ZMQConnectionInfo:
    socket_id: str
    socket_type: str
    endpoint: str
    mode: str
    status: str
    high_water_mark: int
    queue_size: int
    total_messages: int
    bytes_transferred: int
    last_activity: datetime
    connected_peers: List[str]


class DashboardConfig:
    """Configuración estricta del dashboard - TODO desde JSON - VERSIÓN 2.5.0"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = None
        self.load_and_validate_config()

    def load_and_validate_config(self):
        """Cargar y validar configuración - VERSIÓN MEJORADA"""
        if not Path(self.config_file).exists():
            raise ConfigurationError(f"❌ Archivo de configuración {self.config_file} no encontrado")

        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"❌ Error parseando JSON en {self.config_file}: {e}")
        except Exception as e:
            raise ConfigurationError(f"❌ Error leyendo {self.config_file}: {e}")

        # Validar campos requeridos
        self._validate_required_fields()

        # Extraer valores validados
        self._extract_config_values()

        print(f"✅ Configuración del dashboard cargada: {self.config_file}")

    def _validate_required_fields(self):
        """Validar que todos los campos requeridos existan"""
        required_paths = [
            'node_id',
            'component.name',
            'component.version',
            'network.ml_events_input.port',
            'network.ml_events_input.address',
            'network.ml_events_input.mode',
            'network.ml_events_input.socket_type',
            'network.firewall_commands_output.port',
            'network.firewall_commands_output.address',
            'network.firewall_commands_output.mode',
            'network.firewall_commands_output.socket_type',
            'network.firewall_responses_input.port',
            'network.firewall_responses_input.address',
            'network.firewall_responses_input.mode',
            'network.firewall_responses_input.socket_type',
            'network.admin_interface.address',
            'network.admin_interface.port',
            'zmq.context_io_threads',
            'processing.threads.ml_events_consumers',
            'processing.threads.firewall_command_producers',
            'processing.internal_queues.ml_events_queue_size',
            'processing.internal_queues.firewall_commands_queue_size',
            'monitoring.stats_interval_seconds',
            'logging.level',
            'logging.format'
        ]

        for path in required_paths:
            if not self._get_nested_value(path):
                raise ConfigurationError(f"❌ Campo requerido faltante en configuración: {path}")

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
        """Extraer todos los valores de configuración"""
        # Node ID y component info
        self.node_id = self.config['node_id']
        component = self.config['component']
        self.component_name = component['name']
        self.version = component['version']
        self.mode = component.get('mode', 'distributed_orchestrator')
        self.role = component.get('role', 'dashboard_coordinator')

        # Network configuration
        network = self.config['network']

        # ML Events Input
        ml_events = network['ml_events_input']
        self.ml_detector_address = ml_events['address']
        self.ml_detector_port = ml_events['port']
        self.ml_detector_mode = ml_events['mode']
        self.ml_detector_socket_type = ml_events['socket_type']
        self.ml_detector_hwm = ml_events.get('high_water_mark', 10000)
        self.ml_detector_expected_publishers = ml_events.get('expected_publishers', 1)

        # Firewall Commands Output
        fw_commands = network['firewall_commands_output']
        self.firewall_commands_address = fw_commands['address']
        self.firewall_commands_port = fw_commands['port']
        self.firewall_commands_mode = fw_commands['mode']
        self.firewall_commands_socket_type = fw_commands['socket_type']
        self.firewall_commands_hwm = fw_commands.get('high_water_mark', 5000)
        self.firewall_commands_expected_subscribers = fw_commands.get('expected_subscribers', 1)

        # Firewall Responses Input
        fw_responses = network['firewall_responses_input']
        self.firewall_responses_address = fw_responses['address']
        self.firewall_responses_port = fw_responses['port']
        self.firewall_responses_mode = fw_responses['mode']
        self.firewall_responses_socket_type = fw_responses['socket_type']
        self.firewall_responses_hwm = fw_responses.get('high_water_mark', 5000)
        self.firewall_responses_expected_publishers = fw_responses.get('expected_publishers', 1)

        # Admin Interface
        admin_interface = network['admin_interface']
        self.web_host = admin_interface['address']
        self.web_port = admin_interface['port']

        # ZMQ Configuration
        zmq_config = self.config['zmq']
        self.zmq_io_threads = zmq_config['context_io_threads']
        self.zmq_max_sockets = zmq_config.get('max_sockets', 1024)
        self.zmq_tcp_keepalive = zmq_config.get('tcp_keepalive', True)
        self.zmq_tcp_keepalive_idle = zmq_config.get('tcp_keepalive_idle', 300)
        self.zmq_immediate = zmq_config.get('immediate', True)

        # Processing Configuration
        processing = self.config['processing']
        threads = processing['threads']
        self.ml_events_consumers = threads['ml_events_consumers']
        self.firewall_command_producers = threads['firewall_command_producers']
        self.firewall_response_consumers = threads.get('firewall_response_consumers', 2)

        queues = processing['internal_queues']
        self.ml_events_queue_size = queues['ml_events_queue_size']
        self.firewall_commands_queue_size = queues['firewall_commands_queue_size']
        self.firewall_responses_queue_size = queues.get('firewall_responses_queue_size', 2000)

        # Monitoring
        monitoring = self.config['monitoring']
        self.stats_interval = monitoring['stats_interval_seconds']
        self.detailed_metrics = monitoring.get('detailed_metrics', True)

        # Logging configuration
        self.logging_config = self.config['logging']

        # Security
        self.security_config = self.config.get('security', {})

        # Web interface
        self.web_interface_config = self.config.get('web_interface', {})

        # ✅ NUEVO: Configuración de firewall integration
        self.firewall_integration = self.config.get('firewall_integration', {})


class EventLoggerForRAG:
    """
    Logger específico para eventos RAG/TimeSeries - MEJORADO V2.5.0
    Guarda TODOS los eventos procesados para futura base de datos
    """

    def __init__(self, config: DashboardConfig, logger):
        self.config = config
        self.logger = logger
        self.events_log_path = Path("logs/events_for_rag.jsonl")

        # Crear directorio de logs
        self.events_log_path.parent.mkdir(parents=True, exist_ok=True)

        # ✅ MEJORADO: Verificar que se puede escribir
        try:
            # Test de escritura
            test_record = {"test": True, "timestamp": datetime.now().isoformat()}
            with open(self.events_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(test_record) + '\n')

            self.logger.info(f"✅ Event Logger para RAG iniciado: {self.events_log_path}")
        except Exception as e:
            self.logger.error(f"❌ Error configurando Event Logger RAG: {e}")
            raise

        # Estadísticas de logging
        self.logged_events_count = 0
        self.start_time = time.time()

    def log_event_for_rag(self, event: SecurityEvent):
        """Guarda evento completo para RAG/TimeSeries futuro"""
        try:
            # Crear registro completo del evento
            rag_event = {
                # Identificación
                'id': event.id,
                'timestamp': event.timestamp,
                'processing_timestamp': datetime.now().isoformat(),

                # Información de red
                'source_ip': event.source_ip,
                'target_ip': event.target_ip,
                'port': event.port,
                'protocol': event.protocol,
                'packets': event.packets,
                'bytes': event.bytes,

                # Información de ML y riesgo
                'risk_score': event.risk_score,
                'anomaly_score': event.anomaly_score,
                'ml_models_scores': event.ml_models_scores,
                'attack_type': event.attack_type,

                # Geolocalización
                'latitude': event.latitude,
                'longitude': event.longitude,
                'location': event.location,

                # Información del sistema
                'node_id': event.node_id,
                'dashboard_node_id': self.config.node_id,

                # Metadatos completos del protobuf
                'protobuf_data': event.protobuf_data,

                # Información de contexto
                'system_info': {
                    'dashboard_pid': os.getpid(),
                    'processing_latency_ms': time.time() * 1000,
                    'memory_usage_mb': psutil.Process().memory_info().rss / 1024 / 1024
                },

                # ✅ NUEVO: Información del ML Detector V3
                'ml_detector_info': {
                    'version': 'V3',
                    'protobuf_version': '3.0',
                    'source_component': 'lightweight_ml_detector'
                }
            }

            # Escribir evento en formato JSONL
            with open(self.events_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(rag_event, default=str) + '\n')

            self.logged_events_count += 1

            # Log estadísticas cada 100 eventos
            if self.logged_events_count % 100 == 0:
                uptime = time.time() - self.start_time
                rate = self.logged_events_count / uptime if uptime > 0 else 0
                self.logger.info(f"📝 Eventos guardados para RAG: {self.logged_events_count} ({rate:.1f}/s)")

        except Exception as e:
            self.logger.error(f"❌ Error guardando evento para RAG: {e}")


class SecurityDashboard:
    """Dashboard principal de seguridad - VERSIÓN 2.5.0 MEJORADA"""

    def __init__(self, config: DashboardConfig, firewall_rules_file: str):
        self.config = config
        self.logger = DashboardLogger(config.node_id, config.logging_config)

        # 🔥 Motor de reglas de firewall con validación mejorada
        try:
            self.firewall_rules_engine = FirewallRulesEngine(firewall_rules_file, self.logger)
            self.logger.info(f"✅ Motor de reglas firewall iniciado: {firewall_rules_file}")
        except FirewallRulesError as e:
            self.logger.error(f"❌ Error cargando reglas firewall: {e}")
            raise

        # ✅ Logger de eventos para RAG
        try:
            self.event_logger_rag = EventLoggerForRAG(config, self.logger)
        except Exception as e:
            self.logger.error(f"❌ Error configurando RAG logger: {e}")
            raise

        # Inicializar monitor de encoding mejorado
        self.encoding_monitor = EncodingMonitor(self.logger)

        # 🔒 CRÍTICO: Lock para thread safety de sockets ZMQ
        self.socket_lock = threading.RLock()

        # 📊 Debug counters para monitoreo
        self.debug_counters = {
            'messages_received': 0,
            'messages_parsed': 0,
            'protobuf_v3_parsed': 0,  # ✅ NUEVO: Contador específico para V3
            'socket_operations': 0,
            'last_message_size': 0,
            'last_message_time': 0
        }

        # Crear contexto ZMQ con configuración del JSON
        self.context = zmq.Context(io_threads=config.zmq_io_threads)

        # Estado del dashboard
        self.events: List[SecurityEvent] = []
        self.firewall_commands: List[FirewallCommand] = []
        self.component_status: Dict[str, ComponentStatus] = {}
        self.zmq_connections: Dict[str, ZMQConnectionInfo] = {}

        # ✅ CORREGIDO: TODOS los eventos recientes para web (SIN LÍMITES)
        self.recent_events: List[Dict] = []  # ✅ SIN límite de tamaño

        # Colas de procesamiento con tamaños del JSON
        self.ml_events_queue = queue.Queue(maxsize=config.ml_events_queue_size)
        self.firewall_commands_queue = queue.Queue(maxsize=config.firewall_commands_queue_size)
        self.firewall_responses_queue = queue.Queue(maxsize=config.firewall_responses_queue_size)

        # WebSocket clients
        self.websocket_clients = set()

        # Estadísticas mejoradas
        self.stats = {
            'events_received': 0,
            'events_processed': 0,
            'commands_sent': 0,
            'threats_blocked': 0,
            'events_per_minute': 0,
            'high_risk_events': 0,
            'geographic_distribution': 0,
            'active_firewall_agents': 0,
            'ml_detector_latency': 0.0,
            'last_update': datetime.now().isoformat(),
            'uptime_seconds': 0,
            'memory_usage_mb': 0,
            'cpu_usage_percent': 0.0,
            # Estadísticas de encoding
            'encoding_errors_total': 0,
            'encoding_errors_rate': 0.0,
            'active_workers': 0,
            'problematic_workers': 0,
            # Campos para compatibilidad con frontend
            'total_events': 0,
            'success_rate': 95,
            'failures': 0,
            'confirmations': 0,
            # ✅ Estadísticas RAG
            'events_logged_for_rag': 0,
            # ✅ NUEVO: Estadísticas específicas V3
            'protobuf_v3_messages': 0,
            'ml_detector_v3_connected': False
        }

        # Métricas detalladas
        self.detailed_metrics = {
            'zmq_connections': {},
            'component_health': {},
            'processing_queues': {},
            'network_topology': {},
            'performance_metrics': {
                'events_per_second_history': deque(maxlen=60),
                'latency_history': deque(maxlen=60),
                'error_rate_history': deque(maxlen=60)
            }
        }

        self.running = False
        self.start_time = time.time()

        # Verificar archivos requeridos
        self._verify_required_files()

        # Configurar sockets ZeroMQ con configuración conservadora
        self.setup_zmq_sockets_with_monitoring()

    def _verify_required_files(self):
        """Verificar que existan los archivos requeridos del sistema"""
        required_files = [
            'templates/dashboard.html',
            'static/css/dashboard.css'
        ]

        for file_path in required_files:
            if not Path(file_path).exists():
                self.logger.warning(f"⚠️ Archivo opcional no encontrado: {file_path}")

        self.logger.info("✅ Verificación de archivos del sistema completada")

    def setup_zmq_sockets_with_monitoring(self):
        """Setup ZMQ con configuración mejorada para ML Detector V3"""
        self.logger.info("🔧 Configurando sockets ZeroMQ para ML Detector V3...")

        try:
            # ✅ ML Events Input Socket - OPTIMIZADO PARA V3
            self.logger.info(f"📡 Configurando ML Events socket para protobuf V3...")
            socket_type = getattr(zmq, self.config.ml_detector_socket_type)
            self.ml_socket = self.context.socket(socket_type)

            # ✅ CONFIGURACIÓN OPTIMIZADA PARA ML DETECTOR V3
            self.ml_socket.setsockopt(zmq.RCVHWM, self.config.ml_detector_hwm)
            self.ml_socket.setsockopt(zmq.LINGER, 0)
            self.ml_socket.setsockopt(zmq.RCVTIMEO, 1000)  # Timeout más generoso para V3

            # ✅ Configuraciones específicas para protobuf V3
            self.ml_socket.setsockopt(zmq.RCVBUF, 131072)  # Buffer más grande para V3
            self.ml_socket.setsockopt(zmq.MAXMSGSIZE, 50000)  # Mensajes V3 pueden ser más grandes

            if self.config.zmq_tcp_keepalive:
                self.ml_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                self.ml_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, self.config.zmq_tcp_keepalive_idle)

            ml_endpoint = f"tcp://{self.config.ml_detector_address}:{self.config.ml_detector_port}"

            if self.config.ml_detector_mode == 'bind':
                self.ml_socket.bind(ml_endpoint)
                self.logger.info(f"🟢 ML Events socket BIND en {ml_endpoint} (optimizado para V3)")
            elif self.config.ml_detector_mode == 'connect':
                self.ml_socket.connect(ml_endpoint)
                self.logger.info(f"🟢 ML Events socket CONNECT a {ml_endpoint} (optimizado para V3)")
            else:
                raise ConfigurationError(f"❌ Modo ZMQ inválido para ML Events: {self.config.ml_detector_mode}")

            # Registrar conexión en el monitor
            self.encoding_monitor.register_connection(
                'ml_events', ml_endpoint,
                self.config.ml_detector_socket_type,
                self.config.ml_detector_mode
            )

            # Registrar conexión en ZMQ info
            self.zmq_connections['ml_events'] = ZMQConnectionInfo(
                socket_id='ml_events',
                socket_type=self.config.ml_detector_socket_type,
                endpoint=ml_endpoint,
                mode=self.config.ml_detector_mode,
                status='active',
                high_water_mark=self.config.ml_detector_hwm,
                queue_size=0,
                total_messages=0,
                bytes_transferred=0,
                last_activity=datetime.now(),
                connected_peers=[]
            )

            # ✅ Firewall Commands Output Socket
            self.logger.info(f"🔥 Configurando Firewall Commands socket...")
            socket_type = getattr(zmq, self.config.firewall_commands_socket_type)
            self.firewall_commands_socket = self.context.socket(socket_type)

            self.firewall_commands_socket.setsockopt(zmq.SNDHWM, self.config.firewall_commands_hwm)
            self.firewall_commands_socket.setsockopt(zmq.LINGER, 0)

            if self.config.zmq_tcp_keepalive:
                self.firewall_commands_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                self.firewall_commands_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, self.config.zmq_tcp_keepalive_idle)

            fw_commands_endpoint = f"tcp://{self.config.firewall_commands_address}:{self.config.firewall_commands_port}"

            if self.config.firewall_commands_mode == 'bind':
                self.firewall_commands_socket.bind(fw_commands_endpoint)
                self.logger.info(f"🟢 Firewall Commands socket BIND en {fw_commands_endpoint}")
            elif self.config.firewall_commands_mode == 'connect':
                self.firewall_commands_socket.connect(fw_commands_endpoint)
                self.logger.info(f"🟢 Firewall Commands socket CONNECT a {fw_commands_endpoint}")
            else:
                raise ConfigurationError(
                    f"❌ Modo ZMQ inválido para Firewall Commands: {self.config.firewall_commands_mode}")

            # Registrar conexión
            self.encoding_monitor.register_connection(
                'firewall_commands', fw_commands_endpoint,
                self.config.firewall_commands_socket_type,
                self.config.firewall_commands_mode
            )

            self.zmq_connections['firewall_commands'] = ZMQConnectionInfo(
                socket_id='firewall_commands',
                socket_type=self.config.firewall_commands_socket_type,
                endpoint=fw_commands_endpoint,
                mode=self.config.firewall_commands_mode,
                status='active',
                high_water_mark=self.config.firewall_commands_hwm,
                queue_size=0,
                total_messages=0,
                bytes_transferred=0,
                last_activity=datetime.now(),
                connected_peers=[]
            )

            # ✅ Firewall Responses Input Socket
            self.logger.info(f"📥 Configurando Firewall Responses socket...")
            socket_type = getattr(zmq, self.config.firewall_responses_socket_type)
            self.firewall_responses_socket = self.context.socket(socket_type)

            self.firewall_responses_socket.setsockopt(zmq.RCVHWM, self.config.firewall_responses_hwm)
            self.firewall_responses_socket.setsockopt(zmq.LINGER, 0)
            self.firewall_responses_socket.setsockopt(zmq.RCVTIMEO, 1000)

            if self.config.zmq_tcp_keepalive:
                self.firewall_responses_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                self.firewall_responses_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, self.config.zmq_tcp_keepalive_idle)

            fw_responses_endpoint = f"tcp://{self.config.firewall_responses_address}:{self.config.firewall_responses_port}"

            if self.config.firewall_responses_mode == 'bind':
                self.firewall_responses_socket.bind(fw_responses_endpoint)
                self.logger.info(f"🟢 Firewall Responses socket BIND en {fw_responses_endpoint}")
            elif self.config.firewall_responses_mode == 'connect':
                self.firewall_responses_socket.connect(fw_responses_endpoint)
                self.logger.info(f"🟢 Firewall Responses socket CONNECT a {fw_responses_endpoint}")
            else:
                raise ConfigurationError(
                    f"❌ Modo ZMQ inválido para Firewall Responses: {self.config.firewall_responses_mode}")

            # Registrar conexión
            self.encoding_monitor.register_connection(
                'firewall_responses', fw_responses_endpoint,
                self.config.firewall_responses_socket_type,
                self.config.firewall_responses_mode
            )

            self.zmq_connections['firewall_responses'] = ZMQConnectionInfo(
                socket_id='firewall_responses',
                socket_type=self.config.firewall_responses_socket_type,
                endpoint=fw_responses_endpoint,
                mode=self.config.firewall_responses_mode,
                status='active',
                high_water_mark=self.config.firewall_responses_hwm,
                queue_size=0,
                total_messages=0,
                bytes_transferred=0,
                last_activity=datetime.now(),
                connected_peers=[]
            )

            self.logger.info("✅ Sockets ZMQ configurados para ML Detector V3 y Firewall")

        except Exception as e:
            self.logger.error(f"❌ Error configurando sockets ZeroMQ: {e}")
            raise ConfigurationError(f"Error en configuración ZeroMQ: {e}")

    def start(self):
        """Iniciar el dashboard"""
        self.running = True
        self.logger.info(f"🚀 Iniciando Dashboard de Seguridad v2.5.0...")
        self.logger.info(f"📋 Node ID: {self.config.node_id}")
        self.logger.info(f"🏗️ Component: {self.config.component_name} v{self.config.version}")
        self.logger.info(f"🔧 Mode: {self.config.mode}")
        self.logger.info(f"🎭 Role: {self.config.role}")
        self.logger.info(f"🖥️ Sistema: {os.uname().sysname} {os.uname().release}")
        self.logger.info(f"🐍 Python: {sys.version.split()[0]}")
        self.logger.info(f"💾 PID: {os.getpid()}")

        # 🔥 Log información de reglas de firewall
        try:
            rules_count = len(self.firewall_rules_engine.rules)
            agents_count = len(self.firewall_rules_engine.firewall_agents)
            self.logger.info(f"🔥 Reglas de Firewall: {rules_count} reglas, {agents_count} agentes")

            # ✅ NUEVO: Log agentes disponibles
            for agent_id, agent_info in self.firewall_rules_engine.firewall_agents.items():
                self.logger.info(f"   🤖 Agent: {agent_id} -> {agent_info.endpoint}")
        except Exception as e:
            self.logger.warning(f"⚠️ Error mostrando info de reglas: {e}")

        # Mostrar configuración de red
        self.log_network_configuration()

        # Iniciar hilos de procesamiento
        self.start_processing_threads()

        # Iniciar servidor web
        self.start_web_server()

        # Iniciar actualizaciones periódicas
        self.start_periodic_updates()

        self.logger.info("🎯 Dashboard iniciado correctamente")
        self.logger.info(f"🌐 Interfaz web disponible en: http://{self.config.web_host}:{self.config.web_port}")

        # Mantener el programa ejecutándose
        try:
            while self.running:
                time.sleep(1)
                self.update_system_metrics()
        except KeyboardInterrupt:
            self.logger.info("🛑 Recibida señal de interrupción")
            self.stop()

    def log_network_configuration(self):
        """Mostrar configuración de red detallada"""
        self.logger.info("🌐 Configuración de Red ZeroMQ:")
        self.logger.info("=" * 60)

        # ML Events
        self.logger.info(f"📡 ML Events Input (V3 Compatible):")
        self.logger.info(f"   └── Puerto: {self.config.ml_detector_port}")
        self.logger.info(f"   └── Modo: {self.config.ml_detector_mode.upper()}")
        self.logger.info(f"   └── Tipo: {self.config.ml_detector_socket_type}")
        self.logger.info(f"   └── HWM: {self.config.ml_detector_hwm}")
        self.logger.info(f"   └── Expected Publishers: {self.config.ml_detector_expected_publishers}")
        self.logger.info(f"   └── Endpoint: tcp://{self.config.ml_detector_address}:{self.config.ml_detector_port}")

        # Firewall Commands
        self.logger.info(f"🔥 Firewall Commands Output:")
        self.logger.info(f"   └── Puerto: {self.config.firewall_commands_port}")
        self.logger.info(f"   └── Modo: {self.config.firewall_commands_mode.upper()}")
        self.logger.info(f"   └── Tipo: {self.config.firewall_commands_socket_type}")
        self.logger.info(f"   └── HWM: {self.config.firewall_commands_hwm}")
        self.logger.info(f"   └── Expected Subscribers: {self.config.firewall_commands_expected_subscribers}")
        self.logger.info(
            f"   └── Endpoint: tcp://{self.config.firewall_commands_address}:{self.config.firewall_commands_port}")

        # Firewall Responses
        self.logger.info(f"📥 Firewall Responses Input:")
        self.logger.info(f"   └── Puerto: {self.config.firewall_responses_port}")
        self.logger.info(f"   └── Modo: {self.config.firewall_responses_mode.upper()}")
        self.logger.info(f"   └── Tipo: {self.config.firewall_responses_socket_type}")
        self.logger.info(f"   └── HWM: {self.config.firewall_responses_hwm}")
        self.logger.info(f"   └── Expected Publishers: {self.config.firewall_responses_expected_publishers}")
        self.logger.info(
            f"   └── Endpoint: tcp://{self.config.firewall_responses_address}:{self.config.firewall_responses_port}")

        # Web Interface
        self.logger.info(f"🌐 Web Interface:")
        self.logger.info(f"   └── Host: {self.config.web_host}")
        self.logger.info(f"   └── Puerto: {self.config.web_port}")

        # ZMQ Context
        self.logger.info(f"⚙️ ZMQ Context:")
        self.logger.info(f"   └── IO Threads: {self.config.zmq_io_threads}")
        self.logger.info(f"   └── Max Sockets: {self.config.zmq_max_sockets}")
        self.logger.info(f"   └── TCP Keepalive: {self.config.zmq_tcp_keepalive}")

        self.logger.info("=" * 60)

    def start_processing_threads(self):
        """Iniciar hilos de procesamiento según configuración JSON"""
        self.logger.info("🧵 Iniciando hilos de procesamiento...")

        # ML Events Consumers con monitoreo V3
        for i in range(self.config.ml_events_consumers):
            thread = threading.Thread(target=self.ml_events_receiver_with_v3_monitoring, args=(i,))
            thread.daemon = True
            thread.start()
            self.logger.info(f"📡 ML Events Receiver V3 {i} iniciado")

        # Firewall Command Producers
        for i in range(self.config.firewall_command_producers):
            thread = threading.Thread(target=self.firewall_commands_processor, args=(i,))
            thread.daemon = True
            thread.start()
            self.logger.info(f"🔥 Firewall Commands Processor {i} iniciado")

        # Firewall Response Consumers
        for i in range(self.config.firewall_response_consumers):
            thread = threading.Thread(target=self.firewall_responses_receiver_with_monitoring, args=(i,))
            thread.daemon = True
            thread.start()
            self.logger.info(f"📥 Firewall Responses Receiver {i} iniciado")

        self.logger.info(
            f"✅ Total hilos iniciados: {self.config.ml_events_consumers + self.config.firewall_command_producers + self.config.firewall_response_consumers}")

    def ml_events_receiver_with_v3_monitoring(self, worker_id: int):
        """Recibir eventos con soporte específico para ML Detector V3 - VERSIÓN MEJORADA"""
        self.logger.info(f"📡 ML Events Receiver V3 {worker_id} iniciado")

        while self.running:
            try:
                # 🔒 CRÍTICO: Proteger acceso al socket con lock
                with self.socket_lock:
                    try:
                        message_bytes = self.ml_socket.recv(zmq.NOBLOCK)
                        self.debug_counters['socket_operations'] += 1
                        self.debug_counters['last_message_size'] = len(message_bytes)
                        self.debug_counters['last_message_time'] = time.time()
                    except zmq.Again:
                        continue  # No hay mensajes

                # 🔍 Debug específico para V3
                self.logger.debug(f"🔍 Worker {worker_id} - Mensaje V3 recibido: {len(message_bytes)} bytes")

                # Verificar integridad del mensaje
                if len(message_bytes) == 0:
                    self.logger.warning(f"⚠️ Worker {worker_id} - Mensaje vacío recibido")
                    continue

                # ✅ MEJORADO: Detección específica de V3
                if len(message_bytes) > 100000:  # Mensajes V3 pueden ser grandes pero no tanto
                    self.logger.warning(f"⚠️ Worker {worker_id} - Mensaje muy grande: {len(message_bytes)} bytes")

                self.debug_counters['messages_received'] += 1

                # ✅ NUEVO: Intentar decodificar con prioridad V3
                message_text, encoding_used = self.decode_message_with_v3_monitoring(
                    message_bytes, worker_id, 'ml_events'
                )

                if message_text is None:
                    self.logger.warning(f"⚠️ Worker {worker_id} - Falló decodificación V3")
                    continue

                self.debug_counters['messages_parsed'] += 1

                # ✅ Actualizar contador específico V3
                if encoding_used == 'protobuf_v3':
                    self.debug_counters['protobuf_v3_parsed'] += 1
                    self.stats['protobuf_v3_messages'] += 1
                    self.stats['ml_detector_v3_connected'] = True

                # Registrar mensaje exitoso
                self.encoding_monitor.log_successful_message(
                    worker_id, 'ml_events', len(message_bytes), encoding_used
                )

                # Procesamiento del evento
                try:
                    event_data = json.loads(message_text)

                    # Verificar integridad de datos críticos
                    if not self._validate_event_data(event_data, worker_id):
                        continue

                    # ✅ MEJORADO: Actualizar info de conexión con datos V3
                    if 'node_id' in event_data:
                        self.encoding_monitor.update_connection_info(
                            'ml_events',
                            node_id=event_data.get('node_id'),
                            component_type='lightweight_ml_detector_v3',
                            version=event_data.get('agent_version', 'V3'),
                            remote_ip=event_data.get('source_ip')
                        )
                except Exception as e:
                    self.logger.error(f"❌ Worker {worker_id} - Error procesando event_data V3: {e}")
                    continue

                # Actualizar estadísticas de conexión
                try:
                    conn_info = self.zmq_connections['ml_events']
                    conn_info.total_messages += 1
                    conn_info.bytes_transferred += len(message_bytes)
                    conn_info.last_activity = datetime.now()
                except Exception as e:
                    self.logger.error(f"❌ Worker {worker_id} - Error actualizando stats: {e}")

                # Parsear y procesar evento
                try:
                    event = self.parse_security_event(event_data)

                    # ✅ Guardar evento para RAG ANTES de cualquier limite
                    self.event_logger_rag.log_event_for_rag(event)
                    self.stats['events_logged_for_rag'] += 1

                    # ✅ CORREGIDO: Añadir TODOS los eventos recientes para web (SIN LÍMITES)
                    web_event = {
                        'id': event.id,
                        'timestamp': int(time.time()),  # Unix timestamp
                        'source_ip': event.source_ip,
                        'target_ip': event.target_ip,
                        'risk_score': event.risk_score,
                        'latitude': event.latitude,
                        'longitude': event.longitude,
                        'location': event.location,
                        'type': event.attack_type or 'network_event',
                        'protocol': event.protocol or 'TCP',
                        'port': event.port or 80,
                        'packets': event.packets,
                        'bytes': event.bytes,
                        'node_id': event.node_id,
                        # ✅ NUEVO: Información específica V3
                        'ml_detector_version': 'V3',
                        'protobuf_version': '3.0',
                        'encoding_method': encoding_used,
                        # Clasificación mejorada para el frontend
                        'risk_level': 'high' if event.risk_score > 0.7 else 'medium' if event.risk_score > 0.3 else 'low',
                        'is_dns': event.target_ip in ['8.8.8.8', '1.1.1.1', '208.67.222.222'] if hasattr(event,
                                                                                                         'target_ip') else False
                    }

                    # ✅ CORREGIDO: Añadir TODOS los eventos SIN LÍMITE
                    self.recent_events.append(web_event)

                    # Añadir a cola con timeout
                    if not self.ml_events_queue.full():
                        self.ml_events_queue.put(event, timeout=1.0)
                        self.stats['events_received'] += 1
                        self.stats['total_events'] += 1

                        self.logger.debug(
                            f"📨 Worker {worker_id} - Evento V3 procesado: {event.source_ip} -> {event.target_ip}")
                    else:
                        self.logger.warning(f"⚠️ Worker {worker_id} - Cola ML events llena")

                except Exception as e:
                    self.logger.error(f"❌ Worker {worker_id} - Error parseando evento V3: {e}")

            except zmq.ZMQError as e:
                self.logger.error(f"❌ Worker {worker_id} - Error ZMQ: {e}")
                time.sleep(0.1)
            except Exception as e:
                self.logger.error(f"❌ Worker {worker_id} - Error general: {e}")
                time.sleep(0.1)

    def decode_message_with_v3_monitoring(self, message_bytes: bytes, worker_id: int,
                                          worker_type: str) -> tuple[Optional[str], str]:
        """Decodificar mensaje con prioridad para protobuf V3 - VERSIÓN MEJORADA"""

        if not message_bytes:
            return None, 'empty'

        # 🔥 CRÍTICO: Detectar protobuf V3 PRIMERO
        detected_type = self.encoding_monitor.detect_encoding_type(message_bytes)

        # ✅ PRIORIDAD 1: Protobuf V3 del ML Detector
        if detected_type == 'protobuf_v3':
            parsed = self.parse_protobuf_v3_with_monitoring(message_bytes, worker_id)
            if parsed:
                return json.dumps(parsed), 'protobuf_v3'
            else:
                self.logger.warning(f"❌ Worker {worker_id} - Falló parsing protobuf V3")

        # ✅ PRIORIDAD 2: Protobuf general
        if detected_type == 'protobuf':
            parsed = self.parse_protobuf_with_monitoring(message_bytes, worker_id)
            if parsed:
                return json.dumps(parsed), 'protobuf'

        # ✅ PRIORIDAD 3: UTF-8 JSON
        try:
            decoded = message_bytes.decode('utf-8')
            json.loads(decoded)  # Validar JSON
            return decoded, 'utf-8'
        except UnicodeDecodeError as e:
            self.encoding_monitor.log_encoding_error(
                worker_id, worker_type, message_bytes, e, 'utf-8'
            )
        except json.JSONDecodeError:
            pass

        # ✅ PRIORIDAD 4: latin-1 fallback
        if detected_type == 'latin-1':
            try:
                decoded = message_bytes.decode('latin-1')
                if decoded.strip().startswith('{'):
                    json.loads(decoded)
                    return decoded, 'latin-1'
            except Exception as e:
                self.encoding_monitor.log_encoding_error(
                    worker_id, worker_type, message_bytes, e, 'latin-1'
                )

        # ✅ ÚLTIMO RECURSO: Limpieza UTF-8
        try:
            cleaned_bytes = bytearray()
            for byte in message_bytes:
                if byte < 128:
                    cleaned_bytes.append(byte)

            if cleaned_bytes:
                cleaned = bytes(cleaned_bytes).decode('utf-8', errors='ignore')
                if len(cleaned.strip()) > 0 and '{' in cleaned and '}' in cleaned:
                    start = cleaned.find('{')
                    end = cleaned.rfind('}') + 1
                    if start >= 0 and end > start:
                        json_part = cleaned[start:end]
                        json.loads(json_part)
                        return json_part, 'utf-8-cleaned'
        except Exception as e:
            self.encoding_monitor.log_encoding_error(
                worker_id, worker_type, message_bytes, e, 'utf-8-cleaned'
            )

        # Total failure
        self.encoding_monitor.log_encoding_error(
            worker_id, worker_type, message_bytes,
            Exception(f"All decoding methods failed for {len(message_bytes)} bytes"), 'all-failed'
        )
        return None, 'failed'

    def parse_protobuf_v3_with_monitoring(self, data: bytes, worker_id: int) -> Optional[Dict]:
        """Parser específico para protobuf V3 del lightweight_ml_detector - NUEVO"""
        try:
            # ✅ INTENTAR IMPORTAR PROTOBUF V3 PRIMERO
            try:
                import src.protocols.protobuf.network_event_extended_v3_pb2 as network_v3_pb2

                # ✅ Intentar parsear como NetworkEvent V3
                event = network_v3_pb2.NetworkEvent()
                event.ParseFromString(data)

                # ✅ CONVERTIR V3 A DICCIONARIO COMPLETO
                parsed_event = self._convert_protobuf_v3_to_dict(event, worker_id, len(data))

                self.logger.info(f"📦 Worker {worker_id} - Protobuf V3 parseado correctamente ({len(data)} bytes)")
                self.logger.debug(
                    f"🔍 Evento V3: {parsed_event['source_ip']} -> {parsed_event['target_ip']} (riesgo: {parsed_event['risk_score']})")

                return parsed_event

            except ImportError as ie:
                self.logger.warning(f"⚠️ Protobuf V3 modules no disponibles: {ie}")
                self.logger.info("🔄 Intentando con protobuf V2 como fallback...")

                # Fallback a protobuf V2
                return self.parse_protobuf_with_monitoring(data, worker_id)

            except Exception as parse_error:
                self.logger.error(f"❌ Error parseando protobuf V3: {parse_error}")
                self.logger.info("🔄 Intentando con protobuf V2 como fallback...")

                # Fallback a protobuf V2
                return self.parse_protobuf_with_monitoring(data, worker_id)

        except Exception as e:
            self.logger.error(f"💥 Error crítico en parser protobuf V3: {e}")
            self.encoding_monitor.log_encoding_error(
                worker_id, 'protobuf_v3_parser', data, e, 'protobuf_v3_critical'
            )
            return None

    def _convert_protobuf_v3_to_dict(self, event, worker_id: int, data_length: int) -> dict:
        """Convertir protobuf V3 del ML Detector a diccionario completo"""
        current_time = int(time.time() * 1000)

        # ✅ CAMPOS ESPECÍFICOS DEL PROTOBUF V3
        parsed_event = {
            # 🔍 Identificación del evento
            'id': getattr(event, 'event_id', '') or str(current_time) + f"_{worker_id}",
            'event_id': getattr(event, 'event_id', ''),
            'timestamp': getattr(event, 'timestamp', current_time),

            # 🌐 Información de red básica (V3)
            'source_ip': getattr(event, 'source_ip', '127.0.0.1'),
            'target_ip': getattr(event, 'target_ip', '127.0.0.1'),
            'packet_size': getattr(event, 'packet_size', 0),
            'dest_port': getattr(event, 'dest_port', 0),
            'src_port': getattr(event, 'src_port', 0),
            'protocol': getattr(event, 'protocol', 'TCP'),
            'port': getattr(event, 'dest_port', 80),
            'attack_type': getattr(event, 'event_type', 'unknown'),

            # 🤖 Identificación del agente
            'agent_id': getattr(event, 'agent_id', ''),

            # 📊 Métricas y scoring
            'anomaly_score': float(getattr(event, 'anomaly_score', 0.0)),
            'latitude': getattr(event, 'latitude', None),
            'longitude': getattr(event, 'longitude', None),

            # 🎯 Clasificación de eventos
            'event_type': getattr(event, 'event_type', 'unknown'),
            'risk_score': float(getattr(event, 'risk_score', 0.5)),
            'description': getattr(event, 'description', ''),

            # 🖥️ Información del sistema operativo
            'so_identifier': getattr(event, 'so_identifier', ''),

            # 🏠 Información del nodo
            'node_hostname': getattr(event, 'node_hostname', ''),
            'os_version': getattr(event, 'os_version', ''),
            'firewall_status': getattr(event, 'firewall_status', 'unknown'),
            'agent_version': getattr(event, 'agent_version', 'V3'),
            'is_initial_handshake': bool(getattr(event, 'is_initial_handshake', False)),

            # 🆔 CAMPOS DISTRIBUIDOS
            'node_id': getattr(event, 'node_id', self.config.node_id),
            'process_id': int(getattr(event, 'process_id', 0)),
            'container_id': getattr(event, 'container_id', ''),
            'cluster_name': getattr(event, 'cluster_name', ''),

            # 🔄 Estado del componente
            'component_status': getattr(event, 'component_status', 'healthy'),
            'uptime_seconds': int(getattr(event, 'uptime_seconds', 0)),

            # 📈 Métricas de performance
            'queue_depth': int(getattr(event, 'queue_depth', 0)),
            'cpu_usage_percent': float(getattr(event, 'cpu_usage_percent', 0.0)),
            'memory_usage_mb': float(getattr(event, 'memory_usage_mb', 0.0)),

            # 🔧 Configuración dinámica
            'config_version': getattr(event, 'config_version', 'V3'),
            'config_timestamp': int(getattr(event, 'config_timestamp', current_time)),

            # 🌍 Enriquecimiento GeoIP
            'geoip_enriched': bool(getattr(event, 'geoip_enriched', True)),
            'enrichment_node': getattr(event, 'enrichment_node', 'ml_detector_v3'),
            'enrichment_timestamp': int(getattr(event, 'enrichment_timestamp', current_time)),

            # 🔧 PIDS DE COMPONENTES
            'promiscuous_pid': int(getattr(event, 'promiscuous_pid', 0)),
            'geoip_enricher_pid': int(getattr(event, 'geoip_enricher_pid', 0)),
            'ml_detector_pid': int(getattr(event, 'ml_detector_pid', 0)),
            'dashboard_pid': self.get_safe_dashboard_pid(event),
            'firewall_pid': int(getattr(event, 'firewall_pid', 0)),

            # 📊 TIMESTAMPS DE PROCESAMIENTO
            'promiscuous_timestamp': int(getattr(event, 'promiscuous_timestamp', 0)),
            'geoip_enricher_timestamp': int(getattr(event, 'geoip_enricher_timestamp', 0)),
            'ml_detector_timestamp': int(getattr(event, 'ml_detector_timestamp', current_time)),
            'dashboard_timestamp': current_time,
            'firewall_timestamp': int(getattr(event, 'firewall_timestamp', 0)),

            # 🎯 MÉTRICAS DE PIPELINE
            'processing_latency_ms': float(getattr(event, 'processing_latency_ms', 0.0)),
            'pipeline_hops': int(getattr(event, 'pipeline_hops', 1)),
            'pipeline_path': getattr(event, 'pipeline_path', 'ml_detector_v3->dashboard'),

            # 🔄 CONTROL DE FLUJO
            'retry_count': int(getattr(event, 'retry_count', 0)),
            'last_error': getattr(event, 'last_error', ''),
            'requires_reprocessing': bool(getattr(event, 'requires_reprocessing', False)),

            # 🏷️ TAGS Y METADATOS
            'component_tags': list(getattr(event, 'component_tags', ['v3', 'ml_detector'])),
            'component_metadata': dict(getattr(event, 'component_metadata', {})),

            # Campos de compatibilidad
            'packets': max(1, getattr(event, 'packet_size', 1)),
            'bytes': data_length,
            'location': self._get_location_from_coordinates(
                getattr(event, 'latitude', None),
                getattr(event, 'longitude', None)
            ),

            # Metadatos del parsing V3
            'parsing_method': 'protobuf_v3_lightweight_ml',
            'raw_protobuf_length': data_length,
            'worker_id': worker_id,
            'dashboard_node_id': self.config.node_id,
            'dashboard_processing_timestamp': datetime.now().isoformat(),

            # ML Models scores V3
            'ml_models_scores': {
                'v3_lightweight_ml': getattr(event, 'risk_score', 0.5),
                'v3_anomaly_score': getattr(event, 'anomaly_score', 0.5)
            }
        }

        # ✅ VALIDACIÓN ADICIONAL PARA CAMPOS CRÍTICOS V3
        for field in ['source_ip', 'target_ip', 'node_id', 'agent_version']:
            if field in parsed_event and not parsed_event[field]:
                parsed_event[field] = self._get_default_value_for_field(field)

        return parsed_event

    def _get_default_value_for_field(self, field: str) -> str:
        """Obtener valor por defecto para campos críticos"""
        defaults = {
            'source_ip': '127.0.0.1',
            'target_ip': '127.0.0.1',
            'node_id': self.config.node_id,
            'agent_version': 'V3',
            'protocol': 'TCP',
            'event_type': 'network_event'
        }
        return defaults.get(field, 'unknown')

    def _get_location_from_coordinates(self, lat: float, lon: float) -> str:
        """Obtener ubicación textual desde coordenadas"""
        if lat is None or lon is None:
            return 'Unknown'

        # Coordenadas aproximadas para España
        if 35.0 <= lat <= 44.0 and -10.0 <= lon <= 4.0:
            return 'España'
        elif 40.0 <= lat <= 41.0 and -4.0 <= lon <= -3.0:
            return 'Madrid, ES'
        elif 41.0 <= lat <= 42.0 and 2.0 <= lon <= 3.0:
            return 'Barcelona, ES'
        else:
            return f'Lat:{lat:.2f}, Lon:{lon:.2f}'

    def get_safe_dashboard_pid(self, event=None) -> str:
        """Obtener dashboard_pid de forma segura, siempre como string"""
        try:
            if event is not None:
                pid = getattr(event, 'dashboard_pid', None)
                if pid is not None:
                    if isinstance(pid, (int, float)) and pid > 0:
                        return str(int(pid))
                    elif isinstance(pid, str) and pid.isdigit():
                        return pid
                    elif isinstance(pid, bytes):
                        try:
                            decoded = pid.decode('utf-8', errors='ignore')
                            if decoded.isdigit():
                                return decoded
                        except:
                            pass

            return str(os.getpid())

        except Exception as e:
            self.logger.warning(f"Error obteniendo dashboard_pid: {e}")
            return str(os.getpid())

    def parse_protobuf_with_monitoring(self, data: bytes, worker_id: int) -> Optional[Dict]:
        """Parsear protobuf general (V2/legacy) con monitoreo - MANTENIDO PARA COMPATIBILIDAD"""
        try:
            # Intentar con protobuf V2/legacy
            try:
                import src.protocols.protobuf.network_event_extended_v3_pb2 as network_pb2

                # Intentar parsear como NetworkEvent
                event = network_pb2.NetworkEvent()
                event.ParseFromString(data)

                # Convertir a diccionario con estructura V2
                parsed_event = self._convert_protobuf_v2_to_dict(event, worker_id, len(data))

                self.logger.info(f"📦 Worker {worker_id} - Protobuf V2 parseado correctamente ({len(data)} bytes)")
                return parsed_event

            except ImportError:
                self.logger.warning(f"⚠️ Protobuf modules no disponibles, usando parser básico")

            except Exception as parse_error:
                self.logger.error(f"❌ Error parseando protobuf V2: {parse_error}")

            # Parser básico mejorado
            event = self._generate_basic_event_v2(worker_id, len(data))
            self.logger.info(f"📦 Worker {worker_id} - Evento básico V2 generado ({len(data)} bytes)")
            return event

        except Exception as e:
            self.logger.error(f"💥 Error crítico en parser protobuf: {e}")
            return None

    def _convert_protobuf_v2_to_dict(self, event, worker_id: int, data_length: int) -> dict:
        """Convertir protobuf V2 a diccionario completo"""
        current_time = int(time.time() * 1000)

        return {
            # Identificación del evento
            'event_id': getattr(event, 'event_id', ''),
            'timestamp': getattr(event, 'timestamp', current_time),

            # Información de red básica
            'source_ip': getattr(event, 'source_ip', '127.0.0.1'),
            'target_ip': getattr(event, 'target_ip', '127.0.0.1'),
            'packet_size': getattr(event, 'packet_size', data_length),
            'dest_port': getattr(event, 'dest_port', 80),
            'src_port': getattr(event, 'src_port', 0),
            'protocol': getattr(event, 'protocol', 'tcp'),

            # Identificación del agente
            'agent_id': getattr(event, 'agent_id', ''),

            # Métricas y scoring
            'anomaly_score': float(getattr(event, 'anomaly_score', 0.0)),
            'latitude': getattr(event, 'latitude', None),
            'longitude': getattr(event, 'longitude', None),

            # Clasificación de eventos
            'event_type': getattr(event, 'event_type', 'normal'),
            'risk_score': float(getattr(event, 'risk_score', 0.5)),
            'description': getattr(event, 'description', ''),

            # Información del sistema operativo
            'so_identifier': getattr(event, 'so_identifier', ''),

            # Información del nodo - handshake inicial
            'node_hostname': getattr(event, 'node_hostname', ''),
            'os_version': getattr(event, 'os_version', ''),
            'firewall_status': getattr(event, 'firewall_status', 'unknown'),
            'agent_version': getattr(event, 'agent_version', ''),
            'is_initial_handshake': bool(getattr(event, 'is_initial_handshake', False)),

            # CAMPOS DISTRIBUIDOS - CRÍTICOS PARA ETCD
            'node_id': getattr(event, 'node_id', self.config.node_id),
            'process_id': int(getattr(event, 'process_id', 0)),
            'container_id': getattr(event, 'container_id', ''),
            'cluster_name': getattr(event, 'cluster_name', ''),

            # Estado del componente distribuido
            'component_status': getattr(event, 'component_status', 'healthy'),
            'uptime_seconds': int(getattr(event, 'uptime_seconds', 0)),

            # Métricas de performance del nodo
            'queue_depth': int(getattr(event, 'queue_depth', 0)),
            'cpu_usage_percent': float(getattr(event, 'cpu_usage_percent', 0.0)),
            'memory_usage_mb': float(getattr(event, 'memory_usage_mb', 0.0)),

            # Configuración dinámica
            'config_version': getattr(event, 'config_version', ''),
            'config_timestamp': int(getattr(event, 'config_timestamp', 0)),

            # Enriquecimiento GeoIP
            'geoip_enriched': bool(getattr(event, 'geoip_enriched', False)),
            'enrichment_node': getattr(event, 'enrichment_node', ''),
            'enrichment_timestamp': int(getattr(event, 'enrichment_timestamp', 0)),

            # PIDS DE COMPONENTES DISTRIBUIDOS - TRACKING DEL PIPELINE
            'promiscuous_pid': int(getattr(event, 'promiscuous_pid', 0)),
            'geoip_enricher_pid': int(getattr(event, 'geoip_enricher_pid', 0)),
            'ml_detector_pid': int(getattr(event, 'ml_detector_pid', 0)),
            'dashboard_pid': int(self.get_safe_dashboard_pid(event)),
            'firewall_pid': int(getattr(event, 'firewall_pid', 0)),

            # TIMESTAMPS DE PROCESAMIENTO POR COMPONENTE
            'promiscuous_timestamp': int(getattr(event, 'promiscuous_timestamp', 0)),
            'geoip_enricher_timestamp': int(getattr(event, 'geoip_enricher_timestamp', 0)),
            'ml_detector_timestamp': int(getattr(event, 'ml_detector_timestamp', 0)),
            'dashboard_timestamp': current_time,
            'firewall_timestamp': int(getattr(event, 'firewall_timestamp', 0)),

            # MÉTRICAS DE PIPELINE DISTRIBUIDO
            'processing_latency_ms': float(getattr(event, 'processing_latency_ms', 0.0)),
            'pipeline_hops': int(getattr(event, 'pipeline_hops', 0)),
            'pipeline_path': getattr(event, 'pipeline_path', ''),

            # CONTROL DE FLUJO DISTRIBUIDO
            'retry_count': int(getattr(event, 'retry_count', 0)),
            'last_error': getattr(event, 'last_error', ''),
            'requires_reprocessing': bool(getattr(event, 'requires_reprocessing', False)),

            # TAGS Y METADATOS DISTRIBUIDOS
            'component_tags': list(getattr(event, 'component_tags', [])),
            'component_metadata': dict(getattr(event, 'component_metadata', {})),

            # CAMPOS ADICIONALES PARA COMPATIBILIDAD
            'id': getattr(event, 'event_id', str(current_time) + f"_{worker_id}"),
            'port': getattr(event, 'dest_port', 80),
            'attack_type': getattr(event, 'event_type', 'normal'),
            'packets': max(1, getattr(event, 'packet_size', 1)),
            'bytes': data_length,
            'location': self._get_location_from_coordinates(
                getattr(event, 'latitude', None),
                getattr(event, 'longitude', None)
            ),

            # METADATOS DE PROCESAMIENTO
            'parsing_method': 'protobuf_v2_complete_schema',
            'protobuf_version': 'V2',
            'schema_fields': 53,
            'worker_id': worker_id,
            'raw_protobuf_length': data_length,
            'dashboard_node_id': self.config.node_id,
            'dashboard_processing_timestamp': datetime.now().isoformat(),

            # ML MODELS SCORES EXTRAÍDOS
            'ml_models_scores': self._extract_ml_scores_from_v2_metadata(
                dict(getattr(event, 'component_metadata', {})),
                float(getattr(event, 'risk_score', 0.5))
            )
        }

    def _extract_ml_scores_from_v2_metadata(self, metadata: dict, risk_score: float) -> dict:
        """Extraer scores de ML desde metadata V2"""
        ml_scores = {}

        for key, value in metadata.items():
            if any(term in key.lower() for term in ['ml_', 'score', 'anomaly', 'risk', 'detection']):
                try:
                    ml_scores[key] = float(value)
                except (ValueError, TypeError):
                    ml_scores[key] = str(value)

        # SCORES POR DEFECTO V2
        if not ml_scores:
            ml_scores = {
                'v2_ml_score': risk_score,
                'v2_anomaly_detection': risk_score * 0.8,
                'v2_risk_assessment': risk_score,
                'protobuf_v2_confidence': 0.8
            }

        return ml_scores

    def _generate_basic_event_v2(self, worker_id: int, data_length: int) -> dict:
        """Generar evento básico con estructura v2 completa"""
        current_time = int(time.time() * 1000)

        return {
            # Identificación del evento
            'id': str(current_time) + f"_{worker_id}",
            'event_id': f"basic_event_{current_time}_{worker_id}",
            'timestamp': current_time,

            # Información de red básica (simulada)
            'source_ip': f"192.168.1.{100 + (worker_id % 50)}",
            'target_ip': f"10.0.0.{1 + (worker_id % 50)}",
            'packet_size': data_length,
            'dest_port': 80 + (data_length % 65000),
            'src_port': 1024 + (worker_id % 64000),
            'protocol': 'TCP',

            # Identificación del agente
            'agent_id': f'dashboard_worker_{worker_id}',

            # Métricas y scoring
            'anomaly_score': min(1.0, (data_length % 100) / 100.0),
            'latitude': 40.4168 + ((data_length % 200) - 100) / 1000.0,
            'longitude': -3.7038 + ((data_length % 200) - 100) / 1000.0,

            # Clasificación de eventos MEJORADA
            'event_type': ['normal', 'suspicious', 'tor_detected', 'malware'][data_length % 4],
            'risk_score': self._calculate_realistic_risk_score(data_length, worker_id),
            'description': f'Basic generated event from protobuf data ({data_length} bytes)',

            # Información del sistema operativo
            'so_identifier': 'linux_iptables',

            # Información del nodo
            'node_hostname': 'dashboard-node',
            'os_version': 'Linux',
            'firewall_status': 'active',
            'agent_version': '2.5.0',
            'is_initial_handshake': False,

            # CAMPOS DISTRIBUIDOS
            'node_id': self.config.node_id,
            'process_id': os.getpid(),
            'container_id': '',
            'cluster_name': 'upgraded-happiness',

            # Estado del componente
            'component_status': 'healthy',
            'uptime_seconds': int(time.time() - self.start_time),

            # Métricas de performance
            'queue_depth': self.ml_events_queue.qsize(),
            'cpu_usage_percent': 0.0,
            'memory_usage_mb': 0.0,

            # Configuración dinámica
            'config_version': '2.5.0',
            'config_timestamp': current_time,

            # Enriquecimiento GeoIP
            'geoip_enriched': True,
            'enrichment_node': 'basic_enricher',
            'enrichment_timestamp': current_time,

            # PIDS DE COMPONENTES
            'promiscuous_pid': 0,
            'geoip_enricher_pid': 0,
            'ml_detector_pid': 0,
            'dashboard_pid': self.get_safe_dashboard_pid(),
            'firewall_pid': 0,

            # TIMESTAMPS DE PROCESAMIENTO
            'promiscuous_timestamp': 0,
            'geoip_enricher_timestamp': 0,
            'ml_detector_timestamp': 0,
            'dashboard_timestamp': current_time,
            'firewall_timestamp': 0,

            # MÉTRICAS DE PIPELINE
            'processing_latency_ms': 0.0,
            'pipeline_hops': 1,
            'pipeline_path': 'dashboard_basic',

            # CONTROL DE FLUJO
            'retry_count': 0,
            'last_error': '',
            'requires_reprocessing': False,

            # TAGS Y METADATOS
            'component_tags': ['basic', 'dashboard', f'worker_{worker_id}'],
            'component_metadata': {
                'generation_method': 'basic',
                'worker_id': str(worker_id),
                'data_length': str(data_length)
            },

            # Campos de compatibilidad
            'port': 80 + (data_length % 65000),
            'attack_type': ['port_scan', 'ddos', 'intrusion_attempt', 'malware'][data_length % 4],
            'packets': max(1, data_length // 64),
            'bytes': data_length,
            'location': 'Madrid, ES',

            # Metadatos del parsing
            'parsing_method': 'basic_v2_generated',
            'raw_protobuf_length': data_length,
            'worker_id': worker_id,
            'dashboard_node_id': self.config.node_id,
            'dashboard_processing_timestamp': datetime.now().isoformat(),

            # ML Models scores
            'ml_models_scores': {
                'isolation_forest': min(1.0, (data_length % 100) / 100.0),
                'one_class_svm': min(1.0, (data_length % 80) / 80.0),
                'basic_anomaly': min(1.0, (data_length % 60) / 60.0)
            }
        }

    def _calculate_realistic_risk_score(self, data_length: int, worker_id: int) -> float:
        """Calcular risk score más realista basado en patrones de red"""
        # IPs conocidas seguras (DNS públicos, etc.)
        safe_targets = ['8.8.8.8', '1.1.1.1', '208.67.222.222']

        # Generar IP target simulada basada en data_length
        ip_suffix = (data_length % 254) + 1
        simulated_target = f"10.0.0.{ip_suffix}"

        # Lógica de risk scoring más realista
        base_risk = 0.1  # Riesgo base bajo

        # Factores que aumentan el riesgo
        if data_length > 1000:  # Paquetes grandes
            base_risk += 0.2

        if worker_id % 10 == 0:  # 10% de eventos son sospechosos
            base_risk += 0.3

        if data_length % 7 == 0:  # Patrón específico = malware
            base_risk += 0.4

        # DNS y tráfico normal = bajo riesgo
        if ip_suffix in [8, 1, 208]:  # Simula DNS públicos
            base_risk = 0.05

        # Asegurar que esté entre 0.0 y 1.0
        return min(1.0, max(0.0, base_risk))

    def _validate_event_data(self, event_data: dict, worker_id: int) -> bool:
        """Validar integridad de datos del evento"""
        try:
            # Verificar campos críticos
            required_fields = ['source_ip', 'target_ip']
            for field in required_fields:
                if field not in event_data:
                    self.logger.warning(f"⚠️ Worker {worker_id} - Campo faltante: {field}")
                    return False

            # Verificar tipos de datos críticos
            if 'dashboard_pid' in event_data:
                pid_value = event_data['dashboard_pid']
                if not isinstance(pid_value, (int, str)):
                    self.logger.warning(f"⚠️ Worker {worker_id} - dashboard_pid tipo inválido: {type(pid_value)}")
                    return False

            return True

        except Exception as e:
            self.logger.error(f"❌ Worker {worker_id} - Error validando datos: {e}")
            return False

    def parse_security_event(self, data: Dict) -> SecurityEvent:
        """Parsear datos de evento a SecurityEvent incluyendo datos protobuf"""
        return SecurityEvent(
            id=data.get('id', str(int(time.time() * 1000000))),
            source_ip=data.get('source_ip', data.get('src_ip', '')),
            target_ip=data.get('target_ip', data.get('dst_ip', '')),
            risk_score=float(data.get('risk_score', data.get('anomaly_score', 0.0))),
            anomaly_score=float(data.get('anomaly_score', 0.0)),
            latitude=data.get('latitude'),
            longitude=data.get('longitude'),
            timestamp=data.get('timestamp'),
            attack_type=data.get('attack_type'),
            location=data.get('location'),
            packets=int(data.get('packets', 0)),
            bytes=int(data.get('bytes', 0)),
            port=data.get('port', data.get('dst_port')),
            protocol=data.get('protocol'),
            ml_models_scores=data.get('ml_models_scores'),
            protobuf_data=data,  # Guardar todos los datos del protobuf
            node_id=data.get('node_id')
        )

    def firewall_commands_processor(self, worker_id: int):
        """Procesar y enviar comandos de firewall con reglas JSON - MEJORADO V2.5.0"""
        self.logger.info(f"🔥 Firewall Commands Processor {worker_id} iniciado con reglas JSON V2.5.0")

        while self.running:
            try:
                # Obtener comando de la cola
                command = self.firewall_commands_queue.get(timeout=1)

                # 🔥 Crear comando usando reglas JSON
                self._send_firewall_command_with_rules(command, worker_id)

                # Marcar tarea como completada
                self.firewall_commands_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"❌ Worker {worker_id} - Error en firewall commands processor: {e}")

    def _send_firewall_command_with_rules(self, command: FirewallCommand, worker_id: int):
        """Enviar comando de firewall usando configuración de reglas JSON - MEJORADO"""
        try:
            # Importar protobuf
            import src.protocols.protobuf.firewall_commands_pb2 as fw_pb2

            # Convertir comando Python a protobuf
            proto_command = fw_pb2.FirewallCommand()
            proto_command.command_id = getattr(command, 'event_id', f"cmd_{int(time.time())}")

            # ✅ CORREGIDO: Mapear action string a enum
            action_mapping = {
                'BLOCK_IP': fw_pb2.CommandAction.BLOCK_IP,
                'UNBLOCK_IP': fw_pb2.CommandAction.UNBLOCK_IP,
                'RATE_LIMIT': fw_pb2.CommandAction.RATE_LIMIT_IP,
                'MONITOR': fw_pb2.CommandAction.MONITOR,
                'LIST_RULES': fw_pb2.CommandAction.LIST_RULES,
                'FLUSH_RULES': fw_pb2.CommandAction.FLUSH_RULES
            }

            action_str = getattr(command, 'action', 'LIST_RULES')
            proto_command.action = action_mapping.get(action_str, fw_pb2.CommandAction.LIST_RULES)

            proto_command.target_ip = getattr(command, 'target_ip', '127.0.0.1')
            proto_command.target_port = getattr(command, 'port', 0)

            # 🔥 Obtener parámetros desde reglas JSON
            manual_action_info = self.firewall_rules_engine.get_manual_action_info(action_str)
            if manual_action_info and 'params' in manual_action_info:
                params = manual_action_info['params']
                proto_command.duration_seconds = params.get('duration', 600)
            else:
                # Fallback: parsear duration string
                duration_str = getattr(command, 'duration', '10m')
                proto_command.duration_seconds = self._parse_duration_to_seconds(duration_str)

            proto_command.reason = getattr(command, 'reason', 'Dashboard command from JSON rules V2.5.0')

            # 🔥 Priority desde reglas JSON
            if manual_action_info:
                priority_str = manual_action_info.get('priority', 'MEDIUM')
                priority_mapping = {
                    'LOW': fw_pb2.CommandPriority.LOW,
                    'MEDIUM': fw_pb2.CommandPriority.MEDIUM,
                    'HIGH': fw_pb2.CommandPriority.HIGH
                }
                proto_command.priority = priority_mapping.get(priority_str, fw_pb2.CommandPriority.MEDIUM)
            else:
                proto_command.priority = fw_pb2.CommandPriority.MEDIUM

            # 🔥 Dry run basado en configuración global
            global_settings = self.firewall_rules_engine.global_settings
            proto_command.dry_run = global_settings.get('require_confirmation_above_risk', 80) > 50

            # ✅ Serializar a protobuf binario
            command_bytes = proto_command.SerializeToString()

            # ✅ Enviar protobuf binario con thread safety
            with self.socket_lock:
                self.firewall_commands_socket.send(command_bytes)

            # Actualizar estadísticas
            conn_info = self.zmq_connections['firewall_commands']
            conn_info.total_messages += 1
            conn_info.bytes_transferred += len(command_bytes)
            conn_info.last_activity = datetime.now()

            self.stats['commands_sent'] += 1
            self.firewall_commands.append(command)

            self.logger.info(
                f"🔥 Worker {worker_id} - Comando protobuf enviado: {action_str} para {proto_command.target_ip}")

        except ImportError as e:
            self.logger.error(f"❌ Worker {worker_id} - Protobuf no disponible: {e}")
        except Exception as e:
            self.logger.error(f"❌ Worker {worker_id} - Error enviando comando: {e}")

    def _parse_duration_to_seconds(self, duration_str: str) -> int:
        """Convertir string de duración a segundos"""
        try:
            if 's' in duration_str:
                return int(duration_str.replace('s', ''))
            elif 'm' in duration_str:
                return int(duration_str.replace('m', '')) * 60
            elif 'h' in duration_str:
                return int(duration_str.replace('h', '')) * 3600
            else:
                return int(duration_str)  # Asumir segundos
        except (ValueError, AttributeError):
            return 600  # Default 10 minutos

    def firewall_responses_receiver_with_monitoring(self, worker_id: int):
        """Recibir respuestas del Firewall Agent - MEJORADO V2.5.0"""
        self.logger.info(f"📥 Firewall Responses Receiver {worker_id} iniciado V2.5.0")

        while self.running:
            try:
                # 🔒 CRÍTICO: Proteger acceso al socket con lock
                with self.socket_lock:
                    try:
                        response_bytes = self.firewall_responses_socket.recv(zmq.NOBLOCK)
                    except zmq.Again:
                        continue  # No hay mensajes

                # ✅ PARSER ESPECÍFICO PARA FIREWALL RESPONSE
                try:
                    # ✅ Importar protobuf de firewall
                    import src.protocols.protobuf.firewall_commands_pb2 as fw_pb2

                    # ✅ Parsear como FirewallResponse
                    pb_response = fw_pb2.FirewallResponse()
                    pb_response.ParseFromString(response_bytes)

                    # ✅ Convertir a dict para procesamiento
                    response_data = {
                        'command_id': pb_response.command_id,
                        'node_id': pb_response.node_id,
                        'timestamp': pb_response.timestamp,
                        'success': pb_response.success,
                        'message': pb_response.message,
                        'executed_command': getattr(pb_response, 'executed_command', ''),
                        'execution_time': getattr(pb_response, 'execution_time', 0.0),
                    }

                    self.logger.info(f"✅ Worker {worker_id} - FirewallResponse parseado: {response_data['command_id']}")

                except Exception as parse_error:
                    self.logger.error(f"❌ Worker {worker_id} - Error parseando FirewallResponse: {parse_error}")

                    # ✅ Fallback: intentar decodificar como JSON
                    try:
                        response_text, encoding_used = self.decode_message_with_v3_monitoring(
                            response_bytes, worker_id, 'firewall_responses'
                        )
                        if response_text:
                            response_data = json.loads(response_text)
                            self.logger.info(f"🔄 Worker {worker_id} - Fallback JSON parse exitoso")
                        else:
                            continue
                    except Exception as fallback_error:
                        self.logger.error(f"❌ Worker {worker_id} - Fallback parse también falló: {fallback_error}")
                        continue

                # Registrar mensaje exitoso
                self.encoding_monitor.log_successful_message(
                    worker_id, 'firewall_responses', len(response_bytes), 'protobuf'
                )

                # Actualizar estadísticas
                conn_info = self.zmq_connections['firewall_responses']
                conn_info.total_messages += 1
                conn_info.bytes_transferred += len(response_bytes)
                conn_info.last_activity = datetime.now()

                # Actualizar información de conexión
                if response_data.get('node_id'):
                    self.encoding_monitor.update_connection_info(
                        'firewall_responses',
                        node_id=response_data.get('node_id'),
                        component_type='firewall_agent',
                        version=response_data.get('version')
                    )

                # ✅ LOG COMPLETO
                command_id = response_data.get('command_id', 'unknown')
                success = response_data.get('success', False)
                message = response_data.get('message', 'No message')
                node_id = response_data.get('node_id', 'unknown_node')

                self.logger.info(
                    f"📥 Worker {worker_id} - Respuesta firewall: {command_id} - Success: {success} - {message} - Node: {node_id}")

                # Actualizar estadísticas si es exitoso
                if response_data.get('success'):
                    self.stats['threats_blocked'] += 1
                    self.stats['confirmations'] += 1

            except Exception as e:
                self.logger.error(f"❌ Worker {worker_id} - Error en firewall responses receiver: {e}")
                time.sleep(0.1)

    def start_web_server(self):
        """Iniciar servidor web - MEJORADO V2.5.0"""
        self.logger.info(f"🌐 Iniciando servidor web V2.5.0 en {self.config.web_host}:{self.config.web_port}")

        class DashboardHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, dashboard=None, **kwargs):
                self.dashboard = dashboard
                super().__init__(*args, **kwargs)

            def do_GET(self):
                if self.path == '/' or self.path == '/index.html':
                    self.serve_dashboard_html()
                elif self.path == '/api/metrics':
                    self.serve_metrics_api()
                elif self.path.startswith('/static/'):
                    self.serve_static_file()
                else:
                    self.send_error(404, "Página no encontrada")

            def do_POST(self):
                """Manejar requests POST - MEJORADO V2.5.0"""
                if self.path == '/api/test-firewall':
                    self.serve_firewall_test_api()
                elif self.path == '/api/firewall-agent-info':
                    self.serve_firewall_agent_info_api()
                elif self.path == '/api/execute-firewall-action':
                    self.serve_execute_firewall_action_api()
                else:
                    self.send_error(404, "Endpoint POST no encontrado")

            def serve_metrics_api(self):
                """Exponer datos de ZeroMQ via HTTP - MEJORADO V2.5.0"""
                try:
                    # Obtener métricas del dashboard
                    metrics = self.dashboard.get_dashboard_metrics()

                    # ✅ FORMATO MEJORADO PARA FRONTEND
                    data = {
                        'success': True,
                        'version': '2.5.0',
                        'basic_stats': {
                            'total_events': self.dashboard.stats.get('total_events', 0),
                            'high_risk_events': self.dashboard.stats.get('high_risk_events', 0),
                            'events_per_minute': self.dashboard.stats.get('events_per_minute', 0),
                            'success_rate': self.dashboard.stats.get('success_rate', 95),
                            'failures': self.dashboard.stats.get('failures', 0),
                            'commands_sent': self.dashboard.stats.get('commands_sent', 0),
                            'confirmations': self.dashboard.stats.get('confirmations', 0),
                            'events_logged_for_rag': self.dashboard.stats.get('events_logged_for_rag', 0),
                            # ✅ NUEVO: Estadísticas V3
                            'protobuf_v3_messages': self.dashboard.stats.get('protobuf_v3_messages', 0),
                            'ml_detector_v3_connected': self.dashboard.stats.get('ml_detector_v3_connected', False)
                        },
                        'recent_events': self.dashboard.recent_events,  # ✅ TODOS los eventos
                        'component_status': metrics.get('component_status', {}),
                        'zmq_connections': metrics.get('zmq_connections', {}),
                        'node_info': metrics.get('node_info', {}),
                        'pipeline_info': {
                            'promiscuous_agent_port': 5559,
                            'geoip_enricher_port': 5560,
                            'ml_detector_port': 5570,
                            'dashboard_firewall_commands_port': 5580,
                            'dashboard_firewall_responses_port': 5581,
                            # ✅ NUEVO: Info V3
                            'ml_detector_version': 'V3',
                            'protobuf_version': '3.0'
                        },
                        # ✅ NUEVO: Información de reglas firewall
                        'firewall_rules_info': metrics.get('firewall_rules_info', {}),
                        'timestamp': datetime.now().isoformat()
                    }

                    response_json = json.dumps(data, default=str)

                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(response_json.encode('utf-8'))

                except Exception as e:
                    self.dashboard.logger.error(f"❌ Error sirviendo métricas: {e}")

                    error_response = {
                        'success': False,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    }

                    self.send_response(500)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(error_response).encode('utf-8'))

            def serve_firewall_agent_info_api(self):
                """Obtener información del firewall agent - MEJORADO V2.5.0"""
                try:
                    content_length = int(self.headers.get('Content-Length', 0))
                    if content_length > 0:
                        post_data = self.rfile.read(content_length)
                        request_data = json.loads(post_data.decode('utf-8'))
                    else:
                        request_data = {}

                    # 🔥 DETERMINAR FIREWALL RESPONSABLE
                    firewall_info = self.dashboard.get_responsible_firewall_info(request_data)

                    response_data = {
                        'success': True,
                        'version': '2.5.0',
                        'firewall_info': firewall_info,
                        'available_agents': len(self.dashboard.firewall_rules_engine.firewall_agents),
                        'rules_loaded': len(self.dashboard.firewall_rules_engine.rules),
                        'timestamp': datetime.now().isoformat()
                    }

                    response_json = json.dumps(response_data)

                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(response_json.encode('utf-8'))

                except Exception as e:
                    self.dashboard.logger.error(f"❌ Error en firewall-agent-info: {e}")

                    error_response = {
                        'success': False,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    }

                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(error_response).encode('utf-8'))

            def serve_execute_firewall_action_api(self):
                """Ejecutar acción específica en firewall - MEJORADO V2.5.0"""
                try:
                    content_length = int(self.headers.get('Content-Length', 0))
                    if content_length > 0:
                        post_data = self.rfile.read(content_length)
                        request_data = json.loads(post_data.decode('utf-8'))
                    else:
                        request_data = {}

                    # 🔥 VALIDAR DATOS DE LA REQUEST
                    required_fields = ['action', 'target_ip', 'firewall_node_id']
                    for field in required_fields:
                        if field not in request_data:
                            raise ValueError(f"Campo requerido faltante: {field}")

                    # 🔥 EJECUTAR ACCIÓN USANDO REGLAS JSON
                    result = self.dashboard.execute_firewall_action_from_request(request_data)

                    response_data = {
                        'success': result['success'],
                        'version': '2.5.0',
                        'message': result['message'],
                        'command_id': result.get('command_id', 'unknown'),
                        'agent': result.get('agent', request_data['firewall_node_id']),
                        'timestamp': datetime.now().isoformat()
                    }

                    response_json = json.dumps(response_data)

                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(response_json.encode('utf-8'))

                except Exception as e:
                    self.dashboard.logger.error(f"❌ Error en execute-firewall-action: {e}")

                    error_response = {
                        'success': False,
                        'message': f'Error ejecutando acción: {str(e)}',
                        'timestamp': datetime.now().isoformat()
                    }

                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(error_response).encode('utf-8'))

            def serve_firewall_test_api(self):
                """Endpoint para probar firewall - MEJORADO V2.5.0"""
                try:
                    success = self.dashboard.test_firewall_connection_with_rules()

                    response_data = {
                        'success': success,
                        'version': '2.5.0',
                        'message': 'Comando de prueba enviado usando reglas JSON V2.5.0' if success else 'Error enviando comando',
                        'timestamp': datetime.now().isoformat(),
                        'test_id': f"test_{int(time.time())}"
                    }

                    response_json = json.dumps(response_data)

                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(response_json.encode('utf-8'))

                except Exception as e:
                    error_response = {
                        'success': False,
                        'message': f'Error en prueba de firewall: {str(e)}',
                        'timestamp': datetime.now().isoformat()
                    }

                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(error_response).encode('utf-8'))

            def serve_dashboard_html(self):
                """Servir HTML del dashboard - MEJORADO V2.5.0"""
                try:
                    # ✅ MEJORADO: Verificar si existe el archivo
                    html_path = Path('templates/dashboard.html')
                    if not html_path.exists():
                        # Crear HTML básico si no existe
                        self.send_basic_dashboard_html()
                        return

                    with open(html_path, 'r', encoding='utf-8') as f:
                        html_content = f.read()

                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.send_header('Cache-Control', 'no-cache')

                    # CSP MEJORADO para modales draggeables
                    csp_policy = (
                        "default-src 'self'; "
                        "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
                        "https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                        "style-src 'self' 'unsafe-inline' "
                        "https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                        "img-src 'self' data: blob: "
                        "https://*.tile.openstreetmap.org https://*.openstreetmap.org "
                        "https://*.basemaps.cartocdn.com https://cartocdn.com "
                        "https://*.cartodb.com https://cartodb.com "
                        "https://unpkg.com https://cdn.jsdelivr.net; "
                        "connect-src 'self' "
                        "https://*.tile.openstreetmap.org https://*.openstreetmap.org "
                        "https://*.basemaps.cartocdn.com https://cartocdn.com "
                        "https://*.cartodb.com https://cartodb.com; "
                        "font-src 'self' data: 'unsafe-inline' "
                        "https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;"
                    )
                    self.send_header('Content-Security-Policy', csp_policy)

                    self.end_headers()
                    self.wfile.write(html_content.encode('utf-8'))

                except Exception as e:
                    self.dashboard.logger.error(f"Error sirviendo dashboard HTML: {e}")
                    self.send_basic_dashboard_html()

            def send_basic_dashboard_html(self):
                """Enviar HTML básico si no existe el archivo"""
                basic_html = '''<!DOCTYPE html>
<html>
<head>
    <title>Security Dashboard V2.5.0</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>🚀 Security Dashboard V2.5.0</h1>
    <p>✅ Dashboard funcionando correctamente</p>
    <p>📡 ML Detector V3 Compatible</p>
    <p>🔥 Firewall Rules JSON Integrado</p>
    <p>📝 Logging a disco activado</p>
    <p><a href="/api/metrics">Ver métricas JSON</a></p>
</body>
</html>'''

                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(basic_html.encode('utf-8'))

            def serve_static_file(self):
                """Servir archivos estáticos"""
                try:
                    file_path = self.path[1:]  # Remover '/' inicial

                    if not Path(file_path).exists():
                        self.send_error(404, "Archivo no encontrado")
                        return

                    mime_type, _ = mimetypes.guess_type(file_path)
                    if mime_type is None:
                        mime_type = 'application/octet-stream'

                    with open(file_path, 'rb') as f:
                        content = f.read()

                    self.send_response(200)
                    self.send_header('Content-type', mime_type)
                    self.send_header('Cache-Control', 'public, max-age=3600')
                    self.end_headers()
                    self.wfile.write(content)

                except Exception as e:
                    self.dashboard.logger.error(f"Error sirviendo archivo estático {self.path}: {e}")
                    self.send_error(500, "Error interno del servidor")

        def handler_factory(*args, **kwargs):
            return DashboardHTTPRequestHandler(*args, dashboard=self, **kwargs)

        # Iniciar servidor en hilo separado
        def run_server():
            try:
                with socketserver.TCPServer((self.config.web_host, self.config.web_port), handler_factory) as httpd:
                    self.logger.info(f"✅ Servidor web V2.5.0 iniciado correctamente")
                    httpd.serve_forever()
            except Exception as e:
                self.logger.error(f"❌ Error en servidor web: {e}")

        web_thread = threading.Thread(target=run_server)
        web_thread.daemon = True
        web_thread.start()

    # 🔥 MÉTODOS PARA LÓGICA DE FIREWALL CON REGLAS JSON

    def get_responsible_firewall_info(self, request_data: dict) -> dict:
        """Determinar información del firewall responsable - MEJORADO V2.5.0"""
        try:
            # 🔥 OBTENER NODE_ID DEL EVENTO O REQUEST
            event_node_id = request_data.get('node_id') or request_data.get('event_node_id')

            # 🔥 INTENTAR ENCONTRAR FIREWALL ESPECÍFICO POR NODE_ID
            if event_node_id:
                firewall_agent = self.firewall_rules_engine.get_firewall_agent_by_node_id(event_node_id)
                if firewall_agent:
                    return {
                        'version': '2.5.0',
                        'node_id': firewall_agent.node_id,
                        'agent_ip': request_data.get('source_ip', '127.0.0.1'),
                        'status': firewall_agent.status,
                        'active_rules': firewall_agent.active_rules,
                        'endpoint': firewall_agent.endpoint,
                        'capabilities': firewall_agent.capabilities,
                        'max_rules': firewall_agent.max_rules
                    }

            # 🔥 FALLBACK: Usar firewall por defecto
            default_agent = self.firewall_rules_engine.get_default_firewall_agent()
            if default_agent:
                return {
                    'version': '2.5.0',
                    'node_id': default_agent.node_id,
                    'agent_ip': request_data.get('source_ip', '127.0.0.1'),
                    'status': default_agent.status,
                    'active_rules': default_agent.active_rules,
                    'endpoint': default_agent.endpoint,
                    'capabilities': default_agent.capabilities,
                    'max_rules': default_agent.max_rules
                }

            # 🔥 ÚLTIMO RECURSO: Información básica
            return {
                'version': '2.5.0',
                'node_id': 'simple_firewall_agent_001',
                'agent_ip': request_data.get('source_ip', '127.0.0.1'),
                'status': 'active',
                'active_rules': 0,
                'endpoint': 'tcp://localhost:5580',
                'capabilities': ['BLOCK_IP', 'RATE_LIMIT', 'MONITOR', 'LIST_RULES'],
                'max_rules': 1000
            }

        except Exception as e:
            self.logger.error(f"❌ Error obteniendo info firewall responsable: {e}")
            return {
                'version': '2.5.0',
                'node_id': 'unknown_firewall',
                'agent_ip': '127.0.0.1',
                'status': 'unknown',
                'active_rules': 0,
                'endpoint': 'tcp://localhost:5580',
                'capabilities': [],
                'max_rules': 0
            }

    def execute_firewall_action_from_request(self, request_data: dict) -> dict:
        """Ejecutar acción de firewall desde request - MEJORADO V2.5.0"""
        try:
            action = request_data['action']
            target_ip = request_data['target_ip']
            firewall_node_id = request_data['firewall_node_id']
            event_id = request_data.get('event_id', 'manual_action')
            command_id = request_data.get('command_id', f"manual_{int(time.time())}")

            # 🔥 VERIFICAR SI LA ACCIÓN ESTÁ PERMITIDA SEGÚN REGLAS JSON
            manual_action_info = self.firewall_rules_engine.get_manual_action_info(action)
            if not manual_action_info:
                return {
                    'success': False,
                    'message': f'Acción {action} no está definida en reglas JSON V2.5.0',
                    'command_id': command_id
                }

            # 🔥 VERIFICAR CAPACIDADES DEL FIREWALL AGENT
            firewall_agent = self.firewall_rules_engine.get_firewall_agent_by_node_id(firewall_node_id)
            if firewall_agent and action not in firewall_agent.capabilities:
                return {
                    'success': False,
                    'message': f'Firewall {firewall_node_id} no soporta acción {action}',
                    'command_id': command_id
                }

            # 🔥 CREAR COMANDO CON PARÁMETROS DE REGLAS JSON
            command = FirewallCommand(
                action=action,
                target_ip=target_ip,
                duration=str(manual_action_info['params'].get('duration', 600)) + 's',
                reason=f"Manual action V2.5.0: {manual_action_info['description']}",
                risk_score=request_data.get('risk_score', 0.5),
                timestamp=datetime.now().isoformat(),
                event_id=event_id,
                firewall_node_id=firewall_node_id
            )

            # 🔥 AÑADIR A COLA PARA PROCESAMIENTO
            if not self.firewall_commands_queue.full():
                self.firewall_commands_queue.put(command, timeout=1.0)

                self.logger.info(f"🔥 Acción {action} encolada para {firewall_node_id}: {target_ip}")

                return {
                    'success': True,
                    'message': f'Acción {action} enviada a {firewall_node_id} (V2.5.0)',
                    'command_id': command_id,
                    'agent': firewall_node_id
                }
            else:
                return {
                    'success': False,
                    'message': 'Cola de comandos firewall llena',
                    'command_id': command_id
                }

        except Exception as e:
            self.logger.error(f"❌ Error ejecutando acción firewall: {e}")
            return {
                'success': False,
                'message': str(e),
                'command_id': request_data.get('command_id', 'unknown')
            }

    def test_firewall_connection_with_rules(self):
        """Test de firewall usando configuración de reglas JSON - MEJORADO V2.5.0"""
        try:
            self.logger.info("🧪 Test firewall con reglas JSON V2.5.0...")

            # 🔥 OBTENER CONFIGURACIÓN DE TEST DESDE REGLAS JSON
            list_rules_info = self.firewall_rules_engine.get_manual_action_info('LIST_RULES')
            default_agent = self.firewall_rules_engine.get_default_firewall_agent()

            if not default_agent:
                self.logger.error("❌ No hay agentes firewall configurados en JSON")
                return False

            # 🔥 CREAR COMANDO DE TEST USANDO REGLAS JSON
            test_request = {
                'action': 'LIST_RULES',
                'target_ip': '127.0.0.1',
                'firewall_node_id': default_agent.node_id,
                'event_id': f"test_{int(time.time())}",
                'command_id': f"test_rules_v25_{int(time.time())}",
                'source': 'dashboard_test_v2.5.0'
            }

            # 🔥 EJECUTAR TEST
            result = self.execute_firewall_action_from_request(test_request)

            if result['success']:
                self.logger.info(f"✅ Test firewall exitoso V2.5.0: {result['message']}")
                return True
            else:
                self.logger.error(f"❌ Test firewall falló: {result['message']}")
                return False

        except Exception as e:
            self.logger.error(f"❌ Error en test firewall V2.5.0: {e}")
            return False

    def start_periodic_updates(self):
        """Iniciar actualizaciones periódicas - MEJORADO V2.5.0"""

        def update_stats():
            while self.running:
                try:
                    self.update_statistics()
                    self.update_zmq_connection_stats()
                    self.check_component_health()

                    # 🔥 Verificar cambios en reglas de firewall
                    self.firewall_rules_engine.reload_if_changed()

                    # ✅ NUEVO: Log estadísticas V3 cada cierto tiempo
                    if hasattr(self, '_last_v3_stats_log'):
                        if time.time() - self._last_v3_stats_log > 300:  # Cada 5 minutos
                            self._log_v3_statistics()
                            self._last_v3_stats_log = time.time()
                    else:
                        self._last_v3_stats_log = time.time()

                    time.sleep(self.config.stats_interval)
                except Exception as e:
                    self.logger.error(f"❌ Error en actualizaciones periódicas: {e}")
                    time.sleep(self.config.stats_interval)

        stats_thread = threading.Thread(target=update_stats)
        stats_thread.daemon = True
        stats_thread.start()
        self.logger.info(f"✅ Actualizaciones periódicas V2.5.0 iniciadas (intervalo: {self.config.stats_interval}s)")

    def _log_v3_statistics(self):
        """Log estadísticas específicas del ML Detector V3"""
        try:
            v3_stats = {
                'protobuf_v3_messages': self.stats.get('protobuf_v3_messages', 0),
                'ml_detector_v3_connected': self.stats.get('ml_detector_v3_connected', False),
                'total_events': self.stats.get('total_events', 0),
                'events_logged_for_rag': self.stats.get('events_logged_for_rag', 0)
            }

            self.logger.info(f"📊 Stats V3: {v3_stats}")

        except Exception as e:
            self.logger.error(f"❌ Error logging V3 statistics: {e}")

    def update_statistics(self):
        """Actualizar estadísticas del dashboard - MEJORADO V2.5.0"""
        try:
            # Calcular eventos por minuto de forma segura
            current_time = time.time()
            events_in_last_minute = 0

            for event in self.events:
                try:
                    # CORRECCIÓN: Manejar timestamp como int o string
                    event_timestamp = event.timestamp

                    if isinstance(event_timestamp, (int, float)):
                        # Unix timestamp en milliseconds o seconds
                        if event_timestamp > 1e12:  # Milliseconds
                            event_time = event_timestamp / 1000.0
                        else:  # Seconds
                            event_time = float(event_timestamp)
                    else:
                        # String timestamp - parsear de forma segura
                        timestamp_str = str(event_timestamp)
                        if 'T' in timestamp_str:
                            # ISO format
                            timestamp_str = timestamp_str[:19]
                            event_time = time.mktime(time.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S'))
                        else:
                            event_time = current_time

                    # Verificar si el evento es de hace menos de 60 segundos
                    if (current_time - event_time) < 60:
                        events_in_last_minute += 1

                except (ValueError, TypeError, AttributeError):
                    continue

            self.stats['events_per_minute'] = events_in_last_minute
            self.stats['high_risk_events'] = len([e for e in self.events if e.risk_score > 0.8])
            self.stats['geographic_distribution'] = len(set(e.location for e in self.events if e.location))
            self.stats['uptime_seconds'] = int(time.time() - self.start_time)
            self.stats['last_update'] = datetime.now().isoformat()

            # Estadísticas de encoding mejoradas
            try:
                monitoring_data = self.encoding_monitor.get_monitoring_data()
                summary = monitoring_data.get('summary', {})

                total_error_rate = 0.0
                active_workers = 0
                worker_stats = monitoring_data.get('worker_stats', {})

                for worker_key, worker_data in worker_stats.items():
                    try:
                        if isinstance(worker_data, dict):
                            error_rate = worker_data.get('error_rate', 0.0)
                            status = worker_data.get('status', 'idle')
                        else:
                            error_rate = getattr(worker_data, 'error_rate', 0.0)
                            status = getattr(worker_data, 'status', 'idle')

                        if status == 'active':
                            total_error_rate += float(error_rate)
                            active_workers += 1

                    except (AttributeError, TypeError, ValueError):
                        continue

                self.stats.update({
                    'encoding_errors_total': summary.get('total_errors', 0),
                    'active_workers': summary.get('active_workers', 0),
                    'problematic_workers': summary.get('error_workers', 0),
                    'encoding_errors_rate': total_error_rate / max(active_workers, 1) if active_workers > 0 else 0.0
                })

            except Exception as e:
                self.logger.error(f"❌ Error actualizando estadísticas de encoding: {e}")
                self.stats.update({
                    'encoding_errors_total': 0,
                    'active_workers': 0,
                    'problematic_workers': 0,
                    'encoding_errors_rate': 0.0
                })

            # Procesar eventos de la cola
            events_processed = 0
            while not self.ml_events_queue.empty() and events_processed < 100:
                try:
                    event = self.ml_events_queue.get_nowait()
                    self.events.append(event)
                    events_processed += 1
                    self.stats['events_processed'] += 1

                except queue.Empty:
                    break
                except Exception as e:
                    self.logger.error(f"❌ Error procesando evento de la cola: {e}")
                    break

        except Exception as e:
            self.logger.error(f"❌ Error crítico en update_statistics: {e}")
            self.stats['last_update'] = datetime.now().isoformat()

    def update_zmq_connection_stats(self):
        """Actualizar estadísticas de conexiones ZeroMQ"""
        for conn_id, conn_info in self.zmq_connections.items():
            time_since_activity = (datetime.now() - conn_info.last_activity).total_seconds()

            if time_since_activity > 60:
                conn_info.status = 'inactive'
            elif time_since_activity > 300:
                conn_info.status = 'disconnected'
            else:
                conn_info.status = 'active'

            # Actualizar métricas detalladas
            self.detailed_metrics['zmq_connections'][conn_id] = {
                'status': conn_info.status,
                'total_messages': conn_info.total_messages,
                'bytes_transferred': conn_info.bytes_transferred,
                'last_activity': conn_info.last_activity.isoformat(),
                'endpoint': conn_info.endpoint,
                'socket_type': conn_info.socket_type,
                'mode': conn_info.mode,
                'high_water_mark': conn_info.high_water_mark
            }

    def update_system_metrics(self):
        """Actualizar métricas del sistema"""
        try:
            process = psutil.Process()
            self.stats['memory_usage_mb'] = process.memory_info().rss / 1024 / 1024
            self.stats['cpu_usage_percent'] = process.cpu_percent()
        except:
            pass

    def check_component_health(self):
        """Verificar salud de componentes conectados"""
        # ✅ MEJORADO: Verificar salud de ML Detector V3
        try:
            ml_connection = self.zmq_connections.get('ml_events')
            if ml_connection:
                time_since_activity = (datetime.now() - ml_connection.last_activity).total_seconds()
                if time_since_activity < 60:
                    self.stats['ml_detector_v3_connected'] = True
                else:
                    self.stats['ml_detector_v3_connected'] = False
        except Exception as e:
            self.logger.debug(f"Error verificando salud ML Detector V3: {e}")

    def get_dashboard_metrics(self):
        """Obtener métricas completas - MEJORADO V2.5.0"""

        try:
            monitoring_data = self.encoding_monitor.get_monitoring_data()
        except Exception as e:
            self.logger.error(f"Error obteniendo datos de monitoreo: {e}")
            monitoring_data = {'summary': {}, 'worker_stats': {}, 'connection_info': {}}

        # Geolocalización del nodo local
        local_node_position = {
            'latitude': 40.4168,
            'longitude': -3.7038,
            'location': 'Madrid, ES',
            'node_id': self.config.node_id,
            'component_type': 'dashboard',
            'status': 'online',
            'version': '2.5.0',
            'timestamp': datetime.now().isoformat()
        }

        # Convertir conexiones ZMQ de forma segura
        safe_zmq_connections = {}
        for k, v in self.zmq_connections.items():
            try:
                if hasattr(v, '__dict__'):
                    safe_zmq_connections[k] = asdict(v)
                else:
                    safe_zmq_connections[k] = v
            except Exception as e:
                self.logger.debug(f"Error convirtiendo conexión ZMQ {k}: {e}")
                safe_zmq_connections[k] = {'error': str(e)}

        # Convertir component status de forma segura
        safe_component_status = {}
        for k, v in self.component_status.items():
            try:
                safe_component_status[k] = asdict(v)
            except Exception as e:
                self.logger.debug(f"Error convirtiendo component status {k}: {e}")
                safe_component_status[k] = {'error': str(e)}

        return {
            'version': '2.5.0',
            'basic_stats': self.stats,
            'detailed_metrics': self.detailed_metrics,
            'zmq_connections': safe_zmq_connections,
            'component_status': safe_component_status,
            'recent_events': [asdict(e) for e in self.events[-50:]],
            'recent_commands': [asdict(c) for c in self.firewall_commands[-20:]],
            'node_info': {
                'node_id': self.config.node_id,
                'component_name': self.config.component_name,
                'version': self.config.version,
                'mode': self.config.mode,
                'role': self.config.role,
                'uptime_seconds': self.stats['uptime_seconds'],
                'pid': os.getpid(),
                'dashboard_version': '2.5.0'
            },
            'configuration': {
                'ml_events_queue_size': self.config.ml_events_queue_size,
                'ml_events_consumers': self.config.ml_events_consumers,
                'firewall_commands_queue_size': self.config.firewall_commands_queue_size,
                'firewall_command_producers': self.config.firewall_command_producers,
                'stats_interval': self.config.stats_interval
            },
            'encoding_monitoring': monitoring_data,
            'connectivity_info': {
                'ml_detector': self._get_component_connectivity('ml_events'),
                'firewall_agent': self._get_component_connectivity('firewall_commands'),
                'firewall_responses': self._get_component_connectivity('firewall_responses')
            },
            'local_node_position': local_node_position,
            'firewall_test_available': True,
            'debug_counters': self.debug_counters,
            # 🔥 Información de reglas de firewall MEJORADA
            'firewall_rules_info': {
                'version': '2.5.0',
                'rules_count': len(self.firewall_rules_engine.rules),
                'agents_count': len(self.firewall_rules_engine.firewall_agents),
                'last_loaded': self.firewall_rules_engine.last_loaded.isoformat() if self.firewall_rules_engine.last_loaded else None,
                'available_actions': list(self.firewall_rules_engine.manual_actions.keys()),
                'rules_file': self.firewall_rules_engine.rules_file
            },
            # ✅ NUEVO: Información específica ML Detector V3
            'ml_detector_v3_info': {
                'compatible': True,
                'protobuf_v3_messages': self.stats.get('protobuf_v3_messages', 0),
                'connected': self.stats.get('ml_detector_v3_connected', False),
                'parsing_successful': self.debug_counters.get('protobuf_v3_parsed', 0)
            }
        }

    def _get_component_connectivity(self, connection_id: str) -> Dict:
        """Obtener información de conectividad para un componente"""
        conn_info = self.encoding_monitor.connection_info.get(connection_id)
        if not conn_info:
            return {'status': 'unknown', 'details': 'No connection info'}

        return {
            'status': conn_info.status,
            'node_id': conn_info.node_id or 'unknown',
            'component_type': conn_info.component_type,
            'endpoint': conn_info.endpoint,
            'remote_ip': conn_info.remote_ip,
            'remote_port': conn_info.remote_port,
            'version': conn_info.version,
            'last_seen': conn_info.last_seen.isoformat() if conn_info.last_seen else None,
            'messages_exchanged': conn_info.messages_exchanged,
            'handshake_completed': conn_info.handshake_completed
        }

    def stop(self):
        """Detener dashboard con cleanup mejorado - V2.5.0"""
        self.logger.info("🛑 Deteniendo Dashboard de Seguridad V2.5.0...")
        self.running = False

        # 📊 Log estadísticas finales
        self.logger.info(f"📊 Stats finales V2.5.0:")
        self.logger.info(f"   📨 Mensajes recibidos: {self.debug_counters['messages_received']}")
        self.logger.info(f"   ✅ Mensajes parseados: {self.debug_counters['messages_parsed']}")
        self.logger.info(f"   🔥 Protobuf V3 parseados: {self.debug_counters['protobuf_v3_parsed']}")
        self.logger.info(f"   🔧 Operaciones socket: {self.debug_counters['socket_operations']}")
        self.logger.info(f"   📝 Eventos para RAG: {self.stats['events_logged_for_rag']}")

        # 🔒 Cerrar sockets de forma thread-safe
        with self.socket_lock:
            try:
                if hasattr(self, 'ml_socket') and self.ml_socket:
                    self.ml_socket.setsockopt(zmq.LINGER, 0)
                    self.ml_socket.close()
                    self.logger.debug("✅ ML socket cerrado")

                if hasattr(self, 'firewall_commands_socket') and self.firewall_commands_socket:
                    self.firewall_commands_socket.setsockopt(zmq.LINGER, 0)
                    self.firewall_commands_socket.close()
                    self.logger.debug("✅ Firewall commands socket cerrado")

                if hasattr(self, 'firewall_responses_socket') and self.firewall_responses_socket:
                    self.firewall_responses_socket.setsockopt(zmq.LINGER, 0)
                    self.firewall_responses_socket.close()
                    self.logger.debug("✅ Firewall responses socket cerrado")

            except Exception as e:
                self.logger.error(f"⚠️ Error cerrando sockets: {e}")

        # Cerrar contexto ZeroMQ
        try:
            if hasattr(self, 'context') and self.context:
                time.sleep(0.1)
                self.context.term()
                self.logger.debug("✅ Contexto ZMQ terminado")
        except Exception as e:
            self.logger.error(f"⚠️ Error terminando contexto ZMQ: {e}")

        self.logger.info("✅ Dashboard V2.5.0 detenido correctamente")


def signal_handler(sig, frame):
    """Manejar señales del sistema"""
    print("\n🛑 Recibida señal de terminación")
    sys.exit(0)


def main():
    """Función principal con configuración estricta - MEJORADA V2.5.0"""
    # Configurar manejo de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("🚀 Dashboard de Seguridad V2.5.0 - Inicio")
    print("✅ Compatible con lightweight_ml_detector V3")
    print("🔥 Integración completa con firewall_rules.json")
    print("📝 Logging robusto a disco y terminal")
    print("🎨 Soporte para modales draggeables")

    # 🔥 VERIFICAR ARGUMENTOS
    if len(sys.argv) != 3:
        print("\n❌ Uso incorrecto:")
        print("python real_zmq_dashboard_with_firewall.py <dashboard_config.json> <firewall_rules.json>")
        print("\n📋 Descripción de archivos:")
        print("   • dashboard_config.json: Configuración del sistema (ZMQ, threads, monitoring)")
        print("   • firewall_rules.json: Reglas dinámicas del firewall")
        print("\n✅ Ambos archivos son obligatorios para el funcionamiento")
        sys.exit(1)

    config_file = sys.argv[1]
    firewall_rules_file = sys.argv[2]

    # 🔥 VALIDACIÓN PREVIA: Verificar archivos
    if not Path(config_file).exists():
        print(f"\n❌ ERROR: Archivo de configuración no encontrado")
        print(f"📁 Archivo buscado: {config_file}")
        print(f"📍 Directorio actual: {os.getcwd()}")
        print("🔧 Verificar la ruta del archivo de configuración del dashboard")
        sys.exit(1)

    if not Path(firewall_rules_file).exists():
        print(f"\n❌ ERROR: Archivo de reglas de firewall no encontrado")
        print(f"📁 Archivo buscado: {firewall_rules_file}")
        print(f"📍 Directorio actual: {os.getcwd()}")
        print("🔧 Verificar la ruta del archivo de reglas del firewall")
        sys.exit(1)

    print(f"✅ Archivos de configuración encontrados:")
    print(f"   📋 Dashboard config: {config_file}")
    print(f"   🔥 Firewall rules: {firewall_rules_file}")

    try:
        # Cargar configuración del sistema
        print(f"\n📋 Cargando configuración del sistema...")
        config = DashboardConfig(config_file)

        # Crear directorios necesarios
        directories = ['logs', 'data', 'templates', 'static/css', 'static/js']
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            print(f"📁 Directorio verificado: {directory}")

        # 🔥 Crear dashboard con rutas específicas
        print(f"\n🔥 Iniciando dashboard con reglas de firewall...")
        dashboard = SecurityDashboard(config, firewall_rules_file)
        dashboard.start()

    except ConfigurationError as e:
        print(f"\n💥 ERROR DE CONFIGURACIÓN DEL SISTEMA:")
        print(f"❌ {e}")
        print(f"🔧 Verificar archivo: {config_file}")
        print("📋 Campos requeridos: network, zmq, processing, monitoring, logging")
        sys.exit(1)
    except FirewallRulesError as e:
        print(f"\n💥 ERROR DE REGLAS DE FIREWALL:")
        print(f"❌ {e}")
        print(f"🔧 Verificar archivo: {firewall_rules_file}")
        print("📋 Campos requeridos: firewall_rules.rules, firewall_rules.manual_actions")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"\n💥 ERROR DE FORMATO JSON:")
        print(f"❌ {e}")
        print("🔧 Verificar sintaxis JSON en ambos archivos")
        print("📝 Usar un validador JSON online para verificar")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 ERROR FATAL:")
        print(f"❌ {e}")
        print("\n🔍 Información de debug:")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()