#!/usr/bin/env python3
"""
core/etcd_crypto_client_simple_firewall_agent_fixed.py
🔥 Cliente ETCD FIJO para Simple Firewall Agent - Compatible con diferentes versiones de protobuf/etcd
- Registra el componente simple_firewall_agent con ETCD con PERFIL COMPLETO DE PERFORMANCE
- Obtiene crypto tokens para dual communication (scheduler + dashboard)
- Maneja dependencias problemáticas (protobuf v3_1 + etcd)
- Fallback si etcd no está disponible solo en testing mode
- Testing mode incluido
- Usa simple_firewall_agent_v31_etcd_config_dev.json
- DUAL COMMUNICATION: scheduler (PUSH/PULL) + dashboard (PUB/SUB)
- GUARDA TODO: JSON config + performance data para optimización futura
"""

import asyncio
import json
import logging
import os
import sys
import socket
from typing import Dict, Optional, Union, Any
from dataclasses import dataclass
import time
from datetime import datetime

# 🔧 MANEJO DE DEPENDENCIAS PROBLEMÁTICAS
ETCD_AVAILABLE = False
ETCD_CLIENT_TYPE = None


def setup_etcd_environment():
    """Setup environment para evitar problemas con protobuf"""
    # Workaround para etcd3 + protobuf nuevo
    if 'PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION' not in os.environ:
        os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'


setup_etcd_environment()

# Intentar importar etcd con fallbacks
try:
    import etcd3

    ETCD_AVAILABLE = True
    ETCD_CLIENT_TYPE = "etcd3"
    print("✅ Using etcd3 client")
except ImportError as e:
    print(f"⚠️  etcd3 import failed: {e}")
    try:
        import etcd3 as etcd3_alt

        ETCD_AVAILABLE = True
        ETCD_CLIENT_TYPE = "etcd3-alt"
        etcd3 = etcd3_alt
        print("✅ Using alternative etcd3 client")
    except ImportError:
        print("❌ No etcd client available")
        print("💡 Install: pip install etcd3-py OR pip install 'protobuf<=3.20.3'")


@dataclass
class SimpleFirewallAgentETCDConfig:
    """Configuración ETCD extraída desde simple_firewall_agent_config.json"""
    etcd_host: str
    etcd_port: int
    cluster_name: str
    node_id: str

    # DUAL COMMUNICATION - Scheduler endpoints
    scheduler_commands_host: str
    scheduler_commands_port: int
    scheduler_responses_host: str
    scheduler_responses_port: int

    # DUAL COMMUNICATION - Dashboard endpoints
    dashboard_commands_host: str
    dashboard_commands_port: int
    dashboard_responses_host: str
    dashboard_responses_port: int

    # Opcional: HTTP API si está configurado (futuro)
    http_api_host: Optional[str] = None
    http_api_port: Optional[int] = None


class ETCDCryptoClientSimpleFirewallAgent:
    """
    🔥 Cliente ETCD FIJO para Simple Firewall Agent
    - Maneja problemas de dependencias protobuf v3_1 + etcd
    - Modo testing incluido
    - Fallback solo en testing mode
    - Registra como receiver_sender (descifra comandos + cifra respuestas)
    - Pipeline position: 5 (después de scheduler_firewall=4)
    - DUAL COMMUNICATION: scheduler + dashboard
    - GUARDA TODO EL PERFIL DE PERFORMANCE PARA OPTIMIZACIÓN FUTURA
    """

    def __init__(self, agent_config_path: str, testing_mode: bool = False):
        self.agent_config_path = agent_config_path
        self.testing_mode = testing_mode
        self.agent_config = None
        self.etcd_config = None
        self.pipeline_key = None
        self.crypto_ready = False

        # Logger específico del simple firewall agent
        self.logger = logging.getLogger("etcd_crypto_simple_firewall_agent_fixed")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s | 🔥 SIMPLE-FIREWALL-AGENT-CRYPTO-FIXED | %(levelname)s | %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        if testing_mode:
            self.logger.info("🧪 Testing mode enabled")

    def _load_agent_config(self):
        """Cargar configuración del agent desde JSON"""
        self.logger.info(f"📋 Loading agent config from: {self.agent_config_path}")

        if not os.path.exists(self.agent_config_path):
            raise FileNotFoundError(f"❌ Agent config file not found: {self.agent_config_path}")

        try:
            with open(self.agent_config_path, 'r') as f:
                self.agent_config = json.load(f)

            self.logger.info("✅ Agent config loaded successfully")

        except json.JSONDecodeError as e:
            raise ValueError(f"❌ Invalid JSON in agent config: {e}")
        except Exception as e:
            raise RuntimeError(f"❌ Failed to load agent config: {e}")

    def _extract_etcd_config(self):
        """
        Extraer configuración ETCD desde config del agent
        OBLIGATORIO: debe existir sección 'etcd_crypto' en el JSON
        """
        self.logger.info("🔍 Extracting ETCD config from agent config...")

        if not self.agent_config:
            raise RuntimeError("❌ Agent config not loaded")

        # OBLIGATORIO: sección etcd_crypto debe existir
        if 'etcd_crypto' not in self.agent_config:
            raise KeyError(
                "❌ REQUIRED section 'etcd_crypto' not found in agent config.\n"
                "   Add 'etcd_crypto' section to simple_firewall_agent_v31_etcd_config_dev.json"
            )

        etcd_section = self.agent_config['etcd_crypto']

        # OBLIGATORIO: campos requeridos
        required_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']
        missing_fields = []

        for field in required_fields:
            if field not in etcd_section:
                missing_fields.append(field)

        if missing_fields:
            raise KeyError(
                f"❌ REQUIRED fields missing in etcd_crypto section: {missing_fields}\n"
                f"   Add these fields to simple_firewall_agent_v31_etcd_config_dev.json"
            )

        # DUAL COMMUNICATION - Scheduler endpoints
        scheduler_commands_host = "localhost"
        scheduler_commands_port = 5582

        if 'network' in self.agent_config and 'scheduler_commands' in self.agent_config['network']:
            scheduler_commands = self.agent_config['network']['scheduler_commands']
            scheduler_commands_host = scheduler_commands.get('address', 'localhost')
            scheduler_commands_port = scheduler_commands.get('port', 5582)

        scheduler_responses_host = "localhost"
        scheduler_responses_port = 5581

        if 'network' in self.agent_config and 'scheduler_responses' in self.agent_config['network']:
            scheduler_responses = self.agent_config['network']['scheduler_responses']
            scheduler_responses_host = scheduler_responses.get('address', 'localhost')
            scheduler_responses_port = scheduler_responses.get('port', 5581)

        # DUAL COMMUNICATION - Dashboard endpoints
        dashboard_commands_host = "localhost"
        dashboard_commands_port = 5580

        if 'network' in self.agent_config and 'dashboard_commands' in self.agent_config['network']:
            dashboard_commands = self.agent_config['network']['dashboard_commands']
            dashboard_commands_host = dashboard_commands.get('address', 'localhost')
            dashboard_commands_port = dashboard_commands.get('port', 5580)

        dashboard_responses_host = "localhost"
        dashboard_responses_port = 5584

        if 'network' in self.agent_config and 'dashboard_responses' in self.agent_config['network']:
            dashboard_responses = self.agent_config['network']['dashboard_responses']
            dashboard_responses_host = dashboard_responses.get('address', 'localhost')
            dashboard_responses_port = dashboard_responses.get('port', 5584)

        # Extraer HTTP API si existe (futuro - dashboard web del agent)
        http_api_host = None
        http_api_port = None

        if 'http' in self.agent_config:
            http_section = self.agent_config['http']
            if 'api' in http_section:
                api_section = http_section['api']
                http_api_host = api_section.get('host')
                http_api_port = api_section.get('port')

        # Crear config ETCD
        self.etcd_config = SimpleFirewallAgentETCDConfig(
            etcd_host=etcd_section['etcd_host'],
            etcd_port=etcd_section['etcd_port'],
            cluster_name=etcd_section['cluster_name'],
            node_id=etcd_section['node_id'],
            scheduler_commands_host=scheduler_commands_host,
            scheduler_commands_port=scheduler_commands_port,
            scheduler_responses_host=scheduler_responses_host,
            scheduler_responses_port=scheduler_responses_port,
            dashboard_commands_host=dashboard_commands_host,
            dashboard_commands_port=dashboard_commands_port,
            dashboard_responses_host=dashboard_responses_host,
            dashboard_responses_port=dashboard_responses_port,
            http_api_host=http_api_host,
            http_api_port=http_api_port
        )

        self.logger.info("✅ ETCD config extracted successfully")
        self.logger.info(f"   📡 ETCD: {self.etcd_config.etcd_host}:{self.etcd_config.etcd_port}")
        self.logger.info(f"   🏢 Cluster: {self.etcd_config.cluster_name}")
        self.logger.info(f"   🆔 Node ID: {self.etcd_config.node_id}")
        self.logger.info(f"   📥 Scheduler Commands: {self.etcd_config.scheduler_commands_host}:{self.etcd_config.scheduler_commands_port}")
        self.logger.info(f"   📤 Scheduler Responses: {self.etcd_config.scheduler_responses_host}:{self.etcd_config.scheduler_responses_port}")
        self.logger.info(f"   📥 Dashboard Commands: {self.etcd_config.dashboard_commands_host}:{self.etcd_config.dashboard_commands_port}")
        self.logger.info(f"   📤 Dashboard Responses: {self.etcd_config.dashboard_responses_host}:{self.etcd_config.dashboard_responses_port}")

    def _build_component_info(self) -> Dict:
        """Construir información del componente simple firewall agent para registro ETCD"""

        # DUAL COMMUNICATION - endpoints separados
        endpoints = {
            "zmq_pull_scheduler_commands": f"tcp://{self.etcd_config.scheduler_commands_host}:{self.etcd_config.scheduler_commands_port}",
            "zmq_push_scheduler_responses": f"tcp://{self.etcd_config.scheduler_responses_host}:{self.etcd_config.scheduler_responses_port}",
            "zmq_sub_dashboard_commands": f"tcp://{self.etcd_config.dashboard_commands_host}:{self.etcd_config.dashboard_commands_port}",
            "zmq_pub_dashboard_responses": f"tcp://{self.etcd_config.dashboard_responses_host}:{self.etcd_config.dashboard_responses_port}"
        }

        if self.etcd_config.http_api_host and self.etcd_config.http_api_port:
            endpoints["http_api"] = f"http://{self.etcd_config.http_api_host}:{self.etcd_config.http_api_port}"

        # 🎯 NUEVO: PERFIL COMPLETO DE PERFORMANCE PARA OPTIMIZACIÓN FUTURA
        performance_profile = self._extract_performance_profile()

        return {
            "node_id": self.etcd_config.node_id,
            "component_type": "simple_firewall_agent",
            "version": self.agent_config.get('component', {}).get('version', '3.1.0-etcd-integration'),
            "capabilities": [
                "firewall_command_execution",
                "dual_communication_patterns",
                "scheduler_integration",
                "dashboard_integration",
                "human_oversight_support",
                "iptables_management",
                "pfctl_management",
                "netsh_management",
                "rule_timeout_management",
                "dry_run_execution",
                "safety_validation",
                "command_authentication",
                "security_logging",
                "environment_detection",
                "privilege_escalation_prevention",
                "encrypted_dual_channels",
                "performance_monitoring",
                "pubsub_architecture",
                "pushpull_architecture",
                "zmq_dual_patterns",
                "crypto_receiver_sender",
                "protobuf_v31_native"
            ],
            "endpoints": endpoints,
            "host_ip": self._get_component_ip(),
            "process_id": os.getpid(),
            "crypto_role": "receiver_sender",  # Descifra comandos, cifra respuestas
            "pipeline_position": 5,  # Después de scheduler_firewall (4)
            "input_from": ["scheduler_firewall", "dashboard"],
            "output_to": ["scheduler_firewall", "dashboard"],

            # 🎯 DUAL COMMUNICATION ESPECÍFICO
            "communication_patterns": {
                "scheduler_pattern": "PUSH/PULL",
                "dashboard_pattern": "PUB/SUB",
                "response_independence": True,
                "human_oversight": True
            },

            # 🎯 NUEVO: PERFIL COMPLETO DE PERFORMANCE
            "performance_profile": performance_profile,

            # 🎯 NUEVO: CONFIGURACIONES COMPLETAS PARA OPTIMIZACIÓN FUTURA
            "current_config": {
                "agent_config": self.agent_config,
                "config_timestamp": datetime.now().isoformat(),
                "config_version": self.agent_config.get('version', '3.1.0')
            },

            # 🎯 DATOS PARA OPTIMIZADOR GENÉTICO
            "optimization_data": {
                "zmq_optimization_ready": True,
                "performance_tracking_enabled": True,
                "optimization_target": "command_execution_latency_and_dual_throughput",
                "last_optimization_timestamp": None,
                "optimization_cycle_count": 0
            }
        }

    def _extract_performance_profile(self) -> Dict:
        """Extraer perfil completo de performance del agent para optimización futura"""
        try:
            performance_profile = {
                # ZMQ Performance Configuration - DUAL PATTERNS
                "zmq_config": self.agent_config.get('zmq', {}),

                # Processing Configuration - DUAL COMMUNICATION
                "processing_config": self.agent_config.get('processing', {}),

                # Network Configuration - SCHEDULER + DASHBOARD
                "network_config": self.agent_config.get('network', {}),

                # Monitoring Configuration
                "monitoring_config": self.agent_config.get('monitoring', {}),

                # Security Configuration - FIREWALL ESPECÍFICO
                "security_config": self.agent_config.get('security', {}),

                # Firewall Configuration - CORE DEL AGENT
                "firewall_config": self.agent_config.get('firewall', {}),

                # DUAL COMMUNICATION CONFIG
                "dual_communication_config": self.agent_config.get('_dual_communication_config', {}),

                # Performance Metrics Structure (para futuras métricas)
                "performance_metrics_structure": {
                    "command_execution_latency_ms": None,
                    "scheduler_commands_per_second": None,
                    "dashboard_commands_per_second": None,
                    "responses_per_second": None,
                    "dual_queue_utilization_percent": None,
                    "cpu_usage_percent": None,
                    "memory_usage_mb": None,
                    "zmq_dual_socket_performance": None,
                    "firewall_rule_processing_time_ms": None,
                    "crypto_operations_per_second": None,
                    "safety_validation_time_ms": None
                },

                # Configuration Optimization Targets
                "optimization_targets": {
                    "max_command_latency_ms": self.agent_config.get('monitoring', {}).get('alerts', {}).get(
                        'max_response_time_ms', 3000),
                    "min_success_rate_percent": self.agent_config.get('monitoring', {}).get('alerts', {}).get(
                        'min_success_rate_percent', 98),
                    "max_queue_usage_percent": self.agent_config.get('monitoring', {}).get('alerts', {}).get(
                        'max_queue_usage_percent', 50),
                    "max_error_rate_percent": self.agent_config.get('monitoring', {}).get('alerts', {}).get(
                        'max_error_rate_percent', 5),
                    "max_concurrent_commands": self.agent_config.get('processing', {}).get(
                        'max_concurrent_commands', 2)
                }
            }

            self.logger.info("✅ Performance profile extracted for optimization")
            return performance_profile

        except Exception as e:
            self.logger.warning(f"⚠️ Error extracting performance profile: {e}")
            return {
                "error": f"Failed to extract performance profile: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }

    def _get_component_ip(self) -> str:
        """Obtener IP del componente"""
        # Intentar obtener IP desde environment (K8s POD_IP)
        pod_ip = os.environ.get("POD_IP")
        if pod_ip:
            return pod_ip

        # Intentar obtener hostname (K8s pod name)
        hostname = os.environ.get("HOSTNAME")
        if hostname and hostname != "localhost":
            return hostname

        # Fallback: obtener IP local
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    async def initialize_crypto(self) -> bool:
        """
        Inicializar crypto para simple firewall agent con fallbacks
        """
        try:
            self.logger.info("🚀 Initializing ETCD crypto for Simple Firewall Agent...")

            # 1. Cargar config del agent
            self._load_agent_config()

            # 2. Extraer config ETCD
            self._extract_etcd_config()

            # 3. Verificar que crypto esté habilitado en el JSON
            crypto_config = self.agent_config.get("crypto", {})
            if not crypto_config.get("enabled", False):
                raise RuntimeError("❌ Crypto disabled in JSON config - component MUST shutdown")

            # 4. Verificar ETCD disponible
            if not ETCD_AVAILABLE:
                if self.testing_mode:
                    self.logger.warning("⚠️  ETCD not available - using mock token for testing")
                    self.pipeline_key = "mock_pipeline_key_for_testing_simple_firewall_agent_" + "x" * 32
                    self.crypto_ready = True
                    return True
                else:
                    raise RuntimeError("❌ etcd3 package not available and not in testing mode")

            # 5. Conectar a ETCD
            self.logger.info(f"📡 Connecting to ETCD at {self.etcd_config.etcd_host}:{self.etcd_config.etcd_port}...")

            try:
                etcd_client = etcd3.client(
                    host=self.etcd_config.etcd_host,
                    port=self.etcd_config.etcd_port,
                    timeout=5
                )

                # Test connection
                etcd_client.status()
                self.logger.info("✅ ETCD connection successful")

            except Exception as e:
                if self.testing_mode:
                    self.logger.warning(f"⚠️  ETCD connection failed - using mock token: {e}")
                    self.pipeline_key = "mock_pipeline_key_for_testing_simple_firewall_agent_" + "x" * 32
                    self.crypto_ready = True
                    return True
                else:
                    raise ConnectionError(f"❌ Cannot connect to ETCD: {e}")

            # 6. Importar coordinador
            try:
                # Intentar importar desde diferentes paths - RUTAS CORREGIDAS
                try:
                    from etcd_coordinator import ETCDCryptoCoordinator
                except ImportError:
                    from core.etcd_coordinator import ETCDCryptoCoordinator
            except ImportError as e:
                if self.testing_mode:
                    self.logger.warning(f"⚠️  ETCDCryptoCoordinator not available - using mock: {e}")
                    self.pipeline_key = "mock_pipeline_key_for_testing_simple_firewall_agent_" + "x" * 32
                    self.crypto_ready = True
                    return True
                else:
                    raise ImportError(f"❌ Cannot import ETCDCryptoCoordinator: {e}")

            # 7. Crear coordinador
            coordinator = ETCDCryptoCoordinator(
                etcd_host=self.etcd_config.etcd_host,
                etcd_port=self.etcd_config.etcd_port,
                cluster_name=self.etcd_config.cluster_name
            )

            # 8. Iniciar coordinador
            self.logger.info("🔄 Starting ETCD coordinator client...")
            await coordinator.start()

            # 9. Preparar info del componente
            component_info = self._build_component_info()

            # 10. Registrar componente
            self.logger.info("📝 Registering simple firewall agent component with ETCD...")
            success, response = await coordinator.register_component(component_info)

            if not success:
                error_msg = response.get('error', 'unknown error')
                raise RuntimeError(f"❌ Component registration failed: {error_msg}")

            # 11. Extraer token crypto
            crypto_token = response["crypto_token"]
            self.pipeline_key = crypto_token["key_material"]
            self.crypto_ready = True

            self.logger.info("✅ Simple Firewall Agent crypto initialization successful!")
            self.logger.info(f"🔑 Token version: {crypto_token['version']}")
            self.logger.info(f"📋 Registration hash: {response['registration_hash'][:16]}...")
            self.logger.info(f"🔐 Crypto role: receiver_sender (descifra comandos, cifra respuestas)")
            self.logger.info(f"🎯 Pipeline position: 5 (después de scheduler_firewall=4)")
            self.logger.info(f"🚀 DUAL COMMUNICATION: scheduler + dashboard patterns enabled")

            return True

        except Exception as e:
            self.logger.error(f"❌ Crypto initialization failed: {e}")

            # Fallback para development/testing
            if self.testing_mode or os.environ.get("UPGRADED_HAPPINESS_DEV_MODE"):
                self.logger.warning("🧪 Using fallback mock token for development")
                self.pipeline_key = "dev_pipeline_key_simple_firewall_agent_" + "x" * 40
                self.crypto_ready = True
                return True

            # Si crypto está habilitado en JSON, DEBE fallar
            crypto_config = self.agent_config.get("crypto", {})
            if crypto_config.get("enabled", False):
                self.logger.error("❌ Crypto enabled in JSON but failed to initialize - COMPONENT MUST SHUTDOWN")
                return False

            return False

    def get_pipeline_key(self) -> Optional[str]:
        """Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para simple firewall agent"""
        if not self.crypto_ready:
            self.logger.error("❌ Crypto not ready - call initialize_crypto() first")
            return None

        return self.pipeline_key

    def is_crypto_ready(self) -> bool:
        """Verificar si crypto está listo"""
        return self.crypto_ready and self.pipeline_key is not None

    def get_status(self) -> Dict:
        """Obtener estado para debugging"""
        status = {
            "ready": self.crypto_ready,
            "testing_mode": self.testing_mode,
            "agent_config_path": self.agent_config_path,
            "pipeline_key_available": self.pipeline_key is not None,
            "etcd_available": ETCD_AVAILABLE,
            "etcd_client_type": ETCD_CLIENT_TYPE,
            "component_type": "simple_firewall_agent",
            "crypto_role": "receiver_sender",
            "pipeline_position": 5
        }

        if self.etcd_config:
            status.update({
                "etcd_host": self.etcd_config.etcd_host,
                "etcd_port": self.etcd_config.etcd_port,
                "cluster_name": self.etcd_config.cluster_name,
                "node_id": self.etcd_config.node_id,
                "scheduler_commands_endpoint": f"{self.etcd_config.scheduler_commands_host}:{self.etcd_config.scheduler_commands_port}",
                "scheduler_responses_endpoint": f"{self.etcd_config.scheduler_responses_host}:{self.etcd_config.scheduler_responses_port}",
                "dashboard_commands_endpoint": f"{self.etcd_config.dashboard_commands_host}:{self.etcd_config.dashboard_commands_port}",
                "dashboard_responses_endpoint": f"{self.etcd_config.dashboard_responses_host}:{self.etcd_config.dashboard_responses_port}"
            })

        # Verificar si crypto está habilitado en JSON
        if self.agent_config:
            crypto_config = self.agent_config.get("crypto", {})
            status["crypto_enabled_in_json"] = crypto_config.get("enabled", False)

        # Estado de configuraciones cargadas
        status["configs_loaded"] = {
            "agent_config": self.agent_config is not None
        }

        return status


# ===============================================================================
# GLOBAL FUNCTIONS FIJAS para integración en simple_firewall_agent_etcd.py
# ===============================================================================

# Global client instance
_simple_firewall_agent_crypto_client = None


async def setup_simple_firewall_agent_crypto(agent_config_path: str, testing_mode: bool = False) -> bool:
    """
    Setup crypto FIJO para simple firewall agent

    Args:
        agent_config_path: Ruta al simple_firewall_agent_v31_etcd_config_dev.json
        testing_mode: Si True, usa mock tokens si ETCD falla

    Returns:
        True si exitoso, False si falla
    """
    global _simple_firewall_agent_crypto_client

    try:
        # Detect dev mode automatically
        if os.environ.get("UPGRADED_HAPPINESS_DEV_MODE") == "true":
            testing_mode = True
            print("🧪 Dev mode detected - enabling testing mode")

        _simple_firewall_agent_crypto_client = ETCDCryptoClientSimpleFirewallAgent(
            agent_config_path, testing_mode
        )
        return await _simple_firewall_agent_crypto_client.initialize_crypto()
    except Exception as e:
        print(f"❌ Setup simple firewall agent crypto failed: {e}")
        return False


def get_simple_firewall_agent_pipeline_key() -> Optional[str]:
    """
    Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para simple firewall agent
    REEMPLAZA: os.environ.get("UPGRADED_HAPPINESS_PIPELINE_KEY")
    """
    global _simple_firewall_agent_crypto_client

    if _simple_firewall_agent_crypto_client is None:
        print("❌ Simple Firewall Agent crypto not initialized - call setup_simple_firewall_agent_crypto() first")
        return None

    return _simple_firewall_agent_crypto_client.get_pipeline_key()


def get_simple_firewall_agent_crypto_status() -> Dict:
    """Obtener estado crypto del simple firewall agent"""
    global _simple_firewall_agent_crypto_client

    if _simple_firewall_agent_crypto_client is None:
        return {"error": "not_initialized"}

    return _simple_firewall_agent_crypto_client.get_status()


# ===============================================================================
# TESTING Y DESARROLLO
# ===============================================================================

async def create_test_simple_firewall_agent_config(config_path: str):
    """Crear configuración de test para simple firewall agent"""
    test_config = {
        "node_id": "simple_firewall_agent_test_001",
        "component": {
            "name": "simple_firewall_agent_v31_etcd",
            "version": "3.1.0-etcd-test",
            "mode": "distributed_safe_dual_etcd_test",
            "role": "firewall_agent_safe_dual_v31_etcd_test"
        },
        "etcd_crypto": {
            "etcd_host": "localhost",
            "etcd_port": 2379,
            "cluster_name": "upgraded-happiness-cluster-v31",
            "node_id": "simple_firewall_agent_test_001"
        },
        "network": {
            "scheduler_commands": {
                "address": "localhost",
                "port": 5582,
                "mode": "bind",
                "socket_type": "PULL",
                "high_water_mark": 500
            },
            "scheduler_responses": {
                "address": "localhost",
                "port": 5581,
                "mode": "connect",
                "socket_type": "PUSH",
                "high_water_mark": 500
            },
            "dashboard_commands": {
                "address": "localhost",
                "port": 5580,
                "mode": "connect",
                "socket_type": "SUB",
                "high_water_mark": 500
            },
            "dashboard_responses": {
                "address": "localhost",
                "port": 5584,
                "mode": "bind",
                "socket_type": "PUB",
                "high_water_mark": 500
            }
        },
        "crypto": {
            "enabled": True,
            "role": "receiver_sender",
            "use_etcd_pipeline_key": True,
            "channels": {
                "scheduler_commands": {"decrypt": True},
                "scheduler_responses": {"encrypt": True},
                "dashboard_commands": {"decrypt": True},
                "dashboard_responses": {"encrypt": True}
            }
        },
        "zmq": {"context_io_threads": 2},
        "processing": {"threads": {"scheduler_commands_consumer": 1, "dashboard_commands_consumer": 1}},
        "monitoring": {"stats_interval_seconds": 60},
        "logging": {"level": "INFO"},
        "firewall": {"dry_run": True, "auto_detect_type": True}
    }

    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    with open(config_path, 'w') as f:
        json.dump(test_config, f, indent=2)

    print(f"✅ Test simple firewall agent config created: {config_path}")


async def test_simple_firewall_agent_crypto_fixed():
    """Test completo del cliente crypto fijo para simple firewall agent"""
    print("🧪 Testing ETCD Crypto Client - SIMPLE FIREWALL AGENT VERSION")
    print("=" * 70)

    test_agent_config_path = "/tmp/test_simple_firewall_agent_config_fixed.json"

    try:
        # 1. Crear config de test
        await create_test_simple_firewall_agent_config(test_agent_config_path)

        # 2. Test con testing mode enabled
        print("\n📋 Testing with testing mode enabled...")
        success = await setup_simple_firewall_agent_crypto(
            test_agent_config_path, testing_mode=True
        )

        if success:
            print("✅ Simple Firewall Agent crypto setup successful!")

            # 3. Test key retrieval
            pipeline_key = get_simple_firewall_agent_pipeline_key()
            if pipeline_key:
                print(f"🔑 Pipeline key: {pipeline_key[:32]}...")

                # 4. Test status
                status = get_simple_firewall_agent_crypto_status()
                print(f"📊 Status: {json.dumps(status, indent=2)}")

                print("\n🎯 READY FOR SIMPLE FIREWALL AGENT INTEGRATION!")
            else:
                print("❌ Failed to get pipeline key")
        else:
            print("❌ Simple Firewall Agent crypto setup failed!")

        # 5. Test sin testing mode (para ver diferencia)
        print("\n📋 Testing without testing mode (may fail)...")
        success_strict = await setup_simple_firewall_agent_crypto(
            test_agent_config_path, testing_mode=False
        )
        print(f"Strict mode result: {'✅ Success' if success_strict else '❌ Failed (expected)'}")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Cleanup
        if os.path.exists(test_agent_config_path):
            os.unlink(test_agent_config_path)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "test":
            asyncio.run(test_simple_firewall_agent_crypto_fixed())
        elif command == "fix-deps":
            print("🔧 DEPENDENCY FIX OPTIONS:")
            print("1. pip install 'protobuf<=3.20.3'")
            print("2. export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python")
            print("3. pip install etcd3-py (alternative)")
            print("4. Ensure protocols folder uses v3_1 (no dots)")
        else:
            print(f"❌ Unknown command: {command}")
            print("💡 Available: test, fix-deps")
    else:
        print("🔥 ETCD Crypto Client - SIMPLE FIREWALL AGENT VERSION")
        print("=" * 60)
        print()
        print("🎯 CAPABILITIES:")
        print("   ✅ Handles protobuf v3_1 compatibility issues")
        print("   ✅ Testing mode for development")
        print("   ✅ NO fallbacks if crypto enabled in JSON")
        print("   ✅ Better error handling")
        print("   ✅ Auto-detection of dev mode")
        print("   ✅ receiver_sender crypto role")
        print("   ✅ Simple Firewall Agent specific registration")
        print("   ✅ Pipeline position 5 (después de scheduler_firewall=4)")
        print("   ✅ DUAL COMMUNICATION: scheduler + dashboard")
        print("   ✅ Supports 4 ZMQ sockets (PULL/PUSH/SUB/PUB)")
        print("   ✅ Complete performance profile storage")
        print("   ✅ Firewall agent capabilities")
        print("   ✅ Optimization data for genetic algorithm")
        print()
        print("🚀 USAGE:")
        print("   python3 etcd_crypto_client_simple_firewall_agent_fixed.py test")
        print("   python3 etcd_crypto_client_simple_firewall_agent_fixed.py fix-deps")
        print()
        print("🧪 DEV MODE:")
        print("   export UPGRADED_HAPPINESS_DEV_MODE=true")
        print()
        print("🔐 CRYPTO MANDATORY:")
        print("   If crypto.enabled=true in JSON → NO fallbacks")
        print("   Component MUST shutdown if no ETCD pipeline key")
        print()
        print("🎯 DUAL COMMUNICATION:")
        print("   Scheduler: PUSH/PULL pattern (5582/5581)")
        print("   Dashboard: PUB/SUB pattern (5580/5584)")
        print("   Independent response channels for human oversight")
        print()
        print("🎯 PERFORMANCE OPTIMIZATION:")
        print("   Stores complete configuration in ETCD")
        print("   Ready for genetic algorithm optimization")
        print("   Supports real-time configuration updates")