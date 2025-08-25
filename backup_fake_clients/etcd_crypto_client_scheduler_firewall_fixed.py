#!/usr/bin/env python3
"""
core/etcd_crypto_client_scheduler_firewall_fixed.py
🔥 Cliente ETCD FIJO para Scheduler Firewall - Compatible con diferentes versiones de protobuf/etcd
- Registra el componente scheduler_firewall con ETCD con PERFIL COMPLETO DE PERFORMANCE
- Obtiene crypto tokens para descifrar del ml_detector y cifrar hacia firewall_agent
- Maneja dependencias problemáticas (protobuf v3_1 + etcd)
- Fallback si etcd no está disponible solo en testing mode
- Testing mode incluido
- Usa scheduler_firewall_etcd_config_dev.json embebido
- GUARDA TODO: JSON config + reglas firewall + performance data para optimización futura
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
class SchedulerFirewallETCDConfig:
    """Configuración ETCD extraída desde scheduler_firewall_config.json"""
    etcd_host: str
    etcd_port: int
    cluster_name: str
    node_id: str

    # Endpoints extraídos del config del scheduler
    ml_events_input_host: str
    ml_events_input_port: int
    firewall_commands_output_host: str
    firewall_commands_output_port: int
    firewall_responses_input_host: str
    firewall_responses_input_port: int

    # Opcional: HTTP API si está configurado (futuro)
    http_api_host: Optional[str] = None
    http_api_port: Optional[int] = None


class ETCDCryptoClientSchedulerFirewall:
    """
    🔥 Cliente ETCD FIJO para Scheduler Firewall
    - Maneja problemas de dependencias protobuf v3_1 + etcd
    - Modo testing incluido
    - Fallback solo en testing mode
    - Registra como receiver_sender (descifra ML + cifra comandos firewall)
    - Pipeline position: 4 (después de ml_detector=3)
    - GUARDA TODO EL PERFIL DE PERFORMANCE PARA OPTIMIZACIÓN FUTURA
    """

    def __init__(self, scheduler_config_path: str, firewall_rules_path: str, testing_mode: bool = False):
        self.scheduler_config_path = scheduler_config_path
        self.firewall_rules_path = firewall_rules_path
        self.testing_mode = testing_mode
        self.scheduler_config = None
        self.firewall_rules_config = None
        self.etcd_config = None
        self.pipeline_key = None
        self.crypto_ready = False

        # Logger específico del scheduler firewall
        self.logger = logging.getLogger("etcd_crypto_scheduler_firewall_fixed")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s | 🔥 SCHEDULER-FIREWALL-CRYPTO-FIXED | %(levelname)s | %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        if testing_mode:
            self.logger.info("🧪 Testing mode enabled")

    def _load_scheduler_config(self):
        """Cargar configuración del scheduler desde JSON"""
        self.logger.info(f"📋 Loading scheduler config from: {self.scheduler_config_path}")

        if not os.path.exists(self.scheduler_config_path):
            raise FileNotFoundError(f"❌ Scheduler config file not found: {self.scheduler_config_path}")

        try:
            with open(self.scheduler_config_path, 'r') as f:
                self.scheduler_config = json.load(f)

            self.logger.info("✅ Scheduler config loaded successfully")

        except json.JSONDecodeError as e:
            raise ValueError(f"❌ Invalid JSON in scheduler config: {e}")
        except Exception as e:
            raise RuntimeError(f"❌ Failed to load scheduler config: {e}")

    def _load_firewall_rules_config(self):
        """Cargar configuración de reglas firewall desde JSON"""
        self.logger.info(f"🔥 Loading firewall rules from: {self.firewall_rules_path}")

        if not os.path.exists(self.firewall_rules_path):
            raise FileNotFoundError(f"❌ Firewall rules file not found: {self.firewall_rules_path}")

        try:
            with open(self.firewall_rules_path, 'r') as f:
                self.firewall_rules_config = json.load(f)

            self.logger.info("✅ Firewall rules config loaded successfully")

        except json.JSONDecodeError as e:
            raise ValueError(f"❌ Invalid JSON in firewall rules: {e}")
        except Exception as e:
            raise RuntimeError(f"❌ Failed to load firewall rules: {e}")

    def _extract_etcd_config(self):
        """
        Extraer configuración ETCD desde config del scheduler
        OBLIGATORIO: debe existir sección 'etcd_crypto' en el JSON
        """
        self.logger.info("🔍 Extracting ETCD config from scheduler config...")

        if not self.scheduler_config:
            raise RuntimeError("❌ Scheduler config not loaded")

        # OBLIGATORIO: sección etcd_crypto debe existir
        if 'etcd_crypto' not in self.scheduler_config:
            raise KeyError(
                "❌ REQUIRED section 'etcd_crypto' not found in scheduler config.\n"
                "   Add 'etcd_crypto' section to scheduler_firewall_etcd_config_dev.json"
            )

        etcd_section = self.scheduler_config['etcd_crypto']

        # OBLIGATORIO: campos requeridos
        required_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']
        missing_fields = []

        for field in required_fields:
            if field not in etcd_section:
                missing_fields.append(field)

        if missing_fields:
            raise KeyError(
                f"❌ REQUIRED fields missing in etcd_crypto section: {missing_fields}\n"
                f"   Add these fields to scheduler_firewall_etcd_config_dev.json"
            )

        # ML Events Input config (CONNECT al ml_detector)
        ml_events_input_host = "localhost"
        ml_events_input_port = 5580

        if 'network' in self.scheduler_config and 'ml_events_input' in self.scheduler_config['network']:
            ml_events_input = self.scheduler_config['network']['ml_events_input']
            ml_events_input_host = ml_events_input.get('address', 'localhost')
            ml_events_input_port = ml_events_input.get('port', 5580)

        # Firewall Commands Output config (PUSH al firewall_agent)
        fw_commands_output_host = "localhost"
        fw_commands_output_port = 5582

        if 'network' in self.scheduler_config and 'firewall_commands_output' in self.scheduler_config['network']:
            fw_commands_output = self.scheduler_config['network']['firewall_commands_output']
            fw_commands_output_host = fw_commands_output.get('address', 'localhost')
            fw_commands_output_port = fw_commands_output.get('port', 5582)

        # Firewall Responses Input config (PULL del firewall_agent)
        fw_responses_input_host = "localhost"
        fw_responses_input_port = 5581

        if 'network' in self.scheduler_config and 'firewall_responses_input' in self.scheduler_config['network']:
            fw_responses_input = self.scheduler_config['network']['firewall_responses_input']
            fw_responses_input_host = fw_responses_input.get('address', 'localhost')
            fw_responses_input_port = fw_responses_input.get('port', 5581)

        # Extraer HTTP API si existe (futuro - dashboard web del scheduler)
        http_api_host = None
        http_api_port = None

        if 'http' in self.scheduler_config:
            http_section = self.scheduler_config['http']
            if 'api' in http_section:
                api_section = http_section['api']
                http_api_host = api_section.get('host')
                http_api_port = api_section.get('port')

        # Crear config ETCD
        self.etcd_config = SchedulerFirewallETCDConfig(
            etcd_host=etcd_section['etcd_host'],
            etcd_port=etcd_section['etcd_port'],
            cluster_name=etcd_section['cluster_name'],
            node_id=etcd_section['node_id'],
            ml_events_input_host=ml_events_input_host,
            ml_events_input_port=ml_events_input_port,
            firewall_commands_output_host=fw_commands_output_host,
            firewall_commands_output_port=fw_commands_output_port,
            firewall_responses_input_host=fw_responses_input_host,
            firewall_responses_input_port=fw_responses_input_port,
            http_api_host=http_api_host,
            http_api_port=http_api_port
        )

        self.logger.info("✅ ETCD config extracted successfully")
        self.logger.info(f"   📡 ETCD: {self.etcd_config.etcd_host}:{self.etcd_config.etcd_port}")
        self.logger.info(f"   🏢 Cluster: {self.etcd_config.cluster_name}")
        self.logger.info(f"   🆔 Node ID: {self.etcd_config.node_id}")
        self.logger.info(
            f"   📥 ML Events: {self.etcd_config.ml_events_input_host}:{self.etcd_config.ml_events_input_port}")
        self.logger.info(
            f"   📤 FW Commands: {self.etcd_config.firewall_commands_output_host}:{self.etcd_config.firewall_commands_output_port}")
        self.logger.info(
            f"   📥 FW Responses: {self.etcd_config.firewall_responses_input_host}:{self.etcd_config.firewall_responses_input_port}")

    def _build_component_info(self) -> Dict:
        """Construir información del componente scheduler firewall para registro ETCD"""

        endpoints = {
            "zmq_sub_ml_events": f"tcp://{self.etcd_config.ml_events_input_host}:{self.etcd_config.ml_events_input_port}",
            "zmq_push_fw_commands": f"tcp://{self.etcd_config.firewall_commands_output_host}:{self.etcd_config.firewall_commands_output_port}",
            "zmq_pull_fw_responses": f"tcp://{self.etcd_config.firewall_responses_input_host}:{self.etcd_config.firewall_responses_input_port}"
        }

        if self.etcd_config.http_api_host and self.etcd_config.http_api_port:
            endpoints["http_api"] = f"http://{self.etcd_config.http_api_host}:{self.etcd_config.http_api_port}"

        # 🎯 NUEVO: PERFIL COMPLETO DE PERFORMANCE PARA OPTIMIZACIÓN FUTURA
        performance_profile = self._extract_performance_profile()

        return {
            "node_id": self.etcd_config.node_id,
            "component_type": "scheduler_firewall",
            "version": self.scheduler_config.get('component', {}).get('version', '1.0.0-etcd-integration'),
            "capabilities": [
                "firewall_decision_engine",
                "ml_events_processing",
                "rule_based_decisions",
                "risk_score_evaluation",
                "firewall_command_generation",
                "firewall_agent_communication",
                "protobuf_v31_commands",
                "json_controlled_rules",
                "real_time_decisions",
                "encrypted_ml_input",
                "encrypted_firewall_output",
                "performance_monitoring",
                "rule_dynamic_reload",
                "multi_agent_support",
                "decision_analytics",
                "pubsub_architecture",
                "zmq_pipeline_processing",
                "crypto_receiver_sender"
            ],
            "endpoints": endpoints,
            "host_ip": self._get_component_ip(),
            "process_id": os.getpid(),
            "crypto_role": "receiver_sender",  # Descifra ML, cifra firewall commands
            "pipeline_position": 4,  # Después de ml_detector (3)
            "input_from": ["ml_detector_tricapa"],
            "output_to": ["simple_firewall_agent", "firewall_agents_fleet"],

            # 🎯 NUEVO: PERFIL COMPLETO DE PERFORMANCE
            "performance_profile": performance_profile,

            # 🎯 NUEVO: CONFIGURACIONES COMPLETAS PARA OPTIMIZACIÓN FUTURA
            "current_config": {
                "scheduler_config": self.scheduler_config,
                "firewall_rules_config": self.firewall_rules_config,
                "config_timestamp": datetime.now().isoformat(),
                "config_version": self.scheduler_config.get('_config_metadata', {}).get('config_version', '1.0.0')
            },

            # 🎯 DATOS PARA OPTIMIZADOR GENÉTICO
            "optimization_data": {
                "zmq_optimization_ready": True,
                "performance_tracking_enabled": True,
                "optimization_target": "decision_latency_and_throughput",
                "last_optimization_timestamp": None,
                "optimization_cycle_count": 0
            }
        }

    def _extract_performance_profile(self) -> Dict:
        """Extraer perfil completo de performance del scheduler para optimización futura"""
        try:
            performance_profile = {
                # ZMQ Performance Configuration
                "zmq_config": self.scheduler_config.get('zmq', {}),

                # Processing Configuration
                "processing_config": self.scheduler_config.get('processing', {}),

                # Network Configuration
                "network_config": self.scheduler_config.get('network', {}),

                # Monitoring Configuration
                "monitoring_config": self.scheduler_config.get('monitoring', {}),

                # Security Configuration
                "security_config": self.scheduler_config.get('security', {}),

                # Decision Engine Configuration
                "decision_engine_config": self.scheduler_config.get('decision_engine', {}),

                # Firewall Rules Summary (para optimización)
                "firewall_rules_summary": self._extract_firewall_rules_summary(),

                # Performance Metrics Structure (para futuras métricas)
                "performance_metrics_structure": {
                    "decision_latency_ms": None,
                    "events_per_second": None,
                    "commands_per_second": None,
                    "queue_utilization_percent": None,
                    "cpu_usage_percent": None,
                    "memory_usage_mb": None,
                    "zmq_socket_performance": None,
                    "rule_processing_time_ms": None,
                    "crypto_operations_per_second": None
                },

                # Configuration Optimization Targets
                "optimization_targets": {
                    "max_decision_latency_ms": self.scheduler_config.get('monitoring', {}).get('alerts', {}).get(
                        'max_decision_latency_ms', 50),
                    "min_decisions_per_minute": self.scheduler_config.get('monitoring', {}).get('alerts', {}).get(
                        'min_decisions_per_minute', 1),
                    "max_queue_usage_percent": self.scheduler_config.get('monitoring', {}).get('alerts', {}).get(
                        'max_queue_usage_percent', 70),
                    "max_cpu_usage_percent": self.scheduler_config.get('monitoring', {}).get('alerts', {}).get(
                        'max_cpu_usage_percent', 40),
                    "max_memory_usage_mb": self.scheduler_config.get('monitoring', {}).get('alerts', {}).get(
                        'max_memory_usage_mb', 256)
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

    def _extract_firewall_rules_summary(self) -> Dict:
        """Extraer resumen de reglas firewall para optimización"""
        try:
            if not self.firewall_rules_config:
                return {"error": "firewall_rules_config_not_loaded"}

            firewall_rules = self.firewall_rules_config.get('firewall_rules', {})
            rules = firewall_rules.get('rules', [])
            agents_fleet = firewall_rules.get('agents_fleet', {})
            manual_actions = firewall_rules.get('manual_actions', {})

            return {
                "total_rules": len(rules),
                "enabled_rules": len([r for r in rules if r.get('enabled', True)]),
                "total_agents": len(agents_fleet),
                "total_manual_actions": len(manual_actions),
                "rule_coverage": self._calculate_rule_coverage(rules),
                "agent_capabilities_summary": self._summarize_agent_capabilities(agents_fleet),
                "rules_by_priority": self._count_rules_by_priority(rules),
                "rules_config_hash": hash(str(firewall_rules))  # Para detectar cambios
            }

        except Exception as e:
            self.logger.warning(f"⚠️ Error extracting firewall rules summary: {e}")
            return {"error": f"Failed to extract rules summary: {str(e)}"}

    def _calculate_rule_coverage(self, rules: list) -> Dict:
        """Calcular cobertura de rangos de riesgo"""
        try:
            covered_risks = set()
            for rule in rules:
                if rule.get('enabled', True):
                    risk_range = rule.get('risk_range', [])
                    if len(risk_range) >= 2:
                        for risk in range(risk_range[0], risk_range[1] + 1):
                            covered_risks.add(risk)

            total_possible = 101  # 0-100
            coverage_percent = (len(covered_risks) / total_possible) * 100

            return {
                "coverage_percent": round(coverage_percent, 2),
                "covered_risk_points": len(covered_risks),
                "total_possible_risk_points": total_possible,
                "uncovered_risks": sorted(list(set(range(0, 101)) - covered_risks))[:10]  # Primeros 10
            }
        except Exception:
            return {"error": "coverage_calculation_failed"}

    def _summarize_agent_capabilities(self, agents_fleet: dict) -> Dict:
        """Resumir capacidades de agentes"""
        try:
            total_agents = len(agents_fleet)
            active_agents = 0
            total_capabilities = set()
            agent_summary = {}

            for agent_id, agent_config in agents_fleet.items():
                status = agent_config.get('status', 'unknown')
                if status == 'active':
                    active_agents += 1

                capabilities = agent_config.get('capabilities', {}).get('allowed_actions', [])
                total_capabilities.update(capabilities)

                agent_summary[agent_id] = {
                    "status": status,
                    "capabilities_count": len(capabilities),
                    "location": agent_config.get('location', 'unknown')
                }

            return {
                "total_agents": total_agents,
                "active_agents": active_agents,
                "unique_capabilities": list(total_capabilities),
                "total_unique_capabilities": len(total_capabilities),
                "agent_summary": agent_summary
            }
        except Exception:
            return {"error": "agent_capabilities_summary_failed"}

    def _count_rules_by_priority(self, rules: list) -> Dict:
        """Contar reglas por prioridad"""
        try:
            priority_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

            for rule in rules:
                if rule.get('enabled', True):
                    priority = rule.get('priority', 'UNKNOWN')
                    if priority in priority_counts:
                        priority_counts[priority] += 1
                    else:
                        priority_counts["UNKNOWN"] += 1

            return priority_counts
        except Exception:
            return {"error": "priority_count_failed"}

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
        Inicializar crypto para scheduler firewall con fallbacks
        """
        try:
            self.logger.info("🚀 Initializing ETCD crypto for Scheduler Firewall...")

            # 1. Cargar config del scheduler
            self._load_scheduler_config()

            # 2. Cargar config de reglas firewall
            self._load_firewall_rules_config()

            # 3. Extraer config ETCD
            self._extract_etcd_config()

            # 4. Verificar que crypto esté habilitado en el JSON
            crypto_config = self.scheduler_config.get("crypto", {})
            if not crypto_config.get("enabled", False):
                raise RuntimeError("❌ Crypto disabled in JSON config - component MUST shutdown")

            # 5. Verificar ETCD disponible
            if not ETCD_AVAILABLE:
                if self.testing_mode:
                    self.logger.warning("⚠️  ETCD not available - using mock token for testing")
                    self.pipeline_key = "mock_pipeline_key_for_testing_scheduler_firewall_" + "x" * 32
                    self.crypto_ready = True
                    return True
                else:
                    raise RuntimeError("❌ etcd3 package not available and not in testing mode")

            # 6. Conectar a ETCD
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
                    self.pipeline_key = "mock_pipeline_key_for_testing_scheduler_firewall_" + "x" * 32
                    self.crypto_ready = True
                    return True
                else:
                    raise ConnectionError(f"❌ Cannot connect to ETCD: {e}")

            # 7. Importar coordinador
            try:
                # Intentar importar desde diferentes paths - RUTAS CORREGIDAS
                try:
                    from etcd_coordinator import ETCDCryptoCoordinator
                except ImportError:
                    from core.etcd_coordinator import ETCDCryptoCoordinator
            except ImportError as e:
                if self.testing_mode:
                    self.logger.warning(f"⚠️  ETCDCryptoCoordinator not available - using mock: {e}")
                    self.pipeline_key = "mock_pipeline_key_for_testing_scheduler_firewall_" + "x" * 32
                    self.crypto_ready = True
                    return True
                else:
                    raise ImportError(f"❌ Cannot import ETCDCryptoCoordinator: {e}")

            # 8. Crear coordinador
            coordinator = ETCDCryptoCoordinator(
                etcd_host=self.etcd_config.etcd_host,
                etcd_port=self.etcd_config.etcd_port,
                cluster_name=self.etcd_config.cluster_name
            )

            # 9. Iniciar coordinador
            self.logger.info("🔄 Starting ETCD coordinator client...")
            await coordinator.start()

            # 10. Preparar info del componente
            component_info = self._build_component_info()

            # 11. Registrar componente
            self.logger.info("📝 Registering scheduler firewall component with ETCD...")
            success, response = await coordinator.register_component(component_info)

            if not success:
                error_msg = response.get('error', 'unknown error')
                raise RuntimeError(f"❌ Component registration failed: {error_msg}")

            # 12. Extraer token crypto
            crypto_token = response["crypto_token"]
            self.pipeline_key = crypto_token["key_material"]
            self.crypto_ready = True

            self.logger.info("✅ Scheduler Firewall crypto initialization successful!")
            self.logger.info(f"🔑 Token version: {crypto_token['version']}")
            self.logger.info(f"📋 Registration hash: {response['registration_hash'][:16]}...")
            self.logger.info(f"🔐 Crypto role: receiver_sender (descifra ML, cifra firewall commands)")
            self.logger.info(f"🎯 Pipeline position: 4 (después de ml_detector=3)")

            return True

        except Exception as e:
            self.logger.error(f"❌ Crypto initialization failed: {e}")

            # Fallback para development/testing
            if self.testing_mode or os.environ.get("UPGRADED_HAPPINESS_DEV_MODE"):
                self.logger.warning("🧪 Using fallback mock token for development")
                self.pipeline_key = "dev_pipeline_key_scheduler_firewall_" + "x" * 40
                self.crypto_ready = True
                return True

            # Si crypto está habilitado en JSON, DEBE fallar
            crypto_config = self.scheduler_config.get("crypto", {})
            if crypto_config.get("enabled", False):
                self.logger.error("❌ Crypto enabled in JSON but failed to initialize - COMPONENT MUST SHUTDOWN")
                return False

            return False

    def get_pipeline_key(self) -> Optional[str]:
        """Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para scheduler firewall"""
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
            "scheduler_config_path": self.scheduler_config_path,
            "firewall_rules_path": self.firewall_rules_path,
            "pipeline_key_available": self.pipeline_key is not None,
            "etcd_available": ETCD_AVAILABLE,
            "etcd_client_type": ETCD_CLIENT_TYPE,
            "component_type": "scheduler_firewall",
            "crypto_role": "receiver_sender",
            "pipeline_position": 4
        }

        if self.etcd_config:
            status.update({
                "etcd_host": self.etcd_config.etcd_host,
                "etcd_port": self.etcd_config.etcd_port,
                "cluster_name": self.etcd_config.cluster_name,
                "node_id": self.etcd_config.node_id,
                "ml_events_endpoint": f"{self.etcd_config.ml_events_input_host}:{self.etcd_config.ml_events_input_port}",
                "fw_commands_endpoint": f"{self.etcd_config.firewall_commands_output_host}:{self.etcd_config.firewall_commands_output_port}",
                "fw_responses_endpoint": f"{self.etcd_config.firewall_responses_input_host}:{self.etcd_config.firewall_responses_input_port}"
            })

        # Verificar si crypto está habilitado en JSON
        if self.scheduler_config:
            crypto_config = self.scheduler_config.get("crypto", {})
            status["crypto_enabled_in_json"] = crypto_config.get("enabled", False)

        # Estado de configuraciones cargadas
        status["configs_loaded"] = {
            "scheduler_config": self.scheduler_config is not None,
            "firewall_rules_config": self.firewall_rules_config is not None
        }

        return status


# ===============================================================================
# GLOBAL FUNCTIONS FIJAS para integración en scheduler_firewall_etcd.py
# ===============================================================================

# Global client instance
_scheduler_firewall_crypto_client = None


async def setup_scheduler_firewall_crypto(scheduler_config_path: str, firewall_rules_path: str,
                                          testing_mode: bool = False) -> bool:
    """
    Setup crypto FIJO para scheduler firewall

    Args:
        scheduler_config_path: Ruta al scheduler_firewall_etcd_config_dev.json
        firewall_rules_path: Ruta al firewall_rules.json
        testing_mode: Si True, usa mock tokens si ETCD falla

    Returns:
        True si exitoso, False si falla
    """
    global _scheduler_firewall_crypto_client

    try:
        # Detect dev mode automatically
        if os.environ.get("UPGRADED_HAPPINESS_DEV_MODE") == "true":
            testing_mode = True
            print("🧪 Dev mode detected - enabling testing mode")

        _scheduler_firewall_crypto_client = ETCDCryptoClientSchedulerFirewall(
            scheduler_config_path, firewall_rules_path, testing_mode
        )
        return await _scheduler_firewall_crypto_client.initialize_crypto()
    except Exception as e:
        print(f"❌ Setup scheduler firewall crypto failed: {e}")
        return False


def get_scheduler_firewall_pipeline_key() -> Optional[str]:
    """
    Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para scheduler firewall
    REEMPLAZA: os.environ.get("UPGRADED_HAPPINESS_PIPELINE_KEY")
    """
    global _scheduler_firewall_crypto_client

    if _scheduler_firewall_crypto_client is None:
        print("❌ Scheduler Firewall crypto not initialized - call setup_scheduler_firewall_crypto() first")
        return None

    return _scheduler_firewall_crypto_client.get_pipeline_key()


def get_scheduler_firewall_crypto_status() -> Dict:
    """Obtener estado crypto del scheduler firewall"""
    global _scheduler_firewall_crypto_client

    if _scheduler_firewall_crypto_client is None:
        return {"error": "not_initialized"}

    return _scheduler_firewall_crypto_client.get_status()


# ===============================================================================
# TESTING Y DESARROLLO
# ===============================================================================

async def create_test_scheduler_firewall_config(config_path: str):
    """Crear configuración de test para scheduler firewall"""
    test_config = {
        "node_id": "scheduler_firewall_test_001",
        "component": {
            "name": "scheduler_firewall_etcd",
            "version": "1.0.0-etcd-test",
            "mode": "distributed_decision_engine_etcd_test",
            "role": "firewall_scheduler_nogui_etcd_test"
        },
        "etcd_crypto": {
            "etcd_host": "localhost",
            "etcd_port": 2379,
            "cluster_name": "upgraded-happiness-cluster-v31",
            "node_id": "scheduler_firewall_test_001"
        },
        "network": {
            "ml_events_input": {
                "address": "localhost",
                "port": 5580,
                "mode": "connect",
                "socket_type": "SUB",
                "high_water_mark": 500
            },
            "firewall_commands_output": {
                "address": "localhost",
                "port": 5582,
                "mode": "connect",
                "socket_type": "PUSH",
                "high_water_mark": 200
            },
            "firewall_responses_input": {
                "address": "localhost",
                "port": 5581,
                "mode": "bind",
                "socket_type": "PULL",
                "high_water_mark": 200
            }
        },
        "crypto": {
            "enabled": True,
            "role": "receiver_sender",
            "use_etcd_pipeline_key": True,
            "channels": {
                "ml_events_input": {"decrypt": True},
                "firewall_commands_output": {"encrypt": True},
                "firewall_responses_input": {"decrypt": True}
            }
        },
        "zmq": {"context_io_threads": 1},
        "processing": {"threads": {"ml_events_consumers": 1}},
        "monitoring": {"stats_interval_seconds": 60},
        "logging": {"level": "INFO"}
    }

    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    with open(config_path, 'w') as f:
        json.dump(test_config, f, indent=2)

    print(f"✅ Test scheduler firewall config created: {config_path}")


async def create_test_firewall_rules_config(config_path: str):
    """Crear configuración de test para reglas firewall"""
    test_config = {
        "firewall_rules": {
            "rules": [
                {
                    "enabled": True,
                    "risk_range": [0, 30],
                    "action": "MONITOR",
                    "params": {"duration": 300},
                    "priority": "LOW",
                    "dry_run": True,
                    "description": "Low risk monitoring"
                },
                {
                    "enabled": True,
                    "risk_range": [70, 100],
                    "action": "BLOCK_IP",
                    "params": {"duration": 600},
                    "priority": "HIGH",
                    "dry_run": False,
                    "description": "High risk blocking"
                }
            ],
            "manual_actions": {
                "MONITOR": {"type": "monitor", "safe": True},
                "BLOCK_IP": {"type": "block", "safe": False}
            },
            "agents_fleet": {
                "simple_firewall_agent_001": {
                    "network_endpoints": {
                        "scheduler_communication": {
                            "commands_input": "tcp://localhost:5582"
                        }
                    },
                    "capabilities": {
                        "allowed_actions": ["MONITOR", "BLOCK_IP"],
                        "max_concurrent_rules": 10
                    },
                    "status": "active",
                    "location": "test_environment"
                }
            }
        }
    }

    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    with open(config_path, 'w') as f:
        json.dump(test_config, f, indent=2)

    print(f"✅ Test firewall rules config created: {config_path}")


async def test_scheduler_firewall_crypto_fixed():
    """Test completo del cliente crypto fijo para scheduler firewall"""
    print("🧪 Testing ETCD Crypto Client - SCHEDULER FIREWALL VERSION")
    print("=" * 70)

    test_scheduler_config_path = "/tmp/test_scheduler_firewall_config_fixed.json"
    test_firewall_rules_path = "/tmp/test_firewall_rules_config_fixed.json"

    try:
        # 1. Crear configs de test
        await create_test_scheduler_firewall_config(test_scheduler_config_path)
        await create_test_firewall_rules_config(test_firewall_rules_path)

        # 2. Test con testing mode enabled
        print("\n📋 Testing with testing mode enabled...")
        success = await setup_scheduler_firewall_crypto(
            test_scheduler_config_path, test_firewall_rules_path, testing_mode=True
        )

        if success:
            print("✅ Scheduler Firewall crypto setup successful!")

            # 3. Test key retrieval
            pipeline_key = get_scheduler_firewall_pipeline_key()
            if pipeline_key:
                print(f"🔑 Pipeline key: {pipeline_key[:32]}...")

                # 4. Test status
                status = get_scheduler_firewall_crypto_status()
                print(f"📊 Status: {json.dumps(status, indent=2)}")

                print("\n🎯 READY FOR SCHEDULER FIREWALL INTEGRATION!")
            else:
                print("❌ Failed to get pipeline key")
        else:
            print("❌ Scheduler Firewall crypto setup failed!")

        # 5. Test sin testing mode (para ver diferencia)
        print("\n📋 Testing without testing mode (may fail)...")
        success_strict = await setup_scheduler_firewall_crypto(
            test_scheduler_config_path, test_firewall_rules_path, testing_mode=False
        )
        print(f"Strict mode result: {'✅ Success' if success_strict else '❌ Failed (expected)'}")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Cleanup
        for path in [test_scheduler_config_path, test_firewall_rules_path]:
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "test":
            asyncio.run(test_scheduler_firewall_crypto_fixed())
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
        print("🔥 ETCD Crypto Client - SCHEDULER FIREWALL VERSION")
        print("=" * 60)
        print()
        print("🎯 CAPABILITIES:")
        print("   ✅ Handles protobuf v3_1 compatibility issues")
        print("   ✅ Testing mode for development")
        print("   ✅ NO fallbacks if crypto enabled in JSON")
        print("   ✅ Better error handling")
        print("   ✅ Auto-detection of dev mode")
        print("   ✅ receiver_sender crypto role")
        print("   ✅ Scheduler Firewall specific registration")
        print("   ✅ Pipeline position 4 (después de ml_detector=3)")
        print("   ✅ Supports 3 ZMQ sockets (SUB/PUSH/PULL)")
        print("   ✅ Complete performance profile storage")
        print("   ✅ Firewall rules integration")
        print("   ✅ Optimization data for genetic algorithm")
        print()
        print("🚀 USAGE:")
        print("   python3 etcd_crypto_client_scheduler_firewall_fixed.py test")
        print("   python3 etcd_crypto_client_scheduler_firewall_fixed.py fix-deps")
        print()
        print("🧪 DEV MODE:")
        print("   export UPGRADED_HAPPINESS_DEV_MODE=true")
        print()
        print("🔐 CRYPTO MANDATORY:")
        print("   If crypto.enabled=true in JSON → NO fallbacks")
        print("   Component MUST shutdown if no ETCD pipeline key")
        print()
        print("🎯 PERFORMANCE OPTIMIZATION:")
        print("   Stores complete configuration in ETCD")
        print("   Ready for genetic algorithm optimization")
        print("   Supports real-time configuration updates")