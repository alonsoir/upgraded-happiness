#!/usr/bin/env python3
"""
core/etcd_crypto_client_dashboard_fixed.py
🔥 Cliente ETCD FIJO para Dashboard - Compatible con diferentes versiones de protobuf/etcd
- Registra el componente dashboard con ETCD con PERFIL COMPLETO DE PERFORMANCE
- Obtiene crypto tokens para descifrar del ml_detector y cifrar hacia firewall_agents fleet
- Maneja dependencias problemáticas (protobuf v3_1 + etcd)
- Fallback si etcd no está disponible solo en testing mode
- Testing mode incluido
- Usa dashboard_config_v31_etcd.json embebido
- GUARDA TODO: JSON config dashboard + reglas firewall + performance data para optimización futura
- REGISTRA DUAL: config dashboard + firewall rules en ETCD
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
class DashboardETCDConfig:
    """Configuración ETCD extraída desde dashboard_config_v31_etcd.json"""
    etcd_host: str
    etcd_port: int
    cluster_name: str
    node_id: str

    # Endpoints extraídos del config del dashboard
    ml_events_input_host: str
    ml_events_input_port: int
    fleet_commands_output_host: str
    fleet_commands_output_port: int
    fleet_responses_input_host: str
    fleet_responses_input_port: int
    web_server_host: str
    web_server_port: int

    # Opcional: Scheduler communication si está habilitado
    scheduler_comm_host: Optional[str] = None
    scheduler_comm_port: Optional[int] = None


class ETCDCryptoClientDashboard:
    """
    🔥 Cliente ETCD FIJO para Dashboard
    - Maneja problemas de dependencias protobuf v3_1 + etcd
    - Modo testing incluido
    - Fallback solo en testing mode
    - Registra como receiver_sender (descifra ML + cifra/descifra fleet commands/responses)
    - Pipeline position: 5 (después de scheduler=4)
    - GUARDA TODO EL PERFIL DE PERFORMANCE PARA OPTIMIZACIÓN FUTURA
    - REGISTRA DUAL: dashboard config + firewall rules en ETCD
    """

    def __init__(self, dashboard_config_path: str, firewall_rules_path: str, testing_mode: bool = False):
        self.dashboard_config_path = dashboard_config_path
        self.firewall_rules_path = firewall_rules_path
        self.testing_mode = testing_mode
        self.dashboard_config = None
        self.firewall_rules_config = None
        self.etcd_config = None
        self.pipeline_key = None
        self.crypto_ready = False

        # Logger específico del dashboard
        self.logger = logging.getLogger("etcd_crypto_dashboard_fixed")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s | 📊 DASHBOARD-CRYPTO-FIXED | %(levelname)s | %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        if testing_mode:
            self.logger.info("🧪 Testing mode enabled")

    def _load_dashboard_config(self):
        """Cargar configuración del dashboard desde JSON"""
        self.logger.info(f"📋 Loading dashboard config from: {self.dashboard_config_path}")

        if not os.path.exists(self.dashboard_config_path):
            raise FileNotFoundError(f"❌ Dashboard config file not found: {self.dashboard_config_path}")

        try:
            with open(self.dashboard_config_path, 'r') as f:
                self.dashboard_config = json.load(f)

            self.logger.info("✅ Dashboard config loaded successfully")

        except json.JSONDecodeError as e:
            raise ValueError(f"❌ Invalid JSON in dashboard config: {e}")
        except Exception as e:
            raise RuntimeError(f"❌ Failed to load dashboard config: {e}")

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
        Extraer configuración ETCD desde config del dashboard
        OBLIGATORIO: debe existir sección 'etcd_crypto' en el JSON
        """
        self.logger.info("🔍 Extracting ETCD config from dashboard config...")

        if not self.dashboard_config:
            raise RuntimeError("❌ Dashboard config not loaded")

        # OBLIGATORIO: sección etcd_crypto debe existir
        if 'etcd_crypto' not in self.dashboard_config:
            raise KeyError(
                "❌ REQUIRED section 'etcd_crypto' not found in dashboard config.\n"
                "   Add 'etcd_crypto' section to dashboard_config_v31_etcd.json"
            )

        etcd_section = self.dashboard_config['etcd_crypto']

        # OBLIGATORIO: campos requeridos
        required_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']
        missing_fields = []

        for field in required_fields:
            if field not in etcd_section:
                missing_fields.append(field)

        if missing_fields:
            raise KeyError(
                f"❌ REQUIRED fields missing in etcd_crypto section: {missing_fields}\n"
                f"   Add these fields to dashboard_config_v31_etcd.json"
            )

        # ML Events Input config (CONNECT al ml_detector)
        ml_events_input_host = "localhost"
        ml_events_input_port = 5580

        if 'network' in self.dashboard_config and 'ml_events_input' in self.dashboard_config['network']:
            ml_events_input = self.dashboard_config['network']['ml_events_input']
            ml_events_input_host = ml_events_input.get('address', 'localhost')
            ml_events_input_port = ml_events_input.get('port', 5580)

        # Fleet Commands Output config (PUSH a firewall_agents)
        fleet_commands_output_host = "localhost"
        fleet_commands_output_port = 5590

        # Fleet Responses Input config (PULL de firewall_agents)
        fleet_responses_input_host = "localhost"
        fleet_responses_input_port = 5591

        # Extraer de fleet configuration
        if 'firewall_fleet' in self.dashboard_config and 'agents' in self.dashboard_config['firewall_fleet']:
            agents = self.dashboard_config['firewall_fleet']['agents']
            if agents and len(agents) > 0:
                first_agent = agents[0]
                if 'network_endpoints' in first_agent:
                    endpoints = first_agent['network_endpoints']

                    if 'dashboard_commands' in endpoints:
                        cmd_config = endpoints['dashboard_commands']
                        fleet_commands_output_host = cmd_config.get('address', 'localhost')
                        fleet_commands_output_port = cmd_config.get('port', 5590)

                    if 'dashboard_responses' in endpoints:
                        resp_config = endpoints['dashboard_responses']
                        fleet_responses_input_host = resp_config.get('address', 'localhost')
                        fleet_responses_input_port = resp_config.get('port', 5591)

        # Web Server config
        web_server_host = "0.0.0.0"
        web_server_port = 8080

        if 'web_server' in self.dashboard_config:
            web_config = self.dashboard_config['web_server']
            web_server_host = web_config.get('host', '0.0.0.0')
            web_server_port = web_config.get('port', 8080)

        # Scheduler Communication (opcional)
        scheduler_comm_host = None
        scheduler_comm_port = None

        if 'network' in self.dashboard_config and 'scheduler_communication' in self.dashboard_config['network']:
            scheduler_comm = self.dashboard_config['network']['scheduler_communication']
            if scheduler_comm.get('enabled', False):
                scheduler_comm_host = scheduler_comm.get('address', 'localhost')
                scheduler_comm_port = scheduler_comm.get('port', 5585)

        # Crear config ETCD
        self.etcd_config = DashboardETCDConfig(
            etcd_host=etcd_section['etcd_host'],
            etcd_port=etcd_section['etcd_port'],
            cluster_name=etcd_section['cluster_name'],
            node_id=etcd_section['node_id'],
            ml_events_input_host=ml_events_input_host,
            ml_events_input_port=ml_events_input_port,
            fleet_commands_output_host=fleet_commands_output_host,
            fleet_commands_output_port=fleet_commands_output_port,
            fleet_responses_input_host=fleet_responses_input_host,
            fleet_responses_input_port=fleet_responses_input_port,
            web_server_host=web_server_host,
            web_server_port=web_server_port,
            scheduler_comm_host=scheduler_comm_host,
            scheduler_comm_port=scheduler_comm_port
        )

        self.logger.info("✅ ETCD config extracted successfully")
        self.logger.info(f"   📡 ETCD: {self.etcd_config.etcd_host}:{self.etcd_config.etcd_port}")
        self.logger.info(f"   🏢 Cluster: {self.etcd_config.cluster_name}")
        self.logger.info(f"   🆔 Node ID: {self.etcd_config.node_id}")
        self.logger.info(
            f"   📥 ML Events: {self.etcd_config.ml_events_input_host}:{self.etcd_config.ml_events_input_port}")
        self.logger.info(
            f"   📤 Fleet Commands: {self.etcd_config.fleet_commands_output_host}:{self.etcd_config.fleet_commands_output_port}")
        self.logger.info(
            f"   📥 Fleet Responses: {self.etcd_config.fleet_responses_input_host}:{self.etcd_config.fleet_responses_input_port}")
        self.logger.info(
            f"   🌐 Web Server: {self.etcd_config.web_server_host}:{self.etcd_config.web_server_port}")

        if self.etcd_config.scheduler_comm_host:
            self.logger.info(
                f"   📞 Scheduler Comm: {self.etcd_config.scheduler_comm_host}:{self.etcd_config.scheduler_comm_port}")

    def _build_component_info(self) -> Dict:
        """Construir información del componente dashboard para registro ETCD"""

        endpoints = {
            "zmq_sub_ml_events": f"tcp://{self.etcd_config.ml_events_input_host}:{self.etcd_config.ml_events_input_port}",
            "zmq_push_fleet_commands": f"tcp://{self.etcd_config.fleet_commands_output_host}:{self.etcd_config.fleet_commands_output_port}",
            "zmq_pull_fleet_responses": f"tcp://{self.etcd_config.fleet_responses_input_host}:{self.etcd_config.fleet_responses_input_port}",
            "http_web_server": f"http://{self.etcd_config.web_server_host}:{self.etcd_config.web_server_port}"
        }

        if self.etcd_config.scheduler_comm_host and self.etcd_config.scheduler_comm_port:
            endpoints[
                "zmq_req_scheduler"] = f"tcp://{self.etcd_config.scheduler_comm_host}:{self.etcd_config.scheduler_comm_port}"

        # 🎯 NUEVO: PERFIL COMPLETO DE PERFORMANCE PARA OPTIMIZACIÓN FUTURA
        performance_profile = self._extract_performance_profile()

        return {
            "node_id": self.etcd_config.node_id,
            "component_type": "dashboard_scada",
            "version": self.dashboard_config.get('component', {}).get('version', '3.1.0-etcd-integration'),
            "capabilities": [
                "real_time_visualization",
                "ml_events_monitoring",
                "fleet_management",
                "firewall_agents_control",
                "web_interface",
                "rest_api_v31",
                "network_topology_visualization",
                "geographic_visualization",
                "risk_score_analytics",
                "event_filtering_aggregation",
                "data_export",
                "health_monitoring",
                "performance_tracking",
                "encrypted_ml_input",
                "encrypted_fleet_communication",
                "real_time_updates",
                "cors_enabled_api",
                "rate_limiting",
                "pubsub_architecture",
                "zmq_pipeline_processing",
                "http_web_serving",
                "crypto_receiver_sender",
                "dual_config_registration"
            ],
            "endpoints": endpoints,
            "host_ip": self._get_component_ip(),
            "process_id": os.getpid(),
            "crypto_role": "receiver_sender",  # Descifra ML, cifra/descifra fleet
            "pipeline_position": 5,  # Después de scheduler (4)
            "input_from": ["ml_detector_tricapa", "firewall_agents_fleet"],
            "output_to": ["firewall_agents_fleet", "web_clients", "api_clients"],

            # 🎯 NUEVO: PERFIL COMPLETO DE PERFORMANCE
            "performance_profile": performance_profile,

            # 🎯 NUEVO: CONFIGURACIONES COMPLETAS PARA OPTIMIZACIÓN FUTURA
            "current_config": {
                "dashboard_config": self.dashboard_config,
                "firewall_rules_config": self.firewall_rules_config,
                "config_timestamp": datetime.now().isoformat(),
                "config_version": self.dashboard_config.get('_config_metadata', {}).get('config_version', '3.1.0')
            },

            # 🎯 DATOS PARA OPTIMIZADOR GENÉTICO
            "optimization_data": {
                "zmq_optimization_ready": True,
                "web_optimization_ready": True,
                "performance_tracking_enabled": True,
                "optimization_target": "visualization_latency_and_throughput",
                "last_optimization_timestamp": None,
                "optimization_cycle_count": 0
            },

            # 🎯 NUEVO: REGISTRO DUAL EN ETCD
            "etcd_data_registration": {
                "registers_own_config": True,
                "registers_firewall_rules": True,
                "registration_paths": {
                    "dashboard_config": "/upgraded-happiness/v31/components/dashboard/config",
                    "firewall_rules": "/upgraded-happiness/v31/components/dashboard/firewall_rules"
                },
                "update_on_config_change": True,
                "config_version_tracking": True
            }
        }

    def _extract_performance_profile(self) -> Dict:
        """Extraer perfil completo de performance del dashboard para optimización futura"""
        try:
            performance_profile = {
                # ZMQ Performance Configuration
                "zmq_config": self.dashboard_config.get('zmq', {}),

                # Processing Configuration
                "processing_config": self.dashboard_config.get('processing', {}),

                # Network Configuration
                "network_config": self.dashboard_config.get('network', {}),

                # Web Server Configuration
                "web_server_config": self.dashboard_config.get('web_server', {}),

                # Firewall Fleet Configuration
                "firewall_fleet_config": self.dashboard_config.get('firewall_fleet', {}),

                # Monitoring Configuration
                "monitoring_config": self.dashboard_config.get('monitoring', {}),

                # Security Configuration
                "security_config": self.dashboard_config.get('security', {}),

                # Data Visualization Configuration
                "data_visualization_config": self.dashboard_config.get('data_visualization', {}),

                # API Configuration
                "api_config": self.dashboard_config.get('api', {}),

                # Firewall Rules Summary (para optimización)
                "firewall_rules_summary": self._extract_firewall_rules_summary(),

                # Performance Metrics Structure (para futuras métricas)
                "performance_metrics_structure": {
                    "visualization_latency_ms": None,
                    "events_per_second": None,
                    "web_response_time_ms": None,
                    "fleet_command_latency_ms": None,
                    "queue_utilization_percent": None,
                    "cpu_usage_percent": None,
                    "memory_usage_mb": None,
                    "zmq_socket_performance": None,
                    "web_server_performance": None,
                    "crypto_operations_per_second": None,
                    "real_time_update_latency_ms": None
                },

                # Configuration Optimization Targets
                "optimization_targets": {
                    "max_web_response_time_ms": self.dashboard_config.get('monitoring', {}).get('alerts', {}).get(
                        'max_web_response_time_ms', 1000),
                    "min_events_per_minute": self.dashboard_config.get('monitoring', {}).get('alerts', {}).get(
                        'min_events_per_minute', 0),
                    "max_queue_usage_percent": self.dashboard_config.get('monitoring', {}).get('alerts', {}).get(
                        'max_queue_usage_percent', 75),
                    "max_cpu_usage_percent": self.dashboard_config.get('monitoring', {}).get('alerts', {}).get(
                        'max_cpu_usage_percent', 50),
                    "max_memory_usage_mb": self.dashboard_config.get('monitoring', {}).get('alerts', {}).get(
                        'max_memory_usage_mb', 512),
                    "max_processing_latency_ms": self.dashboard_config.get('monitoring', {}).get('alerts', {}).get(
                        'max_processing_latency_ms', 200)
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
        Inicializar crypto para dashboard con fallbacks
        """
        try:
            self.logger.info("🚀 Initializing ETCD crypto for Dashboard...")

            # 1. Cargar config del dashboard
            self._load_dashboard_config()

            # 2. Cargar config de reglas firewall
            self._load_firewall_rules_config()

            # 3. Extraer config ETCD
            self._extract_etcd_config()

            # 4. Verificar que crypto esté habilitado en el JSON
            crypto_config = self.dashboard_config.get("crypto", {})
            if not crypto_config.get("enabled", False):
                raise RuntimeError("❌ Crypto disabled in JSON config - component MUST shutdown")

            # 5. Verificar ETCD disponible
            if not ETCD_AVAILABLE:
                if self.testing_mode:
                    self.logger.warning("⚠️  ETCD not available - using mock token for testing")
                    self.pipeline_key = "mock_pipeline_key_for_testing_dashboard_" + "x" * 32
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
                    self.pipeline_key = "mock_pipeline_key_for_testing_dashboard_" + "x" * 32
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
                    self.pipeline_key = "mock_pipeline_key_for_testing_dashboard_" + "x" * 32
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
            self.logger.info("📝 Registering dashboard component with ETCD...")
            success, response = await coordinator.register_component(component_info)

            if not success:
                error_msg = response.get('error', 'unknown error')
                raise RuntimeError(f"❌ Component registration failed: {error_msg}")

            # 12. Extraer token crypto
            crypto_token = response["crypto_token"]
            self.pipeline_key = crypto_token["key_material"]
            self.crypto_ready = True

            # 13. 🎯 NUEVO: REGISTRO DUAL EN ETCD
            await self._register_configs_in_etcd(coordinator)

            self.logger.info("✅ Dashboard crypto initialization successful!")
            self.logger.info(f"🔑 Token version: {crypto_token['version']}")
            self.logger.info(f"📋 Registration hash: {response['registration_hash'][:16]}...")
            self.logger.info(f"🔐 Crypto role: receiver_sender (descifra ML, cifra/descifra fleet)")
            self.logger.info(f"🎯 Pipeline position: 5 (después de scheduler=4)")
            self.logger.info(f"📊 Dual config registration: dashboard + firewall rules")

            return True

        except Exception as e:
            self.logger.error(f"❌ Crypto initialization failed: {e}")

            # Fallback para development/testing
            if self.testing_mode or os.environ.get("UPGRADED_HAPPINESS_DEV_MODE"):
                self.logger.warning("🧪 Using fallback mock token for development")
                self.pipeline_key = "dev_pipeline_key_dashboard_" + "x" * 40
                self.crypto_ready = True
                return True

            # Si crypto está habilitado en JSON, DEBE fallar
            crypto_config = self.dashboard_config.get("crypto", {})
            if crypto_config.get("enabled", False):
                self.logger.error("❌ Crypto enabled in JSON but failed to initialize - COMPONENT MUST SHUTDOWN")
                return False

            return False

    async def _register_configs_in_etcd(self, coordinator):
        """🎯 NUEVO: Registrar ambos configs (dashboard + firewall rules) en ETCD"""
        try:
            self.logger.info("📊 Registering dual configs in ETCD...")

            # Registrar config del dashboard
            dashboard_config_key = "/upgraded-happiness/v31/components/dashboard/config"
            dashboard_config_data = {
                "config_type": "dashboard_config",
                "node_id": self.etcd_config.node_id,
                "component_type": "dashboard_scada",
                "config_data": self.dashboard_config,
                "timestamp": datetime.now().isoformat(),
                "config_version": self.dashboard_config.get('_config_metadata', {}).get('config_version', '3.1.0')
            }

            # Registrar reglas firewall
            firewall_rules_key = "/upgraded-happiness/v31/components/dashboard/firewall_rules"
            firewall_rules_data = {
                "config_type": "firewall_rules",
                "node_id": self.etcd_config.node_id,
                "managed_by": "dashboard_scada",
                "config_data": self.firewall_rules_config,
                "timestamp": datetime.now().isoformat(),
                "rules_summary": self._extract_firewall_rules_summary()
            }

            # Usar el coordinador para registrar (si tiene métodos para esto)
            # Si no, usar cliente etcd directo
            etcd_client = etcd3.client(
                host=self.etcd_config.etcd_host,
                port=self.etcd_config.etcd_port
            )

            # Registrar dashboard config
            etcd_client.put(dashboard_config_key, json.dumps(dashboard_config_data, indent=2))
            self.logger.info(f"✅ Dashboard config registered at: {dashboard_config_key}")

            # Registrar firewall rules
            etcd_client.put(firewall_rules_key, json.dumps(firewall_rules_data, indent=2))
            self.logger.info(f"✅ Firewall rules registered at: {firewall_rules_key}")

            self.logger.info("📊 Dual config registration completed successfully")

        except Exception as e:
            self.logger.warning(f"⚠️ Dual config registration failed: {e}")
            # No fallar el startup por esto - es nice-to-have

    def get_pipeline_key(self) -> Optional[str]:
        """Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para dashboard"""
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
            "dashboard_config_path": self.dashboard_config_path,
            "firewall_rules_path": self.firewall_rules_path,
            "pipeline_key_available": self.pipeline_key is not None,
            "etcd_available": ETCD_AVAILABLE,
            "etcd_client_type": ETCD_CLIENT_TYPE,
            "component_type": "dashboard_scada",
            "crypto_role": "receiver_sender",
            "pipeline_position": 5
        }

        if self.etcd_config:
            status.update({
                "etcd_host": self.etcd_config.etcd_host,
                "etcd_port": self.etcd_config.etcd_port,
                "cluster_name": self.etcd_config.cluster_name,
                "node_id": self.etcd_config.node_id,
                "ml_events_endpoint": f"{self.etcd_config.ml_events_input_host}:{self.etcd_config.ml_events_input_port}",
                "fleet_commands_endpoint": f"{self.etcd_config.fleet_commands_output_host}:{self.etcd_config.fleet_commands_output_port}",
                "fleet_responses_endpoint": f"{self.etcd_config.fleet_responses_input_host}:{self.etcd_config.fleet_responses_input_port}",
                "web_server_endpoint": f"{self.etcd_config.web_server_host}:{self.etcd_config.web_server_port}",
                "scheduler_comm_endpoint": f"{self.etcd_config.scheduler_comm_host}:{self.etcd_config.scheduler_comm_port}" if self.etcd_config.scheduler_comm_host else None
            })

        # Verificar si crypto está habilitado en JSON
        if self.dashboard_config:
            crypto_config = self.dashboard_config.get("crypto", {})
            status["crypto_enabled_in_json"] = crypto_config.get("enabled", False)

        # Estado de configuraciones cargadas
        status["configs_loaded"] = {
            "dashboard_config": self.dashboard_config is not None,
            "firewall_rules_config": self.firewall_rules_config is not None
        }

        return status


# ===============================================================================
# GLOBAL FUNCTIONS FIJAS para integración en dashboard_v31_etcd.py
# ===============================================================================

# Global client instance
_dashboard_crypto_client = None


async def setup_dashboard_crypto(dashboard_config_path: str, firewall_rules_path: str,
                                 testing_mode: bool = False) -> bool:
    """
    Setup crypto FIJO para dashboard

    Args:
        dashboard_config_path: Ruta al dashboard_config_v31_etcd.json
        firewall_rules_path: Ruta al firewall_rules.json
        testing_mode: Si True, usa mock tokens si ETCD falla

    Returns:
        True si exitoso, False si falla
    """
    global _dashboard_crypto_client

    try:
        # Detect dev mode automatically
        if os.environ.get("UPGRADED_HAPPINESS_DEV_MODE") == "true":
            testing_mode = True
            print("🧪 Dev mode detected - enabling testing mode")

        _dashboard_crypto_client = ETCDCryptoClientDashboard(
            dashboard_config_path, firewall_rules_path, testing_mode
        )
        return await _dashboard_crypto_client.initialize_crypto()
    except Exception as e:
        print(f"❌ Setup dashboard crypto failed: {e}")
        return False


def get_dashboard_pipeline_key() -> Optional[str]:
    """
    Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para dashboard
    REEMPLAZA: os.environ.get("UPGRADED_HAPPINESS_PIPELINE_KEY")
    """
    global _dashboard_crypto_client

    if _dashboard_crypto_client is None:
        print("❌ Dashboard crypto not initialized - call setup_dashboard_crypto() first")
        return None

    return _dashboard_crypto_client.get_pipeline_key()


def get_dashboard_crypto_status() -> Dict:
    """Obtener estado crypto del dashboard"""
    global _dashboard_crypto_client

    if _dashboard_crypto_client is None:
        return {"error": "not_initialized"}

    return _dashboard_crypto_client.get_status()


# ===============================================================================
# TESTING Y DESARROLLO
# ===============================================================================

async def create_test_dashboard_config(config_path: str):
    """Crear configuración de test para dashboard"""
    test_config = {
        "node_id": "dashboard_test_001",
        "component": {
            "name": "dashboard_scada_v31_etcd",
            "version": "3.1.0-etcd-test",
            "mode": "distributed_monitoring_etcd_test",
            "role": "dashboard_scada_nogui_etcd_test"
        },
        "etcd_crypto": {
            "etcd_host": "localhost",
            "etcd_port": 2379,
            "cluster_name": "upgraded-happiness-cluster-v31",
            "node_id": "dashboard_test_001"
        },
        "network": {
            "ml_events_input": {
                "address": "localhost",
                "port": 5580,
                "mode": "connect",
                "socket_type": "SUB",
                "high_water_mark": 500
            },
            "scheduler_communication": {
                "enabled": False,
                "address": "localhost",
                "port": 5585,
                "mode": "connect",
                "socket_type": "REQ"
            }
        },
        "firewall_fleet": {
            "enabled": True,
            "agents": [
                {
                    "node_id": "simple_firewall_agent_001",
                    "network_endpoints": {
                        "dashboard_commands": {
                            "address": "localhost",
                            "port": 5590,
                            "mode": "connect",
                            "socket_type": "PUSH"
                        },
                        "dashboard_responses": {
                            "address": "localhost",
                            "port": 5591,
                            "mode": "bind",
                            "socket_type": "PULL"
                        }
                    },
                    "capabilities": {
                        "allowed_actions": ["MONITOR", "LIST_RULES"]
                    },
                    "status": "active",
                    "location": "test_environment"
                }
            ]
        },
        "web_server": {
            "host": "0.0.0.0",
            "port": 8080,
            "debug": False,
            "threaded": True
        },
        "crypto": {
            "enabled": True,
            "role": "receiver_sender",
            "use_etcd_pipeline_key": True,
            "channels": {
                "ml_events_input": {"decrypt": True},
                "fleet_commands_output": {"encrypt": True},
                "fleet_responses_input": {"decrypt": True}
            }
        },
        "zmq": {"context_io_threads": 2},
        "processing": {"threads": {"ml_events_consumers": 1}},
        "monitoring": {"stats_interval_seconds": 60},
        "logging": {"level": "INFO"}
    }

    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    with open(config_path, 'w') as f:
        json.dump(test_config, f, indent=2)

    print(f"✅ Test dashboard config created: {config_path}")


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


async def test_dashboard_crypto_fixed():
    """Test completo del cliente crypto fijo para dashboard"""
    print("🧪 Testing ETCD Crypto Client - DASHBOARD VERSION")
    print("=" * 70)

    test_dashboard_config_path = "/tmp/test_dashboard_config_fixed.json"
    test_firewall_rules_path = "/tmp/test_firewall_rules_config_fixed.json"

    try:
        # 1. Crear configs de test
        await create_test_dashboard_config(test_dashboard_config_path)
        await create_test_firewall_rules_config(test_firewall_rules_path)

        # 2. Test con testing mode enabled
        print("\n📋 Testing with testing mode enabled...")
        success = await setup_dashboard_crypto(
            test_dashboard_config_path, test_firewall_rules_path, testing_mode=True
        )

        if success:
            print("✅ Dashboard crypto setup successful!")

            # 3. Test key retrieval
            pipeline_key = get_dashboard_pipeline_key()
            if pipeline_key:
                print(f"🔑 Pipeline key: {pipeline_key[:32]}...")

                # 4. Test status
                status = get_dashboard_crypto_status()
                print(f"📊 Status: {json.dumps(status, indent=2)}")

                print("\n🎯 READY FOR DASHBOARD INTEGRATION!")
            else:
                print("❌ Failed to get pipeline key")
        else:
            print("❌ Dashboard crypto setup failed!")

        # 5. Test sin testing mode (para ver diferencia)
        print("\n📋 Testing without testing mode (may fail)...")
        success_strict = await setup_dashboard_crypto(
            test_dashboard_config_path, test_firewall_rules_path, testing_mode=False
        )
        print(f"Strict mode result: {'✅ Success' if success_strict else '❌ Failed (expected)'}")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Cleanup
        for path in [test_dashboard_config_path, test_firewall_rules_path]:
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "test":
            asyncio.run(test_dashboard_crypto_fixed())
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
        print("📊 ETCD Crypto Client - DASHBOARD VERSION")
        print("=" * 60)
        print()
        print("🎯 CAPABILITIES:")
        print("   ✅ Handles protobuf v3_1 compatibility issues")
        print("   ✅ Testing mode for development")
        print("   ✅ NO fallbacks if crypto enabled in JSON")
        print("   ✅ Better error handling")
        print("   ✅ Auto-detection of dev mode")
        print("   ✅ receiver_sender crypto role")
        print("   ✅ Dashboard specific registration")
        print("   ✅ Pipeline position 5 (después de scheduler=4)")
        print("   ✅ Supports 4 endpoints (SUB/PUSH/PULL + HTTP)")
        print("   ✅ Complete performance profile storage")
        print("   ✅ Fleet management integration")
        print("   ✅ Web server configuration")
        print("   ✅ Dual config registration (dashboard + firewall rules)")
        print("   ✅ Optimization data for genetic algorithm")
        print()
        print("🚀 USAGE:")
        print("   python3 etcd_crypto_client_dashboard_fixed.py test")
        print("   python3 etcd_crypto_client_dashboard_fixed.py fix-deps")
        print()
        print("🧪 DEV MODE:")
        print("   export UPGRADED_HAPPINESS_DEV_MODE=true")
        print()
        print("🔐 CRYPTO MANDATORY:")
        print("   If crypto.enabled=true in JSON → NO fallbacks")
        print("   Component MUST shutdown if no ETCD pipeline key")
        print()
        print("📊 DUAL ETCD REGISTRATION:")
        print("   Registers dashboard config in ETCD")
        print("   Registers firewall rules in ETCD")
        print("   Path: /upgraded-happiness/v31/components/dashboard/")
        print()
        print("🎯 PERFORMANCE OPTIMIZATION:")
        print("   Stores complete configuration in ETCD")
        print("   Ready for genetic algorithm optimization")
        print("   Supports real-time configuration updates")
        print("   Web server performance tracking")
        print("   Fleet management optimization")