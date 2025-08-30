#!/usr/bin/env python3
"""
tests/test_dashboard_etcd_compatibility.py
🧪 TEST DE COMPATIBILIDAD - DASHBOARD ETCD CLIENT
================================================================================
Verifica que el cliente ETCD puede usar los archivos JSON generados para Docker:
- dashboard_config_docker.json
- firewall_rules_config_docker.json (compartido con otros componentes)

PATRÓN: Similar a test_scheduler_firewall_etcd_compatibility.py
"""

import asyncio
import json
import logging
import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock
import threading
import time

# Mock etcd3 antes de importar el cliente
sys.modules['etcd3'] = Mock()

# Importar el cliente ETCD dashboard
from core.etcd_crypto_client_dashboard_fixed import (
    ETCDCryptoClientDashboard,
    DashboardETCDConfig,
    setup_dashboard_crypto,
    get_dashboard_pipeline_key,
    get_dashboard_crypto_status
)


class TestDashboardETCDCompatibility(unittest.TestCase):
    """🧪 Test de compatibilidad para el cliente ETCD del Dashboard"""

    def setUp(self):
        """Setup para cada test"""
        self.temp_dashboard_config_file = None
        self.temp_firewall_rules_file = None

        # Configurar logging para tests
        logging.basicConfig(level=logging.WARNING)

    def tearDown(self):
        """Cleanup después de cada test"""
        # Limpiar archivos temporales
        if self.temp_dashboard_config_file:
            try:
                os.unlink(self.temp_dashboard_config_file)
            except:
                pass

        if self.temp_firewall_rules_file:
            try:
                os.unlink(self.temp_firewall_rules_file)
            except:
                pass

    def _create_test_dashboard_config(self) -> str:
        """Crear archivo temporal con dashboard config válido"""
        dashboard_config = {
            "deployment_metadata": {
                "environment": "docker-compose",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "pod_id": "dashboard-b8c4f6d2k-p7q9m",
                "container_name": "dashboard"
            },
            "node_id": "dashboard_main_v31_etcd_001",
            "component": {
                "name": "dashboard_scada_v31_etcd",
                "version": "3.1.0-etcd-integration",
                "mode": "distributed_monitoring_etcd",
                "role": "dashboard_scada_nogui_etcd"
            },
            "etcd_crypto": {
                "etcd_host": "etcd",
                "etcd_port": 2379,
                "cluster_name": "upgraded-happiness-cluster-v31",
                "node_id": "dashboard_main_v31_etcd_001"
            },
            "network": {
                "ml_events_input": {
                    "address": "ml-detector",
                    "port": 5580,
                    "socket_type": "SUB"
                },
                "scheduler_communication": {
                    "enabled": False,
                    "address": "scheduler-firewall",
                    "port": 5585,
                    "socket_type": "REQ"
                }
            },
            "firewall_fleet": {
                "enabled": True,
                "agents": [
                    {
                        "node_id": "simple_firewall_agent_001",
                        "status": "active",
                        "network_endpoints": {
                            "dashboard_communication": {
                                "commands_input": "tcp://simple-firewall-agent:5583",
                                "responses_output": "tcp://simple-firewall-agent:5584"
                            }
                        },
                        "capabilities": {
                            "allowed_actions": ["BLOCK_IP", "RATE_LIMIT_IP", "LIST_RULES"]
                        }
                    }
                ]
            },
            "web_server": {
                "host": "0.0.0.0",
                "port": 8080,
                "debug": True
            },
            "crypto": {
                "enabled": True,
                "role": "receiver_sender",
                "use_etcd_pipeline_key": True
            }
        }

        # Crear archivo temporal
        fd, temp_path = tempfile.mkstemp(suffix='_dashboard_config.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(dashboard_config, f, indent=2)

        self.temp_dashboard_config_file = temp_path
        return temp_path

    def _create_test_firewall_rules(self) -> str:
        """Crear archivo temporal con firewall rules válidas"""
        firewall_rules = {
            "deployment_metadata": {
                "environment": "docker",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "container_name": "dashboard"
            },
            "firewall_rules": {
                "version": "1.0.0-RELEASE",
                "description": "Test firewall rules for dashboard",
                "rules": [
                    {
                        "rule_id": "rule_001_dashboard_test",
                        "risk_range": [0, 19],
                        "action": "MONITOR",
                        "priority": "LOW",
                        "dry_run": True,
                        "enabled": True
                    },
                    {
                        "rule_id": "rule_002_dashboard_test",
                        "risk_range": [80, 100],
                        "action": "BLOCK_IP",
                        "priority": "HIGH",
                        "dry_run": False,
                        "enabled": True
                    }
                ],
                "manual_actions": {
                    "MONITOR": {
                        "description": "Monitor IP - SEGURO",
                        "safety_level": "SAFE",
                        "enabled": True
                    },
                    "BLOCK_IP": {
                        "description": "Block IP - PELIGROSO",
                        "safety_level": "CRITICAL",
                        "enabled": True
                    }
                },
                "agents_fleet": {
                    "simple_firewall_agent_001": {
                        "node_id": "simple_firewall_agent_001",
                        "version": "3.1.0",
                        "status": "active",
                        "network_endpoints": {
                            "scheduler_communication": {
                                "commands_input": "tcp://firewall-agent-001:5582",
                                "responses_output": "tcp://firewall-agent-001:5581"
                            },
                            "dashboard_communication": {
                                "commands_input": "tcp://firewall-agent-001:5583",
                                "responses_output": "tcp://firewall-agent-001:5584"
                            }
                        },
                        "capabilities": {
                            "allowed_actions": ["MONITOR", "LIST_RULES", "BLOCK_IP"],
                            "blocked_actions": ["FLUSH_RULES"],
                            "max_concurrent_rules": 10
                        },
                        "security_profile": {
                            "safety_mode": "ULTRA_SECURE_V31",
                            "auto_force_dry_run": True
                        }
                    }
                },
                "global_settings": {
                    "security": {
                        "development_mode": True
                    }
                }
            }
        }

        # Crear archivo temporal
        fd, temp_path = tempfile.mkstemp(suffix='_firewall_rules.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(firewall_rules, f, indent=2)

        self.temp_firewall_rules_file = temp_path
        return temp_path

    def test_01_load_configs_success(self):
        """🧪 Test: Cargar ambas configuraciones correctamente"""
        print("\n🧪 Test 1: Load configs success")

        # Crear archivos de prueba
        dashboard_path = self._create_test_dashboard_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente en testing mode
        client = ETCDCryptoClientDashboard(dashboard_path, firewall_path, testing_mode=True)

        # Test carga de configs
        client._load_dashboard_config()
        client._load_firewall_rules_config()

        # Verificar que se cargaron correctamente
        self.assertIsNotNone(client.dashboard_config)
        self.assertIsNotNone(client.firewall_rules_config)
        self.assertIn('etcd_crypto', client.dashboard_config)
        self.assertIn('firewall_rules', client.firewall_rules_config)

        print("✅ Ambas configuraciones cargadas correctamente")

    def test_02_extract_etcd_config_success(self):
        """🧪 Test: Extraer configuración ETCD correctamente"""
        print("\n🧪 Test 2: Extract ETCD config success")

        # Crear archivos de prueba
        dashboard_path = self._create_test_dashboard_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente y cargar configs
        client = ETCDCryptoClientDashboard(dashboard_path, firewall_path, testing_mode=True)
        client._load_dashboard_config()
        client._load_firewall_rules_config()
        client._extract_etcd_config()

        # Verificar extracción ETCD
        self.assertIsNotNone(client.etcd_config)
        self.assertEqual(client.etcd_config.etcd_host, "etcd")
        self.assertEqual(client.etcd_config.etcd_port, 2379)
        self.assertEqual(client.etcd_config.cluster_name, "upgraded-happiness-cluster-v31")
        self.assertEqual(client.etcd_config.node_id, "dashboard_main_v31_etcd_001")

        # Verificar endpoints específicos del dashboard
        self.assertEqual(client.etcd_config.ml_events_input_host, "ml-detector")
        self.assertEqual(client.etcd_config.ml_events_input_port, 5580)
        self.assertEqual(client.etcd_config.web_server_host, "0.0.0.0")
        self.assertEqual(client.etcd_config.web_server_port, 8080)

        print("✅ Configuración ETCD extraída correctamente")

    def test_03_missing_etcd_section_error(self):
        """🧪 Test: Error cuando falta sección etcd_crypto"""
        print("\n🧪 Test 3: Missing etcd_crypto section error")

        # Crear config sin sección etcd_crypto
        dashboard_config = {"node_id": "test", "component": {"name": "test"}}

        fd, temp_path = tempfile.mkstemp(suffix='_bad_dashboard.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(dashboard_config, f)

        firewall_path = self._create_test_firewall_rules()

        try:
            client = ETCDCryptoClientDashboard(temp_path, firewall_path, testing_mode=True)
            client._load_dashboard_config()
            client._load_firewall_rules_config()

            # Debe fallar al extraer config ETCD
            with self.assertRaises(KeyError) as context:
                client._extract_etcd_config()

            self.assertIn("REQUIRED section 'etcd_crypto' not found", str(context.exception))
            print("✅ Error detectado correctamente: falta sección etcd_crypto")

        finally:
            os.unlink(temp_path)

    def test_04_missing_etcd_fields_error(self):
        """🧪 Test: Error cuando faltan campos requeridos en etcd_crypto"""
        print("\n🧪 Test 4: Missing etcd_crypto fields error")

        # Crear config con etcd_crypto incompleta
        dashboard_config = {
            "node_id": "test",
            "etcd_crypto": {
                "etcd_host": "etcd"
                # Faltan: etcd_port, cluster_name, node_id
            }
        }

        fd, temp_path = tempfile.mkstemp(suffix='_incomplete_dashboard.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(dashboard_config, f)

        firewall_path = self._create_test_firewall_rules()

        try:
            client = ETCDCryptoClientDashboard(temp_path, firewall_path, testing_mode=True)
            client._load_dashboard_config()
            client._load_firewall_rules_config()

            # Debe fallar por campos faltantes
            with self.assertRaises(KeyError) as context:
                client._extract_etcd_config()

            self.assertIn("REQUIRED fields missing", str(context.exception))
            print("✅ Error detectado correctamente: campos etcd_crypto faltantes")

        finally:
            os.unlink(temp_path)

    def test_05_build_component_info(self):
        """🧪 Test: Construir información del componente"""
        print("\n🧪 Test 5: Build component info")

        # Crear archivos de prueba
        dashboard_path = self._create_test_dashboard_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente y configurar
        client = ETCDCryptoClientDashboard(dashboard_path, firewall_path, testing_mode=True)
        client._load_dashboard_config()
        client._load_firewall_rules_config()
        client._extract_etcd_config()

        # Construir info del componente
        component_info = client._build_component_info()

        # Verificar estructura
        self.assertEqual(component_info['node_id'], "dashboard_main_v31_etcd_001")
        self.assertEqual(component_info['component_type'], "dashboard_scada")
        self.assertEqual(component_info['crypto_role'], "receiver_sender")
        self.assertEqual(component_info['pipeline_position'], 5)

        # Verificar endpoints
        endpoints = component_info['endpoints']
        self.assertIn('zmq_sub_ml_events', endpoints)
        self.assertIn('zmq_push_fleet_commands', endpoints)
        self.assertIn('zmq_pull_fleet_responses', endpoints)
        self.assertIn('http_web_server', endpoints)

        # Verificar capacidades específicas del dashboard
        capabilities = component_info['capabilities']
        self.assertIn('real_time_visualization', capabilities)
        self.assertIn('fleet_management', capabilities)
        self.assertIn('web_interface', capabilities)
        self.assertIn('crypto_receiver_sender', capabilities)
        self.assertIn('dual_config_registration', capabilities)

        # Verificar performance profile
        self.assertIn('performance_profile', component_info)
        self.assertIn('current_config', component_info)
        self.assertIn('optimization_data', component_info)
        self.assertIn('etcd_data_registration', component_info)

        print("✅ Información del componente construida correctamente")

    def test_06_extract_performance_profile(self):
        """🧪 Test: Extraer perfil de performance"""
        print("\n🧪 Test 6: Extract performance profile")

        # Crear archivos de prueba
        dashboard_path = self._create_test_dashboard_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente y configurar
        client = ETCDCryptoClientDashboard(dashboard_path, firewall_path, testing_mode=True)
        client._load_dashboard_config()
        client._load_firewall_rules_config()

        # Extraer performance profile
        performance_profile = client._extract_performance_profile()

        # Verificar estructura del performance profile
        self.assertIn('zmq_config', performance_profile)
        self.assertIn('processing_config', performance_profile)
        self.assertIn('network_config', performance_profile)
        self.assertIn('web_server_config', performance_profile)
        self.assertIn('firewall_fleet_config', performance_profile)
        self.assertIn('performance_metrics_structure', performance_profile)
        self.assertIn('optimization_targets', performance_profile)

        # Verificar métricas de performance
        metrics = performance_profile['performance_metrics_structure']
        self.assertIn('visualization_latency_ms', metrics)
        self.assertIn('events_per_second', metrics)
        self.assertIn('web_response_time_ms', metrics)
        self.assertIn('fleet_command_latency_ms', metrics)

        print("✅ Performance profile extraído correctamente")

    def test_07_firewall_rules_summary(self):
        """🧪 Test: Extraer resumen de reglas firewall"""
        print("\n🧪 Test 7: Firewall rules summary")

        # Crear archivos de prueba
        dashboard_path = self._create_test_dashboard_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente y configurar
        client = ETCDCryptoClientDashboard(dashboard_path, firewall_path, testing_mode=True)
        client._load_dashboard_config()
        client._load_firewall_rules_config()

        # Extraer resumen de reglas
        rules_summary = client._extract_firewall_rules_summary()

        # Verificar estructura del resumen
        self.assertIn('total_rules', rules_summary)
        self.assertIn('enabled_rules', rules_summary)
        self.assertIn('total_agents', rules_summary)
        self.assertIn('total_manual_actions', rules_summary)
        self.assertIn('rule_coverage', rules_summary)
        self.assertIn('agent_capabilities_summary', rules_summary)
        self.assertIn('rules_by_priority', rules_summary)

        # Verificar valores esperados
        self.assertEqual(rules_summary['total_rules'], 2)  # 2 reglas de test
        self.assertEqual(rules_summary['total_agents'], 1)  # 1 agente de test
        self.assertEqual(rules_summary['total_manual_actions'], 2)  # MONITOR + BLOCK_IP

        print("✅ Resumen de reglas firewall extraído correctamente")

    def test_08_initialize_crypto_testing_mode(self):
        """🧪 Test: Inicialización crypto en testing mode"""
        print("\n🧪 Test 8: Initialize crypto (testing mode)")

        # Crear archivos de prueba
        dashboard_path = self._create_test_dashboard_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente
        client = ETCDCryptoClientDashboard(dashboard_path, firewall_path, testing_mode=True)

        # Test inicialización completa
        result = asyncio.run(client.initialize_crypto())

        self.assertTrue(result)
        self.assertTrue(client.is_crypto_ready())
        self.assertIsNotNone(client.get_pipeline_key())
        self.assertIn('mock_pipeline_key_for_testing_dashboard', client.get_pipeline_key())

        print("✅ Inicialización crypto exitosa en testing mode")

    def test_09_initialize_crypto_disabled_error(self):
        """🧪 Test: Error cuando crypto está disabled en JSON"""
        print("\n🧪 Test 9: Initialize crypto disabled error")

        # Crear config con crypto disabled
        dashboard_config = {
            "node_id": "test_dashboard",
            "component": {"name": "test", "version": "1.0.0"},
            "etcd_crypto": {
                "etcd_host": "etcd",
                "etcd_port": 2379,
                "cluster_name": "test-cluster",
                "node_id": "test_dashboard"
            },
            "crypto": {
                "enabled": False  # Crypto disabled
            }
        }

        fd, temp_dashboard_path = tempfile.mkstemp(suffix='_crypto_disabled.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(dashboard_config, f)

        firewall_path = self._create_test_firewall_rules()

        try:
            client = ETCDCryptoClientDashboard(temp_dashboard_path, firewall_path, testing_mode=True)

            # Debe fallar porque crypto está disabled
            result = asyncio.run(client.initialize_crypto())
            self.assertFalse(result)

            print("✅ Error detectado correctamente: crypto disabled en JSON")

        finally:
            os.unlink(temp_dashboard_path)

    def test_10_public_functions_compatibility(self):
        """🧪 Test: Funciones públicas para compatibilidad"""
        print("\n🧪 Test 10: Public functions compatibility")

        # Crear archivos de prueba
        dashboard_path = self._create_test_dashboard_config()
        firewall_path = self._create_test_firewall_rules()

        # Test setup function
        result = asyncio.run(setup_dashboard_crypto(dashboard_path, firewall_path, testing_mode=True))
        self.assertTrue(result)

        # Test get pipeline key
        pipeline_key = get_dashboard_pipeline_key()
        self.assertIsNotNone(pipeline_key)
        self.assertIn('mock_pipeline_key_for_testing_dashboard', pipeline_key)

        # Test get status
        status = get_dashboard_crypto_status()
        self.assertTrue(status['ready'])
        self.assertTrue(status['testing_mode'])
        self.assertEqual(status['component_type'], 'dashboard_scada')
        self.assertEqual(status['crypto_role'], 'receiver_sender')
        self.assertEqual(status['pipeline_position'], 5)

        # Verificar configuraciones cargadas
        self.assertTrue(status['configs_loaded']['dashboard_config'])
        self.assertTrue(status['configs_loaded']['firewall_rules_config'])

        print("✅ Funciones públicas funcionan correctamente")

    def test_11_json_compatibility_docker_files(self):
        """🧪 Test: Compatibilidad con archivos JSON Docker reales"""
        print("\n🧪 Test 11: JSON compatibility with real Docker files")

        # Simular archivos reales que debería haber generado
        real_dashboard_config = {
            "deployment_metadata": {
                "environment": "docker-compose",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "pod_id": "dashboard-b8c4f6d2k-p7q9m",
                "container_name": "dashboard",
                "deployment_timestamp": "2025-08-29T08:49:07.621Z",
                "config_version": "3.1.0-etcd-integration-docker"
            },
            "node_id": "dashboard_main_v31_etcd_001",
            "component": {
                "name": "dashboard_scada_v31_etcd",
                "version": "3.1.0-etcd-integration",
                "mode": "distributed_monitoring_etcd",
                "role": "dashboard_scada_nogui_etcd"
            },
            "etcd_crypto": {
                "etcd_host": "etcd",
                "etcd_port": 2379,
                "cluster_name": "upgraded-happiness-cluster-v31",
                "node_id": "dashboard_main_v31_etcd_001"
            },
            "network": {
                "ml_events_input": {
                    "address": "ml-detector",
                    "port": 5580,
                    "mode": "connect",
                    "socket_type": "SUB"
                }
            },
            "firewall_fleet": {
                "enabled": True,
                "agents": [
                    {
                        "node_id": "simple_firewall_agent_001",
                        "status": "active",
                        "network_endpoints": {
                            "dashboard_communication": {
                                "commands_input": "tcp://simple-firewall-agent:5583",
                                "responses_output": "tcp://simple-firewall-agent:5584"
                            }
                        }
                    }
                ]
            },
            "web_server": {
                "host": "0.0.0.0",
                "port": 8080,
                "debug": True
            },
            "crypto": {
                "enabled": True,
                "role": "receiver_sender",
                "use_etcd_pipeline_key": True
            },
            "_config_metadata": {
                "config_version": "3.1.0-etcd-integration-docker"
            }
        }

        real_firewall_rules = {
            "deployment_metadata": {
                "environment": "docker",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "container_name": "dashboard"
            },
            "firewall_rules": {
                "version": "1.0.0-RELEASE",
                "description": "RELEASE-1.0.0 - Single source of truth firewall configuration",
                "rules": [
                    {
                        "rule_id": "rule_001_very_low_risk",
                        "risk_range": [0, 19],
                        "action": "LIST_RULES",
                        "priority": "LOW",
                        "enabled": True
                    }
                ],
                "agents_fleet": {
                    "simple_firewall_agent_001": {
                        "node_id": "simple_firewall_agent_001",
                        "version": "3.1.0",
                        "status": "active",
                        "network_endpoints": {
                            "dashboard_communication": {
                                "commands_input": "tcp://firewall-agent-001:5583",
                                "responses_output": "tcp://firewall-agent-001:5584"
                            }
                        },
                        "capabilities": {
                            "allowed_actions": ["MONITOR", "LIST_RULES"]
                        }
                    }
                }
            },
            "_config_metadata": {
                "config_version": "1.0.0-RELEASE-DOCKER"
            }
        }

        # Crear archivos temporales con estructura real
        fd1, temp_dashboard_path = tempfile.mkstemp(suffix='_real_dashboard.json')
        with os.fdopen(fd1, 'w') as f:
            json.dump(real_dashboard_config, f, indent=2)

        fd2, temp_firewall_path = tempfile.mkstemp(suffix='_real_firewall.json')
        with os.fdopen(fd2, 'w') as f:
            json.dump(real_firewall_rules, f, indent=2)

        try:
            # Test con archivos reales
            client = ETCDCryptoClientDashboard(temp_dashboard_path, temp_firewall_path, testing_mode=True)
            result = asyncio.run(client.initialize_crypto())

            self.assertTrue(result)
            self.assertTrue(client.is_crypto_ready())

            # Verificar que puede acceder a campos específicos de Docker
            self.assertEqual(client.dashboard_config['deployment_metadata']['environment'], 'docker-compose')
            self.assertEqual(client.firewall_rules_config['_config_metadata']['config_version'], '1.0.0-RELEASE-DOCKER')

            # Verificar extracción de endpoints
            self.assertEqual(client.etcd_config.ml_events_input_host, "ml-detector")
            self.assertEqual(client.etcd_config.ml_events_input_port, 5580)
            self.assertEqual(client.etcd_config.web_server_port, 8080)

        finally:
            os.unlink(temp_dashboard_path)
            os.unlink(temp_firewall_path)

        print("✅ Compatibilidad con archivos JSON Docker verificada")


def run_dashboard_etcd_compatibility_tests():
    """🎯 Ejecutar todos los tests de compatibilidad"""
    print("🚀 EJECUTANDO TESTS DE COMPATIBILIDAD - DASHBOARD ETCD CLIENT")
    print("=" * 80)

    # Configurar unittest
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestDashboardETCDCompatibility)

    # Ejecutar tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 80)
    if result.wasSuccessful():
        print("✅ TODOS LOS TESTS DE COMPATIBILIDAD PASARON")
        print("🎯 El cliente ETCD puede usar los archivos JSON Docker generados")
        print("📁 dashboard_config_docker.json ✅")
        print("📁 firewall_rules_config_docker.json ✅")
        print("🌐 Web server endpoint: 8080 (expuesto)")
        print("📊 Fleet management: PUB/SUB pattern 5583/5584")
        print("🔐 Crypto role: receiver_sender (pipeline position 5)")
        return True
    else:
        print("❌ ALGUNOS TESTS FALLARON")
        print(f"🔥 Errores: {len(result.errors)}")
        print(f"🔥 Fallas: {len(result.failures)}")
        return False


if __name__ == "__main__":
    success = run_dashboard_etcd_compatibility_tests()
    sys.exit(0 if success else 1)