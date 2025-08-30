#!/usr/bin/env python3
"""
tests/test_simple_firewall_agent_etcd_compatibility.py
🧪 TEST DE COMPATIBILIDAD - SIMPLE_FIREWALL_AGENT ETCD CLIENT
================================================================================
Verifica que el cliente ETCD puede usar los archivos JSON generados para Docker:
- simple_firewall_agent_config_docker.json
- firewall_rules_config_docker.json (compartido con scheduler)

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

# Importar el cliente ETCD simple_firewall_agent
from core.etcd_crypto_client_simple_firewall_agent_fixed import (
    ETCDCryptoClientSimpleFirewallAgent,
    SimpleFirewallAgentETCDConfig,
    setup_simple_firewall_agent_crypto,
    get_simple_firewall_agent_pipeline_key,
    get_simple_firewall_agent_token,
    get_simple_firewall_agent_crypto_status,
    cleanup_simple_firewall_agent_crypto
)


class TestSimpleFirewallAgentETCDCompatibility(unittest.TestCase):
    """🧪 Test de compatibilidad para el cliente ETCD del Simple Firewall Agent"""

    def setUp(self):
        """Setup para cada test"""
        self.temp_agent_config_file = None
        self.temp_firewall_rules_file = None

        # Configurar logging para tests
        logging.basicConfig(level=logging.WARNING)

        # Limpiar cliente global si existe
        cleanup_simple_firewall_agent_crypto()

    def tearDown(self):
        """Cleanup después de cada test"""
        # Limpiar archivos temporales
        if self.temp_agent_config_file:
            try:
                os.unlink(self.temp_agent_config_file)
            except:
                pass

        if self.temp_firewall_rules_file:
            try:
                os.unlink(self.temp_firewall_rules_file)
            except:
                pass

        # Limpiar cliente global
        cleanup_simple_firewall_agent_crypto()

    def _create_test_agent_config(self) -> str:
        """Crear archivo temporal con agent config válido"""
        agent_config = {
            "deployment_metadata": {
                "environment": "docker-compose",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "pod_id": "simple-firewall-agent-9k4j7h2b-w8x5z",
                "container_name": "simple-firewall-agent"
            },
            "node_id": "simple_firewall_agent_001",
            "component": {
                "name": "simple_firewall_agent_v31_etcd",
                "version": "1.0.0-etcd-integration",
                "mode": "distributed_agent_etcd",
                "role": "simple_firewall_agent_nogui_etcd_dual"
            },
            "etcd_crypto": {
                "etcd_host": "etcd",
                "etcd_port": 2379,
                "cluster_name": "upgraded-happiness-cluster-v31",
                "node_id": "simple_firewall_agent_001"
            },
            "network": {
                "scheduler_commands": {
                    "address": "0.0.0.0",
                    "port": 5582,
                    "socket_type": "PULL"
                },
                "scheduler_responses": {
                    "address": "scheduler-firewall",
                    "port": 5581,
                    "socket_type": "PUSH"
                }
            },
            "crypto": {
                "enabled": True,
                "use_etcd_pipeline_key": True
            }
        }

        # Crear archivo temporal
        fd, temp_path = tempfile.mkstemp(suffix='_agent_config.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(agent_config, f, indent=2)

        self.temp_agent_config_file = temp_path
        return temp_path

    def _create_test_firewall_rules(self) -> str:
        """Crear archivo temporal con firewall rules válidas"""
        firewall_rules = {
            "deployment_metadata": {
                "environment": "docker",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "container_name": "simple-firewall-agent"
            },
            "firewall_rules": {
                "version": "1.0.0-RELEASE",
                "description": "Test firewall rules for agent",
                "rules": [
                    {
                        "rule_id": "rule_001_agent_test",
                        "risk_range": [0, 19],
                        "action": "MONITOR",
                        "priority": "LOW",
                        "dry_run": True,
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
                        "enabled": False
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
        agent_path = self._create_test_agent_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente
        client = ETCDCryptoClientSimpleFirewallAgent(agent_path, firewall_path)

        # Test carga de configs
        client._load_configs()

        # Verificar que se cargaron correctamente
        self.assertIsNotNone(client.agent_config)
        self.assertIsNotNone(client.firewall_rules)
        self.assertIn('etcd_crypto', client.agent_config)
        self.assertIn('firewall_rules', client.firewall_rules)

        print("✅ Ambas configuraciones cargadas correctamente")

    def test_02_extract_etcd_config_success(self):
        """🧪 Test: Extraer configuración ETCD correctamente"""
        print("\n🧪 Test 2: Extract ETCD config success")

        # Crear archivos de prueba
        agent_path = self._create_test_agent_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente y cargar configs
        client = ETCDCryptoClientSimpleFirewallAgent(agent_path, firewall_path)
        client._load_configs()
        client._extract_etcd_config()

        # Verificar extracción ETCD
        self.assertIsNotNone(client.etcd_config)
        self.assertEqual(client.etcd_config.etcd_host, "etcd")
        self.assertEqual(client.etcd_config.etcd_port, 2379)
        self.assertEqual(client.etcd_config.cluster_name, "upgraded-happiness-cluster-v31")
        self.assertEqual(client.etcd_config.node_id, "simple_firewall_agent_001")

        print("✅ Configuración ETCD extraída correctamente")

    def test_03_missing_etcd_section_error(self):
        """🧪 Test: Error cuando falta sección etcd_crypto"""
        print("\n🧪 Test 3: Missing etcd_crypto section error")

        # Crear config sin sección etcd_crypto
        agent_config = {"node_id": "test", "component": {"name": "test"}}

        fd, temp_path = tempfile.mkstemp(suffix='_bad_agent.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(agent_config, f)

        firewall_path = self._create_test_firewall_rules()

        try:
            client = ETCDCryptoClientSimpleFirewallAgent(temp_path, firewall_path)
            client._load_configs()

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
        agent_config = {
            "node_id": "test",
            "etcd_crypto": {
                "etcd_host": "etcd"
                # Faltan: etcd_port, cluster_name, node_id
            }
        }

        fd, temp_path = tempfile.mkstemp(suffix='_incomplete_agent.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(agent_config, f)

        firewall_path = self._create_test_firewall_rules()

        try:
            client = ETCDCryptoClientSimpleFirewallAgent(temp_path, firewall_path)
            client._load_configs()

            # Debe fallar por campos faltantes
            with self.assertRaises(KeyError) as context:
                client._extract_etcd_config()

            self.assertIn("REQUIRED fields missing", str(context.exception))
            print("✅ Error detectado correctamente: campos etcd_crypto faltantes")

        finally:
            os.unlink(temp_path)

    def test_05_generate_rotative_token(self):
        """🧪 Test: Generar token rotativo"""
        print("\n🧪 Test 5: Generate rotative token")

        # Crear archivos de prueba
        agent_path = self._create_test_agent_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente y configurar
        client = ETCDCryptoClientSimpleFirewallAgent(agent_path, firewall_path)
        client._load_configs()
        client._extract_etcd_config()

        # Generar token
        client._generate_rotative_token()

        # Verificar token
        self.assertIsNotNone(client.crypto_token)
        self.assertIn('key', client.crypto_token)
        self.assertIn('token_data', client.crypto_token)
        self.assertIn('hash', client.crypto_token)
        self.assertIn('simple_firewall_agent', client.crypto_token['key'])

        # Verificar datos del token
        token_data = client.crypto_token['token_data']
        self.assertEqual(token_data['component'], 'simple_firewall_agent')
        self.assertEqual(token_data['node_id'], 'simple_firewall_agent_001')
        self.assertIn('firewall', token_data['permissions'])
        self.assertIn('agent', token_data['permissions'])
        self.assertIn('execute', token_data['permissions'])

        print("✅ Token rotativo generado correctamente")

    @patch('etcd3.client')
    def test_06_register_configs_in_etcd_mock(self, mock_etcd_client):
        """🧪 Test: Registrar configuraciones en ETCD (mock)"""
        print("\n🧪 Test 6: Register configs in ETCD (mock)")

        # Configurar mock
        mock_client_instance = Mock()
        mock_etcd_client.return_value = mock_client_instance

        # Crear archivos de prueba
        agent_path = self._create_test_agent_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente y configurar
        client = ETCDCryptoClientSimpleFirewallAgent(agent_path, firewall_path)
        client._load_configs()
        client._extract_etcd_config()

        # Test registro en ETCD
        asyncio.run(client._register_configs_in_etcd())

        # Verificar que se llamó put() dos veces (agent + firewall)
        self.assertEqual(mock_client_instance.put.call_count, 2)

        # Verificar las claves usadas
        calls = mock_client_instance.put.call_args_list

        # Primera llamada: agent config
        agent_key = calls[0][0][0]
        agent_data = json.loads(calls[0][0][1])
        self.assertIn('/simple_firewall_agent/config', agent_key)
        self.assertEqual(agent_data['config_type'], 'simple_firewall_agent_config')

        # Segunda llamada: firewall rules
        firewall_key = calls[1][0][0]
        firewall_data = json.loads(calls[1][0][1])
        self.assertIn('/simple_firewall_agent/rules', firewall_key)
        self.assertEqual(firewall_data['config_type'], 'firewall_rules')

        print("✅ Configuraciones registradas en ETCD correctamente")

    @patch('etcd3.client')
    def test_07_full_initialization_mock(self, mock_etcd_client):
        """🧪 Test: Inicialización completa con mock"""
        print("\n🧪 Test 7: Full initialization (mock)")

        # Configurar mock
        mock_client_instance = Mock()
        mock_etcd_client.return_value = mock_client_instance

        # Crear archivos de prueba
        agent_path = self._create_test_agent_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente
        client = ETCDCryptoClientSimpleFirewallAgent(agent_path, firewall_path)

        # Test inicialización completa
        result = asyncio.run(client.initialize_crypto())

        self.assertTrue(result)
        self.assertTrue(client.is_crypto_ready())
        self.assertIsNotNone(client.get_pipeline_key())
        self.assertIsNotNone(client.get_current_token())

        # Verificar que el thread de rotación está activo
        self.assertIsNotNone(client.token_rotation_thread)
        self.assertTrue(client.token_rotation_thread.is_alive())

        # Limpiar
        client.cleanup()

        print("✅ Inicialización completa exitosa")

    def test_08_get_status_complete(self):
        """🧪 Test: Obtener status completo"""
        print("\n🧪 Test 8: Get complete status")

        # Crear archivos de prueba
        agent_path = self._create_test_agent_config()
        firewall_path = self._create_test_firewall_rules()

        with patch('etcd3.client') as mock_etcd_client:
            mock_client_instance = Mock()
            mock_etcd_client.return_value = mock_client_instance

            # Crear cliente e inicializar
            client = ETCDCryptoClientSimpleFirewallAgent(agent_path, firewall_path)
            asyncio.run(client.initialize_crypto())

            # Obtener status
            status = client.get_status()

            # Verificar estructura del status
            self.assertEqual(status['component'], 'simple_firewall_agent')
            self.assertTrue(status['crypto_ready'])
            self.assertTrue(status['configs_loaded']['agent_config'])
            self.assertTrue(status['configs_loaded']['firewall_rules'])

            # Verificar etcd_config
            etcd_config = status['etcd_config']
            self.assertEqual(etcd_config['host'], 'etcd')
            self.assertEqual(etcd_config['port'], 2379)
            self.assertEqual(etcd_config['cluster'], 'upgraded-happiness-cluster-v31')
            self.assertEqual(etcd_config['node_id'], 'simple_firewall_agent_001')

            # Verificar token_info
            token_info = status['token_info']
            self.assertIsNotNone(token_info['version'])
            self.assertIsNotNone(token_info['created_at'])
            self.assertTrue(status['rotation_active'])

            client.cleanup()

        print("✅ Status completo obtenido correctamente")

    @patch('etcd3.client')
    def test_09_public_functions_compatibility(self, mock_etcd_client):
        """🧪 Test: Funciones públicas para compatibilidad"""
        print("\n🧪 Test 9: Public functions compatibility")

        # Configurar mock
        mock_client_instance = Mock()
        mock_etcd_client.return_value = mock_client_instance

        # Crear archivos de prueba
        agent_path = self._create_test_agent_config()
        firewall_path = self._create_test_firewall_rules()

        # Test setup function
        result = asyncio.run(setup_simple_firewall_agent_crypto(agent_path, firewall_path))
        self.assertTrue(result)

        # Test get pipeline key
        pipeline_key = get_simple_firewall_agent_pipeline_key()
        self.assertIsNotNone(pipeline_key)
        self.assertIn('simple_firewall_agent_key_', pipeline_key)

        # Test get token
        token = get_simple_firewall_agent_token()
        self.assertIsNotNone(token)

        # Test get status
        status = get_simple_firewall_agent_crypto_status()
        self.assertEqual(status['component'], 'simple_firewall_agent')
        self.assertTrue(status['crypto_ready'])

        # Test cleanup
        cleanup_simple_firewall_agent_crypto()

        # Verificar cleanup
        pipeline_key_after = get_simple_firewall_agent_pipeline_key()
        self.assertIsNone(pipeline_key_after)

        print("✅ Funciones públicas funcionan correctamente")

    def test_10_json_compatibility_docker_files(self):
        """🧪 Test: Compatibilidad con archivos JSON Docker reales"""
        print("\n🧪 Test 10: JSON compatibility with real Docker files")

        # Simular archivos reales que debería haber generado
        real_agent_config = {
            "deployment_metadata": {
                "environment": "docker-compose",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "pod_id": "simple-firewall-agent-9k4j7h2b-w8x5z",
                "container_name": "simple-firewall-agent",
                "deployment_timestamp": "2025-08-29T08:47:12.384Z",
                "config_version": "1.0.0-etcd-integration-docker"
            },
            "node_id": "simple_firewall_agent_001",
            "component": {
                "name": "simple_firewall_agent_v31_etcd",
                "version": "1.0.0-etcd-integration",
                "mode": "distributed_agent_etcd",
                "role": "simple_firewall_agent_nogui_etcd_dual"
            },
            "etcd_crypto": {
                "etcd_host": "etcd",
                "etcd_port": 2379,
                "cluster_name": "upgraded-happiness-cluster-v31",
                "node_id": "simple_firewall_agent_001"
            },
            "network": {
                "scheduler_commands": {
                    "address": "0.0.0.0",
                    "port": 5582,
                    "mode": "bind",
                    "socket_type": "PULL"
                },
                "scheduler_responses": {
                    "address": "scheduler-firewall",
                    "port": 5581,
                    "mode": "connect",
                    "socket_type": "PUSH"
                }
            },
            "crypto": {
                "enabled": True,
                "role": "receiver_sender_dual",
                "use_etcd_pipeline_key": True
            }
        }

        real_firewall_rules = {
            "deployment_metadata": {
                "environment": "docker",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "container_name": "simple-firewall-agent"
            },
            "firewall_rules": {
                "version": "1.0.0-RELEASE",
                "description": "RELEASE-1.0.0 - Single source of truth firewall configuration",
                "agents_fleet": {
                    "simple_firewall_agent_001": {
                        "node_id": "simple_firewall_agent_001",
                        "version": "3.1.0",
                        "location": "zona_dmz_001",
                        "status": "active",
                        "network_endpoints": {
                            "scheduler_communication": {
                                "commands_input": "tcp://firewall-agent-001:5582",
                                "responses_output": "tcp://firewall-agent-001:5581"
                            },
                            "dashboard_communication": {
                                "commands_input": "tcp://firewall-agent-001:5580",
                                "responses_output": "tcp://firewall-agent-001:5584"
                            }
                        },
                        "capabilities": {
                            "allowed_actions": ["MONITOR", "LIST_RULES"],
                            "blocked_actions": ["BLOCK_IP", "RATE_LIMIT", "FLUSH_RULES"]
                        }
                    }
                }
            },
            "_config_metadata": {
                "config_version": "1.0.0-RELEASE-DOCKER",
                "compatible_orchestrators": ["docker", "k8s", "k3s", "podman"]
            }
        }

        # Crear archivos temporales con estructura real
        fd1, temp_agent_path = tempfile.mkstemp(suffix='_real_agent.json')
        with os.fdopen(fd1, 'w') as f:
            json.dump(real_agent_config, f, indent=2)

        fd2, temp_firewall_path = tempfile.mkstemp(suffix='_real_firewall.json')
        with os.fdopen(fd2, 'w') as f:
            json.dump(real_firewall_rules, f, indent=2)

        try:
            with patch('etcd3.client') as mock_etcd_client:
                mock_client_instance = Mock()
                mock_etcd_client.return_value = mock_client_instance

                # Test con archivos reales
                client = ETCDCryptoClientSimpleFirewallAgent(temp_agent_path, temp_firewall_path)
                result = asyncio.run(client.initialize_crypto())

                self.assertTrue(result)
                self.assertTrue(client.is_crypto_ready())

                # Verificar que puede acceder a campos específicos de Docker
                self.assertEqual(client.agent_config['deployment_metadata']['environment'], 'docker-compose')
                self.assertEqual(client.firewall_rules['_config_metadata']['config_version'], '1.0.0-RELEASE-DOCKER')

                client.cleanup()

        finally:
            os.unlink(temp_agent_path)
            os.unlink(temp_firewall_path)

        print("✅ Compatibilidad con archivos JSON Docker verificada")


def run_simple_firewall_agent_etcd_compatibility_tests():
    """🎯 Ejecutar todos los tests de compatibilidad"""
    print("🚀 EJECUTANDO TESTS DE COMPATIBILIDAD - SIMPLE_FIREWALL_AGENT ETCD CLIENT")
    print("=" * 80)

    # Configurar unittest
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestSimpleFirewallAgentETCDCompatibility)

    # Ejecutar tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 80)
    if result.wasSuccessful():
        print("✅ TODOS LOS TESTS DE COMPATIBILIDAD PASARON")
        print("🎯 El cliente ETCD puede usar los archivos JSON Docker generados")
        print("📁 simple_firewall_agent_config_docker.json ✅")
        print("📁 firewall_rules_config_docker.json ✅")
        return True
    else:
        print("❌ ALGUNOS TESTS FALLARON")
        print(f"🔥 Errores: {len(result.errors)}")
        print(f"🔥 Fallas: {len(result.failures)}")
        return False


if __name__ == "__main__":
    success = run_simple_firewall_agent_etcd_compatibility_tests()
    sys.exit(0 if success else 1)