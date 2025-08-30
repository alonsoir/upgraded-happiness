#!/usr/bin/env python3
"""
tests/test_scheduler_firewall_etcd_compatibility.py
🧪 TEST DE COMPATIBILIDAD - SCHEDULER_FIREWALL ETCD CLIENT
================================================================================
Verifica que el cliente ETCD puede usar los archivos JSON generados para Docker:
- scheduler_firewall_config_docker.json
- firewall_rules_config_docker.json

PATRÓN: Similar a test_ml_detector_etcd_compatibility.py
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

# Importar el cliente ETCD scheduler_firewall
from core.etcd_crypto_client_scheduler_firewall_fixed import (
    ETCDCryptoClientSchedulerFirewall,
    SchedulerFirewallETCDConfig,
    setup_scheduler_firewall_crypto,
    get_scheduler_firewall_pipeline_key,
    get_scheduler_firewall_token,
    get_scheduler_firewall_crypto_status,
    cleanup_scheduler_firewall_crypto
)


class TestSchedulerFirewallETCDCompatibility(unittest.TestCase):
    """🧪 Test de compatibilidad para el cliente ETCD del Scheduler Firewall"""

    def setUp(self):
        """Setup para cada test"""
        self.temp_scheduler_config_file = None
        self.temp_firewall_rules_file = None

        # Configurar logging para tests
        logging.basicConfig(level=logging.WARNING)

        # Limpiar cliente global si existe
        cleanup_scheduler_firewall_crypto()

    def tearDown(self):
        """Cleanup después de cada test"""
        # Limpiar archivos temporales
        if self.temp_scheduler_config_file:
            try:
                os.unlink(self.temp_scheduler_config_file)
            except:
                pass

        if self.temp_firewall_rules_file:
            try:
                os.unlink(self.temp_firewall_rules_file)
            except:
                pass

        # Limpiar cliente global
        cleanup_scheduler_firewall_crypto()

    def _create_test_scheduler_config(self) -> str:
        """Crear archivo temporal con scheduler config válido"""
        scheduler_config = {
            "deployment_metadata": {
                "environment": "docker-compose",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "pod_id": "scheduler-firewall-7c8f9d6b4a-x9m2k",
                "container_name": "scheduler-firewall"
            },
            "node_id": "scheduler_firewall_001",
            "component": {
                "name": "scheduler_firewall_etcd",
                "version": "1.0.0-etcd-integration",
                "mode": "distributed_decision_engine_etcd",
                "role": "firewall_scheduler_nogui_etcd"
            },
            "etcd_crypto": {
                "etcd_host": "etcd",
                "etcd_port": 2379,
                "cluster_name": "upgraded-happiness-cluster-v31",
                "node_id": "scheduler_firewall_001"
            },
            "network": {
                "ml_events_input": {
                    "address": "ml-detector",
                    "port": 5580,
                    "socket_type": "SUB"
                },
                "firewall_commands_output": {
                    "address": "simple-firewall-agent",
                    "port": 5582,
                    "socket_type": "PUSH"
                }
            }
        }

        # Crear archivo temporal
        fd, temp_path = tempfile.mkstemp(suffix='_scheduler_config.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(scheduler_config, f, indent=2)

        self.temp_scheduler_config_file = temp_path
        return temp_path

    def _create_test_firewall_rules(self) -> str:
        """Crear archivo temporal con firewall rules válidas"""
        firewall_rules = {
            "deployment_metadata": {
                "environment": "docker",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "container_name": "scheduler-firewall"
            },
            "firewall_rules": {
                "version": "1.0.0-RELEASE",
                "description": "Test firewall rules",
                "rules": [
                    {
                        "rule_id": "rule_001_test",
                        "risk_range": [0, 19],
                        "action": "LIST_RULES",
                        "priority": "LOW",
                        "dry_run": True,
                        "enabled": True
                    }
                ],
                "manual_actions": {
                    "LIST_RULES": {
                        "description": "Listar reglas - SEGURO",
                        "safety_level": "SAFE",
                        "enabled": True
                    }
                },
                "agents_fleet": {
                    "simple_firewall_agent_001": {
                        "node_id": "simple_firewall_agent_001",
                        "version": "3.1.0",
                        "status": "active",
                        "capabilities": {
                            "allowed_actions": ["MONITOR", "LIST_RULES"],
                            "blocked_actions": ["BLOCK_IP"]
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
        scheduler_path = self._create_test_scheduler_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente
        client = ETCDCryptoClientSchedulerFirewall(scheduler_path, firewall_path)

        # Test carga de configs
        client._load_configs()

        # Verificar que se cargaron correctamente
        self.assertIsNotNone(client.scheduler_config)
        self.assertIsNotNone(client.firewall_rules)
        self.assertIn('etcd_crypto', client.scheduler_config)
        self.assertIn('firewall_rules', client.firewall_rules)

        print("✅ Ambas configuraciones cargadas correctamente")

    def test_02_extract_etcd_config_success(self):
        """🧪 Test: Extraer configuración ETCD correctamente"""
        print("\n🧪 Test 2: Extract ETCD config success")

        # Crear archivos de prueba
        scheduler_path = self._create_test_scheduler_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente y cargar configs
        client = ETCDCryptoClientSchedulerFirewall(scheduler_path, firewall_path)
        client._load_configs()
        client._extract_etcd_config()

        # Verificar extracción ETCD
        self.assertIsNotNone(client.etcd_config)
        self.assertEqual(client.etcd_config.etcd_host, "etcd")
        self.assertEqual(client.etcd_config.etcd_port, 2379)
        self.assertEqual(client.etcd_config.cluster_name, "upgraded-happiness-cluster-v31")
        self.assertEqual(client.etcd_config.node_id, "scheduler_firewall_001")

        print("✅ Configuración ETCD extraída correctamente")

    def test_03_missing_etcd_section_error(self):
        """🧪 Test: Error cuando falta sección etcd_crypto"""
        print("\n🧪 Test 3: Missing etcd_crypto section error")

        # Crear config sin sección etcd_crypto
        scheduler_config = {"node_id": "test", "component": {"name": "test"}}

        fd, temp_path = tempfile.mkstemp(suffix='_bad_scheduler.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(scheduler_config, f)

        firewall_path = self._create_test_firewall_rules()

        try:
            client = ETCDCryptoClientSchedulerFirewall(temp_path, firewall_path)
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
        scheduler_config = {
            "node_id": "test",
            "etcd_crypto": {
                "etcd_host": "etcd"
                # Faltan: etcd_port, cluster_name, node_id
            }
        }

        fd, temp_path = tempfile.mkstemp(suffix='_incomplete_scheduler.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(scheduler_config, f)

        firewall_path = self._create_test_firewall_rules()

        try:
            client = ETCDCryptoClientSchedulerFirewall(temp_path, firewall_path)
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
        scheduler_path = self._create_test_scheduler_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente y configurar
        client = ETCDCryptoClientSchedulerFirewall(scheduler_path, firewall_path)
        client._load_configs()
        client._extract_etcd_config()

        # Generar token
        client._generate_rotative_token()

        # Verificar token
        self.assertIsNotNone(client.crypto_token)
        self.assertIn('key', client.crypto_token)
        self.assertIn('token_data', client.crypto_token)
        self.assertIn('hash', client.crypto_token)
        self.assertIn('scheduler_firewall', client.crypto_token['key'])

        # Verificar datos del token
        token_data = client.crypto_token['token_data']
        self.assertEqual(token_data['component'], 'scheduler_firewall')
        self.assertEqual(token_data['node_id'], 'scheduler_firewall_001')
        self.assertIn('scheduler', token_data['permissions'])
        self.assertIn('firewall', token_data['permissions'])

        print("✅ Token rotativo generado correctamente")

    @patch('etcd3.client')
    def test_06_register_configs_in_etcd_mock(self, mock_etcd_client):
        """🧪 Test: Registrar configuraciones en ETCD (mock)"""
        print("\n🧪 Test 6: Register configs in ETCD (mock)")

        # Configurar mock
        mock_client_instance = Mock()
        mock_etcd_client.return_value = mock_client_instance

        # Crear archivos de prueba
        scheduler_path = self._create_test_scheduler_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente y configurar
        client = ETCDCryptoClientSchedulerFirewall(scheduler_path, firewall_path)
        client._load_configs()
        client._extract_etcd_config()

        # Test registro en ETCD
        asyncio.run(client._register_configs_in_etcd())

        # Verificar que se llamó put() dos veces (scheduler + firewall)
        self.assertEqual(mock_client_instance.put.call_count, 2)

        # Verificar las claves usadas
        calls = mock_client_instance.put.call_args_list

        # Primera llamada: scheduler config
        scheduler_key = calls[0][0][0]
        scheduler_data = json.loads(calls[0][0][1])
        self.assertIn('/scheduler_firewall/config', scheduler_key)
        self.assertEqual(scheduler_data['config_type'], 'scheduler_firewall_config')

        # Segunda llamada: firewall rules
        firewall_key = calls[1][0][0]
        firewall_data = json.loads(calls[1][0][1])
        self.assertIn('/scheduler_firewall/rules', firewall_key)
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
        scheduler_path = self._create_test_scheduler_config()
        firewall_path = self._create_test_firewall_rules()

        # Crear cliente
        client = ETCDCryptoClientSchedulerFirewall(scheduler_path, firewall_path)

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
        scheduler_path = self._create_test_scheduler_config()
        firewall_path = self._create_test_firewall_rules()

        with patch('etcd3.client') as mock_etcd_client:
            mock_client_instance = Mock()
            mock_etcd_client.return_value = mock_client_instance

            # Crear cliente e inicializar
            client = ETCDCryptoClientSchedulerFirewall(scheduler_path, firewall_path)
            asyncio.run(client.initialize_crypto())

            # Obtener status
            status = client.get_status()

            # Verificar estructura del status
            self.assertEqual(status['component'], 'scheduler_firewall')
            self.assertTrue(status['crypto_ready'])
            self.assertTrue(status['configs_loaded']['scheduler_config'])
            self.assertTrue(status['configs_loaded']['firewall_rules'])

            # Verificar etcd_config
            etcd_config = status['etcd_config']
            self.assertEqual(etcd_config['host'], 'etcd')
            self.assertEqual(etcd_config['port'], 2379)
            self.assertEqual(etcd_config['cluster'], 'upgraded-happiness-cluster-v31')
            self.assertEqual(etcd_config['node_id'], 'scheduler_firewall_001')

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
        scheduler_path = self._create_test_scheduler_config()
        firewall_path = self._create_test_firewall_rules()

        # Test setup function
        result = asyncio.run(setup_scheduler_firewall_crypto(scheduler_path, firewall_path))
        self.assertTrue(result)

        # Test get pipeline key
        pipeline_key = get_scheduler_firewall_pipeline_key()
        self.assertIsNotNone(pipeline_key)
        self.assertIn('scheduler_firewall_key_', pipeline_key)

        # Test get token
        token = get_scheduler_firewall_token()
        self.assertIsNotNone(token)

        # Test get status
        status = get_scheduler_firewall_crypto_status()
        self.assertEqual(status['component'], 'scheduler_firewall')
        self.assertTrue(status['crypto_ready'])

        # Test cleanup
        cleanup_scheduler_firewall_crypto()

        # Verificar cleanup
        pipeline_key_after = get_scheduler_firewall_pipeline_key()
        self.assertIsNone(pipeline_key_after)

        print("✅ Funciones públicas funcionan correctamente")

    def test_10_json_compatibility_docker_files(self):
        """🧪 Test: Compatibilidad con archivos JSON Docker reales"""
        print("\n🧪 Test 10: JSON compatibility with real Docker files")

        # Simular archivos reales que debería haber generado
        real_scheduler_config = {
            "deployment_metadata": {
                "environment": "docker-compose",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "pod_id": "scheduler-firewall-7c8f9d6b4a-x9m2k",
                "container_name": "scheduler-firewall",
                "deployment_timestamp": "2025-08-29T08:45:23.156Z",
                "config_version": "1.0.0-etcd-integration-docker"
            },
            "node_id": "scheduler_firewall_001",
            "component": {
                "name": "scheduler_firewall_etcd",
                "version": "1.0.0-etcd-integration",
                "mode": "distributed_decision_engine_etcd"
            },
            "etcd_crypto": {
                "etcd_host": "etcd",
                "etcd_port": 2379,
                "cluster_name": "upgraded-happiness-cluster-v31",
                "node_id": "scheduler_firewall_001"
            },
            "crypto": {
                "enabled": True,
                "use_etcd_pipeline_key": True
            }
        }

        real_firewall_rules = {
            "deployment_metadata": {
                "environment": "docker",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "container_name": "scheduler-firewall"
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
                        "dry_run": True,
                        "enabled": True
                    }
                ],
                "agents_fleet": {
                    "simple_firewall_agent_001": {
                        "node_id": "simple_firewall_agent_001",
                        "version": "3.1.0",
                        "network_endpoints": {
                            "scheduler_communication": {
                                "commands_input": "tcp://firewall-agent-001:5582",
                                "responses_output": "tcp://firewall-agent-001:5581"
                            }
                        }
                    }
                },
                "global_settings": {
                    "security": {
                        "development_mode": True
                    }
                }
            },
            "_config_metadata": {
                "config_version": "1.0.0-RELEASE-DOCKER",
                "compatible_orchestrators": ["docker", "k8s", "k3s", "podman"]
            }
        }

        # Crear archivos temporales con estructura real
        fd1, temp_scheduler_path = tempfile.mkstemp(suffix='_real_scheduler.json')
        with os.fdopen(fd1, 'w') as f:
            json.dump(real_scheduler_config, f, indent=2)

        fd2, temp_firewall_path = tempfile.mkstemp(suffix='_real_firewall.json')
        with os.fdopen(fd2, 'w') as f:
            json.dump(real_firewall_rules, f, indent=2)

        try:
            with patch('etcd3.client') as mock_etcd_client:
                mock_client_instance = Mock()
                mock_etcd_client.return_value = mock_client_instance

                # Test con archivos reales
                client = ETCDCryptoClientSchedulerFirewall(temp_scheduler_path, temp_firewall_path)
                result = asyncio.run(client.initialize_crypto())

                self.assertTrue(result)
                self.assertTrue(client.is_crypto_ready())

                # Verificar que puede acceder a campos específicos de Docker
                self.assertEqual(client.scheduler_config['deployment_metadata']['environment'], 'docker-compose')
                self.assertEqual(client.firewall_rules['_config_metadata']['config_version'], '1.0.0-RELEASE-DOCKER')

                client.cleanup()

        finally:
            os.unlink(temp_scheduler_path)
            os.unlink(temp_firewall_path)

        print("✅ Compatibilidad con archivos JSON Docker verificada")


def run_scheduler_firewall_etcd_compatibility_tests():
    """🎯 Ejecutar todos los tests de compatibilidad"""
    print("🚀 EJECUTANDO TESTS DE COMPATIBILIDAD - SCHEDULER_FIREWALL ETCD CLIENT")
    print("=" * 80)

    # Configurar unittest
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestSchedulerFirewallETCDCompatibility)

    # Ejecutar tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 80)
    if result.wasSuccessful():
        print("✅ TODOS LOS TESTS DE COMPATIBILIDAD PASARON")
        print("🎯 El cliente ETCD puede usar los archivos JSON Docker generados")
        print("📁 scheduler_firewall_config_docker.json ✅")
        print("📁 firewall_rules_config_docker.json ✅")
        return True
    else:
        print("❌ ALGUNOS TESTS FALLARON")
        print(f"🔥 Errores: {len(result.errors)}")
        print(f"🔥 Fallas: {len(result.failures)}")
        return False


if __name__ == "__main__":
    success = run_scheduler_firewall_etcd_compatibility_tests()
    sys.exit(0 if success else 1)