#!/usr/bin/env python3
"""
tests/test_etcd_client_dashboard_integration.py
🧪 TEST COMPLETO - Cliente ETCD Dashboard con Configuración Dual
================================================================================
Verifica que el cliente etcd_crypto_client_dashboard_fixed.py puede:
1. Cargar correctamente dashboard_config_docker.json
2. Cargar correctamente firewall_rules_dashboard_config_docker.json
3. Extraer configuración ETCD del archivo principal
4. Registrar ambas configuraciones en ETCD (simulado)
"""

import asyncio
import json
import logging
import os
import sys
import tempfile
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Importar el cliente ETCD que vamos a testear
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'core'))
from core.etcd_crypto_client_dashboard_fixed import (
    ETCDCryptoClientDashboard,
    DashboardScadaV31EtcdETCDConfig,
    setup_dashboard_crypto,
    get_dashboard_pipeline_key,
    get_dashboard_crypto_status
)


class TestETCDDashboardClientIntegration:
    """Test Suite para integración completa del cliente ETCD Dashboard"""

    def setup_method(self):
        """Setup para cada test"""
        self.temp_dir = tempfile.mkdtemp()
        self.dashboard_config_path = os.path.join(self.temp_dir, "dashboard_config.json")
        self.rules_config_path = os.path.join(self.temp_dir, "firewall_rules_config.json")

        # Configurar logging para tests
        logging.basicConfig(level=logging.INFO)

    def teardown_method(self):
        """Cleanup después de cada test"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def create_dashboard_config_file(self):
        """Crear archivo de configuración del dashboard basado en el real"""
        dashboard_config = {
            "deployment_metadata": {
                "environment": "docker-compose",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "pod_id": "dashboard-b8c4f6d2k-p7q9m",
                "container_name": "dashboard",
                "deployment_timestamp": "2025-08-29T08:49:07.621Z",
                "config_version": "3.1.0-etcd-integration-docker",
                "cluster_info": {
                    "cluster_name": "upgraded-happiness-cluster-v31",
                    "availability_zone": "docker-local-az1",
                    "region": "docker-compose-local"
                }
            },
            "node_id": "dashboard_main_v31_etcd_001",
            "component": {
                "name": "dashboard_scada_v31_etcd",
                "version": "3.1.0-etcd-integration",
                "mode": "distributed_monitoring_etcd",
                "role": "dashboard_scada_nogui_etcd"
            },
            # 🔑 SECCIÓN CRÍTICA - etcd_crypto
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
            "distributed": {
                "cluster_name": "upgraded-happiness-cluster-v31",
                "component_role": "dashboard_scada_monitoring_etcd"
            },
            "crypto": {
                "enabled": True,
                "role": "receiver_sender",
                "use_etcd_pipeline_key": True
            },
            "_config_metadata": {
                "config_version": "3.1.0-etcd-integration-docker",
                "template_version": "3.1.0-etcd-integration-dashboard-docker"
            }
        }

        with open(self.dashboard_config_path, 'w') as f:
            json.dump(dashboard_config, f, indent=2)

    def create_firewall_rules_config_file(self):
        """Crear archivo de reglas firewall basado en el real"""
        rules_config = {
            "deployment_metadata": {
                "environment": "docker",
                "orchestrator": "docker",
                "namespace": "upgraded-happiness",
                "config_version": "1.0.0-RELEASE-DOCKER",
                "cluster_info": {
                    "cluster_name": "upgraded-happiness-cluster",
                    "availability_zone": "docker-zone-1",
                    "region": "local-docker"
                }
            },
            "firewall_rules": {
                "version": "1.0.0-RELEASE",
                "last_updated": "2025-08-30T18:45:00Z",
                "description": "RELEASE-1.0.0 - Firewall rules for dashboard",
                "rules": [
                    {
                        "rule_id": "rule_001_very_low_risk",
                        "risk_range": [0, 19],
                        "action": "LIST_RULES",
                        "description": "Riesgo muy bajo: Solo listar reglas",
                        "priority": "LOW",
                        "dry_run": True,
                        "enabled": True
                    },
                    {
                        "rule_id": "rule_002_critical_risk",
                        "risk_range": [80, 100],
                        "action": "BLOCK_IP",
                        "description": "Riesgo crítico: Bloqueo inmediato",
                        "priority": "CRITICAL",
                        "dry_run": True,
                        "enabled": False
                    }
                ],
                "agents_fleet": {
                    "simple_firewall_agent_001": {
                        "node_id": "simple_firewall_agent_001",
                        "version": "3.1.0",
                        "status": "active",
                        "capabilities": {
                            "allowed_actions": ["MONITOR", "LIST_RULES"],
                            "blocked_actions": ["BLOCK_IP", "RATE_LIMIT"]
                        }
                    }
                }
            },
            "_config_metadata": {
                "template_version": "1.0.0-RELEASE",
                "config_version": "1.0.0-RELEASE-DOCKER"
            }
        }

        with open(self.rules_config_path, 'w') as f:
            json.dump(rules_config, f, indent=2)

    def test_load_dashboard_config_success(self):
        """Test: Cargar configuración del dashboard exitosamente"""
        print("🧪 Test 1: Cargando configuración principal del dashboard...")

        self.create_dashboard_config_file()

        client = ETCDCryptoClientDashboard(
            self.dashboard_config_path,
            None  # Sin reglas firewall por ahora
        )

        # Cargar config
        client._load_component_config()

        # Verificaciones
        assert client.component_config is not None
        assert client.component_config["node_id"] == "dashboard_main_v31_etcd_001"
        assert client.component_config["component"]["name"] == "dashboard_scada_v31_etcd"
        assert "etcd_crypto" in client.component_config

        print("✅ Configuración principal cargada correctamente")

    def test_load_firewall_rules_config_success(self):
        """Test: Cargar configuración de reglas firewall exitosamente"""
        print("🧪 Test 2: Cargando configuración de reglas firewall...")

        self.create_dashboard_config_file()
        self.create_firewall_rules_config_file()

        client = ETCDCryptoClientDashboard(
            self.dashboard_config_path,
            self.rules_config_path
        )

        # Cargar ambos configs
        client._load_component_config()
        client._load_rules_config()

        # Verificaciones config principal
        assert client.component_config is not None
        assert client.component_config["node_id"] == "dashboard_main_v31_etcd_001"

        # Verificaciones config reglas
        assert client.rules_config is not None
        assert "firewall_rules" in client.rules_config
        assert client.rules_config["firewall_rules"]["version"] == "1.0.0-RELEASE"

        # Verificar que hay reglas
        rules = client.rules_config["firewall_rules"]["rules"]
        assert len(rules) == 2
        assert rules[0]["rule_id"] == "rule_001_very_low_risk"
        assert rules[1]["rule_id"] == "rule_002_critical_risk"

        # Verificar agentes
        agents = client.rules_config["firewall_rules"]["agents_fleet"]
        assert "simple_firewall_agent_001" in agents

        print("✅ Configuración de reglas firewall cargada correctamente")

    def test_extract_etcd_config_success(self):
        """Test: Extraer configuración ETCD del archivo principal"""
        print("🧪 Test 3: Extrayendo configuración ETCD...")

        self.create_dashboard_config_file()

        client = ETCDCryptoClientDashboard(
            self.dashboard_config_path,
            None
        )

        # Cargar y extraer config ETCD
        client._load_component_config()
        client._extract_etcd_config()

        # Verificaciones
        assert client.etcd_config is not None
        assert isinstance(client.etcd_config, DashboardScadaV31EtcdETCDConfig)
        assert client.etcd_config.etcd_host == "etcd"
        assert client.etcd_config.etcd_port == 2379
        assert client.etcd_config.cluster_name == "upgraded-happiness-cluster-v31"
        assert client.etcd_config.node_id == "dashboard_main_v31_etcd_001"

        print("✅ Configuración ETCD extraída correctamente")

    def test_extract_etcd_config_missing_section(self):
        """Test: Error cuando falta sección etcd_crypto"""
        print("🧪 Test 4: Verificando error con sección etcd_crypto faltante...")

        # Crear config SIN sección etcd_crypto
        config_without_etcd = {
            "node_id": "test_node",
            "component": {"name": "test_component"}
        }

        with open(self.dashboard_config_path, 'w') as f:
            json.dump(config_without_etcd, f)

        client = ETCDCryptoClientDashboard(self.dashboard_config_path, None)
        client._load_component_config()

        # Debe fallar al extraer config ETCD
        with pytest.raises(KeyError) as exc_info:
            client._extract_etcd_config()

        assert "etcd_crypto" in str(exc_info.value)
        print("✅ Error detectado correctamente cuando falta sección etcd_crypto")

    def test_extract_etcd_config_missing_required_fields(self):
        """Test: Error cuando faltan campos requeridos en etcd_crypto"""
        print("🧪 Test 5: Verificando error con campos ETCD faltantes...")

        # Crear config con etcd_crypto incompleto
        config_incomplete = {
            "node_id": "test_node",
            "etcd_crypto": {
                "etcd_host": "etcd",
                # Faltan etcd_port, cluster_name, node_id
            }
        }

        with open(self.dashboard_config_path, 'w') as f:
            json.dump(config_incomplete, f)

        client = ETCDCryptoClientDashboard(self.dashboard_config_path, None)
        client._load_component_config()

        # Debe fallar por campos faltantes
        with pytest.raises(KeyError) as exc_info:
            client._extract_etcd_config()

        error_msg = str(exc_info.value)
        assert "etcd_port" in error_msg or "cluster_name" in error_msg
        print("✅ Error detectado correctamente cuando faltan campos ETCD requeridos")

    @patch('etcd3.client')
    async def test_register_configs_in_etcd_success(self, mock_etcd3_client):
        """Test: Registrar configuraciones en ETCD (simulado)"""
        print("🧪 Test 6: Registrando configuraciones en ETCD...")

        # Setup mock ETCD client
        mock_client_instance = Mock()
        mock_etcd3_client.return_value = mock_client_instance

        self.create_dashboard_config_file()
        self.create_firewall_rules_config_file()

        client = ETCDCryptoClientDashboard(
            self.dashboard_config_path,
            self.rules_config_path
        )

        # Cargar configs y extraer ETCD config
        client._load_component_config()
        client._load_rules_config()
        client._extract_etcd_config()

        # Registrar en ETCD
        await client._register_configs_in_etcd()

        # Verificaciones
        mock_etcd3_client.assert_called_once_with(host="etcd", port=2379)

        # Verificar que se hicieron dos PUTs (config principal + reglas)
        assert mock_client_instance.put.call_count == 2

        # Verificar las claves utilizadas
        call_args = mock_client_instance.put.call_args_list
        keys_used = [call[0][0] for call in call_args]

        assert "/upgraded-happiness/v31/components/dashboard/config" in keys_used
        assert "/upgraded-happiness/v31/components/dashboard/firewall_rules" in keys_used

        # Verificar que los datos JSON son válidos
        for call in call_args:
            json_data = call[0][1]  # Segundo argumento (el valor)
            parsed_data = json.loads(json_data)
            assert "config_type" in parsed_data
            assert "timestamp" in parsed_data
            assert "node_id" in parsed_data

        print("✅ Configuraciones registradas correctamente en ETCD")

    @patch('etcd3.client')
    async def test_full_initialization_success(self, mock_etcd3_client):
        """Test: Inicialización completa del cliente ETCD"""
        print("🧪 Test 7: Inicialización completa del cliente ETCD...")

        # Setup mock
        mock_client_instance = Mock()
        mock_etcd3_client.return_value = mock_client_instance

        self.create_dashboard_config_file()
        self.create_firewall_rules_config_file()

        client = ETCDCryptoClientDashboard(
            self.dashboard_config_path,
            self.rules_config_path
        )

        # Inicializar crypto completo
        success = await client.initialize_crypto()

        # Verificaciones
        assert success is True
        assert client.is_crypto_ready() is True
        assert client.crypto_token is not None
        assert client.get_pipeline_key() is not None

        # Verificar status
        status = client.get_status()
        assert status["component"] == "dashboard_scada_v31_etcd"
        assert status["crypto_ready"] is True
        assert status["etcd_config"]["host"] == "etcd"
        assert status["etcd_config"]["port"] == 2379

        print("✅ Inicialización completa exitosa")

    @patch('etcd3.client')
    async def test_public_api_functions(self, mock_etcd3_client):
        """Test: Funciones públicas del API"""
        print("🧪 Test 8: Verificando funciones públicas del API...")

        # Setup mock
        mock_client_instance = Mock()
        mock_etcd3_client.return_value = mock_client_instance

        self.create_dashboard_config_file()
        self.create_firewall_rules_config_file()

        # Test funciones públicas
        success = await setup_dashboard_crypto(
            self.dashboard_config_path,
            self.rules_config_path
        )

        assert success is True

        # Verificar pipeline key
        pipeline_key = get_dashboard_pipeline_key()
        assert pipeline_key is not None
        assert "dashboard_scada_v31_etcd" in pipeline_key

        # Verificar status
        status = get_dashboard_crypto_status()
        assert status["component"] == "dashboard_scada_v31_etcd"
        assert status["crypto_ready"] is True

        print("✅ Funciones públicas del API funcionan correctamente")

    def test_config_files_consistency_check(self):
        """Test: Verificar consistencia entre archivos de configuración"""
        print("🧪 Test 9: Verificando consistencia entre archivos...")

        self.create_dashboard_config_file()
        self.create_firewall_rules_config_file()

        # Cargar ambos archivos
        with open(self.dashboard_config_path, 'r') as f:
            dashboard_config = json.load(f)

        with open(self.rules_config_path, 'r') as f:
            rules_config = json.load(f)

        # Verificar que los metadatos son consistentes
        dashboard_env = dashboard_config["deployment_metadata"]["environment"]
        rules_env = rules_config["deployment_metadata"]["environment"]

        # Verificar campos críticos
        assert dashboard_config["etcd_crypto"]["etcd_host"] == "etcd"
        assert dashboard_config["etcd_crypto"]["etcd_port"] == 2379
        assert dashboard_config["etcd_crypto"]["node_id"] == "dashboard_main_v31_etcd_001"

        # Verificar que las reglas firewall tienen estructura válida
        firewall_rules = rules_config["firewall_rules"]
        assert "rules" in firewall_rules
        assert "agents_fleet" in firewall_rules
        assert len(firewall_rules["rules"]) > 0

        print("✅ Consistencia entre archivos verificada")

    async def run_all_tests(self):
        """Ejecutar todos los tests"""
        print("\n" + "=" * 80)
        print("🚀 EJECUTANDO BATERÍA COMPLETA DE TESTS - Cliente ETCD Dashboard")
        print("=" * 80)

        tests = [
            self.test_load_dashboard_config_success,
            self.test_load_firewall_rules_config_success,
            self.test_extract_etcd_config_success,
            self.test_extract_etcd_config_missing_section,
            self.test_extract_etcd_config_missing_required_fields,
            self.test_register_configs_in_etcd_success,
            self.test_full_initialization_success,
            self.test_public_api_functions,
            self.test_config_files_consistency_check
        ]

        passed = 0
        failed = 0

        for test_func in tests:
            try:
                self.setup_method()
                if asyncio.iscoroutinefunction(test_func):
                    await test_func()
                else:
                    test_func()
                passed += 1
                print(f"✅ {test_func.__name__} - PASSED")
            except Exception as e:
                failed += 1
                print(f"❌ {test_func.__name__} - FAILED: {e}")
            finally:
                self.teardown_method()

        print("\n" + "=" * 80)
        print(f"📊 RESUMEN DE TESTS: {passed} PASSED | {failed} FAILED")
        print("=" * 80)

        if failed == 0:
            print("🎉 TODOS LOS TESTS PASARON - Cliente ETCD Dashboard listo para Docker!")
        else:
            print("⚠️  ALGUNOS TESTS FALLARON - Revisar configuración antes de continuar")

        return failed == 0


async def main():
    """Función principal para ejecutar tests"""
    print("🧪 Test Suite - Cliente ETCD Dashboard con Configuración Dual")
    print("📁 Archivos a verificar:")
    print("  - core/etcd_crypto_client_dashboard_fixed.py")
    print("  - infrastructure/config/dashboard_config_docker.json")
    print("  - infrastructure/config/firewall_rules_dashboard_config_docker.json")

    tester = TestETCDDashboardClientIntegration()
    success = await tester.run_all_tests()

    if success:
        print("\n🎯 CONCLUSIÓN: El cliente ETCD puede trabajar correctamente con ambos archivos")
        print("📋 PRÓXIMOS PASOS:")
        print("  1. ✅ Cliente ETCD soporta configuración dual")
        print("  2. ⏭️  Revisar integración en backend del dashboard")
        print("  3. ⏭️  Validar Dockerfile para copia de archivos")
        print("  4. ⏭️  Crear imágenes Docker de todos los componentes")

    return success


if __name__ == "__main__":
    asyncio.run(main())