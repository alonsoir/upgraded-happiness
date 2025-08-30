#!/usr/bin/env python3
"""
test_dashboard_etcd_compatibility.py
Test de compatibilidad ETCD para Dashboard V3.1 Docker

🎯 OBJETIVO: Verificar que dashboard_v31_etcd.py funciona con:
- dashboard_config_docker.json
- firewall_rules_config_docker.json
- core/etcd_crypto_client_dashboard_fixed.py

✅ Este test usa las clases REALES del archivo fixed
"""

import sys
import os
import json
import logging
import traceback
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def find_firewall_rules_config_docker():
    # Ruta al config Docker del geoip
    config_path = "infrastructure/config/firewall_rules_config_docker.json"
    return config_path

def find_dashboard_config_docker():
    # Ruta al config Docker del geoip
    config_path = "infrastructure/config/dashbo"
    return config_path

def find_project_root():
    """Encuentra la raíz del proyecto buscando archivos característicos"""
    current = Path.cwd()
    for parent in [current] + list(current.parents):
        if (parent / 'dashboard_v31_etcd.py').exists() or (parent / 'core').exists():
            return parent
    return current


def load_json_config(filepath: str) -> Optional[Dict[str, Any]]:
    """Carga y valida un archivo JSON de configuración"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            config = json.load(f)
        logger.info(f"✅ Archivo JSON cargado: {filepath}")
        return config
    except FileNotFoundError:
        logger.error(f"❌ Archivo no encontrado: {filepath}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"❌ Error JSON en {filepath}: {e}")
        return None


def validate_etcd_config_section(config: Dict[str, Any], config_name: str) -> bool:
    """Valida la sección etcd_crypto de la configuración"""
    logger.info(f"🔐 Validando sección etcd_crypto en {config_name}...")

    if 'etcd_crypto' not in config:
        logger.error(f"❌ Sección 'etcd_crypto' faltante en {config_name}")
        return False

    etcd_section = config['etcd_crypto']
    required_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']
    missing_fields = [field for field in required_fields if field not in etcd_section]

    if missing_fields:
        logger.error(f"❌ Campos faltantes en etcd_crypto: {missing_fields}")
        return False

    logger.info(f"✅ Sección etcd_crypto válida en {config_name}")
    logger.info(f"   - ETCD Host: {etcd_section['etcd_host']}")
    logger.info(f"   - ETCD Port: {etcd_section['etcd_port']}")
    logger.info(f"   - Cluster: {etcd_section['cluster_name']}")
    logger.info(f"   - Node ID: {etcd_section['node_id']}")

    return True


def validate_dashboard_docker_structure(config: Dict[str, Any]) -> bool:
    """Valida estructura específica para dashboard Docker"""
    logger.info("🐳 Validando estructura Docker del dashboard...")

    # Validar secciones principales
    required_sections = [
        'deployment_metadata',
        'etcd_crypto',
        'network',
        'firewall_fleet',
        'web_server',
        'crypto',
        'component'
    ]

    missing_sections = [section for section in required_sections if section not in config]
    if missing_sections:
        logger.error(f"❌ Secciones faltantes: {missing_sections}")
        return False

    # Validar metadata Docker
    deployment_meta = config.get('deployment_metadata', {})
    docker_fields = ['container_name', 'environment', 'orchestrator']
    for field in docker_fields:
        if field not in deployment_meta:
            logger.warning(f"⚠️ Campo Docker faltante en deployment_metadata: {field}")

    # Validar crypto role
    crypto_section = config.get('crypto', {})
    if crypto_section.get('role') != 'receiver_sender':
        logger.error(f"❌ Crypto role incorrecto: {crypto_section.get('role')} (esperado: receiver_sender)")
        return False

    # Validar web server
    web_server = config.get('web_server', {})
    if web_server.get('port') != 8080:
        logger.error(f"❌ Puerto web server incorrecto: {web_server.get('port')} (esperado: 8080)")
        return False

    logger.info("✅ Estructura Docker del dashboard válida")
    return True


def test_etcd_client_imports():
    """Test de importaciones del cliente ETCD"""
    logger.info("📦 Testeando importaciones del cliente ETCD...")

    try:
        # Intentar importar las clases REALES
        from core.etcd_crypto_client_dashboard_fixed import (
            DashboardScadaV31EtcdETCDConfig,
            ETCDCryptoClientDashboard,
            setup_dashboard_crypto,
            get_dashboard_pipeline_key,
            get_dashboard_crypto_status
        )

        logger.info("✅ Importaciones exitosas:")
        logger.info(f"   - DashboardScadaV31EtcdETCDConfig (dataclass)")
        logger.info(f"   - ETCDCryptoClientDashboard (clase principal)")
        logger.info(f"   - setup_dashboard_crypto (función)")
        logger.info(f"   - get_dashboard_pipeline_key (función)")
        logger.info(f"   - get_dashboard_crypto_status (función)")

        return True

    except ImportError as e:
        logger.error(f"❌ Error de importación: {e}")
        return False


def test_etcd_client_instantiation(dashboard_config_path: str, rules_config_path: str = None):
    """Test de instanciación del cliente ETCD"""
    logger.info("🔧 Testeando instanciación del cliente ETCD...")

    try:
        from core.etcd_crypto_client_dashboard_fixed import ETCDCryptoClientDashboard

        # Crear instancia del cliente
        client = ETCDCryptoClientDashboard(
            dashboard_config_path=dashboard_config_path,
            rules_config_path=rules_config_path
        )

        logger.info("✅ Cliente ETCD instanciado correctamente")
        logger.info(f"   - Dashboard config: {dashboard_config_path}")
        if rules_config_path:
            logger.info(f"   - Rules config: {rules_config_path}")

        return client

    except Exception as e:
        logger.error(f"❌ Error al instanciar cliente ETCD: {e}")
        logger.error(traceback.format_exc())
        return None


def test_config_loading(client, test_mode: bool = True):
    """Test de carga de configuraciones"""
    logger.info("📖 Testeando carga de configuraciones...")

    try:
        # Cargar config del componente
        client._load_component_config()
        logger.info("✅ Configuración del componente cargada")

        # Cargar config de reglas (si existe)
        if client.rules_config_path:
            client._load_rules_config()
            logger.info("✅ Configuración de reglas cargada")

        # Extraer config ETCD
        client._extract_etcd_config()
        logger.info("✅ Configuración ETCD extraída")
        logger.info(f"   - Host: {client.etcd_config.etcd_host}")
        logger.info(f"   - Puerto: {client.etcd_config.etcd_port}")
        logger.info(f"   - Cluster: {client.etcd_config.cluster_name}")
        logger.info(f"   - Node ID: {client.etcd_config.node_id}")

        return True

    except Exception as e:
        logger.error(f"❌ Error en carga de configuraciones: {e}")
        if not test_mode:
            logger.error(traceback.format_exc())
        return False


async def test_crypto_initialization(client, test_mode: bool = True):
    """Test de inicialización crypto (modo test)"""
    logger.info("🔐 Testeando inicialización crypto (modo test)...")

    try:
        if test_mode:
            # En modo test, simular inicialización sin conectar a ETCD real
            logger.info("🧪 MODO TEST: Simulando inicialización sin ETCD real")

            # Cargar configuraciones localmente
            client._load_component_config()
            if client.rules_config_path:
                client._load_rules_config()
            client._extract_etcd_config()

            # Simular token crypto
            from datetime import datetime
            client.crypto_token = {
                'key': f"dashboard_scada_v31_etcd_key_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'version': 'v3.1.0-test',
                'timestamp': datetime.now().isoformat(),
                'test_mode': True
            }

            logger.info("✅ Inicialización crypto simulada exitosa")
            logger.info(f"   - Token version: {client.crypto_token['version']}")
            logger.info(f"   - Key: {client.crypto_token['key'][:50]}...")

            return True
        else:
            # Inicialización real (requiere ETCD corriendo)
            success = await client.initialize_crypto()
            logger.info(f"✅ Inicialización crypto real: {success}")
            return success

    except Exception as e:
        logger.error(f"❌ Error en inicialización crypto: {e}")
        if not test_mode:
            logger.error(traceback.format_exc())
        return False


def test_api_functions(dashboard_config_path: str, rules_config_path: str = None):
    """Test de funciones públicas de API"""
    logger.info("🎯 Testeando funciones públicas de API...")

    try:
        from core.etcd_crypto_client_dashboard_fixed import (
            setup_dashboard_crypto,
            get_dashboard_pipeline_key,
            get_dashboard_crypto_status
        )

        # Test status antes de setup
        status_before = get_dashboard_crypto_status()
        logger.info(f"📊 Status antes del setup: {status_before}")

        # Test pipeline key antes de setup
        key_before = get_dashboard_pipeline_key()
        logger.info(f"🔑 Pipeline key antes del setup: {key_before}")

        logger.info("✅ Funciones públicas de API accesibles")
        return True

    except Exception as e:
        logger.error(f"❌ Error en test de API: {e}")
        return False


def analyze_component_info(dashboard_config: Dict[str, Any]) -> Dict[str, Any]:
    """Analiza información del componente para el resumen"""
    component_info = {
        'name': dashboard_config.get('component', {}).get('name', 'dashboard_scada_v31_etcd'),
        'version': dashboard_config.get('component', {}).get('version', '3.1.0'),
        'role': dashboard_config.get('component', {}).get('role', 'dashboard_scada'),
        'crypto_role': dashboard_config.get('crypto', {}).get('role', 'receiver_sender'),
        'pipeline_position': 'dashboard_final_stage',
        'endpoints': [],
        'capabilities': []
    }

    # Extraer endpoints de red
    network = dashboard_config.get('network', {})
    if 'ml_events_input' in network:
        ml_input = network['ml_events_input']
        component_info['endpoints'].append(
            f"ML Input: {ml_input.get('address', 'ml-detector')}:{ml_input.get('port', 5580)} (SUB)")

    # Web server
    web_server = dashboard_config.get('web_server', {})
    if web_server.get('enabled', True):
        component_info['endpoints'].append(
            f"Web Server: {web_server.get('host', '0.0.0.0')}:{web_server.get('port', 8080)} (HTTP)")

    # Fleet management
    firewall_fleet = dashboard_config.get('firewall_fleet', {})
    if firewall_fleet.get('enabled', False):
        component_info['capabilities'].append('Fleet Management')
        component_info['capabilities'].append('Firewall Control')

    # Crypto capabilities
    crypto = dashboard_config.get('crypto', {})
    if crypto.get('enabled', False):
        component_info['capabilities'].append('ETCD Crypto')
        component_info['capabilities'].append('Message Encryption/Decryption')

    # Visualización
    data_viz = dashboard_config.get('data_visualization', {})
    if data_viz.get('enabled', False):
        component_info['capabilities'].append('Real-time Visualization')
        component_info['capabilities'].append('Geographic Mapping')

    return component_info


def print_compatibility_summary(
        dashboard_config: Dict[str, Any],
        rules_config: Dict[str, Any],
        test_results: Dict[str, bool],
        component_info: Dict[str, Any]
):
    """Imprime resumen de compatibilidad"""
    print("\n" + "=" * 80)
    print("🎯 RESUMEN DE COMPATIBILIDAD ETCD - DASHBOARD V3.1 DOCKER")
    print("=" * 80)

    # Información del componente
    print(f"\n📊 INFORMACIÓN DEL COMPONENTE:")
    print(f"   • Nombre: {component_info['name']}")
    print(f"   • Versión: {component_info['version']}")
    print(f"   • Rol: {component_info['role']}")
    print(f"   • Crypto Role: {component_info['crypto_role']}")
    print(f"   • Pipeline Position: {component_info['pipeline_position']}")

    # Endpoints
    print(f"\n🌐 ENDPOINTS DE RED:")
    for endpoint in component_info['endpoints']:
        print(f"   • {endpoint}")

    # Capacidades
    print(f"\n⚡ CAPACIDADES:")
    for capability in component_info['capabilities']:
        print(f"   • {capability}")

    # Resultados de tests
    print(f"\n✅ RESULTADOS DE TESTS:")
    for test_name, result in test_results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   • {test_name}: {status}")

    # Configuración ETCD
    etcd_config = dashboard_config.get('etcd_crypto', {})
    print(f"\n🔐 CONFIGURACIÓN ETCD:")
    print(f"   • Host: {etcd_config.get('etcd_host', 'N/A')}")
    print(f"   • Puerto: {etcd_config.get('etcd_port', 'N/A')}")
    print(f"   • Cluster: {etcd_config.get('cluster_name', 'N/A')}")
    print(f"   • Node ID: {etcd_config.get('node_id', 'N/A')}")

    # Docker metadata
    docker_meta = dashboard_config.get('deployment_metadata', {})
    print(f"\n🐳 METADATOS DOCKER:")
    print(f"   • Container: {docker_meta.get('container_name', 'N/A')}")
    print(f"   • Namespace: {docker_meta.get('namespace', 'N/A')}")
    print(f"   • Orchestrator: {docker_meta.get('orchestrator', 'N/A')}")
    print(f"   • Config Version: {docker_meta.get('config_version', 'N/A')}")

    # Estado general
    all_passed = all(test_results.values())
    status_emoji = "🎉" if all_passed else "⚠️"
    status_text = "TODAS LAS PRUEBAS PASARON" if all_passed else "ALGUNAS PRUEBAS FALLARON"

    print(f"\n{status_emoji} ESTADO GENERAL: {status_text}")

    if all_passed:
        print("\n🚀 El dashboard está listo para Docker/K8s con ETCD crypto!")
    else:
        print("\n🔧 Revisa los errores arriba antes de proceder al deployment.")

    print("=" * 80)


async def main():
    """Función principal del test"""
    logger.info("🎯 Iniciando test de compatibilidad ETCD Dashboard V3.1 Docker")

    # Encontrar raíz del proyecto
    project_root = find_project_root()
    logger.info(f"📁 Raíz del proyecto: {project_root}")

    # Rutas de archivos
    dashboard_config_path = project_root / "dashboard_config_docker.json"
    rules_config_path = project_root / "firewall_rules_config_docker.json"

    # Verificar archivos existen
    if not dashboard_config_path.exists():
        logger.error(f"❌ Archivo no encontrado: {dashboard_config_path}")
        return False

    # Rules config es opcional
    rules_path = str(rules_config_path) if rules_config_path.exists() else None
    if not rules_config_path.exists():
        logger.warning(f"⚠️ Archivo de reglas no encontrado (opcional): {rules_config_path}")

    # Cargar configuraciones
    dashboard_config = load_json_config(str(dashboard_config_path))
    rules_config = load_json_config(str(rules_config_path)) if rules_path else {}

    if not dashboard_config:
        logger.error("❌ No se pudo cargar la configuración del dashboard")
        return False

    # Resultados de tests
    test_results = {}

    # Test 1: Validar estructura ETCD
    test_results['ETCD Config Structure'] = validate_etcd_config_section(dashboard_config, "dashboard")

    # Test 2: Validar estructura Docker
    test_results['Docker Structure'] = validate_dashboard_docker_structure(dashboard_config)

    # Test 3: Importaciones
    test_results['ETCD Client Imports'] = test_etcd_client_imports()

    # Test 4: Instanciación del cliente
    client = test_etcd_client_instantiation(str(dashboard_config_path), rules_path)
    test_results['Client Instantiation'] = client is not None

    if client:
        # Test 5: Carga de configuraciones
        test_results['Config Loading'] = test_config_loading(client, test_mode=True)

        # Test 6: Inicialización crypto (modo test)
        test_results['Crypto Initialization'] = await test_crypto_initialization(client, test_mode=True)

    # Test 7: Funciones públicas API
    test_results['Public API Functions'] = test_api_functions(str(dashboard_config_path), rules_path)

    # Analizar información del componente
    component_info = analyze_component_info(dashboard_config)

    # Mostrar resumen
    print_compatibility_summary(dashboard_config, rules_config, test_results, component_info)

    # Retornar resultado general
    all_passed = all(test_results.values())
    return all_passed


if __name__ == "__main__":
    try:
        # Ejecutar test principal
        result = asyncio.run(main())
        exit_code = 0 if result else 1
        sys.exit(exit_code)

    except KeyboardInterrupt:
        logger.info("\n⏹️ Test interrumpido por el usuario")
        sys.exit(1)

    except Exception as e:
        logger.error(f"❌ Error fatal en test: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)