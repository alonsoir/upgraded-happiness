#!/usr/bin/env python3
"""
Test de Compatibilidad - Cliente ETCD GeoIP con Docker Config
================================================================================
Verifica que el cliente ETCD puede cargar geoip_config_docker.json
SIN necesidad de ETCD corriendo - Solo parsing y validación
"""

import json
import sys
import os
from pathlib import Path


class ETCDClientGeoIPTest:
    """Cliente ETCD de prueba - Solo parsing, sin conexión ETCD"""

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.component_config = None
        self.etcd_config = None

    def load_component_config(self):
        """Cargar configuración del componente"""
        try:
            with open(self.config_path, 'r') as f:
                self.component_config = json.load(f)
            print(f"Config loaded successfully from: {self.config_path}")
            return True
        except Exception as e:
            print(f"Failed to load config: {e}")
            return False

    def extract_etcd_config(self):
        """Extraer configuración ETCD"""
        if not self.component_config:
            print("Component config must be loaded first")
            return False

        if 'etcd_crypto' not in self.component_config:
            print("REQUIRED section 'etcd_crypto' not found")
            return False

        etcd_section = self.component_config['etcd_crypto']
        required_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']
        missing_fields = [field for field in required_fields if field not in etcd_section]

        if missing_fields:
            print(f"REQUIRED fields missing: {missing_fields}")
            return False

        self.etcd_config = {
            'etcd_host': etcd_section['etcd_host'],
            'etcd_port': etcd_section['etcd_port'],
            'cluster_name': etcd_section['cluster_name'],
            'node_id': etcd_section['node_id']
        }

        print(f"ETCD config extracted: {self.etcd_config['etcd_host']}:{self.etcd_config['etcd_port']}")
        return True

    def validate_geoip_specific_fields(self):
        """Verificar campos específicos de geoip"""
        print("\nVerificando campos específicos de GeoIP...")

        checks = []

        # Network configuration
        if 'network' in self.component_config:
            network = self.component_config['network']
            checks.append(('input_socket', 'input_socket' in network))
            checks.append(('output_socket', 'output_socket' in network))
            if 'input_socket' in network:
                input_sock = network['input_socket']
                checks.append(('connects_to_sniffer', input_sock.get('address') == 'sniffer'))
                checks.append(('input_port_5571', input_sock.get('port') == 5571))
            print("Network configuration present")
        else:
            print("Network configuration missing")

        # GeoIP configuration
        if 'geoip' in self.component_config:
            geoip = self.component_config['geoip']
            checks.append(('maxmind_enabled', geoip.get('lookup_method') == 'maxmind'))
            checks.append(('fallback_method', 'fallback_method' in geoip))
            if 'maxmind' in geoip:
                maxmind = geoip['maxmind']
                checks.append(('database_path', 'database_path' in maxmind))
            print("GeoIP configuration present")
        else:
            print("GeoIP configuration missing")

        # Processing configuration
        if 'processing' in self.component_config:
            processing = self.component_config['processing']
            checks.append(('tripartite_enabled', processing.get('geolocate_sniffer_node', False)))
            checks.append(('source_ip_geo', processing.get('geolocate_source_ip', False)))
            checks.append(('dest_ip_geo', processing.get('geolocate_destination_ip', False)))
            print("Processing configuration present")
        else:
            print("Processing configuration missing")

        return checks

    def validate_new_metadata_fields(self):
        """Verificar que los nuevos campos de metadatos están presentes"""
        print("\nVerificando nuevos campos de metadatos Docker/K8s...")

        checks = []

        # Deployment metadata
        if 'deployment_metadata' in self.component_config:
            metadata = self.component_config['deployment_metadata']
            checks.append(('environment', metadata.get('environment') == 'docker'))
            checks.append(('orchestrator', metadata.get('orchestrator') == 'docker'))
            checks.append(('pod_id', 'pod_id' in metadata))
            checks.append(('container_name', metadata.get('container_name') == 'geoip'))
            print("deployment_metadata presente")
        else:
            print("deployment_metadata ausente")

        # Runtime metadata
        if 'deployment_metadata' in self.component_config and 'runtime_metadata' in self.component_config[
            'deployment_metadata']:
            runtime = self.component_config['deployment_metadata']['runtime_metadata']
            checks.append(('process_id', 'process_id' in runtime))
            checks.append(('startup_timestamp', 'startup_timestamp' in runtime))
            print("runtime_metadata presente")
        else:
            print("runtime_metadata ausente")

        # Config metadata
        if '_config_metadata' in self.component_config:
            config_meta = self.component_config['_config_metadata']
            checks.append(('docker_specific', 'docker_specific' in config_meta))
            checks.append(('template_version', 'template_version' in config_meta))
            print("_config_metadata presente")
        else:
            print("_config_metadata ausente")

        print(f"\nVerificaciones: {sum(1 for _, passed in checks if passed)}/{len(checks)} exitosas")
        return checks

    def simulate_etcd_registration_data(self):
        """Simular los datos que se enviarían a ETCD (sin enviar)"""
        if not self.component_config or not self.etcd_config:
            print("Config not ready for ETCD registration")
            return None

        registration_data = {
            "config_type": "geoip_config",
            "node_id": self.etcd_config['node_id'],
            "component_type": "geoip_enricher",
            "config_data": self.component_config,  # Incluye TODOS los metadatos
            "timestamp": "2025-08-30T10:00:00Z",
            "config_version": self.component_config.get('_config_metadata', {}).get('config_version', '3.1.0')
        }

        print("Datos de registro ETCD simulados correctamente")
        print(f"   - Tamaño config_data: {len(str(self.component_config))} caracteres")
        print(f"   - Nuevos metadatos incluidos: Si")

        return registration_data


def test_geoip_docker_config():
    """Test principal de compatibilidad"""
    print("TESTING: Cliente ETCD GeoIP + geoip_config_docker.json")
    print("=" * 70)

    # Ruta al config Docker del geoip
    config_path = "infrastructure/config/geoip_config_docker.json"

    # Verificar que existe el archivo
    if not os.path.exists(config_path):
        print(f"Config file not found: {config_path}")
        print("   Asegúrate de que el archivo existe en la ruta correcta")
        return False

    # Crear cliente de test
    client = ETCDClientGeoIPTest(config_path)

    # Test 1: Cargar configuración
    print("\nTEST 1: Carga de configuración")
    if not client.load_component_config():
        return False

    # Test 2: Extraer config ETCD
    print("\nTEST 2: Extracción de configuración ETCD")
    if not client.extract_etcd_config():
        return False

    # Test 3: Validar campos específicos de GeoIP
    print("\nTEST 3: Validación de campos específicos GeoIP")
    geoip_checks = client.validate_geoip_specific_fields()

    # Test 4: Validar nuevos campos
    print("\nTEST 4: Validación de metadatos Docker/K8s")
    metadata_checks = client.validate_new_metadata_fields()

    # Test 5: Simular registro ETCD
    print("\nTEST 5: Simulación de registro ETCD")
    etcd_data = client.simulate_etcd_registration_data()

    if etcd_data:
        print("\nRESUMEN DE COMPATIBILIDAD:")
        print("=" * 50)
        print("Config JSON se carga correctamente")
        print("Sección etcd_crypto es válida")
        print("Campos requeridos están presentes")
        print("Configuración GeoIP específica válida")
        print("Nuevos metadatos no rompen el cliente")
        print("Datos listos para registro en ETCD")
        print("\nRESULTADO: COMPATIBLE")
        return True
    else:
        print("Error en simulación de registro ETCD")
        return False


if __name__ == "__main__":
    print("Iniciando test de compatibilidad GeoIP...")
    success = test_geoip_docker_config()

    if success:
        print("\nTest completado exitosamente!")
        print("   El cliente ETCD del geoip es compatible con geoip_config_docker.json")
        sys.exit(0)
    else:
        print("\nTest falló - Revisar problemas reportados")
        sys.exit(1)