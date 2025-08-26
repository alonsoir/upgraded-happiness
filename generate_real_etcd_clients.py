#!/usr/bin/env python3
"""
🧬 Real ETCD Client Generator - Upgraded Happiness V3.1
================================================================================
Genera clientes ETCD REALES basados en la plantilla del Dashboard
SIN FALLBACKS, SIN MOCKS, SOLO ETCD PURO
"""

import os
import json
from datetime import datetime

# Configuración de componentes
COMPONENTS = {
    'sniffer': {
        'class_name': 'ETCDCryptoClientSniffer',
        'config_path_param': 'sniffer_config_path',
        'config_key': '/upgraded-happiness/v31/components/sniffer/config',
        'component_type': 'evolutionary_sniffer',
        'has_rules': False,
        'setup_function': 'setup_sniffer_crypto',
        'key_function': 'get_sniffer_pipeline_key'
    },
    'geoip': {
        'class_name': 'ETCDCryptoClientGeoIP',
        'config_path_param': 'geoip_config_path',
        'config_key': '/upgraded-happiness/v31/components/geoip/config',
        'component_type': 'geoip_enricher',
        'has_rules': False,
        'setup_function': 'setup_geoip_crypto',
        'key_function': 'get_geoip_pipeline_key'
    },
    'ml_detector': {
        'class_name': 'ETCDCryptoClientMLDetector',
        'config_path_param': 'ml_detector_config_path',
        'config_key': '/upgraded-happiness/v31/components/ml_detector/config',
        'component_type': 'lightweight_ml_detector_tricapa',
        'has_rules': False,
        'setup_function': 'setup_ml_detector_crypto',
        'key_function': 'get_ml_detector_pipeline_key'
    },
    'scheduler': {
        'class_name': 'ETCDCryptoClientSchedulerFirewall',
        'config_path_param': 'scheduler_config_path',
        'config_key': '/upgraded-happiness/v31/components/scheduler/config',
        'rules_key': '/upgraded-happiness/v31/components/scheduler/firewall_rules',
        'component_type': 'scheduler_firewall',
        'has_rules': True,
        'setup_function': 'setup_scheduler_firewall_crypto',
        'key_function': 'get_scheduler_firewall_pipeline_key'
    },
    'agent': {
        'class_name': 'ETCDCryptoClientSimpleFirewallAgent',
        'config_path_param': 'agent_config_path',
        'config_key': '/upgraded-happiness/v31/components/agent/config',
        'rules_key': '/upgraded-happiness/v31/components/agent/firewall_rules',
        'component_type': 'simple_firewall_agent',
        'has_rules': True,
        'setup_function': 'setup_simple_firewall_agent_crypto',
        'key_function': 'get_simple_firewall_agent_pipeline_key'
    },
    'dashboard': {
        'class_name': 'ETCDCryptoClientDashboard',
        'config_path_param': 'dashboard_config_path',
        'config_key': '/upgraded-happiness/v31/components/dashboard/config',
        'rules_key': '/upgraded-happiness/v31/components/dashboard/firewall_rules',
        'component_type': 'dashboard_scada_v31_etcd',
        'has_rules': True,
        'setup_function': 'setup_dashboard_crypto',
        'key_function': 'get_dashboard_pipeline_key'
    }
}


def generate_etcd_client_template(component_name, config):
    """Genera un cliente ETCD real basado en la plantilla del Dashboard"""

    template = f'''#!/usr/bin/env python3
"""
core/etcd_crypto_client_{component_name}_fixed.py
🔍 Cliente ETCD REAL - {config['component_type'].upper()}
================================================================================
BASADO EN LA PLANTILLA DEL DASHBOARD - SIN FALLBACKS, SOLO ETCD PURO
"""

import asyncio
import json
import logging
import os
import sys
import socket
import etcd3
from datetime import datetime
from typing import Dict, Optional, Union
from dataclasses import dataclass

# 🚨 HARD REQUIREMENT: ETCD MUST BE AVAILABLE
# NO FALLBACKS, NO MOCKS, NO FAKE BEHAVIOR
ETCD_REQUIRED = True

@dataclass
class {config['component_type'].title().replace('_', '')}ETCDConfig:
    """Configuración ETCD extraída desde el config JSON del componente"""
    etcd_host: str
    etcd_port: int
    cluster_name: str
    node_id: str

class {config['class_name']}:
    """🔍 Cliente ETCD REAL para {config['component_type'].upper()}"""

    def __init__(self, {config['config_path_param']}: str{"" if not config['has_rules'] else ", rules_config_path: str = None"}):
        """
        Inicializar cliente ETCD REAL

        Args:
            {config['config_path_param']}: Ruta al config JSON del componente{"" if not config['has_rules'] else """
            rules_config_path: Ruta al config JSON de reglas firewall (opcional)"""}
        """
        self.{config['config_path_param']} = {config['config_path_param']}{"" if not config['has_rules'] else f"""
        self.rules_config_path = rules_config_path"""}
        self.component_config = None{"" if not config['has_rules'] else """
        self.rules_config = None"""}
        self.etcd_config = None
        self.crypto_token = None

        # Setup logging
        self.logger = logging.getLogger(f"{config['component_type']}_etcd_client")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - {config['component_type'].upper()}_ETCD - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def _load_component_config(self):
        """Cargar configuración del componente"""
        try:
            with open(self.{config['config_path_param']}, 'r') as f:
                self.component_config = json.load(f)

            self.logger.info(f"✅ {{config['component_type'].title()}} config loaded successfully")

        except json.JSONDecodeError as e:
            raise ValueError(f"❌ Invalid JSON in {{config['component_type']}} config: {{e}}")
        except Exception as e:
            raise RuntimeError(f"❌ Failed to load {{config['component_type']}} config: {{e}}")

    {"def _load_rules_config(self):" if config['has_rules'] else ""}
        {"\"\"\"Cargar configuración de reglas firewall\"\"\"" if config['has_rules'] else ""}
        {"if not self.rules_config_path:" if config['has_rules'] else ""}
            {"self.logger.warning(\"⚠️ No rules config path provided\")" if config['has_rules'] else ""}
            {"return" if config['has_rules'] else ""}
        {"" if config['has_rules'] else ""}
        {"try:" if config['has_rules'] else ""}
            {"with open(self.rules_config_path, 'r') as f:" if config['has_rules'] else ""}
                {"self.rules_config = json.load(f)" if config['has_rules'] else ""}
            {"" if config['has_rules'] else ""}
            {"self.logger.info(\"✅ Firewall rules config loaded successfully\")" if config['has_rules'] else ""}
            {"" if config['has_rules'] else ""}
        {"except json.JSONDecodeError as e:" if config['has_rules'] else ""}
            {"raise ValueError(f\"❌ Invalid JSON in firewall rules config: {{e}}\")" if config['has_rules'] else ""}
        {"except Exception as e:" if config['has_rules'] else ""}
            {"raise RuntimeError(f\"❌ Failed to load firewall rules config: {{e}}\")" if config['has_rules'] else ""}

    def _extract_etcd_config(self):
        """Extraer configuración ETCD del config del componente"""
        if not self.component_config:
            raise ValueError("❌ Component config must be loaded first")

        if 'etcd_crypto' not in self.component_config:
            raise KeyError(
                f"❌ REQUIRED section 'etcd_crypto' not found in {{config['component_type']}} config.\\n"
                f"   Add 'etcd_crypto' section to {{self.{config['config_path_param']}}}"
            )

        etcd_section = self.component_config['etcd_crypto']

        # OBLIGATORIO: campos requeridos
        required_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']
        missing_fields = [field for field in required_fields if field not in etcd_section]

        if missing_fields:
            raise KeyError(
                f"❌ REQUIRED fields missing in etcd_crypto section: {{missing_fields}}\\n"
                f"   Add these fields to {{self.{config['config_path_param']}}}"
            )

        self.etcd_config = {config['component_type'].title().replace('_', '')}ETCDConfig(
            etcd_host=etcd_section['etcd_host'],
            etcd_port=etcd_section['etcd_port'],
            cluster_name=etcd_section['cluster_name'],
            node_id=etcd_section['node_id']
        )

        self.logger.info(f"✅ ETCD config extracted: {{self.etcd_config.etcd_host}}:{{self.etcd_config.etcd_port}}")

    async def _register_configs_in_etcd(self):
        """🎯 Registrar configuración(es) en ETCD - PATRÓN DASHBOARD"""
        try:
            self.logger.info(f"📊 Registering {{config['component_type']}} config{'s' if config['has_rules'] else ''} in ETCD...")

            # Crear cliente ETCD REAL
            etcd_client = etcd3.client(
                host=self.etcd_config.etcd_host,
                port=self.etcd_config.etcd_port
            )

            # Registrar config principal del componente
            component_config_key = "{config['config_key']}"
            component_config_data = {{
                "config_type": "{component_name}_config",
                "node_id": self.etcd_config.node_id,
                "component_type": "{config['component_type']}",
                "config_data": self.component_config,
                "timestamp": datetime.now().isoformat(),
                "config_version": self.component_config.get('_config_metadata', {{}}).get('config_version', '3.1.0')
            }}

            # PUT a ETCD
            etcd_client.put(component_config_key, json.dumps(component_config_data, indent=2))
            self.logger.info(f"✅ {{config['component_type'].title()}} config registered at: {{component_config_key}}")

            {"# Registrar reglas firewall (si aplica)" if config['has_rules'] else ""}
            {"if self.rules_config:" if config['has_rules'] else ""}
                {"rules_config_key = \"" + config.get('rules_key', '') + "\"" if config['has_rules'] else ""}
                {"rules_config_data = {" if config['has_rules'] else ""}
                    {"\"config_type\": \"firewall_rules\"," if config['has_rules'] else ""}
                    {"\"node_id\": self.etcd_config.node_id," if config['has_rules'] else ""}
                    {"\"managed_by\": \"" + config['component_type'] + "\"," if config['has_rules'] else ""}
                    {"\"config_data\": self.rules_config," if config['has_rules'] else ""}
                    {"\"timestamp\": datetime.now().isoformat()," if config['has_rules'] else ""}
                    {"\"rules_summary\": \"Firewall rules for " + config['component_type'] + "\"" if config['has_rules'] else ""}
                {"}" if config['has_rules'] else ""}
                {"" if config['has_rules'] else ""}
                {"# PUT rules a ETCD" if config['has_rules'] else ""}
                {"etcd_client.put(rules_config_key, json.dumps(rules_config_data, indent=2))" if config['has_rules'] else ""}
                {"self.logger.info(f\"✅ Firewall rules registered at: {{rules_config_key}}\")" if config['has_rules'] else ""}

            self.logger.info(f"📊 {{config['component_type'].title()}} config registration completed successfully")

        except Exception as e:
            self.logger.error(f"❌ Config registration failed: {{e}}")
            # 🚨 HARD FAIL - NO FALLBACKS
            raise RuntimeError(f"ETCD config registration failed for {{config['component_type']}}: {{e}}")

    async def initialize_crypto(self) -> bool:
        """
        Inicializar cliente ETCD y registrar configuraciones
        🚨 HARD FAIL si ETCD no está disponible
        """
        try:
            self.logger.info(f"🚀 Initializing {{config['component_type']}} ETCD crypto...")

            # 1. Cargar configuraciones
            self._load_component_config(){"" if not config['has_rules'] else """
            if self.rules_config_path:
                self._load_rules_config()"""}

            # 2. Extraer config ETCD
            self._extract_etcd_config()

            # 3. Registrar en ETCD
            await self._register_configs_in_etcd()

            # 4. Generar token crypto (simplificado por ahora)
            self.crypto_token = {{
                'key': f"{{config['component_type']}}_key_{{datetime.now().strftime('%Y%m%d_%H%M%S')}}",
                'version': 'v3.1.0',
                'timestamp': datetime.now().isoformat()
            }}

            self.logger.info(f"✅ {{config['component_type'].title()}} crypto initialization successful!")
            self.logger.info(f"🔑 Token version: {{self.crypto_token['version']}}")

            return True

        except Exception as e:
            self.logger.error(f"❌ Crypto initialization failed: {{e}}")
            # 🚨 HARD FAIL - NO FALLBACKS, NO MOCKS
            raise RuntimeError(f"ETCD initialization failed for {{config['component_type']}}: {{e}}")

    def get_pipeline_key(self) -> Optional[str]:
        """Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para {config['component_type']}"""
        if not self.crypto_token:
            return None
        return self.crypto_token['key']

    def is_crypto_ready(self) -> bool:
        """Verificar si crypto está listo"""
        return self.crypto_token is not None

    def get_status(self) -> Dict:
        """Obtener status del cliente ETCD"""
        return {{
            'component': '{config['component_type']}',
            'crypto_ready': self.is_crypto_ready(),
            'etcd_config': {{
                'host': self.etcd_config.etcd_host if self.etcd_config else None,
                'port': self.etcd_config.etcd_port if self.etcd_config else None,
                'cluster': self.etcd_config.cluster_name if self.etcd_config else None,
                'node_id': self.etcd_config.node_id if self.etcd_config else None
            }} if self.etcd_config else None,
            'token_version': self.crypto_token['version'] if self.crypto_token else None
        }}

# 🎯 FUNCIONES PÚBLICAS PARA COMPATIBILIDAD
async def {config['setup_function']}({config['config_path_param']}: str{"" if not config['has_rules'] else ", rules_config_path: str = None"}) -> bool:
    """
    Setup crypto para {config['component_type']}

    Args:
        {config['config_path_param']}: Ruta al config JSON del componente{"" if not config['has_rules'] else """
        rules_config_path: Ruta al config JSON de reglas firewall"""}

    Returns:
        True si exitoso

    Raises:
        RuntimeError si ETCD no está disponible
    """
    global _etcd_client
    _etcd_client = {config['class_name']}({config['config_path_param']}{"" if not config['has_rules'] else ", rules_config_path"})

    success = await _etcd_client.initialize_crypto()
    if not success:
        raise RuntimeError(f"Failed to initialize {{config['component_type']}} ETCD crypto")

    return True

def {config['key_function']}() -> Optional[str]:
    """Obtener pipeline key para {config['component_type']}"""
    global _etcd_client
    if not _etcd_client:
        return None
    return _etcd_client.get_pipeline_key()

def get_{component_name}_crypto_status() -> Dict:
    """Obtener status crypto para {config['component_type']}"""
    global _etcd_client
    if not _etcd_client:
        return {{'status': 'not_initialized'}}
    return _etcd_client.get_status()

# Cliente global
_etcd_client: Optional[{config['class_name']}] = None

if __name__ == "__main__":
    # Test básico
    import asyncio

    async def test_{component_name}_etcd():
        """Test básico del cliente ETCD"""
        print(f"🧪 Testing {{config['component_type']}} ETCD client...")

        # Esto requiere que ETCD esté corriendo y config válido
        # python core/etcd_crypto_client_{component_name}_fixed.py

        print("🚨 Para test real, usa un config válido y ETCD corriendo")

    if len(sys.argv) > 1:
        print(f"🔧 Para integrar: from core.etcd_crypto_client_{component_name}_fixed import {config['setup_function']}, {config['key_function']}")
    else:
        asyncio.run(test_{component_name}_etcd())
'''

    return template


def generate_all_clients():
    """Genera todos los clientes ETCD REALES"""
    print("🧬 Generando clientes ETCD REALES basados en plantilla Dashboard")
    print("=" * 60)

    for component_name, config in COMPONENTS.items():
        print(f"📋 Generando: {component_name}")

        client_code = generate_etcd_client_template(component_name, config)

        output_path = f"core/etcd_crypto_client_{component_name}_fixed_REAL.py"

        with open(output_path, 'w') as f:
            f.write(client_code)

        print(f"   ✅ Creado: {output_path}")

    print("\n🎯 GENERACIÓN COMPLETADA")
    print("🔧 SIGUIENTES PASOS:")
    print("   1. Reemplazar los clientes falsos con estos REALES")
    print("   2. Actualizar imports en componentes principales")
    print("   3. Probar con ETCD corriendo")
    print("   4. Eliminar archivos _fixed antiguos")


if __name__ == "__main__":
    generate_all_clients()