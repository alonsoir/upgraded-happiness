#!/usr/bin/env python3
"""
core/etcd_crypto_client_dashboard_fixed.py
🔍 Cliente ETCD REAL - DASHBOARD_SCADA_V31_ETCD
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
class DashboardScadaV31EtcdETCDConfig:
    """Configuración ETCD extraída desde el config JSON del componente"""
    etcd_host: str
    etcd_port: int
    cluster_name: str
    node_id: str

class ETCDCryptoClientDashboard:
    """🔍 Cliente ETCD REAL para DASHBOARD_SCADA_V31_ETCD"""

    def __init__(self, dashboard_config_path: str, rules_config_path: str = None):
        """
        Inicializar cliente ETCD REAL

        Args:
            dashboard_config_path: Ruta al config JSON del componente
            rules_config_path: Ruta al config JSON de reglas firewall (opcional)
        """
        self.dashboard_config_path = dashboard_config_path
        self.rules_config_path = rules_config_path
        self.component_config = None
        self.rules_config = None
        self.etcd_config = None
        self.crypto_token = None

        # Setup logging
        self.logger = logging.getLogger(f"dashboard_scada_v31_etcd_etcd_client")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - DASHBOARD_SCADA_V31_ETCD_ETCD - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def _load_component_config(self):
        """Cargar configuración del componente"""
        try:
            with open(self.dashboard_config_path, 'r') as f:
                self.component_config = json.load(f)

            self.logger.info(f"✅ {'dashboard_scada_v31_etcd'.title()} config loaded successfully")

        except json.JSONDecodeError as e:
            raise ValueError(f"❌ Invalid JSON in {'dashboard_scada_v31_etcd'} config: {e}")
        except Exception as e:
            raise RuntimeError(f"❌ Failed to load {'dashboard_scada_v31_etcd'} config: {e}")

    def _load_rules_config(self):
        """Cargar configuración de reglas firewall"""
        if not self.rules_config_path:
            self.logger.warning("⚠️ No rules config path provided")
            return
        
        try:
            with open(self.rules_config_path, 'r') as f:
                self.rules_config = json.load(f)
            
            self.logger.info("✅ Firewall rules config loaded successfully")
            
        except json.JSONDecodeError as e:
            raise ValueError(f"❌ Invalid JSON in firewall rules config: {{e}}")
        except Exception as e:
            raise RuntimeError(f"❌ Failed to load firewall rules config: {{e}}")

    def _extract_etcd_config(self):
        """Extraer configuración ETCD del config del componente"""
        if not self.component_config:
            raise ValueError("❌ Component config must be loaded first")

        if 'etcd_crypto' not in self.component_config:
            raise KeyError(
                f"❌ REQUIRED section 'etcd_crypto' not found in {'dashboard_scada_v31_etcd'} config.\n"
                f"   Add 'etcd_crypto' section to {self.dashboard_config_path}"
            )

        etcd_section = self.component_config['etcd_crypto']

        # OBLIGATORIO: campos requeridos
        required_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']
        missing_fields = [field for field in required_fields if field not in etcd_section]

        if missing_fields:
            raise KeyError(
                f"❌ REQUIRED fields missing in etcd_crypto section: {missing_fields}\n"
                f"   Add these fields to {self.dashboard_config_path}"
            )

        self.etcd_config = DashboardScadaV31EtcdETCDConfig(
            etcd_host=etcd_section['etcd_host'],
            etcd_port=etcd_section['etcd_port'],
            cluster_name=etcd_section['cluster_name'],
            node_id=etcd_section['node_id']
        )

        self.logger.info(f"✅ ETCD config extracted: {self.etcd_config.etcd_host}:{self.etcd_config.etcd_port}")

    async def _register_configs_in_etcd(self):
        """🎯 Registrar configuración(es) en ETCD - PATRÓN DASHBOARD"""
        try:
            self.logger.info(f"📊 Registering dashboard_scada_v31_etcd configs in ETCD...")

            # Crear cliente ETCD REAL
            etcd_client = etcd3.client(
                host=self.etcd_config.etcd_host,
                port=self.etcd_config.etcd_port
            )

            # Registrar config principal del componente
            component_config_key = "/upgraded-happiness/v31/components/dashboard/config"
            component_config_data = {
                "config_type": "dashboard_config",
                "node_id": self.etcd_config.node_id,
                "component_type": "dashboard_scada_v31_etcd",
                "config_data": self.component_config,
                "timestamp": datetime.now().isoformat(),
                "config_version": self.component_config.get('_config_metadata', {}).get('config_version', '3.1.0')
            }

            # PUT a ETCD
            etcd_client.put(component_config_key, json.dumps(component_config_data, indent=2))
            self.logger.info(f"✅ Dashboard_Scada_V31_Etcd config registered at: {component_config_key}")

            # Registrar reglas firewall (si aplica)
            if self.rules_config:
                rules_config_key = "/upgraded-happiness/v31/components/dashboard/firewall_rules"
                rules_config_data = {
                    "config_type": "firewall_rules",
                    "node_id": self.etcd_config.node_id,
                    "managed_by": "dashboard_scada_v31_etcd",
                    "config_data": self.rules_config,
                    "timestamp": datetime.now().isoformat(),
                    "rules_summary": "Firewall rules for dashboard_scada_v31_etcd"
                }
                
                # PUT rules a ETCD
                etcd_client.put(rules_config_key, json.dumps(rules_config_data, indent=2))
                self.logger.info(f"✅ Firewall rules registered at: {{rules_config_key}}")

            self.logger.info(f"📊 Dashboard_Scada_V31_Etcd config registration completed successfully")

        except Exception as e:
            self.logger.error(f"❌ Config registration failed: {e}")
            # 🚨 HARD FAIL - NO FALLBACKS
            raise RuntimeError(f"ETCD config registration failed for {'dashboard_scada_v31_etcd'}: {e}")

    async def initialize_crypto(self) -> bool:
        """
        Inicializar cliente ETCD y registrar configuraciones
        🚨 HARD FAIL si ETCD no está disponible
        """
        try:
            self.logger.info(f"🚀 Initializing dashboard_scada_v31_etcd ETCD crypto...")

            # 1. Cargar configuraciones
            self._load_component_config()
            if self.rules_config_path:
                self._load_rules_config()

            # 2. Extraer config ETCD
            self._extract_etcd_config()

            # 3. Registrar en ETCD
            await self._register_configs_in_etcd()

            # 4. Generar token crypto (simplificado por ahora)
            self.crypto_token = {
                'key': f"{'dashboard_scada_v31_etcd'}_key_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'version': 'v3.1.0',
                'timestamp': datetime.now().isoformat()
            }

            self.logger.info(f"✅ Dashboard_Scada_V31_Etcd crypto initialization successful!")
            self.logger.info(f"🔑 Token version: {self.crypto_token['version']}")

            return True

        except Exception as e:
            self.logger.error(f"❌ Crypto initialization failed: {e}")
            # 🚨 HARD FAIL - NO FALLBACKS, NO MOCKS
            raise RuntimeError(f"ETCD initialization failed for dashboard_scada_v31_etcd: {e}")

    def get_pipeline_key(self) -> Optional[str]:
        """Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para dashboard_scada_v31_etcd"""
        if not self.crypto_token:
            return None
        return self.crypto_token['key']

    def is_crypto_ready(self) -> bool:
        """Verificar si crypto está listo"""
        return self.crypto_token is not None

    def get_status(self) -> Dict:
        """Obtener status del cliente ETCD"""
        return {
            'component': 'dashboard_scada_v31_etcd',
            'crypto_ready': self.is_crypto_ready(),
            'etcd_config': {
                'host': self.etcd_config.etcd_host if self.etcd_config else None,
                'port': self.etcd_config.etcd_port if self.etcd_config else None,
                'cluster': self.etcd_config.cluster_name if self.etcd_config else None,
                'node_id': self.etcd_config.node_id if self.etcd_config else None
            } if self.etcd_config else None,
            'token_version': self.crypto_token['version'] if self.crypto_token else None
        }

# 🎯 FUNCIONES PÚBLICAS PARA COMPATIBILIDAD
async def setup_dashboard_crypto(dashboard_config_path: str, rules_config_path: str = None) -> bool:
    """
    Setup crypto para dashboard_scada_v31_etcd

    Args:
        dashboard_config_path: Ruta al config JSON del componente
        rules_config_path: Ruta al config JSON de reglas firewall

    Returns:
        True si exitoso

    Raises:
        RuntimeError si ETCD no está disponible
    """
    global _etcd_client
    _etcd_client = ETCDCryptoClientDashboard(dashboard_config_path, rules_config_path)

    success = await _etcd_client.initialize_crypto()
    if not success:
        raise RuntimeError(f"Failed to initialize {'dashboard_scada_v31_etcd'} ETCD crypto")

    return True

def get_dashboard_pipeline_key() -> Optional[str]:
    """Obtener pipeline key para dashboard_scada_v31_etcd"""
    global _etcd_client
    if not _etcd_client:
        return None
    return _etcd_client.get_pipeline_key()

def get_dashboard_crypto_status() -> Dict:
    """Obtener status crypto para dashboard_scada_v31_etcd"""
    global _etcd_client
    if not _etcd_client:
        return {'status': 'not_initialized'}
    return _etcd_client.get_status()

# Cliente global
_etcd_client: Optional[ETCDCryptoClientDashboard] = None

if __name__ == "__main__":
    # Test básico
    import asyncio

    async def test_dashboard_etcd():
        """Test básico del cliente ETCD"""
        print(f"🧪 Testing unknown_component ETCD client...")

        # Esto requiere que ETCD esté corriendo y config válido
        # python core/etcd_crypto_client_dashboard_fixed.py

        print("🚨 Para test real, usa un config válido y ETCD corriendo")

    if len(sys.argv) > 1:
        print(f"🔧 Para integrar: from core.etcd_crypto_client_dashboard_fixed import setup_dashboard_crypto, get_dashboard_pipeline_key")
    else:
        asyncio.run(test_dashboard_etcd())
