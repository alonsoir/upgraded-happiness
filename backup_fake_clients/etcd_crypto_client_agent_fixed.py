#!/usr/bin/env python3
"""
core/etcd_crypto_client_agent_fixed.py
🔍 Cliente ETCD REAL - SIMPLE_FIREWALL_AGENT
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
class SimpleFirewallAgentETCDConfig:
    """Configuración ETCD extraída desde el config JSON del componente"""
    etcd_host: str
    etcd_port: int
    cluster_name: str
    node_id: str

class ETCDCryptoClientSimpleFirewallAgent:
    """🔍 Cliente ETCD REAL para SIMPLE_FIREWALL_AGENT"""

    def __init__(self, agent_config_path: str, rules_config_path: str = None):
        """
        Inicializar cliente ETCD REAL

        Args:
            agent_config_path: Ruta al config JSON del componente
            rules_config_path: Ruta al config JSON de reglas firewall (opcional)
        """
        self.agent_config_path = agent_config_path
        self.rules_config_path = rules_config_path
        self.component_config = None
        self.rules_config = None
        self.etcd_config = None
        self.crypto_token = None

        # Setup logging
        self.logger = logging.getLogger(f"simple_firewall_agent_etcd_client")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - SIMPLE_FIREWALL_AGENT_ETCD - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def _load_component_config(self):
        """Cargar configuración del componente"""
        try:
            with open(self.agent_config_path, 'r') as f:
                self.component_config = json.load(f)

            self.logger.info(f"✅ {config['component_type'].title()} config loaded successfully")

        except json.JSONDecodeError as e:
            raise ValueError(f"❌ Invalid JSON in {config['component_type']} config: {e}")
        except Exception as e:
            raise RuntimeError(f"❌ Failed to load {config['component_type']} config: {e}")

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
                f"❌ REQUIRED section 'etcd_crypto' not found in {config['component_type']} config.\n"
                f"   Add 'etcd_crypto' section to {self.agent_config_path}"
            )

        etcd_section = self.component_config['etcd_crypto']

        # OBLIGATORIO: campos requeridos
        required_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']
        missing_fields = [field for field in required_fields if field not in etcd_section]

        if missing_fields:
            raise KeyError(
                f"❌ REQUIRED fields missing in etcd_crypto section: {missing_fields}\n"
                f"   Add these fields to {self.agent_config_path}"
            )

        self.etcd_config = SimpleFirewallAgentETCDConfig(
            etcd_host=etcd_section['etcd_host'],
            etcd_port=etcd_section['etcd_port'],
            cluster_name=etcd_section['cluster_name'],
            node_id=etcd_section['node_id']
        )

        self.logger.info(f"✅ ETCD config extracted: {self.etcd_config.etcd_host}:{self.etcd_config.etcd_port}")

    async def _register_configs_in_etcd(self):
        """🎯 Registrar configuración(es) en ETCD - PATRÓN DASHBOARD"""
        try:
            self.logger.info(f"📊 Registering {config['component_type']} configs in ETCD...")

            # Crear cliente ETCD REAL
            etcd_client = etcd3.client(
                host=self.etcd_config.etcd_host,
                port=self.etcd_config.etcd_port
            )

            # Registrar config principal del componente
            component_config_key = "/upgraded-happiness/v31/components/agent/config"
            component_config_data = {
                "config_type": "agent_config",
                "node_id": self.etcd_config.node_id,
                "component_type": "simple_firewall_agent",
                "config_data": self.component_config,
                "timestamp": datetime.now().isoformat(),
                "config_version": self.component_config.get('_config_metadata', {}).get('config_version', '3.1.0')
            }

            # PUT a ETCD
            etcd_client.put(component_config_key, json.dumps(component_config_data, indent=2))
            self.logger.info(f"✅ {config['component_type'].title()} config registered at: {component_config_key}")

            # Registrar reglas firewall (si aplica)
            if self.rules_config:
                rules_config_key = "/upgraded-happiness/v31/components/agent/firewall_rules"
                rules_config_data = {
                    "config_type": "firewall_rules",
                    "node_id": self.etcd_config.node_id,
                    "managed_by": "simple_firewall_agent",
                    "config_data": self.rules_config,
                    "timestamp": datetime.now().isoformat(),
                    "rules_summary": "Firewall rules for simple_firewall_agent"
                }
                
                # PUT rules a ETCD
                etcd_client.put(rules_config_key, json.dumps(rules_config_data, indent=2))
                self.logger.info(f"✅ Firewall rules registered at: {{rules_config_key}}")

            self.logger.info(f"📊 {config['component_type'].title()} config registration completed successfully")

        except Exception as e:
            self.logger.error(f"❌ Config registration failed: {e}")
            # 🚨 HARD FAIL - NO FALLBACKS
            raise RuntimeError(f"ETCD config registration failed for {config['component_type']}: {e}")

    async def initialize_crypto(self) -> bool:
        """
        Inicializar cliente ETCD y registrar configuraciones
        🚨 HARD FAIL si ETCD no está disponible
        """
        try:
            self.logger.info(f"🚀 Initializing {config['component_type']} ETCD crypto...")

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
                'key': f"{config['component_type']}_key_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'version': 'v3.1.0',
                'timestamp': datetime.now().isoformat()
            }

            self.logger.info(f"✅ {config['component_type'].title()} crypto initialization successful!")
            self.logger.info(f"🔑 Token version: {self.crypto_token['version']}")

            return True

        except Exception as e:
            self.logger.error(f"❌ Crypto initialization failed: {e}")
            # 🚨 HARD FAIL - NO FALLBACKS, NO MOCKS
            raise RuntimeError(f"ETCD initialization failed for {config['component_type']}: {e}")

    def get_pipeline_key(self) -> Optional[str]:
        """Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para simple_firewall_agent"""
        if not self.crypto_token:
            return None
        return self.crypto_token['key']

    def is_crypto_ready(self) -> bool:
        """Verificar si crypto está listo"""
        return self.crypto_token is not None

    def get_status(self) -> Dict:
        """Obtener status del cliente ETCD"""
        return {
            'component': 'simple_firewall_agent',
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
async def setup_simple_firewall_agent_crypto(agent_config_path: str, rules_config_path: str = None) -> bool:
    """
    Setup crypto para simple_firewall_agent

    Args:
        agent_config_path: Ruta al config JSON del componente
        rules_config_path: Ruta al config JSON de reglas firewall

    Returns:
        True si exitoso

    Raises:
        RuntimeError si ETCD no está disponible
    """
    global _etcd_client
    _etcd_client = ETCDCryptoClientSimpleFirewallAgent(agent_config_path, rules_config_path)

    success = await _etcd_client.initialize_crypto()
    if not success:
        raise RuntimeError(f"Failed to initialize {config['component_type']} ETCD crypto")

    return True

def get_simple_firewall_agent_pipeline_key() -> Optional[str]:
    """Obtener pipeline key para simple_firewall_agent"""
    global _etcd_client
    if not _etcd_client:
        return None
    return _etcd_client.get_pipeline_key()

def get_agent_crypto_status() -> Dict:
    """Obtener status crypto para simple_firewall_agent"""
    global _etcd_client
    if not _etcd_client:
        return {'status': 'not_initialized'}
    return _etcd_client.get_status()

# Cliente global
_etcd_client: Optional[ETCDCryptoClientSimpleFirewallAgent] = None

if __name__ == "__main__":
    # Test básico
    import asyncio

    async def test_agent_etcd():
        """Test básico del cliente ETCD"""
        print(f"🧪 Testing {config['component_type']} ETCD client...")

        # Esto requiere que ETCD esté corriendo y config válido
        # python core/etcd_crypto_client_agent_fixed.py

        print("🚨 Para test real, usa un config válido y ETCD corriendo")

    if len(sys.argv) > 1:
        print(f"🔧 Para integrar: from core.etcd_crypto_client_agent_fixed import setup_simple_firewall_agent_crypto, get_simple_firewall_agent_pipeline_key")
    else:
        asyncio.run(test_agent_etcd())
