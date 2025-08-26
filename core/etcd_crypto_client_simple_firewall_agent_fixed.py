#!/usr/bin/env python3
"""
core/etcd_crypto_client_simple_firewall_agent_fixed.py
🔥 Cliente ETCD REAL - SIMPLE_FIREWALL_AGENT
================================================================================
BASADO EN LA PLANTILLA DEL SCHEDULER - SIN FALLBACKS, SOLO ETCD PURO
- Recibe DOS ficheros JSON (agent config + firewall rules)
- Los guarda en ETCD
- Proporciona token rotativo
"""

import asyncio
import json
import logging
import os
import sys
import etcd3
from datetime import datetime, timedelta
from typing import Dict, Optional, Union
from dataclasses import dataclass
import threading
import time
import uuid
import hashlib

# 🚨 HARD REQUIREMENT: ETCD MUST BE AVAILABLE
# NO FALLBACKS, NO MOCKS, NO FAKE BEHAVIOR
ETCD_REQUIRED = True


@dataclass
class SimpleFirewallAgentETCDConfig:
    """Configuración ETCD extraída desde el config JSON del agent"""
    etcd_host: str
    etcd_port: int
    cluster_name: str
    node_id: str


class ETCDCryptoClientSimpleFirewallAgent:
    """🔥 Cliente ETCD REAL para SIMPLE_FIREWALL_AGENT"""

    def __init__(self, agent_config_path: str, firewall_rules_path: str):
        """
        Inicializar cliente ETCD REAL para simple_firewall_agent

        Args:
            agent_config_path: Ruta al config JSON del agent
            firewall_rules_path: Ruta al config JSON de firewall rules
        """
        self.agent_config_path = agent_config_path
        self.firewall_rules_path = firewall_rules_path
        self.agent_config = None
        self.firewall_rules = None
        self.etcd_config = None
        self.crypto_token = None
        self.token_rotation_thread = None
        self.shutdown_event = threading.Event()

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

    def _load_configs(self):
        """Cargar AMBAS configuraciones JSON"""
        try:
            # 1. Cargar agent config
            with open(self.agent_config_path, 'r') as f:
                self.agent_config = json.load(f)
            self.logger.info(f"✅ Agent config loaded: {self.agent_config_path}")

            # 2. Cargar firewall rules (mismo archivo que scheduler)
            with open(self.firewall_rules_path, 'r') as f:
                self.firewall_rules = json.load(f)
            self.logger.info(f"✅ Firewall rules loaded: {self.firewall_rules_path}")

        except json.JSONDecodeError as e:
            raise ValueError(f"❌ Invalid JSON in simple_firewall_agent configs: {e}")
        except Exception as e:
            raise RuntimeError(f"❌ Failed to load simple_firewall_agent configs: {e}")

    def _extract_etcd_config(self):
        """Extraer configuración ETCD del config del agent"""
        if not self.agent_config:
            raise ValueError("❌ Agent config must be loaded first")

        if 'etcd_crypto' not in self.agent_config:
            raise KeyError(
                f"❌ REQUIRED section 'etcd_crypto' not found in agent config.\n"
                f"   Add 'etcd_crypto' section to {self.agent_config_path}"
            )

        etcd_section = self.agent_config['etcd_crypto']

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
        """🎯 Registrar AMBAS configuraciones en ETCD - PATRÓN SIMPLE_FIREWALL_AGENT"""
        try:
            self.logger.info(f"📊 Registering simple_firewall_agent configs in ETCD...")

            # Crear cliente ETCD REAL
            etcd_client = etcd3.client(
                host=self.etcd_config.etcd_host,
                port=self.etcd_config.etcd_port
            )

            # 1. Registrar AGENT CONFIG
            agent_config_key = "/upgraded-happiness/v31/components/simple_firewall_agent/config"
            agent_config_data = {
                "config_type": "simple_firewall_agent_config",
                "node_id": self.etcd_config.node_id,
                "component_type": "simple_firewall_agent",
                "config_data": self.agent_config,
                "source_file": self.agent_config_path,
                "timestamp": datetime.now().isoformat(),
                "config_version": "3.1.0"
            }

            etcd_client.put(agent_config_key, json.dumps(agent_config_data, indent=2))
            self.logger.info(f"✅ Agent config registered at: {agent_config_key}")

            # 2. Registrar FIREWALL RULES (mismo archivo que scheduler)
            firewall_rules_key = "/upgraded-happiness/v31/components/simple_firewall_agent/rules"
            firewall_rules_data = {
                "config_type": "firewall_rules",
                "node_id": self.etcd_config.node_id,
                "component_type": "simple_firewall_agent",
                "rules_data": self.firewall_rules,
                "source_file": self.firewall_rules_path,
                "timestamp": datetime.now().isoformat(),
                "rules_version": "3.1.0"
            }

            etcd_client.put(firewall_rules_key, json.dumps(firewall_rules_data, indent=2))
            self.logger.info(f"✅ Firewall rules registered at: {firewall_rules_key}")

            self.logger.info(f"📊 Simple_Firewall_Agent dual config registration completed successfully")

        except Exception as e:
            self.logger.error(f"❌ Config registration failed: {e}")
            # 🚨 HARD FAIL - NO FALLBACKS
            raise RuntimeError(f"ETCD config registration failed for simple_firewall_agent: {e}")

    def _generate_rotative_token(self):
        """Generar token rotativo para simple_firewall_agent"""
        try:
            timestamp = int(time.time())
            token_data = {
                'component': 'simple_firewall_agent',
                'node_id': self.etcd_config.node_id,
                'token_id': str(uuid.uuid4()),
                'created_at': timestamp,
                'expires_at': timestamp + 3600,  # 1 hora
                'version': 'v3.1.0',
                'permissions': ['firewall', 'agent', 'read', 'write', 'execute']
            }

            # Hash único del token
            token_string = f"{token_data['component']}_{token_data['node_id']}_{token_data['created_at']}"
            token_hash = hashlib.sha256(token_string.encode()).hexdigest()

            self.crypto_token = {
                'key': f"simple_firewall_agent_key_{token_hash[:16]}",
                'token_data': token_data,
                'hash': token_hash,
                'version': 'v3.1.0',
                'timestamp': datetime.now().isoformat()
            }

            self.logger.info(f"🎫 Rotative token generated: {self.crypto_token['key']}")

        except Exception as e:
            self.logger.error(f"❌ Token generation failed: {e}")
            raise RuntimeError(f"Token generation failed: {e}")

    def _start_token_rotation(self):
        """Iniciar rotación automática de tokens"""

        def token_rotation_worker():
            while not self.shutdown_event.is_set():
                try:
                    # Verificar si el token necesita renovación
                    if self.crypto_token:
                        expires_at = self.crypto_token['token_data']['expires_at']
                        current_time = int(time.time())

                        # Renovar 15 minutos antes de expirar
                        if current_time >= expires_at - 900:
                            self.logger.info("🔄 Rotating token...")
                            self._generate_rotative_token()

                    # Esperar 5 minutos antes de la siguiente verificación
                    self.shutdown_event.wait(300)

                except Exception as e:
                    self.logger.error(f"❌ Error in token rotation: {e}")
                    self.shutdown_event.wait(60)  # Reintentar en 1 minuto

        self.token_rotation_thread = threading.Thread(target=token_rotation_worker, daemon=True)
        self.token_rotation_thread.start()
        self.logger.info("🔄 Token rotation thread started")

    async def initialize_crypto(self) -> bool:
        """
        Inicializar cliente ETCD y registrar AMBAS configuraciones
        🚨 HARD FAIL si ETCD no está disponible
        """
        try:
            self.logger.info(f"🚀 Initializing simple_firewall_agent ETCD crypto...")

            # 1. Cargar AMBAS configuraciones
            self._load_configs()

            # 2. Extraer config ETCD
            self._extract_etcd_config()

            # 3. Registrar AMBOS configs en ETCD
            await self._register_configs_in_etcd()

            # 4. Generar token rotativo inicial
            self._generate_rotative_token()

            # 5. Iniciar rotación automática
            self._start_token_rotation()

            self.logger.info(f"✅ Simple_Firewall_Agent crypto initialization successful!")
            self.logger.info(f"🔑 Token version: {self.crypto_token['version']}")
            self.logger.info(f"📁 Configs stored: agent + firewall rules")

            return True

        except Exception as e:
            self.logger.error(f"❌ Crypto initialization failed: {e}")
            # 🚨 HARD FAIL - NO FALLBACKS, NO MOCKS
            raise RuntimeError(f"ETCD initialization failed for simple_firewall_agent: {e}")

    def get_pipeline_key(self) -> Optional[str]:
        """Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para simple_firewall_agent"""
        if not self.crypto_token:
            return None
        return self.crypto_token['key']

    def get_current_token(self) -> Optional[str]:
        """Obtener token actual para autenticación"""
        if not self.crypto_token:
            return None
        return self.crypto_token['hash']

    def is_crypto_ready(self) -> bool:
        """Verificar si crypto está listo"""
        return self.crypto_token is not None

    def get_status(self) -> Dict:
        """Obtener status del cliente ETCD"""
        return {
            'component': 'simple_firewall_agent',
            'crypto_ready': self.is_crypto_ready(),
            'configs_loaded': {
                'agent_config': self.agent_config is not None,
                'firewall_rules': self.firewall_rules is not None
            },
            'etcd_config': {
                'host': self.etcd_config.etcd_host if self.etcd_config else None,
                'port': self.etcd_config.etcd_port if self.etcd_config else None,
                'cluster': self.etcd_config.cluster_name if self.etcd_config else None,
                'node_id': self.etcd_config.node_id if self.etcd_config else None
            } if self.etcd_config else None,
            'token_info': {
                'version': self.crypto_token['version'] if self.crypto_token else None,
                'created_at': self.crypto_token['timestamp'] if self.crypto_token else None,
                'expires_at': datetime.fromtimestamp(
                    self.crypto_token['token_data']['expires_at']
                ).isoformat() if self.crypto_token else None
            } if self.crypto_token else None,
            'rotation_active': self.token_rotation_thread is not None and self.token_rotation_thread.is_alive()
        }

    def cleanup(self):
        """Limpieza de recursos"""
        try:
            # Parar rotación de tokens
            if self.token_rotation_thread:
                self.shutdown_event.set()
                self.token_rotation_thread.join(timeout=5)

            self.logger.info("🧹 Simple_Firewall_Agent ETCD client cleaned up")
        except Exception as e:
            self.logger.error(f"❌ Error in cleanup: {e}")


# 🎯 FUNCIONES PÚBLICAS PARA COMPATIBILIDAD
async def setup_simple_firewall_agent_crypto(agent_config_path: str, firewall_rules_path: str) -> bool:
    """
    Setup crypto para simple_firewall_agent

    Args:
        agent_config_path: Ruta al config JSON del agent
        firewall_rules_path: Ruta al config JSON de firewall rules

    Returns:
        True si exitoso

    Raises:
        RuntimeError si ETCD no está disponible
    """
    global _etcd_client
    _etcd_client = ETCDCryptoClientSimpleFirewallAgent(agent_config_path, firewall_rules_path)

    success = await _etcd_client.initialize_crypto()
    if not success:
        raise RuntimeError(f"Failed to initialize simple_firewall_agent ETCD crypto")

    return True


def get_simple_firewall_agent_pipeline_key() -> Optional[str]:
    """Obtener pipeline key para simple_firewall_agent"""
    global _etcd_client
    if not _etcd_client:
        return None
    return _etcd_client.get_pipeline_key()


def get_simple_firewall_agent_token() -> Optional[str]:
    """Obtener token rotativo actual para simple_firewall_agent"""
    global _etcd_client
    if not _etcd_client:
        return None
    return _etcd_client.get_current_token()


def get_simple_firewall_agent_crypto_status() -> Dict:
    """Obtener status crypto para simple_firewall_agent - FUNCIÓN REQUERIDA"""
    global _etcd_client
    if not _etcd_client:
        return {'status': 'not_initialized'}
    return _etcd_client.get_status()


def cleanup_simple_firewall_agent_crypto():
    """Limpiar recursos del cliente simple_firewall_agent"""
    global _etcd_client
    if _etcd_client:
        _etcd_client.cleanup()
        _etcd_client = None


# Cliente global
_etcd_client: Optional[ETCDCryptoClientSimpleFirewallAgent] = None

if __name__ == "__main__":
    # Test básico
    import asyncio


    async def test_simple_firewall_agent_etcd():
        """Test básico del cliente ETCD"""
        print(f"🧪 Testing simple_firewall_agent ETCD client...")

        if len(sys.argv) != 3:
            print(
                "❌ Usage: python core/etcd_crypto_client_simple_firewall_agent_fixed.py <agent_config.json> <firewall_rules.json>")
            print(
                "🔧 Example: python core/etcd_crypto_client_simple_firewall_agent_fixed.py config/json/simple_firewall_agent_v31_etcd.json config/json/firewall_rules_v31.json")
            return

        agent_config_path = sys.argv[1]
        firewall_rules_path = sys.argv[2]

        try:
            # Test de inicialización
            success = await setup_simple_firewall_agent_crypto(agent_config_path, firewall_rules_path)

            if success:
                print("✅ Initialization successful!")

                # Mostrar status
                status = get_simple_firewall_agent_crypto_status()
                print(f"📊 Status: {json.dumps(status, indent=2)}")

                # Mostrar pipeline key
                pipeline_key = get_simple_firewall_agent_pipeline_key()
                print(f"🔑 Pipeline Key: {pipeline_key}")

                # Mostrar token
                token = get_simple_firewall_agent_token()
                print(f"🎫 Current Token: {token[:16]}..." if token else "🎫 No token")

                print("\n⏱️ Client running with token rotation... Press Ctrl+C to exit")

                try:
                    while True:
                        await asyncio.sleep(30)
                        new_status = get_simple_firewall_agent_crypto_status()
                        print(f"🔄 Token expires: {new_status.get('token_info', {}).get('expires_at', 'unknown')}")
                except KeyboardInterrupt:
                    print("\n🛑 Interrupted by user")

                cleanup_simple_firewall_agent_crypto()

        except Exception as e:
            print(f"❌ Test failed: {e}")


    if len(sys.argv) > 1:
        asyncio.run(test_simple_firewall_agent_etcd())
    else:
        print(
            f"🔧 Para integrar: from core.etcd_crypto_client_simple_firewall_agent_fixed import setup_simple_firewall_agent_crypto, get_simple_firewall_agent_pipeline_key, get_simple_firewall_agent_crypto_status")
        print(
            f"📋 Usage: python core/etcd_crypto_client_simple_firewall_agent_fixed.py <agent_config.json> <firewall_rules.json>")