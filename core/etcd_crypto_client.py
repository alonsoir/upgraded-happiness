#!/usr/bin/env python3
"""
core/etcd_crypto_client.py
🔐 Cliente ETCD simplificado para componentes del pipeline
- Registro automático con coordinador
- Obtención de UPGRADED_HAPPINESS_PIPELINE_KEY
- Reemplazo de variables de entorno
"""

import asyncio
import json
import time
import logging
import hashlib
import os
import socket
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import base64

# Conditional import
try:
    import etcd3

    ETCD_AVAILABLE = True
except ImportError:
    ETCD_AVAILABLE = False
    print("⚠️  etcd3 not available - install with: pip install etcd3")


@dataclass
class ComponentCryptoConfig:
    """Configuración crypto para componente"""
    node_id: str
    component_type: str
    version: str

    # Token crypto recibido
    pipeline_key: Optional[str] = None
    token_version: Optional[int] = None
    token_id: Optional[str] = None
    component_salt: Optional[str] = None

    # Metadata de registro
    registration_hash: Optional[str] = None
    registered_at: Optional[float] = None
    coordinator_status: str = "not_registered"  # not_registered, registered, error


class UpgradedHappinessCryptoClient:
    """
    🔐 Cliente simplificado para componentes del pipeline
    - Auto-registro con ETCD coordinator
    - Obtención automática de UPGRADED_HAPPINESS_PIPELINE_KEY
    - Fallback a variables de entorno si ETCD no disponible
    """

    def __init__(self,
                 node_id: str,
                 component_type: str,
                 version: str = "3.1.0",
                 etcd_host: str = "localhost",
                 etcd_port: int = 2379,
                 capabilities: List[str] = None,
                 endpoints: Dict[str, str] = None):

        self.config = ComponentCryptoConfig(
            node_id=node_id,
            component_type=component_type,
            version=version
        )

        self.etcd_host = etcd_host
        self.etcd_port = etcd_port
        self.capabilities = capabilities or []
        self.endpoints = endpoints or {}

        # Logger específico del componente
        self.logger = logging.getLogger(f"crypto_client_{component_type}_{node_id}")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                f'%(asctime)s | 🔐 {component_type} | %(levelname)s | %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        # ETCD coordinator connection (lazy)
        self.coordinator = None
        self.etcd_available = ETCD_AVAILABLE

    async def initialize_crypto(self) -> bool:
        """
        Inicializar crypto del componente
        1. Intentar registro con ETCD coordinator
        2. Fallback a variable de entorno si falla

        Returns:
            True si se obtuvo token, False si falla
        """
        self.logger.info(f"🚀 Initializing crypto for {self.config.component_type} ({self.config.node_id})")

        # Intentar ETCD primero
        if self.etcd_available:
            if await self._try_etcd_registration():
                self.logger.info("✅ Crypto initialized via ETCD coordinator")
                return True
            else:
                self.logger.warning("⚠️  ETCD registration failed, trying environment fallback...")
        else:
            self.logger.warning("⚠️  ETCD not available, using environment fallback...")

        # Fallback a variable de entorno
        if self._try_environment_fallback():
            self.logger.info("✅ Crypto initialized via environment variable")
            return True

        self.logger.error("❌ Failed to initialize crypto - no ETCD and no environment variable")
        return False

    async def _try_etcd_registration(self) -> bool:
        """Intentar registro con ETCD coordinator"""
        try:
            # Import aquí para evitar problemas si etcd3 no está disponible
            from core.etcd_coordinator import ETCDCryptoCoordinator

            # Crear coordinador cliente
            self.coordinator = ETCDCryptoCoordinator(
                etcd_host=self.etcd_host,
                etcd_port=self.etcd_port,
                cluster_name="upgraded-happiness-cluster"
            )

            # Verificar conexión
            etcd_client = etcd3.client(host=self.etcd_host, port=self.etcd_port)
            etcd_client.status()  # Test connection

            # Iniciar coordinador cliente
            await self.coordinator.start()

            # Preparar información del componente
            component_info = {
                "node_id": self.config.node_id,
                "component_type": self.config.component_type,
                "version": self.config.version,
                "capabilities": self.capabilities,
                "endpoints": self.endpoints,
                "host_ip": self._get_local_ip(),
                "process_id": os.getpid()
            }

            # Registrar con coordinador
            success, response = await self.coordinator.register_component(component_info)

            if success:
                # Extraer token crypto
                crypto_token = response["crypto_token"]

                # Actualizar configuración
                self.config.pipeline_key = crypto_token["key_material"]
                self.config.token_version = crypto_token["version"]
                self.config.token_id = crypto_token["token_id"]
                self.config.registration_hash = response["registration_hash"]
                self.config.registered_at = time.time()
                self.config.coordinator_status = "registered"

                self.logger.info(f"🔑 Received UPGRADED_HAPPINESS_PIPELINE_KEY v{self.config.token_version}")
                self.logger.info(f"📋 Registration hash: {self.config.registration_hash[:16]}...")

                return True
            else:
                self.logger.error(f"❌ ETCD registration failed: {response.get('error', 'unknown error')}")
                self.config.coordinator_status = "error"
                return False

        except Exception as e:
            self.logger.error(f"❌ ETCD registration exception: {e}")
            self.config.coordinator_status = "error"
            return False

    def _try_environment_fallback(self) -> bool:
        """Fallback a variable de entorno"""
        try:
            env_key = os.environ.get("UPGRADED_HAPPINESS_PIPELINE_KEY")
            if env_key:
                self.config.pipeline_key = env_key
                self.config.token_version = 0  # Environment fallback
                self.config.coordinator_status = "env_fallback"

                self.logger.info("🔑 Using UPGRADED_HAPPINESS_PIPELINE_KEY from environment")
                return True
            else:
                self.logger.error("❌ UPGRADED_HAPPINESS_PIPELINE_KEY not found in environment")
                return False

        except Exception as e:
            self.logger.error(f"❌ Environment fallback failed: {e}")
            return False

    def get_pipeline_key(self) -> Optional[str]:
        """
        Obtener UPGRADED_HAPPINESS_PIPELINE_KEY
        ESTA FUNCIÓN REEMPLAZA: os.environ.get("UPGRADED_HAPPINESS_PIPELINE_KEY")

        Returns:
            Pipeline key si está disponible, None si no
        """
        if self.config.pipeline_key:
            return self.config.pipeline_key
        else:
            self.logger.error("❌ No pipeline key available - call initialize_crypto() first")
            return None

    def get_pipeline_key_bytes(self) -> Optional[bytes]:
        """Obtener pipeline key como bytes para crypto operations"""
        key_str = self.get_pipeline_key()
        if key_str:
            try:
                return base64.b64decode(key_str)
            except Exception as e:
                self.logger.error(f"❌ Failed to decode pipeline key: {e}")
                return None
        return None

    def get_crypto_config(self) -> ComponentCryptoConfig:
        """Obtener configuración crypto completa"""
        return self.config

    def is_crypto_ready(self) -> bool:
        """Verificar si crypto está listo para usar"""
        return self.config.pipeline_key is not None

    def get_status_info(self) -> Dict:
        """Obtener información de estado para debugging"""
        return {
            "node_id": self.config.node_id,
            "component_type": self.config.component_type,
            "crypto_ready": self.is_crypto_ready(),
            "coordinator_status": self.config.coordinator_status,
            "token_version": self.config.token_version,
            "registration_hash": self.config.registration_hash[:16] + "..." if self.config.registration_hash else None,
            "etcd_available": self.etcd_available,
            "etcd_host": self.etcd_host,
            "etcd_port": self.etcd_port
        }

    def _get_local_ip(self) -> str:
        """Obtener IP local del host"""
        try:
            # Conectar a un socket dummy para obtener IP local
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "localhost"

    async def heartbeat(self) -> bool:
        """
        Enviar heartbeat al coordinador (futuro)
        Por ahora solo loggea estado
        """
        if self.config.coordinator_status == "registered":
            self.logger.debug(f"💓 Heartbeat - Token v{self.config.token_version} active")
            return True
        return False

    async def refresh_token(self) -> bool:
        """
        Refrescar token si es necesario (futuro - token rotation)
        Por ahora es placeholder
        """
        if self.coordinator and self.config.coordinator_status == "registered":
            # TODO: Implementar token refresh en futuras fases
            self.logger.debug("🔄 Token refresh not implemented yet")
            return True
        return False


# ===============================================================================
# HELPER FUNCTIONS para integración rápida en componentes existentes
# ===============================================================================

async def quick_crypto_setup(component_type: str,
                             node_id: str = None,
                             version: str = "3.1.0",
                             capabilities: List[str] = None,
                             endpoints: Dict[str, str] = None) -> Optional[str]:
    """
    Setup rápido de crypto para componentes existentes

    Uso en componente:
        pipeline_key = await quick_crypto_setup("dashboard", "dashboard_main_001")
        if pipeline_key:
            crypto_zmq = CryptoZMQV31(pipeline_key)
        else:
            print("❌ Failed to get crypto key")

    Returns:
        UPGRADED_HAPPINESS_PIPELINE_KEY si exitoso, None si falla
    """

    # Generar node_id automático si no se proporciona
    if node_id is None:
        import uuid
        node_id = f"{component_type}_{uuid.uuid4().hex[:8]}"

    # Crear cliente
    client = UpgradedHappinessCryptoClient(
        node_id=node_id,
        component_type=component_type,
        version=version,
        capabilities=capabilities or [],
        endpoints=endpoints or {}
    )

    # Inicializar crypto
    if await client.initialize_crypto():
        return client.get_pipeline_key()
    else:
        return None


def create_component_crypto_client(component_type: str,
                                   node_id: str = None,
                                   version: str = "3.1.0",
                                   capabilities: List[str] = None,
                                   endpoints: Dict[str, str] = None) -> UpgradedHappinessCryptoClient:
    """
    Factory function para crear cliente crypto

    Uso en componente:
        crypto_client = create_component_crypto_client(
            "dashboard",
            "dashboard_main_001",
            capabilities=["visualization", "firewall_control"]
        )

        # En async startup:
        await crypto_client.initialize_crypto()
        pipeline_key = crypto_client.get_pipeline_key()
    """

    if node_id is None:
        import uuid
        node_id = f"{component_type}_{uuid.uuid4().hex[:8]}"

    return UpgradedHappinessCryptoClient(
        node_id=node_id,
        component_type=component_type,
        version=version,
        capabilities=capabilities or [],
        endpoints=endpoints or {}
    )


# ===============================================================================
# EJEMPLO DE USO
# ===============================================================================

async def test_crypto_client():
    """Test del cliente crypto"""

    print("🧪 Testing ETCD Crypto Client")
    print("=" * 40)

    # Crear cliente para dashboard
    client = create_component_crypto_client(
        component_type="dashboard",
        node_id="dashboard_test_001",
        capabilities=["visualization", "firewall_control"],
        endpoints={"web": "http://localhost:8080"}
    )

    print(f"📋 Created client: {client.config.node_id}")

    # Inicializar crypto
    success = await client.initialize_crypto()

    if success:
        print("✅ Crypto initialization successful!")

        # Obtener pipeline key
        pipeline_key = client.get_pipeline_key()
        print(f"🔑 UPGRADED_HAPPINESS_PIPELINE_KEY: {pipeline_key[:32]}...")

        # Status info
        status = client.get_status_info()
        print(f"📊 Status: {status}")

        # Test quick setup
        print("\n🚀 Testing quick setup...")
        quick_key = await quick_crypto_setup("ml_detector", "ml_test_001")
        if quick_key:
            print(f"🔑 Quick key: {quick_key[:32]}...")

    else:
        print("❌ Crypto initialization failed!")


if __name__ == "__main__":
    asyncio.run(test_crypto_client())