#!/usr/bin/env python3
"""
core/etcd_crypto_client_geoip_fixed.py
🌍 Cliente ETCD FIJO para GeoIP Enricher - Compatible con diferentes versiones de protobuf/etcd
- Registra el componente geoip_enricher con ETCD
- Obtiene crypto tokens para descifrar del sniffer y cifrar hacia ML detector
- Maneja dependencias problemáticas
- Fallback si etcd no está disponible
- Testing mode incluido
"""

import asyncio
import json
import logging
import os
import sys
import socket
from typing import Dict, Optional, Union
from dataclasses import dataclass

# 🔧 MANEJO DE DEPENDENCIAS PROBLEMÁTICAS
ETCD_AVAILABLE = False
ETCD_CLIENT_TYPE = None


def setup_etcd_environment():
    """Setup environment para evitar problemas con protobuf"""
    # Workaround para etcd3 + protobuf nuevo
    if 'PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION' not in os.environ:
        os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'


setup_etcd_environment()

# Intentar importar etcd con fallbacks
try:
    import etcd3

    ETCD_AVAILABLE = True
    ETCD_CLIENT_TYPE = "etcd3"
    print("✅ Using etcd3 client")
except ImportError as e:
    print(f"⚠️  etcd3 import failed: {e}")
    try:
        import etcd3 as etcd3_alt

        ETCD_AVAILABLE = True
        ETCD_CLIENT_TYPE = "etcd3-alt"
        etcd3 = etcd3_alt
        print("✅ Using alternative etcd3 client")
    except ImportError:
        print("❌ No etcd client available")
        print("💡 Install: pip install etcd3-py OR pip install 'protobuf<=3.20.3'")


@dataclass
class GeoIPETCDConfig:
    """Configuración ETCD extraída desde geoip_enricher_config_v31.json"""
    etcd_host: str
    etcd_port: int
    cluster_name: str
    node_id: str

    # Endpoints extraídos del config del geoip enricher
    input_host: str
    input_port: int
    output_host: str
    output_port: int

    # Opcional: HTTP API si está configurado
    http_api_host: Optional[str] = None
    http_api_port: Optional[int] = None


class ETCDCryptoClientGeoIP:
    """
    🌍 Cliente ETCD FIJO para GeoIP Enricher
    - Maneja problemas de dependencias
    - Modo testing incluido
    - Fallback si ETCD no disponible
    - Registra como receiver_sender (descifra + cifra)
    """

    def __init__(self, geoip_config_path: str, testing_mode: bool = False):
        self.geoip_config_path = geoip_config_path
        self.testing_mode = testing_mode
        self.geoip_config = None
        self.etcd_config = None
        self.pipeline_key = None
        self.crypto_ready = False

        # Logger específico del geoip enricher
        self.logger = logging.getLogger("etcd_crypto_geoip_fixed")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s | 🌍 GEOIP-CRYPTO-FIXED | %(levelname)s | %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        if testing_mode:
            self.logger.info("🧪 Testing mode enabled")

    def _load_geoip_config(self):
        """Cargar configuración del geoip enricher desde JSON"""
        self.logger.info(f"📋 Loading geoip enricher config from: {self.geoip_config_path}")

        if not os.path.exists(self.geoip_config_path):
            raise FileNotFoundError(f"❌ GeoIP config file not found: {self.geoip_config_path}")

        try:
            with open(self.geoip_config_path, 'r') as f:
                self.geoip_config = json.load(f)

            self.logger.info("✅ GeoIP config loaded successfully")

        except json.JSONDecodeError as e:
            raise ValueError(f"❌ Invalid JSON in geoip config: {e}")
        except Exception as e:
            raise RuntimeError(f"❌ Failed to load geoip config: {e}")

    def _extract_etcd_config(self):
        """
        Extraer configuración ETCD desde config del geoip enricher
        OBLIGATORIO: debe existir sección 'etcd_crypto' en el JSON
        """
        self.logger.info("🔍 Extracting ETCD config from geoip enricher config...")

        if not self.geoip_config:
            raise RuntimeError("❌ GeoIP config not loaded")

        # OBLIGATORIO: sección etcd_crypto debe existir
        if 'etcd_crypto' not in self.geoip_config:
            raise KeyError(
                "❌ REQUIRED section 'etcd_crypto' not found in geoip enricher config.\n"
                "   Add 'etcd_crypto' section to geoip_enricher_config_v31.json"
            )

        etcd_section = self.geoip_config['etcd_crypto']

        # OBLIGATORIO: campos requeridos
        required_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']
        missing_fields = []

        for field in required_fields:
            if field not in etcd_section:
                missing_fields.append(field)

        if missing_fields:
            raise KeyError(
                f"❌ REQUIRED fields missing in etcd_crypto section: {missing_fields}\n"
                f"   Add these fields to geoip_enricher_config_v31.json"
            )

        # Input socket config (CONNECT al sniffer)
        input_host = "localhost"
        input_port = 5570

        if 'network' in self.geoip_config and 'input_socket' in self.geoip_config['network']:
            input_socket = self.geoip_config['network']['input_socket']
            input_host = input_socket.get('address', 'localhost')
            input_port = input_socket.get('port', 5570)

        # Output socket config (BIND para ML detector)
        output_host = "localhost"
        output_port = 5560

        if 'network' in self.geoip_config and 'output_socket' in self.geoip_config['network']:
            output_socket = self.geoip_config['network']['output_socket']
            output_host = output_socket.get('address', 'localhost')
            output_port = output_socket.get('port', 5560)

        # Extraer HTTP API si existe (opcional)
        http_api_host = None
        http_api_port = None

        if 'http' in self.geoip_config:
            http_section = self.geoip_config['http']
            if 'api' in http_section:
                api_section = http_section['api']
                http_api_host = api_section.get('host')
                http_api_port = api_section.get('port')

        # Crear config ETCD
        self.etcd_config = GeoIPETCDConfig(
            etcd_host=etcd_section['etcd_host'],
            etcd_port=etcd_section['etcd_port'],
            cluster_name=etcd_section['cluster_name'],
            node_id=etcd_section['node_id'],
            input_host=input_host,
            input_port=input_port,
            output_host=output_host,
            output_port=output_port,
            http_api_host=http_api_host,
            http_api_port=http_api_port
        )

        self.logger.info("✅ ETCD config extracted successfully")
        self.logger.info(f"   📡 ETCD: {self.etcd_config.etcd_host}:{self.etcd_config.etcd_port}")
        self.logger.info(f"   🏢 Cluster: {self.etcd_config.cluster_name}")
        self.logger.info(f"   🆔 Node ID: {self.etcd_config.node_id}")
        self.logger.info(f"   📥 Input: {self.etcd_config.input_host}:{self.etcd_config.input_port}")
        self.logger.info(f"   📤 Output: {self.etcd_config.output_host}:{self.etcd_config.output_port}")

    def _build_component_info(self) -> Dict:
        """Construir información del componente geoip enricher para registro ETCD"""

        endpoints = {
            "zmq_pull": f"tcp://{self.etcd_config.input_host}:{self.etcd_config.input_port}",
            "zmq_push": f"tcp://{self.etcd_config.output_host}:{self.etcd_config.output_port}"
        }

        if self.etcd_config.http_api_host and self.etcd_config.http_api_port:
            endpoints["http_api"] = f"http://{self.etcd_config.http_api_host}:{self.etcd_config.http_api_port}"

        return {
            "node_id": self.etcd_config.node_id,
            "component_type": "geoip_enricher",
            "version": "3.1.0",
            "capabilities": [
                "geoip_enrichment",
                "tripartite_enrichment",
                "sniffer_node_geo",
                "source_ip_geo",
                "destination_ip_geo",
                "maxmind_lookup",
                "ipapi_lookup",
                "private_ip_resolution",
                "public_ip_discovery"
            ],
            "endpoints": endpoints,
            "host_ip": self._get_component_ip(),
            "process_id": os.getpid(),
            "crypto_role": "receiver_sender",  # Descifra del sniffer, cifra hacia ML detector
            "pipeline_position": 2,
            "input_from": ["evolutionary_sniffer"],
            "output_to": ["ml_detector"]
        }

    def _get_component_ip(self) -> str:
        """Obtener IP del componente"""
        # Intentar obtener IP desde environment (K8s POD_IP)
        pod_ip = os.environ.get("POD_IP")
        if pod_ip:
            return pod_ip

        # Intentar obtener hostname (K8s pod name)
        hostname = os.environ.get("HOSTNAME")
        if hostname and hostname != "localhost":
            return hostname

        # Fallback: obtener IP local
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    async def initialize_crypto(self) -> bool:
        """
        Inicializar crypto para geoip enricher con fallbacks
        """
        try:
            self.logger.info("🚀 Initializing ETCD crypto for geoip enricher...")

            # 1. Cargar config del geoip enricher
            self._load_geoip_config()

            # 2. Extraer config ETCD
            self._extract_etcd_config()

            # 3. Verificar ETCD disponible
            if not ETCD_AVAILABLE:
                if self.testing_mode:
                    self.logger.warning("⚠️  ETCD not available - using mock token for testing")
                    self.pipeline_key = "mock_pipeline_key_for_testing_geoip_" + "x" * 32
                    self.crypto_ready = True
                    return True
                else:
                    raise RuntimeError("❌ etcd3 package not available and not in testing mode")

            # 4. Conectar a ETCD
            self.logger.info(f"📡 Connecting to ETCD at {self.etcd_config.etcd_host}:{self.etcd_config.etcd_port}...")

            try:
                etcd_client = etcd3.client(
                    host=self.etcd_config.etcd_host,
                    port=self.etcd_config.etcd_port,
                    timeout=5
                )

                # Test connection
                etcd_client.status()
                self.logger.info("✅ ETCD connection successful")

            except Exception as e:
                if self.testing_mode:
                    self.logger.warning(f"⚠️  ETCD connection failed - using mock token: {e}")
                    self.pipeline_key = "mock_pipeline_key_for_testing_geoip_" + "x" * 32
                    self.crypto_ready = True
                    return True
                else:
                    raise ConnectionError(f"❌ Cannot connect to ETCD: {e}")

            # 5. Importar coordinador
            try:
                # Intentar importar desde diferentes paths
                try:
                    from core.etcd_coordinator import ETCDCryptoCoordinator
                except ImportError:
                    from etcd_coordinator import ETCDCryptoCoordinator
            except ImportError as e:
                if self.testing_mode:
                    self.logger.warning(f"⚠️  ETCDCryptoCoordinator not available - using mock: {e}")
                    self.pipeline_key = "mock_pipeline_key_for_testing_geoip_" + "x" * 32
                    self.crypto_ready = True
                    return True
                else:
                    raise ImportError(f"❌ Cannot import ETCDCryptoCoordinator: {e}")

            # 6. Crear coordinador
            coordinator = ETCDCryptoCoordinator(
                etcd_host=self.etcd_config.etcd_host,
                etcd_port=self.etcd_config.etcd_port,
                cluster_name=self.etcd_config.cluster_name
            )

            # 7. Iniciar coordinador
            self.logger.info("🔄 Starting ETCD coordinator client...")
            await coordinator.start()

            # 8. Preparar info del componente
            component_info = self._build_component_info()

            # 9. Registrar componente
            self.logger.info("📝 Registering geoip enricher component with ETCD...")
            success, response = await coordinator.register_component(component_info)

            if not success:
                error_msg = response.get('error', 'unknown error')
                raise RuntimeError(f"❌ Component registration failed: {error_msg}")

            # 10. Extraer token crypto
            crypto_token = response["crypto_token"]
            self.pipeline_key = crypto_token["key_material"]
            self.crypto_ready = True

            self.logger.info("✅ GeoIP enricher crypto initialization successful!")
            self.logger.info(f"🔑 Token version: {crypto_token['version']}")
            self.logger.info(f"📋 Registration hash: {response['registration_hash'][:16]}...")
            self.logger.info(f"🔐 Crypto role: receiver_sender (descifra del sniffer, cifra hacia ML)")

            return True

        except Exception as e:
            self.logger.error(f"❌ Crypto initialization failed: {e}")

            # Fallback para development/testing
            if self.testing_mode or os.environ.get("UPGRADED_HAPPINESS_DEV_MODE"):
                self.logger.warning("🧪 Using fallback mock token for development")
                self.pipeline_key = "dev_pipeline_key_geoip_" + "x" * 40
                self.crypto_ready = True
                return True

            return False

    def get_pipeline_key(self) -> Optional[str]:
        """Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para geoip enricher"""
        if not self.crypto_ready:
            self.logger.error("❌ Crypto not ready - call initialize_crypto() first")
            return None

        return self.pipeline_key

    def is_crypto_ready(self) -> bool:
        """Verificar si crypto está listo"""
        return self.crypto_ready and self.pipeline_key is not None

    def get_status(self) -> Dict:
        """Obtener estado para debugging"""
        status = {
            "ready": self.crypto_ready,
            "testing_mode": self.testing_mode,
            "config_path": self.geoip_config_path,
            "pipeline_key_available": self.pipeline_key is not None,
            "etcd_available": ETCD_AVAILABLE,
            "etcd_client_type": ETCD_CLIENT_TYPE,
            "component_type": "geoip_enricher",
            "crypto_role": "receiver_sender"
        }

        if self.etcd_config:
            status.update({
                "etcd_host": self.etcd_config.etcd_host,
                "etcd_port": self.etcd_config.etcd_port,
                "cluster_name": self.etcd_config.cluster_name,
                "node_id": self.etcd_config.node_id,
                "input_endpoint": f"{self.etcd_config.input_host}:{self.etcd_config.input_port}",
                "output_endpoint": f"{self.etcd_config.output_host}:{self.etcd_config.output_port}"
            })

        return status


# ===============================================================================
# GLOBAL FUNCTIONS FIJAS para integración en geoip_enricher_v31.py
# ===============================================================================

# Global client instance
_geoip_crypto_client = None


async def setup_geoip_crypto(geoip_config_path: str, testing_mode: bool = False) -> bool:
    """
    Setup crypto FIJO para geoip enricher

    Args:
        geoip_config_path: Ruta al geoip_enricher_config_v31.json
        testing_mode: Si True, usa mock tokens si ETCD falla

    Returns:
        True si exitoso, False si falla
    """
    global _geoip_crypto_client

    try:
        # Detect dev mode automatically
        if os.environ.get("UPGRADED_HAPPINESS_DEV_MODE") == "true":
            testing_mode = True
            print("🧪 Dev mode detected - enabling testing mode")

        _geoip_crypto_client = ETCDCryptoClientGeoIP(geoip_config_path, testing_mode)
        return await _geoip_crypto_client.initialize_crypto()
    except Exception as e:
        print(f"❌ Setup geoip crypto failed: {e}")
        return False


def get_geoip_pipeline_key() -> Optional[str]:
    """
    Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para geoip enricher
    REEMPLAZA: os.environ.get("UPGRADED_HAPPINESS_PIPELINE_KEY")
    """
    global _geoip_crypto_client

    if _geoip_crypto_client is None:
        print("❌ GeoIP crypto not initialized - call setup_geoip_crypto() first")
        return None

    return _geoip_crypto_client.get_pipeline_key()


def get_geoip_crypto_status() -> Dict:
    """Obtener estado crypto del geoip enricher"""
    global _geoip_crypto_client

    if _geoip_crypto_client is None:
        return {"error": "not_initialized"}

    return _geoip_crypto_client.get_status()


# ===============================================================================
# TESTING Y DESARROLLO
# ===============================================================================

async def create_test_geoip_config(config_path: str):
    """Crear configuración de test para geoip enricher"""
    test_config = {
        "component": {
            "name": "geoip_enricher",
            "version": "3.1.0",
            "mode": "distributed_vertical",
            "description": "GeoIP Enricher v3.1.0 TRIPARTITO with ETCD crypto"
        },
        "node_id": "geoip_enricher_v31_test_001",
        "etcd_crypto": {
            "etcd_host": "localhost",
            "etcd_port": 2379,
            "cluster_name": "upgraded-happiness-cluster",
            "node_id": "geoip_enricher_v31_test_001"
        },
        "network": {
            "input_socket": {
                "address": "localhost",
                "port": 5570,
                "mode": "connect",
                "socket_type": "PULL",
                "description": "Recibe eventos del evolutionary_sniffer_v31"
            },
            "output_socket": {
                "address": "localhost",
                "port": 5560,
                "mode": "bind",
                "socket_type": "PUSH",
                "description": "Envía eventos enriquecidos al ml_detector"
            }
        },
        "crypto": {
            "enabled": True,
            "role": "receiver_sender"
        },
        "geoip": {
            "lookup_method": "maxmind",
            "fallback_method": "ipapi"
        }
    }

    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    with open(config_path, 'w') as f:
        json.dump(test_config, f, indent=2)

    print(f"✅ Test geoip config created: {config_path}")


async def test_geoip_crypto_fixed():
    """Test completo del cliente crypto fijo para geoip enricher"""
    print("🧪 Testing ETCD Crypto Client - GEOIP ENRICHER VERSION")
    print("=" * 60)

    test_config_path = "/tmp/test_geoip_config_fixed.json"

    try:
        # 1. Crear config de test
        await create_test_geoip_config(test_config_path)

        # 2. Test con testing mode enabled
        print("\n📋 Testing with testing mode enabled...")
        success = await setup_geoip_crypto(test_config_path, testing_mode=True)

        if success:
            print("✅ GeoIP enricher crypto setup successful!")

            # 3. Test key retrieval
            pipeline_key = get_geoip_pipeline_key()
            if pipeline_key:
                print(f"🔑 Pipeline key: {pipeline_key[:32]}...")

                # 4. Test status
                status = get_geoip_crypto_status()
                print(f"📊 Status: {json.dumps(status, indent=2)}")

                print("\n🎯 READY FOR GEOIP ENRICHER INTEGRATION!")
            else:
                print("❌ Failed to get pipeline key")
        else:
            print("❌ GeoIP enricher crypto setup failed!")

        # 5. Test sin testing mode (para ver diferencia)
        print("\n📋 Testing without testing mode (may fail)...")
        success_strict = await setup_geoip_crypto(test_config_path, testing_mode=False)
        print(f"Strict mode result: {'✅ Success' if success_strict else '❌ Failed (expected)'}")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Cleanup
        if os.path.exists(test_config_path):
            os.unlink(test_config_path)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "test":
            asyncio.run(test_geoip_crypto_fixed())
        elif command == "fix-deps":
            print("🔧 DEPENDENCY FIX OPTIONS:")
            print("1. pip install 'protobuf<=3.20.3'")
            print("2. export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python")
            print("3. pip install etcd3-py (alternative)")
        else:
            print(f"❌ Unknown command: {command}")
            print("💡 Available: test, fix-deps")
    else:
        print("🌍 ETCD Crypto Client - GEOIP ENRICHER VERSION")
        print("=" * 50)
        print()
        print("🎯 CAPABILITIES:")
        print("   ✅ Handles protobuf compatibility issues")
        print("   ✅ Testing mode for development")
        print("   ✅ Fallbacks if ETCD unavailable")
        print("   ✅ Better error handling")
        print("   ✅ Auto-detection of dev mode")
        print("   ✅ receiver_sender crypto role")
        print("   ✅ GeoIP enricher specific registration")
        print()
        print("🚀 USAGE:")
        print("   python3 etcd_crypto_client_geoip_fixed.py test")
        print("   python3 etcd_crypto_client_geoip_fixed.py fix-deps")
        print()
        print("🧪 DEV MODE:")
        print("   export UPGRADED_HAPPINESS_DEV_MODE=true")