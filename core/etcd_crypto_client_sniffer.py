#!/usr/bin/env python3
"""
core/etcd_crypto_client_sniffer.py
🔍 Cliente ETCD específico para Evolutionary Sniffer
- Lee SOLO desde evolutionary_sniffer_config_v31.json
- ZERO hardcoded values
- Si no está en JSON → ERROR y STOP
- Single responsibility: obtener token crypto para sniffer
"""

import asyncio
import json
import logging
import os
import sys
from typing import Dict, Optional
from dataclasses import dataclass

# Conditional import
try:
    import etcd3

    ETCD_AVAILABLE = True
except ImportError:
    ETCD_AVAILABLE = False
    print("❌ etcd3 package required: pip install etcd3")
    sys.exit(1)


@dataclass
class SnifferETCDConfig:
    """Configuración ETCD extraída desde evolutionary_sniffer_config_v31.json"""
    etcd_host: str
    etcd_port: int
    cluster_name: str
    node_id: str

    # Endpoints extraídos del config del sniffer
    zmq_publisher_host: str
    zmq_publisher_port: int

    # Opcional: HTTP API si está configurado
    http_api_host: Optional[str] = None
    http_api_port: Optional[int] = None


class ETCDCryptoClientSniffer:
    """
    🔍 Cliente ETCD específico para Evolutionary Sniffer
    - Lee evolutionary_sniffer_config_v31.json
    - Extrae configuración ETCD obligatoria
    - Se registra y obtiene token crypto
    - ZERO defaults, ZERO hardcoded
    """

    def __init__(self, sniffer_config_path: str):
        self.sniffer_config_path = sniffer_config_path
        self.sniffer_config = None
        self.etcd_config = None
        self.pipeline_key = None
        self.crypto_ready = False

        # Logger específico del sniffer
        self.logger = logging.getLogger("etcd_crypto_sniffer")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s | 🔍 SNIFFER-CRYPTO | %(levelname)s | %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def _load_sniffer_config(self):
        """Cargar configuración del sniffer desde JSON"""
        self.logger.info(f"📋 Loading sniffer config from: {self.sniffer_config_path}")

        if not os.path.exists(self.sniffer_config_path):
            raise FileNotFoundError(f"❌ Sniffer config file not found: {self.sniffer_config_path}")

        try:
            with open(self.sniffer_config_path, 'r') as f:
                self.sniffer_config = json.load(f)

            self.logger.info("✅ Sniffer config loaded successfully")

        except json.JSONDecodeError as e:
            raise ValueError(f"❌ Invalid JSON in sniffer config: {e}")
        except Exception as e:
            raise RuntimeError(f"❌ Failed to load sniffer config: {e}")

    def _extract_etcd_config(self):
        """
        Extraer configuración ETCD desde config del sniffer
        OBLIGATORIO: debe existir sección 'etcd_crypto' en el JSON
        """
        self.logger.info("🔍 Extracting ETCD config from sniffer config...")

        if not self.sniffer_config:
            raise RuntimeError("❌ Sniffer config not loaded")

        # OBLIGATORIO: sección etcd_crypto debe existir
        if 'etcd_crypto' not in self.sniffer_config:
            raise KeyError(
                "❌ REQUIRED section 'etcd_crypto' not found in sniffer config.\n"
                "   Add 'etcd_crypto' section to evolutionary_sniffer_config_v31.json"
            )

        etcd_section = self.sniffer_config['etcd_crypto']

        # OBLIGATORIO: campos requeridos
        required_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']
        missing_fields = []

        for field in required_fields:
            if field not in etcd_section:
                missing_fields.append(field)

        if missing_fields:
            raise KeyError(
                f"❌ REQUIRED fields missing in etcd_crypto section: {missing_fields}\n"
                f"   Add these fields to evolutionary_sniffer_config_v31.json"
            )

        # OBLIGATORIO: ZMQ publisher config (sniffer siempre publica)
        if 'zmq' not in self.sniffer_config:
            raise KeyError("❌ REQUIRED section 'zmq' not found in sniffer config")

        zmq_section = self.sniffer_config['zmq']

        if 'publisher' not in zmq_section:
            raise KeyError("❌ REQUIRED section 'zmq.publisher' not found in sniffer config")

        publisher_section = zmq_section['publisher']

        zmq_required = ['host', 'port']
        zmq_missing = []

        for field in zmq_required:
            if field not in publisher_section:
                zmq_missing.append(f"zmq.publisher.{field}")

        if zmq_missing:
            raise KeyError(
                f"❌ REQUIRED ZMQ fields missing: {zmq_missing}\n"
                f"   Add these fields to evolutionary_sniffer_config_v31.json"
            )

        # Extraer HTTP API si existe (opcional)
        http_api_host = None
        http_api_port = None

        if 'http' in self.sniffer_config:
            http_section = self.sniffer_config['http']
            if 'api' in http_section:
                api_section = http_section['api']
                http_api_host = api_section.get('host')
                http_api_port = api_section.get('port')

        # Crear config ETCD
        self.etcd_config = SnifferETCDConfig(
            etcd_host=etcd_section['etcd_host'],
            etcd_port=etcd_section['etcd_port'],
            cluster_name=etcd_section['cluster_name'],
            node_id=etcd_section['node_id'],
            zmq_publisher_host=publisher_section['host'],
            zmq_publisher_port=publisher_section['port'],
            http_api_host=http_api_host,
            http_api_port=http_api_port
        )

        self.logger.info("✅ ETCD config extracted successfully")
        self.logger.info(f"   📡 ETCD: {self.etcd_config.etcd_host}:{self.etcd_config.etcd_port}")
        self.logger.info(f"   🏢 Cluster: {self.etcd_config.cluster_name}")
        self.logger.info(f"   🆔 Node ID: {self.etcd_config.node_id}")
        self.logger.info(f"   📤 ZMQ Pub: {self.etcd_config.zmq_publisher_host}:{self.etcd_config.zmq_publisher_port}")

    def _build_component_info(self) -> Dict:
        """Construir información del componente para registro ETCD"""

        endpoints = {
            "zmq_pub": f"tcp://{self.etcd_config.zmq_publisher_host}:{self.etcd_config.zmq_publisher_port}"
        }

        if self.etcd_config.http_api_host and self.etcd_config.http_api_port:
            endpoints["http_api"] = f"http://{self.etcd_config.http_api_host}:{self.etcd_config.http_api_port}"

        return {
            "node_id": self.etcd_config.node_id,
            "component_type": "evolutionary_sniffer",
            "version": "3.1.0",
            "capabilities": [
                "packet_capture",
                "traffic_analysis",
                "network_monitoring",
                "flow_detection",
                "protocol_analysis"
            ],
            "endpoints": endpoints,
            "host_ip": self._get_component_ip(),
            "process_id": os.getpid()
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
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "localhost"

    async def initialize_crypto(self) -> bool:
        """
        Inicializar crypto para sniffer
        1. Cargar config sniffer
        2. Extraer config ETCD
        3. Conectar a ETCD
        4. Registrar componente
        5. Obtener token crypto

        Returns:
            True si exitoso, False si falla
        """
        try:
            self.logger.info("🚀 Initializing ETCD crypto for evolutionary sniffer...")

            # 1. Cargar config del sniffer
            self._load_sniffer_config()

            # 2. Extraer config ETCD
            self._extract_etcd_config()

            # 3. Verificar ETCD disponible
            if not ETCD_AVAILABLE:
                raise RuntimeError("❌ etcd3 package not available")

            # 4. Conectar a ETCD
            self.logger.info(f"📡 Connecting to ETCD at {self.etcd_config.etcd_host}:{self.etcd_config.etcd_port}...")

            etcd_client = etcd3.client(
                host=self.etcd_config.etcd_host,
                port=self.etcd_config.etcd_port
            )

            # Test connection
            try:
                etcd_client.status()
                self.logger.info("✅ ETCD connection successful")
            except Exception as e:
                raise ConnectionError(f"❌ Cannot connect to ETCD: {e}")

            # 5. Importar y crear coordinador
            try:
                from core.etcd_coordinator import ETCDCryptoCoordinator
            except ImportError as e:
                raise ImportError(f"❌ Cannot import ETCDCryptoCoordinator: {e}")

            coordinator = ETCDCryptoCoordinator(
                etcd_host=self.etcd_config.etcd_host,
                etcd_port=self.etcd_config.etcd_port,
                cluster_name=self.etcd_config.cluster_name
            )

            # 6. Iniciar coordinador
            self.logger.info("🔄 Starting ETCD coordinator client...")
            await coordinator.start()

            # 7. Preparar info del componente
            component_info = self._build_component_info()

            # 8. Registrar componente
            self.logger.info("📝 Registering sniffer component with ETCD...")
            success, response = await coordinator.register_component(component_info)

            if not success:
                error_msg = response.get('error', 'unknown error')
                raise RuntimeError(f"❌ Component registration failed: {error_msg}")

            # 9. Extraer token crypto
            crypto_token = response["crypto_token"]
            self.pipeline_key = crypto_token["key_material"]
            self.crypto_ready = True

            self.logger.info("✅ Sniffer crypto initialization successful!")
            self.logger.info(f"🔑 Token version: {crypto_token['version']}")
            self.logger.info(f"📋 Registration hash: {response['registration_hash'][:16]}...")

            return True

        except Exception as e:
            self.logger.error(f"❌ Crypto initialization failed: {e}")
            return False

    def get_pipeline_key(self) -> Optional[str]:
        """
        Obtener UPGRADED_HAPPINESS_PIPELINE_KEY

        Returns:
            Pipeline key si está disponible, None si no
        """
        if not self.crypto_ready:
            self.logger.error("❌ Crypto not ready - call initialize_crypto() first")
            return None

        return self.pipeline_key

    def is_crypto_ready(self) -> bool:
        """Verificar si crypto está listo"""
        return self.crypto_ready and self.pipeline_key is not None

    def get_status(self) -> Dict:
        """Obtener estado para debugging"""
        if not self.etcd_config:
            return {
                "ready": False,
                "error": "config_not_loaded",
                "config_path": self.sniffer_config_path
            }

        return {
            "ready": self.crypto_ready,
            "config_path": self.sniffer_config_path,
            "etcd_host": self.etcd_config.etcd_host,
            "etcd_port": self.etcd_config.etcd_port,
            "cluster_name": self.etcd_config.cluster_name,
            "node_id": self.etcd_config.node_id,
            "pipeline_key_available": self.pipeline_key is not None
        }


# ===============================================================================
# GLOBAL FUNCTIONS para integración en evolutionary_sniffer_v31.py
# ===============================================================================

# Global client instance
_sniffer_crypto_client = None


async def setup_sniffer_crypto(sniffer_config_path: str) -> bool:
    """
    Setup crypto para evolutionary sniffer
    USAR SOLO ESTA FUNCIÓN en evolutionary_sniffer_v31.py

    Args:
        sniffer_config_path: Ruta al evolutionary_sniffer_config_v31.json

    Returns:
        True si exitoso, False si falla
    """
    global _sniffer_crypto_client

    try:
        _sniffer_crypto_client = ETCDCryptoClientSniffer(sniffer_config_path)
        return await _sniffer_crypto_client.initialize_crypto()
    except Exception as e:
        print(f"❌ Setup sniffer crypto failed: {e}")
        return False


def get_sniffer_pipeline_key() -> Optional[str]:
    """
    Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para sniffer

    ESTA FUNCIÓN REEMPLAZA:
        os.environ.get("UPGRADED_HAPPINESS_PIPELINE_KEY")

    Returns:
        Pipeline key si está disponible, None si no
    """
    global _sniffer_crypto_client

    if _sniffer_crypto_client is None:
        print("❌ Sniffer crypto not initialized - call setup_sniffer_crypto() first")
        return None

    return _sniffer_crypto_client.get_pipeline_key()


def get_sniffer_crypto_status() -> Dict:
    """Obtener estado crypto del sniffer"""
    global _sniffer_crypto_client

    if _sniffer_crypto_client is None:
        return {"error": "not_initialized"}

    return _sniffer_crypto_client.get_status()


# ===============================================================================
# EJEMPLO DE CONFIG REQUERIDO
# ===============================================================================

def show_required_config():
    """Mostrar estructura de config requerida"""

    required_config = {
        "zmq": {
            "publisher": {
                "host": "0.0.0.0",  # OBLIGATORIO
                "port": 5550  # OBLIGATORIO
            }
        },
        "etcd_crypto": {  # OBLIGATORIO: sección completa
            "etcd_host": "localhost",  # OBLIGATORIO
            "etcd_port": 2379,  # OBLIGATORIO
            "cluster_name": "upgraded-happiness-cluster",  # OBLIGATORIO
            "node_id": "evolutionary_sniffer_dev_001"  # OBLIGATORIO
        },
        "http": {  # OPCIONAL
            "api": {
                "host": "0.0.0.0",
                "port": 6550
            }
        }
    }

    print("📋 ESTRUCTURA DE CONFIG REQUERIDA:")
    print("=" * 40)
    print(json.dumps(required_config, indent=2))
    print()
    print("🔴 CAMPOS OBLIGATORIOS:")
    print("   - zmq.publisher.host")
    print("   - zmq.publisher.port")
    print("   - etcd_crypto.etcd_host")
    print("   - etcd_crypto.etcd_port")
    print("   - etcd_crypto.cluster_name")
    print("   - etcd_crypto.node_id")
    print()
    print("🟡 CAMPOS OPCIONALES:")
    print("   - http.api.host")
    print("   - http.api.port")
    print()
    print("⚠️  SI FALTA ALGÚN CAMPO OBLIGATORIO → ERROR y STOP")


# ===============================================================================
# TEST
# ===============================================================================

async def test_sniffer_crypto():
    """Test del cliente crypto específico del sniffer"""

    print("🧪 Testing ETCD Crypto Client - Sniffer Specific")
    print("=" * 50)

    # Crear config de test
    test_config = {
        "zmq": {
            "publisher": {
                "host": "0.0.0.0",
                "port": 5550
            }
        },
        "etcd_crypto": {
            "etcd_host": "localhost",
            "etcd_port": 2379,
            "cluster_name": "upgraded-happiness-cluster",
            "node_id": "evolutionary_sniffer_test_001"
        },
        "http": {
            "api": {
                "host": "0.0.0.0",
                "port": 6550
            }
        }
    }

    test_config_path = "/tmp/test_sniffer_config.json"

    try:
        # Guardar config de test
        with open(test_config_path, 'w') as f:
            json.dump(test_config, f, indent=2)

        print(f"📋 Created test config: {test_config_path}")

        # Test setup
        success = await setup_sniffer_crypto(test_config_path)

        if success:
            print("✅ Sniffer crypto setup successful!")

            # Test key retrieval
            pipeline_key = get_sniffer_pipeline_key()
            if pipeline_key:
                print(f"🔑 Pipeline key: {pipeline_key[:32]}...")

                # Test status
                status = get_sniffer_crypto_status()
                print(f"📊 Status: {status}")

                print("🎯 Ready for sniffer integration!")
            else:
                print("❌ Failed to get pipeline key")
        else:
            print("❌ Sniffer crypto setup failed!")

    except Exception as e:
        print(f"❌ Test failed: {e}")

    finally:
        # Cleanup
        if os.path.exists(test_config_path):
            os.unlink(test_config_path)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "config":
            show_required_config()
        elif command == "test":
            asyncio.run(test_sniffer_crypto())
        else:
            print(f"❌ Unknown command: {command}")
            print("💡 Available: config, test")
    else:
        print("🔍 ETCD Crypto Client - Sniffer Specific")
        print("=" * 40)
        print()
        print("🎯 SINGLE RESPONSIBILITY:")
        print("   - Lee evolutionary_sniffer_config_v31.json")
        print("   - Extrae config ETCD OBLIGATORIO")
        print("   - Se registra con ETCD")
        print("   - Devuelve token crypto")
        print()
        print("🚀 USAGE:")
        print("   python3 etcd_crypto_client_sniffer.py config")
        print("   python3 etcd_crypto_client_sniffer.py test")
        print()
        print("🔴 ZERO hardcoded values")
        print("🔴 ZERO defaults")
        print("🔴 Si no está en JSON → ERROR y STOP")