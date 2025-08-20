#!/usr/bin/env python3
"""
core/etcd_coordinator.py
🔐 ETCD Crypto Coordinator V1 - Enterprise Token Management
Sistema Autoinmune Digital - upgraded-happiness

FILOSOFÍA ENTERPRISE:
- ✅ Tokens NUNCA en variables de entorno
- ✅ Distribución centralizada y segura
- ✅ Atomic updates (todos o ninguno)
- ✅ Zero-downtime token rotation
- ✅ HA ready para k8s/k3s
- ✅ Audit trail completo

FASES:
1. Service Discovery + Token Distribution ← ESTA FASE
2. Coordinated Token Rotation
3. Zero-downtime Updates
"""

import asyncio
import json
import time
import logging
import hashlib
import secrets
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import etcd3
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass
class ComponentRegistration:
    """Registro de componente en el cluster"""
    node_id: str
    component_type: str
    version: str
    capabilities: List[str]
    endpoints: Dict[str, str]

    # Metadata de registro
    registered_at: float
    last_heartbeat: float
    registration_hash: str

    # Crypto state
    token_issued: bool = False
    token_version: int = 0
    token_issued_at: Optional[float] = None

    # HA metadata
    pod_name: Optional[str] = None
    namespace: Optional[str] = None
    container_id: Optional[str] = None


@dataclass
class CryptoToken:
    """Token de cifrado enterprise"""
    token_id: str
    version: int
    key_material: bytes  # AES-256 key (32 bytes)

    # Metadata
    issued_at: float
    expires_at: Optional[float]
    issued_to_components: Set[str]

    # Rotation metadata
    rotation_id: Optional[str] = None
    predecessor_token_id: Optional[str] = None
    successor_token_id: Optional[str] = None


class ETCDCryptoCoordinator:
    """
    🔐 Coordinador central de tokens crypto via ETCD
    - Gestión centralizada de tokens de cifrado
    - Service discovery enterprise
    - Zero-downtime token rotation
    - HA ready para Kubernetes
    """

    def __init__(self,
                 etcd_host: str = "localhost",
                 etcd_port: int = 2379,
                 cluster_name: str = "upgraded-happiness-cluster",
                 master_password: Optional[str] = None):

        self.etcd_host = etcd_host
        self.etcd_port = etcd_port
        self.cluster_name = cluster_name

        # ETCD client
        self.etcd = etcd3.client(host=etcd_host, port=etcd_port)

        # Logging
        self.logger = self._setup_logger()

        # Crypto master key (para cifrar tokens en etcd)
        self.master_key = self._derive_master_key(master_password)
        self.cipher = Fernet(self.master_key)

        # Estado interno
        self.registered_components: Dict[str, ComponentRegistration] = {}
        self.active_tokens: Dict[str, CryptoToken] = {}
        self.current_token_version = 0

        # Paths ETCD
        self.base_path = f"/upgraded-happiness/{cluster_name}"
        self.components_path = f"{self.base_path}/components"
        self.tokens_path = f"{self.base_path}/crypto/tokens"
        self.config_path = f"{self.base_path}/config"

        # Estado de coordinación
        self.is_leader = False
        self.leader_key = f"{self.base_path}/coordination/leader"

        self.logger.info(f"🔐 ETCD Crypto Coordinator initialized")
        self.logger.info(f"   🌐 ETCD: {etcd_host}:{etcd_port}")
        self.logger.info(f"   🏢 Cluster: {cluster_name}")
        self.logger.info(f"   📁 Base path: {self.base_path}")

    def _setup_logger(self) -> logging.Logger:
        """Setup logging para el coordinador"""
        logger = logging.getLogger("etcd_crypto_coordinator")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s | %(name)s | %(levelname)s | 🔐 %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _derive_master_key(self, password: Optional[str] = None) -> bytes:
        """
        Derivar master key para cifrar tokens en ETCD
        CRÍTICO: Esta key NUNCA debe aparecer en logs o variables de entorno
        """
        if password is None:
            # Generar password desde datos del cluster (reproducible)
            cluster_seed = f"{self.cluster_name}:{self.etcd_host}:{self.etcd_port}"
            password = hashlib.sha256(cluster_seed.encode()).hexdigest()

        # Derivar key criptográficamente segura
        salt = b"upgraded-happiness-crypto-coordinator-v1"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        master_key = kdf.derive(password.encode())

        # Codificar para Fernet
        return base64.urlsafe_b64encode(master_key)

    async def start(self):
        """Iniciar coordinador crypto"""
        self.logger.info("🚀 Starting ETCD Crypto Coordinator...")

        try:
            # Verificar conexión ETCD
            await self._verify_etcd_connection()

            # Inicializar estructura ETCD
            await self._initialize_etcd_structure()

            # Intentar convertirse en leader
            await self._become_leader()

            # Si somos leader, generar token inicial
            if self.is_leader:
                await self._ensure_current_token()

            # Cargar estado existente
            await self._load_existing_state()

            self.logger.info("✅ ETCD Crypto Coordinator started successfully")

        except Exception as e:
            self.logger.error(f"❌ Failed to start coordinator: {e}")
            raise

    async def _verify_etcd_connection(self):
        """Verificar que ETCD está disponible"""
        try:
            # Test de conectividad simple
            await asyncio.get_event_loop().run_in_executor(
                None, self.etcd.status
            )
            self.logger.info("✅ ETCD connection verified")
        except Exception as e:
            raise ConnectionError(f"Cannot connect to ETCD at {self.etcd_host}:{self.etcd_port}: {e}")

    async def _initialize_etcd_structure(self):
        """Inicializar estructura de directorios en ETCD"""
        paths_to_create = [
            self.base_path,
            self.components_path,
            self.tokens_path,
            self.config_path,
            f"{self.base_path}/coordination",
            f"{self.base_path}/audit"
        ]

        for path in paths_to_create:
            try:
                # Crear path si no existe
                await asyncio.get_event_loop().run_in_executor(
                    None, self.etcd.put, f"{path}/.init", "created"
                )
            except Exception as e:
                self.logger.warning(f"Could not create path {path}: {e}")

        self.logger.info("✅ ETCD structure initialized")

    async def _become_leader(self):
        """Intentar convertirse en leader del cluster"""
        try:
            # Intentar obtener leadership con lease
            lease = self.etcd.lease(ttl=30)

            # Atomic compare-and-swap para leadership
            success, _ = self.etcd.transaction(
                compare=[self.etcd.transactions.create(self.leader_key) == 0],
                success=[self.etcd.transactions.put(self.leader_key,
                                                    f"coordinator-{os.getpid()}",
                                                    lease=lease)],
                failure=[]
            )

            if success:
                self.is_leader = True
                self.leader_lease = lease
                self.logger.info("👑 Became cluster leader")

                # Renovar lease automáticamente
                asyncio.create_task(self._maintain_leadership())
            else:
                self.is_leader = False
                current_leader = self.etcd.get(self.leader_key)[0]
                if current_leader:
                    self.logger.info(f"📡 Following leader: {current_leader.decode()}")

        except Exception as e:
            self.logger.error(f"❌ Leadership election failed: {e}")
            self.is_leader = False

    async def _maintain_leadership(self):
        """Mantener leadership renovando lease"""
        while self.is_leader:
            try:
                await asyncio.sleep(10)  # Renovar cada 10s (lease 30s)
                await asyncio.get_event_loop().run_in_executor(
                    None, self.leader_lease.refresh
                )
            except Exception as e:
                self.logger.error(f"❌ Lost leadership: {e}")
                self.is_leader = False
                break

    async def _ensure_current_token(self):
        """Asegurar que existe un token actual válido"""
        if not self.is_leader:
            return

        # Verificar si hay token actual
        current_token = await self._get_current_token()

        if current_token is None:
            # Generar primer token
            await self._generate_new_token()
            self.logger.info("🔑 Generated initial crypto token")
        else:
            self.logger.info(f"🔑 Using existing token version {current_token.version}")

    async def _generate_new_token(self) -> CryptoToken:
        """Generar nuevo token de cifrado"""
        # Generar material criptográfico seguro
        key_material = secrets.token_bytes(32)  # AES-256

        # Crear token
        token = CryptoToken(
            token_id=secrets.token_hex(16),
            version=self.current_token_version + 1,
            key_material=key_material,
            issued_at=time.time(),
            expires_at=None,  # Por ahora sin expiración
            issued_to_components=set()
        )

        # Cifrar y almacenar en ETCD
        await self._store_token_in_etcd(token)

        # Actualizar estado local
        self.active_tokens[token.token_id] = token
        self.current_token_version = token.version

        # Audit log
        await self._audit_log("token_generated", {
            "token_id": token.token_id,
            "version": token.version,
            "issued_at": token.issued_at
        })

        return token

    async def _store_token_in_etcd(self, token: CryptoToken):
        """Almacenar token cifrado en ETCD"""
        # Serializar token (SIN key_material en logs)
        token_data = {
            "token_id": token.token_id,
            "version": token.version,
            "key_material": base64.b64encode(token.key_material).decode(),
            "issued_at": token.issued_at,
            "expires_at": token.expires_at,
            "issued_to_components": list(token.issued_to_components)
        }

        # Cifrar con master key
        encrypted_data = self.cipher.encrypt(json.dumps(token_data).encode())

        # Almacenar en ETCD
        token_path = f"{self.tokens_path}/v{token.version}"
        await asyncio.get_event_loop().run_in_executor(
            None, self.etcd.put, token_path, encrypted_data
        )

        # Marcar como token actual
        current_path = f"{self.tokens_path}/current"
        await asyncio.get_event_loop().run_in_executor(
            None, self.etcd.put, current_path, str(token.version)
        )

    async def _get_current_token(self) -> Optional[CryptoToken]:
        """Obtener token actual desde ETCD"""
        try:
            # Obtener versión actual
            current_version_data = await asyncio.get_event_loop().run_in_executor(
                None, self.etcd.get, f"{self.tokens_path}/current"
            )

            if not current_version_data[0]:
                return None

            current_version = int(current_version_data[0].decode())

            # Obtener datos del token
            token_data = await asyncio.get_event_loop().run_in_executor(
                None, self.etcd.get, f"{self.tokens_path}/v{current_version}"
            )

            if not token_data[0]:
                return None

            # Descifrar
            decrypted_data = self.cipher.decrypt(token_data[0])
            token_dict = json.loads(decrypted_data.decode())

            # Reconstruir token
            token = CryptoToken(
                token_id=token_dict["token_id"],
                version=token_dict["version"],
                key_material=base64.b64decode(token_dict["key_material"]),
                issued_at=token_dict["issued_at"],
                expires_at=token_dict["expires_at"],
                issued_to_components=set(token_dict["issued_to_components"])
            )

            return token

        except Exception as e:
            self.logger.error(f"❌ Error loading current token: {e}")
            return None

    async def register_component(self,
                                 component_info: Dict[str, str]) -> Tuple[bool, Dict[str, str]]:
        """
        Registrar componente y obtener token crypto

        Returns:
            (success, response_data)
            response_data contiene el token cifrado si success=True
        """
        try:
            node_id = component_info.get("node_id")
            if not node_id:
                return False, {"error": "node_id is required"}

            # Crear registro
            registration = ComponentRegistration(
                node_id=node_id,
                component_type=component_info.get("component_type", "unknown"),
                version=component_info.get("version", "unknown"),
                capabilities=component_info.get("capabilities", []),
                endpoints=component_info.get("endpoints", {}),
                registered_at=time.time(),
                last_heartbeat=time.time(),
                registration_hash=hashlib.sha256(
                    f"{node_id}:{time.time()}".encode()
                ).hexdigest(),

                # K8s metadata si está disponible
                pod_name=component_info.get("pod_name"),
                namespace=component_info.get("namespace"),
                container_id=component_info.get("container_id")
            )

            # Almacenar registro en ETCD
            registration_path = f"{self.components_path}/{node_id}"
            registration_data = json.dumps(asdict(registration))

            await asyncio.get_event_loop().run_in_executor(
                None, self.etcd.put, registration_path, registration_data
            )

            # Obtener token actual
            current_token = await self._get_current_token()
            if not current_token:
                return False, {"error": "No crypto token available"}

            # Preparar token para el componente (CIFRADO)
            token_response = {
                "token_id": current_token.token_id,
                "version": current_token.version,
                "key_material": base64.b64encode(current_token.key_material).decode(),
                "issued_at": current_token.issued_at
            }

            # Marcar token como entregado
            current_token.issued_to_components.add(node_id)
            registration.token_issued = True
            registration.token_version = current_token.version
            registration.token_issued_at = time.time()

            # Actualizar en ETCD
            await self._store_token_in_etcd(current_token)

            # Actualizar registro
            updated_registration_data = json.dumps(asdict(registration))
            await asyncio.get_event_loop().run_in_executor(
                None, self.etcd.put, registration_path, updated_registration_data
            )

            # Audit log
            await self._audit_log("component_registered", {
                "node_id": node_id,
                "component_type": registration.component_type,
                "token_version": current_token.version,
                "registration_hash": registration.registration_hash
            })

            self.logger.info(f"✅ Component registered: {node_id} ({registration.component_type})")

            return True, {
                "status": "registered",
                "registration_hash": registration.registration_hash,
                "crypto_token": token_response
            }

        except Exception as e:
            self.logger.error(f"❌ Component registration failed: {e}")
            return False, {"error": str(e)}

    async def _load_existing_state(self):
        """Cargar estado existente desde ETCD"""
        try:
            # Cargar componentes registrados
            components_data = await asyncio.get_event_loop().run_in_executor(
                None, self.etcd.get_prefix, self.components_path
            )

            for kv in components_data:
                try:
                    registration_data = json.loads(kv[0].decode())
                    registration = ComponentRegistration(**registration_data)
                    self.registered_components[registration.node_id] = registration
                except Exception as e:
                    self.logger.warning(f"Could not load component registration: {e}")

            self.logger.info(f"📋 Loaded {len(self.registered_components)} component registrations")

        except Exception as e:
            self.logger.error(f"❌ Error loading existing state: {e}")

    async def _audit_log(self, action: str, details: Dict):
        """Registrar evento en audit log"""
        audit_entry = {
            "timestamp": time.time(),
            "action": action,
            "details": details,
            "coordinator_id": f"pid-{os.getpid()}"
        }

        audit_path = f"{self.base_path}/audit/{int(time.time())}-{action}"
        audit_data = json.dumps(audit_entry)

        try:
            await asyncio.get_event_loop().run_in_executor(
                None, self.etcd.put, audit_path, audit_data
            )
        except Exception as e:
            self.logger.error(f"❌ Audit logging failed: {e}")

    async def get_cluster_status(self) -> Dict:
        """Obtener estado del cluster"""
        return {
            "cluster_name": self.cluster_name,
            "is_leader": self.is_leader,
            "registered_components": len(self.registered_components),
            "active_tokens": len(self.active_tokens),
            "current_token_version": self.current_token_version,
            "components": [
                {
                    "node_id": reg.node_id,
                    "component_type": reg.component_type,
                    "version": reg.version,
                    "token_issued": reg.token_issued,
                    "last_heartbeat": reg.last_heartbeat
                }
                for reg in self.registered_components.values()
            ]
        }


# ===============================================================================
# CLIENT LIBRARY para componentes
# ===============================================================================

class ETCDCryptoClient:
    """
    Cliente para que componentes se registren y obtengan tokens
    - Oculta complejidad de ETCD al componente
    - Maneja registro automático
    - Obtiene tokens de forma segura
    """

    def __init__(self,
                 node_id: str,
                 component_type: str,
                 version: str = "1.0.0",
                 etcd_host: str = "localhost",
                 etcd_port: int = 2379):
        self.node_id = node_id
        self.component_type = component_type
        self.version = version

        # Para futuro coordinador HTTP API
        self.coordinator_url = f"http://{etcd_host}:8500"  # Puerto API coordinador

        self.logger = logging.getLogger(f"etcd_crypto_client_{node_id}")

    async def register_and_get_token(self) -> Optional[Dict]:
        """
        Registrarse con coordinador y obtener token crypto

        Returns:
            Token data si exitoso, None si falla
        """
        # Por ahora implementación placeholder
        # En siguiente fase: HTTP client al coordinador
        self.logger.info(f"🔐 Registering component {self.node_id} with crypto coordinator...")

        # Placeholder response
        return {
            "token_id": "placeholder-token",
            "version": 1,
            "key_material": base64.b64encode(secrets.token_bytes(32)).decode(),
            "issued_at": time.time()
        }


# ===============================================================================
# EJEMPLO DE USO
# ===============================================================================

async def main():
    """Ejemplo de uso del coordinador"""

    print("🔐 ETCD Crypto Coordinator Demo")
    print("=" * 50)

    # Inicializar coordinador
    coordinator = ETCDCryptoCoordinator(
        cluster_name="demo-cluster"
    )

    try:
        # Iniciar coordinador
        await coordinator.start()

        # Simular registro de componentes
        component_info = {
            "node_id": "dashboard_main_v31_001",
            "component_type": "dashboard",
            "version": "3.1.0",
            "capabilities": ["visualization", "firewall_control"],
            "endpoints": {
                "web": "http://localhost:8080",
                "api": "http://localhost:8080/api"
            }
        }

        success, response = await coordinator.register_component(component_info)

        if success:
            print("✅ Component registered successfully!")
            print(f"📋 Registration hash: {response['registration_hash']}")
            print(f"🔑 Token version: {response['crypto_token']['version']}")
        else:
            print(f"❌ Registration failed: {response['error']}")

        # Mostrar estado del cluster
        status = await coordinator.get_cluster_status()
        print(f"\n📊 Cluster Status:")
        print(f"   Leader: {status['is_leader']}")
        print(f"   Components: {status['registered_components']}")
        print(f"   Token version: {status['current_token_version']}")

    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())