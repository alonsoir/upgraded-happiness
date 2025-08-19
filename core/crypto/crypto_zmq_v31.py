#!/usr/bin/env python3
"""
🔐 Crypto ZeroMQ Wrapper V3.1 - SIMPLIFICADO Y CONFIABLE
Sistema Autoinmune Digital - upgraded-happiness

FILOSOFÍA:
- SIEMPRE comprimir/descomprimir (sin threshold)
- SIEMPRE consistente (sin detección)
- SIEMPRE confiable (sin complejidad)
- Belleza en la simplicidad

CAMBIOS:
- ❌ Eliminado compression_threshold
- ❌ Eliminada detección LZ4
- ✅ SIEMPRE comprimir si está habilitado
- ✅ SIEMPRE descomprimir si está habilitado
- ✅ Consistencia total en el pipeline
"""

import zmq
import time
import json
import lz4.frame
import zstandard
import nacl.public
import nacl.utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
import threading
from typing import Optional, Dict, Any, Tuple
import os
import base64


class CryptoZMQV31:
    """
    🔐 ZeroMQ Cifrado Wrapper V3.1 SIMPLIFICADO
    - AES-256-GCM para cifrado simétrico
    - Compresión LZ4 CONSISTENTE (sin threshold)
    - Variables de entorno INVISIBLES
    - SIEMPRE predecible y confiable
    """

    def __init__(self, component_name: str, config_path: str = "config/crypto/crypto_config_v31.json"):
        self.component_name = component_name
        self.logger = self._setup_logger()

        # Cargar configuración crypto
        self.config = self._load_crypto_config(config_path)

        # Estados crypto
        self.current_session_key = None
        self.key_generation_time = 0
        self.key_rotation_interval = self.config.get("key_rotation_minutes", 15) * 60
        self.compression_enabled = self.config.get("compression_enabled", True)
        self.compression_algorithm = self.config.get("compression_algorithm", "lz4")

        # Contadores y métricas
        self.metrics = {
            "messages_encrypted": 0,
            "messages_decrypted": 0,
            "bytes_compressed": 0,
            "bytes_uncompressed": 0,
            "compression_ratio": 0.0,
            "key_rotations": 0,
            "encryption_errors": 0
        }

        self.using_shared_key = False  # Flag para indicar si usa clave compartida

        # Thread para rotación automática
        self.rotation_thread = None
        self.stop_rotation = threading.Event()

        # Inicializar crypto
        self._initialize_crypto()

        self.logger.info(f"🔐 CryptoZMQ V3.1 SIMPLIFICADO initialized for {component_name}")

    def _setup_logger(self) -> logging.Logger:
        """Setup logger específico para crypto"""
        logger = logging.getLogger(f"crypto_zmq_{self.component_name}")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s | %(name)s | %(levelname)s | 🔐 %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _load_crypto_config(self, config_path: str) -> Dict[str, Any]:
        """Cargar configuración crypto SIMPLIFICADA"""
        default_config = {
            "encryption_enabled": True,
            "algorithm": "AES-256-GCM",
            "key_rotation_minutes": 15,
            "compression_enabled": True,
            "compression_algorithm": "lz4",
            # ❌ ELIMINADO: compression_threshold
            "auto_rotation": True
        }

        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    return {**default_config, **config}
            else:
                self.logger.warning(f"⚠️ Config file not found: {config_path}, using defaults")
                return default_config
        except Exception as e:
            self.logger.error(f"❌ Error loading crypto config: {e}")
            return default_config

    def _initialize_crypto(self):
        """Inicializar sistema criptográfico SIMPLIFICADO"""
        try:
            # 🔐🤝 PASO 1: Configurar clave compartida para el pipeline
            if self._setup_shared_pipeline_key():
                self.logger.info("🔐 ✅ Shared pipeline key configured successfully")
            else:
                # Fallback: usar clave individual
                self.logger.warning("⚠️ Falling back to individual component key")
                self._rotate_session_key()
                self.using_shared_key = False

            # 🗜️ PASO 2: Inicializar compresores SIMPLIFICADO
            self._initialize_compressors()

            # 🔄 PASO 3: Configurar rotación automática
            if hasattr(self, 'using_shared_key') and self.using_shared_key:
                self.logger.info("🔐 🔒 Key rotation DISABLED (using shared pipeline key)")
            else:
                if self.config.get("auto_rotation", True):
                    self._start_key_rotation()
                    self.logger.info("🔐 🔄 Key rotation ENABLED (individual component key)")

            self.logger.info("🔐 Crypto system SIMPLIFICADO initialized successfully")

            # 📊 Log resumen SIMPLIFICADO
            self.logger.info("🔐 📋 Crypto Configuration Summary:")
            self.logger.info(f"   🔒 Algorithm: AES-256-GCM")
            self.logger.info(
                f"   🗜️ Compression: {self.compression_algorithm if self.compression_enabled else 'disabled'}")
            self.logger.info(f"   🎯 Mode: ALWAYS_CONSISTENT (no threshold)")
            self.logger.info(f"   🤝 Shared key: {self.using_shared_key}")

        except Exception as e:
            self.logger.error(f"❌ Error initializing crypto: {e}")
            raise

    def _setup_shared_pipeline_key(self):
        """Configurar clave compartida para todo el pipeline"""
        try:
            shared_key_env_name = "UPGRADED_HAPPINESS_PIPELINE_KEY"
            existing_shared_key = os.environ.get(shared_key_env_name)

            if existing_shared_key:
                try:
                    shared_key = base64.b64decode(existing_shared_key)
                    if len(shared_key) == 32:
                        self.current_session_key = shared_key
                        self.key_generation_time = time.time()
                        self.using_shared_key = True
                        self.logger.info(f"🔐 🤝 Using existing shared pipeline key")
                        return True
                    else:
                        del os.environ[shared_key_env_name]
                except Exception as e:
                    if shared_key_env_name in os.environ:
                        del os.environ[shared_key_env_name]

            # Generar nueva clave compartida
            new_shared_key = os.urandom(32)
            new_shared_key_b64 = base64.b64encode(new_shared_key).decode()
            os.environ[shared_key_env_name] = new_shared_key_b64

            self.current_session_key = new_shared_key
            self.key_generation_time = time.time()
            self.using_shared_key = True

            self.logger.info(f"🔐 🆕 Generated NEW shared pipeline key")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error setting up shared pipeline key: {e}")
            self.using_shared_key = False
            return False

    def _rotate_session_key(self):
        """Rotar clave de sesión"""
        try:
            self.current_session_key = os.urandom(32)
            self.key_generation_time = time.time()
            self._save_session_key_invisible()
            self.metrics["key_rotations"] += 1
            self.logger.info(f"🔄 Session key rotated (rotation #{self.metrics['key_rotations']})")
        except Exception as e:
            self.logger.error(f"❌ Error rotating session key: {e}")

    def _save_session_key_invisible(self):
        """Guardar clave de sesión en variable de entorno INVISIBLE"""
        try:
            process_id = os.getpid()
            var_name = f"_CRYPTO_ZMQ_{self.component_name.upper()}_{process_id}_KEY"
            key_b64 = base64.b64encode(self.current_session_key).decode()
            os.environ[var_name] = key_b64
            os.environ[f"_CRYPTO_ZMQ_{self.component_name.upper()}_{process_id}_TIME"] = str(self.key_generation_time)
        except Exception as e:
            self.logger.error(f"❌ Error saving session key: {e}")

    def _initialize_compressors(self):
        """Inicializar compresores SIMPLIFICADO"""
        if not self.compression_enabled:
            self.logger.info("🗜️ Compression DISABLED")
            return

        if self.compression_algorithm == "lz4":
            # LZ4 no necesita inicialización especial
            self.logger.info("🗜️ LZ4 compression ENABLED (always consistent)")
        elif self.compression_algorithm == "zstd":
            self.compressor = zstandard.ZstdCompressor()
            self.decompressor = zstandard.ZstdDecompressor()
            self.logger.info("🗜️ Zstd compression ENABLED (always consistent)")
        else:
            self.logger.warning(f"⚠️ Unknown compression algorithm: {self.compression_algorithm}")
            self.compression_enabled = False

    def _start_key_rotation(self):
        """Iniciar thread de rotación automática"""
        if self.rotation_thread is not None:
            return

        def rotation_worker():
            while not self.stop_rotation.wait(self.key_rotation_interval):
                self._rotate_session_key()

        self.rotation_thread = threading.Thread(target=rotation_worker, daemon=True)
        self.rotation_thread.start()
        self.logger.info(f"🔄 Auto key rotation started (every {self.key_rotation_interval // 60} minutes)")

    def encrypt_message(self, message: bytes) -> bytes:
        """
        🔐 Cifrar mensaje SIMPLIFICADO Y CONSISTENTE
        SIEMPRE comprimir si está habilitado (sin threshold)
        """
        try:
            original_size = len(message)

            # ✅ SIMPLIFICADO: SIEMPRE comprimir si está habilitado
            if self.compression_enabled:
                if self.compression_algorithm == "lz4":
                    message = lz4.frame.compress(message)
                elif self.compression_algorithm == "zstd":
                    message = self.compressor.compress(message)

                compressed_size = len(message)
                self.metrics["bytes_uncompressed"] += original_size
                self.metrics["bytes_compressed"] += compressed_size

                if original_size > 0:
                    self.metrics["compression_ratio"] = compressed_size / original_size

                self.logger.debug(f"📦 ALWAYS Compressed {original_size} → {compressed_size} bytes "
                                  f"(ratio: {self.metrics['compression_ratio']:.3f})")

            # Verificar rotación SOLO si NO usamos clave compartida
            if (not getattr(self, 'using_shared_key', False) and
                    (time.time() - self.key_generation_time) > self.key_rotation_interval):
                self._rotate_session_key()

            # Cifrar con AES-256-GCM
            iv = os.urandom(12)  # 96-bit IV para GCM
            cipher = Cipher(
                algorithms.AES(self.current_session_key),
                modes.GCM(iv)
            )
            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(message) + encryptor.finalize()

            # Combinar IV + tag + ciphertext
            encrypted_message = iv + encryptor.tag + ciphertext

            self.metrics["messages_encrypted"] += 1
            return encrypted_message

        except Exception as e:
            self.metrics["encryption_errors"] += 1
            self.logger.error(f"❌ Encryption error: {e}")
            raise

    def decrypt_message(self, encrypted_message: bytes) -> bytes:
        """
        🔓 Descifrar mensaje SIMPLIFICADO Y CONSISTENTE
        SIEMPRE descomprimir si está habilitado (sin detección)
        """
        try:
            # Extraer IV, tag y ciphertext
            iv = encrypted_message[:12]
            tag = encrypted_message[12:28]
            ciphertext = encrypted_message[28:]

            # Descifrar con AES-256-GCM
            cipher = Cipher(
                algorithms.AES(self.current_session_key),
                modes.GCM(iv, tag)
            )
            decryptor = cipher.decryptor()

            message = decryptor.update(ciphertext) + decryptor.finalize()

            # ✅ SIMPLIFICADO: SIEMPRE descomprimir si está habilitado
            if self.compression_enabled:
                original_size = len(message)

                if self.compression_algorithm == "lz4":
                    message = lz4.frame.decompress(message)
                elif self.compression_algorithm == "zstd":
                    message = self.decompressor.decompress(message)

                decompressed_size = len(message)
                self.logger.debug(f"🗜️ ALWAYS Decompressed {original_size} → {decompressed_size} bytes")

            self.metrics["messages_decrypted"] += 1
            return message

        except Exception as e:
            self.metrics["encryption_errors"] += 1
            self.logger.error(f"❌ Decryption error: {e}")
            raise

    def wrap_socket_send(self, socket):
        """Wrapper para socket.send() que cifra automáticamente"""
        original_send = socket.send

        def secure_send(data, flags=0, copy=True, track=False):
            if isinstance(data, bytes):
                encrypted_data = self.encrypt_message(data)
                return original_send(encrypted_data, flags, copy, track)
            else:
                return original_send(data, flags, copy, track)

        socket.send = secure_send
        self.logger.info(f"🔒 Socket send() wrapped with CONSISTENT encryption for {self.component_name}")
        return socket

    def wrap_socket_recv(self, socket):
        """Wrapper para socket.recv() que descifra automáticamente"""
        original_recv = socket.recv
        original_recv_multipart = socket.recv_multipart

        def encrypted_recv(flags=0, copy=True, track=False):
            encrypted_data = original_recv(flags, copy, track)
            return self.decrypt_message(encrypted_data)

        def encrypted_recv_multipart(flags=0, copy=True, track=False):
            encrypted_parts = original_recv_multipart(flags, copy, track)
            decrypted_parts = []
            for part in encrypted_parts:
                decrypted_parts.append(self.decrypt_message(part))
            return decrypted_parts

        socket.recv = encrypted_recv
        socket.recv_multipart = encrypted_recv_multipart

        self.logger.info("🔐 🔓 Socket recv() wrapped with CONSISTENT decryption")
        return socket

    def get_metrics(self) -> Dict[str, Any]:
        """Obtener métricas crypto"""
        return {
            **self.metrics,
            "current_key_age_seconds": time.time() - self.key_generation_time,
            "time_to_next_rotation": self.key_rotation_interval - (time.time() - self.key_generation_time),
            "compression_enabled": self.compression_enabled,
            "encryption_enabled": self.config.get("encryption_enabled", True),
            "mode": "ALWAYS_CONSISTENT"
        }

    def close(self):
        """Limpiar recursos"""
        try:
            # Detener rotación automática
            if self.rotation_thread:
                self.stop_rotation.set()
                self.rotation_thread.join(timeout=1)

            # Gestión de clave compartida
            if hasattr(self, 'using_shared_key') and self.using_shared_key:
                self.logger.info("🔐 🤝 Shared pipeline key kept in environment for other components")

            # Limpiar variables de entorno individuales
            process_id = os.getpid()
            prefix = f"_CRYPTO_ZMQ_{self.component_name.upper()}_{process_id}_"
            vars_to_clean = [k for k in os.environ.keys() if k.startswith(prefix)]

            for var in vars_to_clean:
                del os.environ[var]

            if vars_to_clean:
                self.logger.info(f"🧹 Cleaned {len(vars_to_clean)} individual crypto vars")

            self.logger.info("🔐 CryptoZMQ V3.1 SIMPLIFICADO closed successfully")

        except Exception as e:
            self.logger.error(f"❌ Error closing CryptoZMQ: {e}")


# Test de consistencia
if __name__ == "__main__":
    print("🧪 Testing CONSISTENT crypto wrapper...")

    crypto = CryptoZMQV31("test_component")

    # Test con mensaje pequeño (antes problemático)
    small_message = b"Small message < 512 bytes"
    print(f"📦 Small message: {len(small_message)} bytes")

    encrypted = crypto.encrypt_message(small_message)
    print(f"🔒 Encrypted: {len(encrypted)} bytes")

    decrypted = crypto.decrypt_message(encrypted)
    print(f"🔓 Decrypted: {len(decrypted)} bytes")

    print(f"✅ Consistency check: {small_message == decrypted}")

    # Test con mensaje grande
    large_message = b"Large message " + b"X" * 1000 + b" > 512 bytes"
    print(f"📦 Large message: {len(large_message)} bytes")

    encrypted_large = crypto.encrypt_message(large_message)
    decrypted_large = crypto.decrypt_message(encrypted_large)

    print(f"✅ Large consistency check: {large_message == decrypted_large}")
    print(f"📊 Metrics: {crypto.get_metrics()}")

    crypto.close()
    print("✅ CONSISTENT crypto wrapper test completed")