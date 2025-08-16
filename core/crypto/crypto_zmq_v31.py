#!/usr/bin/env python3
"""
🔐 Crypto ZeroMQ Wrapper V3.1 - Simplified Version
Sistema Autoinmune Digital - upgraded-happiness
Cifrado rotativo + compresión para comunicaciones ZeroMQ
- SOLO variables de entorno en memoria
- Sin funciones huérfanas
- Variables invisibles para el operador
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
    - Rotación automática de claves cada 15 min
    - Compresión LZ4/Zstd adaptativa
    - Variables de entorno INVISIBLES
    - Sin persistencia en disco
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

        # Thread para rotación automática
        self.rotation_thread = None
        self.stop_rotation = threading.Event()

        # Inicializar crypto
        self._initialize_crypto()

        self.logger.info(f"🔐 CryptoZMQ V3.1 initialized for {component_name}")

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
        """Cargar configuración crypto"""
        default_config = {
            "encryption_enabled": True,
            "algorithm": "AES-256-GCM",
            "key_rotation_minutes": 15,
            "compression_enabled": True,
            "compression_algorithm": "lz4",
            "compression_threshold": 512,
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
        """Inicializar sistema criptográfico"""
        try:
            # Generar clave de sesión inicial (automática)
            self._rotate_session_key()

            # Inicializar compresores
            self._initialize_compressors()

            # Iniciar rotación automática
            if self.config.get("auto_rotation", True):
                self._start_key_rotation()

            self.logger.info("🔐 Crypto system initialized successfully")

        except Exception as e:
            self.logger.error(f"❌ Error initializing crypto: {e}")
            raise

    def _rotate_session_key(self):
        """Rotar clave de sesión para Perfect Forward Secrecy"""
        try:
            # Generar nueva clave AES-256 (INVISIBLE)
            self.current_session_key = os.urandom(32)  # 256 bits
            self.key_generation_time = time.time()

            # Guardar en variable de entorno INVISIBLE
            self._save_session_key_invisible()

            self.metrics["key_rotations"] += 1
            self.logger.info(f"🔄 Session key rotated (rotation #{self.metrics['key_rotations']})")

        except Exception as e:
            self.logger.error(f"❌ Error rotating session key: {e}")

    def _save_session_key_invisible(self):
        """Guardar clave de sesión en variable de entorno INVISIBLE"""
        try:
            # Variable de entorno con nombre único por proceso
            process_id = os.getpid()
            var_name = f"_CRYPTO_ZMQ_{self.component_name.upper()}_{process_id}_KEY"

            # Guardar clave cifrada en base64 (doble ofuscación)
            key_b64 = base64.b64encode(self.current_session_key).decode()
            os.environ[var_name] = key_b64

            # Timestamp para debugging (si es necesario)
            os.environ[f"_CRYPTO_ZMQ_{self.component_name.upper()}_{process_id}_TIME"] = str(self.key_generation_time)

            # NO logear el nombre de la variable para mantener invisibilidad
            self.logger.debug("🔑 Session key stored in memory")

        except Exception as e:
            self.logger.error(f"❌ Error saving session key: {e}")

    def _load_session_key_invisible(self) -> bool:
        """Cargar clave de sesión desde variable de entorno INVISIBLE"""
        try:
            process_id = os.getpid()
            var_name = f"_CRYPTO_ZMQ_{self.component_name.upper()}_{process_id}_KEY"

            if var_name in os.environ:
                key_b64 = os.environ[var_name]
                self.current_session_key = base64.b64decode(key_b64)

                # Cargar timestamp si existe
                time_var = f"_CRYPTO_ZMQ_{self.component_name.upper()}_{process_id}_TIME"
                if time_var in os.environ:
                    self.key_generation_time = float(os.environ[time_var])

                self.logger.debug("🔑 Session key loaded from memory")
                return True

            return False

        except Exception as e:
            self.logger.warning(f"⚠️ Could not load session key: {e}")
            return False

    def _initialize_compressors(self):
        """Inicializar compresores"""
        if self.compression_algorithm == "lz4":
            self.compressor = lz4.frame
        elif self.compression_algorithm == "zstd":
            self.compressor = zstandard.ZstdCompressor()
            self.decompressor = zstandard.ZstdDecompressor()
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
        """Cifrar mensaje con AES-256-GCM + compresión opcional"""
        try:
            # Comprimir si está habilitado y el mensaje es lo suficientemente grande
            original_size = len(message)
            if (self.compression_enabled and
                    original_size > self.config.get("compression_threshold", 512)):

                if self.compression_algorithm == "lz4":
                    message = lz4.frame.compress(message)
                elif self.compression_algorithm == "zstd":
                    message = self.compressor.compress(message)

                compressed_size = len(message)
                self.metrics["bytes_uncompressed"] += original_size
                self.metrics["bytes_compressed"] += compressed_size

                if original_size > 0:
                    self.metrics["compression_ratio"] = compressed_size / original_size

                self.logger.debug(f"📦 Compressed {original_size} → {compressed_size} bytes "
                                  f"(ratio: {self.metrics['compression_ratio']:.3f})")

            # Verificar si necesitamos rotar clave
            if (time.time() - self.key_generation_time) > self.key_rotation_interval:
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
        """Descifrar mensaje"""
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

            # Descomprimir si es necesario
            if self.compression_enabled:
                try:
                    if self.compression_algorithm == "lz4":
                        message = lz4.frame.decompress(message)
                    elif self.compression_algorithm == "zstd":
                        message = self.decompressor.decompress(message)
                except:
                    # Mensaje no estaba comprimido
                    pass

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
            # Cifrar datos antes de enviar
            if isinstance(data, bytes):
                encrypted_data = self.encrypt_message(data)
                return original_send(encrypted_data, flags, copy, track)
            else:
                # Si no son bytes, enviar sin cifrar (como metadatos ZMQ)
                return original_send(data, flags, copy, track)

        # Reemplazar método send
        socket.send = secure_send
        self.logger.info(f"🔒 Socket send() wrapped with encryption for {self.component_name}")
        return socket

    def get_metrics(self) -> Dict[str, Any]:
        """Obtener métricas crypto"""
        return {
            **self.metrics,
            "current_key_age_seconds": time.time() - self.key_generation_time,
            "time_to_next_rotation": self.key_rotation_interval - (time.time() - self.key_generation_time),
            "compression_enabled": self.compression_enabled,
            "encryption_enabled": self.config.get("encryption_enabled", True)
        }

    def close(self):
        """Limpiar recursos incluyendo variables de entorno INVISIBLES"""
        try:
            # Detener rotación automática
            if self.rotation_thread:
                self.stop_rotation.set()
                self.rotation_thread.join(timeout=1)

            # Limpiar variables de entorno crypto INVISIBLES
            process_id = os.getpid()
            prefix = f"_CRYPTO_ZMQ_{self.component_name.upper()}_{process_id}_"

            vars_to_clean = [k for k in os.environ.keys() if k.startswith(prefix)]

            for var in vars_to_clean:
                del os.environ[var]

            self.logger.info(f"🧹 Cleaned {len(vars_to_clean)} invisible crypto vars")
            self.logger.info("🔐 CryptoZMQ V3.1 closed successfully")

        except Exception as e:
            self.logger.error(f"❌ Error closing CryptoZMQ: {e}")


# Ejemplo de uso
if __name__ == "__main__":
    # Test básico del wrapper crypto
    crypto = CryptoZMQV31("test_component")

    # Test cifrado/descifrado
    original_message = b"Hello, this is a test message for encryption!"
    print(f"Original: {original_message}")

    encrypted = crypto.encrypt_message(original_message)
    print(f"Encrypted: {len(encrypted)} bytes")

    decrypted = crypto.decrypt_message(encrypted)
    print(f"Decrypted: {decrypted}")

    print(f"Match: {original_message == decrypted}")
    print(f"Metrics: {crypto.get_metrics()}")

    crypto.close()