# crypto_utils.py - Enhanced Entropy & Thermal Noise
import os
import time
import hashlib
import psutil
import struct
import socket
from threading import Lock, Thread
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import logging

logger = logging.getLogger(__name__)


class EntropyCollector:
    """Collector for various entropy sources including thermal noise"""

    def __init__(self, sources: List[str]):
        self.sources = sources
        self._last_thermal_reading = 0
        self._network_timing_cache = []
        self._disk_timing_cache = []

    def _get_thermal_entropy(self) -> bytes:
        """Get thermal noise from CPU temperature sensors"""
        entropy = b""
        try:
            # Linux thermal zones
            thermal_paths = [
                "/sys/class/thermal/thermal_zone0/temp",
                "/sys/class/thermal/thermal_zone1/temp",
                "/sys/class/thermal/thermal_zone2/temp"
            ]

            for path in thermal_paths:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        temp = int(f.read().strip())
                        # Use micro-variations in temperature as entropy
                        entropy += struct.pack('<Q', temp * int(time.time() * 1000000))

        except Exception:
            # Fallback: Use CPU frequency as thermal proxy
            try:
                freq = psutil.cpu_freq()
                if freq:
                    # Current frequency varies with thermal state
                    entropy += struct.pack('<f', freq.current)
                    entropy += struct.pack('<f', freq.min)
                    entropy += struct.pack('<f', freq.max)
            except Exception:
                pass

        # macOS thermal (if available)
        try:
            import subprocess
            result = subprocess.run(['pmset', '-g', 'therm'],
                                    capture_output=True, text=True, timeout=1)
            if result.returncode == 0:
                # Hash thermal output for entropy
                entropy += hashlib.sha256(result.stdout.encode()).digest()[:8]
        except Exception:
            pass

        return entropy or os.urandom(16)

    def _get_network_timing_entropy(self) -> bytes:
        """Get entropy from network timing jitter"""
        entropy = b""
        try:
            # Measure timing variations in network operations
            start = time.perf_counter_ns()

            # Quick network check (localhost)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.001)  # 1ms timeout
            try:
                sock.connect(('127.0.0.1', 1))
                sock.close()
            except Exception:
                pass

            end = time.perf_counter_ns()
            timing_delta = end - start

            # Store recent timings for jitter calculation
            self._network_timing_cache.append(timing_delta)
            if len(self._network_timing_cache) > 10:
                self._network_timing_cache.pop(0)

            # Calculate jitter as entropy source
            if len(self._network_timing_cache) > 1:
                jitter = max(self._network_timing_cache) - min(self._network_timing_cache)
                entropy += struct.pack('<Q', jitter)

        except Exception:
            pass

        return entropy or os.urandom(8)

    def _get_disk_timing_entropy(self) -> bytes:
        """Get entropy from disk I/O timing variations"""
        entropy = b""
        try:
            # Measure disk I/O timing
            start = time.perf_counter_ns()

            # Quick disk stat check
            disk_usage = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()

            end = time.perf_counter_ns()
            timing_delta = end - start

            # Store timing for jitter calculation
            self._disk_timing_cache.append(timing_delta)
            if len(self._disk_timing_cache) > 10:
                self._disk_timing_cache.pop(0)

            # Use disk stats as entropy
            if disk_io:
                entropy += struct.pack('<Q', disk_io.read_bytes)
                entropy += struct.pack('<Q', disk_io.write_bytes)
                entropy += struct.pack('<Q', timing_delta)

        except Exception:
            pass

        return entropy or os.urandom(8)

    def _get_cpu_performance_entropy(self) -> bytes:
        """Get entropy from CPU performance counters"""
        entropy = b""
        try:
            # CPU times (vary with system load)
            cpu_times = psutil.cpu_times()
            entropy += struct.pack('<f', cpu_times.user)
            entropy += struct.pack('<f', cpu_times.system)
            entropy += struct.pack('<f', cpu_times.idle)

            # CPU percent (instantaneous measurement has variance)
            cpu_percent = psutil.cpu_percent(interval=0.01, percpu=True)
            for percent in cpu_percent[:4]:  # First 4 cores
                entropy += struct.pack('<f', percent)

        except Exception:
            pass

        return entropy or os.urandom(16)

    def _get_memory_entropy(self) -> bytes:
        """Get entropy from memory usage patterns"""
        entropy = b""
        try:
            # Memory stats change constantly
            mem = psutil.virtual_memory()
            entropy += struct.pack('<Q', mem.available)
            entropy += struct.pack('<Q', mem.used)
            entropy += struct.pack('<Q', mem.free)

            # Process memory (our own process)
            process = psutil.Process()
            mem_info = process.memory_info()
            entropy += struct.pack('<Q', mem_info.rss)
            entropy += struct.pack('<Q', mem_info.vms)

        except Exception:
            pass

        return entropy or os.urandom(16)

    def collect_entropy(self) -> bytes:
        """Collect entropy from all configured sources"""
        entropy = b""

        for source in self.sources:
            if source == "pid":
                entropy += str(os.getpid()).encode()

            elif source == "boot_time":
                try:
                    # Linux boot time
                    with open('/proc/stat') as f:
                        for line in f:
                            if line.startswith('btime'):
                                boot_time = int(line.strip().split()[1])
                                entropy += str(boot_time).encode()
                                break
                except Exception:
                    # Fallback: system boot time
                    boot_time = psutil.boot_time()
                    entropy += struct.pack('<f', boot_time)

            elif source == "random_bytes":
                entropy += os.urandom(16)

            elif source == "cpu_temperature":
                entropy += self._get_thermal_entropy()

            elif source == "network_traffic":
                entropy += self._get_network_timing_entropy()

            elif source == "disk_io_timing":
                entropy += self._get_disk_timing_entropy()

            elif source == "cpu_performance":
                entropy += self._get_cpu_performance_entropy()

            elif source == "memory_patterns":
                entropy += self._get_memory_entropy()

            elif source == "high_resolution_time":
                # Nanosecond precision timing
                entropy += struct.pack('<Q', time.perf_counter_ns())
                entropy += struct.pack('<Q', time.process_time_ns())
                entropy += struct.pack('<Q', time.thread_time_ns())

            else:
                # Unknown source, add some randomness
                entropy += os.urandom(8)

        return entropy


class SecureEnvelope:
    """Enhanced secure envelope with thermal entropy and advanced features"""

    def __init__(self, config: Dict):
        self.enabled = config.get("enabled", False)
        self.algorithm = config.get("algorithm", "AES-256-GCM")
        self.rotation_interval = config.get("rotation_interval_seconds", 3600)
        self.key_derivation_method = config.get("key_derivation_method", "HKDF")
        self.entropy_sources = config.get("entropy_sources", ["pid", "random_bytes"])
        self.aad_includes = config.get("aad_includes", [])

        # Enhanced features
        self.min_entropy_bits = config.get("min_entropy_bits", 256)
        self.key_stretching_iterations = config.get("key_stretching_iterations", 100000)
        self.emergency_entropy_threshold = config.get("emergency_entropy_threshold", 64)

        self._lock = Lock()
        self._key = None
        self._last_rotation = 0
        self._entropy_collector = EntropyCollector(self.entropy_sources)
        self._rotation_thread = None

        # Metrics
        self.metrics = {
            "encryptions": 0,
            "decryptions": 0,
            "key_rotations": 0,
            "entropy_collections": 0,
            "errors": 0
        }

        if self.enabled:
            self._generate_key()
            self._start_rotation_thread()

    def _start_rotation_thread(self):
        """Start the key rotation thread"""
        if self._rotation_thread is None:
            self._rotation_thread = Thread(target=self._rotate_key_periodically, daemon=True)
            self._rotation_thread.start()
            logger.info(f"Started key rotation thread (interval: {self.rotation_interval}s)")

    def _collect_entropy(self) -> bytes:
        """Collect entropy from all sources"""
        try:
            entropy = self._entropy_collector.collect_entropy()
            self.metrics["entropy_collections"] += 1

            # Ensure minimum entropy
            if len(entropy) < self.emergency_entropy_threshold:
                logger.warning(f"Low entropy collected: {len(entropy)} bytes, adding random bytes")
                entropy += os.urandom(self.emergency_entropy_threshold - len(entropy))

            return entropy

        except Exception as e:
            logger.error(f"Entropy collection failed: {e}")
            self.metrics["errors"] += 1
            return os.urandom(32)  # Emergency fallback

    def _generate_key(self):
        """Generate a new encryption key"""
        with self._lock:
            try:
                entropy = self._collect_entropy()

                if self.key_derivation_method == "HKDF":
                    # Use HKDF for key derivation
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,  # 256 bits
                        salt=None,
                        info=b"upgraded-happiness-secure-envelope-v2",
                    )
                    self._key = hkdf.derive(entropy)

                elif self.key_derivation_method == "PBKDF2":
                    # Alternative: PBKDF2 for key stretching
                    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=entropy[:16],  # Use part of entropy as salt
                        iterations=self.key_stretching_iterations,
                    )
                    self._key = kdf.derive(entropy[16:])

                else:
                    # Simple hash-based derivation
                    self._key = hashlib.sha256(entropy).digest()

                self._last_rotation = time.time()
                self.metrics["key_rotations"] += 1

                logger.debug(f"Generated new key from {len(entropy)} bytes of entropy")

            except Exception as e:
                logger.error(f"Key generation failed: {e}")
                self.metrics["errors"] += 1
                raise

    def _rotate_key_periodically(self):
        """Rotate keys periodically with precise timing"""
        while True:
            try:
                # Calculate exact sleep time
                next_rotation = self._last_rotation + self.rotation_interval
                sleep_time = max(0, next_rotation - time.time())

                if sleep_time > 0:
                    time.sleep(sleep_time)

                # Check if rotation is still needed (thread-safe)
                with self._lock:
                    if time.time() >= self._last_rotation + self.rotation_interval:
                        self._generate_key()
                        logger.info("Key rotated successfully")

            except Exception as e:
                logger.error(f"Key rotation failed: {e}")
                self.metrics["errors"] += 1
                time.sleep(60)  # Wait 1 minute before retrying

    def _get_key(self) -> bytes:
        """Get current encryption key (thread-safe)"""
        with self._lock:
            if self._key is None:
                self._generate_key()
            return self._key

    def _build_aad(self, metadata: Optional[Dict]) -> bytes:
        """Build Additional Authenticated Data from metadata"""
        aad = b""
        if metadata and self.aad_includes:
            parts = []
            for field in self.aad_includes:
                val = metadata.get(field, "")
                if isinstance(val, str):
                    parts.append(val.encode())
                elif isinstance(val, bytes):
                    parts.append(val)
                else:
                    parts.append(str(val).encode())
            aad = b"|".join(parts)
        return aad

    def encrypt(self, plaintext: bytes, metadata: Optional[Dict] = None) -> bytes:
        """Encrypt plaintext with current key"""
        if not self.enabled:
            return plaintext

        try:
            key = self._get_key()
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)  # 96 bits nonce for GCM
            aad = self._build_aad(metadata)

            ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
            self.metrics["encryptions"] += 1

            # Return: nonce (12 bytes) + ciphertext + optional metadata
            return nonce + ciphertext

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            self.metrics["errors"] += 1
            raise

    def decrypt(self, data: bytes, metadata: Optional[Dict] = None) -> bytes:
        """Decrypt data with current key"""
        if not self.enabled:
            return data

        try:
            key = self._get_key()
            aesgcm = AESGCM(key)
            nonce = data[:12]
            ciphertext = data[12:]
            aad = self._build_aad(metadata)

            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            self.metrics["decryptions"] += 1

            return plaintext

        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            self.metrics["errors"] += 1
            raise

    def get_metrics(self) -> Dict:
        """Get encryption metrics"""
        return self.metrics.copy()

    def force_key_rotation(self):
        """Force immediate key rotation"""
        with self._lock:
            self._generate_key()
            logger.info("Key rotation forced manually")

    def get_key_age(self) -> float:
        """Get current key age in seconds"""
        with self._lock:
            return time.time() - self._last_rotation

    def is_healthy(self) -> bool:
        """Check if encryption system is healthy"""
        try:
            # Test encryption/decryption
            test_data = b"health_check_test_data"
            encrypted = self.encrypt(test_data)
            decrypted = self.decrypt(encrypted)

            return decrypted == test_data

        except Exception:
            return False

    def shutdown(self):
        """Safely shutdown the encryption system"""
        if self._rotation_thread:
            # Note: daemon threads will be killed automatically
            pass

        # Clear key from memory
        with self._lock:
            if self._key:
                self._key = b'\x00' * len(self._key)
                self._key = None

        logger.info("SecureEnvelope shutdown complete")