#!/usr/bin/env python3
"""
lightweight_ml_detector_tricapa_v31.py - FULLY JSON-CONTROLLED VERSION WITH PUB/SUB
🚀 UPGRADED HAPPINESS - TRICAPA ML DETECTOR v3.1.2 - 100% PORTABLE

CARACTERÍSTICAS v3.1.2-PUBSUB:
- 🎯 100% controlado por JSON (sin hardcoding)
- 🔒 ZMQ sockets protegidos con locks (thread-safe)
- 🧵 Pool de workers optimizado
- 📊 Logs informativos VISIBLES con scores ML
- ⚡ Performance boost completo
- 🌐 PORTABLE entre diferentes configuraciones HW
- 📋 Respeta completamente enabled/disabled del JSON
- 📡 SOPORTE PUB/SUB para múltiples suscriptores

PORTABILIDAD:
- HW Limitado: Usar config con modelos LGB disabled
- HW Potente: Usar config con todos los modelos enabled
- Script idéntico, solo cambia JSON
- PUSH/PULL: Un solo consumidor
- PUB/SUB: Múltiples consumidores (dashboard + no-gui)

FILOSOFÍA:
- Script: Lee 100% del JSON, sin asumir nada
- Config: Controla completamente qué modelos cargar Y qué patrón ZMQ usar
- Hardware: Solo cambiar JSON para diferentes capacidades

Autor: Alonso Isidoro, Claude
Fecha: Agosto 11, 2025
Versión: 3.1.2-json-controlled-pubsub
"""

# Suprimir warnings de sklearn
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", message="X does not have valid feature names")
warnings.filterwarnings("ignore", message=".*Parallel.*")

import zmq
import json
import time
import logging
import threading
import sys
import os
import socket
import psutil
import joblib
import pickle
import numpy as np
import math
from queue import Queue, Empty
from datetime import datetime
from pathlib import Path
from collections import deque, defaultdict
from typing import Dict, Any, Optional, Tuple, List
from threading import Event, Lock
from crypto.crypto_zmq_v31 import CryptoZMQV31

# 📦 Protobuf v3.1 - REQUERIDO
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = "unavailable"
NetworkSecurityEventProto = None


def import_protobuf_v31():
    """Importa el protobuf v3.1 limpio - EXCLUSIVO con búsqueda automática"""
    global NetworkSecurityEventProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    # Estrategias de importación múltiples
    import_strategies = [
        ("network_security_clean_v31_pb2", "Importación directa"),
        ("protocols.v3_1.network_security_clean_v31_pb2", "Paquete protocols.v3_1"),
    ]

    for import_path, description in import_strategies:
        try:
            NetworkSecurityEventProto = __import__(import_path, fromlist=[''])
            PROTOBUF_AVAILABLE = True
            PROTOBUF_VERSION = "v3.1.0-clean"
            print(f"✅ Protobuf v3.1 LIMPIO cargado: {description}")
            return True
        except ImportError:
            continue

    # Estrategia 3: Búsqueda por paths dinámicos
    current_dir = os.path.dirname(os.path.abspath(__file__))
    possible_paths = [
        os.path.join(current_dir, '..', 'protocols', 'v3.1'),
        os.path.join(current_dir, 'protocols', 'v3.1'),
        current_dir,
        os.path.join(current_dir, '..'),
    ]

    for protocols_path in possible_paths:
        protocols_path = os.path.abspath(protocols_path)
        pb2_file = os.path.join(protocols_path, 'network_security_clean_v31_pb2.py')

        if os.path.exists(pb2_file):
            try:
                sys.path.insert(0, protocols_path)
                import network_security_clean_v31_pb2 as NetworkSecurityEventProto
                PROTOBUF_AVAILABLE = True
                PROTOBUF_VERSION = "v3.1.0-clean"
                print(f"✅ Protobuf v3.1 LIMPIO cargado desde: {protocols_path}")
                return True
            except ImportError as e:
                if protocols_path in sys.path:
                    sys.path.remove(protocols_path)
                continue

    print(f"❌ Protobuf v3.1 REQUERIDO pero no encontrado")
    return False


# Ejecutar importación
import_protobuf_v31()

# 📦 ML Libraries
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    import sklearn

    ML_AVAILABLE = True
    print(f"✅ Scikit-learn {sklearn.__version__} disponible")
except ImportError as e:
    print(f"⚠️ Scikit-learn no disponible: {e}")
    ML_AVAILABLE = False


class TricapaMLDetectorV31JsonControlled:
    """
    🚀 Detector ML Tricapa v3.1.2 - 100% JSON CONTROLLED CON PUB/SUB
    - 🎯 Sin hardcoding - respeta completamente JSON
    - 🔒 ZMQ sockets protegidos con locks
    - 🧵 Pool de workers optimizado
    - 📊 Logs informativos VISIBLES
    - ⚡ Performance boost completo
    - 🌐 PORTABLE entre configuraciones HW
    - 📡 SOPORTE PUB/SUB para múltiples suscriptores
    """

    def __init__(self, config_file: str):
        # 📄 Cargar configuración PURA (sin modificaciones)
        self.config = self._load_config_pure(config_file)
        self.config_file = config_file
        # 🔐 Crypto wrapper setup
        self.crypto_wrapper = None
        # 🏷️ Identidad distribuida
        self.node_id = self.config["node_id"]
        self.process_id = os.getpid()
        self.start_time = time.time()

        # 🔒 Locks para thread safety
        self.socket_lock = Lock()
        self.stats_lock = Lock()
        self.logger_lock = Lock()

        # 📝 Setup logging PRIMERO
        self.setup_logging()

        # 🔍 Detectar patrón de socket desde JSON - SIN HARDCODING
        output_config = self.config.get("network", {}).get("output_socket", {})
        self.socket_pattern = output_config.get("socket_type", "PUSH").upper()

        print(f"🔌 Configurando sockets ZMQ JSON-controlled para {self.node_id}...")
        print(f"📡 Patrón detectado desde JSON: {self.socket_pattern}")

        # 🔌 Setup ZeroMQ desde JSON
        self.context = zmq.Context()
        self.input_socket = None
        self.output_socket = None
        self.setup_sockets_from_json()

        # 🔄 Backpressure desde JSON
        self.backpressure_config = self.config.get("backpressure", {})

        # 📦 Colas internas desde JSON
        self.setup_queues_from_json()

        # 🧠 SISTEMA TRICAPA 100% desde JSON
        self.ml_config = self.config.get("ml", {})
        self.tricapa_config = self.config.get("tricapa", {})

        # 📂 Rutas de modelos
        self.setup_model_paths()

        print(f"🧠 Configurando arsenal tricapa 100% desde JSON...")

        # 🤖 MODELOS: Estructura vacía (se llena desde JSON)
        self.models = {}
        self.scalers = {}
        self.enabled_models = []
        self.model_configs = {}

        # 🗂️ Feature mappings tricapa
        self.feature_mappings = {}

        # 📊 Métricas tricapa thread-safe
        self.setup_tricapa_stats()

        # 🎛️ Control thread-safe
        self.running = True
        self.stop_event = Event()
        self.worker_shutdown_event = Event()

        # 🧵 Pool de workers desde JSON
        processing_config = self.config.get("processing", {})
        self.worker_pool_size = processing_config.get("threads", 2)

        # 📁 Sistema de logging avanzado
        self.setup_advanced_logging()

        # ✅ Verificar dependencias críticas
        self._verify_critical_dependencies()

        # 🔄 Cargar modelos 100% DESDE JSON
        self.load_models_from_json()

        # 🔇 Contador para reducir spam de backpressure
        self.backpressure_log_counter = 0

        # 📊 Mostrar resumen de configuración
        self._log_configuration_summary()

    def _load_config_pure(self, config_file: str) -> Dict[str, Any]:
        """Carga configuración SIN modificaciones - 100% JSON puro"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)

            print(f"✅ Configuración JSON cargada PURA desde: {config_file}")
            return config

        except FileNotFoundError:
            raise RuntimeError(f"❌ CRÍTICO: Archivo de configuración no encontrado: {config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ CRÍTICO: Error parseando JSON: {e}")

    def setup_model_paths(self):
        """Configurar rutas de modelos desde JSON - RUTAS CORREGIDAS"""
        script_dir = Path(__file__).parent
        project_root = script_dir.parent

        # Usar rutas del JSON si están disponibles
        tricapa_paths = self.tricapa_config.get("model_paths", {})

        # ✅ RUTAS CORREGIDAS - Siempre partir de models/
        base_dir = tricapa_paths.get("base_models_dir", "models")

        # Construir rutas completas correctamente
        self.models_dir = project_root / base_dir

        # ✅ CRUCIAL: production debe estar DENTRO de models/
        self.production_dir = self.models_dir / "production"

        # ✅ CRUCIAL: tricapa debe estar DENTRO de models/production/
        self.tricapa_dir = self.models_dir / "production" / "tricapa"

        print(f"📂 Rutas de modelos CORREGIDAS desde JSON:")
        print(f"   📁 Base: {self.models_dir}")
        print(f"   📁 Production: {self.production_dir}")
        print(f"   📁 Tricapa: {self.tricapa_dir}")

        # 🔍 VERIFICACIÓN DE RUTAS
        print(f"📋 Verificando estructura de directorios:")
        print(f"   📁 {self.models_dir} existe: {self.models_dir.exists()}")
        print(f"   📁 {self.production_dir} existe: {self.production_dir.exists()}")
        print(f"   📁 {self.tricapa_dir} existe: {self.tricapa_dir.exists()}")

        if not self.production_dir.exists():
            self.logger.warning(f"⚠️ Production dir no encontrado: {self.production_dir}")
        if not self.tricapa_dir.exists():
            self.logger.warning(f"⚠️ Tricapa dir no encontrado: {self.tricapa_dir}")

        # 🔍 LISTAR ARCHIVOS ENCONTRADOS PARA DEBUG
        if self.production_dir.exists():
            production_files = list(self.production_dir.glob("*.joblib"))
            print(f"   📄 Archivos en production: {[f.name for f in production_files]}")

        if self.tricapa_dir.exists():
            tricapa_files = list(self.tricapa_dir.glob("*.joblib"))
            print(f"   📄 Archivos en tricapa: {[f.name for f in tricapa_files]}")

    def setup_logging(self):
        """Setup logging desde JSON"""
        log_config = self.config.get("logging", {})

        # Nivel desde JSON
        level_str = log_config.get("level", "INFO").upper()
        level = getattr(logging, level_str)

        log_format = log_config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s").format(
            node_id=self.node_id, pid=self.process_id)
        formatter = logging.Formatter(log_format)

        self.logger = logging.getLogger(f"tricapa_ml_detector_{self.node_id}")
        self.logger.setLevel(level)
        self.logger.handlers.clear()

        # Console handler
        console_config = log_config.get("console_logging", {})
        if console_config.get("enabled", True):
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            console_level = getattr(logging, console_config.get("level", "INFO").upper())
            console_handler.setLevel(console_level)
            self.logger.addHandler(console_handler)

        # File handler
        file_config = log_config.get("file_logging", {})
        if file_config.get("enabled", True) and log_config.get("file"):
            log_file = Path(log_config["file"])
            log_file.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_config["file"])
            file_handler.setFormatter(formatter)
            file_level = getattr(logging, file_config.get("level", "INFO").upper())
            file_handler.setLevel(file_level)
            self.logger.addHandler(file_handler)

        self.logger.propagate = False

    def setup_advanced_logging(self):
        """Configurar sistema de logging avanzado desde JSON"""
        adv_log_config = self.config.get("advanced_logging", {})

        if not adv_log_config.get("enabled", False):
            self.proto_log_dir = Path("logs/proto")  # Default
            self.proto_log_dir.mkdir(parents=True, exist_ok=True)
            return

        proto_config = adv_log_config.get("protobuf_logging", {})
        if proto_config.get("enabled", False):
            self.proto_log_dir = Path(proto_config.get("protobuf_base_dir", "logs/proto"))
            self.proto_log_dir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"📁 Protobuf logging: {self.proto_log_dir}")

    def setup_sockets_from_json(self):
        """🔒 Configuración ZMQ 100% desde JSON - CON SOPORTE PUB/SUB + CRYPTO"""
        network_config = self.config.get("network", {})
        zmq_config = self.config.get("zmq", {})

        try:
            # Socket de entrada desde JSON (sin cambios)
            input_config = network_config.get("input_socket", {})
            self.input_socket = self.context.socket(zmq.PULL)

            # Configuración desde JSON
            self.input_socket.setsockopt(zmq.RCVHWM, zmq_config.get("rcvhwm", 500))
            self.input_socket.setsockopt(zmq.RCVTIMEO, zmq_config.get("recv_timeout_ms", 500))
            self.input_socket.setsockopt(zmq.LINGER, zmq_config.get("linger_ms", 0))
            self.input_socket.setsockopt(zmq.MAXMSGSIZE, zmq_config.get("max_message_size", 50000))

            # Buffer desde JSON si está disponible
            if "recv_buffer_size" in zmq_config:
                self.input_socket.setsockopt(zmq.RCVBUF, zmq_config["recv_buffer_size"])

            input_address = f"tcp://{input_config.get('address', 'localhost')}:{input_config.get('port', 5560)}"
            self.input_socket.connect(input_address)

            # 📡 Socket de salida desde JSON - SOPORTE PUB/SUB COMPLETO
            output_config = network_config.get("output_socket", {})
            socket_type = output_config.get("socket_type", "PUSH").upper()

            if socket_type == "PUB":
                self.output_socket = self.context.socket(zmq.PUB)
                self.socket_pattern = "PUB"
                self.logger.info("🔄 Usando patrón PUB/SUB para múltiples suscriptores")
            else:
                self.output_socket = self.context.socket(zmq.PUSH)
                self.socket_pattern = "PUSH"
                self.logger.info("🔄 Usando patrón PUSH/PULL para un solo consumidor")

            # 📈 Configuración optimizada según el patrón
            if socket_type == "PUB":
                # Configuración específica para PUB
                self.output_socket.setsockopt(zmq.SNDHWM, zmq_config.get("sndhwm", 1000))
                send_buffer_size = zmq_config.get("send_buffer_size", 262144)

                # Optimizaciones PUB específicas desde JSON
                pub_opts = zmq_config.get("pub_socket_optimizations", {})

                if pub_opts.get("tcp_keepalive", True):
                    self.output_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                    self.output_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, pub_opts.get("tcp_keepalive_idle", 300))

                # Configuración de immediate para PUB
                if not pub_opts.get("immediate", False):
                    self.output_socket.setsockopt(zmq.IMMEDIATE, 0)

            else:
                # Configuración estándar para PUSH
                self.output_socket.setsockopt(zmq.SNDHWM, zmq_config.get("sndhwm", 500))
                send_buffer_size = zmq_config.get("send_buffer_size", 131072)

            # Configuración común
            self.output_socket.setsockopt(zmq.SNDTIMEO, zmq_config.get("send_timeout_ms", 250))
            self.output_socket.setsockopt(zmq.LINGER, zmq_config.get("linger_ms", 0))
            self.output_socket.setsockopt(zmq.MAXMSGSIZE, zmq_config.get("max_message_size", 50000))
            self.output_socket.setsockopt(zmq.SNDBUF, send_buffer_size)

            output_address = f"tcp://*:{output_config.get('port', 5580)}"
            self.output_socket.bind(output_address)

            # 🔐 NUEVO: CRYPTO WRAPPER SETUP
            if self.config.get("crypto", {}).get("enabled", False):
                try:
                    crypto_config_file = self.config.get("crypto", {}).get("config_file",
                                                                           "config/crypto/crypto_config_v31.json")
                    crypto_component_id = self.config.get("crypto", {}).get("component_crypto_id", self.node_id)

                    # Inicializar crypto wrapper
                    self.crypto_wrapper = CryptoZMQV31(crypto_component_id, crypto_config_file)

                    # 🔓 Wrap input socket para DESCIFRAR (del geoip_enricher)
                    self.input_socket = self.crypto_wrapper.wrap_socket_recv(self.input_socket)

                    # 🔒 Wrap output socket para CIFRAR (hacia múltiples suscriptores)
                    self.output_socket = self.crypto_wrapper.wrap_socket_send(self.output_socket)

                    self.logger.info("🔐 Crypto wrapper habilitado para Tricapa ML Detector v3.1.2")
                    self.logger.info(f"   🔓 Input: Descifrado automático desde geoip_enricher")
                    self.logger.info(f"   🔒 Output: Cifrado automático hacia múltiples suscriptores ({socket_type})")

                except Exception as e:
                    self.logger.error(f"❌ Error configurando crypto wrapper: {e}")
                    raise RuntimeError(f"Error inicializando crypto: {e}")
            else:
                self.logger.info("🔐 Crypto wrapper deshabilitado")

            self.logger.info(f"🔌 Sockets ZMQ desde JSON:")
            self.logger.info(f"   📥 Input: {input_address} (HWM: {zmq_config.get('rcvhwm', 500)})")
            self.logger.info(
                f"   📤 Output: {output_address} ({socket_type}, HWM: {zmq_config.get('sndhwm', 500 if socket_type == 'PUSH' else 1000)})")

            if socket_type == "PUB":
                self.logger.info(f"   🔄 Patrón: PUB/SUB (múltiples suscriptores permitidos)")
                self.logger.info(
                    f"   📡 Suscriptores pueden conectarse a: tcp://localhost:{output_config.get('port', 5580)}")
            else:
                self.logger.info(f"   🔄 Patrón: PUSH/PULL (un solo consumidor)")

        except Exception as e:
            raise RuntimeError(f"❌ Error configurando sockets ZMQ: {e}")

    def setup_queues_from_json(self):
        """📋 Configuración de colas desde JSON"""
        proc_config = self.config.get("processing", {})

        queue_size_protobuf = proc_config.get("protobuf_queue_size", 300)
        queue_size_internal = proc_config.get("internal_queue_size", 200)

        self.protobuf_queue = Queue(maxsize=queue_size_protobuf)
        self.enriched_queue = Queue(maxsize=queue_size_internal)

        self.logger.info(f"📋 Colas desde JSON:")
        self.logger.info(f"   📦 Protobuf queue: {queue_size_protobuf}")
        self.logger.info(f"   🎯 Internal queue: {queue_size_internal}")

    def setup_tricapa_stats(self):
        """📊 Configurar métricas tricapa thread-safe"""
        self.stats = {
            'received': 0, 'processed': 0, 'sent': 0,
            'level1_predictions': 0, 'level1_attacks_detected': 0,
            'level2_ddos_detected': 0, 'level2_ransomware_detected': 0,
            'level3_internal_anomalies': 0, 'level3_web_anomalies': 0,
            'tricapa_degraded_mode': 0, 'model_failures': 0,
            'protobuf_logs_written': 0, 'processing_errors': 0,
            'dropped_by_backpressure': 0, 'dropped_output_full': 0,
            'dropped_send_timeout': 0, 'enrichment_failures': 0,
            'start_time': time.time()
        }

    def _verify_critical_dependencies(self):
        """Verificar dependencias críticas"""
        issues = []

        if not PROTOBUF_AVAILABLE:
            issues.append("❌ Protobuf v3.1 no disponible")

        if not ML_AVAILABLE:
            issues.append("❌ Scikit-learn no disponible")

        if issues:
            for issue in issues:
                print(issue)

            if not PROTOBUF_AVAILABLE:
                raise RuntimeError("❌ Protobuf v3.1 es crítico")
            elif not ML_AVAILABLE:
                print("⚠️ Continuando sin ML - solo modo heurístico")
                self.ml_config["enabled"] = False

    def load_models_from_json(self):
        """🧠 Cargar modelos 100% DESDE JSON - INTELIGENTE (solo carga lo que existe)"""
        self.logger.info("🔄 Cargando modelos 100% desde configuración JSON...")

        if not self.ml_config.get("enabled", True):
            self.logger.warning("⚠️ ML deshabilitado en JSON - no se cargarán modelos")
            return

        models_config = self.ml_config.get("models", {})
        if not models_config:
            self.logger.error("❌ No hay configuración de modelos en JSON")
            return

        models_loaded = 0
        models_failed = 0
        models_skipped_disabled = 0
        models_skipped_missing = 0

        # Limpiar estructuras
        self.models = {}
        self.scalers = {}
        self.enabled_models = []
        self.model_configs = {}

        # Procesar TODOS los modelos del JSON
        for model_name, model_config in models_config.items():
            # Saltar comentarios
            if model_name.startswith("_comment"):
                continue

            # Verificar si está habilitado en JSON
            if not isinstance(model_config, dict):
                continue

            if not model_config.get("enabled", False):
                models_skipped_disabled += 1
                self.logger.info(f"⏭️ {model_name}: SKIP (disabled en JSON)")
                continue

            # 🔍 VERIFICACIÓN PREVIA DE EXISTENCIA - CLAVE DEL ÉXITO
            model_file = model_config.get("model_file")
            if not model_file:
                models_skipped_missing += 1
                self.logger.warning(f"⚠️ {model_name}: No model_file configurado")
                continue

            model_location = model_config.get("model_location", "tricapa")

            # Determinar path según location
            if model_location == "production":
                model_path = self.production_dir / model_file
            elif model_location == "tricapa":
                model_path = self.tricapa_dir / model_file
            elif model_location == "tricapa_or_production":
                model_path = self.tricapa_dir / model_file
                if not model_path.exists():
                    model_path = self.production_dir / model_file
            else:
                models_skipped_missing += 1
                self.logger.warning(f"⚠️ {model_name}: model_location desconocido: {model_location}")
                continue

            # 🚨 VERIFICACIÓN CRÍTICA: Solo proceder si el archivo existe
            if not model_path.exists():
                models_skipped_missing += 1
                self.logger.warning(f"⚠️ {model_name}: Archivo no disponible: {model_path}")
                continue

            # Solo intentar cargar si el archivo existe físicamente
            try:
                success = self._load_individual_model_verified(model_name, model_config, model_path)
                if success:
                    models_loaded += 1
                    self.enabled_models.append(model_name)
                    self.model_configs[model_name] = model_config

                    # Log detallado del modelo cargado
                    threat_type = model_config.get("threat_type", "")
                    traffic_type = model_config.get("traffic_type", "")
                    features_count = model_config.get("features_count", "?")
                    model_location = model_config.get("model_location", "?")

                    type_info = threat_type or traffic_type or "general"
                    self.logger.info(
                        f"✅ {model_name}: LOADED ({features_count} features, {type_info}, {model_location})")
                else:
                    models_failed += 1
            except Exception as e:
                models_failed += 1
                self.logger.error(f"❌ {model_name}: FAILED - {e}")

        # Setup feature mappings
        self.setup_feature_mappings()

        # Resumen final
        total_in_config = len(
            [k for k in models_config.keys() if not k.startswith("_comment") and isinstance(models_config[k], dict)])

        self.logger.info(f"🎯 CARGA DE MODELOS DESDE JSON COMPLETADA:")
        self.logger.info(f"   📊 Total en config: {total_in_config}")
        self.logger.info(f"   ✅ Cargados exitosamente: {models_loaded}")
        self.logger.info(f"   ⏭️ Saltados (disabled): {models_skipped_disabled}")
        self.logger.info(f"   ⚠️ No disponibles (missing): {models_skipped_missing}")
        self.logger.info(f"   ❌ Fallidos (error): {models_failed}")
        self.logger.info(f"   🧠 Modelos activos: {self.enabled_models}")

        # 🚀 LÓGICA INTELIGENTE: Permitir continuar con modelos disponibles
        min_models_required = self.ml_config.get("degraded_mode", {}).get("min_models_required", 0)

        if models_loaded == 0:
            if min_models_required > 0:
                raise RuntimeError("❌ CRÍTICO: No se pudo cargar ningún modelo desde JSON")
            else:
                self.logger.warning("⚠️ ADVERTENCIA: No hay modelos disponibles - continuando en modo heurístico")
                return False
        elif models_loaded < min_models_required:
            self.logger.warning(f"⚠️ Solo {models_loaded}/{min_models_required} modelos requeridos - modo degradado")

        self.logger.info(f"✅ Sistema tricapa OPERATIVO con {models_loaded} modelos desde JSON")
        return True

    def _load_individual_model_verified(self, model_name: str, model_config: Dict[str, Any], model_path: Path) -> bool:
        """Cargar modelo individual con path ya verificado"""
        try:
            # Cargar modelo (sabemos que el archivo existe)
            model_data = joblib.load(model_path)

            # Manejar diferentes formatos de modelo
            if isinstance(model_data, dict):
                # Formato con modelo y scaler en el mismo archivo
                self.models[model_name] = model_data.get('model')
                if 'scaler' in model_data:
                    scaler_key = f"{model_name}_scaler" if model_name != "level1_attack_detector" else "level1_scaler"
                    self.scalers[scaler_key] = model_data['scaler']
                if 'feature_names' in model_data and model_name == "level1_attack_detector":
                    self.feature_mappings['level1_features'] = model_data['feature_names']
            else:
                # Formato simple - solo modelo
                self.models[model_name] = model_data

                # Intentar cargar scaler por separado si es requerido
                if model_config.get("requires_scaling", False):
                    scaler_file = model_config.get("scaler_file")
                    if scaler_file:
                        scaler_path = self.production_dir / scaler_file
                        if scaler_path.exists():
                            scaler_key = f"{model_name}_scaler" if model_name != "level1_attack_detector" else "level1_scaler"
                            self.scalers[scaler_key] = joblib.load(scaler_path)
                        else:
                            self.logger.warning(f"⚠️ {model_name}: Scaler no encontrado: {scaler_path}")

            return True

        except Exception as e:
            self.logger.error(f"❌ Error cargando {model_name}: {e}")
            return False

    def setup_feature_mappings(self):
        """Configurar mapeos de features"""
        # Mapeo básico 82 → 23
        self.feature_mappings['82_to_23_map'] = {
            'duration': ' Flow Duration',
            'spkts': ' Total Fwd Packets',
            'dpkts': ' Total Backward Packets',
            'sbytes': ' Total Length of Fwd Packets',
            'dbytes': ' Total Length of Bwd Packets',
            'sload': ' Flow Bytes/s',
            'smean': ' Fwd Packet Length Mean',
            'dmean': ' Bwd Packet Length Mean',
            'flow_iat_mean': ' Flow IAT Mean',
            'flow_iat_std': ' Flow IAT Std',
            'fwd_psh_flags': ' Fwd PSH Flags',
            'bwd_psh_flags': ' Bwd PSH Flags',
            'fwd_urg_flags': ' Fwd URG Flags',
            'bwd_urg_flags': ' Bwd URG Flags',
            'packet_len_mean': ' Packet Length Mean',
            'packet_len_std': ' Packet Length Std',
            'packet_len_var': ' Packet Length Variance',
            'fin_flag_count': ' FIN Flag Count',
            'syn_flag_count': ' SYN Flag Count',
            'rst_flag_count': ' RST Flag Count',
            'psh_flag_count': ' PSH Flag Count',
            'ack_flag_count': ' ACK Flag Count',
            'urg_flag_count': ' URG Flag Count'
        }

        # Mapeo 82 → 4
        self.feature_mappings['82_to_4_map'] = {
            0: ' Flow Duration',
            1: ' Total Fwd Packets',
            2: ' Total Backward Packets',
            3: ' Total Length of Fwd Packets'
        }

    def _log_configuration_summary(self):
        """Log resumen de configuración cargada"""
        self.logger.info(f"🚀 TRICAPA ML DETECTOR v3.1.2 JSON-CONTROLLED-PUBSUB inicializado")
        self.logger.info(f"   🏷️ Node ID: {self.node_id}")
        self.logger.info(f"   🔢 PID: {self.process_id}")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")
        self.logger.info(f"   🧠 Modelos desde JSON: {len(self.enabled_models)} ({self.enabled_models})")
        self.logger.info(f"   🔒 Thread Safety: ZMQ sockets protegidos")
        self.logger.info(f"   🧵 Workers desde JSON: {self.worker_pool_size}")
        self.logger.info(f"   📡 Patrón ZMQ: {getattr(self, 'socket_pattern', 'PUSH')} (configurado desde JSON)")
        self.logger.info(f"   ⚡ Performance: Configuración desde JSON")
        self.logger.info(f"   🌐 PORTABLE: 100% controlado por JSON")

    def extract_features_from_protobuf_v31_optimized(self, event) -> Tuple[np.ndarray, List[str]]:
        """Extraer features OPTIMIZADO para máximo performance"""
        if not hasattr(event, 'network_features'):
            return np.zeros(82), [f'dummy_{i}' for i in range(82)]

        nf = event.network_features
        features = []
        feature_names = []

        # Fields básicos optimizados
        basic_fields = [
            ('source_port', 'source_port'),
            ('destination_port', 'destination_port'),
            ('protocol_number', 'protocol_number'),
            ('total_forward_packets', 'total_forward_packets'),
            ('total_backward_packets', 'total_backward_packets'),
            ('total_forward_bytes', 'total_forward_bytes'),
            ('total_backward_bytes', 'total_backward_bytes'),
            ('forward_packet_length_max', 'forward_packet_length_max'),
            ('forward_packet_length_min', 'forward_packet_length_min'),
            ('forward_packet_length_mean', 'forward_packet_length_mean'),
        ]

        # Extraer solo lo necesario
        for field_name, attr_name in basic_fields:
            if hasattr(nf, attr_name):
                try:
                    value = getattr(nf, attr_name)
                    features.append(float(value) if value is not None else 0.0)
                    feature_names.append(field_name)
                except:
                    features.append(0.0)
                    feature_names.append(field_name)
            else:
                features.append(0.0)
                feature_names.append(field_name)

        # Rellenar hasta 82
        while len(features) < 82:
            features.append(0.0)
            feature_names.append(f'feature_{len(features)}')

        return np.array(features[:82]), feature_names[:82]

    def extract_features_23_optimized(self, features_82: np.ndarray, feature_names_82: List[str]) -> np.ndarray:
        """Extraer 23 features OPTIMIZADO"""
        return features_82[:23]

    def extract_features_4_optimized(self, features_82: np.ndarray, feature_names_82: List[str]) -> np.ndarray:
        """Extraer 4 features OPTIMIZADO"""
        return features_82[:4]

    def classify_traffic_type_optimized(self, features_82: np.ndarray, feature_names_82: List[str]) -> str:
        """Clasificar tipo de tráfico OPTIMIZADO"""
        if len(features_82) >= 2:
            src_port = features_82[0]
            dst_port = features_82[1]

            web_ports = [80, 443, 8080, 8443]
            if src_port in web_ports or dst_port in web_ports:
                return 'web'

            return 'internal'
        return 'internal'

    def predict_tricapa_json_controlled(self, features_82: np.ndarray, feature_names_82: List[str]) -> Dict:
        """🎯 PREDICCIÓN TRICAPA 100% controlada por JSON"""
        start_time = time.time()

        # Obtener umbrales del JSON
        thresholds = self.ml_config.get("thresholds", {})
        level1_threshold = thresholds.get("level1_attack_threshold", 0.65)
        level2_ddos_threshold = thresholds.get("level2_ddos_threshold", 0.70)
        level2_ransomware_threshold = thresholds.get("level2_ransomware_threshold", 0.75)
        level3_threshold = thresholds.get("level3_anomaly_threshold", 0.80)

        results = {
            'timestamp': time.time(),
            'processing_time_ms': 0,
            'tricapa_analysis': {
                'level1': {'attack_detected': False, 'confidence': 0.0, 'model_status': 'failed'},
                'level2': {'ddos_scores': {}, 'ransomware_scores': {}, 'final_type': 'UNKNOWN'},
                'level3': {'anomaly_detected': False, 'traffic_type': 'unknown', 'scores': {}}
            },
            'final_classification': 'NORMAL',
            'overall_confidence': 0.0,
            'alerts': [],
            'degraded_mode': False,
            'models_used': []
        }

        try:
            # 🥇 NIVEL 1: Buscar detector de nivel 1 en modelos habilitados
            level1_model = None
            level1_scaler = None

            if 'level1_attack_detector' in self.enabled_models:
                level1_model = self.models.get('level1_attack_detector')
                level1_scaler = self.scalers.get('level1_scaler')

            if level1_model and level1_scaler:
                try:
                    features_23 = self.extract_features_23_optimized(features_82, feature_names_82)
                    features_23_scaled = level1_scaler.transform(features_23.reshape(1, -1))

                    attack_proba = level1_model.predict_proba(features_23_scaled)[0]
                    attack_probability = float(attack_proba[1])

                    results['tricapa_analysis']['level1'] = {
                        'attack_detected': attack_probability > level1_threshold,
                        'confidence': attack_probability,
                        'model_status': 'active'
                    }
                    results['models_used'].append('level1_attack_detector')

                    with self.stats_lock:
                        self.stats['level1_predictions'] += 1

                    # LOG VISIBLE del score nivel 1
                    self.logger.info(
                        f"🥇 Nivel 1 Score: {attack_probability:.3f} (threshold: {level1_threshold}) - {'ATTACK' if attack_probability > level1_threshold else 'NORMAL'}")

                    if attack_probability > level1_threshold:
                        with self.stats_lock:
                            self.stats['level1_attacks_detected'] += 1

                        # 🥈 NIVEL 2: Buscar modelos de nivel 2 habilitados en JSON
                        results['final_classification'] = 'ATTACK'

                        # DDOS models (buscar todos los habilitados)
                        ddos_scores = {}
                        ddos_models = [m for m in self.enabled_models if 'ddos' in m]
                        for model_name in ddos_models:
                            if model_name in self.models:
                                try:
                                    ddos_proba = self.models[model_name].predict_proba(features_82.reshape(1, -1))[0]
                                    ddos_scores[model_name] = float(ddos_proba[1])
                                    results['models_used'].append(model_name)
                                    self.logger.info(f"🔥 {model_name.upper()} Score: {ddos_scores[model_name]:.3f}")
                                except Exception as e:
                                    self.logger.warning(f"⚠️ {model_name} falló: {e}")

                        # Ransomware models (buscar todos los habilitados)
                        ransomware_scores = {}
                        ransomware_models = [m for m in self.enabled_models if 'ransomware' in m]
                        for model_name in ransomware_models:
                            if model_name in self.models:
                                try:
                                    ransomware_proba = \
                                        self.models[model_name].predict_proba(features_82.reshape(1, -1))[0]
                                    ransomware_scores[model_name] = float(ransomware_proba[1])
                                    results['models_used'].append(model_name)
                                    self.logger.info(
                                        f"🦠 {model_name.upper()} Score: {ransomware_scores[model_name]:.3f}")
                                except Exception as e:
                                    self.logger.warning(f"⚠️ {model_name} falló: {e}")

                        results['tricapa_analysis']['level2'] = {
                            'ddos_scores': ddos_scores,
                            'ransomware_scores': ransomware_scores
                        }

                        # Determinar tipo final de ataque
                        ddos_max = max(ddos_scores.values()) if ddos_scores else 0.0
                        ransomware_max = max(ransomware_scores.values()) if ransomware_scores else 0.0

                        if ddos_max > level2_ddos_threshold and ddos_max >= ransomware_max:
                            results['final_classification'] = 'DDOS'
                            results['overall_confidence'] = ddos_max
                            results['alerts'].append(f'🚨 DDoS Attack Detected (confidence: {ddos_max:.2%})')
                            results['tricapa_analysis']['level2']['final_type'] = 'DDOS'
                            with self.stats_lock:
                                self.stats['level2_ddos_detected'] += 1
                            self.logger.info(f"🚨 DDOS DETECTADO! Confidence: {ddos_max:.3f}")

                        elif ransomware_max > level2_ransomware_threshold:
                            results['final_classification'] = 'RANSOMWARE'
                            results['overall_confidence'] = ransomware_max
                            results['alerts'].append(f'🦠 Ransomware Detected (confidence: {ransomware_max:.2%})')
                            results['tricapa_analysis']['level2']['final_type'] = 'RANSOMWARE'
                            with self.stats_lock:
                                self.stats['level2_ransomware_detected'] += 1
                            self.logger.info(f"🦠 RANSOMWARE DETECTADO! Confidence: {ransomware_max:.3f}")

                        else:
                            results['final_classification'] = 'UNKNOWN_ATTACK'
                            results['overall_confidence'] = attack_probability
                            results['alerts'].append(f'⚠️ Unknown Attack Type (confidence: {attack_probability:.2%})')
                            results['tricapa_analysis']['level2']['final_type'] = 'UNKNOWN'

                    else:
                        # 🥉 NIVEL 3: Buscar detectores de nivel 3 habilitados en JSON
                        traffic_type = self.classify_traffic_type_optimized(features_82, feature_names_82)
                        features_4 = self.extract_features_4_optimized(features_82, feature_names_82)

                        level3_results = {'traffic_type': traffic_type, 'scores': {}}

                        # Buscar detector apropiado según tipo de tráfico
                        if traffic_type == 'internal' and 'internal_detector' in self.enabled_models:
                            model = self.models.get('internal_detector')
                            if model:
                                try:
                                    internal_proba = model.predict_proba(features_4.reshape(1, -1))[0]
                                    internal_anomaly_score = float(internal_proba[1])
                                    level3_results['scores']['internal_anomaly'] = internal_anomaly_score
                                    results['models_used'].append('internal_detector')

                                    self.logger.info(f"🔍 Internal Anomaly Score: {internal_anomaly_score:.3f}")

                                    if internal_anomaly_score > level3_threshold:
                                        results['final_classification'] = 'INTERNAL_ANOMALY'
                                        results['overall_confidence'] = internal_anomaly_score
                                        results['alerts'].append(
                                            f'🔍 Internal Traffic Anomaly (confidence: {internal_anomaly_score:.2%})')
                                        level3_results['anomaly_detected'] = True
                                        with self.stats_lock:
                                            self.stats['level3_internal_anomalies'] += 1
                                        self.logger.info(
                                            f"🔍 ANOMALÍA INTERNA DETECTADA! Confidence: {internal_anomaly_score:.3f}")

                                except Exception as e:
                                    self.logger.warning(f"⚠️ Internal detector falló: {e}")

                        elif traffic_type == 'web' and 'web_detector' in self.enabled_models:
                            model = self.models.get('web_detector')
                            if model:
                                try:
                                    web_proba = model.predict_proba(features_4.reshape(1, -1))[0]
                                    web_anomaly_score = float(web_proba[1])
                                    level3_results['scores']['web_anomaly'] = web_anomaly_score
                                    results['models_used'].append('web_detector')

                                    self.logger.info(f"🌐 Web Anomaly Score: {web_anomaly_score:.3f}")

                                    if web_anomaly_score > level3_threshold:
                                        results['final_classification'] = 'WEB_ANOMALY'
                                        results['overall_confidence'] = web_anomaly_score
                                        results['alerts'].append(
                                            f'🌐 Web Traffic Anomaly (confidence: {web_anomaly_score:.2%})')
                                        level3_results['anomaly_detected'] = True
                                        with self.stats_lock:
                                            self.stats['level3_web_anomalies'] += 1
                                        self.logger.info(
                                            f"🌐 ANOMALÍA WEB DETECTADA! Confidence: {web_anomaly_score:.3f}")

                                except Exception as e:
                                    self.logger.warning(f"⚠️ Web detector falló: {e}")

                        results['tricapa_analysis']['level3'] = level3_results

                        if results['final_classification'] == 'NORMAL':
                            results['overall_confidence'] = 1.0 - attack_probability

                except Exception as e:
                    self.logger.error(f"❌ Nivel 1 falló: {e}")
                    results['degraded_mode'] = True
                    with self.stats_lock:
                        self.stats['model_failures'] += 1
            else:
                self.logger.warning("⚠️ Nivel 1 no disponible en JSON - modo degradado")
                results['degraded_mode'] = True

        except Exception as e:
            self.logger.error(f"❌ Error predicción tricapa: {e}")
            results['error'] = str(e)
            results['final_classification'] = 'ERROR'
            with self.stats_lock:
                self.stats['processing_errors'] += 1

        # Sistema degradado si no hay suficientes modelos
        min_models = self.tricapa_config.get("failure_handling", {}).get("min_models_for_operation", 1)
        if len(results['models_used']) < min_models:
            results['degraded_mode'] = True
            with self.stats_lock:
                self.stats['tricapa_degraded_mode'] += 1

        results['processing_time_ms'] = (time.time() - start_time) * 1000
        return results

    def enrich_protobuf_with_tricapa_analysis(self, protobuf_data: bytes) -> Optional[bytes]:
        """🎯 Enriquecer protobuf con análisis tricapa JSON-controlled"""
        if not PROTOBUF_AVAILABLE:
            return None

        try:
            # Deserializar evento v3.1
            event = NetworkSecurityEventProto.NetworkSecurityEvent()
            event.ParseFromString(protobuf_data)

            # Extraer features 82 del protobuf v3.1
            features_82, feature_names_82 = self.extract_features_from_protobuf_v31_optimized(event)

            # Ejecutar análisis tricapa JSON-controlled
            tricapa_results = self.predict_tricapa_json_controlled(features_82, feature_names_82)

            # Crear evento enriquecido
            enriched_event = NetworkSecurityEventProto.NetworkSecurityEvent()
            enriched_event.CopyFrom(event)

            # Scoring general
            enriched_event.overall_threat_score = tricapa_results['overall_confidence']
            enriched_event.final_classification = tricapa_results['final_classification']
            enriched_event.threat_category = tricapa_results['final_classification']

            # Metadatos
            enriched_event.schema_version = 31
            enriched_event.protobuf_version = "3.1.2-json-controlled-pubsub"

            # Incrementar estadísticas thread-safe
            with self.stats_lock:
                self.stats['processed'] += 1

            return enriched_event.SerializeToString()

        except Exception as e:
            with self.stats_lock:
                self.stats['processing_errors'] += 1
            return None

    def write_protobuf_log(self, enriched_event_data: bytes):
        """📦 Escribir log protobuf thread-safe"""
        try:
            now = datetime.now()
            date_dir = self.proto_log_dir / str(now.year) / f"{now.month:02d}" / f"{now.day:02d}"
            date_dir.mkdir(parents=True, exist_ok=True)

            filename = f"events_{now.hour:02d}{now.minute:02d}{now.second:02d}.proto"
            filepath = date_dir / filename

            with self.logger_lock:
                with open(filepath, 'ab') as f:
                    f.write(enriched_event_data)

            with self.stats_lock:
                self.stats['protobuf_logs_written'] += 1

        except Exception as e:
            pass

    # === THREADS ===

    def receive_protobuf_events(self):
        """🔒 Thread ÚNICO de recepción"""
        self.logger.info("📡 Iniciando recepción protobuf tricapa v3.1.2 JSON-CONTROLLED-PUBSUB...")

        consecutive_empty_receives = 0

        # Obtener threshold desde JSON
        backpressure_threshold = 0.7  # Default
        if self.backpressure_config:
            # Calcular threshold desde configuración JSON
            activation_threshold = self.backpressure_config.get("activation_threshold", 20)
            queue_size = self.config.get("processing", {}).get("protobuf_queue_size", 300)
            if queue_size > 0:
                backpressure_threshold = activation_threshold / queue_size
                backpressure_threshold = max(0.5, min(0.9, backpressure_threshold))  # Entre 50-90%

        while self.running:
            try:
                with self.socket_lock:
                    try:
                        protobuf_data = self.input_socket.recv(zmq.NOBLOCK)
                        consecutive_empty_receives = 0
                    except zmq.Again:
                        consecutive_empty_receives += 1
                        if consecutive_empty_receives > 10:
                            time.sleep(0.001)
                        continue

                with self.stats_lock:
                    self.stats['received'] += 1

                # Validación de tamaño desde JSON
                max_size = self.config.get("zmq", {}).get("max_message_size", 50000)
                if len(protobuf_data) > max_size:
                    continue

                # Backpressure desde JSON
                current_usage = self.protobuf_queue.qsize() / self.config.get("processing", {}).get(
                    "protobuf_queue_size", 300)
                if current_usage > backpressure_threshold:
                    self.backpressure_log_counter += 1
                    # Configurar frecuencia de log desde JSON
                    log_frequency = self.backpressure_config.get("log_frequency", 500)
                    if self.backpressure_log_counter % log_frequency == 0:
                        self.logger.warning(f"🚨 Cola muy llena ({current_usage * 100:.1f}%) - backpressure activo")
                    continue

                try:
                    self.protobuf_queue.put_nowait(protobuf_data)
                except:
                    with self.stats_lock:
                        self.stats['dropped_by_backpressure'] += 1
                    continue

            except Exception as e:
                time.sleep(0.1)

    def process_protobuf_events_worker(self, worker_id: int):
        """🛠️ Worker de procesamiento JSON-controlled"""
        self.logger.info(f"⚙️ Worker {worker_id} iniciado para procesamiento tricapa JSON-CONTROLLED-PUBSUB...")

        local_stats = {'processed': 0, 'errors': 0}

        while self.running and not self.worker_shutdown_event.is_set():
            try:
                try:
                    protobuf_data = self.protobuf_queue.get(timeout=1.0)
                except Empty:
                    continue

                try:
                    enriched_protobuf = self.enrich_protobuf_with_tricapa_analysis(protobuf_data)
                    local_stats['processed'] += 1

                    if enriched_protobuf:
                        self.write_protobuf_log(enriched_protobuf)

                        try:
                            self.enriched_queue.put_nowait(enriched_protobuf)
                        except:
                            with self.stats_lock:
                                self.stats['dropped_output_full'] += 1

                except Exception:
                    local_stats['errors'] += 1

                finally:
                    self.protobuf_queue.task_done()

                if local_stats['processed'] % 50 == 0:
                    with self.stats_lock:
                        self.stats['processed'] += local_stats['processed']
                        self.stats['processing_errors'] += local_stats['errors']
                    local_stats = {'processed': 0, 'errors': 0}

            except Exception:
                time.sleep(0.1)

        # Actualizar stats finales
        with self.stats_lock:
            self.stats['processed'] += local_stats['processed']
            self.stats['processing_errors'] += local_stats['errors']

    def send_enriched_events(self):
        """📤 Thread ÚNICO de envío - SOPORTE PUB/SUB"""
        self.logger.info(f"📤 Iniciando envío tricapa v3.1.2 JSON-CONTROLLED ({self.socket_pattern})...")

        local_sent_count = 0
        consecutive_empty_sends = 0

        while self.running:
            try:
                try:
                    enriched_protobuf = self.enriched_queue.get(timeout=1.0)
                    consecutive_empty_sends = 0
                except Empty:
                    consecutive_empty_sends += 1
                    if consecutive_empty_sends > 10:
                        time.sleep(0.001)
                    continue

                with self.socket_lock:
                    try:
                        # 🚀 Envío unificado (PUB y PUSH usan el mismo método)
                        self.output_socket.send(enriched_protobuf, zmq.NOBLOCK)
                        local_sent_count += 1

                    except zmq.Again:
                        # Retry una vez si está ocupado
                        time.sleep(0.001)
                        try:
                            self.output_socket.send(enriched_protobuf, zmq.NOBLOCK)
                            local_sent_count += 1
                        except zmq.Again:
                            # Si falla después del retry, contar como drop
                            with self.stats_lock:
                                self.stats['dropped_send_timeout'] += 1

                # Actualizar stats periódicamente
                if local_sent_count % 50 == 0:
                    with self.stats_lock:
                        self.stats['sent'] += local_sent_count
                    local_sent_count = 0

                self.enriched_queue.task_done()

            except Exception:
                time.sleep(0.1)

        # Actualizar stats finales
        with self.stats_lock:
            self.stats['sent'] += local_sent_count

    def monitor_tricapa_performance(self):
        """Monitor de performance desde JSON"""
        interval = self.config.get("monitoring", {}).get("stats_interval_seconds", 60)

        while self.running:
            time.sleep(interval)
            if not self.running:
                break
            self._log_tricapa_stats()

    def _log_tricapa_stats(self):
        """📊 Log estadísticas tricapa thread-safe"""
        with self.stats_lock:
            current_stats = dict(self.stats)

        self.logger.info(f"📊 TRICAPA v3.1.2 JSON-CONTROLLED-PUBSUB Stats:")
        self.logger.info(f"   📨 Recibidos: {current_stats.get('received', 0)}")
        self.logger.info(f"   🎯 Procesados: {current_stats.get('processed', 0)}")
        self.logger.info(f"   📤 Enviados: {current_stats.get('sent', 0)}")
        self.logger.info(f"   🥇 Nivel 1 predicciones: {current_stats.get('level1_predictions', 0)}")
        self.logger.info(f"   🚨 Ataques detectados: {current_stats.get('level1_attacks_detected', 0)}")
        self.logger.info(f"   💥 DDOS detectados: {current_stats.get('level2_ddos_detected', 0)}")
        self.logger.info(f"   🦠 Ransomware detectados: {current_stats.get('level2_ransomware_detected', 0)}")
        self.logger.info(f"   🔍 Anomalías internas: {current_stats.get('level3_internal_anomalies', 0)}")
        self.logger.info(f"   🌐 Anomalías web: {current_stats.get('level3_web_anomalies', 0)}")
        self.logger.info(f"   ⚠️ Modo degradado: {current_stats.get('tricapa_degraded_mode', 0)}")
        self.logger.info(f"   📦 Logs Proto: {current_stats.get('protobuf_logs_written', 0)}")
        self.logger.info(f"   🚫 Drops backpressure: {current_stats.get('dropped_by_backpressure', 0)}")
        self.logger.info(f"   🚫 Drops output full: {current_stats.get('dropped_output_full', 0)}")
        self.logger.info(f"   🚫 Drops send timeout: {current_stats.get('dropped_send_timeout', 0)}")

        # Reset stats thread-safe
        with self.stats_lock:
            for key in ['received', 'processed', 'sent', 'level1_predictions',
                        'level1_attacks_detected', 'level2_ddos_detected',
                        'level2_ransomware_detected', 'level3_internal_anomalies',
                        'level3_web_anomalies', 'protobuf_logs_written',
                        'dropped_by_backpressure', 'dropped_output_full',
                        'dropped_send_timeout']:
                self.stats[key] = 0

    def run(self):
        """🚀 Ejecutar detector tricapa v3.1.2 - JSON CONTROLLED CON PUB/SUB"""
        print(f"🚀 Iniciando TRICAPA ML DETECTOR v3.1.2 JSON-CONTROLLED-PUBSUB...")
        self.logger.info("🚀 Iniciando TRICAPA ML DETECTOR v3.1.2 JSON-CONTROLLED-PUBSUB...")

        threads = []

        # Thread de recepción
        recv_thread = threading.Thread(target=self.receive_protobuf_events, name="TricapaReceiver")
        recv_thread.daemon = True
        threads.append(recv_thread)

        # Pool de workers desde JSON
        for i in range(self.worker_pool_size):
            worker_thread = threading.Thread(
                target=self.process_protobuf_events_worker,
                args=(i + 1,),
                name=f"TricapaWorker_{i + 1}"
            )
            worker_thread.daemon = True
            threads.append(worker_thread)

        # Thread de envío
        send_thread = threading.Thread(target=self.send_enriched_events, name="TricapaSender")
        send_thread.daemon = True
        threads.append(send_thread)

        # Thread de monitoreo
        monitor_thread = threading.Thread(target=self.monitor_tricapa_performance, name="TricapaMonitor")
        monitor_thread.daemon = True
        threads.append(monitor_thread)

        # Iniciar todos los threads
        for thread in threads:
            thread.start()

        total_threads = len(threads)

        # Información de arquitectura según patrón
        if self.socket_pattern == "PUB":
            distribution_info = "📡 PUB/SUB: dashboard + no-gui pueden suscribirse simultáneamente"
            subscriber_cmd = f"tcp://localhost:{self.config.get('network', {}).get('output_socket', {}).get('port', 5580)}"
        else:
            distribution_info = "📤 PUSH/PULL: un solo consumidor"
            subscriber_cmd = "Un solo componente puede conectarse"

        print(f"✅ TRICAPA ML DETECTOR v3.1.2 JSON-CONTROLLED-PUBSUB iniciado:")
        print(f"   🧵 Threads: {total_threads} ({self.worker_pool_size} workers + 3 control)")
        print(f"   🧠 Modelos JSON: {len(self.enabled_models)} ({self.enabled_models})")
        print(f"   🔒 Thread Safety: ZMQ sockets protegidos")
        print(f"   📡 Patrón: {self.socket_pattern}")
        print(f"   {distribution_info}")
        if self.socket_pattern == "PUB":
            print(f"   🔌 Suscribirse en: {subscriber_cmd}")
        print(f"   🌐 PORTABLE: 100% controlado por JSON")
        print(f"   📊 Logs: VISIBLES (scores ML + stats)")

        self.logger.info(f"✅ TRICAPA ML DETECTOR v3.1.2 JSON-CONTROLLED-PUBSUB iniciado:")
        self.logger.info(f"   🧵 Threads: {total_threads} ({self.worker_pool_size} workers + 3 control)")
        self.logger.info(f"   🧠 Modelos activos: {len(self.enabled_models)} {self.enabled_models}")
        self.logger.info(f"   🔒 Thread Safety: ZMQ sockets protegidos")
        self.logger.info(f"   📡 Patrón: {self.socket_pattern}")
        if self.socket_pattern == "PUB":
            self.logger.info(f"   📡 Múltiples suscriptores permitidos en: {subscriber_cmd}")
        self.logger.info(f"   🌐 PORTABLE: 100% configuración desde JSON")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("🛑 Deteniendo TRICAPA ML DETECTOR v3.1.2 JSON-CONTROLLED-PUBSUB...")

        self.shutdown_json_controlled(threads)

    def shutdown_json_controlled(self, threads):
        """🔒 Cierre graceful JSON-controlled"""
        self.logger.info("🛑 Iniciando shutdown JSON-controlled...")

        self.running = False
        self.worker_shutdown_event.set()

        runtime = time.time() - self.stats['start_time']
        self.logger.info(f"📊 Runtime total: {runtime:.1f}s")

        for thread in threads:
            thread.join(timeout=2.0)
            if thread.is_alive():
                self.logger.warning(f"⚠️ Thread {thread.name} no terminó")

        # 🔐 NUEVO: Cleanup crypto wrapper
        if self.crypto_wrapper:
            try:
                self.crypto_wrapper.close()
                self.logger.info("🔐 Crypto wrapper cerrado correctamente")
            except Exception as e:
                self.logger.error(f"❌ Error cerrando crypto wrapper: {e}")

        with self.socket_lock:
            if self.input_socket:
                self.input_socket.close()
            if self.output_socket:
                self.output_socket.close()
            self.context.term()

        with self.stats_lock:
            final_stats = dict(self.stats)

        self.logger.info("📊 STATS FINALES JSON-CONTROLLED-PUBSUB:")
        self.logger.info(f"   📨 Recibidos: {final_stats.get('received', 0)}")
        self.logger.info(f"   🎯 Procesados: {final_stats.get('processed', 0)}")
        self.logger.info(f"   📤 Enviados: {final_stats.get('sent', 0)}")

        self.logger.info("✅ TRICAPA ML DETECTOR v3.1.2 JSON-CONTROLLED-PUBSUB cerrado")


# 🚀 Main
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Uso: python lightweight_ml_detector_tricapa_v31.py <config.json>")
        print("💡 Ejemplo: python lightweight_ml_detector_tricapa_v31.py tricapa_v31_config.json")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        detector = TricapaMLDetectorV31JsonControlled(config_file)
        detector.run()
    except Exception as e:
        print(f"❌ Error fatal tricapa JSON-controlled: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)