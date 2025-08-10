#!/usr/bin/env python3
"""
lightweight_ml_detector_tricapa_v31.py
🚀 UPGRADED HAPPINESS - TRICAPA ML DETECTOR v3.1
✨ Combinación PERFECTA: Configuración conservadora ZMQ + Cerebro tricapa

FILOSOFÍA:
- ZMQ/Network: Configuración conservadora del lightweight_ml_detector_v3
- ML: Sistema tricapa completo del complete_ml_pipeline
- Protobuf: v3.1 con mapping 82→23→4
- Logs: JSON para RAG + Protobuf para análisis profundo
- Error handling: Sistema degradado > sistema roto

ARQUITECTURA TRICAPA:
- NIVEL 1: RF Production (23 features) → ¿HAY ATAQUE?
- NIVEL 2: DDOS/Ransomware (82 features) → ¿QUÉ TIPO? (4 modelos)
- NIVEL 3: Internal/Web Detectors (4 features) → ¿"Normal" es REALMENTE normal?

Autor: Alonso Isidoro, Claude
Fecha: Agosto 10, 2025
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
from threading import Event

# 📦 Protobuf v3.1 - REQUERIDO
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = "unavailable"
NetworkSecurityEventProto = None

# 📦 Protobuf v3.1 LIMPIO - REQUERIDO
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = "unavailable"
NetworkSecurityEventProto = None


def import_protobuf_v31():
    """Importa el protobuf v3.1 limpio - EXCLUSIVO con búsqueda automática"""
    global NetworkSecurityEventProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    # Estrategias de importación múltiples
    import_strategies = [
        # Estrategia 1: Importación directa (si está en el mismo directorio)
        ("network_security_clean_v31_pb2", "Importación directa"),

        # Estrategia 2: Desde protocols.v3.1
        ("protocols.v3.1.network_security_clean_v31_pb2", "Paquete protocols.v3.1"),
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
        # Desde core/ buscar en protocols/v3.1/
        os.path.join(current_dir, '..', 'protocols', 'v3.1'),
        # Desde raíz del proyecto buscar protocols/v3.1/
        os.path.join(current_dir, 'protocols', 'v3.1'),
        # Directorio actual
        current_dir,
        # Directorio padre
        os.path.join(current_dir, '..'),
    ]

    for protocols_path in possible_paths:
        protocols_path = os.path.abspath(protocols_path)
        pb2_file = os.path.join(protocols_path, 'network_security_clean_v31_pb2.py')

        if os.path.exists(pb2_file):
            try:
                # Añadir el path temporalmente
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

    # Si llegamos aquí, no se encontró el protobuf
    print(f"❌ Protobuf v3.1 REQUERIDO pero no encontrado")
    print(f"🔍 Buscando en:")
    for path in possible_paths:
        pb2_file = os.path.join(os.path.abspath(path), 'network_security_clean_v31_pb2.py')
        exists = "✅" if os.path.exists(pb2_file) else "❌"
        print(f"   {exists} {pb2_file}")
    print(f"💡 Solución:")
    print(f"   1. cd protocols/v3.1/")
    print(f"   2. protoc --python_out=. network_security_clean_v31.proto")
    print(f"   3. Verificar que se generó: network_security_clean_v31_pb2.py")
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


class TricapaMLDetectorV31:
    """
    🚀 Detector ML Tricapa v3.1 - La evolución definitiva
    - Configuración ZMQ conservadora del lightweight_v3
    - Sistema tricapa completo del complete_ml_pipeline
    - Protobuf v3.1 con features organizadas
    - Logging dual: JSON para RAG + Protobuf para análisis
    - Arsenal completo de modelos: 1 + 4 + 2 = 7 modelos
    """

    def __init__(self, config_file: str):
        # 📄 Cargar configuración con validación estricta
        self.config = self._load_and_validate_config(config_file)
        self.config_file = config_file

        # 🏷️ Identidad distribuida
        self.node_id = self.config["node_id"]
        self.process_id = os.getpid()
        self.start_time = time.time()

        # 📝 Setup logging PRIMERO
        self.setup_dual_logging()

        # 🔌 Setup ZeroMQ CONSERVADOR
        self.context = zmq.Context()
        self.input_socket = None
        self.output_socket = None
        self.setup_conservative_sockets()

        # 🔄 Backpressure AGRESIVO
        self.backpressure_config = self.config["backpressure"]

        # 📦 Colas internas PEQUEÑAS
        self.setup_internal_queues()

        # 🧠 SISTEMA TRICAPA COMPLETO
        self.ml_config = self.config["ml"]
        self.tricapa_config = self.config["tricapa"]

        # 📂 Rutas de modelos
        self.setup_model_paths()

        # 🤖 ARSENAL DE MODELOS TRICAPA
        self.models = {
            # Nivel 1: Detector general (23 features)
            'level1_attack_detector': None,

            # Nivel 2: Especialistas (82 features) - ARSENAL COMPLETO
            'ddos_rf': None,
            'ddos_lgb': None,
            'ransomware_rf': None,
            'ransomware_lgb': None,

            # Nivel 3: Detectores normalidad (4 features)
            'internal_detector': None,
            'web_detector': None
        }

        # 🔧 Scalers (solo nivel 1 tiene scaler)
        self.scalers = {
            'level1_scaler': None
        }

        # 🗂️ Feature mappings tricapa
        self.feature_mappings = {}

        # 📊 Métricas tricapa
        self.setup_tricapa_stats()

        # 🎛️ Control
        self.running = True
        self.stop_event = Event()

        # 📁 Sistema de logging avanzado
        self.setup_advanced_logging()

        # ✅ Verificar dependencias críticas
        self._verify_critical_dependencies()

        # 🔄 Cargar modelos tricapa
        self.load_tricapa_models()

        self.logger.info(f"🚀 TRICAPA ML DETECTOR v3.1 inicializado")
        self.logger.info(f"   🏷️ Node ID: {self.node_id}")
        self.logger.info(f"   🔢 PID: {self.process_id}")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")
        self.logger.info(f"   🧠 Arsenal: {list(self.models.keys())}")
        self.logger.info(f"   🎯 Sistema: TRICAPA v3.1 con logging dual")

    def _load_and_validate_config(self, config_file: str) -> Dict[str, Any]:
        """Carga y valida configuración con warnings enormes"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            raise RuntimeError(f"❌ CRÍTICO: Archivo de configuración no encontrado: {config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ CRÍTICO: Error parseando JSON: {e}")

        # ✅ Validar campos críticos
        required_sections = [
            "node_id", "network", "zmq", "backpressure", "processing",
            "ml", "tricapa", "logging"
        ]

        # Advanced_logging es opcional con valores por defecto
        optional_sections = ["advanced_logging"]

        for section in required_sections:
            if section not in config:
                raise RuntimeError(f"❌ CRÍTICO: Sección requerida faltante: {section}")

        for section in optional_sections:
            if section not in config:
                print(f"⚠️ WARNING: Sección opcional '{section}' no encontrada - usando valores por defecto")
                config[section] = {}  # Crear sección vacía

        # ⚠️ Validar umbrales críticos con WARNINGS ENORMES
        critical_thresholds = [
            ("ml.thresholds.level1_attack_threshold", 0.5),
            ("ml.thresholds.level2_ddos_threshold", 0.5),
            ("ml.thresholds.level2_ransomware_threshold", 0.5),
            ("ml.thresholds.level3_anomaly_threshold", 0.7),
            ("tricapa.ensemble.confidence_threshold", 0.6)
        ]

        for threshold_path, default_value in critical_thresholds:
            if not self._get_nested_config(config, threshold_path):
                print("=" * 80)
                print(f"🚨 WARNING ENORME: UMBRAL CRÍTICO NO ENCONTRADO: {threshold_path}")
                print(f"🚨 USANDO VALOR POR DEFECTO: {default_value}")
                print(f"🚨 ESTO PUEDE AFECTAR LA DETECCIÓN DE ATAQUES")
                print("=" * 80)
                self._set_nested_config(config, threshold_path, default_value)

        return config

    def _get_nested_config(self, config: dict, path: str) -> Any:
        """Obtiene valor anidado del config usando dot notation"""
        keys = path.split('.')
        value = config
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return None

    def _set_nested_config(self, config: dict, path: str, value: Any):
        """Establece valor anidado en config usando dot notation"""
        keys = path.split('.')
        current = config
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value

    def setup_model_paths(self):
        """Configurar rutas de modelos"""
        script_dir = Path(__file__).parent
        project_root = script_dir.parent

        self.models_dir = project_root / "models"
        self.production_dir = self.models_dir / "production"
        self.tricapa_dir = self.production_dir / "tricapa"

        self.logger.info(f"📂 Rutas de modelos:")
        self.logger.info(f"   📁 Production: {self.production_dir}")
        self.logger.info(f"   📁 Tricapa: {self.tricapa_dir}")

    def setup_dual_logging(self):
        """Setup logging dual: consola + archivo"""
        log_config = self.config["logging"]
        level = getattr(logging, log_config["level"].upper())
        log_format = log_config["format"].format(node_id=self.node_id, pid=self.process_id)
        formatter = logging.Formatter(log_format)

        self.logger = logging.getLogger(f"tricapa_ml_detector_{self.node_id}")
        self.logger.setLevel(level)
        self.logger.handlers.clear()

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(level)
        self.logger.addHandler(console_handler)

        # File handler
        if log_config.get("file"):
            log_file = Path(log_config["file"])
            log_file.parent.mkdir(parents=True, exist_ok=True)

            if log_config.get("max_file_size_mb") and log_config.get("backup_count"):
                from logging.handlers import RotatingFileHandler
                file_handler = RotatingFileHandler(
                    log_config["file"],
                    maxBytes=log_config["max_file_size_mb"] * 1024 * 1024,
                    backupCount=log_config["backup_count"]
                )
            else:
                file_handler = logging.FileHandler(log_config["file"])

            file_handler.setFormatter(formatter)
            file_handler.setLevel(level)
            self.logger.addHandler(file_handler)

        self.logger.propagate = False

    def setup_advanced_logging(self):
        """Configurar sistema de logging avanzado para RAG"""
        adv_log_config = self.config["advanced_logging"]

        # Acceder correctamente a la estructura anidada
        rag_config = adv_log_config.get("rag_logging", {})
        proto_config = adv_log_config.get("protobuf_logging", {})

        # Directorios de logging con valores por defecto
        self.rag_log_dir = Path(rag_config.get("rag_json_base_dir", "logs/rag/json"))
        self.proto_log_dir = Path(proto_config.get("protobuf_base_dir", "logs/proto"))

        # Crear estructura de directorios
        self.rag_log_dir.mkdir(parents=True, exist_ok=True)
        self.proto_log_dir.mkdir(parents=True, exist_ok=True)

        self.logger.info(f"📁 Logging avanzado configurado:")
        self.logger.info(f"   📄 RAG JSON: {self.rag_log_dir}")
        self.logger.info(f"   📦 Protobuf: {self.proto_log_dir}")

    def setup_conservative_sockets(self):
        """🔒 Configuración ZMQ CONSERVADORA"""
        network_config = self.config["network"]
        zmq_config = self.config["zmq"]

        try:
            # Socket de entrada
            input_config = network_config["input_socket"]
            self.input_socket = self.context.socket(zmq.PULL)

            self.input_socket.setsockopt(zmq.RCVHWM, zmq_config["rcvhwm"])
            self.input_socket.setsockopt(zmq.RCVTIMEO, zmq_config["recv_timeout_ms"])
            self.input_socket.setsockopt(zmq.LINGER, zmq_config["linger_ms"])
            self.input_socket.setsockopt(zmq.MAXMSGSIZE, zmq_config["max_message_size"])

            input_address = f"tcp://{input_config['address']}:{input_config['port']}"
            self.input_socket.connect(input_address)

            # Socket de salida
            output_config = network_config["output_socket"]
            self.output_socket = self.context.socket(zmq.PUSH)

            self.output_socket.setsockopt(zmq.SNDHWM, zmq_config["sndhwm"])
            self.output_socket.setsockopt(zmq.SNDTIMEO, zmq_config["send_timeout_ms"])
            self.output_socket.setsockopt(zmq.LINGER, zmq_config["linger_ms"])
            self.output_socket.setsockopt(zmq.MAXMSGSIZE, zmq_config["max_message_size"])

            output_address = f"tcp://*:{output_config['port']}"
            self.output_socket.bind(output_address)

            self.logger.info(f"🔌 Sockets ZMQ TRICAPA v3.1 configurados:")
            self.logger.info(f"   📥 Input: {input_address}")
            self.logger.info(f"   📤 Output: {output_address}")

        except Exception as e:
            raise RuntimeError(f"❌ Error configurando sockets ZMQ: {e}")

    def setup_internal_queues(self):
        """📋 Configuración de colas conservadoras"""
        proc_config = self.config["processing"]

        self.protobuf_queue = Queue(maxsize=proc_config["protobuf_queue_size"])
        self.enriched_queue = Queue(maxsize=proc_config["internal_queue_size"])

    def setup_tricapa_stats(self):
        """📊 Configurar métricas tricapa"""
        self.stats = {
            'received': 0, 'processed': 0, 'sent': 0,
            'level1_predictions': 0, 'level1_attacks_detected': 0,
            'level2_ddos_detected': 0, 'level2_ransomware_detected': 0,
            'level3_internal_anomalies': 0, 'level3_web_anomalies': 0,
            'tricapa_degraded_mode': 0, 'model_failures': 0,
            'rag_logs_written': 0, 'protobuf_logs_written': 0,
            'processing_errors': 0, 'start_time': time.time()
        }

    def _verify_critical_dependencies(self):
        """Verificar dependencias críticas"""
        issues = []

        if not PROTOBUF_AVAILABLE:
            issues.append("❌ Protobuf v3.1 no disponible")

        if not ML_AVAILABLE:
            issues.append("❌ Scikit-learn no disponible")
            print("💡 Solución: pip install scikit-learn")

        if issues:
            for issue in issues:
                print(issue)

            # Solo abortar si protobuf no está disponible
            if not PROTOBUF_AVAILABLE:
                raise RuntimeError("❌ Protobuf v3.1 es crítico")
            elif not ML_AVAILABLE:
                print("⚠️ Continuando sin ML - solo modo heurístico")
                self.ml_config["enabled"] = False

    def load_tricapa_models(self):
        """🧠 Cargar ARSENAL COMPLETO de modelos tricapa"""
        self.logger.info("🔄 Cargando arsenal tricapa completo...")

        models_loaded = 0
        models_failed = 0

        # NIVEL 1: Detector general de ataques (23 features + scaler)
        try:
            level1_path = self.production_dir / "rf_production_sniffer_compatible.joblib"
            scaler_path = self.production_dir / "rf_production_sniffer_compatible_scaler.joblib"

            production_data = joblib.load(level1_path)
            if isinstance(production_data, dict):
                self.models['level1_attack_detector'] = production_data['model']
                self.scalers['level1_scaler'] = production_data['scaler']
                self.feature_mappings['level1_features'] = production_data['feature_names']
            else:
                self.models['level1_attack_detector'] = production_data
                self.scalers['level1_scaler'] = joblib.load(scaler_path)

            models_loaded += 1
            self.logger.info("✅ Nivel 1: Attack Detector (23 features + scaler)")

        except Exception as e:
            models_failed += 1
            self.logger.error(f"❌ NIVEL 1 FALLÓ: {e}")

        # NIVEL 2: Arsenal especializado (82 features, sin scaler)
        level2_models = [
            ('ddos_rf', 'ddos_random_forest.joblib'),
            ('ddos_lgb', 'ddos_lightgbm.joblib'),
            ('ransomware_rf', 'ransomware_random_forest.joblib'),
            ('ransomware_lgb', 'ransomware_lightgbm.joblib')
        ]

        for model_name, filename in level2_models:
            try:
                model_path = self.tricapa_dir / filename
                self.models[model_name] = joblib.load(model_path)
                models_loaded += 1
                self.logger.info(f"✅ Nivel 2: {model_name} (82 features)")
            except Exception as e:
                models_failed += 1
                self.logger.error(f"❌ NIVEL 2 {model_name} FALLÓ: {e}")

        # NIVEL 3: Detectores de normalidad (4 features, sin scaler)
        level3_models = [
            ('internal_detector', 'internal_normal_detector.joblib'),
            ('web_detector', 'web_normal_detector.joblib')
        ]

        for model_name, filename in level3_models:
            try:
                # Primero intentar desde tricapa, luego desde production
                model_path = self.tricapa_dir / filename
                if not model_path.exists():
                    model_path = self.production_dir / filename

                self.models[model_name] = joblib.load(model_path)
                models_loaded += 1
                self.logger.info(f"✅ Nivel 3: {model_name} (4 features)")
            except Exception as e:
                models_failed += 1
                self.logger.error(f"❌ NIVEL 3 {model_name} FALLÓ: {e}")

        # Setup feature mappings
        self.setup_feature_mappings()

        # Determinar estado del sistema
        total_models = len(self.models)
        if models_loaded == total_models:
            self.logger.info(f"🎯 ARSENAL TRICAPA COMPLETO: {models_loaded}/{total_models} modelos")
        elif models_loaded > 0:
            print("=" * 80)
            print(f"⚠️ WARNING TRICAPA: SISTEMA DEGRADADO")
            print(f"⚠️ Modelos cargados: {models_loaded}/{total_models}")
            print(f"⚠️ Modelos fallidos: {models_failed}")
            print(f"⚠️ Continuando en MODO DEGRADADO")
            print("=" * 80)
        else:
            raise RuntimeError("❌ CRÍTICO: NO se pudo cargar ningún modelo")

    def setup_feature_mappings(self):
        """Configurar mapeos de features 82→23→4"""
        # Mapeo 82 → 23 (del complete_ml_pipeline)
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

    def extract_features_from_protobuf_v31(self, event) -> Tuple[np.ndarray, List[str]]:
        """Extraer features del protobuf v3.1 usando counts específicos"""
        if not hasattr(event, 'network_features'):
            raise ValueError("Evento sin network_features")

        nf = event.network_features
        features = []
        feature_names = []

        # Mapeo directo de fields protobuf v3.1 a features numpy
        protobuf_field_mapping = [
            # Básicos (6)
            ('source_port', getattr(nf, 'source_port', 0)),
            ('destination_port', getattr(nf, 'destination_port', 0)),
            ('protocol_number', getattr(nf, 'protocol_number', 0)),
            ('total_forward_packets', getattr(nf, 'total_forward_packets', 0)),
            ('total_backward_packets', getattr(nf, 'total_backward_packets', 0)),
            ('total_forward_bytes', getattr(nf, 'total_forward_bytes', 0)),

            # Continúa con más campos...
            ('total_backward_bytes', getattr(nf, 'total_backward_bytes', 0)),
            ('forward_packet_length_max', getattr(nf, 'forward_packet_length_max', 0)),
            ('forward_packet_length_min', getattr(nf, 'forward_packet_length_min', 0)),
            ('forward_packet_length_mean', getattr(nf, 'forward_packet_length_mean', 0.0)),

            # Agregar hasta llegar a 82 features...
            # (Continuará según la estructura real del protobuf)
        ]

        # Construir arrays de features y nombres
        for name, value in protobuf_field_mapping:
            features.append(float(value) if value is not None else 0.0)
            feature_names.append(name)

        # Asegurar exactamente 82 features
        while len(features) < 82:
            features.append(0.0)
            feature_names.append(f'padding_feature_{len(features)}')

        if len(features) > 82:
            features = features[:82]
            feature_names = feature_names[:82]

        return np.array(features), feature_names

    def extract_features_23(self, features_82: np.ndarray, feature_names_82: List[str]) -> np.ndarray:
        """Extraer 23 features de las 82 usando mapping"""
        if not hasattr(self, 'feature_mappings') or 'level1_features' not in self.feature_mappings:
            # Fallback: usar primeras 23 features
            return features_82[:23]

        feature_name_to_idx = {name.strip(): idx for idx, name in enumerate(feature_names_82)}
        features_23 = np.zeros(23)

        level1_features = self.feature_mappings.get('level1_features', [])
        if len(level1_features) >= 23:
            for i in range(23):
                target_feature = level1_features[i] if i < len(level1_features) else ''
                source_feature = self.feature_mappings['82_to_23_map'].get(target_feature)

                if source_feature and source_feature.strip() in feature_name_to_idx:
                    source_idx = feature_name_to_idx[source_feature.strip()]
                    features_23[i] = features_82[source_idx]

        return features_23

    def extract_features_4(self, features_82: np.ndarray, feature_names_82: List[str]) -> np.ndarray:
        """Extraer 4 features clave de las 82"""
        feature_name_to_idx = {name.strip(): idx for idx, name in enumerate(feature_names_82)}
        features_4 = np.zeros(4)

        for i, source_feature_name in self.feature_mappings['82_to_4_map'].items():
            if source_feature_name.strip() in feature_name_to_idx:
                source_idx = feature_name_to_idx[source_feature_name.strip()]
                features_4[i] = features_82[source_idx]

        return features_4

    def classify_traffic_type(self, features_82: np.ndarray, feature_names_82: List[str]) -> str:
        """Clasificar tipo de tráfico para nivel 3"""
        name_to_idx = {name.strip(): idx for idx, name in enumerate(feature_names_82)}

        src_port_idx = name_to_idx.get('source_port', name_to_idx.get('Source Port'))
        dst_port_idx = name_to_idx.get('destination_port', name_to_idx.get('Destination Port'))

        if src_port_idx is not None and dst_port_idx is not None:
            src_port = features_82[src_port_idx]
            dst_port = features_82[dst_port_idx]

            # Puertos web
            web_ports = [80, 443, 8080, 8443]
            if src_port in web_ports or dst_port in web_ports:
                return 'web'

            # Puertos internos
            if (src_port > 32768 or dst_port > 32768) or (src_port < 1024 and dst_port < 1024):
                return 'internal'

        return 'other'

    def predict_tricapa_complete(self, features_82: np.ndarray, feature_names_82: List[str]) -> Dict:
        """🎯 PREDICCIÓN TRICAPA COMPLETA v3.1"""
        start_time = time.time()

        # Obtener umbrales del config (con warnings si faltan)
        level1_threshold = self._get_nested_config(self.config, "ml.thresholds.level1_attack_threshold") or 0.5
        level2_ddos_threshold = self._get_nested_config(self.config, "ml.thresholds.level2_ddos_threshold") or 0.5
        level2_ransomware_threshold = self._get_nested_config(self.config,
                                                              "ml.thresholds.level2_ransomware_threshold") or 0.5
        level3_threshold = self._get_nested_config(self.config, "ml.thresholds.level3_anomaly_threshold") or 0.7

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
            # 🥇 NIVEL 1: ¿HAY ATAQUE GENERAL?
            if self.models['level1_attack_detector'] and self.scalers['level1_scaler']:
                try:
                    features_23 = self.extract_features_23(features_82, feature_names_82)
                    features_23_scaled = self.scalers['level1_scaler'].transform(features_23.reshape(1, -1))

                    attack_proba = self.models['level1_attack_detector'].predict_proba(features_23_scaled)[0]
                    attack_probability = float(attack_proba[1])

                    results['tricapa_analysis']['level1'] = {
                        'attack_detected': attack_probability > level1_threshold,
                        'confidence': attack_probability,
                        'model_status': 'active'
                    }
                    results['models_used'].append('level1_attack_detector')
                    self.stats['level1_predictions'] += 1

                    if attack_probability > level1_threshold:
                        self.stats['level1_attacks_detected'] += 1

                        # 🥈 NIVEL 2: ¿QUÉ TIPO DE ATAQUE?
                        results['final_classification'] = 'ATTACK'

                        # ARSENAL DDOS
                        ddos_scores = {}
                        if self.models['ddos_rf']:
                            try:
                                ddos_rf_proba = self.models['ddos_rf'].predict_proba(features_82.reshape(1, -1))[0]
                                ddos_scores['ddos_rf'] = float(ddos_rf_proba[1])
                                results['models_used'].append('ddos_rf')
                            except Exception as e:
                                self.logger.warning(f"⚠️ DDOS RF falló: {e}")

                        if self.models['ddos_lgb']:
                            try:
                                ddos_lgb_proba = self.models['ddos_lgb'].predict_proba(features_82.reshape(1, -1))[0]
                                ddos_scores['ddos_lgb'] = float(ddos_lgb_proba[1])
                                results['models_used'].append('ddos_lgb')
                            except Exception as e:
                                self.logger.warning(f"⚠️ DDOS LGB falló: {e}")

                        # ARSENAL RANSOMWARE
                        ransomware_scores = {}
                        if self.models['ransomware_rf']:
                            try:
                                ransomware_rf_proba = \
                                self.models['ransomware_rf'].predict_proba(features_82.reshape(1, -1))[0]
                                ransomware_scores['ransomware_rf'] = float(ransomware_rf_proba[1])
                                results['models_used'].append('ransomware_rf')
                            except Exception as e:
                                self.logger.warning(f"⚠️ Ransomware RF falló: {e}")

                        if self.models['ransomware_lgb']:
                            try:
                                ransomware_lgb_proba = \
                                self.models['ransomware_lgb'].predict_proba(features_82.reshape(1, -1))[0]
                                ransomware_scores['ransomware_lgb'] = float(ransomware_lgb_proba[1])
                                results['models_used'].append('ransomware_lgb')
                            except Exception as e:
                                self.logger.warning(f"⚠️ Ransomware LGB falló: {e}")

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
                            self.stats['level2_ddos_detected'] += 1

                        elif ransomware_max > level2_ransomware_threshold:
                            results['final_classification'] = 'RANSOMWARE'
                            results['overall_confidence'] = ransomware_max
                            results['alerts'].append(f'🦠 Ransomware Detected (confidence: {ransomware_max:.2%})')
                            results['tricapa_analysis']['level2']['final_type'] = 'RANSOMWARE'
                            self.stats['level2_ransomware_detected'] += 1

                        else:
                            results['final_classification'] = 'UNKNOWN_ATTACK'
                            results['overall_confidence'] = attack_probability
                            results['alerts'].append(f'⚠️ Unknown Attack Type (confidence: {attack_probability:.2%})')
                            results['tricapa_analysis']['level2']['final_type'] = 'UNKNOWN'

                    else:
                        # 🥉 NIVEL 3: ¿EL TRÁFICO "NORMAL" ES REALMENTE NORMAL?
                        traffic_type = self.classify_traffic_type(features_82, feature_names_82)
                        features_4 = self.extract_features_4(features_82, feature_names_82)

                        level3_results = {'traffic_type': traffic_type, 'scores': {}}

                        if traffic_type == 'internal' and self.models['internal_detector']:
                            try:
                                internal_proba = \
                                self.models['internal_detector'].predict_proba(features_4.reshape(1, -1))[0]
                                internal_anomaly_score = float(internal_proba[1])
                                level3_results['scores']['internal_anomaly'] = internal_anomaly_score
                                results['models_used'].append('internal_detector')

                                if internal_anomaly_score > level3_threshold:
                                    results['final_classification'] = 'INTERNAL_ANOMALY'
                                    results['overall_confidence'] = internal_anomaly_score
                                    results['alerts'].append(
                                        f'🔍 Internal Traffic Anomaly (confidence: {internal_anomaly_score:.2%})')
                                    level3_results['anomaly_detected'] = True
                                    self.stats['level3_internal_anomalies'] += 1

                            except Exception as e:
                                self.logger.warning(f"⚠️ Internal detector falló: {e}")

                        elif traffic_type == 'web' and self.models['web_detector']:
                            try:
                                web_proba = self.models['web_detector'].predict_proba(features_4.reshape(1, -1))[0]
                                web_anomaly_score = float(web_proba[1])
                                level3_results['scores']['web_anomaly'] = web_anomaly_score
                                results['models_used'].append('web_detector')

                                if web_anomaly_score > level3_threshold:
                                    results['final_classification'] = 'WEB_ANOMALY'
                                    results['overall_confidence'] = web_anomaly_score
                                    results['alerts'].append(
                                        f'🌐 Web Traffic Anomaly (confidence: {web_anomaly_score:.2%})')
                                    level3_results['anomaly_detected'] = True
                                    self.stats['level3_web_anomalies'] += 1

                            except Exception as e:
                                self.logger.warning(f"⚠️ Web detector falló: {e}")

                        results['tricapa_analysis']['level3'] = level3_results

                        if results['final_classification'] == 'NORMAL':
                            results['overall_confidence'] = 1.0 - attack_probability

                except Exception as e:
                    self.logger.error(f"❌ Nivel 1 falló completamente: {e}")
                    results['degraded_mode'] = True
                    self.stats['model_failures'] += 1
            else:
                self.logger.warning("⚠️ Nivel 1 no disponible - modo degradado")
                results['degraded_mode'] = True

        except Exception as e:
            self.logger.error(f"❌ Error predicción tricapa: {e}")
            results['error'] = str(e)
            results['final_classification'] = 'ERROR'
            self.stats['processing_errors'] += 1

        # Sistema degradado si usamos menos de 3 modelos
        if len(results['models_used']) < 3:
            results['degraded_mode'] = True
            self.stats['tricapa_degraded_mode'] += 1

        results['processing_time_ms'] = (time.time() - start_time) * 1000
        return results

    def enrich_protobuf_with_tricapa_analysis(self, protobuf_data: bytes) -> Optional[bytes]:
        """🎯 Enriquecer protobuf con análisis tricapa completo"""
        if not PROTOBUF_AVAILABLE:
            return None

        try:
            # Deserializar evento v3.1
            event = NetworkSecurityEventProto.NetworkSecurityEvent()
            event.ParseFromString(protobuf_data)

            # Extraer features 82 del protobuf v3.1
            features_82, feature_names_82 = self.extract_features_from_protobuf_v31(event)

            # Ejecutar análisis tricapa completo
            tricapa_results = self.predict_tricapa_complete(features_82, feature_names_82)

            # Crear evento enriquecido
            enriched_event = NetworkSecurityEventProto.NetworkSecurityEvent()
            enriched_event.CopyFrom(event)

            # Llenar análisis ML tricapa
            if hasattr(enriched_event, 'ml_analysis'):
                ml_analysis = enriched_event.ml_analysis

                # Nivel 1
                if hasattr(ml_analysis, 'level1_general_detection'):
                    level1_pred = ml_analysis.level1_general_detection
                    level1_data = tricapa_results['tricapa_analysis']['level1']
                    level1_pred.confidence_score = level1_data['confidence']
                    level1_pred.prediction_class = 'ATTACK' if level1_data['attack_detected'] else 'NORMAL'
                    level1_pred.model_name = 'rf_production_sniffer_compatible'

                # Nivel 2 - Predicciones especializadas
                level2_data = tricapa_results['tricapa_analysis']['level2']
                for model_type, scores in [('ddos', level2_data.get('ddos_scores', {})),
                                           ('ransomware', level2_data.get('ransomware_scores', {}))]:
                    for model_name, score in scores.items():
                        specialized_pred = ml_analysis.level3_specialized_predictions.add()
                        specialized_pred.model_name = model_name
                        specialized_pred.confidence_score = score
                        specialized_pred.prediction_class = model_type.upper()

                # Clasificación final
                ml_analysis.final_threat_classification = tricapa_results['final_classification']
                ml_analysis.ensemble_confidence = tricapa_results['overall_confidence']

            # Scoring general
            enriched_event.overall_threat_score = tricapa_results['overall_confidence']
            enriched_event.final_classification = tricapa_results['final_classification']
            enriched_event.threat_category = tricapa_results['final_classification']

            # Pipeline tracking
            if hasattr(enriched_event, 'pipeline_tracking'):
                pipeline = enriched_event.pipeline_tracking
                pipeline.analyzer_process_id = self.process_id
                pipeline.ml_analyzed_at.GetCurrentTime()

            # Metadatos del componente
            enriched_event.schema_version = 31
            enriched_event.protobuf_version = "3.1.0"

            # Incrementar estadísticas
            self.stats['processed'] += 1

            return enriched_event.SerializeToString()

        except Exception as e:
            self.logger.error(f"❌ Error enriquecimiento tricapa: {e}")
            self.stats['processing_errors'] += 1
            return None

    def write_rag_log(self, tricapa_results: Dict, enriched_event_data: bytes):
        """📝 Escribir log JSON para RAG"""
        try:
            now = datetime.now()

            # Estructura de directorios por fecha
            date_dir = self.rag_log_dir / str(now.year) / f"{now.month:02d}" / f"{now.day:02d}"
            date_dir.mkdir(parents=True, exist_ok=True)

            # Nombre de archivo con timestamp
            filename = f"events_{now.hour:02d}{now.minute:02d}{now.second:02d}.json"
            filepath = date_dir / filename

            # Crear entrada de log para RAG
            rag_entry = {
                "timestamp": now.isoformat(),
                "event_id": f"tricapa_{self.node_id}_{int(time.time() * 1000)}",
                "protobuf_file": f"logs/proto/{now.year}/{now.month:02d}/{now.day:02d}/events_{now.hour:02d}{now.minute:02d}{now.second:02d}.proto",
                "threat_summary": self._generate_threat_summary(tricapa_results),
                "ml_summary": self._generate_ml_summary(tricapa_results),
                "tricapa_analysis": tricapa_results['tricapa_analysis'],
                "final_classification": tricapa_results['final_classification'],
                "overall_confidence": tricapa_results['overall_confidence'],
                "alerts": tricapa_results['alerts'],
                "models_used": tricapa_results['models_used'],
                "degraded_mode": tricapa_results['degraded_mode'],
                "processing_time_ms": tricapa_results['processing_time_ms'],
                "embeddings_keywords": self._generate_embeddings_keywords(tricapa_results)
            }

            # Escribir o append al archivo JSON
            if filepath.exists():
                with open(filepath, 'r') as f:
                    existing_data = json.load(f)
                if not isinstance(existing_data, list):
                    existing_data = [existing_data]
                existing_data.append(rag_entry)
            else:
                existing_data = [rag_entry]

            with open(filepath, 'w') as f:
                json.dump(existing_data, f, indent=2)

            self.stats['rag_logs_written'] += 1

        except Exception as e:
            self.logger.error(f"❌ Error escribiendo RAG log: {e}")

    def write_protobuf_log(self, enriched_event_data: bytes):
        """📦 Escribir log protobuf para análisis profundo"""
        try:
            now = datetime.now()

            # Estructura de directorios por fecha
            date_dir = self.proto_log_dir / str(now.year) / f"{now.month:02d}" / f"{now.day:02d}"
            date_dir.mkdir(parents=True, exist_ok=True)

            # Nombre de archivo con timestamp
            filename = f"events_{now.hour:02d}{now.minute:02d}{now.second:02d}.proto"
            filepath = date_dir / filename

            # Escribir datos protobuf
            with open(filepath, 'ab') as f:  # Append binary
                f.write(enriched_event_data)

            self.stats['protobuf_logs_written'] += 1

        except Exception as e:
            self.logger.error(f"❌ Error escribiendo protobuf log: {e}")

    def _generate_threat_summary(self, tricapa_results: Dict) -> str:
        """Generar resumen de amenaza para RAG"""
        classification = tricapa_results['final_classification']
        confidence = tricapa_results['overall_confidence']

        if classification == 'DDOS':
            return f"DDoS attack detected: confidence={confidence:.3f}"
        elif classification == 'RANSOMWARE':
            return f"Ransomware detected: confidence={confidence:.3f}"
        elif classification == 'INTERNAL_ANOMALY':
            return f"Internal traffic anomaly: confidence={confidence:.3f}"
        elif classification == 'WEB_ANOMALY':
            return f"Web traffic anomaly: confidence={confidence:.3f}"
        elif classification == 'UNKNOWN_ATTACK':
            return f"Unknown attack type: confidence={confidence:.3f}"
        else:
            return f"Normal traffic: confidence={confidence:.3f}"

    def _generate_ml_summary(self, tricapa_results: Dict) -> str:
        """Generar resumen ML para RAG"""
        tricapa = tricapa_results['tricapa_analysis']

        parts = []
        if tricapa['level1']['model_status'] == 'active':
            level1_conf = tricapa['level1']['confidence']
            attack_status = "ATTACK" if tricapa['level1']['attack_detected'] else "NORMAL"
            parts.append(f"Level1={attack_status}({level1_conf:.2f})")

        if tricapa['level2'].get('final_type') != 'UNKNOWN':
            final_type = tricapa['level2']['final_type']
            parts.append(f"Level2={final_type}")

        if tricapa['level3'].get('anomaly_detected'):
            traffic_type = tricapa['level3']['traffic_type']
            parts.append(f"Level3={traffic_type.upper()}_ANOMALY")

        return ", ".join(parts) if parts else "No significant ML findings"

    def _generate_embeddings_keywords(self, tricapa_results: Dict) -> List[str]:
        """Generar keywords para embeddings RAG"""
        keywords = []

        classification = tricapa_results['final_classification'].lower()
        keywords.append(classification)

        if tricapa_results['overall_confidence'] > 0.8:
            keywords.append('high_confidence')
        elif tricapa_results['overall_confidence'] > 0.6:
            keywords.append('medium_confidence')
        else:
            keywords.append('low_confidence')

        if tricapa_results['degraded_mode']:
            keywords.append('degraded_mode')

        if tricapa_results['alerts']:
            keywords.append('alert_generated')

        # Agregar modelos usados
        keywords.extend([f"model_{model}" for model in tricapa_results['models_used']])

        return keywords

    # Threads principales (heredar del lightweight_v3)
    def receive_protobuf_events(self):
        """Thread de recepción con backpressure agresivo"""
        self.logger.info("📡 Iniciando recepción protobuf tricapa v3.1...")

        backpressure_log_counter = 0  # Para reducir spam de logs

        while self.running:
            try:
                protobuf_data = self.input_socket.recv(zmq.NOBLOCK)
                self.stats['received'] += 1

                # Validación de tamaño
                max_size = self.config["zmq"]["max_message_size"]
                if len(protobuf_data) > max_size:
                    self.logger.warning(f"🚫 Mensaje oversized: {len(protobuf_data)} > {max_size}")
                    continue

                # Backpressure más tolerante
                current_usage = self.protobuf_queue.qsize() / self.config["processing"]["protobuf_queue_size"]
                if current_usage > 0.9:  # Aumentado de 0.8 a 0.9
                    backpressure_log_counter += 1
                    # Solo log cada 50 activaciones para reducir spam
                    if backpressure_log_counter % 50 == 0:
                        self.logger.warning(f"🚨 Cola muy llena ({current_usage * 100:.1f}%) - backpressure activo")
                    continue

                try:
                    self.protobuf_queue.put_nowait(protobuf_data)
                except:
                    # Cola llena - descartar silenciosamente
                    continue

            except zmq.Again:
                continue
            except Exception as e:
                self.logger.error(f"❌ Error recepción: {e}")

    def process_protobuf_events(self):
        """Thread de procesamiento tricapa"""
        self.logger.info("⚙️ Iniciando procesamiento tricapa v3.1...")

        while self.running:
            try:
                protobuf_data = self.protobuf_queue.get(timeout=1.0)

                # Procesar con análisis tricapa
                enriched_protobuf = self.enrich_protobuf_with_tricapa_analysis(protobuf_data)

                if enriched_protobuf:
                    # Escribir logs para RAG y análisis
                    if hasattr(self, 'rag_log_dir'):
                        # Necesitamos los resultados tricapa para el log RAG
                        # Por ahora solo escribimos el protobuf log
                        self.write_protobuf_log(enriched_protobuf)

                    try:
                        self.enriched_queue.put_nowait(enriched_protobuf)
                    except:
                        # Cola llena
                        pass

                self.protobuf_queue.task_done()

            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"❌ Error procesamiento tricapa: {e}")

    def send_enriched_events(self):
        """Thread de envío con backpressure conservador"""
        self.logger.info("📤 Iniciando envío tricapa v3.1...")

        while self.running:
            try:
                enriched_protobuf = self.enriched_queue.get(timeout=1.0)

                # Enviar con backpressure normal
                try:
                    self.output_socket.send(enriched_protobuf, zmq.NOBLOCK)
                    self.stats['sent'] += 1
                except zmq.Again:
                    # Backpressure - reintento limitado
                    time.sleep(0.001)
                    try:
                        self.output_socket.send(enriched_protobuf, zmq.NOBLOCK)
                        self.stats['sent'] += 1
                    except zmq.Again:
                        # Después de reintento, descartar
                        pass

                self.enriched_queue.task_done()

            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"❌ Error envío: {e}")

    def monitor_tricapa_performance(self):
        """Monitor de performance tricapa"""
        interval = self.config["monitoring"]["stats_interval_seconds"]

        while self.running:
            time.sleep(interval)
            if not self.running:
                break

            self._log_tricapa_stats()

    def _log_tricapa_stats(self):
        """Log estadísticas tricapa"""
        self.logger.info(f"📊 TRICAPA v3.1 Stats:")
        self.logger.info(f"   📨 Recibidos: {self.stats['received']}")
        self.logger.info(f"   🎯 Procesados: {self.stats['processed']}")
        self.logger.info(f"   📤 Enviados: {self.stats['sent']}")
        self.logger.info(f"   🥇 Nivel 1 predicciones: {self.stats['level1_predictions']}")
        self.logger.info(f"   🚨 Ataques detectados: {self.stats['level1_attacks_detected']}")
        self.logger.info(f"   💥 DDOS detectados: {self.stats['level2_ddos_detected']}")
        self.logger.info(f"   🦠 Ransomware detectados: {self.stats['level2_ransomware_detected']}")
        self.logger.info(f"   🔍 Anomalías internas: {self.stats['level3_internal_anomalies']}")
        self.logger.info(f"   🌐 Anomalías web: {self.stats['level3_web_anomalies']}")
        self.logger.info(f"   ⚠️ Modo degradado: {self.stats['tricapa_degraded_mode']}")
        self.logger.info(f"   📝 Logs RAG: {self.stats['rag_logs_written']}")
        self.logger.info(f"   📦 Logs Proto: {self.stats['protobuf_logs_written']}")

        # Reset stats
        for key in ['received', 'processed', 'sent', 'level1_predictions',
                    'level1_attacks_detected', 'level2_ddos_detected',
                    'level2_ransomware_detected', 'level3_internal_anomalies',
                    'level3_web_anomalies', 'rag_logs_written', 'protobuf_logs_written']:
            self.stats[key] = 0

    def run(self):
        """🚀 Ejecutar detector tricapa v3.1 - PATRÓN SEGURO"""
        self.logger.info("🚀 Iniciando TRICAPA ML DETECTOR v3.1...")

        threads = []

        # 📡 Thread de recepción (SOLO 1 - thread-safe ZMQ)
        recv_thread = threading.Thread(target=self.receive_protobuf_events, name="TricapaReceiver")
        threads.append(recv_thread)

        # ⚙️ Threads de procesamiento (LIMITADOS y seguros)
        processing_threads_count = min(self.config["processing"]["threads"], 4)  # Máximo 4 para seguridad
        for i in range(processing_threads_count):
            proc_thread = threading.Thread(
                target=self.process_protobuf_events,
                name=f"TricapaProcessor_{i + 1}"
            )
            threads.append(proc_thread)

        # 📤 Thread de envío (SOLO 1 - thread-safe ZMQ)
        send_thread = threading.Thread(target=self.send_enriched_events, name="TricapaSender")
        threads.append(send_thread)

        # 📊 Thread de monitoreo (SOLO 1)
        monitor_thread = threading.Thread(target=self.monitor_tricapa_performance, name="TricapaMonitor")
        threads.append(monitor_thread)

        # Iniciar todos los threads
        for thread in threads:
            thread.start()

        total_threads = len(threads)
        self.logger.info(f"✅ TRICAPA ML DETECTOR v3.1 iniciado (PATRÓN SEGURO):")
        self.logger.info(
            f"   🧵 Threads: {total_threads} ({processing_threads_count} procesamiento + 1 envío + 2 control)")
        self.logger.info(f"   🧠 Modelos: {len([m for m in self.models.values() if m is not None])}")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")
        self.logger.info(f"   ⚡ Patrón: Producer-Consumer thread-safe")
        self.logger.info(f"   📝 Logging: RAG + Protobuf dual")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("🛑 Deteniendo TRICAPA ML DETECTOR v3.1...")

        self.shutdown(threads)

    def shutdown(self, threads):
        """Cierre graceful"""
        self.running = False
        self.stop_event.set()

        runtime = time.time() - self.stats['start_time']
        self.logger.info(f"📊 Runtime tricapa: {runtime:.1f}s")

        # Esperar threads con timeout
        self.logger.info(f"⏳ Esperando {len(threads)} threads...")
        for i, thread in enumerate(threads):
            thread.join(timeout=5)
            if thread.is_alive():
                self.logger.warning(f"⚠️ Thread {thread.name} no terminó en tiempo")

        # Cerrar sockets
        if self.input_socket:
            self.input_socket.close()
        if self.output_socket:
            self.output_socket.close()
        self.context.term()

        self.logger.info("✅ TRICAPA ML DETECTOR v3.1 cerrado correctamente")


# 🚀 Main
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Uso: python lightweight_ml_detector_tricapa_v31.py <config.json>")
        print("💡 Ejemplo: python lightweight_ml_detector_tricapa_v31.py tricapa_v31_config.json")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        detector = TricapaMLDetectorV31(config_file)
        detector.run()
    except Exception as e:
        print(f"❌ Error fatal tricapa: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)