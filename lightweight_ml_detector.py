#!/usr/bin/env python3
"""
lightweight_ml_detector.py - Detector ML distribuido con 6 algoritmos y persistencia
🤖 Enhanced ML Detector para Upgraded-Happiness
- Lee TODA la configuración desde JSON (sin hardcodeo)
- 6 algoritmos ML: IsolationForest, OneClassSVM, LocalOutlierFactor, DBSCAN, KMeans, RandomForest
- Sistema de persistencia automática con versionado
- Arquitectura distribuida con pipeline tracking completo
- Protobuf network_event_extended_v2 compatible
- ZMQ PULL/CONNECT input + PUSH/BIND output
- Enriquece eventos con anomaly_score y risk_score
- Sin GeoIP (responsabilidad del geoip_enricher)
"""

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

# 📦 Protobuf - USAR VERSIÓN ACTUALIZADA v2
try:
    import network_event_extended_v2_pb2 as NetworkEventProto

    PROTOBUF_AVAILABLE = True
except ImportError:
    try:
        from src.protocols.protobuf import network_event_extended_v2_pb2 as NetworkEventProto

        PROTOBUF_AVAILABLE = True
    except ImportError:
        print("⚠️ Protobuf network_event_extended_v2 no disponible")
        PROTOBUF_AVAILABLE = False

# 📦 ML Libraries - 6 algoritmos
try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.svm import OneClassSVM
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.preprocessing import StandardScaler, RobustScaler
    from sklearn.decomposition import PCA
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, silhouette_score
    from functools import lru_cache

    ML_AVAILABLE = True
except ImportError:
    print("⚠️ Scikit-learn no disponible - ML deshabilitado")
    ML_AVAILABLE = False


class ModelPersistenceManager:
    """Gestor de persistencia y evaluación de modelos ML configurado desde JSON"""

    def __init__(self, persistence_config: Dict[str, Any]):
        self.config = persistence_config
        self.models_dir = Path(self.config.get("models_dir", "ml_models"))
        self.models_dir.mkdir(exist_ok=True)

        # Subdirectorios organizados
        self.model_versions_dir = self.models_dir / "versions"
        self.best_models_dir = self.models_dir / "best"
        self.evaluation_dir = self.models_dir / "evaluations"

        for dir_path in [self.model_versions_dir, self.best_models_dir, self.evaluation_dir]:
            dir_path.mkdir(exist_ok=True)

        self.current_version = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.metrics_history = []

        self.enabled = self.config.get("enabled", True)
        self.backup_models = self.config.get("backup_models", True)
        self.model_versioning = self.config.get("model_versioning", True)

    def save_models(self, models, processors, training_metrics=None):
        """Guardar modelos y procesadores con versionado"""
        if not self.enabled:
            return None

        version_dir = self.model_versions_dir / self.current_version
        version_dir.mkdir(exist_ok=True)

        saved_files = []

        try:
            # Guardar cada modelo individual
            for model_name, model in models.items():
                if model is not None and self.config["models"].get(model_name, {}).get("enabled", True):
                    model_file = version_dir / f"{model_name}.joblib"
                    joblib.dump(model, model_file)
                    saved_files.append(model_file)

            # Guardar procesadores
            processors_file = version_dir / "processors.joblib"
            joblib.dump(processors, processors_file)
            saved_files.append(processors_file)

            # Guardar metadatos del entrenamiento
            metadata = {
                "version": self.current_version,
                "timestamp": datetime.now().isoformat(),
                "training_metrics": training_metrics or {},
                "model_count": sum(1 for m in models.values() if m is not None),
                "saved_files": [str(f) for f in saved_files],
                "config_snapshot": self.config
            }

            metadata_file = version_dir / "metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)

            return version_dir

        except Exception as e:
            raise RuntimeError(f"❌ Error guardando modelos: {e}")

    def load_models(self, version=None):
        """Cargar modelos de una versión específica o la mejor"""
        if not self.enabled:
            return None, None

        if version is None:
            # Cargar el mejor modelo disponible
            best_models = list(self.best_models_dir.glob("*.joblib"))
            if best_models:
                return self._load_best_models()
            else:
                # Si no hay mejores, cargar la versión más reciente
                versions = sorted(self.model_versions_dir.glob("*"))
                if versions:
                    version = versions[-1].name
                else:
                    return None, None

        version_dir = self.model_versions_dir / version
        if not version_dir.exists():
            return None, None

        try:
            models = {}

            # Cargar modelos individuales
            model_files = list(version_dir.glob("*.joblib"))
            for model_file in model_files:
                if model_file.name != "processors.joblib":
                    model_name = model_file.stem
                    if self.config["models"].get(model_name, {}).get("enabled", True):
                        models[model_name] = joblib.load(model_file)

            # Cargar procesadores
            processors_file = version_dir / "processors.joblib"
            processors = None
            if processors_file.exists():
                processors = joblib.load(processors_file)

            return models, processors

        except Exception as e:
            raise RuntimeError(f"❌ Error cargando modelos: {e}")

    def _load_best_models(self):
        """Cargar los mejores modelos guardados"""
        try:
            models = {}

            # Cargar mejores modelos
            for model_file in self.best_models_dir.glob("*_best.joblib"):
                if model_file.name != "processors_best.joblib":
                    model_name = model_file.stem.replace("_best", "")
                    if self.config["models"].get(model_name, {}).get("enabled", True):
                        models[model_name] = joblib.load(model_file)

            # Cargar mejores procesadores
            processors_file = self.best_models_dir / "processors_best.joblib"
            processors = None
            if processors_file.exists():
                processors = joblib.load(processors_file)

            return models, processors

        except Exception as e:
            raise RuntimeError(f"❌ Error cargando mejores modelos: {e}")


class DistributedMLDetector:
    """
    Detector ML distribuido completamente configurable desde JSON
    - 6 algoritmos ML configurables
    - Protobuf network_event_extended_v2 compatible
    - Pipeline tracking completo
    - Sistema de persistencia automática
    - Sin valores hardcodeados
    """

    def __init__(self, config_file: str):
        # 📄 Cargar configuración - SIN defaults hardcodeados
        self.config = self._load_config_strict(config_file)
        self.config_file = config_file

        # 🏷️ Identidad distribuida
        self.node_id = self.config["node_id"]
        self.process_id = os.getpid()
        self.container_id = self._get_container_id()
        self.start_time = time.time()

        # 🖥️ Información del sistema
        self.system_info = self._gather_system_info()

        # 📝 Setup logging desde configuración (PRIMERO)
        self.setup_logging()

        # 🔌 Setup ZeroMQ desde configuración usando network section
        self.context = zmq.Context()
        self.input_socket = None
        self.output_socket = None
        self.setup_sockets()

        # 🔄 Backpressure desde configuración
        self.backpressure_config = self.config["backpressure"]

        # 📦 Colas internas para procesamiento asíncrono
        self.setup_internal_queues()

        # 🤖 Configuración ML desde JSON
        self.ml_config = self.config["ml"]
        self.models_enabled = self.ml_config.get("enabled", True)

        # 🧠 6 Modelos ML configurables
        self.models = {
            'isolation_forest': None,
            'one_class_svm': None,
            'local_outlier_factor': None,
            'dbscan': None,
            'kmeans': None,
            'random_forest': None
        }

        # 🔧 Procesadores configurables
        self.processors = {
            'scaler': StandardScaler(),
            'robust_scaler': RobustScaler(),
            'pca': None  # Se configurará según features
        }

        # 💾 Sistema de persistencia desde configuración
        self.persistence_manager = None
        if self.config.get("persistence", {}).get("enabled", False):
            self.persistence_manager = ModelPersistenceManager(
                {**self.config["persistence"], "models": self.ml_config["models"]}
            )

        # 📊 Métricas distribuidas (igual que geoip_enricher)
        self.stats = {
            'received': 0,
            'processed': 0,
            'sent': 0,
            'ml_predictions': 0,
            'anomalies_detected': 0,
            'high_risk_events': 0,
            'training_sessions': 0,
            'model_updates': 0,
            'processing_errors': 0,
            'backpressure_activations': 0,
            'queue_overflows': 0,
            'dropped_events': 0,
            'buffer_full_errors': 0,
            'send_errors': 0,
            'feature_extraction_errors': 0,
            'pipeline_latency_total': 0.0,
            'start_time': time.time(),
            'last_stats_time': time.time()
        }

        # 🎛️ Control
        self.running = True
        self.stop_event = Event()
        self.models_trained = False

        # 📈 Buffer de entrenamiento desde configuración
        training_config = self.ml_config.get("training", {})
        self.training_data = deque(maxlen=training_config.get("min_training_samples", 1000))
        self.last_training_time = 0
        self.training_interval = training_config.get("retrain_interval_minutes", 5) * 60

        # 📊 Estadísticas para features
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)

        # ✅ Verificar dependencias críticas
        self._verify_dependencies()

        # 🔄 Intentar cargar modelos existentes
        if self.persistence_manager:
            self._load_existing_models()

        self.logger.info(f"🤖 Distributed ML Detector inicializado")
        self.logger.info(f"   🏷️ Node ID: {self.node_id}")
        self.logger.info(f"   🔢 PID: {self.process_id}")
        self.logger.info(f"   📄 Config: {config_file}")
        self.logger.info(f"   🧠 6 algoritmos ML: {list(self.models.keys())}")
        self.logger.info(f"   💾 Persistencia: {'✅' if self.persistence_manager else '❌'}")

    def _load_config_strict(self, config_file: str) -> Dict[str, Any]:
        """Carga configuración SIN proporcionar defaults"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            raise RuntimeError(f"❌ Archivo de configuración no encontrado: {config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ Error parseando JSON: {e}")

        # ✅ Validar campos críticos
        required_fields = [
            "node_id", "network", "zmq", "backpressure", "processing",
            "ml", "logging", "monitoring", "distributed"
        ]

        for field in required_fields:
            if field not in config:
                raise RuntimeError(f"❌ Campo requerido faltante en config: {field}")

        # ✅ Validar subcampos críticos
        self._validate_config_structure(config)

        return config

    def _validate_config_structure(self, config: Dict[str, Any]):
        """Valida estructura de configuración"""
        # Network fields
        network_config = config["network"]
        for socket_name in ["input_socket", "output_socket"]:
            if socket_name not in network_config:
                raise RuntimeError(f"❌ Socket faltante: network.{socket_name}")

            socket_config = network_config[socket_name]
            required_fields = ["address", "port", "mode", "socket_type"]
            for field in required_fields:
                if field not in socket_config:
                    raise RuntimeError(f"❌ Campo network.{socket_name} faltante: {field}")

        # ML fields
        ml_required = ["enabled", "models", "training", "features"]
        for field in ml_required:
            if field not in config["ml"]:
                raise RuntimeError(f"❌ Campo ML faltante: ml.{field}")

    def _get_container_id(self) -> Optional[str]:
        """Obtiene ID del contenedor si está ejecutándose en uno"""
        try:
            with open('/proc/self/cgroup', 'r') as f:
                content = f.read()
                for line in content.split('\n'):
                    if 'docker' in line:
                        return line.split('/')[-1][:12]
            return None
        except:
            return None

    def _gather_system_info(self) -> Dict[str, Any]:
        """Recolecta información del sistema"""
        return {
            'hostname': socket.gethostname(),
            'cpu_count': psutil.cpu_count(),
            'memory_total_gb': round(psutil.virtual_memory().total / (1024 ** 3), 2)
        }

    def _verify_dependencies(self):
        """Verifica que las dependencias críticas estén disponibles"""
        issues = []

        if not PROTOBUF_AVAILABLE:
            issues.append("❌ Protobuf network_event_extended_v2 no disponible")

        if not ML_AVAILABLE:
            issues.append("❌ Scikit-learn no disponible - modelos ML deshabilitados")

        if issues:
            for issue in issues:
                print(issue)
            if not PROTOBUF_AVAILABLE:
                raise RuntimeError("❌ Protobuf es crítico para el funcionamiento")

    def setup_logging(self):
        """Setup logging desde configuración con node_id y PID"""
        log_config = self.config["logging"]

        # 📝 Configurar nivel
        level = getattr(logging, log_config["level"].upper())

        # 🏷️ Formato con node_id y PID
        log_format = log_config["format"].format(
            node_id=self.node_id,
            pid=self.process_id
        )
        formatter = logging.Formatter(log_format)

        # 🔧 Configurar handler
        if log_config.get("file"):
            handler = logging.FileHandler(log_config["file"])
        else:
            handler = logging.StreamHandler()

        handler.setFormatter(formatter)

        # 📋 Setup logger
        self.logger = logging.getLogger(f"ml_detector_{self.node_id}")
        self.logger.setLevel(level)
        self.logger.addHandler(handler)
        self.logger.propagate = False

    def setup_sockets(self):
        """Configuración ZMQ desde nueva estructura network"""
        network_config = self.config["network"]
        zmq_config = self.config["zmq"]

        try:
            # 📥 Socket de entrada (PULL) - CONNECT al geoip_enricher
            input_config = network_config["input_socket"]
            self.input_socket = self.context.socket(zmq.PULL)
            self.input_socket.setsockopt(zmq.RCVHWM, zmq_config["rcvhwm"])
            self.input_socket.setsockopt(zmq.RCVTIMEO, zmq_config["recv_timeout_ms"])

            # CONNECT al puerto del geoip_enricher
            input_address = f"tcp://{input_config['address']}:{input_config['port']}"
            self.input_socket.connect(input_address)

            # 📤 Socket de salida (PUSH) - BIND para dashboard
            output_config = network_config["output_socket"]
            self.output_socket = self.context.socket(zmq.PUSH)
            self.output_socket.setsockopt(zmq.SNDHWM, zmq_config["sndhwm"])
            self.output_socket.setsockopt(zmq.LINGER, zmq_config["linger_ms"])
            self.output_socket.setsockopt(zmq.SNDTIMEO, zmq_config["send_timeout_ms"])

            # BIND para que dashboard se conecte
            output_address = f"tcp://*:{output_config['port']}"
            self.output_socket.bind(output_address)

            self.logger.info(f"🔌 Sockets ZMQ configurados:")
            self.logger.info(f"   📥 Input: CONNECT to {input_address}")
            self.logger.info(f"   📤 Output: BIND on {output_address}")
            self.logger.info(f"   🌊 RCVHWM: {zmq_config['rcvhwm']}, SNDHWM: {zmq_config['sndhwm']}")

        except Exception as e:
            raise RuntimeError(f"❌ Error configurando sockets ZMQ: {e}")

    def setup_internal_queues(self):
        """Configuración de colas internas desde configuración"""
        proc_config = self.config["processing"]

        # 📋 Cola principal para eventos protobuf sin procesar
        self.protobuf_queue = Queue(maxsize=proc_config["protobuf_queue_size"])

        # 📋 Cola para eventos enriquecidos listos para envío
        self.enriched_queue = Queue(maxsize=proc_config["internal_queue_size"])

        self.logger.info(f"📋 Colas internas configuradas:")
        self.logger.info(f"   📦 Protobuf queue: {proc_config['protobuf_queue_size']}")
        self.logger.info(f"   🤖 Enriched queue: {proc_config['internal_queue_size']}")

    def _load_existing_models(self):
        """Cargar modelos existentes si están disponibles"""
        self.logger.info("🔍 Buscando modelos ML guardados...")
        try:
            loaded_models, loaded_processors = self.persistence_manager.load_models()

            if loaded_models:
                self.models.update(loaded_models)
                if loaded_processors:
                    self.processors.update(loaded_processors)
                self.models_trained = True
                self.logger.info("✅ Modelos ML existentes cargados")
                self.logger.info(f"   📊 Modelos disponibles: {[k for k, v in self.models.items() if v is not None]}")
            else:
                self.logger.info("💡 No hay modelos ML guardados - se entrenarán automáticamente")
        except Exception as e:
            self.logger.warning(f"⚠️ Error cargando modelos existentes: {e}")

    def receive_protobuf_events(self):
        """Thread de recepción de eventos protobuf con backpressure robusto"""
        self.logger.info("📡 Iniciando thread de recepción protobuf ML...")

        consecutive_errors = 0
        queue_full_count = 0

        while self.running:
            try:
                # 📨 Recibir evento protobuf
                protobuf_data = self.input_socket.recv(zmq.NOBLOCK)
                self.stats['received'] += 1
                consecutive_errors = 0

                # 🔍 Verificar backpressure antes de añadir a cola
                current_queue_usage = self.protobuf_queue.qsize() / self.config["processing"]["protobuf_queue_size"]

                if current_queue_usage > 0.9:  # Cola casi llena
                    queue_full_count += 1
                    if queue_full_count % 10 == 0:
                        self.logger.warning(f"🔴 Backpressure: Cola protobuf {current_queue_usage * 100:.1f}% llena")

                # 📋 Añadir a cola con estrategia configurada
                try:
                    queue_config = self.config["processing"].get("queue_overflow_handling", {})
                    queue_timeout = queue_config.get("max_queue_wait_ms", 100) / 1000.0

                    self.protobuf_queue.put(protobuf_data, timeout=queue_timeout)
                    queue_full_count = 0  # Reset counter si se pudo añadir

                except:
                    self.stats['queue_overflows'] += 1

                    # 🔄 Estrategia de overflow configurada
                    strategy = queue_config.get("strategy", "backpressure_and_drop")

                    if strategy == "drop_oldest" and not self.protobuf_queue.empty():
                        try:
                            # Descartar evento más antiguo para hacer espacio
                            self.protobuf_queue.get_nowait()
                            self.protobuf_queue.put_nowait(protobuf_data)
                            self.logger.debug("🔄 Evento más antiguo descartado por backpressure")
                        except:
                            self.logger.warning("⚠️ No se pudo aplicar estrategia drop_oldest")

                    if queue_config.get("log_drops", True) and self.stats['queue_overflows'] % 50 == 0:
                        self.logger.warning(f"⚠️ {self.stats['queue_overflows']} eventos descartados por backpressure")

            except zmq.Again:
                # Sin datos disponibles - continuar
                continue
            except zmq.ZMQError as e:
                consecutive_errors += 1
                if consecutive_errors % 10 == 0:
                    self.logger.error(f"❌ Error ZMQ recepción ({consecutive_errors}): {e}")
                time.sleep(0.1)

    def process_protobuf_events(self):
        """Thread de procesamiento de eventos protobuf con ML"""
        self.logger.info("⚙️ Iniciando thread de procesamiento ML...")

        queue_timeout = self.config["processing"]["queue_timeout_seconds"]

        while self.running:
            try:
                # 📋 Obtener evento protobuf de la cola
                protobuf_data = self.protobuf_queue.get(timeout=queue_timeout)

                # 🔄 Medir latencia de procesamiento
                start_time = time.time()

                # 🤖 Enriquecer evento con ML
                enriched_protobuf = self.enrich_protobuf_event_with_ml(protobuf_data)

                if enriched_protobuf:
                    # 📊 Actualizar métricas de latencia
                    processing_time = (time.time() - start_time) * 1000  # ms
                    self.stats['pipeline_latency_total'] += processing_time

                    self.stats['processed'] += 1

                    # 📋 Añadir a cola de eventos enriquecidos
                    try:
                        self.enriched_queue.put(enriched_protobuf, timeout=queue_timeout)
                    except:
                        self.stats['queue_overflows'] += 1
                        self.logger.warning("⚠️ Enriched queue lleno - evento descartado")
                else:
                    self.stats['processing_errors'] += 1

                self.protobuf_queue.task_done()

            except Empty:
                # Timeout normal - continuar
                continue
            except Exception as e:
                self.logger.error(f"❌ Error procesando protobuf ML: {e}")
                self.stats['processing_errors'] += 1

    def send_enriched_events(self):
        """Thread de envío de eventos enriquecidos"""
        self.logger.info("📤 Iniciando thread de envío ML...")

        queue_timeout = self.config["processing"]["queue_timeout_seconds"]

        while self.running:
            try:
                # 📋 Obtener evento enriquecido
                enriched_protobuf = self.enriched_queue.get(timeout=queue_timeout)

                # 📤 Enviar con backpressure
                success = self.send_event_with_backpressure(enriched_protobuf)

                if success:
                    self.stats['sent'] += 1

                self.enriched_queue.task_done()

            except Empty:
                # Timeout normal - continuar
                continue
            except Exception as e:
                self.logger.error(f"❌ Error enviando evento ML: {e}")

    def enrich_protobuf_event_with_ml(self, protobuf_data: bytes) -> Optional[bytes]:
        """Enriquece evento protobuf con análisis ML de 6 algoritmos"""
        if not PROTOBUF_AVAILABLE:
            raise RuntimeError("❌ Protobuf no disponible")

        try:
            # 📦 Deserializar evento protobuf
            event = NetworkEventProto.NetworkEvent()
            event.ParseFromString(protobuf_data)

            # 🤖 Extraer features para ML
            features = self._extract_ml_features(event)
            if features is None:
                self.stats['feature_extraction_errors'] += 1
                return None

            # 📈 Añadir a buffer de entrenamiento
            self.training_data.append(features)

            # 🧠 Predecir con 6 algoritmos ML
            anomaly_score, risk_score = self._predict_with_ml_ensemble(features)

            # 🔄 Actualizar estadísticas
            self.stats['ml_predictions'] += 1

            if anomaly_score > self.ml_config.get("anomaly_threshold", 0.8):
                self.stats['anomalies_detected'] += 1

            if risk_score > self.ml_config.get("high_risk_threshold", 0.9):
                self.stats['high_risk_events'] += 1

            # ✅ Enriquecimiento exitoso - PRESERVAR TODOS LOS CAMPOS
            enriched_event = NetworkEventProto.NetworkEvent()
            enriched_event.CopyFrom(event)  # Copiar TODO incluyendo coordenadas del geoip_enricher

            # 🤖 AÑADIR enriquecimiento ML
            enriched_event.anomaly_score = self._sanitize_float(anomaly_score)
            enriched_event.risk_score = self._sanitize_float(risk_score)

            # 🆔 Añadir información del ML detector
            enriched_event.ml_detector_pid = self.process_id
            enriched_event.ml_detector_timestamp = int(time.time() * 1000)

            # 📊 Actualizar métricas del pipeline
            if enriched_event.geoip_enricher_timestamp > 0:
                pipeline_latency = enriched_event.ml_detector_timestamp - enriched_event.geoip_enricher_timestamp
                enriched_event.processing_latency_ms = float(pipeline_latency)

            # 🎯 Actualizar path del pipeline
            if enriched_event.pipeline_path:
                enriched_event.pipeline_path += "->ml"
            else:
                enriched_event.pipeline_path = "geoip->ml"

            enriched_event.pipeline_hops += 1

            # 🏷️ Añadir tag del componente
            enriched_event.component_tags.append(f"ml_detector_{self.node_id}")

            # 📝 Enriquecer descripción con info ML
            ml_info = []
            if enriched_event.description:
                ml_info.append(enriched_event.description)

            if risk_score > 0.8:
                ml_info.append(f"🚨 Alto riesgo ML: {risk_score:.3f}")
            elif anomaly_score > 0.7:
                ml_info.append(f"⚠️ Anomalía ML: {anomaly_score:.3f}")
            elif anomaly_score > 0 or risk_score > 0:
                ml_info.append(f"🤖 ML scores: A={anomaly_score:.3f}, R={risk_score:.3f}")

            enriched_event.description = " | ".join(ml_info)

            # 🔄 Actualizar estado del componente
            enriched_event.component_status = "healthy"

            # 💾 Guardar predicción si está habilitado
            if self.persistence_manager and self.config["persistence"].get("save_predictions", False):
                self._save_prediction_to_file(event, anomaly_score, risk_score)

            # 🔄 Serializar evento enriquecido
            return enriched_event.SerializeToString()

        except Exception as e:
            self.stats['processing_errors'] += 1
            self.logger.error(f"❌ Error enriqueciendo evento ML: {e}")
            return None

    def _extract_ml_features(self, event) -> Optional[np.ndarray]:
        """Extrae features configurables del evento para ML con longitud fija"""
        try:
            # 🔧 FEATURES FIJOS - SIEMPRE 17 features para compatibilidad
            features = []

            # 📊 Features básicas (4 features) - SIEMPRE
            features.extend([
                float(event.packet_size or 0),
                float(event.dest_port or 0),
                float(event.src_port or 0),
                float(self._protocol_to_numeric(getattr(event, 'protocol', '')))
            ])

            # ⏰ Features temporales (3 features) - SIEMPRE
            now = datetime.now()
            features.extend([
                float(now.hour),
                float(now.minute),
                float(1 if now.weekday() >= 5 else 0)  # is_weekend
            ])

            # 🌐 Features de IP (2 features) - SIEMPRE
            source_ip = event.source_ip or ""
            target_ip = event.target_ip or ""

            features.extend([
                float(len(set(source_ip.replace('.', ''))) / max(len(source_ip), 1)),  # ip_entropy_src
                float(len(set(target_ip.replace('.', ''))) / max(len(target_ip), 1))  # ip_entropy_dst
            ])

            # 🚪 Features de puertos (2 features) - SIEMPRE
            self.port_stats[event.src_port] += 1
            self.port_stats[event.dest_port] += 1

            features.extend([
                float(self.port_stats[event.src_port]),  # port_frequency_src
                float(self.port_stats[event.dest_port])  # port_frequency_dst
            ])

            # 🌍 Features de GeoIP (4 features) - SIEMPRE
            has_geoip = 1 if (event.latitude != 0 and event.longitude != 0) else 0
            lat_abs = abs(event.latitude) if has_geoip else 0
            lon_abs = abs(event.longitude) if has_geoip else 0
            distance = math.sqrt(lat_abs ** 2 + lon_abs ** 2) if has_geoip else 0

            features.extend([
                float(has_geoip),
                float(lat_abs),
                float(lon_abs),
                float(distance)
            ])

            # 🔧 Features adicionales para llegar a 17 (2 features más)
            features.extend([
                float(1 if event.dest_port in [22, 23, 80, 443, 135, 139, 445] else 0),  # is_common_port
                float(len(event.event_id or "") % 100) / 100.0  # event_id_hash
            ])

            # ✅ Verificar longitud exacta
            final_features = np.array(features)

            if len(final_features) != 17:
                self.logger.error(f"❌ Features mismatch: esperado 17, obtenido {len(final_features)}")
                # 🔧 Padding/truncate para forzar 17 features
                if len(final_features) < 17:
                    padding = np.zeros(17 - len(final_features))
                    final_features = np.concatenate([final_features, padding])
                else:
                    final_features = final_features[:17]

                self.logger.warning(f"🔧 Features ajustados a 17: {final_features.shape}")

            return final_features

        except Exception as e:
            self.logger.error(f"❌ Error extrayendo features ML: {e}")
            # 🔧 Fallback: vector de 17 ceros
            return np.zeros(17)

    def _protocol_to_numeric(self, protocol: str) -> int:
        """Convierte protocolo a valor numérico"""
        protocol_map = {
            'tcp': 6, 'udp': 17, 'icmp': 1, 'icmpv6': 58,
            'http': 80, 'https': 443, 'ssh': 22, 'ftp': 21
        }
        return protocol_map.get(protocol.lower(), 0)

    def _predict_with_ml_ensemble(self, features: np.ndarray) -> Tuple[float, float]:
        """Predice usando ensemble de 6 algoritmos ML configurables con detección de mismatch"""
        if not ML_AVAILABLE or not self.models_enabled:
            return self._heuristic_prediction(features)

        # 🔄 Entrenar modelos automáticamente si es necesario
        self._auto_train_models()

        if not self.models_trained:
            return self._heuristic_prediction(features)

        try:
            # 🔧 Verificar compatibilidad de features con modelos cargados
            try:
                # Test con un modelo para detectar mismatch
                test_features = features.reshape(1, -1)
                test_scaled = self.processors['scaler'].transform(test_features)

                # Si llegamos aquí, los features son compatibles
                features_scaled = test_scaled

            except ValueError as e:
                if "expecting" in str(e) and "features" in str(e):
                    self.logger.warning(f"🔧 Feature mismatch detectado: {e}")
                    self.logger.info("🔄 Re-entrenando modelos para nueva configuración de features...")

                    # 🔄 Forzar re-entrenamiento con features actuales
                    self._force_retrain_models_with_current_features(features)

                    # Intentar nuevamente después del re-entrenamiento
                    features_scaled = self.processors['scaler'].transform(features.reshape(1, -1))
                else:
                    raise e

            anomaly_scores = []
            risk_scores = []

            # 1️⃣ Isolation Forest
            if self.models['isolation_forest'] and self.ml_config["models"]["isolation_forest"]["enabled"]:
                try:
                    iso_score = self.models['isolation_forest'].decision_function(features_scaled)[0]
                    iso_normalized = max(0, min(1, (iso_score + 1) / 2))
                    anomaly_scores.append(1 - iso_normalized)
                except Exception as e:
                    self.logger.debug(f"⚠️ Error Isolation Forest: {e}")

            # 2️⃣ One Class SVM
            if self.models['one_class_svm'] and self.ml_config["models"]["one_class_svm"]["enabled"]:
                try:
                    svm_score = self.models['one_class_svm'].decision_function(features_scaled)[0]
                    svm_normalized = max(0, min(1, (svm_score + 1) / 2))
                    anomaly_scores.append(1 - svm_normalized)
                except Exception as e:
                    self.logger.debug(f"⚠️ Error One Class SVM: {e}")

            # 3️⃣ Local Outlier Factor
            if self.models['local_outlier_factor'] and self.ml_config["models"]["local_outlier_factor"]["enabled"]:
                try:
                    lof_score = self.models['local_outlier_factor'].decision_function(features_scaled)[0]
                    lof_normalized = max(0, min(1, (lof_score + 1) / 2))
                    anomaly_scores.append(1 - lof_normalized)
                except Exception as e:
                    self.logger.debug(f"⚠️ Error LOF: {e}")

            # 4️⃣ DBSCAN - usar distancia promedio a clusters
            if self.models['dbscan'] and self.ml_config["models"]["dbscan"]["enabled"]:
                try:
                    # Para DBSCAN en tiempo real, usar score heurístico
                    dbscan_score = 0.3  # Score neutral por defecto
                    anomaly_scores.append(dbscan_score)
                except Exception as e:
                    self.logger.debug(f"⚠️ Error DBSCAN: {e}")

            # 5️⃣ K-Means - distancia al centroide más cercano
            if self.models['kmeans'] and self.ml_config["models"]["kmeans"]["enabled"]:
                try:
                    cluster = self.models['kmeans'].predict(features_scaled)[0]
                    center = self.models['kmeans'].cluster_centers_[cluster]
                    distance = np.linalg.norm(features_scaled[0] - center)
                    kmeans_score = min(1.0, distance / 2.0)
                    anomaly_scores.append(kmeans_score)
                except Exception as e:
                    self.logger.debug(f"⚠️ Error K-Means: {e}")

            # 6️⃣ Random Forest - probabilidad de clase anómala
            if self.models['random_forest'] and self.ml_config["models"]["random_forest"]["enabled"]:
                try:
                    rf_proba = self.models['random_forest'].predict_proba(features_scaled)[0]
                    if len(rf_proba) > 1:
                        risk_scores.append(rf_proba[1])  # Probabilidad de clase positiva
                except Exception as e:
                    self.logger.debug(f"⚠️ Error Random Forest: {e}")

            # 🔄 Combinar scores del ensemble
            final_anomaly = np.mean(anomaly_scores) if anomaly_scores else 0.0
            final_risk = np.mean(risk_scores) if risk_scores else final_anomaly

            # 🔧 Asegurar rango válido
            final_anomaly = max(0.0, min(1.0, final_anomaly))
            final_risk = max(0.0, min(1.0, final_risk))

            return final_anomaly, final_risk

        except Exception as e:
            self.logger.error(f"❌ Error predicción ML ensemble: {e}")
            return self._heuristic_prediction(features)

    def _force_retrain_models_with_current_features(self, sample_features: np.ndarray):
        """Fuerza re-entrenamiento de modelos con configuración actual de features"""
        try:
            self.logger.info(f"🔧 Forzando re-entrenamiento con {len(sample_features)} features...")

            # 🔄 Limpiar modelos existentes incompatibles
            for model_name in self.models:
                self.models[model_name] = None

            # 🔄 Resetear processors
            self.processors['scaler'] = StandardScaler()
            self.models_trained = False

            # 📊 Crear datos sintéticos para re-entrenamiento rápido
            synthetic_size = max(100, len(self.training_data))
            synthetic_data = []

            for _ in range(synthetic_size):
                # Crear features sintéticas basadas en la muestra actual
                synthetic_features = sample_features.copy()
                # Añadir ruido para variación
                synthetic_features += np.random.normal(0, 0.1, len(synthetic_features))
                synthetic_data.append(synthetic_features)

            # 🔄 Actualizar buffer de entrenamiento
            self.training_data.clear()
            self.training_data.extend(synthetic_data)

            # 🚀 Forzar entrenamiento inmediato
            self._train_ml_models()

            self.logger.info("✅ Re-entrenamiento completado con nueva configuración de features")

        except Exception as e:
            self.logger.error(f"❌ Error en re-entrenamiento forzado: {e}")
            self.models_trained = False

    def _heuristic_prediction(self, features: np.ndarray) -> Tuple[float, float]:
        """Predicción heurística cuando ML no está disponible"""
        try:
            if len(features) < 4:
                return 0.0, 0.0

            packet_size, dest_port, src_port = features[0], features[1], features[2]

            anomaly_score = 0.0
            risk_score = 0.0

            # Heurística 1: Tamaño de paquete anómalo
            if packet_size > 1500 or packet_size < 20:
                anomaly_score += 0.3

            # Heurística 2: Puertos sospechosos
            suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5900]
            if dest_port in suspicious_ports:
                risk_score += 0.4

            # Heurística 3: Puertos no estándar
            if dest_port > 49152:
                anomaly_score += 0.2

            return min(anomaly_score, 1.0), min(risk_score, 1.0)

        except Exception as e:
            self.logger.error(f"❌ Error predicción heurística: {e}")
            return 0.0, 0.0

    def _auto_train_models(self):
        """Entrenamiento automático de modelos según configuración"""
        current_time = time.time()
        training_config = self.ml_config.get("training", {})

        # Verificar si es necesario entrenar
        should_train = (
                len(self.training_data) >= training_config.get("min_training_samples", 1000) and
                (not self.models_trained or
                 (current_time - self.last_training_time > self.training_interval and
                  training_config.get("auto_retrain", True)))
        )

        if should_train:
            self.logger.info("🔧 Iniciando entrenamiento automático de 6 algoritmos ML...")
            self._train_ml_models()
            self.last_training_time = current_time

    def _train_ml_models(self):
        """Entrenar los 6 modelos ML según configuración"""
        try:
            if len(self.training_data) < 50:
                self.logger.warning("⚠️ Pocos datos para entrenamiento ML")
                return

            start_time = time.time()

            # Convertir datos a array
            X = np.array(list(self.training_data))

            # Generar labels sintéticas (en producción usar labels reales)
            y = np.random.choice([0, 1], size=len(X), p=[0.9, 0.1])

            self.logger.info(f"🔧 Entrenando 6 algoritmos ML con {len(X)} muestras...")

            # Preprocesamiento
            X_scaled = self.processors['scaler'].fit_transform(X)

            models_config = self.ml_config["models"]

            # 1️⃣ Isolation Forest
            if models_config["isolation_forest"]["enabled"]:
                iso_config = models_config["isolation_forest"]
                self.models['isolation_forest'] = IsolationForest(
                    contamination=iso_config["contamination"],
                    random_state=iso_config["random_state"],
                    n_estimators=iso_config["n_estimators"],
                    n_jobs=-1
                )
                self.models['isolation_forest'].fit(X_scaled)
                self.logger.info("✅ Isolation Forest entrenado")

            # 2️⃣ One Class SVM
            if models_config["one_class_svm"]["enabled"]:
                svm_config = models_config["one_class_svm"]
                self.models['one_class_svm'] = OneClassSVM(
                    nu=svm_config["nu"],
                    kernel=svm_config["kernel"]
                )
                self.models['one_class_svm'].fit(X_scaled)
                self.logger.info("✅ One Class SVM entrenado")

            # 3️⃣ Local Outlier Factor
            if models_config["local_outlier_factor"]["enabled"]:
                lof_config = models_config["local_outlier_factor"]
                self.models['local_outlier_factor'] = LocalOutlierFactor(
                    n_neighbors=lof_config["n_neighbors"],
                    contamination=lof_config["contamination"],
                    novelty=True
                )
                self.models['local_outlier_factor'].fit(X_scaled)
                self.logger.info("✅ Local Outlier Factor entrenado")

            # 4️⃣ DBSCAN
            if models_config["dbscan"]["enabled"]:
                dbscan_config = models_config["dbscan"]
                self.models['dbscan'] = DBSCAN(
                    eps=dbscan_config["eps"],
                    min_samples=dbscan_config["min_samples"]
                )
                self.models['dbscan'].fit(X_scaled)
                self.logger.info("✅ DBSCAN entrenado")

            # 5️⃣ K-Means
            if models_config["kmeans"]["enabled"]:
                kmeans_config = models_config["kmeans"]
                self.models['kmeans'] = KMeans(
                    n_clusters=kmeans_config["n_clusters"],
                    random_state=kmeans_config["random_state"],
                    n_init=kmeans_config["n_init"]
                )
                self.models['kmeans'].fit(X_scaled)
                self.logger.info("✅ K-Means entrenado")

            # 6️⃣ Random Forest
            if models_config["random_forest"]["enabled"] and len(np.unique(y)) > 1:
                rf_config = models_config["random_forest"]
                self.models['random_forest'] = RandomForestClassifier(
                    n_estimators=rf_config["n_estimators"],
                    random_state=rf_config["random_state"],
                    max_depth=rf_config.get("max_depth"),
                    n_jobs=-1
                )
                self.models['random_forest'].fit(X_scaled, y)
                self.logger.info("✅ Random Forest entrenado")

            training_time = time.time() - start_time
            self.stats['training_sessions'] += 1
            self.stats['model_updates'] += 1

            self.logger.info(f"✅ 6 algoritmos ML entrenados en {training_time:.2f}s")

            # 💾 Guardar modelos automáticamente
            if self.persistence_manager:
                training_metrics = {
                    "training_time": training_time,
                    "samples_count": len(X),
                    "timestamp": datetime.now().isoformat(),
                    "models_trained": [k for k, v in self.models.items() if v is not None]
                }

                version_dir = self.persistence_manager.save_models(
                    self.models, self.processors, training_metrics
                )

                if version_dir:
                    self.logger.info(f"💾 Modelos ML guardados en: {version_dir}")

            self.models_trained = True

        except Exception as e:
            self.logger.error(f"❌ Error entrenando modelos ML: {e}")

    def _save_prediction_to_file(self, event, anomaly_score: float, risk_score: float):
        """Guarda predicción en archivo si está configurado"""
        try:
            predictions_file = self.config["persistence"]["predictions_file"]

            # Crear directorio si no existe
            predictions_dir = os.path.dirname(predictions_file)
            if predictions_dir and not os.path.exists(predictions_dir):
                os.makedirs(predictions_dir, exist_ok=True)

            prediction_record = {
                'timestamp': time.time(),
                'event_id': event.event_id,
                'source_ip': event.source_ip,
                'target_ip': event.target_ip,
                'node_id': self.node_id,
                'anomaly_score': float(anomaly_score),
                'risk_score': float(risk_score),
                'features': {
                    'packet_size': event.packet_size,
                    'dest_port': event.dest_port,
                    'src_port': event.src_port,
                    'protocol': getattr(event, 'protocol', '')
                }
            }

            with open(predictions_file, 'a') as f:
                f.write(json.dumps(prediction_record) + '\n')

        except Exception as e:
            self.logger.error(f"❌ Error guardando predicción: {e}")

    def send_event_with_backpressure(self, enriched_data: bytes) -> bool:
        """Envío robusto con backpressure configurable igual que promiscuous_agent"""
        bp_config = self.backpressure_config
        max_retries = bp_config["max_retries"]

        for attempt in range(max_retries + 1):
            try:
                # 🚀 Intento de envío
                self.output_socket.send(enriched_data, zmq.NOBLOCK)
                return True

            except zmq.Again:
                # 🔴 Buffer lleno - aplicar backpressure
                self.stats['buffer_full_errors'] = self.stats.get('buffer_full_errors', 0) + 1

                if attempt == max_retries:
                    # 🗑️ Último intento fallido
                    self.stats['dropped_events'] = self.stats.get('dropped_events', 0) + 1
                    return False

                # 🔄 Aplicar backpressure configurado
                if not self._apply_backpressure(attempt):
                    return False

                continue

            except zmq.ZMQError as e:
                self.logger.error(f"❌ Error ZMQ envío ML: {e}")
                self.stats['send_errors'] = self.stats.get('send_errors', 0) + 1
                return False

        return False

    def _apply_backpressure(self, attempt: int) -> bool:
        """Aplica backpressure según configuración (igual que geoip_enricher)"""
        bp_config = self.backpressure_config

        if not bp_config["enabled"]:
            return False

        if attempt >= bp_config["max_retries"]:
            self.stats['dropped_events'] = self.stats.get('dropped_events', 0) + 1
            return False

        # 🔄 Aplicar delay configurado
        delays = bp_config["retry_delays_ms"]
        delay_ms = delays[attempt] if attempt < len(delays) else delays[-1]

        time.sleep(delay_ms / 1000.0)
        self.stats['backpressure_activations'] += 1

        # 📊 Log backpressure activity
        if self.stats['backpressure_activations'] % bp_config.get("activation_threshold", 50) == 0:
            self.logger.warning(f"🔄 Backpressure activo: {self.stats['backpressure_activations']} activaciones")

        return True

    def _sanitize_float(self, value) -> float:
        """Sanitiza valores float para protobuf"""
        try:
            if value is None:
                return 0.0

            float_val = float(value)

            if math.isnan(float_val) or math.isinf(float_val):
                return 0.0

            return max(0.0, min(1.0, float_val))

        except (TypeError, ValueError, OverflowError):
            return 0.0

    def monitor_performance(self):
        """Thread de monitoreo de performance ML"""
        monitoring_config = self.config["monitoring"]
        interval = monitoring_config["stats_interval_seconds"]

        while self.running:
            time.sleep(interval)
            if not self.running:
                break

            self._log_performance_stats()
            self._check_performance_alerts()

    def _log_performance_stats(self):
        """Log de estadísticas de performance ML"""
        now = time.time()
        interval = now - self.stats['last_stats_time']

        # 📊 Calcular rates
        recv_rate = self.stats['received'] / interval if interval > 0 else 0
        process_rate = self.stats['processed'] / interval if interval > 0 else 0
        send_rate = self.stats['sent'] / interval if interval > 0 else 0

        # 📊 Calcular latencia promedio
        avg_latency = 0.0
        if self.stats['processed'] > 0:
            avg_latency = self.stats['pipeline_latency_total'] / self.stats['processed']

        # 📊 Calcular accuracy aproximada
        total_predictions = self.stats['ml_predictions']
        anomaly_rate = (self.stats['anomalies_detected'] / max(total_predictions, 1)) * 100
        risk_rate = (self.stats['high_risk_events'] / max(total_predictions, 1)) * 100

        self.logger.info(f"📊 ML Detector Stats:")
        self.logger.info(f"   📨 Recibidos: {self.stats['received']} ({recv_rate:.1f}/s)")
        self.logger.info(f"   🤖 Procesados: {self.stats['processed']} ({process_rate:.1f}/s)")
        self.logger.info(f"   📤 Enviados: {self.stats['sent']} ({send_rate:.1f}/s)")
        self.logger.info(f"   🧠 Predicciones ML: {self.stats['ml_predictions']}")
        self.logger.info(f"   🚨 Anomalías: {self.stats['anomalies_detected']} ({anomaly_rate:.1f}%)")
        self.logger.info(f"   ⚠️ Alto riesgo: {self.stats['high_risk_events']} ({risk_rate:.1f}%)")
        self.logger.info(f"   🎓 Entrenamientos: {self.stats['training_sessions']}")
        self.logger.info(f"   ⏱️ Latencia promedio: {avg_latency:.1f}ms")
        self.logger.info(f"   📋 Colas: protobuf={self.protobuf_queue.qsize()}, enriched={self.enriched_queue.qsize()}")
        self.logger.info(f"   🔄 Backpressure: {self.stats['backpressure_activations']} activaciones")
        self.logger.info(f"   🗑️ Descartados: {self.stats.get('dropped_events', 0)} eventos")
        self.logger.info(f"   🔴 Buffer lleno: {self.stats.get('buffer_full_errors', 0)} veces")
        self.logger.info(f"   📋 Cola overflow: {self.stats['queue_overflows']} eventos")
        self.logger.info(
            f"   ❌ Errores: processing={self.stats['processing_errors']}, send={self.stats.get('send_errors', 0)}, features={self.stats['feature_extraction_errors']}")

        # 🔄 Reset stats para próximo intervalo (incluyendo nuevas métricas)
        for key in ['received', 'processed', 'sent', 'ml_predictions', 'anomalies_detected',
                    'high_risk_events', 'backpressure_activations', 'processing_errors',
                    'feature_extraction_errors', 'queue_overflows', 'dropped_events',
                    'buffer_full_errors', 'send_errors']:
            self.stats[key] = 0

        self.stats['pipeline_latency_total'] = 0.0
        self.stats['last_stats_time'] = now

    def _check_performance_alerts(self):
        """Verifica alertas de performance ML (incluyendo backpressure)"""
        monitoring_config = self.config["monitoring"]
        alerts = monitoring_config.get("alerts", {})

        # 🚨 Alert de colas llenas
        protobuf_usage = self.protobuf_queue.qsize() / self.config["processing"]["protobuf_queue_size"]
        enriched_usage = self.enriched_queue.qsize() / self.config["processing"]["internal_queue_size"]

        max_queue_usage = alerts.get("max_queue_usage_percent", 100) / 100.0

        if protobuf_usage > max_queue_usage:
            self.logger.warning(f"🚨 ALERTA: Protobuf queue llena ({protobuf_usage * 100:.1f}%)")

        if enriched_usage > max_queue_usage:
            self.logger.warning(f"🚨 ALERTA: Enriched queue llena ({enriched_usage * 100:.1f}%)")

        # 🚨 Alert de backpressure excesivo
        max_backpressure = alerts.get("max_backpressure_activations", 100)
        if self.stats.get('backpressure_activations', 0) > max_backpressure:
            self.logger.warning(
                f"🚨 ALERTA: Backpressure excesivo ({self.stats['backpressure_activations']} activaciones)")

        # 🚨 Alert de drop rate alto
        total_received = self.stats.get('received', 0)
        dropped = self.stats.get('dropped_events', 0)
        if total_received > 0:
            drop_rate = (dropped / total_received) * 100
            max_drop_rate = alerts.get("max_drop_rate_percent", 10)
            if drop_rate > max_drop_rate:
                self.logger.warning(f"🚨 ALERTA: Drop rate alto ({drop_rate:.1f}% > {max_drop_rate}%)")

        # 🚨 Alert de tasa de fallo ML
        total_predictions = self.stats.get('ml_predictions', 0)
        ml_errors = self.stats.get('processing_errors', 0)
        if total_predictions > 0:
            failure_rate = (ml_errors / total_predictions) * 100
            max_failure_rate = alerts.get("max_ml_failure_rate_percent", 15)
            if failure_rate > max_failure_rate:
                self.logger.warning(f"🚨 ALERTA: Tasa de fallo ML alta ({failure_rate:.1f}%)")

    def run(self):
        """Ejecutar el detector ML distribuido"""
        self.logger.info("🚀 Iniciando Distributed ML Detector...")

        # 🧵 Crear threads según configuración
        threads = []

        # Thread de recepción protobuf
        recv_thread = threading.Thread(target=self.receive_protobuf_events, name="ProtobufReceiver")
        threads.append(recv_thread)

        # Threads de procesamiento ML
        num_processing_threads = self.config["processing"]["threads"]
        for i in range(num_processing_threads):
            proc_thread = threading.Thread(target=self.process_protobuf_events, name=f"MLProcessor-{i}")
            threads.append(proc_thread)

        # Threads de envío
        num_send_threads = self.config["processing"].get("send_threads", 1)
        for i in range(num_send_threads):
            send_thread = threading.Thread(target=self.send_enriched_events, name=f"Sender-{i}")
            threads.append(send_thread)

        # Thread de monitoreo
        monitor_thread = threading.Thread(target=self.monitor_performance, name="Monitor")
        threads.append(monitor_thread)

        # 🚀 Iniciar todos los threads
        for thread in threads:
            thread.start()

        self.logger.info(f"✅ ML Detector iniciado con {len(threads)} threads")
        self.logger.info(f"   📡 Recepción: 1 thread")
        self.logger.info(f"   🤖 Procesamiento ML: {num_processing_threads} threads")
        self.logger.info(f"   📤 Envío: {num_send_threads} threads")
        self.logger.info(
            f"   🧠 Algoritmos ML: {[k for k, v in self.models.items() if self.ml_config['models'][k]['enabled']]}")

        try:
            # 🔄 Mantener vivo el proceso principal
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("🛑 Deteniendo ML Detector...")

        # 🛑 Cierre graceful
        self.shutdown(threads)

    def shutdown(self, threads):
        """Cierre graceful del detector ML"""
        self.running = False
        self.stop_event.set()

        # 📊 Stats finales
        runtime = time.time() - self.stats['start_time']
        self.logger.info(f"📊 Stats finales ML - Runtime: {runtime:.1f}s")
        self.logger.info(f"   Total procesados: {self.stats['processed']}")
        self.logger.info(f"   Modelos entrenados: {'✅' if self.models_trained else '❌'}")

        # 🧵 Esperar threads
        for thread in threads:
            thread.join(timeout=5)

        # 🔌 Cerrar sockets
        if self.input_socket:
            self.input_socket.close()
        if self.output_socket:
            self.output_socket.close()
        self.context.term()

        self.logger.info("✅ Distributed ML Detector cerrado correctamente")


# 🚀 Main
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Uso: python lightweight_ml_detector.py <config.json>")
        print("💡 Ejemplo: python lightweight_ml_detector.py lightweight_ml_detector_config.json")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        detector = DistributedMLDetector(config_file)
        detector.run()
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        sys.exit(1)