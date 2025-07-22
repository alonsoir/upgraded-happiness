#!/usr/bin/env python3
"""
lightweight_ml_detector.py - VERSIÓN CONSERVADORA COMPATIBLE CON DASHBOARD
🤖 Enhanced ML Detector para Upgraded-Happiness - CONFIGURACIÓN LOCAL ESTABLE
- Configuración ZMQ conservadora compatible con dashboard thread-safe
- Validación estricta de tamaño de mensajes (MAXMSGSIZE: 10000)
- Backpressure agresivo para evitar saturación del dashboard
- Solo 2 algoritmos ML ligeros: Isolation Forest + K-Means
- Timeouts y buffers compatible con dashboard (LINGER=0, timeout=500ms)
- Colas pequeñas para uso eficiente de memoria local
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
    import src.protocols.protobuf.network_event_extended_v3_pb2 as NetworkEventProto

    PROTOBUF_AVAILABLE = True
except ImportError:
    try:
        from src.protocols.protobuf import network_event_extended_v3_pb2 as NetworkEventProto

        PROTOBUF_AVAILABLE = True
    except ImportError:
        print("⚠️ Protobuf network_event_extended_v2 no disponible")
        PROTOBUF_AVAILABLE = False

# 📦 ML Libraries - SOLO 2 algoritmos ligeros para local
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler, RobustScaler
    from sklearn.metrics import silhouette_score
    from functools import lru_cache

    ML_AVAILABLE = True
except ImportError:
    print("⚠️ Scikit-learn no disponible - ML deshabilitado")
    ML_AVAILABLE = False


class ModelPersistenceManager:
    """Gestor de persistencia simplificado para configuración conservadora"""

    def __init__(self, persistence_config: Dict[str, Any]):
        self.config = persistence_config
        self.models_dir = Path(self.config.get("models_dir", "ml_models"))
        self.models_dir.mkdir(exist_ok=True)

        # Subdirectorios organizados pero simplificados
        self.model_versions_dir = self.models_dir / "versions"
        self.best_models_dir = self.models_dir / "best"

        for dir_path in [self.model_versions_dir, self.best_models_dir]:
            dir_path.mkdir(exist_ok=True)

        self.current_version = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.enabled = self.config.get("enabled", True)
        self.max_model_files = self.config.get("max_model_files", 5)

    def save_models(self, models, processors, training_metrics=None):
        """Guardar modelos con cleanup automático para conservar espacio"""
        if not self.enabled:
            return None

        version_dir = self.model_versions_dir / self.current_version
        version_dir.mkdir(exist_ok=True)

        saved_files = []

        try:
            # Guardar solo modelos habilitados y entrenados
            for model_name, model in models.items():
                if model is not None:
                    model_file = version_dir / f"{model_name}.joblib"
                    joblib.dump(model, model_file)
                    saved_files.append(model_file)

            # Guardar procesadores
            processors_file = version_dir / "processors.joblib"
            joblib.dump(processors, processors_file)
            saved_files.append(processors_file)

            # Guardar metadatos simplificados
            metadata = {
                "version": self.current_version,
                "timestamp": datetime.now().isoformat(),
                "training_metrics": training_metrics or {},
                "model_count": len([m for m in models.values() if m is not None]),
                "config_mode": "conservative_local"
            }

            metadata_file = version_dir / "metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)

            # 🧹 Limpiar versiones antiguas para conservar espacio
            self._cleanup_old_versions()

            return version_dir

        except Exception as e:
            raise RuntimeError(f"❌ Error guardando modelos: {e}")

    def _cleanup_old_versions(self):
        """Limpiar versiones antiguas para conservar espacio"""
        try:
            versions = sorted(self.model_versions_dir.glob("*"))
            if len(versions) > self.max_model_files:
                for old_version in versions[:-self.max_model_files]:
                    if old_version.is_dir():
                        import shutil
                        shutil.rmtree(old_version)
        except Exception as e:
            print(f"⚠️ Error limpiando versiones antiguas: {e}")

    def load_models(self, version=None):
        """Cargar modelos de la versión más reciente"""
        if not self.enabled:
            return None, None

        # Cargar la versión más reciente
        versions = sorted(self.model_versions_dir.glob("*"))
        if not versions:
            return None, None

        version_dir = versions[-1]  # Más reciente

        try:
            models = {}

            # Cargar solo los modelos que existan
            for model_file in version_dir.glob("*.joblib"):
                if model_file.name != "processors.joblib":
                    model_name = model_file.stem
                    models[model_name] = joblib.load(model_file)

            # Cargar procesadores
            processors_file = version_dir / "processors.joblib"
            processors = None
            if processors_file.exists():
                processors = joblib.load(processors_file)

            return models, processors

        except Exception as e:
            raise RuntimeError(f"❌ Error cargando modelos: {e}")


class ConservativeMLDetector:
    """
    Detector ML conservador compatible con dashboard thread-safe
    - Solo 2 algoritmos ML ligeros para local
    - Configuración ZMQ compatible con dashboard conservador
    - Validación estricta de tamaño de mensajes
    - Backpressure agresivo para estabilidad
    """

    def __init__(self, config_file: str):
        # 📄 Cargar configuración conservadora
        self.config = self._load_config_strict(config_file)
        self.config_file = config_file

        # 🏷️ Identidad distribuida
        self.node_id = self.config["node_id"]
        self.process_id = os.getpid()
        self.start_time = time.time()

        # 📝 Setup logging PRIMERO
        self.setup_logging()

        # 🔌 Setup ZeroMQ CONSERVADOR compatible con dashboard
        self.context = zmq.Context()
        self.input_socket = None
        self.output_socket = None
        self.setup_conservative_sockets()

        # 🔄 Backpressure AGRESIVO
        self.backpressure_config = self.config["backpressure"]

        # 📦 Colas internas PEQUEÑAS para local
        self.setup_internal_queues()

        # 🤖 Configuración ML CONSERVADORA
        self.ml_config = self.config["ml"]
        self.models_enabled = self.ml_config.get("enabled", True)

        # 🧠 SOLO 2 Modelos ML ligeros para local
        self.models = {
            'isolation_forest': None,
            'kmeans': None
        }

        # 🔧 Procesadores simplificados
        self.processors = {
            'scaler': StandardScaler()
        }

        # 💾 Sistema de persistencia conservador
        self.persistence_manager = None
        if self.config.get("persistence", {}).get("enabled", False):
            self.persistence_manager = ModelPersistenceManager(self.config["persistence"])

        # 📊 Métricas conservadoras
        self.stats = {
            'received': 0, 'processed': 0, 'sent': 0,
            'ml_predictions': 0, 'anomalies_detected': 0, 'high_risk_events': 0,
            'training_sessions': 0, 'processing_errors': 0,
            'backpressure_activations': 0, 'queue_overflows': 0, 'dropped_events': 0,
            'buffer_full_errors': 0, 'send_errors': 0, 'send_timeouts': 0,
            'oversized_messages': 0, 'message_validation_errors': 0,
            'pipeline_latency_total': 0.0, 'start_time': time.time()
        }

        # 🎛️ Control
        self.running = True
        self.stop_event = Event()
        self.models_trained = False

        # 📈 Buffer de entrenamiento PEQUEÑO para local
        training_config = self.ml_config.get("training", {})
        self.training_data = deque(maxlen=training_config.get("min_training_samples", 200))
        self.last_training_time = 0
        self.training_interval = training_config.get("retrain_interval_minutes", 60) * 60

        # 📊 Estadísticas simplificadas
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)

        # ✅ Verificar dependencias
        self._verify_dependencies()

        # 🔄 Intentar cargar modelos existentes
        if self.persistence_manager:
            self._load_existing_models()

        self.logger.info(f"🤖 Conservative ML Detector inicializado")
        self.logger.info(f"   🏷️ Node ID: {self.node_id}")
        self.logger.info(f"   🔢 PID: {self.process_id}")
        self.logger.info(f"   🧠 Algoritmos: {list(self.models.keys())} (conservador)")
        self.logger.info(f"   💾 Persistencia: {'✅' if self.persistence_manager else '❌'}")
        self.logger.info(f"   🔒 Modo: CONSERVADOR - Compatible con dashboard thread-safe")

    def _load_config_strict(self, config_file: str) -> Dict[str, Any]:
        """Carga configuración conservadora estricta"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            raise RuntimeError(f"❌ Archivo de configuración no encontrado: {config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ Error parseando JSON: {e}")

        # ✅ Validar campos críticos conservadores
        required_fields = ["node_id", "network", "zmq", "backpressure", "processing", "ml"]
        for field in required_fields:
            if field not in config:
                raise RuntimeError(f"❌ Campo requerido faltante: {field}")

        return config

    def _verify_dependencies(self):
        """Verifica dependencias críticas"""
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
        """Setup logging conservador"""
        log_config = self.config["logging"]
        level = getattr(logging, log_config["level"].upper())
        log_format = log_config["format"].format(node_id=self.node_id, pid=self.process_id)
        formatter = logging.Formatter(log_format)

        if log_config.get("file"):
            handler = logging.FileHandler(log_config["file"])
        else:
            handler = logging.StreamHandler()

        handler.setFormatter(formatter)
        self.logger = logging.getLogger(f"ml_detector_{self.node_id}")
        self.logger.setLevel(level)
        self.logger.addHandler(handler)
        self.logger.propagate = False

    def setup_conservative_sockets(self):
        """🔒 Configuración ZMQ CONSERVADORA compatible con dashboard"""
        network_config = self.config["network"]
        zmq_config = self.config["zmq"]

        try:
            # 📥 Socket de entrada (PULL) con configuración conservadora
            input_config = network_config["input_socket"]
            self.input_socket = self.context.socket(zmq.PULL)

            # 🔧 CONFIGURACIÓN CONSERVADORA COMPATIBLE CON DASHBOARD
            self.input_socket.setsockopt(zmq.RCVHWM, min(zmq_config["rcvhwm"], 500))
            self.input_socket.setsockopt(zmq.RCVTIMEO, zmq_config["recv_timeout_ms"])
            self.input_socket.setsockopt(zmq.LINGER, 0)  # 🔒 CRÍTICO: Cierre inmediato como dashboard
            self.input_socket.setsockopt(zmq.RCVBUF, zmq_config.get("recv_buffer_size", 65536))
            self.input_socket.setsockopt(zmq.MAXMSGSIZE, zmq_config.get("max_message_size", 10000))

            # TCP Keepalive conservador
            if zmq_config["vertical_scaling_optimizations"]["tcp_keepalive"]:
                self.input_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                self.input_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE,
                                             zmq_config["vertical_scaling_optimizations"]["tcp_keepalive_idle"])

            input_address = f"tcp://{input_config['address']}:{input_config['port']}"
            self.input_socket.connect(input_address)

            # 📤 Socket de salida (PUSH) con configuración conservadora
            output_config = network_config["output_socket"]
            self.output_socket = self.context.socket(zmq.PUSH)

            # 🔧 CONFIGURACIÓN CONSERVADORA COMPATIBLE CON DASHBOARD
            self.output_socket.setsockopt(zmq.SNDHWM, min(zmq_config["sndhwm"], 500))
            self.output_socket.setsockopt(zmq.SNDTIMEO, zmq_config["send_timeout_ms"])
            self.output_socket.setsockopt(zmq.LINGER, 0)  # 🔒 CRÍTICO: Cierre inmediato como dashboard
            self.output_socket.setsockopt(zmq.SNDBUF, zmq_config.get("send_buffer_size", 65536))
            self.output_socket.setsockopt(zmq.MAXMSGSIZE, zmq_config.get("max_message_size", 10000))

            # TCP Keepalive para salida
            if zmq_config["vertical_scaling_optimizations"]["tcp_keepalive"]:
                self.output_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                self.output_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE,
                                              zmq_config["vertical_scaling_optimizations"]["tcp_keepalive_idle"])

            output_address = f"tcp://*:{output_config['port']}"
            self.output_socket.bind(output_address)

            self.logger.info(f"🔌 Sockets ZMQ CONSERVADORES configurados:")
            self.logger.info(f"   📥 Input: CONNECT to {input_address}")
            self.logger.info(f"   📤 Output: BIND on {output_address}")
            self.logger.info(f"   🔒 LINGER: 0ms (cierre inmediato como dashboard)")
            self.logger.info(
                f"   ⏱️ Timeouts: RCV={zmq_config['recv_timeout_ms']}ms, SND={zmq_config['send_timeout_ms']}ms")
            self.logger.info(f"   📏 MAXMSGSIZE: {zmq_config.get('max_message_size', 10000)} bytes")
            self.logger.info(f"   🌊 HWM: RCV={min(zmq_config['rcvhwm'], 500)}, SND={min(zmq_config['sndhwm'], 500)}")

        except Exception as e:
            raise RuntimeError(f"❌ Error configurando sockets ZMQ conservadores: {e}")

    def setup_internal_queues(self):
        """📋 Configuración de colas PEQUEÑAS para local"""
        proc_config = self.config["processing"]

        # Colas más pequeñas para evitar uso excesivo de memoria
        self.protobuf_queue = Queue(maxsize=proc_config["protobuf_queue_size"])
        self.enriched_queue = Queue(maxsize=proc_config["internal_queue_size"])

        self.logger.info(f"📋 Colas conservadoras configuradas:")
        self.logger.info(f"   📦 Protobuf queue: {proc_config['protobuf_queue_size']} (pequeña)")
        self.logger.info(f"   🤖 Enriched queue: {proc_config['internal_queue_size']} (pequeña)")

    def _load_existing_models(self):
        """Cargar modelos existentes conservadores"""
        self.logger.info("🔍 Buscando modelos ML conservadores...")
        try:
            loaded_models, loaded_processors = self.persistence_manager.load_models()

            if loaded_models:
                # Solo cargar modelos que están habilitados en configuración conservadora
                for model_name in self.models.keys():
                    if model_name in loaded_models:
                        self.models[model_name] = loaded_models[model_name]

                if loaded_processors:
                    self.processors.update(loaded_processors)

                self.models_trained = True
                active_models = [k for k, v in self.models.items() if v is not None]
                self.logger.info(f"✅ Modelos conservadores cargados: {active_models}")
            else:
                self.logger.info("💡 No hay modelos guardados - entrenamiento automático activado")
        except Exception as e:
            self.logger.warning(f"⚠️ Error cargando modelos: {e}")

    def receive_protobuf_events(self):
        """Thread de recepción con backpressure AGRESIVO"""
        self.logger.info("📡 Iniciando recepción protobuf CONSERVADORA...")

        consecutive_errors = 0
        queue_full_count = 0

        while self.running:
            try:
                # 📨 Recibir evento protobuf
                protobuf_data = self.input_socket.recv(zmq.NOBLOCK)
                self.stats['received'] += 1
                consecutive_errors = 0

                # 🔍 VALIDACIÓN CRÍTICA: Verificar tamaño antes de procesar
                max_size = self.config["zmq"].get("max_message_size", 10000)
                if len(protobuf_data) > max_size:
                    self.stats['oversized_messages'] += 1
                    self.logger.warning(
                        f"🚫 Mensaje demasiado grande: {len(protobuf_data)} > {max_size} bytes, descartado")
                    continue

                if len(protobuf_data) == 0:
                    self.stats['message_validation_errors'] += 1
                    self.logger.warning("🚫 Mensaje vacío recibido, descartado")
                    continue

                # 🔍 Verificar backpressure AGRESIVO
                queue_config = self.config["processing"].get("queue_overflow_handling", {})
                current_usage = self.protobuf_queue.qsize() / self.config["processing"]["protobuf_queue_size"]

                emergency_threshold = queue_config.get("emergency_drop_threshold_percent", 50.0) / 100.0

                if current_usage > emergency_threshold:
                    # 🚨 EMERGENCY DROP - descartar inmediatamente
                    self.stats['queue_overflows'] += 1
                    self.stats['dropped_events'] += 1

                    if self.stats['queue_overflows'] % 10 == 0:
                        self.logger.warning(f"🚨 EMERGENCY DROP activado: cola {current_usage * 100:.1f}% llena")
                    continue

                # 📋 Añadir a cola con timeout MUY CORTO
                queue_timeout = queue_config.get("max_queue_wait_ms", 10) / 1000.0

                try:
                    self.protobuf_queue.put(protobuf_data, timeout=queue_timeout)
                    queue_full_count = 0
                except:
                    # 🔄 Aplicar estrategia drop_oldest si está configurada
                    self.stats['queue_overflows'] += 1
                    strategy = queue_config.get("strategy", "emergency_drop")

                    if strategy == "drop_oldest" and not self.protobuf_queue.empty():
                        try:
                            self.protobuf_queue.get_nowait()  # Descartar más antiguo
                            self.protobuf_queue.put_nowait(protobuf_data)  # Añadir nuevo
                        except:
                            self.stats['dropped_events'] += 1

            except zmq.Again:
                continue
            except zmq.ZMQError as e:
                consecutive_errors += 1
                if consecutive_errors % 20 == 0:
                    self.logger.error(f"❌ Error ZMQ recepción ({consecutive_errors}): {e}")
                time.sleep(0.05)

    def process_protobuf_events(self):
        """Thread de procesamiento ML CONSERVADOR"""
        self.logger.info("⚙️ Iniciando procesamiento ML CONSERVADOR...")

        queue_timeout = self.config["processing"]["queue_timeout_seconds"]
        max_processing_time = self.config["processing"].get("max_processing_time", 1.0)

        while self.running:
            try:
                protobuf_data = self.protobuf_queue.get(timeout=queue_timeout)
                start_time = time.time()

                # 🔒 Verificar timeout de procesamiento
                enriched_protobuf = self.enrich_protobuf_event_with_conservative_ml(protobuf_data)

                processing_time = time.time() - start_time

                # ⚠️ Verificar si el procesamiento fue demasiado lento
                if processing_time > max_processing_time:
                    self.logger.warning(
                        f"⚠️ Procesamiento lento: {processing_time * 1000:.1f}ms > {max_processing_time * 1000:.1f}ms")

                if enriched_protobuf:
                    self.stats['pipeline_latency_total'] += processing_time * 1000
                    self.stats['processed'] += 1

                    # 📋 Añadir a cola con timeout corto
                    try:
                        self.enriched_queue.put(enriched_protobuf, timeout=queue_timeout)
                    except:
                        self.stats['queue_overflows'] += 1

                self.protobuf_queue.task_done()

            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"❌ Error procesamiento conservador: {e}")
                self.stats['processing_errors'] += 1

    def send_enriched_events(self):
        """Thread de envío con validación ESTRICTA"""
        self.logger.info("📤 Iniciando envío CONSERVADOR...")

        queue_timeout = self.config["processing"]["queue_timeout_seconds"]
        max_message_size = self.config["zmq"].get("max_message_size", 10000)

        while self.running:
            try:
                enriched_protobuf = self.enriched_queue.get(timeout=queue_timeout)

                # 🔍 VALIDACIÓN CRÍTICA antes de enviar
                if len(enriched_protobuf) > max_message_size:
                    self.stats['oversized_messages'] += 1
                    self.logger.error(
                        f"🚫 Evento demasiado grande para enviar: {len(enriched_protobuf)} > {max_message_size}")
                    continue

                # 📤 Enviar con backpressure conservador
                success = self.send_event_with_conservative_backpressure(enriched_protobuf)

                if success:
                    self.stats['sent'] += 1

                self.enriched_queue.task_done()

            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"❌ Error envío conservador: {e}")

    def enrich_protobuf_event_with_conservative_ml(self, protobuf_data: bytes) -> Optional[bytes]:
        """Enriquecimiento ML CONSERVADOR - solo 2 algoritmos ligeros"""
        if not PROTOBUF_AVAILABLE:
            return None

        try:
            # 📦 Deserializar evento
            event = NetworkEventProto.NetworkEvent()
            event.ParseFromString(protobuf_data)
            # 🆕 Usar campos duales si disponibles
            if event.dual_enrichment_success:
                source_location = (event.source_latitude, event.source_longitude)
                target_location = (event.target_latitude, event.target_longitude)

                # Calcular métricas geográficas
                distance = calculate_distance(source_location, target_location)
                event.geographic_distance_km = distance
                event.distance_category = categorize_distance(distance)
                event.same_country = (event.source_country_code == event.target_country_code)

                # Score de anomalía geográfica
                event.geographic_anomaly_score = calculate_geo_anomaly(event)

            # 🤖 Extraer features SIMPLIFICADAS
            features = self._extract_conservative_ml_features(event)
            if features is None:
                self.stats['processing_errors'] += 1
                return None

            # 📈 Añadir a buffer de entrenamiento (más pequeño)
            self.training_data.append(features)

            # 🧠 Predecir con SOLO 2 algoritmos conservadores
            anomaly_score, risk_score = self._predict_with_conservative_ml(features)

            # 🔄 Actualizar estadísticas
            self.stats['ml_predictions'] += 1

            if anomaly_score > self.ml_config.get("anomaly_threshold", 0.6):
                self.stats['anomalies_detected'] += 1

            if risk_score > self.ml_config.get("high_risk_threshold", 0.8):
                self.stats['high_risk_events'] += 1

            # ✅ Enriquecer evento - PRESERVAR TODO del geoip_enricher
            enriched_event = NetworkEventProto.NetworkEvent()
            enriched_event.CopyFrom(event)

            # 🤖 Añadir scores ML conservadores
            enriched_event.anomaly_score = self._sanitize_float(anomaly_score)
            enriched_event.risk_score = self._sanitize_float(risk_score)

            # 🆔 Información del ML detector conservador
            enriched_event.ml_detector_pid = self.process_id
            enriched_event.ml_detector_timestamp = int(time.time() * 1000)

            # 📊 Pipeline tracking simplificado
            if enriched_event.geoip_enricher_timestamp > 0:
                pipeline_latency = enriched_event.ml_detector_timestamp - enriched_event.geoip_enricher_timestamp
                enriched_event.processing_latency_ms = float(pipeline_latency)

            # 🎯 Path del pipeline
            if enriched_event.pipeline_path:
                enriched_event.pipeline_path += "->ml_conservative"
            else:
                enriched_event.pipeline_path = "geoip->ml_conservative"

            enriched_event.pipeline_hops += 1

            # 🏷️ Tag conservador
            enriched_event.component_tags.append(f"ml_conservative_{self.node_id}")

            # 📝 Descripción simplificada
            if risk_score > 0.7:
                enriched_event.description = f"🚨 ML Risk: {risk_score:.2f} | {enriched_event.description or ''}"
            elif anomaly_score > 0.6:
                enriched_event.description = f"⚠️ ML Anomaly: {anomaly_score:.2f} | {enriched_event.description or ''}"

            enriched_event.component_status = "healthy"

            return enriched_event.SerializeToString()

        except Exception as e:
            self.stats['processing_errors'] += 1
            self.logger.error(f"❌ Error enriquecimiento conservador: {e}")
            return None

    def _extract_conservative_ml_features(self, event) -> Optional[np.ndarray]:
        """Extrae features SIMPLIFICADAS - siempre 17 para compatibilidad"""
        try:
            features = []

            # 📊 Features básicas (4)
            features.extend([
                float(event.packet_size or 0),
                float(event.dest_port or 0),
                float(event.src_port or 0),
                float(self._protocol_to_numeric(getattr(event, 'protocol', '')))
            ])

            # ⏰ Features temporales simplificadas (3)
            now = datetime.now()
            features.extend([
                float(now.hour),
                float(now.minute),
                float(1 if now.weekday() >= 5 else 0)
            ])

            # 🌐 Features de IP simplificadas (2)
            source_ip = event.source_ip or ""
            target_ip = event.target_ip or ""
            features.extend([
                float(len(set(source_ip.replace('.', ''))) / max(len(source_ip), 1)),
                float(len(set(target_ip.replace('.', ''))) / max(len(target_ip), 1))
            ])

            # 🚪 Features de puertos (2)
            self.port_stats[event.src_port] += 1
            self.port_stats[event.dest_port] += 1
            features.extend([
                float(min(self.port_stats[event.src_port], 100)),  # Limitado para estabilidad
                float(min(self.port_stats[event.dest_port], 100))
            ])

            # 🌍 Features de GeoIP (4)
            has_geoip = 1 if (event.latitude != 0 and event.longitude != 0) else 0
            lat_abs = abs(event.latitude) if has_geoip else 0
            lon_abs = abs(event.longitude) if has_geoip else 0
            distance = math.sqrt(lat_abs ** 2 + lon_abs ** 2) if has_geoip else 0

            features.extend([float(has_geoip), float(lat_abs), float(lon_abs), float(distance)])

            # 🔧 Features adicionales (2)
            features.extend([
                float(1 if event.dest_port in [22, 23, 80, 443, 135, 139, 445] else 0),
                float(len(event.event_id or "") % 100) / 100.0
            ])

            # ✅ Verificar longitud exacta (17)
            final_features = np.array(features)
            if len(final_features) != 17:
                # 🔧 Ajustar a 17 exactamente
                if len(final_features) < 17:
                    padding = np.zeros(17 - len(final_features))
                    final_features = np.concatenate([final_features, padding])
                else:
                    final_features = final_features[:17]

            return final_features

        except Exception as e:
            self.logger.error(f"❌ Error extrayendo features conservadoras: {e}")
            return np.zeros(17)  # Fallback seguro

    def _protocol_to_numeric(self, protocol: str) -> int:
        """Convierte protocolo a numérico"""
        protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1, 'http': 80, 'https': 443}
        return protocol_map.get(protocol.lower(), 0)

    def _predict_with_conservative_ml(self, features: np.ndarray) -> Tuple[float, float]:
        """Predicción con SOLO 2 algoritmos conservadores"""
        if not ML_AVAILABLE or not self.models_enabled:
            return self._conservative_heuristic_prediction(features)

        # 🔄 Auto-entrenamiento conservador
        self._auto_train_conservative_models()

        if not self.models_trained:
            return self._conservative_heuristic_prediction(features)

        try:
            features_scaled = self.processors['scaler'].transform(features.reshape(1, -1))

            anomaly_scores = []
            risk_scores = []

            # 1️⃣ Isolation Forest (habilitado)
            if self.models['isolation_forest'] and self.ml_config["models"]["isolation_forest"]["enabled"]:
                try:
                    iso_score = self.models['isolation_forest'].decision_function(features_scaled)[0]
                    iso_normalized = max(0, min(1, (iso_score + 1) / 2))
                    anomaly_scores.append(1 - iso_normalized)
                except Exception as e:
                    self.logger.debug(f"⚠️ Error Isolation Forest: {e}")

            # 2️⃣ K-Means (habilitado)
            if self.models['kmeans'] and self.ml_config["models"]["kmeans"]["enabled"]:
                try:
                    cluster = self.models['kmeans'].predict(features_scaled)[0]
                    center = self.models['kmeans'].cluster_centers_[cluster]
                    distance = np.linalg.norm(features_scaled[0] - center)
                    kmeans_score = min(1.0, distance / 2.0)
                    anomaly_scores.append(kmeans_score)
                    risk_scores.append(kmeans_score)  # Usar para ambos scores
                except Exception as e:
                    self.logger.debug(f"⚠️ Error K-Means: {e}")

            # 🔄 Combinar scores (promedio simple)
            final_anomaly = np.mean(anomaly_scores) if anomaly_scores else 0.0
            final_risk = np.mean(risk_scores) if risk_scores else final_anomaly

            return max(0.0, min(1.0, final_anomaly)), max(0.0, min(1.0, final_risk))

        except Exception as e:
            self.logger.error(f"❌ Error predicción conservadora: {e}")
            return self._conservative_heuristic_prediction(features)

    def _conservative_heuristic_prediction(self, features: np.ndarray) -> Tuple[float, float]:
        """Predicción heurística CONSERVADORA"""
        try:
            if len(features) < 4:
                return 0.0, 0.0

            packet_size, dest_port = features[0], features[1]

            anomaly_score = 0.0
            risk_score = 0.0

            # Heurísticas conservadoras simples
            if packet_size > 1500 or packet_size < 20:
                anomaly_score += 0.2

            if dest_port in [22, 23, 135, 139, 445]:
                risk_score += 0.3

            if dest_port > 49152:
                anomaly_score += 0.1

            return min(anomaly_score, 1.0), min(risk_score, 1.0)

        except:
            return 0.0, 0.0

    def _auto_train_conservative_models(self):
        """Entrenamiento automático CONSERVADOR"""
        current_time = time.time()
        training_config = self.ml_config.get("training", {})

        min_samples = training_config.get("min_training_samples", 200)

        should_train = (
                len(self.training_data) >= min_samples and
                (not self.models_trained or
                 (current_time - self.last_training_time > self.training_interval and
                  training_config.get("auto_retrain", True)))
        )

        if should_train:
            self.logger.info("🔧 Entrenamiento automático conservador...")
            self._train_conservative_models()
            self.last_training_time = current_time

    def _train_conservative_models(self):
        """Entrenar SOLO 2 modelos conservadores"""
        try:
            if len(self.training_data) < 50:
                return

            start_time = time.time()
            X = np.array(list(self.training_data))

            self.logger.info(f"🔧 Entrenando 2 algoritmos conservadores con {len(X)} muestras...")

            # Preprocesamiento simple
            X_scaled = self.processors['scaler'].fit_transform(X)

            models_config = self.ml_config["models"]

            # 1️⃣ Isolation Forest (conservador)
            if models_config["isolation_forest"]["enabled"]:
                iso_config = models_config["isolation_forest"]
                self.models['isolation_forest'] = IsolationForest(
                    contamination=iso_config["contamination"],
                    random_state=iso_config["random_state"],
                    n_estimators=iso_config["n_estimators"],  # Ya reducido en config
                    n_jobs=1  # Solo 1 job para local
                )
                self.models['isolation_forest'].fit(X_scaled)
                self.logger.info("✅ Isolation Forest conservador entrenado")

            # 2️⃣ K-Means (conservador)
            if models_config["kmeans"]["enabled"]:
                kmeans_config = models_config["kmeans"]
                self.models['kmeans'] = KMeans(
                    n_clusters=kmeans_config["n_clusters"],  # Ya reducido en config
                    random_state=kmeans_config["random_state"],
                    n_init=kmeans_config["n_init"]  # Ya reducido en config
                )
                self.models['kmeans'].fit(X_scaled)
                self.logger.info("✅ K-Means conservador entrenado")

            training_time = time.time() - start_time
            self.stats['training_sessions'] += 1

            self.logger.info(f"✅ 2 algoritmos conservadores entrenados en {training_time:.2f}s")

            # 💾 Guardar modelos
            if self.persistence_manager:
                training_metrics = {
                    "training_time": training_time,
                    "samples_count": len(X),
                    "mode": "conservative_local"
                }
                self.persistence_manager.save_models(self.models, self.processors, training_metrics)

            self.models_trained = True

        except Exception as e:
            self.logger.error(f"❌ Error entrenamiento conservador: {e}")

    def send_event_with_conservative_backpressure(self, enriched_data: bytes) -> bool:
        """Envío con backpressure MUY AGRESIVO"""
        bp_config = self.backpressure_config
        max_retries = min(bp_config["max_retries"], 2)  # Máximo 2 reintentos

        for attempt in range(max_retries + 1):
            try:
                self.output_socket.send(enriched_data, zmq.NOBLOCK)
                return True

            except zmq.Again:
                self.stats['buffer_full_errors'] += 1

                if attempt == max_retries:
                    self.stats['dropped_events'] += 1
                    return False

                # 🔄 Backpressure MUY corto
                delays = bp_config["retry_delays_ms"]
                delay_ms = delays[attempt] if attempt < len(delays) else delays[-1]
                time.sleep(min(delay_ms, 10) / 1000.0)  # Máximo 10ms de delay

                self.stats['backpressure_activations'] += 1
                continue

            except zmq.ZMQError as e:
                self.stats['send_errors'] += 1
                if "timeout" in str(e).lower():
                    self.stats['send_timeouts'] += 1
                return False

        return False

    def _sanitize_float(self, value) -> float:
        """Sanitizar valores float"""
        try:
            if value is None:
                return 0.0
            float_val = float(value)
            if math.isnan(float_val) or math.isinf(float_val):
                return 0.0
            return max(0.0, min(1.0, float_val))
        except:
            return 0.0

    def monitor_conservative_performance(self):
        """Monitoreo de performance CONSERVADOR"""
        monitoring_config = self.config["monitoring"]
        interval = monitoring_config["stats_interval_seconds"]

        while self.running:
            time.sleep(interval)
            if not self.running:
                break

            self._log_conservative_stats()
            self._check_conservative_alerts()

    def _log_conservative_stats(self):
        """Log estadísticas conservadoras"""
        self.logger.info(f"📊 Conservative ML Stats:")
        self.logger.info(f"   📨 Recibidos: {self.stats['received']}")
        self.logger.info(f"   🤖 Procesados: {self.stats['processed']}")
        self.logger.info(f"   📤 Enviados: {self.stats['sent']}")
        self.logger.info(f"   🧠 Predicciones: {self.stats['ml_predictions']}")
        self.logger.info(f"   🚨 Anomalías: {self.stats['anomalies_detected']}")
        self.logger.info(f"   ⚠️ Alto riesgo: {self.stats['high_risk_events']}")
        self.logger.info(f"   🔄 Backpressure: {self.stats['backpressure_activations']}")
        self.logger.info(f"   🗑️ Descartados: {self.stats['dropped_events']}")
        self.logger.info(f"   📏 Oversized: {self.stats['oversized_messages']}")
        self.logger.info(f"   ⏰ Send timeouts: {self.stats['send_timeouts']}")
        self.logger.info(f"   📋 Colas: protobuf={self.protobuf_queue.qsize()}, enriched={self.enriched_queue.qsize()}")

        # Reset stats
        for key in ['received', 'processed', 'sent', 'ml_predictions', 'anomalies_detected',
                    'high_risk_events', 'backpressure_activations', 'dropped_events',
                    'oversized_messages', 'send_timeouts']:
            self.stats[key] = 0

    def _check_conservative_alerts(self):
        """Verificar alertas conservadoras"""
        monitoring_config = self.config["monitoring"]
        alerts = monitoring_config.get("alerts", {})

        # 🚨 Alertas de colas
        protobuf_usage = self.protobuf_queue.qsize() / self.config["processing"]["protobuf_queue_size"]
        enriched_usage = self.enriched_queue.qsize() / self.config["processing"]["internal_queue_size"]

        max_usage = alerts.get("max_queue_usage_percent", 40.0) / 100.0

        if protobuf_usage > max_usage:
            self.logger.warning(f"🚨 ALERTA CONSERVADORA: Protobuf queue {protobuf_usage * 100:.1f}% llena")

        if enriched_usage > max_usage:
            self.logger.warning(f"🚨 ALERTA CONSERVADORA: Enriched queue {enriched_usage * 100:.1f}% llena")

        # 🚨 Alertas de mensajes oversized
        max_violations = alerts.get("max_message_size_violations", 5)
        if self.stats.get('oversized_messages', 0) > max_violations:
            self.logger.warning(f"🚨 ALERTA: Demasiados mensajes oversized ({self.stats['oversized_messages']})")

        # 🚨 Alertas de timeouts
        max_timeouts = alerts.get("max_send_timeouts", 10)
        if self.stats.get('send_timeouts', 0) > max_timeouts:
            self.logger.warning(f"🚨 ALERTA: Demasiados send timeouts ({self.stats['send_timeouts']})")

    def run(self):
        """Ejecutar detector ML CONSERVADOR"""
        self.logger.info("🚀 Iniciando Conservative ML Detector...")

        threads = []

        # Thread de recepción
        recv_thread = threading.Thread(target=self.receive_protobuf_events, name="ConservativeReceiver")
        threads.append(recv_thread)

        # Thread de procesamiento (solo 1 para local)
        proc_thread = threading.Thread(target=self.process_protobuf_events, name="ConservativeProcessor")
        threads.append(proc_thread)

        # Thread de envío (solo 1 para local)
        send_thread = threading.Thread(target=self.send_enriched_events, name="ConservativeSender")
        threads.append(send_thread)

        # Thread de monitoreo
        monitor_thread = threading.Thread(target=self.monitor_conservative_performance, name="ConservativeMonitor")
        threads.append(monitor_thread)

        # 🚀 Iniciar threads
        for thread in threads:
            thread.start()

        self.logger.info(f"✅ Conservative ML Detector iniciado:")
        self.logger.info(f"   🧵 Threads: {len(threads)} (conservador)")
        self.logger.info(f"   🧠 Algoritmos: Isolation Forest + K-Means")
        self.logger.info(f"   🔒 Modo: ULTRA CONSERVADOR para estabilidad local")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("🛑 Deteniendo Conservative ML Detector...")

        self.shutdown(threads)

    def shutdown(self, threads):
        """Cierre graceful conservador"""
        self.running = False
        self.stop_event.set()

        runtime = time.time() - self.stats['start_time']
        self.logger.info(f"📊 Runtime conservador: {runtime:.1f}s")

        # Esperar threads con timeout corto
        for thread in threads:
            thread.join(timeout=3)

        # Cerrar sockets con LINGER=0 (inmediato)
        if self.input_socket:
            self.input_socket.close()
        if self.output_socket:
            self.output_socket.close()
        self.context.term()

        self.logger.info("✅ Conservative ML Detector cerrado correctamente")


# 🚀 Main
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Uso: python lightweight_ml_detector_conservative.py <config.json>")
        print("💡 Ejemplo: python lightweight_ml_detector_conservative.py ml_detector_conservative_config.json")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        detector = ConservativeMLDetector(config_file)
        detector.run()
    except Exception as e:
        print(f"❌ Error fatal conservador: {e}")
        sys.exit(1)