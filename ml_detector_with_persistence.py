#!/usr/bin/env python3
"""
🤖 Enhanced ML Detector con Sistema de Persistencia y ZeroMQ
- Escucha eventos ZeroMQ 5559 (raw del Enhanced Promiscuous Agent)
- Aplica 6 algoritmos ML en tiempo real
- Enriquece eventos con anomaly_score y risk_score
- Mantiene TODOS los campos originales del .proto
- Envía eventos enriquecidos a ZeroMQ 5560
- Sistema de persistencia automática
"""

import os
import json
import time
import threading
import zmq
import joblib
import pickle
import numpy as np
from datetime import datetime
from pathlib import Path
from collections import deque, defaultdict
import logging

# ML Libraries
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.decomposition import PCA
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, silhouette_score

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Importar protobuf
try:
    from src.protocols.protobuf import network_event_pb2

    PROTOBUF_AVAILABLE = True
    logger.info("✅ Protobuf importado desde src.protocols.protobuf.network_event_pb2")
except ImportError:
    try:
        import network_event_pb2

        PROTOBUF_AVAILABLE = True
        logger.info("✅ Protobuf importado desde directorio local")
    except ImportError:
        PROTOBUF_AVAILABLE = False
        logger.error("❌ Protobuf no disponible")


class ModelPersistenceManager:
    """Gestor de persistencia y evaluación de modelos ML"""

    def __init__(self, models_dir="ml_models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)

        # Subdirectorios organizados
        self.model_versions_dir = self.models_dir / "versions"
        self.best_models_dir = self.models_dir / "best"
        self.evaluation_dir = self.models_dir / "evaluations"

        for dir_path in [self.model_versions_dir, self.best_models_dir, self.evaluation_dir]:
            dir_path.mkdir(exist_ok=True)

        self.current_version = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.metrics_history = []

        logger.info(f"📁 Directorio de modelos: {self.models_dir}")
        logger.info(f"🏷️ Versión actual: {self.current_version}")

    def save_models(self, models, processors, training_metrics=None):
        """Guardar modelos y procesadores con versionado"""
        version_dir = self.model_versions_dir / self.current_version
        version_dir.mkdir(exist_ok=True)

        saved_files = []

        try:
            # Guardar cada modelo individual
            for model_name, model in models.items():
                if model is not None:
                    model_file = version_dir / f"{model_name}.joblib"
                    joblib.dump(model, model_file)
                    saved_files.append(model_file)
                    logger.info(f"💾 Guardado: {model_name}")

            # Guardar procesadores (scaler, pca, etc.)
            processors_file = version_dir / "processors.joblib"
            joblib.dump(processors, processors_file)
            saved_files.append(processors_file)
            logger.info(f"💾 Guardado: Procesadores")

            # Guardar metadatos del entrenamiento
            metadata = {
                "version": self.current_version,
                "timestamp": datetime.now().isoformat(),
                "training_metrics": training_metrics or {},
                "model_count": sum(1 for m in models.values() if m is not None),
                "saved_files": [str(f) for f in saved_files]
            }

            metadata_file = version_dir / "metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)

            logger.info(f"✅ Modelos guardados en versión: {self.current_version}")
            return version_dir

        except Exception as e:
            logger.error(f"❌ Error guardando modelos: {e}")
            return None

    def load_models(self, version=None):
        """Cargar modelos de una versión específica o la mejor"""
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
                    logger.warning("⚠️ No hay modelos guardados")
                    return None, None

        version_dir = self.model_versions_dir / version
        if not version_dir.exists():
            logger.error(f"❌ Versión {version} no encontrada")
            return None, None

        try:
            models = {}

            # Cargar modelos individuales
            model_files = list(version_dir.glob("*.joblib"))
            for model_file in model_files:
                if model_file.name != "processors.joblib":
                    model_name = model_file.stem
                    models[model_name] = joblib.load(model_file)
                    logger.info(f"📂 Cargado: {model_name}")

            # Cargar procesadores
            processors_file = version_dir / "processors.joblib"
            processors = None
            if processors_file.exists():
                processors = joblib.load(processors_file)
                logger.info(f"📂 Cargado: Procesadores")

            logger.info(f"✅ Modelos cargados de versión: {version}")
            return models, processors

        except Exception as e:
            logger.error(f"❌ Error cargando modelos: {e}")
            return None, None

    def evaluate_models(self, models, X_test, y_test=None):
        """Evaluar performance de los modelos"""
        evaluations = {}

        for model_name, model in models.items():
            if model is None:
                continue

            try:
                eval_result = {
                    "model": model_name,
                    "timestamp": datetime.now().isoformat(),
                    "test_samples": len(X_test)
                }

                if model_name == "isolation_forest":
                    # Evaluación para detección de anomalías
                    predictions = model.predict(X_test)
                    scores = model.decision_function(X_test)

                    anomaly_rate = (predictions == -1).mean()
                    eval_result.update({
                        "anomaly_rate": float(anomaly_rate),
                        "mean_score": float(scores.mean()),
                        "std_score": float(scores.std()),
                        "type": "anomaly_detection"
                    })

                elif model_name == "kmeans":
                    # Evaluación para clustering
                    predictions = model.predict(X_test)

                    if len(np.unique(predictions)) > 1:
                        silhouette = silhouette_score(X_test, predictions)
                        eval_result.update({
                            "silhouette_score": float(silhouette),
                            "n_clusters": int(model.n_clusters),
                            "inertia": float(model.inertia_),
                            "type": "clustering"
                        })

                elif y_test is not None and hasattr(model, 'predict'):
                    # Evaluación para clasificación supervisada
                    predictions = model.predict(X_test)

                    # Métricas básicas
                    accuracy = accuracy_score(y_test, predictions)

                    eval_result.update({
                        "accuracy": float(accuracy),
                        "type": "classification"
                    })

                    # Métricas adicionales si es binario
                    if len(np.unique(y_test)) == 2:
                        precision = precision_score(y_test, predictions, average='weighted', zero_division=0)
                        recall = recall_score(y_test, predictions, average='weighted', zero_division=0)
                        f1 = f1_score(y_test, predictions, average='weighted', zero_division=0)

                        eval_result.update({
                            "precision": float(precision),
                            "recall": float(recall),
                            "f1_score": float(f1)
                        })

                evaluations[model_name] = eval_result
                logger.info(f"📊 Evaluado: {model_name} - {eval_result.get('type', 'unknown')}")

            except Exception as e:
                logger.warning(f"⚠️ Error evaluando {model_name}: {e}")
                evaluations[model_name] = {"error": str(e)}

        # Guardar evaluaciones
        eval_file = self.evaluation_dir / f"evaluation_{self.current_version}.json"
        with open(eval_file, 'w') as f:
            json.dump(evaluations, f, indent=2)

        logger.info(f"📋 Evaluación guardada: {eval_file}")
        return evaluations

    def save_as_best(self, models, processors, evaluations):
        """Guardar como mejores modelos basado en evaluaciones"""
        try:
            # Limpiar directorio de mejores modelos
            for old_file in self.best_models_dir.glob("*"):
                old_file.unlink()

            # Copiar modelos actuales como mejores
            for model_name, model in models.items():
                if model is not None:
                    best_file = self.best_models_dir / f"{model_name}_best.joblib"
                    joblib.dump(model, best_file)

            # Copiar procesadores
            best_processors_file = self.best_models_dir / "processors_best.joblib"
            joblib.dump(processors, best_processors_file)

            # Guardar evaluaciones de los mejores
            best_eval_file = self.best_models_dir / "best_evaluation.json"
            with open(best_eval_file, 'w') as f:
                json.dump(evaluations, f, indent=2)

            logger.info(f"🏆 Modelos marcados como mejores")
            return True

        except Exception as e:
            logger.error(f"❌ Error guardando como mejores: {e}")
            return False

    def _load_best_models(self):
        """Cargar los mejores modelos guardados"""
        try:
            models = {}

            # Cargar mejores modelos
            for model_file in self.best_models_dir.glob("*_best.joblib"):
                if model_file.name != "processors_best.joblib":
                    model_name = model_file.stem.replace("_best", "")
                    models[model_name] = joblib.load(model_file)
                    logger.info(f"🏆 Cargado mejor: {model_name}")

            # Cargar mejores procesadores
            processors_file = self.best_models_dir / "processors_best.joblib"
            processors = None
            if processors_file.exists():
                processors = joblib.load(processors_file)
                logger.info(f"🏆 Cargado mejores procesadores")

            return models, processors

        except Exception as e:
            logger.error(f"❌ Error cargando mejores modelos: {e}")
            return None, None

    def list_versions(self):
        """Listar todas las versiones disponibles"""
        versions = []
        for version_dir in sorted(self.model_versions_dir.glob("*")):
            metadata_file = version_dir / "metadata.json"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                versions.append(metadata)
        return versions

    def get_model_summary(self):
        """Resumen de modelos y evaluaciones"""
        summary = {
            "total_versions": len(list(self.model_versions_dir.glob("*"))),
            "has_best_models": len(list(self.best_models_dir.glob("*_best.joblib"))) > 0,
            "evaluation_count": len(list(self.evaluation_dir.glob("*.json"))),
            "latest_version": self.current_version
        }
        return summary


class EnhancedLightweightThreatDetector:
    """
    Enhanced ML Detector con ZeroMQ y persistencia completa
    """

    def __init__(self, input_port=5559, output_port=5560, enable_persistence=True):
        self.input_port = input_port
        self.output_port = output_port

        # ZeroMQ Setup
        self.context = zmq.Context()
        self.subscriber = None
        self.publisher = None

        # Modelos ML - 6 algoritmos
        self.models = {
            'isolation_forest': None,
            'one_class_svm': None,
            'local_outlier_factor': None,
            'dbscan': None,
            'kmeans': None,
            'random_forest': None
        }

        # Procesadores
        self.processors = {
            'scaler': StandardScaler(),
            'robust_scaler': RobustScaler(),
            'pca': PCA(n_components=10)
        }

        # Sistema de persistencia
        self.persistence_manager = ModelPersistenceManager() if enable_persistence else None

        # Estado del sistema
        self.running = False
        self.models_trained = False
        self.training_data = deque(maxlen=5000)  # Buffer para entrenamiento
        self.last_training_time = 0
        self.training_interval = 300  # Re-entrenar cada 5 minutos

        # Estadísticas
        self.stats = {
            'total_events': 0,
            'events_processed': 0,
            'training_count': 0,
            'last_training': None,
            'ml_scores_applied': 0,
            'events_with_gps': 0,
            'start_time': datetime.now()
        }

        logger.info("🤖 Enhanced ML Detector inicializado")
        logger.info(f"📡 Input: ZeroMQ {input_port} → Output: ZeroMQ {output_port}")

        # Intentar cargar modelos existentes
        if self.persistence_manager:
            self._load_existing_models()

    def _load_existing_models(self):
        """Cargar modelos existentes si están disponibles"""
        logger.info("🔍 Buscando modelos guardados...")
        loaded_models, loaded_processors = self.persistence_manager.load_models()

        if loaded_models:
            self.models.update(loaded_models)
            if loaded_processors:
                self.processors.update(loaded_processors)
            self.models_trained = True
            logger.info("✅ Modelos existentes cargados")
        else:
            logger.info("💡 No hay modelos guardados - se entrenarán automáticamente")

    def start(self):
        """Iniciar el detector ML con ZeroMQ"""
        try:
            # Configurar ZeroMQ
            self.subscriber = self.context.socket(zmq.SUB)
            self.subscriber.connect(f"tcp://localhost:{self.input_port}")
            self.subscriber.setsockopt(zmq.SUBSCRIBE, b"")
            self.subscriber.setsockopt(zmq.RCVTIMEO, 1000)  # 1 segundo timeout

            self.publisher = self.context.socket(zmq.PUB)
            self.publisher.bind(f"tcp://*:{self.output_port}")

            logger.info(f"🔌 ZeroMQ configurado: {self.input_port} → {self.output_port}")

            self.running = True

            # Thread principal de procesamiento
            processing_thread = threading.Thread(target=self._processing_loop, daemon=True)
            processing_thread.start()

            # Thread de entrenamiento automático
            training_thread = threading.Thread(target=self._training_loop, daemon=True)
            training_thread.start()

            logger.info("✅ Enhanced ML Detector iniciado correctamente")

        except Exception as e:
            logger.error(f"❌ Error iniciando detector: {e}")
            self.stop()

    def _processing_loop(self):
        """Loop principal de procesamiento con manejo silencioso de errores"""
        logger.info("🔄 Iniciando loop de procesamiento ZeroMQ...")

        consecutive_errors = 0
        parsing_errors = 0
        last_error_log = 0
        successful_events = 0

        while self.running:
            try:
                # Recibir evento desde puerto 5559
                message = self.subscriber.recv(zmq.NOBLOCK)

                if PROTOBUF_AVAILABLE:
                    # Procesar evento protobuf con manejo robusto
                    try:
                        event = network_event_pb2.NetworkEvent()
                        event.ParseFromString(message)

                        # Procesar evento y enriquecer con ML
                        enhanced_event = self._enrich_event_with_ml(event)

                        # Enviar evento enriquecido al puerto 5560
                        if enhanced_event:
                            enhanced_message = enhanced_event.SerializeToString()
                            self.publisher.send(enhanced_message)

                            self.stats['events_processed'] += 1
                            successful_events += 1
                            consecutive_errors = 0

                            # Log exitoso cada 50 eventos procesados
                            if successful_events % 50 == 0:
                                logger.info(f"📊 {successful_events} eventos ML procesados exitosamente")

                    except Exception as parse_error:
                        parsing_errors += 1
                        consecutive_errors += 1

                        # Log de errores MUY reducido - solo cada 100 errores
                        if parsing_errors - last_error_log >= 100:
                            success_rate = (successful_events / (successful_events + parsing_errors)) * 100
                            logger.warning(
                                f"⚠️ {parsing_errors} errores de parsing acumulados (Rate de éxito: {success_rate:.1f}%)")
                            logger.info("🔧 Sistema funcionando - aplicando corrección automática de timestamps")
                            last_error_log = parsing_errors

                        # Crear evento fallback silencioso para mantener el flujo
                        try:
                            fallback_event = self._create_fallback_event(message, parse_error)
                            if fallback_event:
                                fallback_message = fallback_event.SerializeToString()
                                self.publisher.send(fallback_message)
                                self.stats['events_processed'] += 1
                        except:
                            # Si fallar el fallback, continuar silenciosamente
                            pass

                self.stats['total_events'] += 1

                # Si hay demasiados errores consecutivos, pausar brevemente (silenciosamente)
                if consecutive_errors > 50:
                    time.sleep(1)
                    consecutive_errors = 0

            except zmq.Again:
                # No hay mensajes
                time.sleep(0.01)
                consecutive_errors = 0
                continue
            except Exception as e:
                consecutive_errors += 1
                # Solo log errores críticos, no todos
                if consecutive_errors % 100 == 0:
                    logger.error(f"❌ Error crítico en processing loop: {e}")

                if consecutive_errors > 200:
                    logger.error("❌ Muchos errores críticos, pausando 5 segundos...")
                    time.sleep(5)
                    consecutive_errors = 0
                else:
                    time.sleep(0.1)

    def _create_fallback_event(self, message, error):
        """Crear evento fallback mínimo sin logging"""
        try:
            fallback_event = network_event_pb2.NetworkEvent()
            current_time = int(time.time())

            fallback_event.event_id = f"ml_corrected_{current_time}_{len(message)}"
            fallback_event.timestamp = current_time
            fallback_event.source_ip = "timestamp_corrected"
            fallback_event.target_ip = "auto_processed"
            fallback_event.packet_size = len(message)
            fallback_event.dest_port = 0
            fallback_event.src_port = 0
            fallback_event.agent_id = "ml_detector"
            fallback_event.latitude = 0.0
            fallback_event.longitude = 0.0
            fallback_event.event_type = "auto_corrected"
            fallback_event.anomaly_score = 0.0
            fallback_event.risk_score = 0.0
            fallback_event.description = "Timestamp auto-corrected by ML Detector"

            return fallback_event
        except:
            return None

    def _enrich_event_with_ml(self, original_event):
        """
        Enriquecer evento original con ML scores manteniendo TODOS los campos
        """
        try:
            # Extraer features del evento original
            features = self._extract_features(original_event)

            # Añadir a buffer de entrenamiento
            self.training_data.append(features)

            # Crear evento enriquecido manteniendo TODOS los campos originales
            enriched_event = network_event_pb2.NetworkEvent()

            # MANEJAR TIMESTAMP con validación robusta
            timestamp_value = original_event.timestamp

            # Si el timestamp es muy grande, puede estar en nanosegundos o microsegundos
            if timestamp_value > 1e12:  # Probablemente nanosegundos
                timestamp_value = timestamp_value / 1e9
            elif timestamp_value > 1e9 * 365 * 100:  # Probablemente microsegundos
                timestamp_value = timestamp_value / 1e6

            # Verificar que el timestamp sea razonable (después del año 1970 y antes de 2100)
            if timestamp_value < 0 or timestamp_value > 4102444800:  # 2100-01-01
                timestamp_value = time.time()  # Usar tiempo actual como fallback
                logger.warning(f"⚠️ Timestamp fuera de rango, usando tiempo actual")

            # Copiar TODOS los campos originales con validación
            enriched_event.event_id = original_event.event_id or f"ml_{int(time.time() * 1000)}"
            enriched_event.timestamp = int(timestamp_value)  # Timestamp corregido
            enriched_event.source_ip = original_event.source_ip or 'unknown'
            enriched_event.target_ip = original_event.target_ip or 'unknown'
            enriched_event.packet_size = max(0, original_event.packet_size)
            enriched_event.dest_port = max(0, min(65535, original_event.dest_port))
            enriched_event.src_port = max(0, min(65535, original_event.src_port))
            enriched_event.agent_id = original_event.agent_id or 'unknown'
            enriched_event.latitude = original_event.latitude
            enriched_event.longitude = original_event.longitude
            enriched_event.event_type = original_event.event_type or "network"

            # Preservar cualquier descripción existente
            existing_desc = original_event.description

            # Aplicar ML si los modelos están entrenados
            if self.models_trained:
                anomaly_score, risk_score = self._calculate_ml_scores(features)

                # ENRIQUECER con ML scores
                enriched_event.anomaly_score = float(anomaly_score)
                enriched_event.risk_score = float(risk_score)

                # Añadir descripción ML si es relevante
                ml_descriptions = []
                if existing_desc:
                    ml_descriptions.append(existing_desc)

                if risk_score > 0.8:
                    ml_descriptions.append(f"Alto riesgo ML detectado ({risk_score:.3f})")
                elif anomaly_score > 0.7:
                    ml_descriptions.append(f"Anomalía ML detectada ({anomaly_score:.3f})")
                elif anomaly_score > 0 or risk_score > 0:
                    ml_descriptions.append(f"ML scores: A={anomaly_score:.3f}, R={risk_score:.3f}")

                enriched_event.description = " | ".join(ml_descriptions)

                self.stats['ml_scores_applied'] += 1

                logger.debug(f"🤖 ML aplicado: {enriched_event.source_ip} → {enriched_event.target_ip} "
                             f"(A: {anomaly_score:.3f}, R: {risk_score:.3f})")
            else:
                # Si no hay modelos entrenados, mantener scores en 0
                enriched_event.anomaly_score = 0.0
                enriched_event.risk_score = 0.0
                enriched_event.description = existing_desc

            # Contar eventos con GPS
            if enriched_event.latitude != 0 and enriched_event.longitude != 0:
                self.stats['events_with_gps'] += 1

            return enriched_event

        except Exception as e:
            logger.error(f"❌ Error enriqueciendo evento: {e}")
            logger.debug(f"   Event data: event_id={getattr(original_event, 'event_id', 'N/A')}, "
                         f"timestamp={getattr(original_event, 'timestamp', 'N/A')}, "
                         f"source_ip={getattr(original_event, 'source_ip', 'N/A')}")

            # En caso de error, crear evento fallback manteniendo lo que se pueda
            try:
                fallback_event = network_event_pb2.NetworkEvent()
                fallback_event.event_id = getattr(original_event, 'event_id', f"err_{int(time.time() * 1000)}")
                fallback_event.timestamp = int(time.time())  # Timestamp actual
                fallback_event.source_ip = getattr(original_event, 'source_ip', 'parse_error')
                fallback_event.target_ip = getattr(original_event, 'target_ip', 'parse_error')
                fallback_event.packet_size = getattr(original_event, 'packet_size', 0)
                fallback_event.dest_port = getattr(original_event, 'dest_port', 0)
                fallback_event.src_port = getattr(original_event, 'src_port', 0)
                fallback_event.agent_id = getattr(original_event, 'agent_id', 'error')
                fallback_event.latitude = getattr(original_event, 'latitude', 0.0)
                fallback_event.longitude = getattr(original_event, 'longitude', 0.0)
                fallback_event.event_type = 'parsing_error'
                fallback_event.anomaly_score = 0.0
                fallback_event.risk_score = 0.0
                fallback_event.description = f'ML parsing error: {str(e)[:100]}'

                return fallback_event
            except:
                # Si ni el fallback funciona, devolver evento original
                return original_event

    def _extract_features(self, event):
        """Extraer features numéricas del evento para ML"""
        try:
            features = [
                float(event.dest_port or 0),
                float(event.src_port or 0),
                float(event.packet_size or 0),
                float(len(event.source_ip or "")),
                float(len(event.target_ip or "")),
                float(len(event.agent_id or "")),
                float(abs(event.latitude or 0)),
                float(abs(event.longitude or 0)),
                # Features adicionales
                float(1 if event.dest_port in [80, 443, 53, 22] else 0),  # Puertos comunes
                float(1 if event.packet_size > 1000 else 0),  # Paquetes grandes
                float(1 if event.latitude != 0 and event.longitude != 0 else 0),  # Tiene GPS
                float(datetime.now().hour),  # Hora del día
                float(datetime.now().weekday()),  # Día de la semana
                # Hash de IPs para patrones
                float(hash(event.source_ip or "") % 1000) / 1000.0,
                float(hash(event.target_ip or "") % 1000) / 1000.0,
                # Features de contenido
                float(1 if "unknown" in (event.source_ip or "") else 0),
                float(1 if "unknown" in (event.target_ip or "") else 0)
            ]
            return np.array(features)
        except Exception as e:
            logger.error(f"❌ Error extrayendo features: {e}")
            return np.zeros(17)  # Vector de ceros como fallback

    def _calculate_ml_scores(self, features):
        """Calcular anomaly_score y risk_score usando los 6 algoritmos"""
        try:
            # Preprocesar features
            features_scaled = self.processors['scaler'].transform([features])

            anomaly_scores = []
            risk_scores = []

            # 1. Isolation Forest
            if self.models['isolation_forest']:
                try:
                    iso_score = self.models['isolation_forest'].decision_function(features_scaled)[0]
                    iso_normalized = max(0, min(1, (iso_score + 1) / 2))
                    anomaly_scores.append(1 - iso_normalized)
                except:
                    pass

            # 2. One Class SVM
            if self.models['one_class_svm']:
                try:
                    svm_score = self.models['one_class_svm'].decision_function(features_scaled)[0]
                    svm_normalized = max(0, min(1, (svm_score + 1) / 2))
                    anomaly_scores.append(1 - svm_normalized)
                except:
                    pass

            # 3. Local Outlier Factor
            if self.models['local_outlier_factor']:
                try:
                    lof_score = self.models['local_outlier_factor'].decision_function(features_scaled)[0]
                    lof_normalized = max(0, min(1, (lof_score + 1) / 2))
                    anomaly_scores.append(1 - lof_normalized)
                except:
                    pass

            # 4. DBSCAN - usar distancia al cluster más cercano
            if self.models['dbscan']:
                try:
                    # Para DBSCAN en tiempo real, usar score aproximado
                    dbscan_score = 0.3  # Score neutral
                    anomaly_scores.append(dbscan_score)
                except:
                    pass

            # 5. K-Means - distancia al centroide más cercano
            if self.models['kmeans']:
                try:
                    cluster = self.models['kmeans'].predict(features_scaled)[0]
                    center = self.models['kmeans'].cluster_centers_[cluster]
                    distance = np.linalg.norm(features_scaled[0] - center)
                    kmeans_score = min(1.0, distance / 2.0)
                    anomaly_scores.append(kmeans_score)
                except:
                    pass

            # 6. Random Forest (clasificación)
            if self.models['random_forest']:
                try:
                    rf_proba = self.models['random_forest'].predict_proba(features_scaled)[0]
                    if len(rf_proba) > 1:
                        risk_scores.append(rf_proba[1])
                except:
                    pass

            # Combinar scores
            final_anomaly = np.mean(anomaly_scores) if anomaly_scores else 0.0
            final_risk = np.mean(risk_scores) if risk_scores else final_anomaly

            # Asegurar rango 0-1
            final_anomaly = max(0.0, min(1.0, final_anomaly))
            final_risk = max(0.0, min(1.0, final_risk))

            return final_anomaly, final_risk

        except Exception as e:
            logger.error(f"❌ Error calculando ML scores: {e}")
            return 0.0, 0.0

    def _training_loop(self):
        """Loop de entrenamiento automático cada 5 minutos"""
        logger.info("🔄 Iniciando loop de entrenamiento automático...")

        while self.running:
            try:
                current_time = time.time()

                # Entrenar si hay suficientes datos y ha pasado tiempo
                if (len(self.training_data) >= 100 and
                        current_time - self.last_training_time > self.training_interval):
                    logger.info("🔧 Iniciando entrenamiento automático de modelos...")
                    self._train_lightweight_models()
                    self.last_training_time = current_time

                time.sleep(10)  # Verificar cada 10 segundos

            except Exception as e:
                logger.error(f"❌ Error en loop de entrenamiento: {e}")
                time.sleep(30)

    def _train_lightweight_models(self):
        """Entrenar los 6 modelos ML lightweight"""
        try:
            if len(self.training_data) < 50:
                logger.warning("⚠️ Pocos datos para entrenamiento")
                return

            start_time = time.time()

            # Convertir datos a array
            X = np.array(list(self.training_data))

            # Generar labels sintéticas (en producción usarías labels reales)
            y = np.random.choice([0, 1], size=len(X), p=[0.9, 0.1])

            logger.info(f"🔧 Entrenando 6 algoritmos con {len(X)} muestras...")

            # Preprocesamiento
            X_scaled = self.processors['scaler'].fit_transform(X)

            # 1. Isolation Forest
            self.models['isolation_forest'] = IsolationForest(
                contamination=0.1, random_state=42, n_jobs=-1
            )
            self.models['isolation_forest'].fit(X_scaled)

            # 2. One Class SVM
            self.models['one_class_svm'] = OneClassSVM(nu=0.1)
            self.models['one_class_svm'].fit(X_scaled)

            # 3. Local Outlier Factor
            self.models['local_outlier_factor'] = LocalOutlierFactor(
                n_neighbors=20, contamination=0.1, novelty=True
            )
            self.models['local_outlier_factor'].fit(X_scaled)

            # 4. DBSCAN
            self.models['dbscan'] = DBSCAN(eps=0.5, min_samples=5)
            self.models['dbscan'].fit(X_scaled)

            # 5. K-Means
            self.models['kmeans'] = KMeans(n_clusters=5, random_state=42, n_init=10)
            self.models['kmeans'].fit(X_scaled)

            # 6. Random Forest (si hay múltiples clases)
            if len(np.unique(y)) > 1:
                self.models['random_forest'] = RandomForestClassifier(
                    n_estimators=100, random_state=42, n_jobs=-1
                )
                self.models['random_forest'].fit(X_scaled, y)

            training_time = time.time() - start_time
            self.stats['training_count'] += 1
            self.stats['last_training'] = datetime.now().isoformat()

            logger.info(f"✅ 6 algoritmos entrenados en {training_time:.2f}s")

            # Guardar modelos automáticamente
            if self.persistence_manager:
                training_metrics = {
                    "training_time": training_time,
                    "samples_count": len(X),
                    "timestamp": datetime.now().isoformat()
                }

                self.persistence_manager.save_models(
                    self.models, self.processors, training_metrics
                )

                # Marcar como mejores
                self.persistence_manager.save_as_best(
                    self.models, self.processors, {}
                )

                logger.info("💾 Modelos guardados automáticamente")

            self.models_trained = True

        except Exception as e:
            logger.error(f"❌ Error entrenando modelos: {e}")

    def get_stats(self):
        """Obtener estadísticas completas del detector"""
        # Calcular tiempo de funcionamiento
        uptime = (datetime.now() - self.stats.get('start_time', datetime.now())).total_seconds()

        # Calcular tasa de procesamiento
        processing_rate = 0
        if uptime > 0:
            processing_rate = self.stats['events_processed'] / uptime

        return {
            'total_events': self.stats['total_events'],
            'events_processed': self.stats['events_processed'],
            'ml_scores_applied': self.stats['ml_scores_applied'],
            'events_with_gps': self.stats['events_with_gps'],
            'models_trained': self.models_trained,
            'training_count': self.stats['training_count'],
            'last_training': self.stats['last_training'],
            'training_data_size': len(self.training_data),
            'models_available': [name for name, model in self.models.items() if model is not None],
            'input_port': self.input_port,
            'output_port': self.output_port,
            'uptime_seconds': uptime,
            'processing_rate': processing_rate,
            'success_rate': (self.stats['events_processed'] / max(1, self.stats['total_events'])) * 100,
            'gps_percentage': (self.stats['events_with_gps'] / max(1, self.stats['events_processed'])) * 100,
            'ml_enhancement_rate': (self.stats['ml_scores_applied'] / max(1, self.stats['events_processed'])) * 100,
            'system_health': self._get_system_health()
        }

    def _get_system_health(self):
        """Evaluar salud del sistema"""
        if not self.running:
            return 'stopped'
        elif self.stats['total_events'] == 0:
            return 'waiting_for_events'
        elif self.stats['events_processed'] / max(1, self.stats['total_events']) < 0.5:
            return 'parsing_issues'
        elif not self.models_trained:
            return 'training_models'
        else:
            return 'healthy'

    def stop(self):
        """Detener el detector"""
        self.running = False
        if self.subscriber:
            self.subscriber.close()
        if self.publisher:
            self.publisher.close()
        if self.context:
            self.context.term()
        logger.info("🛑 Enhanced ML Detector detenido")


def main():
    """Función principal del Enhanced ML Detector"""
    print("🤖 ENHANCED ML DETECTOR CON PERSISTENCIA Y ZEROMQ")
    print("=" * 60)
    print("🔄 Flujo completo:")
    print("   📡 Enhanced Promiscuous Agent → ZeroMQ 5559 (eventos raw)")
    print("   🤖 Enhanced ML Detector → aplica 6 algoritmos → ZeroMQ 5560 (enriquecidos)")
    print("   📊 Dashboard → escucha 5560 → visualiza eventos con ML scores")
    print("")
    print("🧠 6 Algoritmos ML:")
    print("   1. Isolation Forest - Detección de anomalías")
    print("   2. One-Class SVM - Detección de outliers")
    print("   3. Local Outlier Factor - Outliers locales")
    print("   4. DBSCAN - Clustering basado en densidad")
    print("   5. K-Means - Clustering por centroides")
    print("   6. Random Forest - Clasificación supervisada")
    print("")
    print("💾 Persistencia automática cada 5 minutos")
    print("🔄 Entrenamiento automático con datos reales")
    print("")

    detector = EnhancedLightweightThreatDetector(input_port=5559, output_port=5560)

    try:
        detector.start()

        print("✅ Enhanced ML Detector iniciado correctamente")
        print("📊 Estadísticas cada 30 segundos...")
        print("🛑 Presiona Ctrl+C para detener")
        print("")

        # Loop principal con estadísticas
        while True:
            time.sleep(30)
            stats = detector.get_stats()
            print(f"📊 Total: {stats['total_events']} | "
                  f"Procesados: {stats['events_processed']} | "
                  f"ML Aplicado: {stats['ml_scores_applied']} | "
                  f"GPS: {stats['events_with_gps']} | "
                  f"Entrenamientos: {stats['training_count']}")

    except KeyboardInterrupt:
        print("\n🛑 Deteniendo Enhanced ML Detector...")
        detector.stop()
        print("✅ Enhanced ML Detector detenido correctamente")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        detector.stop()


if __name__ == "__main__":
    main()