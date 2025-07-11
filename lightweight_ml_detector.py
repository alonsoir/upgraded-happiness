#!/usr/bin/env python3
"""
Sistema ML Ligero para Intel i9 + 32GB RAM
Optimizado para CPU, sin dependencias GPU
lightweight_ml_detector.py - PUERTO CORREGIDO + MULTIPART FIX
"""

# Auto-discovery functions
import socket
import time

import zmq


def find_available_port(start_port=5559, max_attempts=10):
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("localhost", port))
                return port
        except OSError:
            continue
    return start_port


def find_active_broker(start_port=5559, max_attempts=10):
    for port in range(start_port, start_port + max_attempts):
        try:
            context = zmq.Context()
            socket_test = context.socket(zmq.REQ)
            socket_test.setsockopt(zmq.RCVTIMEO, 500)
            socket_test.connect(f"tcp://localhost:{port}")
            socket_test.send_string("ping", zmq.NOBLOCK)
            socket_test.close()
            context.term()
            print(f"✅ Broker encontrado en puerto {port}")
            return f"tcp://localhost:{port}"
        except:
            continue
    print(f"⚠️  No se encontró broker, usando puerto {start_port}")
    return f"tcp://localhost:{start_port}"


def get_smart_broker_address():
    import sys

    for i, arg in enumerate(sys.argv):
        if arg == "--broker" and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return find_active_broker()


import json
import os
import pickle
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
# XGBoost es muy eficiente en CPU
import xgboost as xgb
import zmq
from sklearn.cluster import DBSCAN, KMeans
from sklearn.decomposition import PCA
# ML optimizado para CPU
from sklearn.ensemble import (GradientBoostingClassifier, IsolationForest,
                              RandomForestClassifier)
from sklearn.feature_selection import SelectKBest, f_classif
# Para análisis temporal básico sin GPU
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import RobustScaler, StandardScaler

sys.path.insert(0, os.getcwd())

try:
    from src.protocols.protobuf import network_event_pb2

    print("✅ Protobuf importado exitosamente")
except ImportError as e:
    print(f"❌ Error importando protobuf: {e}")
    sys.exit(1)


class LightweightThreatDetector:
    def __init__(self, broker_address="tcp://localhost:5559"):
        self.broker_address = broker_address
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.SUB)
        # ⭐ FIX: Suscribirse al topic específico del agente promiscuo
        self.socket.setsockopt(zmq.SUBSCRIBE, b"network_event")

        # Optimización para CPU Intel i9
        self.cpu_config = {
            "n_jobs": 8,  # Usar 8 cores del i9
            "batch_size": 1000,  # Procesar en lotes
            "memory_limit": "24GB",  # Dejar 8GB para el SO
            "model_cache_size": 50,  # Cachear 50 modelos
            "feature_limit": 50,  # Máximo 50 features para eficiencia
        }

        # Modelos ligeros optimizados para CPU
        self.models = {
            "isolation_forest": None,
            "random_forest": None,
            "xgboost": None,
            "gradient_boost": None,
            "kmeans": None,
            "dbscan": None,
            "sgd_classifier": None,
            "naive_bayes": None,
        }

        # Pipelines de procesamiento rápido
        self.processors = {
            "scaler": RobustScaler(),  # Más robusto que StandardScaler
            "pca": PCA(n_components=20),  # Reducir dimensionalidad
            "feature_selector": SelectKBest(score_func=f_classif, k=30),
        }

        # Cache para features frecuentes
        self.feature_cache = {}
        self.pattern_cache = deque(maxlen=10000)  # Últimos 10k patrones

        # Ventana deslizante para entrenamiento incremental
        self.sliding_window = deque(maxlen=5000)  # 5k samples para reentrenamiento

        # Estadísticas de rendimiento
        self.performance_stats = {
            "processing_time_ms": deque(maxlen=1000),
            "prediction_time_ms": deque(maxlen=1000),
            "memory_usage_mb": deque(maxlen=100),
            "cpu_utilization": deque(maxlen=100),
        }

        print(f"🧠 DETECTOR ML LIGERO (Optimizado para Intel i9)")
        print(f"💾 RAM disponible: 32GB (usando hasta 24GB)")
        print(f"🔧 CPU cores: {self.cpu_config['n_jobs']}")
        print(f"📊 Batch size: {self.cpu_config['batch_size']}")
        print(f"🔌 Conectando a: {broker_address}")
        print(f"📡 Suscrito a topic: 'network_event'")  # AÑADIDO
        print("=" * 60)

    def connect(self):
        """Conectar al broker ZeroMQ"""
        try:
            self.socket.connect(self.broker_address)
            print(f"✅ Conectado al Enhanced Promiscuous Agent: {self.broker_address}")
            return True
        except Exception as e:
            print(f"❌ Error conectando: {e}")
            return False

    def extract_lightweight_features(self, event):
        """Extraer features optimizadas para procesamiento rápido"""
        # Cache check para IPs frecuentes
        cache_key = f"{event.source_ip}:{event.target_ip}:{event.dest_port}"
        if cache_key in self.feature_cache:
            cached_features = self.feature_cache[cache_key].copy()
            cached_features["timestamp"] = time.time()
            return cached_features

        # Features básicas optimizadas
        features = {
            # Network features (más importantes)
            "src_port": event.src_port,
            "dst_port": event.dest_port,
            "packet_size": event.packet_size,
            "port_diff": abs(event.dest_port - event.src_port)
            if event.src_port > 0
            else 0,
            # IP features simplificadas
            "is_internal_src": 1 if self._is_internal_ip(event.source_ip) else 0,
            "is_internal_dst": 1 if self._is_internal_ip(event.target_ip) else 0,
            "ip_class": self._classify_ip_range(event.target_ip),
            # Port classification (más eficiente que muchos booleanos)
            "port_category": self._categorize_port(event.dest_port),
            "src_port_category": self._categorize_port(event.src_port),
            # Temporal features básicas
            "hour": datetime.now().hour,
            "is_business_hours": 1 if 9 <= datetime.now().hour <= 17 else 0,
            "is_weekend": 1 if datetime.now().weekday() >= 5 else 0,
            # Size features
            "size_category": min(4, event.packet_size // 256),  # 0-4 categories
            "is_large_packet": 1 if event.packet_size > 1500 else 0,
            # Protocol inference (rápido)
            "likely_protocol": self._infer_protocol(event.dest_port),
            # GPS/Geolocation features (usando coordenadas del enhanced agent)
            "has_gps": 1 if (event.latitude != 0.0 or event.longitude != 0.0) else 0,
            "lat_category": int(abs(event.latitude) // 10) if event.latitude != 0.0 else 0,
            "lon_category": int(abs(event.longitude) // 10) if event.longitude != 0.0 else 0,
            # Metadata básico
            "timestamp": time.time(),
        }

        # Cache para IPs frecuentes (optimización)
        if len(self.feature_cache) < 1000:  # Limitar cache
            self.feature_cache[cache_key] = features.copy()

        return features

    def _is_internal_ip(self, ip):
        """Verificación rápida de IP interna"""
        if not ip or ip == "unknown":
            return 0
        return 1 if ip.startswith(("192.168.", "10.", "172.")) else 0

    def _classify_ip_range(self, ip):
        """Clasificar rango de IP (0-5)"""
        if not ip or ip == "unknown":
            return 0

        if ip.startswith("192.168."):
            return 1  # LAN
        elif ip.startswith("10."):
            return 2  # Private Class A
        elif ip.startswith("172."):
            return 3  # Private Class B
        elif ip.startswith(("8.8.", "1.1.", "208.67.")):
            return 4  # Public DNS
        else:
            return 5  # Other public

    def _categorize_port(self, port):
        """Categorizar puerto (0-6) para eficiencia"""
        if port == 0:
            return 0
        elif port < 1024:
            return 1  # Privileged
        elif port in [80, 443, 22, 25, 53, 21, 23]:
            return 2  # Common services
        elif 1024 <= port <= 5000:
            return 3  # Registered
        elif 5001 <= port <= 32767:
            return 4  # Registered high
        elif 32768 <= port <= 49151:
            return 5  # Dynamic/ephemeral
        else:
            return 6  # Private/dynamic high

    def _infer_protocol(self, port):
        """Inferir protocolo por puerto (0-10)"""
        protocol_map = {
            80: 1,
            8080: 1,  # HTTP
            443: 2,
            8443: 2,  # HTTPS
            22: 3,  # SSH
            25: 4,
            587: 4,
            465: 4,  # SMTP
            53: 5,  # DNS
            21: 6,  # FTP
            23: 7,  # Telnet
            110: 8,
            995: 8,  # POP3
            143: 9,
            993: 9,  # IMAP
        }
        return protocol_map.get(port, 0)  # Unknown = 0

    def train_lightweight_models(self, X, y=None):
        """Entrenar modelos optimizados para CPU"""
        print(f"🔧 Entrenando modelos con {len(X)} muestras...")

        start_time = time.time()

        # Preprocesamiento rápido
        X_processed = self.processors["scaler"].fit_transform(X)

        # Reducir dimensionalidad si es necesario
        if X_processed.shape[1] > 20:
            X_processed = self.processors["pca"].fit_transform(X_processed)

        # 1. Isolation Forest (muy rápido para anomalías)
        print("🌲 Entrenando Isolation Forest...")
        self.models["isolation_forest"] = IsolationForest(
            contamination=0.1,
            n_estimators=50,  # Reducido para velocidad
            n_jobs=self.cpu_config["n_jobs"],
            random_state=42,
        )
        self.models["isolation_forest"].fit(X_processed)

        # 2. Random Forest (eficiente y preciso)
        if y is not None and len(np.unique(y)) > 1:
            print("🌳 Entrenando Random Forest...")
            self.models["random_forest"] = RandomForestClassifier(
                n_estimators=50,  # Optimizado para velocidad
                max_depth=10,
                n_jobs=self.cpu_config["n_jobs"],
                random_state=42,
            )
            self.models["random_forest"].fit(X_processed, y)

        # 3. XGBoost (excelente en CPU)
        if y is not None and len(np.unique(y)) > 1:
            print("🚀 Entrenando XGBoost...")
            self.models["xgboost"] = xgb.XGBClassifier(
                n_estimators=50,
                max_depth=6,
                learning_rate=0.1,
                n_jobs=self.cpu_config["n_jobs"],
                random_state=42,
                eval_metric="logloss",
            )
            self.models["xgboost"].fit(X_processed, y)

        # 4. SGD Classifier (muy rápido, ideal para streaming)
        if y is not None:
            print("⚡ Entrenando SGD Classifier...")
            self.models["sgd_classifier"] = SGDClassifier(
                loss="hinge",
                alpha=0.01,
                random_state=42,
                n_jobs=self.cpu_config["n_jobs"],
            )
            self.models["sgd_classifier"].fit(X_processed, y)

        # 5. KMeans (clustering rápido)
        print("🎯 Entrenando KMeans...")
        self.models["kmeans"] = KMeans(
            n_clusters=5, n_init=5, random_state=42  # Reducido para velocidad
        )
        self.models["kmeans"].fit(X_processed)

        # 6. Naive Bayes (ultrarrápido)
        if y is not None:
            print("🧮 Entrenando Naive Bayes...")
            self.models["naive_bayes"] = GaussianNB()
            self.models["naive_bayes"].fit(X_processed, y)

        training_time = time.time() - start_time
        print(f"✅ Entrenamiento completado en {training_time:.2f} segundos")

        return X_processed

    def predict_threat(self, features):
        """Predicción rápida de amenazas"""
        start_time = time.time()

        # Convertir a array
        feature_array = np.array(list(features.values())[:-1]).reshape(
            1, -1
        )  # Excluir timestamp

        # Preprocesar
        try:
            feature_array = self.processors["scaler"].transform(feature_array)
            if hasattr(self.processors["pca"], "components_"):
                feature_array = self.processors["pca"].transform(feature_array)
        except:
            # Si no están entrenados los processors, usar array original
            pass

        threats = []

        # Isolation Forest (detección de anomalías)
        if self.models["isolation_forest"] is not None:
            try:
                anomaly_score = self.models["isolation_forest"].decision_function(
                    feature_array
                )[0]
                is_anomaly = (
                        self.models["isolation_forest"].predict(feature_array)[0] == -1
                )

                if is_anomaly:
                    threats.append(
                        {
                            "type": "anomaly",
                            "model": "isolation_forest",
                            "score": float(anomaly_score),
                            "severity": "medium" if anomaly_score < -0.5 else "low",
                        }
                    )
            except:
                pass

        # Random Forest
        if self.models["random_forest"] is not None:
            try:
                proba = self.models["random_forest"].predict_proba(feature_array)[0]
                max_proba = max(proba)

                if max_proba > 0.7:  # Umbral de confianza
                    threats.append(
                        {
                            "type": "classification",
                            "model": "random_forest",
                            "probability": float(max_proba),
                            "severity": "high" if max_proba > 0.9 else "medium",
                        }
                    )
            except:
                pass

        # XGBoost
        if self.models["xgboost"] is not None:
            try:
                proba = self.models["xgboost"].predict_proba(feature_array)[0]
                max_proba = max(proba)

                if max_proba > 0.8:
                    threats.append(
                        {
                            "type": "ml_classification",
                            "model": "xgboost",
                            "probability": float(max_proba),
                            "severity": "high",
                        }
                    )
            except:
                pass

        # KMeans (clustering)
        if self.models["kmeans"] is not None:
            try:
                cluster = self.models["kmeans"].predict(feature_array)[0]
                distance = self.models["kmeans"].transform(feature_array)[0][cluster]

                if distance > 2.0:  # Lejos del centro del cluster
                    threats.append(
                        {
                            "type": "outlier",
                            "model": "kmeans",
                            "distance": float(distance),
                            "cluster": int(cluster),
                            "severity": "low",
                        }
                    )
            except:
                pass

        prediction_time = time.time() - start_time
        self.performance_stats["prediction_time_ms"].append(prediction_time * 1000)

        return threats

    def process_event_batch(self, events):
        """Procesar eventos en lotes para eficiencia"""
        if not events:
            return

        features_batch = []
        for event in events:
            features = self.extract_lightweight_features(event)
            features_batch.append(features)
            self.sliding_window.append(features)

        # Procesar amenazas en lote
        for i, features in enumerate(features_batch):
            threats = self.predict_threat(features)
            if threats:
                self.handle_threat_detection(events[i], threats)

    def handle_threat_detection(self, event, threats):
        """Manejar detección de amenazas"""
        for threat in threats:
            # Mostrar coordenadas GPS si existen
            gps_info = ""
            if event.latitude != 0.0 or event.longitude != 0.0:
                gps_info = f" GPS:({event.latitude:.3f},{event.longitude:.3f})"

            print(
                f"🚨 AMENAZA: {threat['type']} ({threat['model']}) - {event.source_ip}:{event.src_port} → {event.target_ip}:{event.dest_port}{gps_info}"
            )

    def incremental_training(self):
        """Entrenamiento incremental con ventana deslizante"""
        if len(self.sliding_window) < 1000:
            return

        print(
            f"🔄 Reentrenamiento incremental con {len(self.sliding_window)} muestras..."
        )

        # Convertir a DataFrame
        df = pd.DataFrame(list(self.sliding_window))

        # Preparar datos
        X = df.drop(["timestamp"], axis=1).values

        # Generar etiquetas simples (para demo)
        y = self._generate_simple_labels(df)

        # Reentrenar modelos rápidos
        self.train_lightweight_models(X, y)

    def _generate_simple_labels(self, df):
        """Generar etiquetas simples para entrenamiento"""
        labels = []
        for _, row in df.iterrows():
            # Heurística simple para etiquetado
            if (
                    row.get("port_category", 0) == 6
                    or row.get("packet_size", 0) > 8000  # High ports
                    or (  # Large packets
                    row.get("hour", 12) < 6 or row.get("hour", 12) > 22
            )
            ):  # Unusual hours
                labels.append(1)  # Suspicious
            else:
                labels.append(0)  # Normal

        return np.array(labels)

    def start_monitoring(self):
        """Iniciar monitoreo optimizado"""
        print("🚀 Iniciando monitoreo ML ligero...")
        print("📡 Esperando eventos del Enhanced Promiscuous Agent...")
        print("🔄 Configurado para recibir mensajes multipart ZeroMQ")  # AÑADIDO

        event_batch = []
        last_batch_process = time.time()

        try:
            while True:
                try:
                    # ⭐ FIX: Recibir mensaje multipart correctamente
                    topic, message = self.socket.recv_multipart(zmq.NOBLOCK)

                    # Debug: mostrar que estamos recibiendo eventos
                    if len(event_batch) == 0:  # Solo mostrar el primer evento
                        print(f"📨 Primer evento recibido - Topic: {topic.decode()}, Tamaño: {len(message)} bytes")

                    event = network_event_pb2.NetworkEvent()
                    event.ParseFromString(message)  # Ahora parseamos el mensaje correcto

                    event_batch.append(event)

                    # Procesar en lotes para eficiencia
                    if (
                            len(event_batch) >= self.cpu_config["batch_size"]
                            or time.time() - last_batch_process > 5
                    ):  # Máximo 5 segundos
                        self.process_event_batch(event_batch)
                        event_batch = []
                        last_batch_process = time.time()

                        # Reentrenamiento periódico
                        if len(self.sliding_window) >= 2000:
                            self.incremental_training()

                except zmq.Again:
                    time.sleep(0.1)

                    # Procesar lote parcial si hay timeout
                    if event_batch and time.time() - last_batch_process > 10:
                        self.process_event_batch(event_batch)
                        event_batch = []
                        last_batch_process = time.time()

                    continue

        except KeyboardInterrupt:
            print(f"\n🛑 Monitoreo detenido")
            if event_batch:  # Procesar eventos restantes
                self.process_event_batch(event_batch)

    # En lightweight_ml_detector.py, añadir al final de la clase LightweightThreatDetector:

    def save_models_quick(self):
        """Guardar modelos actuales con timestamp"""
        import joblib
        from datetime import datetime
        from pathlib import Path

        models_dir = Path("saved_models")
        models_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved_files = []

        # Guardar cada modelo
        for model_name, model in self.models.items():
            if model is not None:
                filename = models_dir / f"{model_name}_{timestamp}.joblib"
                joblib.dump(model, filename)
                saved_files.append(filename)
                print(f"💾 {model_name} → {filename}")

        # Guardar procesadores
        processors_file = models_dir / f"processors_{timestamp}.joblib"
        joblib.dump(self.processors, processors_file)
        print(f"💾 Procesadores → {processors_file}")

        print(f"✅ {len(saved_files)} modelos guardados")
        return saved_files

    def load_models_quick(self, timestamp=None):
        """Cargar modelos guardados"""
        import joblib
        from pathlib import Path

        models_dir = Path("saved_models")
        if not models_dir.exists():
            print("❌ No hay modelos guardados")
            return False

        # Si no se especifica timestamp, usar el más reciente
        if timestamp is None:
            model_files = list(models_dir.glob("isolation_forest_*.joblib"))
            if model_files:
                latest_file = max(model_files, key=lambda f: f.stat().st_mtime)
                timestamp = latest_file.stem.split('_')[-1]
            else:
                print("❌ No se encontraron modelos")
                return False

        print(f"📂 Cargando modelos del timestamp: {timestamp}")

        # Cargar modelos
        for model_name in self.models.keys():
            model_file = models_dir / f"{model_name}_{timestamp}.joblib"
            if model_file.exists():
                self.models[model_name] = joblib.load(model_file)
                print(f"📂 {model_name} ✓")

        # Cargar procesadores
        processors_file = models_dir / f"processors_{timestamp}.joblib"
        if processors_file.exists():
            self.processors = joblib.load(processors_file)
            print(f"📂 Procesadores ✓")

        return True

def main():
    """Función principal optimizada"""
    print("🤖 ML DETECTOR LIGERO - PUERTO CORREGIDO + MULTIPART FIX")
    print("=" * 55)
    print("🔧 FIX 1: Puerto 5560 → 5559")
    print("🔧 FIX 2: Recepción multipart ZeroMQ")
    print("📡 FUENTE: Enhanced Promiscuous Agent")
    print("🧠 ENTRENAMIENTO: Datos sintéticos + aprendizaje incremental")
    print("⚡ OPTIMIZADO: Intel i9 + 32GB RAM")
    print("=" * 55)

    detector = LightweightThreatDetector()

    if detector.connect():
        # Entrenamiento inicial
        X_initial = np.random.rand(1000, 17)
        y_initial = np.random.choice([0, 1], 1000)

        detector.train_lightweight_models(X_initial, y_initial)

        # ⭐ AÑADIR: Guardar modelos automáticamente
        detector.save_models_quick()

        try:
            detector.start_monitoring()
        finally:
            detector.socket.close()
            detector.context.term()


if __name__ == "__main__":
    main()