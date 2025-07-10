#!/usr/bin/env python3
"""
Lightweight ML Detector para Upgraded-Happiness
REFACTORIZADO: Lee TODA la configuración desde JSON
Usa lightweight_ml_detector_config.json para TODA la configuración
Puerto configurable (entrada desde promiscuous_agent) - Puerto configurable (salida a dashboard)
"""

import zmq
import time
import logging
import threading
import numpy as np
import json
import os
import sys
from collections import deque, defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Configurar logging básico (se reconfigurará desde JSON)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Importar protobuf - USAR ESTRUCTURAS REALES
try:
    from src.protocols.protobuf import network_event_extended_fixed_pb2

    PROTOBUF_AVAILABLE = True
    logger.info("✅ Protobuf network_event_extended_fixed_pb2 importado desde src.protocols.protobuf")
except ImportError:
    try:
        import network_event_extended_fixed_pb2

        PROTOBUF_AVAILABLE = True
        logger.info("✅ Protobuf network_event_extended_fixed_pb2 importado desde directorio local")
    except ImportError:
        PROTOBUF_AVAILABLE = False
        logger.error("❌ Protobuf no disponible")

# Importar ML dependencies
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    ML_AVAILABLE = True
    logger.info("✅ Scikit-learn disponible para ML")
except ImportError:
    ML_AVAILABLE = False
    logger.warning("⚠️  Scikit-learn no disponible - ML deshabilitado")

# Importar geoip
try:
    import geoip2.database
    import geoip2.errors

    GEOIP_AVAILABLE = True
    logger.info("✅ GeoIP2 disponible")
except ImportError:
    GEOIP_AVAILABLE = False
    logger.warning("⚠️  GeoIP2 no disponible")


class SimpleMLModel:
    """Modelo ML simple para detección de anomalías configurado desde JSON"""

    def __init__(self, ml_config: Dict):
        """Inicializar modelo ML desde configuración JSON"""
        self.config = ml_config

        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.training_data = deque(maxlen=self.config.get('training', {}).get('min_training_samples', 1000))

        # Características desde configuración
        self.feature_names = self.config.get('features', [
            'packet_size', 'dest_port', 'src_port',
            'hour', 'minute', 'is_weekend',
            'ip_entropy', 'port_frequency'
        ])

        # Configuración del modelo desde JSON
        self.confidence_threshold = self.config.get('confidence_threshold', 0.7)
        self.contamination_rate = self.config.get('training', {}).get('contamination_rate', 0.1)

        # Estadísticas para features
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)

        if ML_AVAILABLE:
            self.anomaly_detector = IsolationForest(
                contamination=self.contamination_rate,
                random_state=42,
                n_estimators=100
            )
            logger.info("🤖 Modelo ML inicializado desde configuración JSON")
        else:
            logger.warning("⚠️  Modelo ML no disponible - usando heurísticas")

    def extract_features(self, event_data: Dict) -> np.ndarray:
        """Extrae características del evento para ML"""

        # Características básicas
        packet_size = event_data.get('packet_size', 0)
        dest_port = event_data.get('dest_port', 0)
        src_port = event_data.get('src_port', 0)

        # Características temporales
        now = datetime.now()
        hour = now.hour
        minute = now.minute
        is_weekend = 1 if now.weekday() >= 5 else 0

        # Características de IP (entropía simple)
        source_ip = event_data.get('source_ip', '')
        ip_entropy = len(set(source_ip.replace('.', ''))) / max(len(source_ip), 1)

        # Frecuencia de puerto
        self.port_stats[dest_port] += 1
        port_frequency = self.port_stats[dest_port]

        return np.array([
            packet_size, dest_port, src_port,
            hour, minute, is_weekend,
            ip_entropy, port_frequency
        ])

    def train_or_update(self, features: np.ndarray):
        """Entrena o actualiza el modelo usando configuración"""
        if not ML_AVAILABLE:
            return

        self.training_data.append(features)

        min_samples = self.config.get('training', {}).get('min_training_samples', 100)

        # Entrenar cuando tengamos suficientes datos
        if len(self.training_data) >= min_samples and not self.is_trained:
            X = np.array(list(self.training_data))
            X_scaled = self.scaler.fit_transform(X)
            self.anomaly_detector.fit(X_scaled)
            self.is_trained = True
            logger.info("🎯 Modelo ML entrenado con %d muestras", len(self.training_data))

        # Reentrenar periódicamente según configuración
        retrain_samples = self.config.get('training', {}).get('retrain_interval_samples', 200)
        if self.is_trained and len(self.training_data) % retrain_samples == 0:
            X = np.array(list(self.training_data))
            X_scaled = self.scaler.fit_transform(X)
            self.anomaly_detector.fit(X_scaled)
            logger.info("🔄 Modelo ML reentrenado")

    def predict_anomaly(self, features: np.ndarray) -> Tuple[float, float]:
        """Predice anomalía y score de riesgo usando configuración"""

        if not ML_AVAILABLE or not self.is_trained:
            # Usar heurísticas simples
            return self._heuristic_prediction(features)

        try:
            # Usar modelo ML
            X_scaled = self.scaler.transform(features.reshape(1, -1))
            anomaly_score = self.anomaly_detector.decision_function(X_scaled)[0]

            # Normalizar score (-1 a 1) -> (0 a 1)
            anomaly_score = max(0, min(1, (1 - anomaly_score) / 2))

            # Calcular risk score basado en múltiples factores
            risk_score = self._calculate_risk_score(features, anomaly_score)

            return anomaly_score, risk_score

        except Exception as e:
            logger.error("Error en predicción ML: %s", e)
            return self._heuristic_prediction(features)

    def _heuristic_prediction(self, features: np.ndarray) -> Tuple[float, float]:
        """Predicción heurística cuando ML no está disponible"""

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
        if dest_port > 49152 or (dest_port < 1024 and dest_port not in [80, 443, 22, 21]):
            anomaly_score += 0.2

        # Heurística 4: Combinaciones sospechosas
        if dest_port == 22 and packet_size < 100:  # SSH con paquetes pequeños
            risk_score += 0.3

        return min(anomaly_score, 1.0), min(risk_score, 1.0)

    def _calculate_risk_score(self, features: np.ndarray, anomaly_score: float) -> float:
        """Calcula score de riesgo basado en múltiples factores"""

        packet_size, dest_port, src_port = features[0], features[1], features[2]
        hour = features[3]

        risk_score = anomaly_score * 0.5  # Base del score de anomalía

        # Factor 1: Puertos de alto riesgo
        high_risk_ports = [22, 23, 135, 139, 445, 1433, 3389, 5900]
        if dest_port in high_risk_ports:
            risk_score += 0.3

        # Factor 2: Horario sospechoso (madrugada)
        if hour >= 0 and hour <= 5:
            risk_score += 0.1

        # Factor 3: Tamaño de paquete anómalo
        if packet_size > 1400:
            risk_score += 0.2

        # Factor 4: Puertos dinámicos como destino
        if dest_port > 49152:
            risk_score += 0.15

        return min(risk_score, 1.0)


class GeoIPEnricher:
    """Enriquecedor geográfico para IPs configurado desde JSON"""

    def __init__(self, db_path: str = None, geoip_config: Dict = None):
        """Inicializar GeoIP enricher desde configuración"""
        self.config = geoip_config or {}
        self.reader = None
        self.enabled = False

        # Cache configurado desde JSON
        self.cache = {}
        self.cache_max_size = self.config.get('cache_size', 10000)
        self.cache_ttl = self.config.get('cache_ttl_seconds', 3600)

        if GEOIP_AVAILABLE and db_path:
            try:
                self.reader = geoip2.database.Reader(db_path)
                self.enabled = True
                logger.info("🌍 GeoIP database cargada: %s", db_path)
            except Exception as e:
                logger.warning("⚠️  Error cargando GeoIP database: %s", e)
        else:
            logger.warning("⚠️  GeoIP no disponible o sin base de datos")

    def enrich_ip(self, ip: str) -> Tuple[Optional[float], Optional[float]]:
        """Enriquece IP con coordenadas geográficas usando cache"""

        if not self.enabled or not ip or ip == 'unknown':
            return None, None

        # Verificar cache
        if ip in self.cache:
            cache_entry = self.cache[ip]
            if time.time() - cache_entry['timestamp'] < self.cache_ttl:
                return cache_entry['lat'], cache_entry['lon']

        try:
            response = self.reader.city(ip)
            latitude = float(response.location.latitude) if response.location.latitude else None
            longitude = float(response.location.longitude) if response.location.longitude else None

            # Guardar en cache
            if latitude is not None and longitude is not None:
                self._cache_result(ip, latitude, longitude)

            return latitude, longitude

        except geoip2.errors.AddressNotFoundError:
            self._cache_result(ip, None, None)
            return None, None
        except Exception as e:
            logger.debug("Error en GeoIP para %s: %s", ip, e)
            return None, None

    def _cache_result(self, ip: str, lat: Optional[float], lon: Optional[float]):
        """Guarda resultado en cache con TTL"""
        # Limpiar cache si está lleno
        if len(self.cache) >= self.cache_max_size:
            # Eliminar entradas más antiguas
            oldest_entries = sorted(
                self.cache.items(),
                key=lambda x: x[1]['timestamp']
            )[:self.cache_max_size // 2]

            for old_ip, _ in oldest_entries:
                del self.cache[old_ip]

        self.cache[ip] = {
            'lat': lat,
            'lon': lon,
            'timestamp': time.time()
        }

    def close(self):
        """Cierra la base de datos GeoIP"""
        if self.reader:
            self.reader.close()


class LightweightMLDetector:
    """Detector ML ligero configurado completamente desde JSON"""

    def __init__(self, config_file=None):
        """Inicializar detector desde configuración JSON"""
        self.config = self._load_config(config_file)
        self.config_file = config_file

        # Configurar logging desde JSON PRIMERO
        self._setup_logging()

        # Todas las configuraciones de red desde JSON
        self.input_port = self.config['network']['listen_port']
        self.output_port = self.config['network']['publish_port']
        self.bind_address = self.config['network']['bind_address']
        self.socket_timeout = self.config['network']['socket_timeout']

        # Configuración de detección desde JSON
        self.window_size = self.config['detection']['window_size_seconds']
        self.batch_size = self.config['detection']['batch_size']
        self.anomaly_threshold = self.config['detection']['anomaly_threshold']
        self.alert_cooldown = self.config['detection']['alert_cooldown_seconds']
        self.min_samples = self.config['detection']['min_samples_for_detection']

        # Configuración de performance desde JSON
        self.max_buffer_size = self.config['data_processing']['max_buffer_size']
        self.processing_timeout = self.config['performance']['processing_timeout_seconds']

        self.running = False

        # ZeroMQ setup desde configuración
        zmq_threads = self.config['network']['zmq_context_threads']
        self.context = zmq.Context(zmq_threads)
        self.input_socket = None
        self.output_socket = None

        # Componentes ML con configuración
        self.ml_model = SimpleMLModel(self.config.get('ml_model', {}))

        # GeoIP con configuración
        geoip_db_path = self.config.get('geoip', {}).get('database_path')
        self.geoip_enricher = GeoIPEnricher(geoip_db_path, self.config.get('geoip', {}))

        # Estadísticas
        self.stats = {
            'events_processed': 0,
            'events_enriched': 0,
            'anomalies_detected': 0,
            'high_risk_events': 0,
            'geoip_enriched': 0,
            'handshakes_processed': 0,
            'start_time': time.time(),
            'model_predictions': 0,
            'heuristic_predictions': 0,
            'cache_hits': 0,
            'processing_errors': 0
        }

        # Buffer para procesamiento configurado desde JSON
        self.event_buffer = deque(maxlen=self.max_buffer_size)

        # Alertas configuradas desde JSON
        self.alerts_enabled = self.config['alerts']['enabled']
        self.alert_levels = self.config['alerts']['severity_levels']

        # Performance monitoring
        self.performance_config = self.config.get('performance', {})
        self.max_cpu_usage = self.performance_config.get('max_cpu_usage_percent', 80)
        self.max_memory_usage = self.performance_config.get('max_memory_usage_mb', 512)

        # Persistencia configurada desde JSON
        if self.config['persistence']['save_predictions']:
            self.predictions_file = self.config['persistence']['predictions_file']
            self.auto_save_interval = self.config['persistence']['auto_save_interval']
            self._setup_persistence()

        logger.info("🤖 LightweightMLDetector initialized from JSON config")
        logger.info("Config file: %s", config_file or 'default config')
        logger.info("📡 Input port: %d", self.input_port)
        logger.info("📤 Output port: %d", self.output_port)
        logger.info("🧠 ML disponible: %s", ML_AVAILABLE)
        logger.info("🌍 GeoIP disponible: %s", GEOIP_AVAILABLE)
        logger.info("📦 Protobuf disponible: %s", PROTOBUF_AVAILABLE)
        logger.info("🎯 Detection threshold: %.2f", self.anomaly_threshold)

    def _load_config(self, config_file):
        """Cargar configuración desde archivo JSON"""
        default_config = {
            "agent_info": {
                "name": "lightweight_ml_detector",
                "version": "1.0.0",
                "description": "Detector ML ligero para análisis de tráfico de red"
            },
            "network": {
                "listen_port": 5559,
                "publish_port": 5560,
                "bind_address": "*",
                "zmq_context_threads": 1,
                "socket_timeout": 3000,
                "max_message_size": 1048576
            },
            "ml_model": {
                "model_type": "isolation_forest",
                "model_path": "models/lightweight_detector.pkl",
                "auto_retrain": True,
                "retrain_interval_hours": 24,
                "confidence_threshold": 0.7,
                "features": [
                    "packet_size", "packets_per_second", "unique_ips",
                    "port_diversity", "protocol_distribution", "time_intervals"
                ],
                "training": {
                    "initial_training_required": False,
                    "validation_split": 0.2,
                    "auto_update_model": True,
                    "contamination_rate": 0.1,
                    "min_training_samples": 1000,
                    "retrain_interval_samples": 200
                }
            },
            "detection": {
                "window_size_seconds": 60,
                "sliding_window": True,
                "batch_size": 100,
                "anomaly_threshold": 0.8,
                "alert_cooldown_seconds": 300,
                "min_samples_for_detection": 50
            },
            "data_processing": {
                "max_buffer_size": 10000,
                "preprocessing": {
                    "normalize_features": True,
                    "remove_outliers": True,
                    "outlier_std_threshold": 3.0
                },
                "feature_engineering": {
                    "create_temporal_features": True,
                    "create_statistical_features": True,
                    "rolling_window_size": 10
                }
            },
            "alerts": {
                "enabled": True,
                "severity_levels": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                "notification_channels": ["zmq", "log"],
                "alert_aggregation": {
                    "enabled": True,
                    "window_minutes": 5,
                    "max_alerts_per_window": 10
                }
            },
            "performance": {
                "max_cpu_usage_percent": 80,
                "max_memory_usage_mb": 512,
                "processing_timeout_seconds": 30,
                "parallel_processing": {
                    "enabled": False,
                    "max_workers": 2
                }
            },
            "logging": {
                "level": "INFO",
                "file": "logs/ml_detector.log",
                "max_size_mb": 20,
                "backup_count": 3,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "console_output": True,
                "log_predictions": False
            },
            "monitoring": {
                "health_check_interval": 45,
                "metrics_collection": True,
                "performance_monitoring": True,
                "model_drift_detection": {
                    "enabled": True,
                    "check_interval_hours": 6,
                    "drift_threshold": 0.1
                }
            },
            "persistence": {
                "save_predictions": True,
                "predictions_file": "data/predictions.jsonl",
                "save_model_state": True,
                "state_file": "data/ml_detector_state.json",
                "auto_save_interval": 300
            },
            "geoip": {
                "database_path": "GeoLite2-City.mmdb",
                "cache_size": 10000,
                "cache_ttl_seconds": 3600
            }
        }

        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)

                # Merge recursivo de configuraciones
                self._merge_config(default_config, user_config)
                logger.info(f"📄 Configuración ML cargada desde {config_file}")

            except Exception as e:
                logger.error(f"❌ Error cargando configuración ML: {e}")
                logger.info("⚠️ Usando configuración por defecto")
        else:
            if config_file:
                logger.warning(f"⚠️ Archivo de configuración ML no encontrado: {config_file}")
            logger.info("⚠️ Usando configuración ML por defecto")

        return default_config

    def _merge_config(self, base, update):
        """Merge recursivo de configuraciones"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def _setup_logging(self):
        """Configurar logging desde configuración JSON"""
        log_config = self.config.get('logging', {})

        # Configurar nivel
        level = getattr(logging, log_config.get('level', 'INFO').upper())
        logger.setLevel(level)

        # Limpiar handlers existentes
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        # Formatter desde configuración
        formatter = logging.Formatter(
            log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )

        # Console handler si está habilitado
        if log_config.get('console_output', True):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        # File handler si se especifica archivo
        if log_config.get('file'):
            # Crear directorio si no existe
            log_file = log_config['file']
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=log_config.get('max_size_mb', 20) * 1024 * 1024,
                backupCount=log_config.get('backup_count', 3)
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    def _setup_persistence(self):
        """Configurar persistencia desde JSON"""
        # Crear directorio para predictions si no existe
        predictions_dir = os.path.dirname(self.predictions_file)
        if predictions_dir and not os.path.exists(predictions_dir):
            os.makedirs(predictions_dir, exist_ok=True)

        # Abrir archivo de predicciones
        self.predictions_file_handle = None
        try:
            self.predictions_file_handle = open(self.predictions_file, 'a')
        except Exception as e:
            logger.warning(f"⚠️ No se pudo abrir archivo de predicciones: {e}")

    def start(self):
        """Inicia el detector ML usando configuración JSON"""
        try:
            # Configurar sockets usando configuración
            self.input_socket = self.context.socket(zmq.SUB)
            input_addr = f"tcp://localhost:{self.input_port}"
            self.input_socket.connect(input_addr)
            self.input_socket.setsockopt(zmq.SUBSCRIBE, b"")
            self.input_socket.setsockopt(zmq.RCVTIMEO, self.socket_timeout)

            self.output_socket = self.context.socket(zmq.PUB)
            output_addr = f"tcp://{self.bind_address}:{self.output_port}"
            self.output_socket.bind(output_addr)

            self.running = True

            print(f"\n🤖 Lightweight ML Detector Started (JSON CONFIG)")
            print(f"📄 Config: {self.config_file or 'default'}")
            print(f"📡 Input: {input_addr} (from promiscuous_agent)")
            print(f"📤 Output: {output_addr} (to dashboard)")
            print(f"📦 Protobuf: {'✅ Available' if PROTOBUF_AVAILABLE else '❌ Not available'}")
            print(f"🧠 ML: {'✅ Available' if ML_AVAILABLE else '❌ Heuristics only'}")
            print(f"🌍 GeoIP: {'✅ Available' if self.geoip_enricher.enabled else '❌ Not available'}")
            print(f"🎯 Anomaly threshold: {self.anomaly_threshold}")
            print(f"📊 Buffer size: {self.max_buffer_size}")
            print(f"⚡ Batch size: {self.batch_size}")
            print(f"🔔 Alerts: {'✅ Enabled' if self.alerts_enabled else '❌ Disabled'}")
            print("=" * 70)

            # Thread principal de procesamiento
            processing_thread = threading.Thread(target=self._processing_loop, daemon=True)
            processing_thread.start()

            # Thread de estadísticas configurado desde JSON
            stats_interval = self.config['monitoring']['health_check_interval']
            stats_thread = threading.Thread(target=self._stats_loop, args=(stats_interval,), daemon=True)
            stats_thread.start()

            # Thread de auto-guardado si está habilitado
            if self.config['persistence']['save_predictions']:
                save_thread = threading.Thread(target=self._auto_save_loop, daemon=True)
                save_thread.start()

            # Mantener vivo
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n🛑 Stopping ML detector...")
                self.running = False

        except Exception as e:
            logger.error("Error starting ML detector: %s", e)
            raise
        finally:
            self.cleanup()

    def _processing_loop(self):
        """Loop principal de procesamiento"""
        logger.info("🔄 Iniciando loop de procesamiento...")

        while self.running:
            try:
                # Recibir evento con timeout configurado
                message = self.input_socket.recv(zmq.NOBLOCK)
                self.stats['events_processed'] += 1

                # Procesar evento
                enriched_event = self._process_event(message)

                if enriched_event:
                    # Enviar evento enriquecido
                    self.output_socket.send(enriched_event)
                    self.stats['events_enriched'] += 1

            except zmq.Again:
                continue  # Timeout - continuar
            except Exception as e:
                logger.error("Error en processing loop: %s", e)
                self.stats['processing_errors'] += 1
                time.sleep(0.1)

    def _process_event(self, message: bytes) -> Optional[bytes]:
        """Procesa un evento individual usando estructuras protobuf reales"""

        if not PROTOBUF_AVAILABLE:
            logger.warning("Protobuf no disponible - no se puede procesar evento")
            return None

        try:
            # Parsear evento protobuf entrante
            event = network_event_extended_fixed_pb2.NetworkEvent()
            event.ParseFromString(message)

            # Convertir a diccionario para procesamiento
            event_dict = {
                'event_id': event.event_id,
                'source_ip': event.source_ip,
                'target_ip': event.target_ip,
                'packet_size': event.packet_size,
                'dest_port': event.dest_port,
                'src_port': event.src_port,
                'agent_id': event.agent_id,
                'event_type': event.event_type,
                'description': event.description,
                'so_identifier': event.so_identifier,
                'node_hostname': event.node_hostname,
                'os_version': event.os_version,
                'firewall_status': event.firewall_status,
                'agent_version': event.agent_version,
                'is_initial_handshake': event.is_initial_handshake
            }

            # Procesar handshake inicial
            if event.is_initial_handshake:
                self.stats['handshakes_processed'] += 1
                logger.info(f"🤝 Procesando handshake inicial de {event.agent_id} ({event.so_identifier})")

                # Para handshakes, solo pasamos la información sin ML
                enriched_event = network_event_extended_fixed_pb2.NetworkEvent()
                enriched_event.CopyFrom(event)  # Copiar todo el evento original

                # Enriquecer con GeoIP si está disponible
                if event.source_ip and event.source_ip != 'unknown':
                    latitude, longitude = self.geoip_enricher.enrich_ip(event.source_ip)
                    if latitude is not None and longitude is not None:
                        enriched_event.latitude = latitude
                        enriched_event.longitude = longitude
                        self.stats['geoip_enriched'] += 1

                return enriched_event.SerializeToString()

            # Para eventos normales, aplicar ML
            # Extraer features para ML
            features = self.ml_model.extract_features(event_dict)

            # Entrenar/actualizar modelo
            self.ml_model.train_or_update(features)

            # Predecir anomalía y riesgo
            anomaly_score, risk_score = self.ml_model.predict_anomaly(features)

            # Actualizar estadísticas según configuración
            if ML_AVAILABLE and self.ml_model.is_trained:
                self.stats['model_predictions'] += 1
            else:
                self.stats['heuristic_predictions'] += 1

            # Estadísticas según umbrales de configuración
            if anomaly_score > self.anomaly_threshold:
                self.stats['anomalies_detected'] += 1

            high_risk_threshold = self.config['detection'].get('high_risk_threshold', 0.8)
            if risk_score > high_risk_threshold:
                self.stats['high_risk_events'] += 1

            # Enriquecer con GeoIP
            latitude, longitude = self.geoip_enricher.enrich_ip(event.source_ip)
            if latitude is not None and longitude is not None:
                self.stats['geoip_enriched'] += 1

            # Crear evento enriquecido usando toda la estructura protobuf
            enriched_event = network_event_extended_fixed_pb2.NetworkEvent()

            # Copiar campos originales
            enriched_event.event_id = event.event_id
            enriched_event.timestamp = event.timestamp
            enriched_event.source_ip = event.source_ip
            enriched_event.target_ip = event.target_ip
            enriched_event.packet_size = event.packet_size
            enriched_event.dest_port = event.dest_port
            enriched_event.src_port = event.src_port
            enriched_event.agent_id = event.agent_id
            enriched_event.event_type = event.event_type
            enriched_event.description = event.description

            # Copiar campos adicionales del protobuf real
            enriched_event.so_identifier = event.so_identifier
            enriched_event.node_hostname = event.node_hostname
            enriched_event.os_version = event.os_version
            enriched_event.firewall_status = event.firewall_status
            enriched_event.agent_version = event.agent_version
            enriched_event.is_initial_handshake = event.is_initial_handshake

            # Agregar enriquecimiento ML
            enriched_event.anomaly_score = anomaly_score
            enriched_event.risk_score = risk_score

            # Agregar coordenadas GPS si están disponibles
            if latitude is not None and longitude is not None:
                enriched_event.latitude = latitude
                enriched_event.longitude = longitude

            # Enriquecer descripción según configuración
            if anomaly_score > self.config['detection'].get('description_threshold', 0.5) or \
                    risk_score > self.config['detection'].get('description_threshold', 0.5):
                ml_info = f"ML: A:{anomaly_score:.2f} R:{risk_score:.2f}"
                if event.description:
                    enriched_event.description = f"{ml_info} | {event.description}"
                else:
                    enriched_event.description = ml_info

            # Guardar predicción si está configurado
            if self.config['persistence']['save_predictions'] and \
                    self.config['logging'].get('log_predictions', False):
                self._save_prediction(event_dict, anomaly_score, risk_score)

            logger.debug("📊 Evento enriquecido: %s A:%.2f R:%.2f",
                         event.event_id, anomaly_score, risk_score)

            return enriched_event.SerializeToString()

        except Exception as e:
            logger.error("Error procesando evento: %s", e)
            self.stats['processing_errors'] += 1
            return None

    def _save_prediction(self, event_dict: Dict, anomaly_score: float, risk_score: float):
        """Guarda predicción en archivo si está configurado"""
        if not hasattr(self, 'predictions_file_handle') or not self.predictions_file_handle:
            return

        try:
            prediction_record = {
                'timestamp': time.time(),
                'event_id': event_dict.get('event_id'),
                'source_ip': event_dict.get('source_ip'),
                'anomaly_score': anomaly_score,
                'risk_score': risk_score,
                'features': {
                    'packet_size': event_dict.get('packet_size'),
                    'dest_port': event_dict.get('dest_port'),
                    'src_port': event_dict.get('src_port')
                }
            }

            self.predictions_file_handle.write(json.dumps(prediction_record) + '\n')
            self.predictions_file_handle.flush()

        except Exception as e:
            logger.error(f"Error guardando predicción: {e}")

    def _stats_loop(self, interval: int):
        """Loop de estadísticas configurado desde JSON"""
        while self.running:
            try:
                time.sleep(interval)
                self._print_stats()

                # Monitoring de performance si está habilitado
                if self.config['monitoring']['performance_monitoring']:
                    self._check_performance()

            except Exception as e:
                logger.error("Error en stats loop: %s", e)

    def _check_performance(self):
        """Verifica performance según configuración"""
        try:
            import psutil

            # CPU usage
            cpu_percent = psutil.cpu_percent()
            if cpu_percent > self.max_cpu_usage:
                logger.warning(f"⚠️ Alta CPU usage: {cpu_percent}% (límite: {self.max_cpu_usage}%)")

            # Memory usage
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            if memory_mb > self.max_memory_usage:
                logger.warning(f"⚠️ Alta memoria usage: {memory_mb:.1f}MB (límite: {self.max_memory_usage}MB)")

        except ImportError:
            pass  # psutil no disponible
        except Exception as e:
            logger.debug(f"Error en performance check: {e}")

    def _auto_save_loop(self):
        """Loop de auto-guardado configurado desde JSON"""
        save_interval = self.auto_save_interval

        while self.running:
            try:
                time.sleep(save_interval)
                self._save_state()
            except Exception as e:
                logger.error(f"Error en auto-save: {e}")

    def _save_state(self):
        """Guarda estado según configuración"""
        if not self.config['persistence']['save_model_state']:
            return

        try:
            state_file = self.config['persistence']['state_file']

            # Crear directorio si no existe
            state_dir = os.path.dirname(state_file)
            if state_dir and not os.path.exists(state_dir):
                os.makedirs(state_dir, exist_ok=True)

            state = {
                'stats': self.stats,
                'ml_model_trained': self.ml_model.is_trained,
                'training_samples': len(self.ml_model.training_data),
                'config_file': self.config_file,
                'last_saved': time.time()
            }

            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)

        except Exception as e:
            logger.error(f"❌ Error guardando estado ML: {e}")

    def _print_stats(self):
        """Imprime estadísticas configuradas desde JSON"""
        uptime = time.time() - self.stats['start_time']

        print(f"\n📊 ML Detector Stats (JSON CONFIG) - Uptime: {uptime:.0f}s")
        print(f"📥 Events Processed: {self.stats['events_processed']}")
        print(f"📤 Events Enriched: {self.stats['events_enriched']}")
        print(f"🚨 Anomalies Detected: {self.stats['anomalies_detected']}")
        print(f"⚠️  High Risk Events: {self.stats['high_risk_events']}")
        print(f"🌍 GeoIP Enriched: {self.stats['geoip_enriched']}")
        print(f"🤝 Handshakes Processed: {self.stats['handshakes_processed']}")
        print(f"🤖 ML Model Trained: {self.ml_model.is_trained}")
        print(f"📚 Training Samples: {len(self.ml_model.training_data)}")
        print(f"🎯 ML Predictions: {self.stats['model_predictions']}")
        print(f"🔧 Heuristic Predictions: {self.stats['heuristic_predictions']}")
        print(f"❌ Processing Errors: {self.stats['processing_errors']}")
        print(f"📄 Config: {self.config_file or 'default'}")
        print("-" * 50)

    def get_statistics(self) -> Dict:
        """Retorna estadísticas completas"""
        uptime = time.time() - self.stats['start_time']

        return {
            'uptime_seconds': uptime,
            'events_processed': self.stats['events_processed'],
            'events_enriched': self.stats['events_enriched'],
            'anomalies_detected': self.stats['anomalies_detected'],
            'high_risk_events': self.stats['high_risk_events'],
            'geoip_enriched': self.stats['geoip_enriched'],
            'handshakes_processed': self.stats['handshakes_processed'],
            'ml_model_trained': self.ml_model.is_trained,
            'training_samples': len(self.ml_model.training_data),
            'model_predictions': self.stats['model_predictions'],
            'heuristic_predictions': self.stats['heuristic_predictions'],
            'processing_errors': self.stats['processing_errors'],
            'protobuf_available': PROTOBUF_AVAILABLE,
            'ml_available': ML_AVAILABLE,
            'geoip_available': self.geoip_enricher.enabled,
            'config_file': self.config_file,
            'configuration': {
                'input_port': self.input_port,
                'output_port': self.output_port,
                'anomaly_threshold': self.anomaly_threshold,
                'batch_size': self.batch_size,
                'buffer_size': self.max_buffer_size,
                'alerts_enabled': self.alerts_enabled
            }
        }

    def cleanup(self):
        """Limpia recursos y guarda estado final"""
        # Guardar estado final
        if self.config['persistence']['save_model_state']:
            self._save_state()

        # Cerrar archivo de predicciones
        if hasattr(self, 'predictions_file_handle') and self.predictions_file_handle:
            self.predictions_file_handle.close()

        if self.input_socket:
            self.input_socket.close()
        if self.output_socket:
            self.output_socket.close()
        if self.context:
            self.context.term()
        if self.geoip_enricher:
            self.geoip_enricher.close()


def main():
    """Función principal con configuración JSON completa"""
    import argparse

    parser = argparse.ArgumentParser(description='Lightweight ML Detector (JSON Config)')
    parser.add_argument('config_file', nargs='?',
                        default='lightweight_ml_detector_config.json',
                        help='Archivo de configuración JSON')
    parser.add_argument('--test-config', action='store_true',
                        help='Validar configuración y salir')

    args = parser.parse_args()

    if args.test_config:
        try:
            detector = LightweightMLDetector(config_file=args.config_file)
            print("✅ Configuración JSON válida")
            stats = detector.get_statistics()
            print(f"📡 Input port: {stats['configuration']['input_port']}")
            print(f"📤 Output port: {stats['configuration']['output_port']}")
            print(f"🎯 Threshold: {stats['configuration']['anomaly_threshold']}")
            return 0
        except Exception as e:
            print(f"❌ Error en configuración: {e}")
            return 1

    if not PROTOBUF_AVAILABLE:
        print("❌ Error: Protobuf no disponible")
        print("📦 Instalar con: pip install protobuf")
        return 1

    try:
        detector = LightweightMLDetector(config_file=args.config_file)

        print(f"\n🤖 ML Detector iniciado con configuración JSON:")
        stats = detector.get_statistics()
        print(f"   📡 Input port: {stats['configuration']['input_port']}")
        print(f"   📤 Output port: {stats['configuration']['output_port']}")
        print(f"   🎯 Anomaly threshold: {stats['configuration']['anomaly_threshold']}")
        print(f"   📊 Buffer size: {stats['configuration']['buffer_size']}")
        print(f"   🔔 Alerts: {'✅' if stats['configuration']['alerts_enabled'] else '❌'}")

        detector.start()

    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        logger.error("Error fatal: %s", e)
        return 1
    finally:
        if 'detector' in locals():
            detector._print_stats()

    return 0


if __name__ == "__main__":
    sys.exit(main())