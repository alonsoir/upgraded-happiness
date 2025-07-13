#!/usr/bin/env python3
"""
Lightweight ML Detector para Upgraded-Happiness (LIMPIO)
REFACTORIZADO: Lee TODA la configuración desde JSON
RESPONSABILIDAD ÚNICA: Análisis ML + scoring de eventos
ELIMINADO: GeoIP logic (ahora en geoip_enricher.py)
CORREGIDO: ZMQ pattern PULL/PUSH para pipeline secuencial
"""

import zmq
import time
import logging
import threading
import numpy as np
import json
import os
import sys
import math
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


class LightweightMLDetector:
    """Detector ML ligero configurado completamente desde JSON (SIN GeoIP)"""

    def __init__(self, config_file=None):
        """Inicializar detector desde configuración JSON"""
        self.config = self._load_config(config_file)
        self.config_file = config_file

        # Configurar logging desde JSON PRIMERO
        self._setup_logging()

        # Configuraciones de red desde JSON (NUEVA ARQUITECTURA)
        self.input_port = self.config['zmq']['input_port']  # 5560 desde geoip_enricher
        self.output_port = self.config['zmq']['output_port']  # 5561 hacia dashboard
        self.context_threads = self.config['zmq']['context_threads']
        self.high_water_mark = self.config['zmq']['high_water_mark']

        # Configuración ML desde JSON
        self.ml_config = self.config.get('ml', {})
        self.ml_enabled = self.ml_config.get('enabled', True)
        self.anomaly_threshold = self.ml_config.get('anomaly_threshold', 0.8)
        self.high_risk_threshold = self.ml_config.get('high_risk_threshold', 0.9)
        self.buffer_size = self.ml_config.get('buffer_size', 10000)
        self.batch_size = self.ml_config.get('batch_size', 100)

        # Configuración de processing desde JSON
        self.processing_config = self.config.get('processing', {})
        self.enable_heuristics = self.processing_config.get('enable_heuristics', True)
        self.enable_alerts = self.processing_config.get('enable_alerts', True)
        self.stats_interval = self.processing_config.get('stats_interval', 45)
        self.max_processing_time = self.processing_config.get('max_processing_time', 5.0)

        self.running = False

        # ZeroMQ setup desde configuración
        self.context = zmq.Context(self.context_threads)
        self.input_socket = None
        self.output_socket = None

        # Componente ML (ÚNICA responsabilidad)
        self.ml_model = SimpleMLModel(self.ml_config)

        # Estadísticas (SIN coordenadas, solo ML)
        self.stats = {
            'events_processed': 0,
            'events_enriched': 0,
            'anomalies_detected': 0,
            'high_risk_events': 0,
            'handshakes_processed': 0,
            'start_time': time.time(),
            'model_predictions': 0,
            'heuristic_predictions': 0,
            'processing_errors': 0
        }

        # Buffer para procesamiento configurado desde JSON
        self.event_buffer = deque(maxlen=self.buffer_size)

        # Persistencia configurada desde JSON
        self.persistence_config = self.config.get('persistence', {})
        if self.persistence_config.get('save_predictions', False):
            self.predictions_file = self.persistence_config.get('predictions_file', 'data/predictions.jsonl')
            self.auto_save_interval = self.persistence_config.get('auto_save_interval', 300)
            self._setup_persistence()

        logger.info("🤖 LightweightMLDetector inicializado (LIMPIO - Sin GeoIP)")
        logger.info("Config file: %s", config_file or 'default config')
        logger.info("📡 Input port: %d (desde geoip_enricher)", self.input_port)
        logger.info("📤 Output port: %d (hacia dashboard)", self.output_port)
        logger.info("🧠 ML enabled: %s", self.ml_enabled)
        logger.info("📦 Protobuf disponible: %s", PROTOBUF_AVAILABLE)
        logger.info("🎯 Anomaly threshold: %.2f", self.anomaly_threshold)
        logger.info("🧹 LIMPIO: Sin GeoIP - solo análisis ML")

    def _load_config(self, config_file):
        """Cargar configuración desde archivo JSON (SIN sección GeoIP)"""
        default_config = {
            "agent_info": {
                "name": "lightweight_ml_detector",
                "version": "1.0.0",
                "description": "Detector ML ligero para análisis de tráfico (sin GeoIP)"
            },
            "zmq": {
                "input_port": 5560,
                "output_port": 5561,
                "context_threads": 1,
                "high_water_mark": 1000
            },
            "ml": {
                "enabled": True,
                "anomaly_threshold": 0.8,
                "high_risk_threshold": 0.9,
                "models": ["IsolationForest"],
                "buffer_size": 10000,
                "batch_size": 100,
                "training_interval": 3600,
                "training": {
                    "min_training_samples": 1000,
                    "retrain_interval_samples": 200,
                    "contamination_rate": 0.1
                },
                "features": [
                    "packet_size", "dest_port", "src_port",
                    "hour", "minute", "is_weekend",
                    "ip_entropy", "port_frequency"
                ]
            },
            "processing": {
                "enable_heuristics": True,
                "enable_alerts": True,
                "stats_interval": 45,
                "max_processing_time": 5.0
            },
            "logging": {
                "level": "INFO",
                "file": "logs/ml_detector.log",
                "max_size": "10MB",
                "backup_count": 5,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "console_output": True
            },
            "protobuf": {
                "enabled": True,
                "timeout": 1000,
                "retry_attempts": 3
            },
            "persistence": {
                "save_predictions": False,
                "predictions_file": "data/predictions.jsonl",
                "auto_save_interval": 300
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
                maxBytes=self._parse_size(log_config.get('max_size', '10MB')),
                backupCount=log_config.get('backup_count', 5)
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    def _parse_size(self, size_str: str) -> int:
        """Parse size string (e.g., '10MB') to bytes"""
        if isinstance(size_str, int):
            return size_str

        size_str = size_str.upper()
        if size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        else:
            return int(size_str)

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
        """Inicia el detector ML usando configuración JSON - ZMQ PULL/PUSH CORREGIDO"""
        try:
            # ✅ CORREGIDO: Configurar sockets con patrón PULL/PUSH para pipeline
            self.input_socket = self.context.socket(zmq.PULL)  # ← CAMBIO: SUB → PULL
            input_addr = f"tcp://localhost:{self.input_port}"
            self.input_socket.connect(input_addr)
            # ❌ ELIMINADO: self.input_socket.setsockopt(zmq.SUBSCRIBE, b"")  # No necesario para PULL
            self.input_socket.setsockopt(zmq.RCVTIMEO, 3000)
            self.input_socket.setsockopt(zmq.RCVHWM, self.high_water_mark)

            self.output_socket = self.context.socket(zmq.PUSH)  # ← CAMBIO: PUB → PUSH
            output_addr = f"tcp://*:{self.output_port}"
            self.output_socket.bind(output_addr)
            self.output_socket.setsockopt(zmq.SNDHWM, self.high_water_mark)

            self.running = True

            print(f"\n🤖 Lightweight ML Detector Started (LIMPIO) - ZMQ PULL/PUSH + TIMEOUT CORREGIDO")
            print(f"📄 Config: {self.config_file or 'default'}")
            print(f"📡 Input: {input_addr} (desde geoip_enricher) - PULL socket")
            print(f"📤 Output: {output_addr} (hacia dashboard) - PUSH socket")
            print(f"📦 Protobuf: {'✅ Available' if PROTOBUF_AVAILABLE else '❌ Not available'}")
            print(f"🧠 ML: {'✅ Available' if ML_AVAILABLE else '❌ Heuristics only'}")
            print(f"🧹 GeoIP: ❌ ELIMINADO (responsabilidad del geoip_enricher)")
            print(f"🎯 Anomaly threshold: {self.anomaly_threshold}")
            print(f"⚠️ High risk threshold: {self.high_risk_threshold}")
            print(f"📊 Buffer size: {self.buffer_size}")
            print(f"⚡ Batch size: {self.batch_size}")
            print(f"🔔 Alerts: {'✅ Enabled' if self.enable_alerts else '❌ Disabled'}")
            print(f"🔧 ZMQ Pattern: PULL/PUSH (pipeline corregido)")
            print(f"⏱️ Recv Timeout: 3000ms (bug NOBLOCK corregido)")
            print(f"🔍 Debug ML Values: ✅ Enabled (logs NaN/inf detection)")
            print(f"🧹 Value Sanitization: ✅ Enabled (clamp 0-1, clean NaN/inf)")
            print("=" * 70)

            # Thread principal de procesamiento
            processing_thread = threading.Thread(target=self._processing_loop, daemon=True)
            processing_thread.start()

            # Thread de estadísticas
            stats_thread = threading.Thread(target=self._stats_loop, args=(self.stats_interval,), daemon=True)
            stats_thread.start()

            # Thread de auto-guardado si está habilitado
            if self.persistence_config.get('save_predictions', False):
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
        """Loop principal de procesamiento (SOLO ML) - TIMEOUT CORREGIDO"""
        logger.info("🔄 Iniciando loop de procesamiento ML...")

        while self.running:
            try:
                # ✅ CORRECCIÓN: Usar timeout en lugar de NOBLOCK
                message = self.input_socket.recv()  # ← QUITADO zmq.NOBLOCK
                self.stats['events_processed'] += 1

                # Procesar evento (SOLO ML)
                enriched_event = self._process_event(message)

                if enriched_event is not None:  # ← CORREGIDO: usar 'is not None' en lugar de verificación truthy
                    # Enviar evento enriquecido
                    self.output_socket.send(enriched_event)
                    self.stats['events_enriched'] += 1
                    logger.debug(f"✅ Evento enviado al dashboard: {len(enriched_event)} bytes")
                else:
                    logger.warning(f"⚠️ Evento no procesado/enviado - _process_event devolvió None")

            except zmq.Again:
                continue  # Timeout - continuar
            except Exception as e:
                logger.error("Error en processing loop: %s", e)
                self.stats['processing_errors'] += 1
                time.sleep(0.1)

    def _process_event(self, message: bytes) -> Optional[bytes]:
        """Procesa un evento individual - SOLO análisis ML"""

        if not PROTOBUF_AVAILABLE:
            logger.warning("Protobuf no disponible - no se puede procesar evento")
            return None

        try:
            # Parsear evento protobuf entrante (YA CON COORDENADAS del geoip_enricher)
            event = network_event_extended_fixed_pb2.NetworkEvent()
            event.ParseFromString(message)

            # Convertir a diccionario para procesamiento ML
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

            # Procesar handshake inicial (pasar sin ML)
            if event.is_initial_handshake:
                self.stats['handshakes_processed'] += 1
                logger.info(f"🤝 Procesando handshake inicial de {event.agent_id} ({event.so_identifier})")

                # Para handshakes, solo pasamos la información completa sin ML
                enriched_event = network_event_extended_fixed_pb2.NetworkEvent()
                enriched_event.CopyFrom(event)  # Copiar TODO incluyendo coordenadas

                return enriched_event.SerializeToString()

            # Para eventos normales, aplicar SOLO ML
            if not self.ml_enabled:
                # Si ML está deshabilitado, pasar evento sin cambios
                enriched_event = network_event_extended_fixed_pb2.NetworkEvent()
                enriched_event.CopyFrom(event)
                return enriched_event.SerializeToString()

            # Extraer features para ML
            features = self.ml_model.extract_features(event_dict)

            # Entrenar/actualizar modelo
            self.ml_model.train_or_update(features)

            # Predecir anomalía y riesgo
            anomaly_score, risk_score = self.ml_model.predict_anomaly(features)

            # 🔍 DEBUG: Verificar valores ML antes de asignar
            logger.debug(f"🔍 Valores ML RAW: anomaly={anomaly_score} (type={type(anomaly_score)})")
            logger.debug(f"🔍 Valores ML RAW: risk={risk_score} (type={type(risk_score)})")
            logger.debug(
                f"🔍 Validez anomaly: nan={math.isnan(anomaly_score) if isinstance(anomaly_score, (int, float)) else 'N/A'}, inf={math.isinf(anomaly_score) if isinstance(anomaly_score, (int, float)) else 'N/A'}")
            logger.debug(
                f"🔍 Validez risk: nan={math.isnan(risk_score) if isinstance(risk_score, (int, float)) else 'N/A'}, inf={math.isinf(risk_score) if isinstance(risk_score, (int, float)) else 'N/A'}")

            # Sanitizar valores ML
            clean_anomaly_score = self._sanitize_float(anomaly_score)
            clean_risk_score = self._sanitize_float(risk_score)

            logger.debug(f"🔍 Valores ML CLEAN: anomaly={clean_anomaly_score}, risk={clean_risk_score}")

            # Actualizar estadísticas según configuración
            if ML_AVAILABLE and self.ml_model.is_trained:
                self.stats['model_predictions'] += 1
            else:
                self.stats['heuristic_predictions'] += 1

            # Estadísticas según umbrales de configuración
            if clean_anomaly_score > self.anomaly_threshold:
                self.stats['anomalies_detected'] += 1

            if clean_risk_score > self.high_risk_threshold:
                self.stats['high_risk_events'] += 1

            # Crear evento enriquecido PRESERVANDO coordenadas del geoip_enricher
            enriched_event = network_event_extended_fixed_pb2.NetworkEvent()

            # Copiar TODOS los campos originales (incluyendo coordenadas)
            enriched_event.CopyFrom(event)

            logger.debug(f"🔍 Evento copiado: event_id={enriched_event.event_id}")

            # SOLO AÑADIR enriquecimiento ML con valores sanitizados
            enriched_event.anomaly_score = clean_anomaly_score
            enriched_event.risk_score = clean_risk_score

            logger.debug(
                f"🔍 Valores ML asignados al protobuf: A={enriched_event.anomaly_score}, R={enriched_event.risk_score}")

            # Enriquecer descripción con info ML
            if clean_anomaly_score > 0.5 or clean_risk_score > 0.5:
                ml_info = f"ML: A:{clean_anomaly_score:.2f} R:{clean_risk_score:.2f}"
                if event.description:
                    enriched_event.description = f"{ml_info} | {event.description}"
                else:
                    enriched_event.description = ml_info

            # Guardar predicción si está configurado
            if self.persistence_config.get('save_predictions', False):
                self._save_prediction(event_dict, clean_anomaly_score, clean_risk_score)

            # 🔍 DEBUG: Verificar serialización
            try:
                serialized_data = enriched_event.SerializeToString()
                logger.debug(f"🔍 Serialización: {len(serialized_data)} bytes")
                if len(serialized_data) == 0:
                    logger.error(f"❌ SERIALIZACIÓN VACÍA - evento: {enriched_event}")
                    return None
                else:
                    logger.debug(f"✅ Serialización exitosa: {len(serialized_data)} bytes")
            except Exception as e:
                logger.error(f"❌ Error en serialización: {e}")
                return None

            logger.debug("📊 Evento ML procesado: %s A:%.2f R:%.2f",
                         event.event_id, clean_anomaly_score, clean_risk_score)

            return serialized_data

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
                'anomaly_score': float(anomaly_score),  # Asegurar tipo float
                'risk_score': float(risk_score),  # Asegurar tipo float
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
            except Exception as e:
                logger.error("Error en stats loop: %s", e)

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
        try:
            state_file = self.persistence_config.get('state_file', 'data/ml_detector_state.json')

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

        print(f"\n📊 ML Detector Stats (LIMPIO) - Uptime: {uptime:.0f}s")
        print(f"📥 Events Processed: {self.stats['events_processed']}")
        print(f"📤 Events Enriched: {self.stats['events_enriched']}")
        print(f"🚨 Anomalies Detected: {self.stats['anomalies_detected']}")
        print(f"⚠️ High Risk Events: {self.stats['high_risk_events']}")
        print(f"🤝 Handshakes Processed: {self.stats['handshakes_processed']}")
        print(f"🤖 ML Model Trained: {self.ml_model.is_trained}")
        print(f"📚 Training Samples: {len(self.ml_model.training_data)}")
        print(f"🎯 ML Predictions: {self.stats['model_predictions']}")
        print(f"🔧 Heuristic Predictions: {self.stats['heuristic_predictions']}")
        print(f"❌ Processing Errors: {self.stats['processing_errors']}")
        print(f"📄 Config: {self.config_file or 'default'}")
        print(f"🧹 GeoIP: ❌ ELIMINADO - solo ML")
        print(f"🔧 ZMQ Pattern: PULL/PUSH (corregido)")
        print(f"⏱️ Recv Timeout: 3000ms (bug NOBLOCK corregido)")
        print(f"🔍 Debug ML Values: ✅ (NaN/inf detection)")
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
            'handshakes_processed': self.stats['handshakes_processed'],
            'ml_model_trained': self.ml_model.is_trained,
            'training_samples': len(self.ml_model.training_data),
            'model_predictions': self.stats['model_predictions'],
            'heuristic_predictions': self.stats['heuristic_predictions'],
            'processing_errors': self.stats['processing_errors'],
            'protobuf_available': PROTOBUF_AVAILABLE,
            'ml_available': ML_AVAILABLE,
            'config_file': self.config_file,
            'configuration': {
                'input_port': self.input_port,
                'output_port': self.output_port,
                'anomaly_threshold': self.anomaly_threshold,
                'high_risk_threshold': self.high_risk_threshold,
                'batch_size': self.batch_size,
                'buffer_size': self.buffer_size,
                'ml_enabled': self.ml_enabled,
                'alerts_enabled': self.enable_alerts
            }
        }

    def cleanup(self):
        """Limpia recursos y guarda estado final"""
        # Guardar estado final
        if self.persistence_config.get('save_predictions', False):
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

    def _sanitize_float(self, value) -> float:
        """Sanitiza valores float para protobuf (elimina NaN, inf, clamp a 0-1)"""
        try:
            if value is None:
                return 0.0

            # Convertir a float nativo de Python
            float_val = float(value)

            # Verificar NaN e infinity
            if math.isnan(float_val) or math.isinf(float_val):
                logger.warning(f"⚠️ Valor ML problemático detectado: {value} (type={type(value)})")
                return 0.0

            # Clamp a rango válido 0-1
            return max(0.0, min(1.0, float_val))

        except (TypeError, ValueError, OverflowError) as e:
            logger.error(f"❌ Error convirtiendo valor ML: {value} -> {e}")
            return 0.0


def main():
    """Función principal con configuración JSON completa"""
    import argparse

    parser = argparse.ArgumentParser(description='Lightweight ML Detector (LIMPIO - Sin GeoIP)')
    parser.add_argument('config_file', nargs='?',
                        default='lightweight_ml_detector_config.json',
                        help='Archivo de configuración JSON')
    parser.add_argument('--test-config', action='store_true',
                        help='Validar configuración y salir')

    args = parser.parse_args()

    if args.test_config:
        try:
            detector = LightweightMLDetector(config_file=args.config_file)
            print("✅ Configuración JSON válida (LIMPIO)")
            stats = detector.get_statistics()
            print(f"📡 Input port: {stats['configuration']['input_port']}")
            print(f"📤 Output port: {stats['configuration']['output_port']}")
            print(f"🎯 Anomaly threshold: {stats['configuration']['anomaly_threshold']}")
            print(f"⚠️ High risk threshold: {stats['configuration']['high_risk_threshold']}")
            print(f"🧹 GeoIP: ❌ ELIMINADO - responsabilidad del geoip_enricher.py")
            print(f"🔧 ZMQ Pattern: PULL/PUSH (corregido)")
            print(f"⏱️ Recv Timeout: 3000ms (bug NOBLOCK corregido)")
            print(f"🔍 Debug ML Values: ✅ (NaN/inf detection)")
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

        print(f"\n🤖 ML Detector iniciado (LIMPIO):")
        stats = detector.get_statistics()
        print(f"   📡 Input port: {stats['configuration']['input_port']}")
        print(f"   📤 Output port: {stats['configuration']['output_port']}")
        print(f"   🎯 Anomaly threshold: {stats['configuration']['anomaly_threshold']}")
        print(f"   📊 Buffer size: {stats['configuration']['buffer_size']}")
        print(f"   🧠 ML enabled: {'✅' if stats['configuration']['ml_enabled'] else '❌'}")
        print(f"   🧹 GeoIP: ❌ ELIMINADO")
        print(f"   🔧 ZMQ Pattern: PULL/PUSH (corregido)")
        print(f"   ⏱️ Recv Timeout: 3000ms (bug NOBLOCK corregido)")
        print(f"   🔍 Debug ML Values: ✅ (NaN/inf detection)")

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