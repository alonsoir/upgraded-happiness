#!/usr/bin/env python3
"""
Lightweight ML Detector para Upgraded-Happiness
ACTUALIZADO: Usa network_event_extended_fixed_pb2 (estructuras protobuf reales)
Puerto 5559 (entrada desde promiscuous_agent) - Puerto 5560 (salida a dashboard)
"""

import zmq
import time
import logging
import threading
import numpy as np
from collections import deque, defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
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
    """Modelo ML simple para detección de anomalías"""

    def __init__(self):
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.training_data = deque(maxlen=1000)
        self.feature_names = [
            'packet_size', 'dest_port', 'src_port',
            'hour', 'minute', 'is_weekend',
            'ip_entropy', 'port_frequency'
        ]

        # Estadísticas para features
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)

        if ML_AVAILABLE:
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            logger.info("🤖 Modelo ML inicializado")
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
        """Entrena o actualiza el modelo"""
        if not ML_AVAILABLE:
            return

        self.training_data.append(features)

        # Entrenar cuando tengamos suficientes datos
        if len(self.training_data) >= 100 and not self.is_trained:
            X = np.array(list(self.training_data))
            X_scaled = self.scaler.fit_transform(X)
            self.anomaly_detector.fit(X_scaled)
            self.is_trained = True
            logger.info("🎯 Modelo ML entrenado con %d muestras", len(self.training_data))

        # Reentrenar periódicamente
        elif self.is_trained and len(self.training_data) % 200 == 0:
            X = np.array(list(self.training_data))
            X_scaled = self.scaler.fit_transform(X)
            self.anomaly_detector.fit(X_scaled)
            logger.info("🔄 Modelo ML reentrenado")

    def predict_anomaly(self, features: np.ndarray) -> Tuple[float, float]:
        """Predice anomalía y score de riesgo"""

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
    """Enriquecedor geográfico para IPs"""

    def __init__(self, db_path: str = None):
        self.reader = None
        self.enabled = False

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
        """Enriquece IP con coordenadas geográficas"""

        if not self.enabled or not ip or ip == 'unknown':
            return None, None

        try:
            response = self.reader.city(ip)
            latitude = float(response.location.latitude) if response.location.latitude else None
            longitude = float(response.location.longitude) if response.location.longitude else None

            return latitude, longitude

        except geoip2.errors.AddressNotFoundError:
            return None, None
        except Exception as e:
            logger.debug("Error en GeoIP para %s: %s", ip, e)
            return None, None

    def close(self):
        """Cierra la base de datos GeoIP"""
        if self.reader:
            self.reader.close()


class LightweightMLDetector:
    """Detector ML ligero que procesa eventos y los enriquece"""

    def __init__(self, input_port=5559, output_port=5560, geoip_db_path=None):
        self.input_port = input_port
        self.output_port = output_port
        self.running = False

        # ZeroMQ setup
        self.context = zmq.Context()
        self.input_socket = None
        self.output_socket = None

        # Componentes ML
        self.ml_model = SimpleMLModel()
        self.geoip_enricher = GeoIPEnricher(geoip_db_path)

        # Estadísticas
        self.stats = {
            'events_processed': 0,
            'events_enriched': 0,
            'anomalies_detected': 0,
            'high_risk_events': 0,
            'geoip_enriched': 0,
            'handshakes_processed': 0,
            'start_time': time.time()
        }

        # Buffer para procesamiento
        self.event_buffer = deque(maxlen=100)

        logger.info("🤖 LightweightMLDetector inicializado")
        logger.info("📡 Input port: %d", input_port)
        logger.info("📤 Output port: %d", output_port)
        logger.info("🧠 ML disponible: %s", ML_AVAILABLE)
        logger.info("🌍 GeoIP disponible: %s", GEOIP_AVAILABLE)

    def start(self):
        """Inicia el detector ML"""
        try:
            # Configurar sockets
            self.input_socket = self.context.socket(zmq.SUB)
            self.input_socket.connect(f"tcp://localhost:{self.input_port}")
            self.input_socket.setsockopt(zmq.SUBSCRIBE, b"")
            self.input_socket.setsockopt(zmq.RCVTIMEO, 1000)

            self.output_socket = self.context.socket(zmq.PUB)
            self.output_socket.bind(f"tcp://*:{self.output_port}")

            self.running = True

            print(f"\n🤖 Lightweight ML Detector Started (PROTOBUF REAL)")
            print(f"📡 Input: localhost:{self.input_port} (from promiscuous_agent)")
            print(f"📤 Output: localhost:{self.output_port} (to dashboard)")
            print(f"📦 Protobuf: {'✅ Available' if PROTOBUF_AVAILABLE else '❌ Not available'}")
            print(f"🧠 ML: {'✅ Available' if ML_AVAILABLE else '❌ Heuristics only'}")
            print(f"🌍 GeoIP: {'✅ Available' if self.geoip_enricher.enabled else '❌ Not available'}")
            print("=" * 70)

            # Thread principal de procesamiento
            processing_thread = threading.Thread(target=self._processing_loop, daemon=True)
            processing_thread.start()

            # Thread de estadísticas
            stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
            stats_thread.start()

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
                # Recibir evento
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

            # Estadísticas
            if anomaly_score > 0.7:
                self.stats['anomalies_detected'] += 1
            if risk_score > 0.8:
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

            # Enriquecer descripción
            if anomaly_score > 0.5 or risk_score > 0.5:
                ml_info = f"ML: A:{anomaly_score:.2f} R:{risk_score:.2f}"
                if event.description:
                    enriched_event.description = f"{ml_info} | {event.description}"
                else:
                    enriched_event.description = ml_info

            logger.debug("📊 Evento enriquecido: %s A:%.2f R:%.2f",
                         event.event_id, anomaly_score, risk_score)

            return enriched_event.SerializeToString()

        except Exception as e:
            logger.error("Error procesando evento: %s", e)
            return None

    def _stats_loop(self):
        """Loop de estadísticas"""
        while self.running:
            try:
                time.sleep(30)  # Cada 30 segundos
                self._print_stats()
            except Exception as e:
                logger.error("Error en stats loop: %s", e)

    def _print_stats(self):
        """Imprime estadísticas"""
        uptime = time.time() - self.stats['start_time']

        print(f"\n📊 ML Detector Stats - Uptime: {uptime:.0f}s")
        print(f"📥 Events Processed: {self.stats['events_processed']}")
        print(f"📤 Events Enriched: {self.stats['events_enriched']}")
        print(f"🚨 Anomalies Detected: {self.stats['anomalies_detected']}")
        print(f"⚠️  High Risk Events: {self.stats['high_risk_events']}")
        print(f"🌍 GeoIP Enriched: {self.stats['geoip_enriched']}")
        print(f"🤝 Handshakes Processed: {self.stats['handshakes_processed']}")
        print(f"🤖 ML Model Trained: {self.ml_model.is_trained}")
        print(f"📚 Training Samples: {len(self.ml_model.training_data)}")
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
            'protobuf_available': PROTOBUF_AVAILABLE,
            'ml_available': ML_AVAILABLE,
            'geoip_available': self.geoip_enricher.enabled
        }

    def cleanup(self):
        """Limpia recursos"""
        if self.input_socket:
            self.input_socket.close()
        if self.output_socket:
            self.output_socket.close()
        if self.context:
            self.context.term()
        if self.geoip_enricher:
            self.geoip_enricher.close()


def main():
    """Función principal"""
    import argparse

    parser = argparse.ArgumentParser(description='Lightweight ML Detector (PROTOBUF REAL)')
    parser.add_argument('--input-port', type=int, default=5559,
                        help='Input port (from promiscuous_agent)')
    parser.add_argument('--output-port', type=int, default=5560,
                        help='Output port (to dashboard)')
    parser.add_argument('--geoip-db', type=str, default=None,
                        help='Path to GeoIP database file')

    args = parser.parse_args()

    if not PROTOBUF_AVAILABLE:
        print("❌ Error: Protobuf no disponible")
        print("📦 Instalar con: pip install protobuf")
        return 1

    detector = LightweightMLDetector(
        input_port=args.input_port,
        output_port=args.output_port,
        geoip_db_path=args.geoip_db
    )

    try:
        detector.start()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        logger.error("Error fatal: %s", e)
        return 1
    finally:
        detector._print_stats()

    return 0


if __name__ == "__main__":
    exit(main())