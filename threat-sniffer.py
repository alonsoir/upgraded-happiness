import json
import joblib
import numpy as np
import pandas as pd
import logging
import time
from datetime import datetime
from pathlib import Path
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP
import geoip2.database

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("threat_sniffer.log"),
        logging.StreamHandler()
    ]
)


class ThreatDetector:
    def __init__(self, model_path=None):
        self.model, self.scaler, self.feature_names, self.config = self.load_latest_model(model_path)
        self.feature_extractor = PacketFeatureExtractor(self.config)
        self.flow_tracker = FlowTracker()
        self.packet_queue = deque(maxlen=100)
        self.last_processing_time = time.time()

    @staticmethod
    def load_latest_model(model_path=None):
        """Carga el modelo más reciente del directorio models/"""
        if model_path:
            model_dir = Path(model_path)
        else:
            model_dirs = sorted(Path("models").glob("model_*"), reverse=True)
            if not model_dirs:
                logging.error("No se encontraron modelos en el directorio 'models/'")
                return None, None, None, None
            model_dir = model_dirs[0]

        try:
            model = joblib.load(model_dir / "model.pkl")
            scaler = joblib.load(model_dir / "scaler.pkl")
            with open(model_dir / "metadata.json") as f:
                metadata = json.load(f)

            logging.info(f"Modelo cargado: {model_dir}")
            return model, scaler, metadata["feature_set"]["features"], metadata
        except Exception as e:
            logging.error(f"Error cargando modelo: {str(e)}")
            return None, None, None, None

    def process_packet(self, packet):
        """Procesa un paquete individual"""
        try:
            if not packet.haslayer(IP):
                return

            # Extraer características básicas
            features = self.feature_extractor.extract_basic_features(packet)

            # Actualizar el seguimiento de flujo
            flow_id = self.flow_tracker.get_flow_id(packet)
            self.flow_tracker.update_flow(flow_id, packet, features)

            # Añadir a la cola para procesamiento
            self.packet_queue.append((flow_id, features))

            # Procesar cola periódicamente
            self.process_queue()

        except Exception as e:
            logging.error(f"Error procesando paquete: {str(e)}")

    def process_queue(self):
        """Procesa la cola de paquetes acumulados"""
        current_time = time.time()
        if not self.packet_queue or current_time - self.last_processing_time < 0.5:
            return

        try:
            # Procesar todos los paquetes en la cola
            while self.packet_queue:
                flow_id, _ = self.packet_queue.popleft()
                flow_features = self.flow_tracker.get_flow_features(flow_id)
                if not flow_features:
                    continue

                threat_level, probability = self.detect_threat(flow_features)
                if threat_level != "Normal":
                    log_msg = (
                        f"[{threat_level}] Prob: {probability:.4f} | "
                        f"Flow: {flow_id} | "
                        f"Src: {flow_features.get('src_ip', '')} | "
                        f"Dst: {flow_features.get('dst_ip', '')} | "
                        f"Proto: {flow_features.get('proto', 0)}"
                    )
                    logging.warning(log_msg)

            self.last_processing_time = current_time

        except Exception as e:
            logging.error(f"Error procesando cola: {str(e)}")

    def detect_threat(self, features):
        """Detecta amenazas en un conjunto de características"""
        if self.model is None or self.scaler is None:
            return "Error", 0.0

        try:
            # Preparar datos para el modelo
            input_data = self.prepare_input(features)

            # Realizar predicción
            probability = self.model.predict_proba(input_data)[0][1]

            # Determinar nivel de amenaza
            anomaly_threshold = self.config["ml"]["anomaly_threshold"]
            high_risk_threshold = self.config["ml"]["high_risk_threshold"]

            if probability > high_risk_threshold:
                return "Critical", probability
            elif probability > anomaly_threshold:
                return "Warning", probability
            else:
                return "Normal", probability

        except Exception as e:
            logging.error(f"Error en detección de amenaza: {str(e)}")
            return "Error", 0.0

    def prepare_input(self, features):
        """Prepara los datos de entrada para el modelo"""
        # Crear DataFrame con valores por defecto
        df = pd.DataFrame([features])

        # Asegurar todas las columnas esperadas
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0

        # Mantener solo las características necesarias
        df = df[self.feature_names]

        # Aplicar escalado
        return self.scaler.transform(df)


class PacketFeatureExtractor:
    def __init__(self, config):
        self.hq_coords = tuple(config["geo"]["hq_coords"])
        self.country_risk_scores = config["geo"]["country_risk_scores"]
        self.geo_reader = geoip2.database.Reader(config["geo"]["city_db_path"])
        self.geo_cache = {}

    def extract_basic_features(self, packet):
        """Extrae características básicas de un paquete individual"""
        ip_layer = packet[IP]
        features = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'proto': ip_layer.proto,
            'sbytes': len(packet),
            'sttl': ip_layer.ttl,
        }

        # Manejar capas de transporte
        if TCP in packet:
            tcp_layer = packet[TCP]
            features.update({
                'sport': tcp_layer.sport,
                'dport': tcp_layer.dport,
                'flags': tcp_layer.flags
            })
        elif UDP in packet:
            udp_layer = packet[UDP]
            features.update({
                'sport': udp_layer.sport,
                'dport': udp_layer.dport
            })

        # Añadir geolocalización
        features.update(self.get_geo_features(features['src_ip']))

        return features

    def get_geo_features(self, ip):
        """Obtiene características geográficas para una IP"""
        if ip in self.geo_cache:
            return self.geo_cache[ip]

        try:
            response = self.geo_reader.city(ip)
            geo_features = {
                'src_country': response.country.iso_code,
                'src_asn': response.traits.autonomous_system_number,
                'country_risk': self.country_risk_scores.get(
                    response.country.iso_code, 0.5
                ),
                'distance_km': self.calculate_distance(
                    response.location.latitude,
                    response.location.longitude
                )
            }
        except Exception as e:
            geo_features = {
                'src_country': "UNKNOWN",
                'src_asn': 0,
                'country_risk': 0.5,
                'distance_km': 0
            }

        self.geo_cache[ip] = geo_features
        return geo_features

    def calculate_distance(self, lat, lon):
        """Calcula la distancia desde las coordenadas a la sede central"""
        if lat == 0 or lon == 0:
            return 0

        hq_lat, hq_lon = self.hq_coords
        return 111 * np.sqrt((lat - hq_lat) ** 2 + (lon - hq_lon) ** 2)


class FlowTracker:
    def __init__(self, timeout=120):
        self.flows = defaultdict(self.create_flow)
        self.timeout = timeout
        self.last_cleanup = time.time()

    @staticmethod
    def create_flow():
        """Crea una nueva estructura de flujo"""
        return {
            'start_time': time.time(),
            'last_update': time.time(),
            'packet_count': 0,
            'total_bytes': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'src_packets': 0,
            'dst_packets': 0,
            'min_ttl': float('inf'),
            'max_ttl': 0,
            'flags': set(),
            'sport': 0,
            'dport': 0
        }

    def get_flow_id(self, packet):
        """Obtiene un ID único para el flujo"""
        ip = packet[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto

        sport = dport = 0
        if TCP in packet:
            tcp = packet[TCP]
            sport = tcp.sport
            dport = tcp.dport
        elif UDP in packet:
            udp = packet[UDP]
            sport = udp.sport
            dport = udp.dport

        return f"{src}-{sport}-{dst}-{dport}-{proto}"

    def update_flow(self, flow_id, packet, features):
        """Actualiza la información del flujo con un nuevo paquete"""
        flow = self.flows[flow_id]
        current_time = time.time()
        flow['last_update'] = current_time
        flow['packet_count'] += 1
        flow['total_bytes'] += len(packet)

        # Guardar puertos en el primer paquete
        if flow['packet_count'] == 1:
            flow['sport'] = features.get('sport', 0)
            flow['dport'] = features.get('dport', 0)

        # Determinar dirección
        if features['src_ip'] == flow_id.split('-')[0]:
            direction = 'src'
        else:
            direction = 'dst'

        # Actualizar estadísticas de dirección
        flow[f'{direction}_bytes'] += len(packet)
        flow[f'{direction}_packets'] += 1

        # Actualizar TTL
        ttl = features.get('sttl', 64)
        flow['min_ttl'] = min(flow['min_ttl'], ttl)
        flow['max_ttl'] = max(flow['max_ttl'], ttl)

        # Guardar flags TCP
        if 'flags' in features:
            flow['flags'].add(str(features['flags']))

        # Limpieza periódica de flujos antiguos
        if current_time - self.last_cleanup > 30:
            self.cleanup_flows()
            self.last_cleanup = current_time

    def get_flow_features(self, flow_id):
        """Obtiene características completas del flujo"""
        if flow_id not in self.flows:
            return {}

        flow = self.flows[flow_id]
        duration = flow['last_update'] - flow['start_time']

        # Calcular características basadas en el flujo
        features = {
            'dur': duration,
            'src_ip': flow_id.split('-')[0],
            'dst_ip': flow_id.split('-')[2],
            'proto': int(flow_id.split('-')[-1]),
            'spkts': flow['src_packets'],
            'dpkts': flow['dst_packets'],
            'sbytes': flow['src_bytes'],
            'dbytes': flow['dst_bytes'],
            'sttl': flow['min_ttl'],
            'dttl': flow['min_ttl'],  # Usar mismo valor para simplificar
            'rate': flow['packet_count'] / duration if duration > 0 else 0,
            'sload': flow['src_bytes'] / duration if duration > 0 else 0,
            'dload': flow['dst_bytes'] / duration if duration > 0 else 0,
            'packet_imbalance': flow['src_packets'] / max(flow['dst_packets'], 1),
            'byte_imbalance': flow['src_bytes'] / max(flow['dst_bytes'], 1),
            'conn_state_abnormal': 1 if 'S' in ''.join(flow['flags']) and 'A' not in ''.join(flow['flags']) else 0,
            'high_port_activity': 1 if flow['sport'] > 1024 or flow['dport'] > 1024 else 0
        }

        # Añadir características temporales
        now = datetime.now()
        features['hour'] = now.hour
        features['day_of_week'] = now.weekday()
        features['is_weekend'] = 1 if features['day_of_week'] >= 5 else 0

        # Añadir geolocalización desde el primer paquete
        features.update(self.get_geo_features(features['src_ip']))

        return features

    def get_geo_features(self, ip):
        """Simula obtención de características geográficas (implementación real en PacketFeatureExtractor)"""
        return {
            'src_country': "UNKNOWN",
            'src_asn': 0,
            'country_risk': 0.5,
            'distance_km': 0
        }

    def cleanup_flows(self):
        """Elimina flujos inactivos"""
        current_time = time.time()
        inactive_flows = [
            flow_id for flow_id, flow in self.flows.items()
            if current_time - flow['last_update'] > self.timeout
        ]

        for flow_id in inactive_flows:
            del self.flows[flow_id]

        if inactive_flows:
            logging.info(f"Limpiados {len(inactive_flows)} flujos inactivos")


def main():
    """Función principal para iniciar el sniffer"""
    logging.info("Iniciando sniffer de amenazas...")
    detector = ThreatDetector()

    if not detector.model:
        logging.error("No se pudo cargar el modelo. Saliendo.")
        return

    def packet_callback(packet):
        detector.process_packet(packet)

    try:
        logging.info("Comenzando captura de paquetes...")
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        logging.info("Sniffer detenido por el usuario")
    except Exception as e:
        logging.error(f"Error en captura: {str(e)}")


if __name__ == "__main__":
    main()