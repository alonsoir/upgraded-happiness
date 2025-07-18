#!/usr/bin/env python3
"""
Reparador de Configuración para Sistema SCADA
Corrige configuraciones ML y define correctamente eventos de alto riesgo
"""

import json
import os
import shutil
from datetime import datetime
from pathlib import Path


class ConfigurationFixer:
    def __init__(self):
        self.config_files = {
            'ml_detector': 'lightweight_ml_detector_config.json',
            'dashboard': 'dashboard_config.json',
            'agent': 'enhanced_agent_config.json'
        }
        self.backup_dir = Path('config_backups')
        self.backup_dir.mkdir(exist_ok=True)

    def backup_existing_configs(self):
        """Crear backup de configuraciones existentes"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        for config_name, config_file in self.config_files.items():
            if os.path.exists(config_file):
                backup_file = self.backup_dir / f"{config_name}_{timestamp}.json"
                shutil.copy2(config_file, backup_file)
                print(f"✅ Backup creado: {backup_file}")
            else:
                print(f"⚠️ Archivo no encontrado: {config_file}")

    def create_ml_detector_config(self):
        """Crear configuración optimizada para ML detector"""
        config = {
            "ml_models": {
                "enabled_models": [
                    {
                        "name": "IsolationForest",
                        "enabled": True,
                        "params": {
                            "contamination": 0.1,
                            "random_state": 42,
                            "n_estimators": 100
                        },
                        "weight": 0.2
                    },
                    {
                        "name": "OneClassSVM",
                        "enabled": True,
                        "params": {
                            "kernel": "rbf",
                            "gamma": "scale",
                            "nu": 0.1
                        },
                        "weight": 0.15
                    },
                    {
                        "name": "EllipticEnvelope",
                        "enabled": True,
                        "params": {
                            "contamination": 0.1,
                            "random_state": 42
                        },
                        "weight": 0.15
                    },
                    {
                        "name": "LocalOutlierFactor",
                        "enabled": True,
                        "params": {
                            "n_neighbors": 20,
                            "contamination": 0.1
                        },
                        "weight": 0.2
                    },
                    {
                        "name": "RandomForest",
                        "enabled": True,
                        "params": {
                            "n_estimators": 100,
                            "random_state": 42,
                            "max_depth": 10
                        },
                        "weight": 0.15
                    },
                    {
                        "name": "XGBoost",
                        "enabled": True,
                        "params": {
                            "n_estimators": 100,
                            "max_depth": 6,
                            "learning_rate": 0.1,
                            "random_state": 42
                        },
                        "weight": 0.15
                    }
                ]
            },
            "scoring": {
                "anomaly_threshold": 0.7,
                "risk_threshold": 0.8,
                "high_risk_threshold": 0.9,
                "scoring_method": "weighted_average",
                "normalize_scores": True
            },
            "training": {
                "retrain_interval_hours": 6,
                "min_training_samples": 1000,
                "max_training_samples": 50000,
                "feature_window_size": 100,
                "auto_retrain": True
            },
            "features": {
                "enabled_features": [
                    "packet_size",
                    "dest_port",
                    "src_port",
                    "timestamp_hour",
                    "timestamp_minute",
                    "ip_src_frequency",
                    "ip_dst_frequency",
                    "port_frequency",
                    "packet_size_variance"
                ],
                "feature_scaling": "standard",
                "remove_outliers": True
            },
            "persistence": {
                "model_save_path": "models/",
                "save_interval_minutes": 30,
                "keep_model_versions": 5
            }
        }

        with open(self.config_files['ml_detector'], 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✅ Configuración ML creada: {self.config_files['ml_detector']}")
        return config

    def create_dashboard_config(self):
        """Crear configuración optimizada para dashboard con reglas de alto riesgo"""
        config = {
            "network": {
                "zmq_input_port": 5560,
                "zmq_output_port": 5561,
                "http_host": "127.0.0.1",
                "http_port": 8000
            },
            "firewall": {
                "enabled": True,
                "auto_block": False,
                "manual_approval_required": True,
                "default_block_duration": "1h",
                "max_concurrent_rules": 100
            },
            "threat_detection": {
                "enabled": True,
                "auto_threat_detection": True,
                "manual_approval": True,
                "high_risk_threshold": 0.85,
                "medium_risk_threshold": 0.65,
                "low_risk_threshold": 0.45
            },
            "threat_rules": [
                {
                    "name": "SSH_Brute_Force",
                    "description": "Múltiples intentos de conexión SSH",
                    "conditions": {
                        "dest_port": 22,
                        "anomaly_score": {"min": 0.7},
                        "connections_per_minute": {"min": 5}
                    },
                    "risk_score": 0.9,
                    "auto_block": False,
                    "block_duration": "24h"
                },
                {
                    "name": "RDP_Attack",
                    "description": "Ataque a protocolo RDP",
                    "conditions": {
                        "dest_port": 3389,
                        "anomaly_score": {"min": 0.6},
                        "packet_size": {"min": 100}
                    },
                    "risk_score": 0.85,
                    "auto_block": False,
                    "block_duration": "12h"
                },
                {
                    "name": "Port_Scan",
                    "description": "Escaneo de puertos detectado",
                    "conditions": {
                        "unique_ports_per_minute": {"min": 10},
                        "anomaly_score": {"min": 0.8}
                    },
                    "risk_score": 0.8,
                    "auto_block": False,
                    "block_duration": "6h"
                },
                {
                    "name": "Unknown_Service",
                    "description": "Conexión a servicio desconocido",
                    "conditions": {
                        "dest_port": {"not_in": [80, 443, 22, 21, 25, 53, 993, 995]},
                        "anomaly_score": {"min": 0.75}
                    },
                    "risk_score": 0.7,
                    "auto_block": False,
                    "block_duration": "2h"
                },
                {
                    "name": "Large_Data_Transfer",
                    "description": "Transferencia de datos inusualmente grande",
                    "conditions": {
                        "packet_size": {"min": 5000},
                        "anomaly_score": {"min": 0.6}
                    },
                    "risk_score": 0.75,
                    "auto_block": False,
                    "block_duration": "4h"
                }
            ],
            "suspicious_ports": [
                22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 1521, 3389, 5432, 5900
            ],
            "dashboard": {
                "max_events_display": 300,
                "auto_refresh_interval_ms": 3000,
                "map_default_zoom": 2,
                "show_event_details": True,
                "enable_click_events": True
            },
            "logging": {
                "level": "INFO",
                "file": "logs/dashboard.log",
                "max_file_size_mb": 100,
                "backup_count": 5
            },
            "rate_limiting": {
                "enabled": True,
                "max_events_per_second": 100,
                "max_firewall_commands_per_minute": 10
            }
        }

        with open(self.config_files['dashboard'], 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✅ Configuración Dashboard creada: {self.config_files['dashboard']}")
        return config

    def create_agent_config(self):
        """Crear configuración optimizada para agente de captura"""
        config = {
            "capture": {
                "interface": "auto",
                "promiscuous_mode": True,
                "buffer_size": 2048,
                "timeout_ms": 1000,
                "max_packet_size": 65535
            },
            "geolocation": {
                "enabled": True,
                "providers": [
                    {
                        "name": "local_geoip",
                        "type": "maxmind",
                        "database_path": "data/GeoLite2-City.mmdb",
                        "priority": 1
                    },
                    {
                        "name": "ip_api",
                        "type": "api",
                        "url": "http://ip-api.com/json/{}",
                        "priority": 2,
                        "rate_limit": 150,
                        "timeout": 5
                    },
                    {
                        "name": "ipapi_co",
                        "type": "api",
                        "url": "https://ipapi.co/{}/json/",
                        "priority": 3,
                        "rate_limit": 100,
                        "timeout": 5
                    }
                ],
                "cache_enabled": True,
                "cache_ttl_hours": 24,
                "default_coordinates": {
                    "private_networks": {
                        "192.168.0.0/16": {"lat": 40.7128, "lon": -74.0060, "city": "Local Network"},
                        "10.0.0.0/8": {"lat": 40.7128, "lon": -74.0060, "city": "Local Network"},
                        "172.16.0.0/12": {"lat": 40.7128, "lon": -74.0060, "city": "Local Network"}
                    }
                }
            },
            "filtering": {
                "enabled": True,
                "ignore_local_traffic": False,
                "ignore_broadcast": True,
                "port_whitelist": [],
                "port_blacklist": [],
                "ip_whitelist": [],
                "ip_blacklist": []
            },
            "output": {
                "zmq_port": 5559,
                "zmq_bind": "tcp://*:5559",
                "message_format": "protobuf",
                "batch_size": 10,
                "flush_interval_ms": 1000
            },
            "performance": {
                "worker_threads": 4,
                "queue_size": 10000,
                "enable_compression": False,
                "memory_limit_mb": 512
            },
            "logging": {
                "level": "INFO",
                "file": "logs/agent.log",
                "enable_packet_logging": False,
                "max_file_size_mb": 100
            }
        }

        with open(self.config_files['agent'], 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✅ Configuración Agente creada: {self.config_files['agent']}")
        return config

    def create_geolocation_fallback_script(self):
        """Crear script de fallback para geolocalización"""
        script_content = '''#!/usr/bin/env python3
"""
Script de fallback para geolocalización cuando servicios externos fallan
"""

import json
import ipaddress
import sys

def get_fallback_coordinates(ip_address):
    """Obtener coordenadas de fallback para IPs conocidas"""

    # Coordenadas por defecto para redes privadas
    private_networks = {
        '192.168.0.0/16': {'lat': 40.7128, 'lon': -74.0060, 'city': 'Local Network NYC'},
        '10.0.0.0/8': {'lat': 37.7749, 'lon': -122.4194, 'city': 'Local Network SF'},
        '172.16.0.0/12': {'lat': 51.5074, 'lon': -0.1278, 'city': 'Local Network London'}
    }

    # Coordenadas conocidas para DNS públicos
    known_ips = {
        '8.8.8.8': {'lat': 37.4056, 'lon': -122.0775, 'city': 'Google DNS'},
        '8.8.4.4': {'lat': 37.4056, 'lon': -122.0775, 'city': 'Google DNS'},
        '1.1.1.1': {'lat': -27.4766, 'lon': 153.0166, 'city': 'Cloudflare DNS'},
        '208.67.222.222': {'lat': 37.7749, 'lon': -122.4194, 'city': 'OpenDNS'},
    }

    try:
        ip = ipaddress.ip_address(ip_address)

        # Verificar IPs conocidas
        if ip_address in known_ips:
            return known_ips[ip_address]

        # Verificar redes privadas
        for network, coords in private_networks.items():
            if ip in ipaddress.ip_network(network):
                return coords

        # Coordenadas por defecto para IPs públicas desconocidas
        return {'lat': 39.8283, 'lon': -98.5795, 'city': 'Unknown Location USA'}

    except ValueError:
        # IP inválida
        return {'lat': 0.0, 'lon': 0.0, 'city': 'Invalid IP'}

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python geolocation_fallback.py <ip_address>")
        sys.exit(1)

    ip_address = sys.argv[1]
    result = get_fallback_coordinates(ip_address)
    print(json.dumps(result))
'''

        with open('geolocation_fallback.py', 'w') as f:
            f.write(script_content)

        # Hacer ejecutable
        os.chmod('geolocation_fallback.py', 0o755)
        print("✅ Script de fallback creado: geolocation_fallback.py")

    def create_model_retraining_script(self):
        """Crear script para reentrenar modelos ML"""
        script_content = '''#!/usr/bin/env python3
"""
Script para reentrenar modelos ML del sistema SCADA
"""

import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.covariance import EllipticEnvelope
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("⚠️ XGBoost no disponible")

def load_training_data():
    """Cargar datos de entrenamiento desde logs"""
    # Datos sintéticos de ejemplo - reemplazar con datos reales
    np.random.seed(42)
    n_samples = 10000

    # Generar características sintéticas
    data = {
        'packet_size': np.random.lognormal(6, 1, n_samples),
        'dest_port': np.random.choice([22, 80, 443, 3389, 21, 25, 53], n_samples),
        'src_port': np.random.randint(1024, 65535, n_samples),
        'timestamp_hour': np.random.randint(0, 24, n_samples),
        'timestamp_minute': np.random.randint(0, 60, n_samples),
    }

    df = pd.DataFrame(data)

    # Añadir algunas anomalías sintéticas
    anomaly_indices = np.random.choice(n_samples, size=int(n_samples * 0.05), replace=False)
    df.loc[anomaly_indices, 'packet_size'] *= 10
    df.loc[anomaly_indices, 'dest_port'] = 9999

    return df

def train_models():
    """Entrenar todos los modelos ML"""
    print("🤖 Iniciando entrenamiento de modelos...")

    # Cargar datos
    data = load_training_data()
    print(f"📊 Datos cargados: {len(data)} muestras")

    # Preparar características
    features = ['packet_size', 'dest_port', 'src_port', 'timestamp_hour', 'timestamp_minute']
    X = data[features]

    # Normalizar datos
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Crear directorio de modelos
    models_dir = Path('models')
    models_dir.mkdir(exist_ok=True)

    models = {}

    # 1. Isolation Forest
    print("🌲 Entrenando Isolation Forest...")
    iso_forest = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
    iso_forest.fit(X_scaled)
    models['IsolationForest'] = iso_forest

    # 2. One-Class SVM
    print("🔮 Entrenando One-Class SVM...")
    oc_svm = OneClassSVM(kernel='rbf', gamma='scale', nu=0.1)
    oc_svm.fit(X_scaled)
    models['OneClassSVM'] = oc_svm

    # 3. Elliptic Envelope
    print("📐 Entrenando Elliptic Envelope...")
    elliptic = EllipticEnvelope(contamination=0.1, random_state=42)
    elliptic.fit(X_scaled)
    models['EllipticEnvelope'] = elliptic

    # 4. Local Outlier Factor
    print("🎯 Entrenando Local Outlier Factor...")
    lof = LocalOutlierFactor(n_neighbors=20, contamination=0.1, novelty=True)
    lof.fit(X_scaled)
    models['LocalOutlierFactor'] = lof

    # 5. Random Forest (para clasificación supervisada)
    print("🌳 Entrenando Random Forest...")
    # Crear etiquetas sintéticas para ejemplo
    y = np.zeros(len(X_scaled))
    anomaly_indices = np.random.choice(len(X_scaled), size=int(len(X_scaled) * 0.05), replace=False)
    y[anomaly_indices] = 1

    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
    rf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    rf.fit(X_train, y_train)
    models['RandomForest'] = rf

    # 6. XGBoost (si está disponible)
    if XGBOOST_AVAILABLE:
        print("🚀 Entrenando XGBoost...")
        xgb_model = xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42)
        xgb_model.fit(X_train, y_train)
        models['XGBoost'] = xgb_model

    # Guardar modelos
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    for name, model in models.items():
        model_file = models_dir / f"{name}_{timestamp}.pkl"
        with open(model_file, 'wb') as f:
            pickle.dump(model, f)
        print(f"💾 Modelo guardado: {model_file}")

    # Guardar scaler
    scaler_file = models_dir / f"scaler_{timestamp}.pkl"
    with open(scaler_file, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"💾 Scaler guardado: {scaler_file}")

    print(f"✅ Entrenamiento completado: {len(models)} modelos")
    return models

if __name__ == "__main__":
    train_models()
'''

        with open('retrain_models.py', 'w') as f:
            f.write(script_content)

        os.chmod('retrain_models.py', 0o755)
        print("✅ Script de reentrenamiento creado: retrain_models.py")

    def create_directories(self):
        """Crear directorios necesarios"""
        directories = ['models', 'logs', 'data', 'config_backups']

        for directory in directories:
            Path(directory).mkdir(exist_ok=True)
            print(f"✅ Directorio creado/verificado: {directory}")

    def run_full_fix(self):
        """Ejecutar reparación completa"""
        print("🔧 Iniciando reparación completa de configuraciones...")

        # 1. Crear directorios
        self.create_directories()

        # 2. Backup de configuraciones existentes
        self.backup_existing_configs()

        # 3. Crear nuevas configuraciones
        ml_config = self.create_ml_detector_config()
        dashboard_config = self.create_dashboard_config()
        agent_config = self.create_agent_config()

        # 4. Crear scripts auxiliares
        self.create_geolocation_fallback_script()
        self.create_model_retraining_script()

        print("\n✅ Reparación completa finalizada!")
        print("\n📋 PRÓXIMOS PASOS:")
        print("1. Revisar configuraciones generadas")
        print("2. Ejecutar: python retrain_models.py")
        print("3. Reiniciar sistema: make stop-firewall && make run-firewall")
        print("4. Verificar: python diagnostic_script.py")

        return {
            'ml_config': ml_config,
            'dashboard_config': dashboard_config,
            'agent_config': agent_config,
            'backup_created': True,
            'scripts_created': True
        }


def main():
    """Función principal"""
    fixer = ConfigurationFixer()
    result = fixer.run_full_fix()

    print(f"\n📊 RESUMEN:")
    print(f"   ✅ Configuraciones creadas: {len(fixer.config_files)}")
    print(f"   ✅ Scripts auxiliares: 2")
    print(f"   ✅ Backups realizados: {result['backup_created']}")

    return result


if __name__ == "__main__":
    main()