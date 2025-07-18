#!/usr/bin/env python3
"""
retrain_models.py - Reentrenamiento de Modelos ML para Sistema SCADA
Entrena los 6 modelos ML requeridos con datos sintéticos o reales
Uso: python retrain_models.py [--force] [--real-data] [--quick]
"""

import json
import pickle
import numpy as np
import pandas as pd
import argparse
import logging
from pathlib import Path
from datetime import datetime
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.covariance import EllipticEnvelope
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import warnings

warnings.filterwarnings('ignore')

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    import xgboost as xgb

    XGBOOST_AVAILABLE = True
    logger.info("✅ XGBoost disponible")
except ImportError:
    XGBOOST_AVAILABLE = False
    logger.warning("⚠️ XGBoost no disponible - se omitirá este modelo")


class MLModelTrainer:
    def __init__(self, force_retrain=False, use_real_data=False, quick_mode=False):
        self.force_retrain = force_retrain
        self.use_real_data = use_real_data
        self.quick_mode = quick_mode
        self.models_dir = Path('models')
        self.models_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Configuración de modelos
        self.model_configs = {
            'IsolationForest': {
                'contamination': 0.1,
                'random_state': 42,
                'n_estimators': 50 if quick_mode else 100
            },
            'OneClassSVM': {
                'kernel': 'rbf',
                'gamma': 'scale',
                'nu': 0.1
            },
            'EllipticEnvelope': {
                'contamination': 0.1,
                'random_state': 42
            },
            'LocalOutlierFactor': {
                'n_neighbors': 10 if quick_mode else 20,
                'contamination': 0.1,
                'novelty': True
            },
            'RandomForest': {
                'n_estimators': 50 if quick_mode else 100,
                'random_state': 42,
                'max_depth': 10
            }
        }

        if XGBOOST_AVAILABLE:
            self.model_configs['XGBoost'] = {
                'n_estimators': 50 if quick_mode else 100,
                'max_depth': 6,
                'learning_rate': 0.1,
                'random_state': 42
            }

    def load_real_data(self):
        """Cargar datos reales desde logs del sistema"""
        logger.info("📊 Intentando cargar datos reales desde logs...")

        # Intentar cargar desde diferentes fuentes
        data_sources = [
            'logs/network_events.json',
            'logs/captured_events.csv',
            'data/training_data.csv'
        ]

        for source in data_sources:
            if Path(source).exists():
                try:
                    if source.endswith('.json'):
                        with open(source, 'r') as f:
                            events = [json.loads(line) for line in f if line.strip()]
                        df = pd.DataFrame(events)
                    else:
                        df = pd.read_csv(source)

                    if len(df) > 100:
                        logger.info(f"✅ Datos reales cargados desde {source}: {len(df)} registros")
                        return self.prepare_features(df)

                except Exception as e:
                    logger.warning(f"⚠️ Error cargando {source}: {e}")
                    continue

        logger.warning("⚠️ No se encontraron datos reales, usando datos sintéticos")
        return self.generate_synthetic_data()

    def generate_synthetic_data(self):
        """Generar datos sintéticos realistas para entrenamiento"""
        logger.info("🎲 Generando datos sintéticos...")

        np.random.seed(42)
        n_samples = 5000 if self.quick_mode else 20000

        # Puertos comunes y sus probabilidades
        common_ports = [22, 80, 443, 21, 25, 53, 993, 995, 3389, 5432, 1433]
        port_weights = [0.15, 0.25, 0.20, 0.05, 0.05, 0.10, 0.03, 0.03, 0.08, 0.03, 0.03]

        # Generar características base
        data = {
            'packet_size': np.random.lognormal(mean=6, sigma=1.5, size=n_samples),
            'dest_port': np.random.choice(common_ports, n_samples, p=port_weights),
            'src_port': np.random.randint(1024, 65535, n_samples),
            'timestamp_hour': np.random.randint(0, 24, n_samples),
            'timestamp_minute': np.random.randint(0, 60, n_samples),
            'ip_frequency': np.random.exponential(scale=2, size=n_samples),
            'connection_duration': np.random.gamma(shape=2, scale=1, size=n_samples)
        }

        df = pd.DataFrame(data)

        # Añadir características derivadas
        df['hour_category'] = pd.cut(df['timestamp_hour'],
                                     bins=[0, 6, 12, 18, 24],
                                     labels=['night', 'morning', 'afternoon', 'evening'])

        df['port_category'] = df['dest_port'].apply(self.categorize_port)
        df['packet_size_log'] = np.log1p(df['packet_size'])

        # Crear etiquetas (0=normal, 1=anomalía)
        anomaly_ratio = 0.05
        n_anomalies = int(n_samples * anomaly_ratio)

        df['is_anomaly'] = 0
        anomaly_indices = np.random.choice(n_samples, size=n_anomalies, replace=False)
        df.loc[anomaly_indices, 'is_anomaly'] = 1

        # Hacer que las anomalías sean más obvias
        df.loc[anomaly_indices, 'packet_size'] *= np.random.uniform(5, 20, n_anomalies)
        df.loc[anomaly_indices, 'dest_port'] = np.random.choice([9999, 8080, 4444, 1337], n_anomalies)
        df.loc[anomaly_indices, 'ip_frequency'] *= np.random.uniform(10, 50, n_anomalies)

        logger.info(f"✅ Datos sintéticos generados: {len(df)} muestras, {n_anomalies} anomalías")
        return df

    def categorize_port(self, port):
        """Categorizar puertos por tipo de servicio"""
        if port in [80, 443, 8080, 8443]:
            return 'web'
        elif port in [22, 23]:
            return 'remote'
        elif port in [21, 22]:
            return 'file_transfer'
        elif port in [25, 993, 995, 143, 110]:
            return 'email'
        elif port in [53]:
            return 'dns'
        elif port in [3389, 5900]:
            return 'desktop'
        elif port in [1433, 3306, 5432]:
            return 'database'
        else:
            return 'other'

    def prepare_features(self, df):
        """Preparar características para entrenamiento"""
        logger.info("🔧 Preparando características...")

        # Seleccionar características numéricas
        numeric_features = []
        for col in ['packet_size', 'dest_port', 'src_port', 'timestamp_hour',
                    'timestamp_minute', 'ip_frequency', 'connection_duration']:
            if col in df.columns:
                numeric_features.append(col)

        # Crear características derivadas si no existen
        if 'packet_size_log' not in df.columns and 'packet_size' in df.columns:
            df['packet_size_log'] = np.log1p(df['packet_size'])
            numeric_features.append('packet_size_log')

        # Codificar características categóricas
        categorical_features = []
        label_encoders = {}

        for col in ['hour_category', 'port_category']:
            if col in df.columns:
                le = LabelEncoder()
                df[f'{col}_encoded'] = le.fit_transform(df[col].astype(str))
                categorical_features.append(f'{col}_encoded')
                label_encoders[col] = le

        # Combinar todas las características
        all_features = numeric_features + categorical_features
        feature_matrix = df[all_features].fillna(0)

        logger.info(f"✅ Características preparadas: {len(all_features)} features")
        logger.info(f"   Numéricas: {numeric_features}")
        logger.info(f"   Categóricas: {categorical_features}")

        return feature_matrix, df.get('is_anomaly', np.zeros(len(df))), label_encoders

    def train_isolation_forest(self, X):
        """Entrenar Isolation Forest"""
        logger.info("🌲 Entrenando Isolation Forest...")
        model = IsolationForest(**self.model_configs['IsolationForest'])
        model.fit(X)

        # Evaluar
        predictions = model.predict(X)
        anomaly_ratio = np.sum(predictions == -1) / len(predictions)
        logger.info(f"   Anomalías detectadas: {anomaly_ratio:.2%}")

        return model

    def train_one_class_svm(self, X):
        """Entrenar One-Class SVM"""
        logger.info("🔮 Entrenando One-Class SVM...")
        model = OneClassSVM(**self.model_configs['OneClassSVM'])
        model.fit(X)

        predictions = model.predict(X)
        anomaly_ratio = np.sum(predictions == -1) / len(predictions)
        logger.info(f"   Anomalías detectadas: {anomaly_ratio:.2%}")

        return model

    def train_elliptic_envelope(self, X):
        """Entrenar Elliptic Envelope"""
        logger.info("📐 Entrenando Elliptic Envelope...")
        model = EllipticEnvelope(**self.model_configs['EllipticEnvelope'])
        model.fit(X)

        predictions = model.predict(X)
        anomaly_ratio = np.sum(predictions == -1) / len(predictions)
        logger.info(f"   Anomalías detectadas: {anomaly_ratio:.2%}")

        return model

    def train_local_outlier_factor(self, X):
        """Entrenar Local Outlier Factor"""
        logger.info("🎯 Entrenando Local Outlier Factor...")
        model = LocalOutlierFactor(**self.model_configs['LocalOutlierFactor'])
        model.fit(X)

        return model

    def train_random_forest(self, X, y):
        """Entrenar Random Forest para clasificación supervisada"""
        logger.info("🌳 Entrenando Random Forest...")

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        model = RandomForestClassifier(**self.model_configs['RandomForest'])
        model.fit(X_train, y_train)

        # Evaluar
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        logger.info(f"   Accuracy: {accuracy:.3f}")

        return model

    def train_xgboost(self, X, y):
        """Entrenar XGBoost si está disponible"""
        if not XGBOOST_AVAILABLE:
            return None

        logger.info("🚀 Entrenando XGBoost...")

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        model = xgb.XGBClassifier(**self.model_configs['XGBoost'])
        model.fit(X_train, y_train)

        # Evaluar
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        logger.info(f"   Accuracy: {accuracy:.3f}")

        return model

    def save_model(self, model, name):
        """Guardar modelo en disco"""
        if model is None:
            return None

        model_file = self.models_dir / f"{name}_{self.timestamp}.pkl"
        with open(model_file, 'wb') as f:
            pickle.dump(model, f)

        # También crear enlace simbólico al modelo más reciente
        latest_file = self.models_dir / f"{name}_latest.pkl"
        if latest_file.exists():
            latest_file.unlink()
        latest_file.symlink_to(model_file.name)

        logger.info(f"💾 Modelo guardado: {model_file}")
        return model_file

    def save_metadata(self, models_info, feature_names, label_encoders):
        """Guardar metadatos de entrenamiento"""
        metadata = {
            'timestamp': self.timestamp,
            'models': models_info,
            'feature_names': feature_names,
            'label_encoders': {k: v.classes_.tolist() for k, v in label_encoders.items()},
            'training_config': {
                'quick_mode': self.quick_mode,
                'use_real_data': self.use_real_data,
                'force_retrain': self.force_retrain
            },
            'model_configs': self.model_configs
        }

        metadata_file = self.models_dir / f"metadata_{self.timestamp}.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)

        # También crear enlace al metadata más reciente
        latest_metadata = self.models_dir / "metadata_latest.json"
        if latest_metadata.exists():
            latest_metadata.unlink()
        latest_metadata.symlink_to(metadata_file.name)

        logger.info(f"📋 Metadata guardado: {metadata_file}")

    def train_all_models(self):
        """Entrenar todos los modelos ML"""
        logger.info("🤖 Iniciando entrenamiento de todos los modelos...")
        start_time = datetime.now()

        # Cargar datos
        if self.use_real_data:
            X, y, label_encoders = self.load_real_data()
        else:
            df = self.generate_synthetic_data()
            X, y, label_encoders = self.prepare_features(df)

        # Normalizar características
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        logger.info(f"📊 Datos preparados: {X_scaled.shape[0]} muestras, {X_scaled.shape[1]} características")

        # Entrenar modelos
        trained_models = {}
        models_info = {}

        # Modelos no supervisados
        trained_models['IsolationForest'] = self.train_isolation_forest(X_scaled)
        trained_models['OneClassSVM'] = self.train_one_class_svm(X_scaled)
        trained_models['EllipticEnvelope'] = self.train_elliptic_envelope(X_scaled)
        trained_models['LocalOutlierFactor'] = self.train_local_outlier_factor(X_scaled)

        # Modelos supervisados
        trained_models['RandomForest'] = self.train_random_forest(X_scaled, y)

        if XGBOOST_AVAILABLE:
            trained_models['XGBoost'] = self.train_xgboost(X_scaled, y)

        # Guardar modelos
        for name, model in trained_models.items():
            if model is not None:
                model_file = self.save_model(model, name)
                models_info[name] = {
                    'file': str(model_file),
                    'type': 'unsupervised' if name in ['IsolationForest', 'OneClassSVM',
                                                       'EllipticEnvelope', 'LocalOutlierFactor'] else 'supervised',
                    'config': self.model_configs[name]
                }

        # Guardar scaler
        scaler_file = self.save_model(scaler, 'scaler')

        # Guardar metadata
        self.save_metadata(models_info, X.columns.tolist(), label_encoders)

        # Resumen
        duration = datetime.now() - start_time
        logger.info(f"✅ Entrenamiento completado en {duration.total_seconds():.1f} segundos")
        logger.info(f"📊 Modelos entrenados: {len([m for m in trained_models.values() if m is not None])}")

        return trained_models, models_info


def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description='Reentrenar modelos ML del sistema SCADA')
    parser.add_argument('--force', action='store_true', help='Forzar reentrenamiento aunque existan modelos')
    parser.add_argument('--real-data', action='store_true', help='Usar datos reales en lugar de sintéticos')
    parser.add_argument('--quick', action='store_true', help='Modo rápido (menos estimadores)')

    args = parser.parse_args()

    # Verificar si ya existen modelos
    models_dir = Path('models')
    existing_models = list(models_dir.glob('*.pkl')) if models_dir.exists() else []

    if existing_models and not args.force:
        logger.warning(f"⚠️ Ya existen {len(existing_models)} modelos en {models_dir}")
        logger.warning("   Usa --force para reentrenar o elimina los modelos existentes")
        return

    # Crear entrenador y ejecutar
    trainer = MLModelTrainer(
        force_retrain=args.force,
        use_real_data=args.real_data,
        quick_mode=args.quick
    )

    models, info = trainer.train_all_models()

    print("\n" + "=" * 60)
    print("📋 RESUMEN DE ENTRENAMIENTO")
    print("=" * 60)
    print(f"⏱️  Timestamp: {trainer.timestamp}")
    print(f"🤖 Modelos entrenados: {len([m for m in models.values() if m is not None])}/6")
    print(f"📁 Directorio: {trainer.models_dir}")
    print("🎯 Modelos disponibles:")
    for name, model in models.items():
        status = "✅" if model is not None else "❌"
        print(f"   {status} {name}")

    if args.quick:
        print("⚡ Modo rápido utilizado - considera reentrenar sin --quick para producción")

    print("\n🚀 Para aplicar los modelos, reinicia el sistema:")
    print("   make stop-firewall && make run-firewall")


if __name__ == "__main__":
    main()