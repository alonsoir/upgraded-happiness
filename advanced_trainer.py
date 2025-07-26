import os
import json
import zipfile
import argparse
from pathlib import Path
from collections import Counter
import joblib
from datetime import datetime
import geoip2.database
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve, auc
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline
from kaggle.api.kaggle_api_extended import KaggleApi
import shap


# -----------------------------------------------------------------------------
# 📁 CONFIGURACIÓN CENTRALIZADA
# -----------------------------------------------------------------------------
def load_config():
    config_path = Path("config-advanced-trainer.json")
    if not config_path.exists():
        raise FileNotFoundError("No se encontró el archivo de configuración.")
    with open(config_path, "r") as f:
        return json.load(f)


# -----------------------------------------------------------------------------
# 📚 DICCIONARIO DE CARACTERÍSTICAS (PARA REPRODUCIBILIDAD)
# -----------------------------------------------------------------------------
FEATURE_DESCRIPTIONS = {
    # Características básicas de flujo
    'dur': 'Duración de la conexión en segundos',
    'proto': 'Protocolo de transporte (codificado numéricamente)',
    'service': 'Servicio de red (codificado numéricamente)',
    'state': 'Estado de la conexión (codificado numéricamente)',
    'spkts': 'Número de paquetes enviados por el origen',
    'dpkts': 'Número de paquetes enviados por el destino',
    'sbytes': 'Número de bytes enviados por el origen',
    'dbytes': 'Número de bytes enviados por el destino',
    'rate': 'Tasa de paquetes por segundo',
    'sttl': 'Time-to-live (TTL) del origen',
    'dttl': 'Time-to-live (TTL) del destino',
    'sload': 'Carga de datos del origen (bytes/segundo)',
    'dload': 'Carga de datos del destino (bytes/segundo)',
    'sloss': 'Pérdida de paquetes del origen',
    'dloss': 'Pérdida de paquetes del destino',
    'sinpkt': 'Intervalo entre paquetes entrantes (origen)',
    'dinpkt': 'Intervalo entre paquetes entrantes (destino)',

    # Características derivadas
    'packet_imbalance': 'Ratio entre paquetes origen/destino',
    'byte_imbalance': 'Ratio entre bytes origen/destino',
    'loss_ratio': 'Ratio de pérdida de paquetes del origen',

    # Características temporales
    'hour': 'Hora del día en que ocurrió la conexión (0-23)',
    'day_of_week': 'Día de la semana (0=Lunes, 6=Domingo)',
    'is_weekend': 'Indica si ocurrió en fin de semana (1=Sí, 0=No)',

    # Geolocalización
    'src_country': 'Código de país del origen (codificado numéricamente)',
    'src_asn': 'Número de sistema autónomo (ASN) del origen',
    'country_risk': 'Puntuación de riesgo del país de origen (0-1)',
    'distance_km': 'Distancia en km desde la IP de origen a la sede central',

    # Características adicionales de seguridad
    'conn_state_abnormal': 'Indica si el estado de conexión es anormal (1=Sí, 0=No)',
    'high_port_activity': 'Indica si se usaron puertos altos (>1024) en origen o destino'
}


# -----------------------------------------------------------------------------
# 🌍 GEOENRIQUECIMIENTO
# -----------------------------------------------------------------------------
class GeoEnricher:
    def __init__(self, config):
        self.geoip_city = geoip2.database.Reader(config['geo']['city_db_path'])
        self.geoip_country = geoip2.database.Reader(config['geo']['country_db_path'])
        self.hq_coords = tuple(config['geo']['hq_coords'])
        self.country_risk_scores = config['geo'].get('country_risk_scores', {})
        self.ip_cache = {}

    def enrich_ip(self, ip):
        if ip in self.ip_cache:
            return self.ip_cache[ip]

        try:
            response = self.geoip_city.city(ip)
            result = {
                'country': response.country.iso_code,
                'city': response.city.name,
                'asn': response.traits.autonomous_system_number,
                'lat': response.location.latitude,
                'lon': response.location.longitude,
                'country_risk': self.country_risk_scores.get(response.country.iso_code, 0.5),
                'distance_km': self.calculate_distance(
                    response.location.latitude,
                    response.location.longitude
                )
            }
        except:
            try:
                response = self.geoip_country.country(ip)
                result = {
                    'country': response.country.iso_code,
                    'city': "Unknown",
                    'asn': 0,
                    'lat': 0,
                    'lon': 0,
                    'country_risk': self.country_risk_scores.get(response.country.iso_code, 0.5),
                    'distance_km': 0
                }
            except:
                result = {
                    'country': "UNKNOWN",
                    'city': "Unknown",
                    'asn': 0,
                    'lat': 0,
                    'lon': 0,
                    'country_risk': 0.5,
                    'distance_km': 0
                }

        self.ip_cache[ip] = result
        return result

    def calculate_distance(self, lat, lon):
        if lat == 0 or lon == 0:
            return 0

        hq_lat, hq_lon = self.hq_coords
        lat_diff = abs(lat - hq_lat)
        lon_diff = abs(lon - hq_lon)
        return 111 * np.sqrt(lat_diff ** 2 + lon_diff ** 2)


# -----------------------------------------------------------------------------
# ⬇️ CARGA DE DATASETS COMBINADOS
# -----------------------------------------------------------------------------
def load_combined_datasets(config):
    dataset_names = config['ml'].get('datasets', ["UNSW-NB15", "CSE-CIC-IDS2018", "TON-IoT"])
    datasets = []

    for name in dataset_names:
        try:
            df = load_dataset(config, name)
            df['dataset_source'] = name
            datasets.append(df)
            print(f"[✅] {name} cargado con {len(df)} registros")

            # Verificar etiquetas en el dataset
            if 'label' in df.columns:
                print(f"  - Distribución de etiquetas: {dict(df['label'].value_counts())}")
            else:
                print("  - No se encontró columna 'label'")
        except Exception as e:
            print(f"[❌] Error cargando {name}: {str(e)}")

    if not datasets:
        raise ValueError("No se pudo cargar ningún dataset")

    # Combinar datasets
    combined = pd.concat(datasets, ignore_index=True)
    print(f"[📊] Total de registros combinados: {len(combined)}")
    return combined


# -----------------------------------------------------------------------------
# 🧠 ENTRENAMIENTO DE ALTA PRECISIÓN
# -----------------------------------------------------------------------------
def train_high_precision_rf(X_train, y_train, config):
    # Parámetros optimizados para máxima precisión
    rf_params = {
        'n_estimators': 2000,
        'max_depth': 120,
        'min_samples_split': 2,
        'min_samples_leaf': 1,
        'max_features': 'log2',
        'bootstrap': True,
        'oob_score': True,
        'n_jobs': -1,
        'random_state': 42,
        'class_weight': 'balanced_subsample',
        'ccp_alpha': 0.0001,
        'max_samples': 0.8
    }

    # Sobreescribir con configuración si existe
    if 'random_forest' in config['ml']['models']:
        rf_params.update(config['ml']['models']['random_forest'])

    print("[🎯] Entrenando RandomForest para máxima precisión:")
    for k, v in rf_params.items():
        print(f"  - {k}: {v}")

    # Validación cruzada estratificada
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    fold_scores = []
    models = []

    for fold, (train_idx, val_idx) in enumerate(skf.split(X_train, y_train)):
        X_fold_train, y_fold_train = X_train[train_idx], y_train[train_idx]
        X_val, y_val = X_train[val_idx], y_train[val_idx]

        model = RandomForestClassifier(**rf_params)
        model.fit(X_fold_train, y_fold_train)

        # Calcular precisión en el fold de validación
        y_pred = model.predict(X_val)
        accuracy = np.mean(y_pred == y_val)
        fold_scores.append(accuracy)
        models.append(model)

        print(f"[🔍] Fold {fold + 1} - Precisión: {accuracy:.4f}")

    # Seleccionar el mejor modelo
    best_idx = np.argmax(fold_scores)
    best_model = models[best_idx]
    print(f"[🏆] Mejor fold: {best_idx + 1} con precisión {fold_scores[best_idx]:.4f}")

    # Entrenar modelo final con todos los datos
    print("[🚀] Entrenando modelo final con todos los datos...")
    final_model = RandomForestClassifier(**rf_params)
    final_model.fit(X_train, y_train)

    # Usar SHAP para explicabilidad
    print("[🔎] Generando explicaciones SHAP...")
    explainer = shap.TreeExplainer(final_model)
    shap_values = explainer.shap_values(X_train[:1000])  # Muestra representativa

    return final_model, explainer


def load_dataset(config, dataset_name, max_rows=0):
    base_data_dir = Path("./data")
    base_data_dir.mkdir(exist_ok=True)

    dataset_config = {
        "UNSW-NB15": {
            "kaggle": "mrwellsdavid/unsw-nb15",
            "csv_file": "UNSW_NB15_training-set.csv",
            "label_col": "label"
        },
        "CSE-CIC-IDS2018": {
            "kaggle": "devendra416/ddos-datasets",
            "csv_file": "ddos_data.csv",
            "label_col": "Label"
        },
        "TON-IoT": {
            "kaggle": "kyeong500/toniot-network-dataset",
            "csv_file": "TON_IoT_Network_Dataset_1.csv",
            "label_col": "label"
        },
        "CIC-Bell-DNS-EXF-2021": {
            "kaggle": "jesucristo/cicbell-dns-exf-2021",
            "csv_file": "dns_exfiltration.csv",
            "label_col": "malicious"
        }
    }

    ds_cfg = dataset_config[dataset_name]
    default_csv = base_data_dir / f"{dataset_name}.csv"

    # Intentar carga local
    if default_csv.exists():
        print(f"[📁] Cargando {dataset_name} desde: {default_csv}")
        df = pd.read_csv(default_csv, nrows=max_rows if max_rows > 0 else None)

        # Verificar etiquetas durante la carga
        if ds_cfg["label_col"] in df.columns:
            label_counts = df[ds_cfg["label_col"]].value_counts()
            print(f"  - Distribución inicial de etiquetas: {dict(label_counts)}")
        else:
            print(f"  - No se encontró columna de etiqueta: {ds_cfg['label_col']}")

        return df

    # Descargar desde Kaggle
    try:
        print(f"[⬇️] Descargando {dataset_name} desde Kaggle...")
        api = KaggleApi()
        api.authenticate()
        api.dataset_download_files(ds_cfg["kaggle"], path=base_data_dir, quiet=False)

        zip_file = base_data_dir / f"{dataset_name}.zip"
        if not zip_file.exists():
            raise FileNotFoundError(f"No se encontró el archivo descargado: {zip_file}")

        print(f"[📦] Extrayendo {zip_file}...")
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall(base_data_dir)

        # Buscar archivo CSV
        csv_path = None
        for file in base_data_dir.glob("**/*.csv"):
            if ds_cfg["csv_file"] in file.name:
                csv_path = file
                break

        if not csv_path:
            raise FileNotFoundError(f"No se encontró {ds_cfg['csv_file']} en {zip_file}")

        print(f"[✅] {dataset_name} cargado desde: {csv_path}")
        df = pd.read_csv(csv_path, nrows=max_rows if max_rows > 0 else None)

        # Verificar etiquetas durante la carga
        if ds_cfg["label_col"] in df.columns:
            label_counts = df[ds_cfg["label_col"]].value_counts()
            print(f"  - Distribución inicial de etiquetas: {dict(label_counts)}")
        else:
            print(f"  - No se encontró columna de etiqueta: {ds_cfg['label_col']}")

        # Guardar copia local
        df.to_csv(default_csv, index=False)
        print(f"[💾] Guardado copia local en: {default_csv}")

        return df

    except Exception as e:
        print(f"[❌] Error al descargar {dataset_name}: {e}")
        raise


# -----------------------------------------------------------------------------
# 🧹 PREPROCESAMIENTO AVANZADO
# -----------------------------------------------------------------------------
def advanced_preprocessing(df, geo_enricher):
    # 1. Manejo de características temporales
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)

    # 2. Enriquecimiento geográfico
    print("[🌍] Enriqueciendo datos con geolocalización...")

    # Ampliar posibles nombres de columnas IP
    possible_ip_columns = [
        'src_ip', 'source_ip', 'ip_src', 'ip', 'srcaddr', 'Source IP',
        'src_ipv4', 'source_address', 'src_address', 'ip_source',
        'sourceip', 'srcip', 'source_ipv4', 'src_ipv4'
    ]

    ip_col = None
    for col in possible_ip_columns:
        if col in df.columns:
            ip_col = col
            print(f"[🔍] Usando columna IP: {ip_col}")
            break

    if ip_col is None:
        print("[⚠️] No se encontró columna de dirección IP. Usando IPs dummy.")
        df['ip_dummy'] = "0.0.0.0"
        ip_col = 'ip_dummy'
    else:
        print(f"[📍] Columna IP detectada: {ip_col}")

    # Solo hacer enriquecimiento si tenemos IPs reales
    if ip_col != 'ip_dummy':
        print(f"[🌐] Procesando {df[ip_col].nunique()} IPs únicas...")
        geo_data = []
        unique_ips = df[ip_col].unique()

        for i, ip in enumerate(unique_ips):
            if i % 1000 == 0:
                print(f"  - Procesando IP {i + 1}/{len(unique_ips)}")
            geo_data.append((ip, geo_enricher.enrich_ip(ip)))

        geo_df = pd.DataFrame(
            [data[1] for data in geo_data],
            index=[data[0] for data in geo_data]
        )

        df = df.merge(geo_df, left_on=ip_col, right_index=True, how='left')
    else:
        print("[⏩] Saltando enriquecimiento geográfico - sin IPs reales")
        # Añadir valores dummy
        df['src_country'] = "UNKNOWN"
        df['src_asn'] = 0
        df['country_risk'] = 0.5
        df['distance_km'] = 0

    # 3. Normalización de protocolos
    if 'proto' in df.columns:
        df['proto'] = df['proto'].str.lower().str.replace('[^a-z0-9]', '', regex=True)

    # 4. Eliminación de columnas problemáticas
    drop_cols = ['id', 'attack_cat', 'flow_id', 'Unnamed: 0', 'Label']
    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors='ignore')

    # 5. Codificación de variables categóricas
    cat_cols = ['proto', 'service', 'state', 'country', 'city']
    for col in cat_cols:
        if col in df.columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))

    # 6. Manejo de valores faltantes
    df = df.fillna(0)

    # 7. Eliminar columnas no numéricas residuales
    non_numeric_cols = ['timestamp', 'src_ip', 'dst_ip', 'city', 'country', 'ip_dummy']
    for col in non_numeric_cols:
        if col in df.columns:
            df = df.drop(columns=[col], errors='ignore')

    # 8. Eliminar columnas con nombres duplicados
    df = df.loc[:, ~df.columns.duplicated()]

    return df


# -----------------------------------------------------------------------------
# ⚖️ BALANCEO HÍBRIDO
# -----------------------------------------------------------------------------
def hybrid_balancing(X, y):
    print("[⚖️] Aplicando balanceo híbrido...")

    # Contar muestras por clase
    class_counts = Counter(y)
    print(f"[📊] Distribución inicial: {class_counts}")

    if len(class_counts) < 2:
        raise ValueError("Solo se encontró una clase. Se necesitan ambas clases para balancear.")

    majority_class = max(class_counts, key=class_counts.get)
    minority_class = min(class_counts, key=class_counts.get)

    # Estrategia de balanceo
    sampling_strategy = {
        majority_class: int(class_counts[majority_class] * 0.7),
        minority_class: min(class_counts[majority_class] * 2, class_counts[minority_class] * 10)
    }

    print(f"[⚖️] Estrategia de balanceo: {sampling_strategy}")

    # Pipeline de balanceo
    pipeline = Pipeline([
        ('oversample', SMOTE(sampling_strategy={minority_class: sampling_strategy[minority_class]},
                             random_state=42)),
        ('undersample', RandomUnderSampler(sampling_strategy={majority_class: sampling_strategy[majority_class]},
                                           random_state=42))
    ])

    X_res, y_res = pipeline.fit_resample(X, y)
    print(f"[⚖️] Distribución después de balanceo: {Counter(y_res)}")
    return X_res, y_res


# -----------------------------------------------------------------------------
# 🧠 ENTRENAMIENTO AGGRESIVO DE RANDOM FOREST
# -----------------------------------------------------------------------------
def train_aggressive_rf(X_train, y_train, config):
    rf_params = {
        'n_estimators': 1500,
        'max_depth': 100,
        'min_samples_split': 2,
        'min_samples_leaf': 1,
        'max_features': 'sqrt',
        'bootstrap': True,
        'oob_score': True,
        'n_jobs': -1,
        'random_state': 42,
        'class_weight': 'balanced_subsample',
        'ccp_alpha': 0.0001,
        'max_samples': 0.8
    }

    # Sobreescribir con configuración si existe
    if 'random_forest' in config['ml']['models']:
        rf_params.update(config['ml']['models']['random_forest'])

    print("[🌲] Entrenando RandomForest con parámetros agresivos:")
    for k, v in rf_params.items():
        print(f"  - {k}: {v}")

    model = RandomForestClassifier(**rf_params)
    model.fit(X_train, y_train)

    if hasattr(model, 'oob_score_'):
        print(f"[🔍] Precisión OOB: {model.oob_score_:.4f}")

    return model


# -----------------------------------------------------------------------------
# 📊 EVALUACIÓN AVANZADA
# -----------------------------------------------------------------------------
def advanced_evaluation(model, X_test, y_test):
    print("[🧪] Evaluando modelo...")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    print("\n[📊] Matriz de Confusión:")
    print(confusion_matrix(y_test, y_pred))

    print("\n[📋] Reporte de Clasificación:")
    print(classification_report(y_test, y_pred))

    # Calcular AUC-ROC y AUC-PR
    roc_auc = roc_auc_score(y_test, y_proba)
    precision, recall, _ = precision_recall_curve(y_test, y_proba)
    pr_auc = auc(recall, precision)

    print(f"[📈] AUC-ROC: {roc_auc:.4f}")
    print(f"[📈] AUC-PR: {pr_auc:.4f}")

    # Calcular métricas específicas para seguridad
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0
    precision_pos = tp / (tp + fp) if (tp + fp) > 0 else 0

    print("\n[🔒] Métricas de Seguridad:")
    print(f"  - Tasa de Falsos Positivos (FPR): {fpr:.4f}")
    print(f"  - Tasa de Falsos Negativos (FNR): {fnr:.4f}")
    print(f"  - Tasa de Detección: {detection_rate:.4f}")
    print(f"  - Precisión en Amenazas: {precision_pos:.4f}")

    return {
        'roc_auc': roc_auc,
        'pr_auc': pr_auc,
        'fpr': fpr,
        'fnr': fnr,
        'detection_rate': detection_rate,
        'precision_pos': precision_pos
    }


# -----------------------------------------------------------------------------
# 💾 GUARDADO DE ARTEFACTOS
# -----------------------------------------------------------------------------
def save_advanced_artifacts(model, explainer, config, features, geo_enricher, evaluation_metrics, scaler):
    os.makedirs("models", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_dir = Path("models") / f"model_{timestamp}"
    model_dir.mkdir(exist_ok=True)

    # 1. Guardar modelo
    model_path = model_dir / "model.pkl"
    joblib.dump(model, model_path)

    # 2. Guardar explainer SHAP
    explainer_path = model_dir / "shap_explainer.pkl"
    joblib.dump(explainer, explainer_path)

    # 3. Guardar metadatos detallados
    metadata = {
        "training_date": timestamp,
        "feature_set": {
            "features": features,
            "descriptions": {feat: FEATURE_DESCRIPTIONS.get(feat, "Descripción no disponible")
                             for feat in features}
        },
        "datasets": config['ml'].get('datasets', []),
        "model_params": model.get_params(),
        "geo_config": {
            "hq_coords": config['geo']['hq_coords'],
            "country_risk_scores": geo_enricher.country_risk_scores
        },
        "evaluation_metrics": evaluation_metrics,
        "scapy_feature_template": generate_scapy_template(features)
    }

    metadata_path = model_dir / "metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=4)

    # 4. Guardar sistema de reputación ASN
    asn_reputation = build_asn_reputation(model, features)
    asn_path = model_dir / "asn_reputation.pkl"
    joblib.dump(asn_reputation, asn_path)

    # 5. Guardar escalador
    scaler_path = model_dir / "scaler.pkl"
    joblib.dump(scaler, scaler_path)

    print(f"[💾] Artefactos guardados en: {model_dir}")
    print(f"  - Modelo: {model_path}")
    print(f"  - Metadatos: {metadata_path}")
    print(f"  - Escalador: {scaler_path}")
    print(f"  - SHAP Explainer: {explainer_path}")
    print(f"  - Reputación ASN: {asn_path}")


def generate_scapy_template(features):
    """Genera plantilla para captura Scapy"""
    template = {
        "required_features": [],
        "feature_mapping": {}
    }

    scapy_mapping = {
        'dur': 'packet.time_delta',
        'proto': 'packet[IP].proto',
        'spkts': 'packet_count_src',
        'dpkts': 'packet_count_dst',
        'sbytes': 'packet_length_src',
        'dbytes': 'packet_length_dst',
        'sttl': 'packet[IP].ttl',
        # ... otros mapeos
    }

    for feat in features:
        if feat in scapy_mapping:
            template['required_features'].append(feat)
            template['feature_mapping'][feat] = scapy_mapping[feat]
        elif feat in ['packet_imbalance', 'byte_imbalance', 'loss_ratio']:
            template['feature_mapping'][feat] = f"Calculated from other features"
        elif feat in FEATURE_DESCRIPTIONS:
            template['required_features'].append(feat)
            template['feature_mapping'][feat] = "Custom calculation"

    return template


def build_asn_reputation(model, features):
    # Este sería un proceso más complejo en producción
    # Aquí un ejemplo simplificado
    return {
        "last_updated": datetime.now().isoformat(),
        "risk_factors": ["known_malicious", "high_attack_rate"],
        "version": "1.0"
    }


# -----------------------------------------------------------------------------
# 🚀 FUNCIÓN PRINCIPAL
# -----------------------------------------------------------------------------
def main():
    config = load_config()
    geo_enricher = GeoEnricher(config)

    # Cargar y combinar datasets
    print("[🔍] Cargando y combinando datasets...")
    df = load_combined_datasets(config)

    # Preprocesamiento avanzado
    print("[🧹] Realizando preprocesamiento avanzado...")
    df = advanced_preprocessing(df, geo_enricher)

    # Asignación robusta de etiquetas
    print("[🏷️] Asignando etiquetas unificadas...")

    # Definir mapeos de etiquetas por dataset (CORREGIDO)
    label_mappings = {
        'UNSW-NB15': ('label', lambda x: x),  # FIX: Mantener valores originales
        'CSE-CIC-IDS2018': ('Label', lambda x: 1 if x != 'Benign' else 0),
        'TON-IoT': ('label', lambda x: 1 if x != 'normal' else 0),
        'CIC-Bell-DNS-EXF-2021': ('malicious', lambda x: int(x))
    }

    # Inicializar columna de etiqueta unificada
    df['unified_label'] = np.nan

    for name in config['ml']['datasets']:
        if name in label_mappings:
            col_name, converter = label_mappings[name]
            if col_name in df.columns:
                print(f"[🔖] Mapeando etiquetas para {name} usando columna '{col_name}'")

                # Aplicar conversión solo al subconjunto del dataset
                mask = df['dataset_source'] == name
                df.loc[mask, 'unified_label'] = df.loc[mask, col_name].apply(converter)

                # Verificar distribución después del mapeo
                subset = df[df['dataset_source'] == name]
                counts = subset['unified_label'].value_counts()
                print(f"  - Distribución después de mapeo: {dict(counts)}")
            else:
                print(f"[⚠️] Columna '{col_name}' no encontrada en {name}")
                raise ValueError(f"Columna '{col_name}' no encontrada en dataset {name}")
        else:
            print(f"[⚠️] No se encontró mapeo para {name}")
            raise ValueError(f"No se encontró mapeo para dataset {name}")

    # Verificar que todas las etiquetas estén asignadas
    if df['unified_label'].isna().any():
        missing_count = df['unified_label'].isna().sum()
        print(f"[❌] Error: {missing_count} filas sin etiqueta asignada")
        raise ValueError("Algunas filas no tienen etiqueta asignada")

    # Verificar distribución global
    class_counts = df['unified_label'].value_counts()
    print(f"\n[📊] Distribución global de etiquetas:\n{class_counts}")

    if len(class_counts) < 2:
        print("[🔍] Analizando distribución por dataset:")
        for name in config['ml']['datasets']:
            subset = df[df['dataset_source'] == name]
            if not subset.empty:
                counts = subset['unified_label'].value_counts()
                print(f"  - {name}: {dict(counts)}")

        raise ValueError(
            "Solo se encontró una clase en los datos. Se necesitan ambas clases (benigno/maligno) para entrenar.")

    # Preparar datos para entrenamiento
    print("[⚙️] Preparando datos para entrenamiento...")
    X = df.drop(columns=['unified_label', 'dataset_source'])
    y = df['unified_label']

    print(f"[🔢] Dimensiones iniciales: X={X.shape}, y={y.shape}")

    # Filtrar solo características numéricas esenciales
    print("[🔍] Filtrando características numéricas...")
    numeric_features = [
        'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
        'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
        'packet_imbalance', 'byte_imbalance', 'loss_ratio', 'hour', 'day_of_week', 'is_weekend',
        'src_country', 'src_asn', 'country_risk', 'distance_km',
        'conn_state_abnormal', 'high_port_activity'
    ]

    # Mantener solo las columnas que existen y son numéricas
    available_features = [col for col in numeric_features if col in X.columns]
    X = X[available_features]
    feature_names = list(X.columns)
    print(f"[🔢] Características finales ({len(feature_names)}): {feature_names}")

    # Verificar que todas las columnas sean numéricas
    non_numeric = X.select_dtypes(exclude=['number']).columns
    if not non_numeric.empty:
        print(f"[⚠️] Columnas no numéricas detectadas: {list(non_numeric)}")
        print("[🔄] Codificando características categóricas...")
        for col in non_numeric:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))

    # Verificar clases antes del balanceo
    class_dist = Counter(y)
    print(f"[⚖️] Distribución antes de balanceo: {class_dist}")
    print(f"[🔍] Valores únicos en y: {np.unique(y)}")

    # Balanceo híbrido
    print("[⚖️] Aplicando balanceo híbrido...")
    try:
        X_balanced, y_balanced = hybrid_balancing(X.values, y.values)
    except Exception as e:
        print(f"[❌] Error en balanceo: {e}")
        print("[🔍] Verificando distribución por dataset:")
        for name in config['ml']['datasets']:
            subset = df[df['dataset_source'] == name]
            if not subset.empty:
                counts = subset['unified_label'].value_counts()
                print(f"  - {name}: {dict(counts)}")
        raise

    # División de datos
    print("[✂️] Dividiendo datos...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_balanced, y_balanced,
        test_size=0.25,
        stratify=y_balanced,
        random_state=42
    )

    # Escalado de características
    print("[📏] Escalando características...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # Entrenamiento de alta precisión
    print("[🧠] Entrenando modelo de alta precisión...")
    model, explainer = train_high_precision_rf(X_train, y_train, config)

    # Evaluación avanzada
    print("[📊] Evaluando modelo...")
    eval_metrics = advanced_evaluation(model, X_test, y_test)

    # Guardar artefactos con gestión de características
    print("[💾] Guardando artefactos...")
    save_advanced_artifacts(model, explainer, config, feature_names, geo_enricher, eval_metrics, scaler)

    print("\n✅ Entrenamiento avanzado completado con éxito!")


# -----------------------------------------------------------------------------
# 🏁 EJECUCIÓN
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Entrenador avanzado de modelos de seguridad")
    parser.add_argument("--max_rows", type=int, default=0,
                        help="Límite de filas a cargar por dataset (0 = sin límite)")
    parser.add_argument("--use_local", action="store_true",
                        help="Usar solo datasets locales sin descargar")
    args = parser.parse_args()

    main()