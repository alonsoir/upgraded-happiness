#!/usr/bin/env python3
"""
advanced_trainer_no_dns.py - VERSIÓN CON TIMING DETALLADO
🤖 Enhanced ML Trainer para Upgraded-Happiness - MULTI-DATASET SIN DNS BIAS
- Filtrado automático de DNS para evitar sesgo
- Soporte múltiples datasets con mapeo correcto
- TIMING DETALLADO para entrenamientos largos
- Logging de progreso y ETAs
"""

import os
import json
import zipfile
import argparse
from pathlib import Path
from collections import Counter
import joblib
from datetime import datetime, timedelta
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
import time


# -----------------------------------------------------------------------------
# ⏰ CLASE DE TIMING DETALLADO
# -----------------------------------------------------------------------------
class DetailedTimer:
    """Clase para manejar timing detallado de entrenamientos largos"""

    def __init__(self):
        self.start_time = time.time()
        self.phase_times = {}
        self.current_phase = None
        self.phase_start = None

    def start_phase(self, phase_name: str):
        """Inicia una nueva fase con timing"""
        if self.current_phase:
            self.end_phase()

        self.current_phase = phase_name
        self.phase_start = time.time()
        elapsed = self.get_elapsed_time()
        print(f"\n⏰ [{elapsed}] INICIANDO: {phase_name}")

    def end_phase(self):
        """Termina la fase actual"""
        if self.current_phase and self.phase_start:
            duration = time.time() - self.phase_start
            self.phase_times[self.current_phase] = duration
            print(f"✅ [{self.format_duration(duration)}] COMPLETADO: {self.current_phase}")
            self.current_phase = None
            self.phase_start = None

    def get_elapsed_time(self) -> str:
        """Obtiene tiempo transcurrido total"""
        elapsed = time.time() - self.start_time
        return self.format_duration(elapsed)

    def format_duration(self, seconds: float) -> str:
        """Formatea duración en formato legible"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            minutes = (seconds % 3600) / 60
            return f"{hours:.1f}h {minutes:.0f}m"

    def log_progress(self, message: str):
        """Log de progreso con timestamp"""
        elapsed = self.get_elapsed_time()
        print(f"📊 [{elapsed}] {message}")

    def estimate_remaining(self, current_step: int, total_steps: int) -> str:
        """Estima tiempo restante basado en progreso"""
        if current_step == 0:
            return "calculando..."

        elapsed = time.time() - self.start_time
        rate = elapsed / current_step
        remaining_steps = total_steps - current_step
        estimated_remaining = rate * remaining_steps

        eta = datetime.now() + timedelta(seconds=estimated_remaining)
        return f"ETA: {eta.strftime('%H:%M:%S')} ({self.format_duration(estimated_remaining)} restante)"

    def print_summary(self):
        """Imprime resumen final de tiempos"""
        total_time = time.time() - self.start_time
        print(f"\n⏰ RESUMEN DE TIEMPOS - TOTAL: {self.format_duration(total_time)}")
        print("=" * 60)

        for phase, duration in self.phase_times.items():
            percentage = (duration / total_time) * 100
            print(f"  📊 {phase:<30} {self.format_duration(duration):>10} ({percentage:.1f}%)")

        print("=" * 60)
        finish_time = datetime.now()
        print(f"🏁 Completado: {finish_time.strftime('%Y-%m-%d %H:%M:%S')}")


# Instancia global del timer
timer = DetailedTimer()


# -----------------------------------------------------------------------------
# 📁 CONFIGURACIÓN CENTRALIZADA
# -----------------------------------------------------------------------------
def load_config():
    config_path = Path("config-advanced-trainer-RF-Agression-NoAgression.json")
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
# 🚫 FILTRO DNS - NUEVA FUNCIÓN CRÍTICA
# -----------------------------------------------------------------------------
def filter_dns_traffic(df, dataset_name):
    """
    Filtra el tráfico DNS para evitar sesgo de que DNS = ataque
    """
    initial_count = len(df)

    # Detectar columnas de servicio posibles
    service_columns = []
    for col in ['service', 'Service', 'protocol_type', 'service_name']:
        if col in df.columns:
            service_columns.append(col)

    if not service_columns:
        print(f"   ⚠️  No se encontró columna de servicio en {dataset_name}")
        return df

    # Filtrar DNS de todas las columnas de servicio detectadas
    dns_filtered = 0
    for col in service_columns:
        if col in df.columns:
            # Contar DNS antes del filtro
            dns_mask = df[col].astype(str).str.lower().str.contains('dns', na=False)
            dns_count = dns_mask.sum()

            if dns_count > 0:
                print(f"   🚫 Filtrando {dns_count} filas DNS de columna '{col}' en {dataset_name}")

                # Analizar labels antes de eliminar
                if 'label' in df.columns or 'Label' in df.columns:
                    label_col = 'label' if 'label' in df.columns else 'Label'
                    dns_labels = df[dns_mask][label_col].value_counts()
                    print(f"      📊 DNS labels: {dict(dns_labels)}")

                # Filtrar DNS
                df = df[~dns_mask]
                dns_filtered += dns_count

    final_count = len(df)
    total_removed = initial_count - final_count

    print(f"   ✅ {dataset_name}: {initial_count} → {final_count} filas ({total_removed} DNS removidas)")

    return df


# -----------------------------------------------------------------------------
# ⬇️ CARGA DE DATASETS COMBINADOS (MODIFICADO)
# -----------------------------------------------------------------------------
def load_combined_datasets(config):
    dataset_names = config['ml'].get('datasets', ["UNSW-NB15"])
    datasets = []

    for name in dataset_names:
        try:
            print(f"\n[📁] Procesando dataset: {name}")
            df = load_dataset(config, name)

            # NUEVO: Filtrar DNS ANTES de continuar
            print(f"[🚫] Filtrando tráfico DNS de {name}...")
            df = filter_dns_traffic(df, name)

            df['dataset_source'] = name
            datasets.append(df)
            print(f"[✅] {name} procesado con {len(df)} registros (sin DNS)")

            # Verificar etiquetas en el dataset después del filtro
            if 'label' in df.columns:
                print(f"  - Distribución de etiquetas post-filtro: {dict(df['label'].value_counts())}")
            elif 'Label' in df.columns:
                print(f"  - Distribución de etiquetas post-filtro: {dict(df['Label'].value_counts())}")
            else:
                print("  - No se encontró columna 'label' o 'Label'")

        except Exception as e:
            print(f"[❌] Error cargando {name}: {str(e)}")

    if not datasets:
        raise ValueError("No se pudo cargar ningún dataset")

    # Combinar datasets
    combined = pd.concat(datasets, ignore_index=True)
    print(f"\n[📊] Total de registros combinados (sin DNS): {len(combined)}")

    # Verificar distribución por dataset
    print(f"[📋] Registros por dataset:")
    for name in dataset_names:
        count = len(combined[combined['dataset_source'] == name])
        print(f"  - {name}: {count:,} registros")

    return combined


def load_dataset(config, dataset_name, max_rows=0):
    base_data_dir = Path("./data")
    base_data_dir.mkdir(exist_ok=True)

    # ACTUALIZADO: Configuraciones para los 3 datasets
    dataset_config = {
        "UNSW-NB15": {
            "kaggle": "mrwellsdavid/unsw-nb15",
            "csv_file": "UNSW_NB15_training-set.csv",
            "label_col": "label"
        },
        "CSE-CIC-IDS2018": {
            "kaggle": "solarmainframe/ids-intrusion-csv",
            "csv_file": "Train_data.csv",
            "label_col": "Label"  # Será detectado automáticamente
        },
        "TON-IoT": {
            "kaggle": "programmer3/ton-iot-network-intrusion-dataset",
            "csv_file": "TON_IoT_Network_dataset.csv",
            "label_col": "label"
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

        # Buscar archivo ZIP descargado
        possible_zip_names = [
            f"{dataset_name}.zip",
            f"{ds_cfg['kaggle'].split('/')[-1]}.zip"
        ]

        zip_file = None
        for zip_name in possible_zip_names:
            potential_zip = base_data_dir / zip_name
            if potential_zip.exists():
                zip_file = potential_zip
                break

        if not zip_file:
            # Buscar cualquier ZIP recién descargado
            zip_files = list(base_data_dir.glob("*.zip"))
            if zip_files:
                zip_file = max(zip_files, key=os.path.getctime)  # Más reciente
            else:
                raise FileNotFoundError(f"No se encontró archivo ZIP para {dataset_name}")

        print(f"[📦] Extrayendo {zip_file}...")
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall(base_data_dir)

        # Buscar archivo CSV
        csv_path = None

        # Primero buscar el archivo específico
        for file in base_data_dir.glob("**/*.csv"):
            if ds_cfg["csv_file"] in file.name:
                csv_path = file
                break

        # Si no se encuentra, tomar el CSV más grande
        if not csv_path:
            csv_files = list(base_data_dir.glob("**/*.csv"))
            if csv_files:
                csv_path = max(csv_files, key=lambda x: x.stat().st_size)
                print(f"[📄] Usando CSV más grande encontrado: {csv_path.name}")

        if not csv_path:
            raise FileNotFoundError(f"No se encontró archivo CSV para {dataset_name}")

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
# 🧹 PREPROCESAMIENTO AVANZADO (SIN CAMBIOS)
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

    # 4. Eliminación de columnas problemáticas (CORREGIDO - NO eliminar Label)
    drop_cols = ['id', 'attack_cat', 'flow_id', 'Unnamed: 0']
    # NOTA: NO eliminamos 'Label' porque contiene las etiquetas de clasificación en CSE-CIC-IDS2018
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
# ⚖️ BALANCEO HÍBRIDO (SIN CAMBIOS)
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
# 🧠 ENTRENAMIENTO DE ALTA PRECISIÓN (SIN CAMBIOS)
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

    # Validación cruzada estratificada con timing detallado
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    fold_scores = []
    models = []

    total_folds = 5
    timer.log_progress(f"Iniciando validación cruzada: {total_folds} folds")

    for fold, (train_idx, val_idx) in enumerate(skf.split(X_train, y_train)):
        fold_start = time.time()

        X_fold_train, y_fold_train = X_train[train_idx], y_train[train_idx]
        X_val, y_val = X_train[val_idx], y_train[val_idx]

        timer.log_progress(f"Fold {fold + 1}/{total_folds}: Entrenando con {len(X_fold_train):,} muestras...")

        model = RandomForestClassifier(**rf_params)
        model.fit(X_fold_train, y_fold_train)

        # Calcular precisión en el fold de validación
        y_pred = model.predict(X_val)
        accuracy = np.mean(y_pred == y_val)
        fold_scores.append(accuracy)
        models.append(model)

        fold_duration = time.time() - fold_start
        remaining_time = timer.estimate_remaining(fold + 1, total_folds)

        print(
            f"[🔍] Fold {fold + 1} - Precisión: {accuracy:.4f} - Tiempo: {timer.format_duration(fold_duration)} - {remaining_time}")

    # Seleccionar el mejor modelo
    best_idx = np.argmax(fold_scores)
    best_model = models[best_idx]
    print(f"[🏆] Mejor fold: {best_idx + 1} con precisión {fold_scores[best_idx]:.4f}")

    # Entrenar modelo final con todos los datos
    timer.log_progress("Entrenando modelo final con todos los datos...")
    final_model = RandomForestClassifier(**rf_params)
    final_model.fit(X_train, y_train)

    # Usar SHAP para explicabilidad
    timer.log_progress("Generando explicaciones SHAP (muestra de 1000)...")
    explainer = shap.TreeExplainer(final_model)
    shap_values = explainer.shap_values(X_train[:1000])  # Muestra representativa

    return final_model, explainer


# -----------------------------------------------------------------------------
# 📊 EVALUACIÓN AVANZADA (SIN CAMBIOS)
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
# 💾 GUARDADO DE ARTEFACTOS (SIN CAMBIOS)
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

    # 3. Guardar metadatos detallados (ACTUALIZADO con timing)
    metadata = {
        "training_date": timestamp,
        "dns_filtered": True,  # NUEVO
        "datasets_used": config['ml'].get('datasets', []),  # NUEVO
        "timing_info": {  # NUEVO
            "total_training_time": timer.get_elapsed_time(),
            "phase_times": timer.phase_times,
            "training_start": datetime.fromtimestamp(timer.start_time).isoformat()
        },
        "feature_set": {
            "features": features,
            "descriptions": {feat: FEATURE_DESCRIPTIONS.get(feat, "Descripción no disponible")
                             for feat in features}
        },
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
        json.dump(metadata, f, indent=4, default=str)

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

    timer.log_progress(f"Todos los artefactos guardados en {model_dir}")


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
# 🚀 FUNCIÓN PRINCIPAL (MODIFICADA PARA MÚLTIPLES DATASETS)
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# 🚀 FUNCIÓN PRINCIPAL CON TIMING DETALLADO
# -----------------------------------------------------------------------------
def main():
    print("🚀 ADVANCED TRAINER v2.3 - MULTI-DATASET CON TIMING DETALLADO")
    print("=" * 70)
    start_time = datetime.now()
    print(f"🕐 Iniciado: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    timer.start_phase("Configuración inicial")
    config = load_config()
    geo_enricher = GeoEnricher(config)
    timer.end_phase()

    # Cargar y combinar datasets (CON FILTRO DNS)
    timer.start_phase("Carga y combinación de datasets")
    print("[🔍] Cargando y combinando datasets...")
    print(f"[📋] Datasets configurados: {config['ml']['datasets']}")
    df = load_combined_datasets(config)
    timer.log_progress(f"Datasets combinados: {len(df):,} registros")
    timer.end_phase()

    # Preprocesamiento avanzado
    timer.start_phase("Preprocesamiento avanzado")
    print("\n[🧹] Realizando preprocesamiento avanzado...")
    df = advanced_preprocessing(df, geo_enricher)
    timer.log_progress(f"Preprocesamiento completado: {df.shape}")
    timer.end_phase()

    # Asignación robusta de etiquetas (MEJORADA PARA MÚLTIPLES DATASETS)
    timer.start_phase("Mapeo de etiquetas")
    print("[🏷️] Asignando etiquetas unificadas...")

    # Definir mapeos de etiquetas por dataset (CORREGIDO FINALMENTE)
    label_mappings = {
        'UNSW-NB15': ('label', lambda x: x),  # Mantener valores originales
        'CSE-CIC-IDS2018': ('Label', lambda x: 0 if str(x).lower() == 'benign' else 1),  # CORRECTO: Label mayúscula
        'TON-IoT': ('label', lambda x: 1 if x != 'normal' else 0)
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
                # Debug: mostrar columnas disponibles
                subset = df[df['dataset_source'] == name]
                if not subset.empty:
                    print(f"  - Columnas disponibles: {list(subset.columns)}")
                    # Buscar columnas parecidas
                    similar_cols = [c for c in subset.columns if 'label' in c.lower()]
                    if similar_cols:
                        print(f"  - Columnas similares encontradas: {similar_cols}")
                continue
        else:
            print(f"[⚠️] No se encontró mapeo para {name}")
            continue

    # Verificar que todas las etiquetas estén asignadas
    if df['unified_label'].isna().any():
        missing_count = df['unified_label'].isna().sum()
        print(f"[❌] Error: {missing_count} filas sin etiqueta asignada")

        # Mostrar diagnóstico
        print("[🔍] Diagnóstico por dataset:")
        for name in config['ml']['datasets']:
            subset = df[df['dataset_source'] == name]
            if not subset.empty:
                missing_in_subset = subset['unified_label'].isna().sum()
                print(f"  - {name}: {missing_in_subset} filas sin etiqueta")

        raise ValueError("Algunas filas no tienen etiqueta asignada")

    # Verificar distribución global
    class_counts = df['unified_label'].value_counts()
    print(f"\n[📊] Distribución global de etiquetas:\n{class_counts}")

    # Calcular porcentajes
    total = len(df)
    normal_pct = (class_counts.get(0.0, 0) / total) * 100
    attack_pct = (class_counts.get(1.0, 0) / total) * 100
    timer.log_progress(f"Distribución final: {normal_pct:.1f}% normal, {attack_pct:.1f}% ataques")

    if len(class_counts) < 2:
        print("[🔍] Analizando distribución por dataset:")
        for name in config['ml']['datasets']:
            subset = df[df['dataset_source'] == name]
            if not subset.empty:
                counts = subset['unified_label'].value_counts()
                print(f"  - {name}: {dict(counts)}")

        raise ValueError(
            "Solo se encontró una clase en los datos. Se necesitan ambas clases (benigno/maligno) para entrenar.")
    timer.end_phase()

    # Preparar datos para entrenamiento
    timer.start_phase("Preparación de datos")
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
    timer.end_phase()

    # Balanceo híbrido
    timer.start_phase("Balanceo de datos")
    print("[⚖️] Aplicando balanceo híbrido...")
    try:
        X_balanced, y_balanced = hybrid_balancing(X.values, y.values)
        balanced_dist = Counter(y_balanced)
        timer.log_progress(f"Balanceo completado: {dict(balanced_dist)}")
    except Exception as e:
        print(f"[❌] Error en balanceo: {e}")
        print("[🔍] Verificando distribución por dataset:")
        for name in config['ml']['datasets']:
            subset = df[df['dataset_source'] == name]
            if not subset.empty:
                counts = subset['unified_label'].value_counts()
                print(f"  - {name}: {dict(counts)}")
        raise
    timer.end_phase()

    # División de datos
    timer.start_phase("División de datos")
    print("[✂️] Dividiendo datos...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_balanced, y_balanced,
        test_size=0.25,
        stratify=y_balanced,
        random_state=42
    )

    train_size = len(X_train)
    test_size = len(X_test)
    timer.log_progress(f"División completada: {train_size:,} entrenamiento, {test_size:,} prueba")
    timer.end_phase()

    # Escalado de características
    timer.start_phase("Escalado de características")
    print("[📏] Escalando características...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)
    timer.end_phase()

    # Entrenamiento de alta precisión
    timer.start_phase("Entrenamiento del modelo")
    print("[🧠] Entrenando modelo de alta precisión...")
    timer.log_progress("Iniciando entrenamiento RandomForest con validación cruzada...")
    model, explainer = train_high_precision_rf(X_train, y_train, config)
    timer.log_progress("Entrenamiento del modelo completado")
    timer.end_phase()

    # Evaluación avanzada
    timer.start_phase("Evaluación del modelo")
    print("[📊] Evaluando modelo...")
    eval_metrics = advanced_evaluation(model, X_test, y_test)
    timer.end_phase()

    # Guardar artefactos con gestión de características
    timer.start_phase("Guardado de artefactos")
    print("[💾] Guardando artefactos...")
    save_advanced_artifacts(model, explainer, config, feature_names, geo_enricher, eval_metrics, scaler)

    # Guardar feature order
    with open("models/feature_order.txt", "w") as f:
        f.write("\n".join(feature_names))
    timer.end_phase()

    # Resumen final
    timer.print_summary()

    final_time = datetime.now()
    total_duration = final_time - start_time

    print(f"\n✅ ENTRENAMIENTO AVANZADO COMPLETADO CON ÉXITO!")
    print(f"🚫 DNS filtrado de todos los datasets para evitar sesgo")
    print(f"📊 Datasets utilizados: {config['ml']['datasets']}")
    print(f"⏰ Tiempo total: {total_duration}")
    print(f"🏁 Finalizado: {final_time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Guardar resumen de timing
    timing_summary = {
        "start_time": start_time.isoformat(),
        "end_time": final_time.isoformat(),
        "total_duration_seconds": total_duration.total_seconds(),
        "phase_times": timer.phase_times,
        "datasets_used": config['ml']['datasets'],
        "final_distribution": dict(Counter(y_balanced)),
        "model_metrics": eval_metrics
    }

    with open("models/training_timing_summary.json", "w") as f:
        json.dump(timing_summary, f, indent=2, default=str)

    print(f"📊 Resumen de timing guardado en: models/training_timing_summary.json")


# -----------------------------------------------------------------------------
# 🏁 EJECUCIÓN
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Entrenador avanzado de modelos de seguridad - SIN DNS")
    parser.add_argument("--max_rows", type=int, default=0,
                        help="Límite de filas a cargar por dataset (0 = sin límite)")
    parser.add_argument("--use_local", action="store_true",
                        help="Usar solo datasets locales sin descargar")
    args = parser.parse_args()

    main()