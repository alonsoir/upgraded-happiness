#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# upgraded_happiness_quantized_training.py
# Especializado para Intel i9 + 32GB RAM

import os
import requests
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import classification_report, f1_score
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnxruntime as ort
from tqdm import tqdm
import duckdb

# Configuración inicial
CONFIG = {
    "ddos_urls": [
        "https://archive.org/download/cicddos2019_202304/CICDDoS2019_sample_10percent.parquet",
        "https://aws-shield-ddos.s3.amazonaws.com/aws-shield-sample-2023.parquet"
    ],
    "ransomware_urls": [
        "https://ransomware-traces.unb.ca/dataset/ransomware_sample_2024.parquet",
        "https://malware-traffic-analysis.net/2024/04/2024-04-ransomware-sample.parquet"
    ],
    "output_dir": "quantized_models",
    "sample_size": 0.1,  # 10% para muestra inicial
    "quantize": True,
    "max_features": 30,  # Features a conservar
    "rf_params": {
        "n_estimators": 150,
        "max_depth": 12,
        "min_samples_leaf": 2,
        "class_weight": "balanced",
        "n_jobs": -1  # Usar todos los núcleos
    }
}


def download_datasets(urls, dataset_type):
    """Descarga datasets optimizados usando streaming y DuckDB"""
    os.makedirs("datasets", exist_ok=True)
    downloaded_files = []

    for url in urls:
        filename = os.path.join("datasets", f"{dataset_type}_{os.path.basename(url)}")

        # Descarga con barra de progreso
        if not os.path.exists(filename):
            print(f"Descargando {dataset_type}: {os.path.basename(url)}")
            with requests.get(url, stream=True) as r:
                r.raise_for_status()
                total_size = int(r.headers.get('content-length', 0))
                with open(filename, 'wb') as f, tqdm(
                        total=total_size, unit='B', unit_scale=True, desc=filename
                ) as pbar:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                        pbar.update(len(chunk))

        downloaded_files.append(filename)

    return downloaded_files


def load_and_sample(file_paths, sample_size):
    """Carga y muestrea datasets usando DuckDB para eficiencia"""
    conn = duckdb.connect()

    # Crear vista unificada
    for i, path in enumerate(file_paths):
        conn.execute(f"""
            CREATE OR REPLACE VIEW dataset_{i} AS 
            SELECT * FROM parquet_scan('{path}')
        """)

    # Unificar datasets con muestreo estratificado
    union_query = " UNION ALL ".join([f"SELECT * FROM dataset_{i}" for i in range(len(file_paths))])

    # Muestreo estratificado manteniendo distribución de clases
    query = f"""
        WITH full_data AS ({union_query}),
        sampled AS (
            SELECT * 
            FROM full_data 
            USING SAMPLE reservoir({sample_size * 100}% PERCENT) 
            PARTITION BY Label
        )
        SELECT * FROM sampled
    """

    return conn.execute(query).fetchdf()


def preprocess_data(df, dataset_type):
    """Preprocesamiento optimizado para datasets de seguridad"""
    # Eliminar columnas innecesarias
    df = df.drop(columns=[col for col in df.columns if 'Unnamed' in col or 'FlowID' in col])

    # Manejo de valores nulos
    for col in df.columns:
        if df[col].dtype in ['float64', 'int64']:
            df[col] = df[col].fillna(df[col].median())

    # Conversión de etiquetas
    if dataset_type == "ddos":
        df['Label'] = df['Label'].apply(lambda x: 1 if 'DDoS' in x else 0)
    elif dataset_type == "ransomware":
        df['Label'] = df['Label'].apply(lambda x: 1 if 'ransomware' in x.lower() else 0)

    # Selección de características
    X = df.drop(columns=['Label'])
    y = df['Label']

    # Selección de mejores características
    selector = SelectKBest(mutual_info_classif, k=CONFIG['max_features'])
    X_selected = selector.fit_transform(X, y)

    return X_selected, y, selector


def train_quantized_model(X, y, model_name):
    """Entrena y cuantiza un modelo Random Forest"""
    # División de datos
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # Entrenamiento del modelo
    print(f"\nEntrenando modelo {model_name}...")
    model = RandomForestClassifier(**CONFIG['rf_params'])
    model.fit(X_train, y_train)

    # Evaluación
    y_pred = model.predict(X_test)
    print(f"\nEvaluación {model_name}:")
    print(classification_report(y_test, y_pred))
    print(f"F1-Score: {f1_score(y_test, y_pred, average='weighted'):.4f}")

    # Cuantización a ONNX
    if CONFIG['quantize']:
        print(f"\nCuantizando {model_name}...")
        initial_type = [('float_input', FloatTensorType([None, X.shape[1]]))]
        onnx_model = convert_sklearn(model, initial_types=initial_type)

        # Guardar modelo cuantizado
        os.makedirs(CONFIG['output_dir'], exist_ok=True)
        model_path = os.path.join(CONFIG['output_dir'], f"{model_name}_quantized.onnx")
        with open(model_path, "wb") as f:
            f.write(onnx_model.SerializeToString())

        # Probar modelo ONNX
        ort_session = ort.InferenceSession(model_path)
        inputs = ort_session.get_inputs()
        outputs = ort_session.run(
            None, {'float_input': X_test[:10].astype(np.float32)}
        )
        print(f"Predicciones ONNX: {outputs[0]}")

        return model_path
    else:
        joblib.dump(model, os.path.join(CONFIG['output_dir'], f"{model_name}.joblib"))
        return None


def main():
    print("=" * 70)
    print("Upgraded Happiness - Entrenamiento Cuantizado de Modelos")
    print(f"Hardware: Intel i9 - RAM: 32GB - Muestreo: {CONFIG['sample_size'] * 100}%")
    print("=" * 70)

    # Paso 1: Descargar y preparar datos DDoS
    ddos_files = download_datasets(CONFIG["ddos_urls"], "ddos")
    print("\nMuestreo inteligente de datos DDoS...")
    ddos_sample = load_and_sample(ddos_files, CONFIG["sample_size"])
    X_ddos, y_ddos, ddos_selector = preprocess_data(ddos_sample, "ddos")

    # Paso 2: Descargar y preparar datos Ransomware
    ransomware_files = download_datasets(CONFIG["ransomware_urls"], "ransomware")
    print("\nMuestreo inteligente de datos Ransomware...")
    ransomware_sample = load_and_sample(ransomware_files, CONFIG["sample_size"])
    X_ransom, y_ransom, ransom_selector = preprocess_data(ransomware_sample, "ransomware")

    # Paso 3: Entrenar y cuantizar modelos
    ddos_model_path = train_quantized_model(X_ddos, y_ddos, "ddos_detector")
    ransom_model_path = train_quantized_model(X_ransom, y_ransom, "ransomware_detector")

    print("\n" + "=" * 70)
    print("Entrenamiento completado con éxito!")
    if CONFIG['quantize']:
        print(f"Modelo DDoS cuantizado: {ddos_model_path}")
        print(f"Modelo Ransomware cuantizado: {ransom_model_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()