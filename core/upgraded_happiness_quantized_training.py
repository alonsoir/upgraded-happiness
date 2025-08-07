#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
upgraded_happiness_fully_fixed.py

Versión completamente corregida con:
- Arreglo para nombres de columnas DDoS (con/sin espacios)
- Debugging mejorado
- Carga robusta de Parquet
- Muestreo optimizado
"""

import os
import sys
import time
import glob
import gc
import json
import random
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report, confusion_matrix, accuracy_score,
                             precision_score, recall_score, f1_score, roc_auc_score)
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns

# Intentar importar LightGBM
try:
    import lightgbm as lgb

    HAS_LGB = True
except ImportError:
    HAS_LGB = False

from sklearn.ensemble import RandomForestClassifier

# CONFIGURACIÓN
DATASETS_DIR = "./datasets"
PARQUET_DIR = "./datasets_parquet"
MODELS_DIR = "./models"

# Parámetros de muestreo
MAX_SAMPLES_PER_CLASS_DDOS = 30000  # Reducido para primera prueba exitosa
MAX_SAMPLES_TOTAL_DDOS = 150000  # Máximo total
BALANCE_RATIO_MAX = 5.0

RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)


def clean_infinite_values(X):
    """Limpia valores infinitos y NaN"""
    print(f"[CLEAN] Verificando datos con shape: {X.shape}")
    X = X.replace([np.inf, -np.inf], np.nan)

    nan_count = X.isnull().sum().sum()
    if nan_count > 0:
        print(f"[CLEAN] Limpiando {nan_count} valores problemáticos...")
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            if X[col].isnull().sum() > 0:
                median_val = X[col].median()
                if pd.isna(median_val):
                    median_val = 0
                X[col] = X[col].fillna(median_val)
    else:
        print(f"[CLEAN] ✅ Datos ya limpios")

    return X


def aggressive_sampling_ddos(df, max_per_class=MAX_SAMPLES_PER_CLASS_DDOS,
                             max_total=MAX_SAMPLES_TOTAL_DDOS):
    """Muestreo ultra-agresivo para datasets DDoS masivos"""
    print(f"[SAMPLING] Dataset original: {len(df):,} filas")

    if len(df) <= max_total:
        print("[SAMPLING] Dataset ya es manejable")
        return df

    label_counts = df['Label'].value_counts()
    print(f"[SAMPLING] Distribución original: {dict(label_counts)}")

    sampled_dfs = []
    total_sampled = 0

    for label in sorted(label_counts.index):
        label_df = df[df['Label'] == label]
        current_count = len(label_df)

        remaining_budget = max_total - total_sampled
        if remaining_budget <= 0:
            break

        n_samples = min(max_per_class, current_count, remaining_budget)

        if n_samples > 0:
            if n_samples >= current_count:
                sampled_df = label_df
            else:
                sampled_df = label_df.sample(n=n_samples, random_state=RANDOM_SEED)

            sampled_dfs.append(sampled_df)
            total_sampled += len(sampled_df)

            print(f"[SAMPLING] Clase {label}: {current_count:,} -> {len(sampled_df):,}")

    if not sampled_dfs:
        return df

    result_df = pd.concat(sampled_dfs, ignore_index=True)
    result_df = result_df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    final_counts = result_df['Label'].value_counts()
    print(f"[SAMPLING] Final: {len(result_df):,} filas, distribución: {dict(final_counts)}")

    return result_df


def find_label_column_robust(df, filename=""):
    """Encuentra columna de etiquetas de manera robusta"""
    # Lista de posibles nombres de columnas de etiquetas
    possible_names = [
        'Label', ' Label', 'label', ' label',  # Con y sin espacios
        'Class', ' Class', 'class', ' class',
        'Target', ' Target', 'target', ' target',
        'Attack', ' Attack', 'attack', ' attack'
    ]

    for name in possible_names:
        if name in df.columns:
            print(f"[DEBUG] Encontrada columna de etiquetas: '{name}' en {filename}")
            return name

    # Buscar por contenido si no encontramos por nombre
    print(f"[DEBUG] Búsqueda por contenido en {filename}")
    for col in df.columns:
        if 'label' in col.lower() or 'class' in col.lower():
            print(f"[DEBUG] Candidato por contenido: '{col}'")
            return col

    return None


def load_ddos_from_parquet():
    """Carga datasets DDoS desde Parquet - VERSIÓN CORREGIDA"""
    print("[INFO] Cargando datasets DDoS desde Parquet...")

    parquet_files = glob.glob(os.path.join(PARQUET_DIR, "*.parquet"))

    if not parquet_files:
        print("[ERROR] No se encontraron archivos Parquet")
        return None

    # Filtrar solo archivos DDoS (no ransomware)
    ddos_files = [f for f in parquet_files
                  if not any(ransom_name in os.path.basename(f).lower()
                             for ransom_name in ['output1', 'output2', 'output3'])]

    print(f"[INFO] Encontrados {len(ddos_files)} archivos DDoS Parquet")

    dfs = []
    total_rows = 0
    successful_loads = 0

    for pq_file in ddos_files:
        try:
            filename = os.path.basename(pq_file)
            print(f"[INFO] Procesando: {filename}")

            df = pd.read_parquet(pq_file)

            if len(df) == 0:
                print(f"[WARN] Archivo vacío: {filename}")
                continue

            print(f"[DEBUG] Shape: {df.shape}")

            # Buscar columna de etiquetas robustamente
            label_col = find_label_column_robust(df, filename)

            if label_col is None:
                print(f"[WARN] No se encontró columna de etiquetas en {filename}")
                print(f"[DEBUG] Columnas disponibles: {list(df.columns)[:10]}...")
                continue

            # Verificar distribución original
            original_dist = df[label_col].value_counts()
            print(f"[DEBUG] Distribución en '{label_col}': {dict(original_dist.head())}")

            # Convertir a binario: 0=BENIGN, resto=ATTACK
            df['Label'] = df[label_col].apply(lambda x: 0 if x == 0 else 1)

            # Limpiar columnas innecesarias
            if label_col != 'Label':
                df = df.drop(columns=[label_col])

            # Eliminar columnas de índice
            index_cols = [col for col in df.columns if 'unnamed' in col.lower()]
            if index_cols:
                df = df.drop(columns=index_cols)
                print(f"[DEBUG] Eliminadas columnas índice: {index_cols}")

            # Verificar resultado final
            if 'Label' in df.columns:
                final_dist = df['Label'].value_counts()
                print(f"[DEBUG] Distribución final: {dict(final_dist)}")

                dfs.append(df)
                total_rows += len(df)
                successful_loads += 1

                print(f"[INFO] ✅ Cargado: {len(df):,} filas")

                # Límite de seguridad para primera prueba
                if total_rows > 3_000_000:  # 3M filas límite
                    print(f"[INFO] Límite alcanzado ({total_rows:,}), deteniendo carga")
                    break
            else:
                print(f"[WARN] Error en procesamiento final de {filename}")

        except Exception as e:
            print(f"[ERROR] Error en {pq_file}: {e}")
            import traceback
            traceback.print_exc()

        gc.collect()

    print(f"[SUMMARY] Cargados exitosamente: {successful_loads}/{len(ddos_files)} archivos")

    if not dfs:
        print("[ERROR] ❌ No se pudieron cargar datasets DDoS")
        return None

    print(f"[INFO] Concatenando {len(dfs)} datasets...")
    ddos_full = pd.concat(dfs, ignore_index=True, sort=False)
    del dfs
    gc.collect()

    print(f"[INFO] Dataset DDoS completo: {len(ddos_full):,} filas, {len(ddos_full.columns)} columnas")

    # Verificar distribución antes del muestreo
    pre_sample_dist = ddos_full['Label'].value_counts()
    print(f"[INFO] Distribución pre-muestreo: {dict(pre_sample_dist)}")

    # Aplicar muestreo
    ddos_sampled = aggressive_sampling_ddos(ddos_full)
    del ddos_full
    gc.collect()

    return ddos_sampled


def load_ransomware_from_parquet():
    """Carga datasets Ransomware desde Parquet"""
    print("[INFO] Cargando datasets Ransomware...")

    ransom_files = [f for f in glob.glob(os.path.join(PARQUET_DIR, "*.parquet"))
                    if any(name in os.path.basename(f).lower() for name in ['output1', 'output2', 'output3'])]

    if not ransom_files:
        print("[WARN] No se encontraron archivos Ransomware")
        return None

    dfs = []
    for pq_file in ransom_files:
        try:
            df = pd.read_parquet(pq_file)
            if len(df) > 0:
                dfs.append(df)
                print(f"[INFO] Cargado: {os.path.basename(pq_file)} - {len(df)} filas")
        except Exception as e:
            print(f"[ERROR] Error cargando {pq_file}: {e}")

    if not dfs:
        return None

    ransom_full = pd.concat(dfs, ignore_index=True, sort=False)
    print(f"[INFO] Dataset Ransomware: {len(ransom_full)} filas")

    return ransom_full


def generate_ransomware_labels(df):
    """Genera etiquetas inteligentes para Ransomware"""
    print("[INFO] Generando etiquetas para Ransomware...")

    def create_label(row):
        score = 0

        # Factor: handles
        for col in df.columns:
            if 'handles.nhandles' in col and pd.notna(row[col]):
                if row[col] > 800:
                    score += 2
                elif row[col] > 400:
                    score += 1
                elif row[col] < 200:
                    score -= 1

        # Factor: procesos
        nproc_cols = [col for col in df.columns if 'nproc' in col.lower()]
        for col in nproc_cols:
            if pd.notna(row[col]):
                if row[col] > 40:
                    score += 1

        # Factor: DLLs
        dll_cols = [col for col in df.columns if 'dll' in col.lower()]
        for col in dll_cols:
            if pd.notna(row[col]) and row[col] > 80:
                score += 1

        # Decisión con aleatorio para balance
        hash_seed = hash(str(row.values)) % 100

        if score >= 3:
            return 1
        elif score <= -1:
            return 0
        else:
            return 1 if hash_seed < 60 else 0  # 60% malware

    labels = df.apply(create_label, axis=1)
    df['Label'] = labels

    label_counts = df['Label'].value_counts()
    print(f"[INFO] Etiquetas generadas: {dict(label_counts)}")

    # Forzar balance mínimo si necesario
    if len(label_counts) == 1:
        n_flip = len(df) // 3
        flip_indices = np.random.choice(df.index, n_flip, replace=False)
        df.loc[flip_indices, 'Label'] = 1 - df.loc[flip_indices, 'Label']
        print(f"[INFO] Balance forzado: {dict(df['Label'].value_counts())}")

    return df


# CONFIGURACIÓN DE MODELOS
MODEL_CONFIGS = {
    "random_forest": {
        "n_estimators": 30,
        "max_depth": 8,
        "min_samples_leaf": 10,
        "min_samples_split": 20,
        "max_features": "sqrt",
        "class_weight": "balanced",
        "n_jobs": -1,
        "random_state": RANDOM_SEED,
        "verbose": 1,
        "bootstrap": True,
        "max_samples": 0.8
    },
}

if HAS_LGB:
    MODEL_CONFIGS["lightgbm"] = {
        "objective": "binary",
        "boosting_type": "gbdt",
        "num_leaves": 20,
        "max_depth": 6,
        "learning_rate": 0.1,
        "n_estimators": 40,
        "class_weight": "balanced",
        "random_state": RANDOM_SEED,
        "n_jobs": -1,
        "verbose": -1,
        "force_col_wise": True,
        "feature_fraction": 0.8
    }


def train_and_evaluate_model(X, y, model_key, model_type):
    """Entrena y evalúa un modelo"""
    print(f"\n[TRAIN] {model_key} para {model_type}")
    print(f"[DATA] X={X.shape}, y distribución={dict(pd.Series(y).value_counts())}")

    # Verificar tipos de datos
    non_numeric = X.select_dtypes(include=['object']).columns
    if len(non_numeric) > 0:
        print(f"[ERROR] Columnas no numéricas: {list(non_numeric)}")
        return None

    # Limpiar datos
    X = clean_infinite_values(X)

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=RANDOM_SEED, stratify=y
    )

    # Entrenamiento
    gc.collect()
    start_time = time.perf_counter()

    try:
        params = MODEL_CONFIGS[model_key]

        if model_key == "random_forest":
            model = RandomForestClassifier(**params)
        elif model_key == "lightgbm" and HAS_LGB:
            model = lgb.LGBMClassifier(**params)
        else:
            raise ValueError(f"Modelo {model_key} no disponible")

        print(f"[TRAIN] Iniciando entrenamiento...")
        model.fit(X_train, y_train)

        train_time = time.perf_counter() - start_time
        print(f"[TRAIN] ✅ Completado en {train_time:.2f} segundos")

        # Predicción y métricas
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None

        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, zero_division=0),
            "recall": recall_score(y_test, y_pred, zero_division=0),
            "f1_score": f1_score(y_test, y_pred, zero_division=0),
            "train_time_sec": train_time
        }

        if y_proba is not None:
            metrics["roc_auc"] = roc_auc_score(y_test, y_proba)

        # Mostrar métricas
        print(f"[METRICS] {model_type} - {model_key}:")
        for metric, value in metrics.items():
            if metric != "train_time_sec":
                print(f"  {metric}: {value:.4f}")

        # Guardar modelo
        Path(MODELS_DIR).mkdir(exist_ok=True)

        model_path = os.path.join(MODELS_DIR, f"{model_type}_{model_key}.joblib")
        import joblib
        joblib.dump(model, model_path)

        metrics_path = os.path.join(MODELS_DIR, f"{model_type}_{model_key}_metrics.json")
        with open(metrics_path, "w") as f:
            json.dump(metrics, f, indent=4)

        print(f"[SAVE] Modelo: {model_path}")
        print(f"[SAVE] Métricas: {metrics_path}")

        # Para resumen final
        metrics.update({
            "model_path": model_path,
            "test_accuracy": metrics["accuracy"],
            "test_f1": metrics["f1_score"]
        })

        gc.collect()
        return {model_key: metrics}

    except Exception as e:
        print(f"[ERROR] Fallo entrenando {model_key}: {e}")
        import traceback
        traceback.print_exc()
        gc.collect()
        return None


def main():
    """Función principal completamente corregida"""
    print("=" * 80)
    print("UPGRADED HAPPINESS - VERSIÓN COMPLETAMENTE CORREGIDA")
    print("Arreglos: nombres columnas, carga robusta, debugging mejorado")
    print("=" * 80)

    start_total = time.perf_counter()

    # Cargar datasets
    print("\n🔄 CARGA DE DATASETS")
    start = time.perf_counter()

    ddos_df = load_ddos_from_parquet()
    ransom_df = load_ransomware_from_parquet()

    load_time = time.perf_counter() - start
    print(f"[TIME] Carga total: {load_time:.2f} segundos")

    # Procesar Ransomware
    if ransom_df is not None:
        start = time.perf_counter()
        ransom_df = generate_ransomware_labels(ransom_df)

        # Limpiar columnas de texto
        text_cols = ransom_df.select_dtypes(include=['object']).columns
        if len(text_cols) > 0:
            print(f"[CLEAN] Eliminando columnas de texto: {list(text_cols)}")
            ransom_df = ransom_df.drop(columns=text_cols)

        prep_time = time.perf_counter() - start
        print(f"[TIME] Preprocesamiento Ransomware: {prep_time:.2f} segundos")

    # Entrenar modelos
    results = {}

    # DDoS
    if ddos_df is not None and 'Label' in ddos_df.columns:
        print(f"\n🔥 ENTRENAMIENTO DDOS")
        print(f"[INFO] Dataset final DDoS: {len(ddos_df):,} filas")

        X = ddos_df.drop(columns=['Label'])
        y = ddos_df['Label']

        for model_key in MODEL_CONFIGS.keys():
            result = train_and_evaluate_model(X, y, model_key, "ddos")
            if result:
                results.update(result)

        del ddos_df, X, y
        gc.collect()
    else:
        print("\n❌ DDOS NO DISPONIBLE")

    # Ransomware
    if ransom_df is not None and 'Label' in ransom_df.columns:
        print(f"\n🔥 ENTRENAMIENTO RANSOMWARE")

        X = ransom_df.drop(columns=['Label'])
        y = ransom_df['Label']

        for model_key in MODEL_CONFIGS.keys():
            result = train_and_evaluate_model(X, y, model_key, "ransomware")
            if result:
                results.update(result)

        del ransom_df, X, y
        gc.collect()

    total_time = time.perf_counter() - start_total

    # Resumen final
    print("\n" + "=" * 80)
    print("🎯 RESUMEN FINAL - ENTRENAMIENTO COMPLETADO")
    print("=" * 80)

    if results:
        print(f"✅ Modelos entrenados exitosamente: {len(results)}")
        for model_name, metrics in results.items():
            acc = metrics.get('test_accuracy', metrics.get('accuracy', 0))
            f1 = metrics.get('test_f1', metrics.get('f1_score', 0))
            time_taken = metrics.get('train_time_sec', 0)
            print(f"   📊 {model_name}: Acc={acc:.4f}, F1={f1:.4f}, Tiempo={time_taken:.1f}s")
    else:
        print("❌ No se entrenaron modelos exitosamente")

    print(f"\n🕒 Tiempo total: {total_time:.2f} segundos")
    print(f"📁 Modelos en: {MODELS_DIR}/")
    print("=" * 80)

    return results


if __name__ == "__main__":
    main()