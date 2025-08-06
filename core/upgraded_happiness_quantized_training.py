#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
upgraded_happiness_quantized_training.py

Entrena modelos ML sobre datasets locales CIC DDoS y Ransomware,
con limpieza inteligente de CSVs, conversión a parquet opcional,
guardado de métricas, visualización y soporte multi-modelo.
"""

import os
import sys
import time
import glob
import gc
import json
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report, confusion_matrix, accuracy_score,
                             precision_score, recall_score, f1_score, roc_auc_score,
                             roc_curve, precision_recall_curve)
import matplotlib.pyplot as plt
import seaborn as sns

# Intentar importar LightGBM, si falla sigue sólo con RandomForest
try:
    import lightgbm as lgb
    HAS_LGB = True
except ImportError:
    HAS_LGB = False

from sklearn.ensemble import RandomForestClassifier


# CONFIG
DATASETS_DIR = "./datasets"  # Ruta base local para los datasets
DDOS_DIRS = ["ddos/01-12", "ddos/03-11"]  # Carpetas con CSVs DDoS
RANSOMWARE_DIR = "ransomware"              # Carpeta con CSVs Ransomware

PARQUET_DIR = "./datasets_parquet"         # Donde guardar los parquet temporalmente
MODELS_DIR = "./models"                    # Donde guardar modelos y métricas

CHUNK_SIZE = 50000  # por si quieres luego procesar en chunks (no usado ahora)
RANDOM_SEED = 42

# Parámetros modelos
MODEL_CONFIGS = {
    "random_forest": {
        "n_estimators": 100,
        "max_depth": 12,
        "min_samples_leaf": 3,
        "class_weight": "balanced",
        "n_jobs": -1,
        "random_state": RANDOM_SEED,
        "verbose": 0,
    },
}

if HAS_LGB:
    MODEL_CONFIGS["lightgbm"] = {
        "objective": "binary",
        "boosting_type": "gbdt",
        "num_leaves": 31,
        "max_depth": 12,
        "learning_rate": 0.05,
        "n_estimators": 100,
        "class_weight": "balanced",
        "random_state": RANDOM_SEED,
        "n_jobs": -1,
        "verbose": -1,
    }


def analyze_column(col: pd.Series, col_name:str, threshold=0.9):
    col_num = pd.to_numeric(col, errors='coerce')
    ratio_num = col_num.notna().mean()
    non_num_vals = col[col_num.isna()].unique()
    print(f"Columna '{col_name}': {ratio_num*100:.2f}% numérico válido.")
    if len(non_num_vals) > 0:
        print(f"  Valores no numéricos detectados: {non_num_vals[:10]}{'...' if len(non_num_vals)>10 else ''}")
    tipo = "Numérica" if ratio_num >= threshold else "Categorica/String"
    return tipo, ratio_num, non_num_vals


def smart_clean_dataframe(df: pd.DataFrame, threshold=0.9):
    tipos = {}
    for col in df.columns:
        tipo, ratio_num, non_num_vals = analyze_column(df[col], col, threshold)
        tipos[col] = tipo
        if tipo == "Numérica":
            df[col] = pd.to_numeric(df[col], errors='coerce')
        else:
            # Limpieza básica para columnas string
            df[col] = df[col].astype(str).str.strip()
            df[col].replace({'nan': np.nan, 'None': np.nan, 'NaN': np.nan, '': np.nan}, inplace=True)
    return df, tipos


def csv_to_parquet_if_needed(csv_path: str):
    Path(PARQUET_DIR).mkdir(parents=True, exist_ok=True)
    parquet_path = os.path.join(PARQUET_DIR, os.path.basename(csv_path).replace(".csv", ".parquet"))

    if os.path.exists(parquet_path):
        csv_size = os.path.getsize(csv_path)
        parquet_size = os.path.getsize(parquet_path)
        if parquet_size < csv_size * 0.8:  # parquet es mucho más ligero: usamos parquet
            print(f"[INFO] Usando parquet existente: {parquet_path}")
            return parquet_path
        else:
            print(f"[INFO] Parquet existente no ahorra mucho espacio, usar CSV directamente.")
            return csv_path
    else:
        print(f"[INFO] Convirtiendo {csv_path} a parquet con limpieza inteligente...")
        df_raw = pd.read_csv(csv_path, dtype=str)
        df_clean, col_types = smart_clean_dataframe(df_raw)
        print(f"[INFO] Tipos detectados en {os.path.basename(csv_path)}:")
        for c, t in col_types.items():
            print(f"  {c}: {t}")
        df_clean.to_parquet(parquet_path)
        return parquet_path


def load_all_datasets():
    print("[INFO] Cargando y limpiando datasets DDoS...")
    ddos_paths = []
    for d in DDOS_DIRS:
        ddos_paths.extend(sorted(glob.glob(os.path.join(DATASETS_DIR, d, "*.csv"))))

    ddos_dfs = []
    for csv_file in ddos_paths:
        source = csv_to_parquet_if_needed(csv_file)
        if source.endswith(".parquet"):
            df = pd.read_parquet(source)
        else:
            df = pd.read_csv(source, dtype=str)
            df, _ = smart_clean_dataframe(df)
        ddos_dfs.append(df)
        gc.collect()
    ddos_full = pd.concat(ddos_dfs, ignore_index=True)

    print("[INFO] Cargando y limpiando datasets Ransomware...")
    ransom_paths = sorted(glob.glob(os.path.join(DATASETS_DIR, RANSOMWARE_DIR, "*.csv")))
    ransom_dfs = []
    for csv_file in ransom_paths:
        source = csv_to_parquet_if_needed(csv_file)
        if source.endswith(".parquet"):
            df = pd.read_parquet(source)
        else:
            df = pd.read_csv(source, dtype=str)
            df, _ = smart_clean_dataframe(df)
        ransom_dfs.append(df)
        gc.collect()
    ransom_full = pd.concat(ransom_dfs, ignore_index=True)

    return ddos_full, ransom_full


def preprocess_ddos(df: pd.DataFrame):
    # Dropear columnas no útiles
    to_drop = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
    df = df.drop(columns=[c for c in to_drop if c in df.columns], errors='ignore')

    # Etiqueta binaria
    if 'Label' in df.columns:
        df['Label'] = df['Label'].apply(lambda x: 1 if 'DDoS' in str(x) else 0)
    else:
        print("[WARN] No se encontró columna 'Label' en dataset DDoS")
        df['Label'] = 0

    # Rellenar nulos numéricos con mediana
    for col in df.select_dtypes(include=[np.number]).columns:
        df[col] = df[col].fillna(df[col].median())

    return df


def preprocess_ransomware(df: pd.DataFrame):
    to_drop = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
    df = df.drop(columns=[c for c in to_drop if c in df.columns], errors='ignore')

    # Asumimos que la columna con etiqueta es 'Class' o 'Label'
    if 'Label' in df.columns:
        df['Label'] = df['Label'].apply(lambda x: 1 if 'Ransomware' in str(x) else 0)
    elif 'Class' in df.columns:
        df['Label'] = df['Class'].apply(lambda x: 1 if 'Ransomware' in str(x) else 0)
    else:
        print("[WARN] No se encontró columna 'Label' ni 'Class' en dataset Ransomware")
        df['Label'] = 0

    for col in df.select_dtypes(include=[np.number]).columns:
        df[col] = df[col].fillna(df[col].median())

    return df


def plot_and_save_metrics(y_true, y_pred, y_proba, model_name, model_type):
    Path(MODELS_DIR).mkdir(exist_ok=True)

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_true, y_proba) if y_proba is not None else None

    print(f"--- Métricas para {model_type} con {model_name} ---")
    print(f"Accuracy: {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall: {rec:.4f}")
    print(f"F1-score: {f1:.4f}")
    if roc_auc:
        print(f"ROC-AUC: {roc_auc:.4f}")

    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, digits=4))

    # Matriz de confusión
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["Benigno", "Ataque"], yticklabels=["Benigno", "Ataque"])
    plt.title(f"Matriz de Confusión {model_type} - {model_name}")
    plt.xlabel("Predicho")
    plt.ylabel("Real")
    plt.tight_layout()
    cm_path = os.path.join(MODELS_DIR, f"{model_type}_{model_name}_confusion_matrix.png")
    plt.savefig(cm_path)
    plt.close()
    print(f"Matriz de confusión guardada en: {cm_path}")

    # Curvas ROC y Precision-Recall
    if y_proba is not None:
        fpr, tpr, _ = roc_curve(y_true, y_proba)
        precision, recall, _ = precision_recall_curve(y_true, y_proba)

        plt.figure(figsize=(12,5))
        plt.subplot(1,2,1)
        plt.plot(fpr, tpr, label=f"ROC Curve (AUC = {roc_auc:.4f})")
        plt.plot([0,1],[0,1],'k--')
        plt.xlabel("FPR")
        plt.ylabel("TPR")
        plt.title(f"ROC Curve {model_type} - {model_name}")
        plt.legend()

        plt.subplot(1,2,2)
        plt.plot(recall, precision, label="Precision-Recall Curve")
        plt.xlabel("Recall")
        plt.ylabel("Precision")
        plt.title(f"Precision-Recall {model_type} - {model_name}")
        plt.legend()

        curves_path = os.path.join(MODELS_DIR, f"{model_type}_{model_name}_roc_pr_curves.png")
        plt.savefig(curves_path)
        plt.close()
        print(f"Curvas ROC y PR guardadas en: {curves_path}")

    # Guardar métricas JSON
    metrics_json = {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "roc_auc": roc_auc,
        "confusion_matrix": cm.tolist(),
    }
    metrics_path = os.path.join(MODELS_DIR, f"{model_type}_{model_name}_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics_json, f, indent=4)
    print(f"Métricas guardadas en: {metrics_path}")

    # Guardar errores de clasificación
    errors_path = os.path.join(MODELS_DIR, f"{model_type}_{model_name}_errors.csv")
    error_df = pd.DataFrame({
        "True": y_true,
        "Predicted": y_pred
    })
    error_df['Error'] = error_df["True"] != error_df["Predicted"]
    error_df[error_df['Error']].to_csv(errors_path, index=False)
    print(f"Errores de clasificación guardados en: {errors_path}")



def train_model(X, y, model_key, model_type):
    print(f"\n[INFO] Entrenando modelo {model_key} para {model_type}...")

    params = MODEL_CONFIGS.get(model_key)
    if model_key == "random_forest":
        model = RandomForestClassifier(**params)
        model.fit(X, y)
    elif model_key == "lightgbm" and HAS_LGB:
        model = lgb.LGBMClassifier(**params)
        model.fit(X, y)
    else:
        raise ValueError(f"Modelo {model_key} no soportado o LightGBM no instalado.")

    return model


def run_training(df, model_type):
    # Asumimos etiqueta en 'Label' y resto features numéricas
    if 'Label' not in df.columns:
        print(f"[ERROR] Dataset {model_type} no tiene columna 'Label' para clasificación.")
        return

    X = df.drop(columns=['Label'])
    y = df['Label']

    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=RANDOM_SEED, stratify=y)

    trained_models = {}

    for model_key in MODEL_CONFIGS.keys():
        start = time.perf_counter()
        model = train_model(X_train, y_train, model_key, model_type)
        duration = time.perf_counter() - start

        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None

        plot_and_save_metrics(y_test, y_pred, y_proba, model_key, model_type)

        # Guardar modelo
        Path(MODELS_DIR).mkdir(parents=True, exist_ok=True)
        model_path = os.path.join(MODELS_DIR, f"{model_type}_{model_key}.joblib")
        import joblib
        joblib.dump(model, model_path)
        print(f"Modelo guardado en: {model_path}")
        print(f"Tiempo de entrenamiento: {duration:.2f} segundos\n")

        trained_models[model_key] = {
            "model": model,
            "train_time_sec": duration,
            "model_path": model_path
        }

    return trained_models


def main():
    print("="*80)
    print("UPGRADED HAPPINESS - QUANTIZED TRAINING PIPELINE")
    print("="*80)
    start_total = time.perf_counter()

    # Cargar y limpiar datasets
    start = time.perf_counter()
    ddos_df, ransom_df = load_all_datasets()
    time_load = time.perf_counter() - start
    print(f"[TIME] Carga y limpieza de datasets: {time_load:.2f} segundos\n")

    # Preprocesar datasets
    start = time.perf_counter()
    ddos_df = preprocess_ddos(ddos_df)
    ransom_df = preprocess_ransomware(ransom_df)
    time_prep = time.perf_counter() - start
    print(f"[TIME] Preprocesamiento de datasets: {time_prep:.2f} segundos\n")

    # Entrenar modelos DDoS
    print("\n[TRAINING] Modelo DDoS")
    trained_ddos = run_training(ddos_df, "ddos")

    # Entrenar modelos Ransomware
    print("\n[TRAINING] Modelo Ransomware")
    trained_ransom = run_training(ransom_df, "ransomware")

    time_total = time.perf_counter() - start_total
    print("="*80)
    print(f"✅ Entrenamiento completado en {time_total:.2f} segundos")
    print("="*80)


if __name__ == "__main__":
    main()
