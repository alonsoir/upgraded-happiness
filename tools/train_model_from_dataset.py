#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
train_model_from_dataset.py

Entrena un modelo Random Forest sobre un solo dataset (CSV o Parquet),
aplicando limpieza, validación, SMOTE y guardado automático del modelo.
"""

import os
import sys
import argparse
import pandas as pd
import numpy as np
import joblib
import time
import warnings

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_score,
    recall_score,
    f1_score,
)
from imblearn.over_sampling import SMOTE

warnings.filterwarnings("ignore")


def load_dataset(input_path):
    if input_path.endswith(".parquet"):
        print(f"[INFO] Cargando archivo Parquet: {input_path}")
        return pd.read_parquet(input_path)
    elif input_path.endswith(".csv"):
        print(f"[INFO] Cargando archivo CSV: {input_path}")
        return pd.read_csv(input_path)
    else:
        raise ValueError("Formato no soportado. Usa .csv o .parquet")


def clean_dataset(df, target_column):
    print(f"[INFO] Dimensión original: {df.shape}")
    df = df.dropna()
    df = df.select_dtypes(include=[np.number])
    if target_column not in df.columns:
        raise ValueError(f"La columna objetivo '{target_column}' no está en el dataset.")
    print(f"[INFO] Dataset limpio: {df.shape}")
    return df


def balance_dataset(X, y):
    print("[INFO] Aplicando SMOTE para balancear clases...")
    smote = SMOTE(random_state=42)
    X_res, y_res = smote.fit_resample(X, y)
    print(f"[INFO] Nuevas dimensiones tras SMOTE: {X_res.shape}")
    return X_res, y_res


def train_model(X_train, y_train):
    print("[INFO] Entrenando modelo Random Forest...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )
    clf.fit(X_train, y_train)
    return clf


def evaluate_model(clf, X_test, y_test):
    print("[INFO] Evaluando modelo...")
    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=False)
    print("[RESULTADOS] Clasificación:")
    print(report)
    print("Matriz de confusión:")
    print(confusion_matrix(y_test, y_pred))
    print(f"F1 Score: {f1_score(y_test, y_pred, average='weighted'):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred, average='weighted'):.4f}")
    print(f"Recall: {recall_score(y_test, y_pred, average='weighted'):.4f}")
    try:
        y_prob = clf.predict_proba(X_test)
        roc_auc = roc_auc_score(y_test, y_prob, multi_class='ovr')
        print(f"ROC AUC: {roc_auc:.4f}")
    except Exception:
        print("[WARN] No se pudo calcular ROC AUC (posiblemente modelo sin predict_proba)")


def save_model(clf, output_dir, dataset_name):
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(output_dir, f"rf_model_{dataset_name}.joblib")
    joblib.dump(clf, filename)
    print(f"[INFO] Modelo guardado en: {filename}")


def main():
    parser = argparse.ArgumentParser(description="Entrenamiento individual de modelo RF desde un dataset CSV o Parquet.")
    parser.add_argument("--input_file", required=True, help="Ruta al archivo .csv o .parquet de entrada")
    parser.add_argument("--output_dir", default="models", help="Directorio donde guardar el modelo entrenado")
    parser.add_argument("--target_column", default="label", help="Nombre de la columna objetivo")
    parser.add_argument("--balance", action="store_true", help="Aplicar SMOTE para balancear clases")
    args = parser.parse_args()

    start_time = time.time()
    dataset_name = os.path.splitext(os.path.basename(args.input_file))[0]

    try:
        df = load_dataset(args.input_file)
        df = clean_dataset(df, args.target_column)

        y = df[args.target_column]
        X = df.drop(columns=[args.target_column])

        if args.balance:
            X, y = balance_dataset(X, y)

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        clf = train_model(X_train, y_train)
        evaluate_model(clf, X_test, y_test)
        save_model(clf, args.output_dir, dataset_name)

        print(f"[DONE] Tiempo total: {time.time() - start_time:.2f}s")

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
