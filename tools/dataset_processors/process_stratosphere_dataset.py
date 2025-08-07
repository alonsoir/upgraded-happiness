#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
process_stratosphere_dataset.py

Preprocesa y normaliza los datasets del proyecto Stratosphere.
Convierte a formatos limpios y usables por el pipeline de entrenamiento ML.
"""

import os
import pandas as pd
import argparse
from sklearn.preprocessing import LabelEncoder


def load_dataset(input_path):
    print(f"[INFO] Cargando dataset desde: {input_path}")
    df = pd.read_csv(input_path)
    print(f"[INFO] Dataset original: {df.shape[0]} filas, {df.shape[1]} columnas")
    return df


def clean_dataset(df):
    print("[INFO] Limpiando dataset...")
    # Eliminar duplicados
    df.drop_duplicates(inplace=True)

    # Eliminar filas con valores nulos si afectan a columnas importantes
    df.dropna(subset=['src_ip', 'dst_ip', 'protocol'], inplace=True)

    # Convertir a minúsculas los protocolos
    df['protocol'] = df['protocol'].str.upper()

    return df


def normalize_labels(df):
    print("[INFO] Normalizando etiquetas...")
    label_col = 'label'
    if label_col in df.columns:
        df[label_col] = df[label_col].str.lower()
        df[label_col] = df[label_col].replace({
            'malware': 1,
            'attack': 1,
            'botnet': 1,
            'normal': 0,
            'benign': 0
        })
    else:
        print("[WARN] No se encontró la columna 'label' para normalizar.")
    return df


def save_outputs(df, output_dir, base_name="stratosphere_cleaned"):
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, base_name + ".csv")
    parquet_path = os.path.join(output_dir, base_name + ".parquet")

    df.to_csv(csv_path, index=False)
    df.to_parquet(parquet_path, index=False)

    print(f"[INFO] Guardado CSV limpio: {csv_path}")
    print(f"[INFO] Guardado Parquet limpio: {parquet_path}")


def summarize(df):
    print("\n[INFO] Resumen del dataset limpio:")
    print(df.describe(include='all'))
    print("\n[INFO] Distribución de etiquetas:")
    print(df['label'].value_counts())


def main():
    parser = argparse.ArgumentParser(description="Procesa y normaliza el dataset Stratosphere")
    parser.add_argument("--input", required=True, help="Ruta al archivo CSV del dataset original")
    parser.add_argument("--output", default="datasets/stratosphere/processed", help="Directorio de salida")
    args = parser.parse_args()

    df = load_dataset(args.input)
    df = clean_dataset(df)
    df = normalize_labels(df)
    save_outputs(df, args.output)
    summarize(df)


if __name__ == "__main__":
    main()
