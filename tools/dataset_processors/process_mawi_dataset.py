#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
process_mawi_dataset.py

Procesa y limpia el dataset MAWI:
- Verifica presencia local del dataset (o guía sobre cómo descargarlo)
- Limpia columnas irrelevantes o corruptas
- Normaliza tipos de datos
- Genera CSV limpio y opcionalmente Parquet
- Guarda metadatos sobre el dataset
"""

import os
import pandas as pd
import argparse
import json
import sys
import gzip
import shutil
from datetime import datetime

# Ruta base del dataset
RAW_DATA_DIR = "./datasets/mawi/raw/"
PROCESSED_DATA_DIR = "./datasets/mawi/processed/"
METADATA_DIR = "./datasets/mawi/metadata/"

# Nombre del archivo esperado (ajustable)
DEFAULT_RAW_FILE = "mawilab-2020-01-01.csv.gz"
DEFAULT_CLEAN_FILE = "mawilab_cleaned.csv"
DEFAULT_PARQUET_FILE = "mawilab_cleaned.parquet"
DEFAULT_METADATA_FILE = "mawilab_metadata.json"


def ensure_directories():
    """Crea directorios necesarios si no existen."""
    for path in [RAW_DATA_DIR, PROCESSED_DATA_DIR, METADATA_DIR]:
        os.makedirs(path, exist_ok=True)


def decompress_if_needed(filepath):
    """Descomprime un archivo .gz si es necesario."""
    if filepath.endswith(".gz"):
        decompressed_path = filepath[:-3]
        print(f"[+] Descomprimiendo {filepath} → {decompressed_path}")
        with gzip.open(filepath, 'rb') as f_in, open(decompressed_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        return decompressed_path
    return filepath


def clean_mawi_csv(input_csv_path):
    """Carga y limpia el dataset MAWI."""
    print(f"[+] Cargando dataset MAWI: {input_csv_path}")
    try:
        df = pd.read_csv(input_csv_path, low_memory=False)
    except Exception as e:
        print(f"[!] Error al leer CSV: {e}")
        sys.exit(1)

    print(f"[+] Filas originales: {len(df)}")

    # Paso 1: eliminar columnas vacías o sin nombre
    df = df.loc[:, ~df.columns.str.contains('^Unnamed')]
    df.dropna(axis=1, how="all", inplace=True)

    # Paso 2: eliminar duplicados
    df.drop_duplicates(inplace=True)

    # Paso 3: convertir tipos si es necesario
    if "ts" in df.columns:
        df["ts"] = pd.to_datetime(df["ts"], errors="coerce")

    # Paso 4: limpieza específica si se conocen columnas inútiles
    cols_to_drop = ["label"] if "label" in df.columns else []
    df.drop(columns=cols_to_drop, inplace=True, errors="ignore")

    # Paso 5: quitar filas con NaN críticos
    df.dropna(subset=["ts", "srcIP", "dstIP"], inplace=True)

    print(f"[+] Filas limpias: {len(df)}")
    return df


def save_outputs(df, output_csv_path, output_parquet_path, metadata_path):
    """Guarda CSV, Parquet y metadatos del dataset."""
    print(f"[+] Guardando CSV limpio en: {output_csv_path}")
    df.to_csv(output_csv_path, index=False)

    print(f"[+] Guardando Parquet (opcional)...")
    df.to_parquet(output_parquet_path, index=False)

    metadata = {
        "n_samples": len(df),
        "n_columns": len(df.columns),
        "columns": df.columns.tolist(),
        "fecha_procesado": datetime.utcnow().isoformat(),
        "origen": "mawilab",
        "csv": os.path.abspath(output_csv_path),
        "parquet": os.path.abspath(output_parquet_path),
    }

    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=4)
    print(f"[+] Metadatos guardados en: {metadata_path}")


def main():
    parser = argparse.ArgumentParser(description="Procesador para el dataset MAWI (MAWILab)")
    parser.add_argument("--file", type=str, default=DEFAULT_RAW_FILE,
                        help="Nombre del archivo CSV crudo (gzip o plano)")
    args = parser.parse_args()

    ensure_directories()

    raw_file_path = os.path.join(RAW_DATA_DIR, args.file)

    if not os.path.isfile(raw_file_path):
        print(f"[!] No se encontró el archivo: {raw_file_path}")
        print("[i] Por favor, descarga manualmente el dataset desde:")
        print("    https://mawilab.mlab-telekom.com/download/")
        sys.exit(1)

    csv_path = decompress_if_needed(raw_file_path)

    df_clean = clean_mawi_csv(csv_path)

    save_outputs(
        df_clean,
        os.path.join(PROCESSED_DATA_DIR, DEFAULT_CLEAN_FILE),
        os.path.join(PROCESSED_DATA_DIR, DEFAULT_PARQUET_FILE),
        os.path.join(METADATA_DIR, DEFAULT_METADATA_FILE)
    )

    print("[✓] Proceso completado con éxito.")


if __name__ == "__main__":
    main()
