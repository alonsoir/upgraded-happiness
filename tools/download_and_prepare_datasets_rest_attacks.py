#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
download_and_prepare_datasets_rest_attacks.py

Descarga automática de datasets REST indicados en un archivo de configuración JSON.
Convierte automáticamente los archivos CSV descargados a formato Parquet.
"""

import os
import sys
import json
import requests
import pandas as pd
from urllib.parse import urlparse

CONFIG_PATH = "config/json/download_and_prepare_datasets_rest_attacks_config.json"
BASE_DATASET_DIR = "datasets"
PARQUET_DIR = "datasets_parquet"

def load_config(config_path):
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Archivo de configuración no encontrado: {config_path}")
    with open(config_path, "r") as f:
        return json.load(f)

def is_valid_url(url):
    try:
        result = urlparse(url)
        return result.scheme in {"http", "https"} and result.netloc != ""
    except Exception:
        return False

def download_file(url, output_path):
    try:
        with requests.get(url, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(output_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        return True
    except Exception as e:
        print(f"[ERROR] Fallo al descargar {url}: {e}")
        return False

def convert_csv_to_parquet(csv_path, parquet_dir, dataset_name, converted, failed):
    try:
        os.makedirs(parquet_dir, exist_ok=True)
        df = pd.read_csv(csv_path)
        parquet_path = os.path.join(parquet_dir, f"{dataset_name}.parquet")

        if os.path.exists(parquet_path):
            print(f"[OK] Parquet ya existe: {parquet_path}")
            return

        df.to_parquet(parquet_path, index=False)
        print(f"[DONE] Convertido a Parquet: {parquet_path}")
        converted.append(dataset_name)
    except Exception as e:
        print(f"[ERROR] Fallo al convertir {csv_path} a Parquet: {e}")
        failed.append(dataset_name)

def prepare_dataset(name, dataset_info, downloaded, skipped, failed, converted):
    print(f"\n==> Procesando dataset: {name}")

    folder = dataset_info.get("folder")
    url = dataset_info.get("url")
    manual = dataset_info.get("manual_download", False)

    if manual or not url:
        print(f"[SKIPPED] '{name}' requiere descarga manual o no tiene URL definida.")
        skipped.append(name)
        return

    if not is_valid_url(url):
        print(f"[ERROR] URL inválida para '{name}': {url}")
        failed.append(name)
        return

    dataset_dir = os.path.join(BASE_DATASET_DIR, folder)
    os.makedirs(dataset_dir, exist_ok=True)

    filename = os.path.basename(urlparse(url).path)
    output_csv_path = os.path.join(dataset_dir, filename)

    if os.path.exists(output_csv_path):
        print(f"[OK] Ya existe el archivo '{filename}', omitiendo descarga.")
        downloaded.append(name)
    else:
        print(f"[...] Descargando '{filename}' desde {url} ...")
        if download_file(url, output_csv_path):
            print(f"[DONE] Descargado correctamente: {output_csv_path}")
            downloaded.append(name)
        else:
            failed.append(name)
            return

    # Convertir a Parquet
    if filename.endswith(".csv"):
        convert_csv_to_parquet(output_csv_path, PARQUET_DIR, name, converted, failed)
    else:
        print(f"[SKIPPED] '{filename}' no es un archivo CSV, no se convierte a Parquet.")

def main():
    print("=== Descarga y conversión de datasets de ataques REST ===")
    config = load_config(CONFIG_PATH)

    downloaded = []
    skipped = []
    failed = []
    converted = []

    for name, dataset_info in config.items():
        prepare_dataset(name, dataset_info, downloaded, skipped, failed, converted)

    print("\n=== RESUMEN ===")
    print(f"✓ Descargados correctamente: {len(downloaded)} → {downloaded}")
    print(f"↺ Requieren descarga manual / sin URL: {len(skipped)} → {skipped}")
    print(f"📦 Convertidos a Parquet: {len(converted)} → {converted}")
    print(f"✗ Fallidos: {len(failed)} → {failed}")

    if failed:
        sys.exit(1)

if __name__ == "__main__":
    main()
