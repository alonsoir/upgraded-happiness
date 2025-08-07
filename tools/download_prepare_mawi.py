#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/download_prepare_mawi.py

Descarga y prepara el dataset MAWI para el sistema IDS distribuido.
"""

import os
import requests
from pathlib import Path

# Configuración
DATASET_NAME = "mawi"
BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "datasets" / DATASET_NAME
DATASET_FILENAME = "mawi_dataset.csv"
DOWNLOAD_URL = "https://www.dropbox.com/scl/fi/example/mawi_dataset.csv?rlkey=abc123&dl=1"


def ensure_dataset_dir():
    DATASET_DIR.mkdir(parents=True, exist_ok=True)


def dataset_exists():
    return (DATASET_DIR / DATASET_FILENAME).exists()


def download_dataset():
    print(f"[...] Descargando '{DATASET_FILENAME}' desde {DOWNLOAD_URL}")
    response = requests.get(DOWNLOAD_URL, stream=True)
    if response.status_code == 200:
        with open(DATASET_DIR / DATASET_FILENAME, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"[OK] Descargado correctamente: {DATASET_DIR / DATASET_FILENAME}")
    else:
        raise RuntimeError(f"Error al descargar dataset MAWI. Código HTTP: {response.status_code}")


def main():
    print(f"\n=== Preparación del dataset: {DATASET_NAME.upper()} ===")
    ensure_dataset_dir()

    if dataset_exists():
        print(f"[SKIP] El archivo ya existe: {DATASET_FILENAME}")
    else:
        try:
            download_dataset()
        except Exception as e:
            print(f"[ERROR] Falló la descarga del dataset MAWI: {str(e)}")
            return

    print(f"[DONE] Dataset '{DATASET_NAME}' preparado correctamente.\n")


if __name__ == "__main__":
    main()
