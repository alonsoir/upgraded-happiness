#!/usr/bin/env python3
"""
diagnostic_script.py

Script para diagnosticar problemas con los datos antes del entrenamiento
"""

import os
import pandas as pd
import numpy as np
import glob
from pathlib import Path

DATASETS_DIR = "./datasets"
PARQUET_DIR = "./datasets_parquet"


def diagnose_dataset(file_path, dataset_name):
    """Diagnostica un dataset individual"""
    print(f"\n{'=' * 60}")
    print(f"DIAGNÓSTICO: {dataset_name}")
    print(f"Archivo: {file_path}")
    print(f"{'=' * 60}")

    try:
        # Cargar muestra pequeña primero
        if file_path.endswith('.parquet'):
            df = pd.read_parquet(file_path)
        else:
            # Solo leer las primeras 10,000 filas para diagnóstico rápido
            df = pd.read_csv(file_path, nrows=10000, low_memory=False)

        print(f"Shape (muestra): {df.shape}")

        # Información básica
        print(f"\nCOLUMNAS ({len(df.columns)}):")
        for i, col in enumerate(df.columns[:20]):  # Solo primeras 20
            print(f"  {i + 1:2d}. {col}")
        if len(df.columns) > 20:
            print(f"  ... y {len(df.columns) - 20} más")

        # Tipos de datos
        print(f"\nTIPOS DE DATOS:")
        type_counts = df.dtypes.value_counts()
        for dtype, count in type_counts.items():
            print(f"  {dtype}: {count} columnas")

        # Valores faltantes
        missing_counts = df.isnull().sum()
        missing_cols = missing_counts[missing_counts > 0]
        if len(missing_cols) > 0:
            print(f"\nVALORES FALTANTES (top 10):")
            for col, count in missing_cols.head(10).items():
                pct = (count / len(df)) * 100
                print(f"  {col}: {count} ({pct:.1f}%)")
        else:
            print(f"\n✅ Sin valores faltantes en la muestra")

        # Buscar posibles columnas de etiquetas
        label_candidates = []
        for col in df.columns:
            col_lower = col.lower().strip()
            if any(keyword in col_lower for keyword in ['label', 'class', 'attack', 'category', 'target']):
                label_candidates.append(col)

        if label_candidates:
            print(f"\nPOSIBLES COLUMNAS DE ETIQUETAS:")
            for col in label_candidates:
                unique_vals = df[col].value_counts()
                print(f"  {col}:")
                for val, count in unique_vals.head(5).items():
                    print(f"    {val}: {count}")
                if len(unique_vals) > 5:
                    print(f"    ... y {len(unique_vals) - 5} valores más")

        # Verificar valores infinitos y problemáticos
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        if len(numeric_cols) > 0:
            print(f"\nCOLUMNAS NUMÉRICAS ({len(numeric_cols)}):")
            inf_counts = {}
            for col in numeric_cols[:10]:  # Revisar solo las primeras 10
                inf_count = np.isinf(df[col]).sum()
                nan_count = df[col].isnull().sum()
                if inf_count > 0 or nan_count > 0:
                    inf_counts[col] = {'inf': inf_count, 'nan': nan_count}

            if inf_counts:
                print("  Columnas con problemas:")
                for col, counts in inf_counts.items():
                    print(f"    {col}: {counts['inf']} inf, {counts['nan']} nan")
            else:
                print("  ✅ Sin valores infinitos en muestra de columnas numéricas")

        # Tamaño del archivo completo
        if os.path.exists(file_path):
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            print(f"\nTAMAÑO DEL ARCHIVO: {file_size_mb:.1f} MB")

        return True

    except Exception as e:
        print(f"❌ ERROR al diagnosticar {file_path}: {e}")
        return False


def main():
    """Función principal de diagnóstico"""
    print("=" * 80)
    print("DIAGNÓSTICO DE DATASETS - UPGRADED HAPPINESS")
    print("=" * 80)

    # Diagnosticar archivos parquet (si existen)
    print(f"\n🔍 REVISANDO ARCHIVOS PARQUET EN: {PARQUET_DIR}")
    parquet_files = glob.glob(os.path.join(PARQUET_DIR, "*.parquet"))

    if parquet_files:
        print(f"Encontrados {len(parquet_files)} archivos parquet")
        # Diagnosticar solo algunos archivos representativos
        sample_files = parquet_files[:5]  # Primeros 5

        for pq_file in sample_files:
            diagnose_dataset(pq_file, os.path.basename(pq_file))
    else:
        print("No se encontraron archivos parquet")

    # Diagnosticar algunos CSVs originales
    print(f"\n🔍 REVISANDO ALGUNOS CSVS ORIGINALES")

    # DDoS
    ddos_dirs = ["ddos/01-12", "ddos/03-11"]
    ddos_files = []
    for d in ddos_dirs:
        ddos_files.extend(sorted(glob.glob(os.path.join(DATASETS_DIR, d, "*.csv"))))

    if ddos_files:
        print(f"Encontrados {len(ddos_files)} archivos DDoS")
        # Diagnosticar solo el primer archivo de cada directorio
        sample_ddos = ddos_files[:2]
        for csv_file in sample_ddos:
            diagnose_dataset(csv_file, f"DDoS - {os.path.basename(csv_file)}")

    # Ransomware
    ransom_files = sorted(glob.glob(os.path.join(DATASETS_DIR, "ransomware", "*.csv")))
    if ransom_files:
        print(f"Encontrados {len(ransom_files)} archivos Ransomware")
        # Diagnosticar todos (son pocos)
        for csv_file in ransom_files:
            diagnose_dataset(csv_file, f"Ransomware - {os.path.basename(csv_file)}")

    print(f"\n{'=' * 80}")
    print("DIAGNÓSTICO COMPLETADO")
    print("=" * 80)


if __name__ == "__main__":
    main()