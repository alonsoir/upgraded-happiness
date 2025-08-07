#!/usr/bin/env python3
"""
debug_parquet_inspector.py
Script rápido para inspeccionar exactamente qué está pasando con los archivos Parquet
"""

import pandas as pd
import glob
import os

PARQUET_DIR = "./datasets_parquet"


def inspect_parquet_file(filepath):
    """Inspecciona un archivo Parquet en detalle"""
    print(f"\n{'=' * 60}")
    print(f"INSPECCIONANDO: {os.path.basename(filepath)}")
    print(f"{'=' * 60}")

    try:
        df = pd.read_parquet(filepath)

        print(f"✅ Cargado exitosamente")
        print(f"   Shape: {df.shape}")
        print(f"   Tamaño archivo: {os.path.getsize(filepath) / (1024 * 1024):.1f} MB")

        # Mostrar todas las columnas que contienen "label"
        print(f"\n📋 TODAS LAS COLUMNAS:")
        for i, col in enumerate(df.columns):
            if 'label' in col.lower():
                print(f"   {i:2d}. '{col}' ⭐ (POSIBLE ETIQUETA)")
            else:
                print(f"   {i:2d}. '{col}'")

        # Buscar específicamente columnas de etiquetas
        label_candidates = []
        for col in df.columns:
            if any(keyword in col.lower() for keyword in ['label', 'class', 'target', 'attack']):
                label_candidates.append(col)

        if label_candidates:
            print(f"\n🎯 CANDIDATOS DE ETIQUETAS: {label_candidates}")

            for col in label_candidates:
                print(f"\n   Columna: '{col}'")
                print(f"   Tipo: {df[col].dtype}")

                unique_vals = df[col].value_counts()
                print(f"   Valores únicos ({len(unique_vals)}):")

                for val, count in unique_vals.head(10).items():
                    print(f"     {repr(val)}: {count:,}")

                if len(unique_vals) > 10:
                    print(f"     ... y {len(unique_vals) - 10} valores más")
        else:
            print(f"\n❌ NO SE ENCONTRARON CANDIDATOS DE ETIQUETAS")
            print(f"Columnas que empiezan con espacios:")
            space_cols = [col for col in df.columns if col.startswith(' ')]
            if space_cols:
                print(f"   {space_cols}")
            else:
                print("   Ninguna")

        return True

    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False


def main():
    """Función principal"""
    print("INSPECTOR DE ARCHIVOS PARQUET - DEBUG DDoS")
    print("=" * 60)

    parquet_files = glob.glob(os.path.join(PARQUET_DIR, "*.parquet"))

    if not parquet_files:
        print("❌ No se encontraron archivos Parquet")
        return

    print(f"📁 Encontrados {len(parquet_files)} archivos")

    # Inspeccionar solo algunos archivos representativos (no todos)
    ddos_files = [f for f in parquet_files if
                  not any(ransom in f.lower() for ransom in ['output1', 'output2', 'output3'])]

    print(f"📊 Inspeccionando {min(3, len(ddos_files))} archivos DDoS...")

    for i, pq_file in enumerate(ddos_files[:3]):
        inspect_parquet_file(pq_file)

        if i < 2:  # No hacer pausa en el último
            input("\n⏸️  Presiona Enter para continuar con el siguiente archivo...")


if __name__ == "__main__":
    main()