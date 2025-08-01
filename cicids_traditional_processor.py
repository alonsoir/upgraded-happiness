#!/usr/bin/env python3
"""
CICIDS-2017 Traditional API Processor
Descarga CICIDS-2017 usando API tradicional de Kaggle (más estable)
"""

import pandas as pd
import numpy as np
import os
import subprocess
import zipfile
import glob
import warnings

warnings.filterwarnings('ignore')


def setup_kaggle_api():
    """Configura la API de Kaggle"""

    print("🔑 CONFIGURANDO KAGGLE API")
    print("=" * 50)

    # Verificar si kaggle está instalado
    try:
        result = subprocess.run(['kaggle', '--version'], capture_output=True, text=True)
        print(f"✅ Kaggle CLI disponible: {result.stdout.strip()}")
        return True
    except FileNotFoundError:
        print("❌ Kaggle CLI no encontrado")
        print("💡 Instalar con: pip install kaggle")
        return False


def download_cicids_manual():
    """Descarga CICIDS-2017 usando Kaggle CLI"""

    print("\n📥 DESCARGANDO CICIDS-2017")
    print("=" * 50)

    dataset_name = "bertvankeulen/cicids-2017"
    download_dir = "cicids_data"

    # Crear directorio
    os.makedirs(download_dir, exist_ok=True)

    try:
        print(f"📥 Descargando: {dataset_name}")
        print("   (Esto puede tomar varios minutos...)")

        cmd = [
            'kaggle', 'datasets', 'download',
            dataset_name,
            '--path', download_dir,
            '--unzip'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print("✅ Descarga exitosa!")

            # Buscar archivos CSV
            csv_files = glob.glob(os.path.join(download_dir, "*.csv"))
            print(f"📁 Archivos CSV encontrados: {len(csv_files)}")

            for file in csv_files:
                filename = os.path.basename(file)
                size_mb = os.path.getsize(file) / (1024 * 1024)
                print(f"   📄 {filename} ({size_mb:.1f} MB)")

            return csv_files
        else:
            print(f"❌ Error en descarga: {result.stderr}")
            return None

    except Exception as e:
        print(f"❌ Error: {e}")
        return None


def manual_download_instructions():
    """Instrucciones para descarga manual"""

    print("\n📋 DESCARGA MANUAL DESDE KAGGLE WEB")
    print("=" * 50)

    print("🌐 Ve a: https://www.kaggle.com/datasets/bertvankeulen/cicids-2017")
    print("📥 Haz click en 'Download'")
    print("📁 Extrae el ZIP en una carpeta llamada 'cicids_data'")
    print("✅ Ejecuta este script de nuevo")

    data_dir = input("\n📁 ¿Ya descargaste? Ingresa la ruta de los archivos CSV: ").strip()

    if os.path.exists(data_dir):
        csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
        if csv_files:
            print(f"✅ Encontrados {len(csv_files)} archivos CSV")
            return csv_files
        else:
            print("❌ No se encontraron archivos CSV")
            return None
    else:
        print("❌ Directorio no existe")
        return None


def load_and_explore_cicids(csv_files):
    """Carga y explora archivos CICIDS-2017"""

    print(f"\n🔍 CARGANDO ARCHIVOS CICIDS-2017")
    print("=" * 50)

    # Cargar primer archivo para explorar estructura
    first_file = csv_files[0]
    filename = os.path.basename(first_file)

    print(f"📖 Explorando: {filename}")

    try:
        # Leer muestra pequeña primero
        df_sample = pd.read_csv(first_file, nrows=1000)

        # Limpiar nombres de columnas
        df_sample.columns = df_sample.columns.str.strip()

        print(f"✅ Archivo leído correctamente")
        print(f"📊 Columnas: {len(df_sample.columns)}")
        print(f"📊 Filas (muestra): {len(df_sample)}")

        # Mostrar columnas principales
        print(f"\n📋 COLUMNAS PRINCIPALES:")
        for i, col in enumerate(df_sample.columns[:15], 1):
            dtype = df_sample[col].dtype
            null_count = df_sample[col].isnull().sum()
            print(f"   {i:2d}. {col:<35} ({dtype}) - {null_count} nulls")

        if len(df_sample.columns) > 15:
            print(f"   ... y {len(df_sample.columns) - 15} columnas más")

        # Buscar columna de labels
        label_col = None
        possible_labels = ['Label', 'label', 'Label ', ' Label']

        for col in possible_labels:
            if col in df_sample.columns:
                label_col = col
                break

        if label_col:
            print(f"\n🏷️ DISTRIBUCIÓN DE LABELS ({label_col}):")
            label_counts = df_sample[label_col].value_counts()
            for label, count in label_counts.items():
                print(f"   {label}: {count}")
        else:
            print("⚠️  Columna de labels no encontrada claramente")
            print("   Últimas columnas:")
            for col in df_sample.columns[-5:]:
                print(f"     {col}")

        return csv_files, df_sample, label_col

    except Exception as e:
        print(f"❌ Error leyendo archivo: {e}")
        return None, None, None


def validate_cicids_data(df_sample):
    """Valida que los datos CICIDS sean realistas (no como UNSW-NB15)"""

    print(f"\n🔍 VALIDACIÓN DE DATOS CICIDS-2017")
    print("=" * 50)

    # Buscar features clave que sabemos pueden estar corruptas
    validation_results = {
        'duration_issues': False,
        'throughput_issues': False,
        'infinite_values': False,
        'quality_score': 'UNKNOWN'
    }

    # 1. Validar duraciones
    duration_cols = [col for col in df_sample.columns
                     if 'duration' in col.lower() or 'dur' in col.lower()]

    for col in duration_cols:
        if df_sample[col].dtype in ['float64', 'int64']:
            stats = df_sample[col].describe()
            print(f"\n⏱️  {col}:")
            print(f"   Min: {stats['min']:.6f}")
            print(f"   Max: {stats['max']:.6f}")
            print(f"   Mean: {stats['mean']:.6f}")

            # Validar si las duraciones son realistas
            if stats['max'] > 300000000:  # > 5 minutos en microsegundos
                print(f"   ⚠️  Duraciones muy altas (posible en microsegundos)")
            elif stats['max'] < 0.00001:  # < 10 microsegundos
                print(f"   🚨 Duraciones sospechosamente bajas como UNSW-NB15!")
                validation_results['duration_issues'] = True
            else:
                print(f"   ✅ Duraciones parecen realistas")

    # 2. Validar throughput/rate features
    rate_cols = [col for col in df_sample.columns
                 if any(x in col.lower() for x in ['bytes/s', 'packets/s', 'rate', 'throughput'])]

    for col in rate_cols:
        if df_sample[col].dtype in ['float64', 'int64']:
            stats = df_sample[col].describe()
            print(f"\n📈 {col}:")
            print(f"   Min: {stats['min']:.2f}")
            print(f"   Max: {stats['max']:.2f}")
            print(f"   Mean: {stats['mean']:.2f}")

            # Validar rangos realistas
            if 'bytes/s' in col.lower() and stats['max'] > 1000000000:  # > 1GB/s
                print(f"   🚨 Throughput irrealmente alto!")
                validation_results['throughput_issues'] = True
            elif 'packets/s' in col.lower() and stats['max'] > 1000000:  # > 1M pps
                print(f"   🚨 Packet rate irrealmente alto!")
                validation_results['throughput_issues'] = True
            else:
                print(f"   ✅ Valores parecen realistas")

    # 3. Buscar valores infinitos
    numeric_cols = df_sample.select_dtypes(include=[np.number]).columns
    inf_counts = {}

    for col in numeric_cols:
        inf_count = np.isinf(df_sample[col]).sum()
        if inf_count > 0:
            inf_counts[col] = inf_count

    if inf_counts:
        print(f"\n🚨 VALORES INFINITOS ENCONTRADOS:")
        for col, count in list(inf_counts.items())[:5]:
            print(f"   {col}: {count} infinitos")
        validation_results['infinite_values'] = True
    else:
        print(f"\n✅ NO HAY VALORES INFINITOS")

    # 4. Puntaje de calidad general
    issues = sum([
        validation_results['duration_issues'],
        validation_results['throughput_issues'],
        validation_results['infinite_values']
    ])

    if issues == 0:
        validation_results['quality_score'] = 'EXCELENTE'
        print(f"\n🎯 CALIDAD: EXCELENTE ✅")
        print(f"   Dataset parece limpio y realista")
    elif issues == 1:
        validation_results['quality_score'] = 'BUENA'
        print(f"\n🎯 CALIDAD: BUENA ⚠️")
        print(f"   1 issue menor detectado")
    else:
        validation_results['quality_score'] = 'PROBLEMÁTICA'
        print(f"\n🎯 CALIDAD: PROBLEMÁTICA 🚨")
        print(f"   {issues} issues detectados - similar a UNSW-NB15")

    return validation_results


def process_cicids_simple(csv_files, label_col):
    """Procesa CICIDS-2017 de forma simple y robusta"""

    print(f"\n🚀 PROCESANDO CICIDS-2017 (SIMPLE)")
    print("=" * 50)

    # Cargar todos los archivos
    dfs = []

    for file in csv_files:
        filename = os.path.basename(file)
        print(f"📥 Cargando {filename}...")

        try:
            df = pd.read_csv(file)
            df.columns = df.columns.str.strip()  # Limpiar nombres
            dfs.append(df)
            print(f"   ✅ {len(df):,} filas cargadas")
        except Exception as e:
            print(f"   ❌ Error: {e}")

    if not dfs:
        print("❌ No se cargaron archivos")
        return None

    # Combinar datasets
    print(f"\n🔗 Combinando {len(dfs)} archivos...")
    combined_df = pd.concat(dfs, ignore_index=True)
    print(f"✅ Dataset combinado: {len(combined_df):,} filas")

    # Limpieza básica
    print(f"\n🧹 Limpieza básica...")
    original_size = len(combined_df)

    # Remover infinitos y NaN
    combined_df = combined_df.replace([np.inf, -np.inf], np.nan)
    combined_df = combined_df.dropna()

    final_size = len(combined_df)
    removed = original_size - final_size
    print(f"   🗑️  Filas removidas: {removed:,} ({removed / original_size * 100:.1f}%)")
    print(f"   ✅ Filas finales: {final_size:,}")

    # Procesar labels
    if not label_col:
        label_col = combined_df.columns[-1]
        print(f"   Usando última columna como label: {label_col}")

    # Crear labels binarias
    combined_df['binary_label'] = (combined_df[label_col] != 'BENIGN').astype(int)

    # Mostrar distribución
    binary_dist = combined_df['binary_label'].value_counts()
    print(f"\n🏷️ DISTRIBUCIÓN FINAL:")
    print(f"   Normal (0): {binary_dist.get(0, 0):,} ({binary_dist.get(0, 0) / len(combined_df) * 100:.1f}%)")
    print(f"   Attack (1): {binary_dist.get(1, 0):,} ({binary_dist.get(1, 0) / len(combined_df) * 100:.1f}%)")

    # Guardar
    output_file = "cicids_2017_processed.csv"
    combined_df.to_csv(output_file, index=False)

    print(f"\n💾 Dataset guardado: {output_file}")
    print(f"   Tamaño: {os.path.getsize(output_file) / 1024 ** 2:.1f} MB")

    return output_file, combined_df


def main():
    """Función principal"""

    print("🚀 CICIDS-2017 PROCESSOR (ESTABLE)")
    print("🎯 Alternativa a kagglehub para Python 3.13")
    print("=" * 60)

    # Opción 1: Usar Kaggle CLI
    if setup_kaggle_api():
        csv_files = download_cicids_manual()
    else:
        csv_files = None

    # Opción 2: Descarga manual
    if not csv_files:
        csv_files = manual_download_instructions()

    if not csv_files:
        print("❌ No se pudo obtener el dataset")
        return

    # Explorar estructura
    csv_files, df_sample, label_col = load_and_explore_cicids(csv_files)

    if df_sample is None:
        return

    # Validar calidad
    validation = validate_cicids_data(df_sample)

    if validation['quality_score'] == 'PROBLEMÁTICA':
        proceed = input("\n🤔 Dataset parece tener issues. ¿Proceder de todos modos? (y/n): ").strip().lower()
        if proceed != 'y':
            print("❌ Proceso cancelado")
            return

    # Procesar dataset
    output_file, df_final = process_cicids_simple(csv_files, label_col)

    if output_file:
        print(f"\n🎯 ¡ÉXITO!")
        print(f"✅ Dataset procesado: {output_file}")
        print(f"✅ Filas: {len(df_final):,}")
        print(f"✅ Columnas: {len(df_final.columns)}")
        print(f"\n🚀 LISTO PARA RE-ENTRENAR CON DATOS LIMPIOS!")


if __name__ == "__main__":
    main()