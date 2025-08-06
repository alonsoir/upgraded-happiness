#!/usr/bin/env python3
"""
GENERADOR DE DATASETS ESPECIALIZADOS
Crea datasets para detectores específicos de tráfico web e interno
"""

import pandas as pd
import numpy as np
import argparse
from pathlib import Path


def load_and_validate_dataset(path, expected_label, name):
    """Carga y valida un dataset individual"""
    try:
        df = pd.read_csv(path)
        print(f"📁 {name}: {len(df):,} registros cargados")

        # Verificar que tenga la columna label esperada o crearla
        if 'label' not in df.columns:
            df['label'] = expected_label
            print(f"   ✅ Etiqueta '{expected_label}' asignada automáticamente")
        else:
            # Verificar distribución
            label_dist = df['label'].value_counts()
            print(f"   📊 Distribución: {dict(label_dist)}")

        return df

    except Exception as e:
        print(f"❌ Error cargando {name}: {e}")
        return None


def create_web_normal_dataset(normal_traffic_df, internal_traffic_df, unsw_attacks_df):
    """
    Crea dataset para detectar tráfico web normal
    Clase 0: Tráfico web normal
    Clase 1: Tráfico interno + ataques
    """
    print(f"\n🌐 CREANDO DATASET: DETECTOR DE TRÁFICO WEB NORMAL")
    print("-" * 50)

    datasets_to_combine = []

    # Clase 0: Tráfico web normal (de tu sniffer)
    if normal_traffic_df is not None:
        web_normal = normal_traffic_df.copy()
        web_normal['specialized_label'] = 0  # Tráfico web normal
        datasets_to_combine.append(web_normal)
        print(f"📊 Clase 0 (Web Normal): {len(web_normal):,} registros")

    # Clase 1: Todo lo demás (tráfico interno + ataques)
    other_traffic = []

    if internal_traffic_df is not None:
        internal_as_other = internal_traffic_df.copy()
        internal_as_other['specialized_label'] = 1  # No es web normal
        other_traffic.append(internal_as_other)
        print(f"📊 Clase 1a (Interno como Otro): {len(internal_as_other):,} registros")

    if unsw_attacks_df is not None:
        attacks_as_other = unsw_attacks_df.copy()
        attacks_as_other['specialized_label'] = 1  # No es web normal
        other_traffic.append(attacks_as_other)
        print(f"📊 Clase 1b (Ataques como Otro): {len(attacks_as_other):,} registros")

    # Combinar todo el tráfico "no web"
    if other_traffic:
        combined_other = pd.concat(other_traffic, ignore_index=True)
        datasets_to_combine.append(combined_other)
        print(f"📊 Clase 1 (Total No-Web): {len(combined_other):,} registros")

    # Crear dataset final
    if len(datasets_to_combine) >= 2:
        web_detector_df = pd.concat(datasets_to_combine, ignore_index=True)

        # Renombrar columna para consistencia
        web_detector_df['label'] = web_detector_df['specialized_label']
        web_detector_df.drop('specialized_label', axis=1, inplace=True)

        # Resumen
        final_dist = web_detector_df['label'].value_counts().sort_index()
        print(f"✅ Dataset Web Detector creado: {len(web_detector_df):,} registros")
        print(f"   Clase 0 (Web Normal): {final_dist.get(0, 0):,}")
        print(f"   Clase 1 (No-Web): {final_dist.get(1, 0):,}")

        return web_detector_df
    else:
        print(f"❌ No hay suficientes datasets para crear detector web")
        return None


def create_internal_normal_dataset(normal_traffic_df, internal_traffic_df, unsw_attacks_df):
    """
    Crea dataset para detectar tráfico interno normal
    Clase 0: Tráfico interno normal
    Clase 1: Tráfico web + ataques
    """
    print(f"\n🏢 CREANDO DATASET: DETECTOR DE TRÁFICO INTERNO NORMAL")
    print("-" * 50)

    datasets_to_combine = []

    # Clase 0: Tráfico interno normal (de tu sniffer)
    if internal_traffic_df is not None:
        internal_normal = internal_traffic_df.copy()
        internal_normal['specialized_label'] = 0  # Tráfico interno normal
        datasets_to_combine.append(internal_normal)
        print(f"📊 Clase 0 (Interno Normal): {len(internal_normal):,} registros")

    # Clase 1: Todo lo demás (tráfico web + ataques)
    other_traffic = []

    if normal_traffic_df is not None:
        web_as_other = normal_traffic_df.copy()
        web_as_other['specialized_label'] = 1  # No es interno normal
        other_traffic.append(web_as_other)
        print(f"📊 Clase 1a (Web como Otro): {len(web_as_other):,} registros")

    if unsw_attacks_df is not None:
        attacks_as_other = unsw_attacks_df.copy()
        attacks_as_other['specialized_label'] = 1  # No es interno normal
        other_traffic.append(attacks_as_other)
        print(f"📊 Clase 1b (Ataques como Otro): {len(attacks_as_other):,} registros")

    # Combinar todo el tráfico "no interno"
    if other_traffic:
        combined_other = pd.concat(other_traffic, ignore_index=True)
        datasets_to_combine.append(combined_other)
        print(f"📊 Clase 1 (Total No-Interno): {len(combined_other):,} registros")

    # Crear dataset final
    if len(datasets_to_combine) >= 2:
        internal_detector_df = pd.concat(datasets_to_combine, ignore_index=True)

        # Renombrar columna para consistencia
        internal_detector_df['label'] = internal_detector_df['specialized_label']
        internal_detector_df.drop('specialized_label', axis=1, inplace=True)

        # Resumen
        final_dist = internal_detector_df['label'].value_counts().sort_index()
        print(f"✅ Dataset Interno Detector creado: {len(internal_detector_df):,} registros")
        print(f"   Clase 0 (Interno Normal): {final_dist.get(0, 0):,}")
        print(f"   Clase 1 (No-Interno): {final_dist.get(1, 0):,}")

        return internal_detector_df
    else:
        print(f"❌ No hay suficientes datasets para crear detector interno")
        return None


def balance_dataset_smart(df, target_column='label', max_samples_per_class=15000):
    """
    Balancea el dataset de manera inteligente
    """
    print(f"\n⚖️ BALANCEANDO DATASET")
    print("-" * 30)

    # Obtener distribución actual
    current_dist = df[target_column].value_counts().sort_index()
    print(f"📊 Distribución actual:")
    for label, count in current_dist.items():
        pct = (count / len(df)) * 100
        print(f"   Clase {label}: {count:,} ({pct:.1f}%)")

    # Determinar tamaño objetivo
    min_class_size = current_dist.min()
    target_size = min(max_samples_per_class, min_class_size)

    print(f"🎯 Tamaño objetivo por clase: {target_size:,}")

    # Muestrear cada clase
    balanced_dfs = []
    for label in df[target_column].unique():
        class_df = df[df[target_column] == label]

        if len(class_df) > target_size:
            sampled_class = class_df.sample(target_size, random_state=42)
        else:
            sampled_class = class_df

        balanced_dfs.append(sampled_class)
        print(f"   Clase {label}: {len(sampled_class):,} muestras")

    # Combinar y mezclar
    balanced_df = pd.concat(balanced_dfs).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"✅ Dataset balanceado: {len(balanced_df):,} registros")
    return balanced_df


def main():
    parser = argparse.ArgumentParser(description='Crear Datasets Especializados para Detección de Tráfico')
    parser.add_argument('--normal_traffic', default='datasets/public_normal/normal_traffic.csv',
                        help='Dataset de tráfico web normal')
    parser.add_argument('--internal_traffic', default='datasets/internal_traffic/internal_traffic_dataset.csv',
                        help='Dataset de tráfico interno normal')
    parser.add_argument('--unsw_attacks', default='data/unsw_attacks_only.csv',
                        help='Dataset de ataques UNSW-NB15')
    parser.add_argument('--output_dir', default='data/specialized',
                        help='Directorio de salida')
    parser.add_argument('--max_samples', type=int, default=15000,
                        help='Máximo muestras por clase')

    args = parser.parse_args()

    print(f"🚀 GENERADOR DE DATASETS ESPECIALIZADOS")
    print("=" * 60)
    print(f"📁 Tráfico Web Normal: {args.normal_traffic}")
    print(f"📁 Tráfico Interno Normal: {args.internal_traffic}")
    print(f"📁 Ataques UNSW: {args.unsw_attacks}")
    print(f"📁 Directorio salida: {args.output_dir}")
    print()

    # Crear directorio de salida
    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Cargar datasets
    print(f"1. CARGANDO DATASETS ORIGINALES")
    print("-" * 40)

    normal_traffic_df = load_and_validate_dataset(args.normal_traffic, 0, "Tráfico Web Normal")
    internal_traffic_df = load_and_validate_dataset(args.internal_traffic, 0, "Tráfico Interno Normal")
    unsw_attacks_df = load_and_validate_dataset(args.unsw_attacks, 1, "Ataques UNSW-NB15")

    # Verificar compatibilidad de columnas
    all_datasets = [df for df in [normal_traffic_df, internal_traffic_df, unsw_attacks_df] if df is not None]

    if len(all_datasets) < 2:
        print(f"❌ Se necesitan al menos 2 datasets válidos")
        return 1

    # Encontrar columnas comunes
    common_columns = set(all_datasets[0].columns)
    for df in all_datasets[1:]:
        common_columns &= set(df.columns)

    # Excluir columnas problemáticas conocidas
    exclude_columns = {'Unnamed: 0', 'index'}
    common_columns -= exclude_columns

    print(f"📋 Columnas comunes encontradas: {len(common_columns)}")
    print(f"   {sorted(list(common_columns)[:10])} {'...' if len(common_columns) > 10 else ''}")

    # Filtrar datasets a columnas comunes
    for i, df in enumerate(all_datasets):
        missing_cols = set(df.columns) - common_columns
        if missing_cols:
            print(f"⚠️ Dataset {i + 1}: eliminando {len(missing_cols)} columnas no comunes")
        all_datasets[i] = df[list(common_columns)]

    # Actualizar referencias
    if normal_traffic_df is not None:
        normal_traffic_df = all_datasets[0] if normal_traffic_df is not None else None
    if internal_traffic_df is not None:
        internal_traffic_df = all_datasets[1] if len(all_datasets) > 1 and internal_traffic_df is not None else None
    if unsw_attacks_df is not None:
        unsw_attacks_df = all_datasets[2] if len(all_datasets) > 2 and unsw_attacks_df is not None else None

    # Crear datasets especializados
    results = {}

    # Dataset 1: Detector de Tráfico Web Normal
    web_detector_df = create_web_normal_dataset(normal_traffic_df, internal_traffic_df, unsw_attacks_df)
    if web_detector_df is not None:
        # Balancear
        web_detector_balanced = balance_dataset_smart(web_detector_df, 'label', args.max_samples)

        # Guardar
        web_output_path = output_path / 'web_normal_detector.csv'
        web_detector_balanced.to_csv(web_output_path, index=False)
        print(f"💾 Web Detector guardado: {web_output_path}")
        results['web_detector'] = str(web_output_path)

    # Dataset 2: Detector de Tráfico Interno Normal
    internal_detector_df = create_internal_normal_dataset(normal_traffic_df, internal_traffic_df, unsw_attacks_df)
    if internal_detector_df is not None:
        # Balancear
        internal_detector_balanced = balance_dataset_smart(internal_detector_df, 'label', args.max_samples)

        # Guardar
        internal_output_path = output_path / 'internal_normal_detector.csv'
        internal_detector_balanced.to_csv(internal_output_path, index=False)
        print(f"💾 Internal Detector guardado: {internal_output_path}")
        results['internal_detector'] = str(internal_output_path)

    # Resumen final
    print(f"\n🎯 DATASETS ESPECIALIZADOS CREADOS")
    print("=" * 50)

    for detector_type, path in results.items():
        df_check = pd.read_csv(path)
        dist = df_check['label'].value_counts().sort_index()
        print(f"✅ {detector_type}:")
        print(f"   📁 Archivo: {path}")
        print(f"   📊 Registros: {len(df_check):,}")
        print(f"   📋 Distribución: Clase 0: {dist.get(0, 0):,}, Clase 1: {dist.get(1, 0):,}")

    print(f"\n🚀 PRÓXIMOS PASOS:")
    print(f"   1. Analizar calidad de los datasets especializados")
    print(f"   2. Entrenar modelos especializados")
    print(f"   3. Validar performance de cada detector")

    return 0


if __name__ == "__main__":
    exit(main())