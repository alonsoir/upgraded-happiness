#!/usr/bin/env python3
"""
LIMPIADOR DE DATASETS - Elimina problemas de overfitting
Basado en el análisis de calidad de datos realizado
"""

import pandas as pd
import numpy as np
import argparse
from pathlib import Path
from sklearn.preprocessing import StandardScaler
import warnings

warnings.filterwarnings('ignore')


def identify_problematic_features(df, target_column='label',
                                  perfect_threshold=0.05, separation_threshold=10):
    """
    Identifica features que causan separabilidad perfecta
    """
    print(f"🔍 Identificando features problemáticas...")

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if target_column in numeric_cols:
        numeric_cols.remove(target_column)

    problematic_features = []

    # 1. Features con separabilidad perfecta
    perfect_separators = []
    for col in numeric_cols:
        if df[col].nunique() > 1:
            # Para cada valor único, ver si predice solo una clase
            value_class_counts = df.groupby(col)[target_column].nunique()
            perfect_values = value_class_counts[value_class_counts == 1].index

            if len(perfect_values) > 0:
                # Calcular coverage
                perfect_rows = df[df[col].isin(perfect_values)]
                coverage = len(perfect_rows) / len(df)

                if coverage > perfect_threshold:
                    perfect_separators.append({
                        'feature': col,
                        'coverage': coverage,
                        'type': 'perfect_separator'
                    })

    # 2. Features con separación extrema entre clases
    extreme_separators = []
    for col in numeric_cols:
        if df[col].nunique() > 1:
            class_stats = df.groupby(target_column)[col].agg(['mean', 'std'])

            if len(class_stats) == 2:  # Clasificación binaria
                means = class_stats['mean'].values
                stds = class_stats['std'].values

                # Calcular separación
                mean_diff = abs(means[1] - means[0])
                pooled_std = np.sqrt(np.mean(stds ** 2))

                if pooled_std > 0:
                    separation_ratio = mean_diff / pooled_std
                    if separation_ratio > separation_threshold:
                        extreme_separators.append({
                            'feature': col,
                            'separation': separation_ratio,
                            'type': 'extreme_separation'
                        })

    # Combinar todas las features problemáticas
    all_problematic = perfect_separators + extreme_separators
    problematic_features = list(set([f['feature'] for f in all_problematic]))

    print(f"🚨 Features problemáticas identificadas: {len(problematic_features)}")
    for feature_info in perfect_separators:
        print(f"   {feature_info['feature']}: separabilidad perfecta ({feature_info['coverage']:.1%})")

    for feature_info in extreme_separators:
        print(f"   {feature_info['feature']}: separación extrema ({feature_info['separation']:.1f} std)")

    return problematic_features, perfect_separators, extreme_separators


def clean_dataset_conservative(df, target_column='label'):
    """
    Limpieza conservadora del dataset - elimina features problemáticas
    """
    print(f"\n🧹 LIMPIEZA CONSERVADORA")
    print("-" * 40)

    df_clean = df.copy()

    # 1. Identificar features problemáticas
    problematic_features, perfect_sep, extreme_sep = identify_problematic_features(
        df_clean, target_column, perfect_threshold=0.05, separation_threshold=20
    )

    # 2. Eliminar features con separabilidad perfecta
    perfect_features = [f['feature'] for f in perfect_sep if f['coverage'] > 0.3]
    if perfect_features:
        print(f"🗑️ Eliminando features con separabilidad perfecta:")
        for feature in perfect_features:
            print(f"   - {feature}")
        df_clean = df_clean.drop(columns=perfect_features)

    # 3. Eliminar features con separación extrema (>50 std)
    extreme_features = [f['feature'] for f in extreme_sep if f['separation'] > 50]
    if extreme_features:
        print(f"🗑️ Eliminando features con separación extrema:")
        for feature in extreme_features:
            print(f"   - {feature}")
        df_clean = df_clean.drop(columns=extreme_features)

    print(f"✅ Dataset limpio: {df_clean.shape[0]} filas, {df_clean.shape[1]} columnas")
    print(f"📉 Features eliminadas: {df.shape[1] - df_clean.shape[1]}")

    return df_clean


def clean_dataset_aggressive(df, target_column='label'):
    """
    Limpieza agresiva - transforma features problemáticas con ruido
    """
    print(f"\n🧹 LIMPIEZA AGRESIVA CON RUIDO")
    print("-" * 40)

    df_clean = df.copy()

    # 1. Identificar features problemáticas
    problematic_features, perfect_sep, extreme_sep = identify_problematic_features(
        df_clean, target_column, perfect_threshold=0.01, separation_threshold=5
    )

    # 2. Agregar ruido a features problemáticas
    for feature_info in perfect_sep + extreme_sep:
        feature = feature_info['feature']

        if feature in df_clean.columns:
            print(f"🎲 Agregando ruido a {feature}...")

            # Calcular ruido proporcional
            feature_std = df_clean[feature].std()
            feature_range = df_clean[feature].max() - df_clean[feature].min()

            # Ruido del 5% del rango o 10% del std (el que sea menor)
            noise_level = min(feature_range * 0.05, feature_std * 0.1)

            if noise_level > 0:
                # Agregar ruido gaussiano
                noise = np.random.normal(0, noise_level, len(df_clean))
                df_clean[feature] = df_clean[feature] + noise

    # 3. Eliminar solo las features MUY extremas
    ultra_extreme = [f['feature'] for f in extreme_sep if f['separation'] > 1000]
    if ultra_extreme:
        print(f"🗑️ Eliminando features ultra-extremas:")
        for feature in ultra_extreme:
            print(f"   - {feature} (separación > 1000 std)")
        df_clean = df_clean.drop(columns=ultra_extreme)

    print(f"✅ Dataset limpio: {df_clean.shape[0]} filas, {df_clean.shape[1]} columnas")
    print(f"📉 Features eliminadas: {df.shape[1] - df_clean.shape[1]}")

    return df_clean


def remove_duplicates_smart(df, target_column='label'):
    """
    Elimina duplicados de manera inteligente
    """
    print(f"\n🔄 ELIMINACIÓN INTELIGENTE DE DUPLICADOS")
    print("-" * 40)

    initial_count = len(df)

    # 1. Eliminar duplicados completos
    df_clean = df.drop_duplicates()
    complete_dups_removed = initial_count - len(df_clean)

    print(f"🗑️ Duplicados completos eliminados: {complete_dups_removed:,}")

    # 2. Para features duplicadas, mantener distribución balanceada
    features_only = df_clean.drop(columns=[target_column])

    # Encontrar grupos de features duplicadas
    dup_mask = features_only.duplicated(keep=False)
    if dup_mask.sum() > 0:
        print(f"🔍 Procesando {dup_mask.sum()} filas con features duplicadas...")

        # Agrupar por features y mantener distribución proporcional
        dup_groups = df_clean[dup_mask].groupby(features_only.columns.tolist())
        keep_indices = []

        for group_key, group_df in dup_groups:
            # Para cada grupo, mantener máximo 2 ejemplos por clase
            for label in group_df[target_column].unique():
                label_rows = group_df[group_df[target_column] == label]
                keep_count = min(2, len(label_rows))
                keep_indices.extend(label_rows.sample(keep_count, random_state=42).index.tolist())

        # Combinar filas únicas + filas seleccionadas de duplicadas
        unique_rows = df_clean[~dup_mask]
        selected_dup_rows = df_clean.loc[keep_indices]
        df_clean = pd.concat([unique_rows, selected_dup_rows]).reset_index(drop=True)

        feature_dups_removed = initial_count - complete_dups_removed - len(df_clean)
        print(f"🗑️ Features duplicadas reducidas: {feature_dups_removed:,}")

    print(f"✅ Dataset final: {len(df_clean):,} filas ({initial_count - len(df_clean):,} eliminadas)")

    return df_clean


def create_balanced_sample(df, target_column='label', max_samples_per_class=15000):
    """
    Crea una muestra balanceada más pequeña
    """
    print(f"\n⚖️ CREANDO MUESTRA BALANCEADA")
    print("-" * 40)

    # Obtener muestras por clase
    sampled_dfs = []
    for label in df[target_column].unique():
        class_df = df[df[target_column] == label]
        sample_size = min(max_samples_per_class, len(class_df))

        if len(class_df) > sample_size:
            sampled_class = class_df.sample(sample_size, random_state=42)
        else:
            sampled_class = class_df

        sampled_dfs.append(sampled_class)
        print(f"📊 Clase {label}: {len(sampled_class):,} muestras")

    # Combinar y mezclar
    balanced_df = pd.concat(sampled_dfs).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"✅ Muestra balanceada: {len(balanced_df):,} filas")

    return balanced_df


def main():
    parser = argparse.ArgumentParser(description='Limpiador de Datasets para Evitar Overfitting')
    parser.add_argument('--input', required=True, help='Dataset CSV de entrada')
    parser.add_argument('--output', required=True, help='Dataset CSV de salida')
    parser.add_argument('--method', choices=['conservative', 'aggressive', 'balanced'],
                        default='conservative', help='Método de limpieza')
    parser.add_argument('--max_samples', type=int, default=15000,
                        help='Máximo de muestras por clase (solo para método balanced)')
    parser.add_argument('--target_column', default='label', help='Columna objetivo')

    args = parser.parse_args()

    print(f"🧹 LIMPIADOR DE DATASETS v1.0")
    print("=" * 50)
    print(f"📁 Input: {args.input}")
    print(f"💾 Output: {args.output}")
    print(f"🔧 Método: {args.method}")
    print()

    # Cargar dataset
    try:
        df = pd.read_csv(args.input)
        print(f"📊 Dataset cargado: {len(df):,} filas, {len(df.columns)} columnas")
    except Exception as e:
        print(f"❌ Error cargando dataset: {e}")
        return 1

    # Aplicar limpieza según método
    if args.method == 'conservative':
        df_clean = clean_dataset_conservative(df, args.target_column)
        df_clean = remove_duplicates_smart(df_clean, args.target_column)

    elif args.method == 'aggressive':
        df_clean = clean_dataset_aggressive(df, args.target_column)
        df_clean = remove_duplicates_smart(df_clean, args.target_column)

    elif args.method == 'balanced':
        df_clean = clean_dataset_conservative(df, args.target_column)
        df_clean = remove_duplicates_smart(df_clean, args.target_column)
        df_clean = create_balanced_sample(df_clean, args.target_column, args.max_samples)

    # Verificar resultado
    print(f"\n📊 RESULTADO FINAL")
    print("-" * 30)
    print(f"📈 Filas: {len(df):,} → {len(df_clean):,}")
    print(f"📈 Columnas: {len(df.columns)} → {len(df_clean.columns)}")

    # Distribución final
    final_dist = df_clean[args.target_column].value_counts().sort_index()
    print(f"📋 Distribución final:")
    for label, count in final_dist.items():
        pct = (count / len(df_clean)) * 100
        print(f"   Clase {label}: {count:,} ({pct:.1f}%)")

    # Guardar dataset limpio
    try:
        # Crear directorio si no existe
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        df_clean.to_csv(args.output, index=False)
        print(f"💾 Dataset limpio guardado: {args.output}")

        # Guardar reporte
        report_path = str(output_path).replace('.csv', '_cleaning_report.txt')
        with open(report_path, 'w') as f:
            f.write(f"REPORTE DE LIMPIEZA\n")
            f.write(f"==================\n")
            f.write(f"Input: {args.input}\n")
            f.write(f"Output: {args.output}\n")
            f.write(f"Método: {args.method}\n")
            f.write(f"Filas originales: {len(df):,}\n")
            f.write(f"Filas finales: {len(df_clean):,}\n")
            f.write(f"Columnas originales: {len(df.columns)}\n")
            f.write(f"Columnas finales: {len(df_clean.columns)}\n")
            f.write(f"Reducción: {((len(df) - len(df_clean)) / len(df) * 100):.1f}%\n")

        print(f"📄 Reporte guardado: {report_path}")

        return 0

    except Exception as e:
        print(f"❌ Error guardando dataset: {e}")
        return 1


if __name__ == "__main__":
    exit(main())