#!/usr/bin/env python3
"""
LIMPIADOR ULTRA-AGRESIVO
Para casos extremos donde el overfitting persiste después de limpieza inicial
"""

import pandas as pd
import numpy as np
import argparse
from sklearn.preprocessing import LabelEncoder
from pathlib import Path


def ultra_aggressive_cleaning(df, target_column='label'):
    """
    Limpieza ultra-agresiva para eliminar cualquier rastro de overfitting
    """
    print(f"🧹 LIMPIEZA ULTRA-AGRESIVA")
    print("=" * 50)

    df_clean = df.copy()
    initial_features = len(df.columns) - 1  # Sin contar target

    # 1. ELIMINAR FEATURES CATEGÓRICAS PROBLEMÁTICAS
    print(f"\n1. ELIMINANDO FEATURES CATEGÓRICAS PROBLEMÁTICAS")
    print("-" * 40)

    categorical_cols = df_clean.select_dtypes(exclude=[np.number]).columns.tolist()
    if target_column in categorical_cols:
        categorical_cols.remove(target_column)

    categorical_to_remove = []

    for col in categorical_cols:
        # Verificar si hay valores exclusivos por clase
        class_values = {}
        for label in df_clean[target_column].unique():
            class_df = df_clean[df_clean[target_column] == label]
            class_values[label] = set(class_df[col].unique())

        if len(class_values) == 2:
            shared_values = class_values[0] & class_values[1]
            total_values = class_values[0] | class_values[1]

            overlap_ratio = len(shared_values) / len(total_values) if total_values else 0

            print(f"   {col}: {overlap_ratio:.1%} valores compartidos entre clases")

            # Si <50% de valores son compartidos, eliminar
            if overlap_ratio < 0.5:
                categorical_to_remove.append(col)
                print(f"   🗑️ ELIMINAR {col}: Separación categórica")

    if categorical_to_remove:
        df_clean = df_clean.drop(columns=categorical_to_remove)
        print(f"✅ Features categóricas eliminadas: {len(categorical_to_remove)}")
    else:
        print(f"✅ No hay features categóricas problemáticas")

    # 2. ELIMINAR FEATURES NUMÉRICAS CON SEPARACIÓN EXTREMA
    print(f"\n2. ELIMINANDO FEATURES NUMÉRICAS CON SEPARACIÓN EXTREMA")
    print("-" * 40)

    numeric_cols = df_clean.select_dtypes(include=[np.number]).columns.tolist()
    if target_column in numeric_cols:
        numeric_cols.remove(target_column)

    numeric_to_remove = []

    for col in numeric_cols:
        if df_clean[col].nunique() > 1:
            class_stats = df_clean.groupby(target_column)[col].agg(['mean', 'std'])

            if len(class_stats) == 2:
                means = class_stats['mean'].values
                stds = class_stats['std'].values
                mean_diff = abs(means[1] - means[0])
                pooled_std = np.sqrt(np.mean(stds ** 2))

                if pooled_std > 0:
                    separation_ratio = mean_diff / pooled_std
                    print(f"   {col}: separación = {separation_ratio:.1f} std deviations")

                    # Eliminar si separación > 3 std (muy agresivo)
                    if separation_ratio > 3:
                        numeric_to_remove.append(col)
                        print(f"   🗑️ ELIMINAR {col}: Separación extrema")

    if numeric_to_remove:
        df_clean = df_clean.drop(columns=numeric_to_remove)
        print(f"✅ Features numéricas eliminadas: {len(numeric_to_remove)}")
    else:
        print(f"✅ No hay features numéricas con separación extrema")

    # 3. VERIFICAR SEPARABILIDAD PERFECTA RESTANTE
    print(f"\n3. VERIFICANDO SEPARABILIDAD PERFECTA RESTANTE")
    print("-" * 40)

    remaining_numeric = df_clean.select_dtypes(include=[np.number]).columns.tolist()
    if target_column in remaining_numeric:
        remaining_numeric.remove(target_column)

    perfect_separators_remaining = []

    for col in remaining_numeric:
        if df_clean[col].nunique() > 1 and df_clean[col].nunique() < len(df_clean) * 0.5:
            value_class_counts = df_clean.groupby(col)[target_column].nunique()
            perfect_values = value_class_counts[value_class_counts == 1].index

            if len(perfect_values) > 0:
                perfect_rows = df_clean[df_clean[col].isin(perfect_values)]
                coverage = len(perfect_rows) / len(df_clean)

                if coverage > 0.05:  # Si >5% es predecible perfectamente
                    perfect_separators_remaining.append({
                        'feature': col,
                        'coverage': coverage
                    })
                    print(f"   {col}: {coverage:.1%} aún predecible perfectamente")

    # Eliminar separadores perfectos restantes
    final_removal = [ps['feature'] for ps in perfect_separators_remaining if ps['coverage'] > 0.1]

    if final_removal:
        df_clean = df_clean.drop(columns=final_removal)
        print(f"🗑️ Eliminados separadores perfectos restantes: {final_removal}")

    # 4. AGREGAR RUIDO A FEATURES NUMÉRICAS RESTANTES
    print(f"\n4. AGREGANDO RUIDO A FEATURES RESTANTES")
    print("-" * 40)

    final_numeric = df_clean.select_dtypes(include=[np.number]).columns.tolist()
    if target_column in final_numeric:
        final_numeric.remove(target_column)

    for col in final_numeric:
        if df_clean[col].std() > 0:
            # Ruido del 20% del rango (agresivo)
            feature_range = df_clean[col].max() - df_clean[col].min()
            noise_level = feature_range * 0.2

            if noise_level > 0:
                noise = np.random.normal(0, noise_level, len(df_clean))
                df_clean[col] = df_clean[col] + noise
                print(f"   🎲 Ruido agregado a {col}: ±{noise_level:.3f}")

    # 5. REDUCIR MUESTRA DRÁSTICAMENTE
    print(f"\n5. REDUCCIÓN DRÁSTICA DE MUESTRA")
    print("-" * 40)

    # Tomar solo 1000 muestras por clase (muy pequeño para reducir memorización)
    sampled_dfs = []
    for label in df_clean[target_column].unique():
        class_df = df_clean[df_clean[target_column] == label]
        sample_size = min(1000, len(class_df))

        if len(class_df) > sample_size:
            sampled_class = class_df.sample(sample_size, random_state=42)
        else:
            sampled_class = class_df

        sampled_dfs.append(sampled_class)
        print(f"   Clase {label}: {len(sampled_class):,} muestras")

    df_ultra_clean = pd.concat(sampled_dfs).sample(frac=1, random_state=42).reset_index(drop=True)

    # Resumen final
    final_features = len(df_ultra_clean.columns) - 1
    print(f"\n📊 RESUMEN ULTRA-AGRESIVO")
    print("-" * 30)
    print(f"📈 Filas: {len(df):,} → {len(df_ultra_clean):,}")
    print(f"📈 Features: {initial_features} → {final_features}")
    print(f"📉 Reducción de features: {((initial_features - final_features) / initial_features * 100):.1f}%")
    print(f"📉 Reducción de filas: {((len(df) - len(df_ultra_clean)) / len(df) * 100):.1f}%")

    return df_ultra_clean


def create_minimal_dataset(df, target_column='label', max_features=3):
    """
    Crea un dataset mínimo con solo las features menos problemáticas
    """
    print(f"\n🎯 CREANDO DATASET MÍNIMO ({max_features} features)")
    print("-" * 40)

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if target_column in numeric_cols:
        numeric_cols.remove(target_column)

    # Calcular separación para cada feature y quedarse con las menos problemáticas
    feature_scores = []

    for col in numeric_cols:
        if df[col].nunique() > 1:
            class_stats = df.groupby(target_column)[col].agg(['mean', 'std'])

            if len(class_stats) == 2:
                means = class_stats['mean'].values
                stds = class_stats['std'].values
                mean_diff = abs(means[1] - means[0])
                pooled_std = np.sqrt(np.mean(stds ** 2))

                if pooled_std > 0:
                    separation_ratio = mean_diff / pooled_std
                    feature_scores.append({
                        'feature': col,
                        'separation': separation_ratio
                    })

    # Seleccionar las features con menor separación
    feature_scores.sort(key=lambda x: x['separation'])
    selected_features = [fs['feature'] for fs in feature_scores[:max_features]]

    print(f"Features seleccionadas (menor separación):")
    for fs in feature_scores[:max_features]:
        print(f"   {fs['feature']}: {fs['separation']:.1f} std separación")

    # Crear dataset mínimo
    cols_to_keep = selected_features + [target_column]
    df_minimal = df[cols_to_keep].copy()

    # Agregar ruido significativo
    for col in selected_features:
        if df_minimal[col].std() > 0:
            feature_range = df_minimal[col].max() - df_minimal[col].min()
            noise_level = feature_range * 0.3  # 30% de ruido
            noise = np.random.normal(0, noise_level, len(df_minimal))
            df_minimal[col] = df_minimal[col] + noise

    return df_minimal


def main():
    parser = argparse.ArgumentParser(description='Limpiador Ultra-Agresivo para Casos Extremos')
    parser.add_argument('--input', required=True, help='Dataset CSV de entrada')
    parser.add_argument('--output', required=True, help='Dataset CSV de salida')
    parser.add_argument('--method', choices=['ultra', 'minimal'], default='ultra',
                        help='ultra=limpieza agresiva, minimal=solo 3 features menos problemáticas')
    parser.add_argument('--max_features', type=int, default=3,
                        help='Máximo features para método minimal')
    parser.add_argument('--target_column', default='label', help='Columna objetivo')

    args = parser.parse_args()

    print(f"🚨 LIMPIADOR ULTRA-AGRESIVO v1.0")
    print("=" * 60)
    print(f"📁 Input: {args.input}")
    print(f"💾 Output: {args.output}")
    print(f"🔧 Método: {args.method}")

    # Cargar dataset
    try:
        df = pd.read_csv(args.input)
        print(f"📊 Dataset cargado: {len(df):,} filas, {len(df.columns)} columnas")
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

    # Aplicar limpieza según método
    if args.method == 'ultra':
        df_result = ultra_aggressive_cleaning(df, args.target_column)
    elif args.method == 'minimal':
        df_result = create_minimal_dataset(df, args.target_column, args.max_features)

    # Distribución final
    final_dist = df_result[args.target_column].value_counts().sort_index()
    print(f"\n📋 Distribución final:")
    for label, count in final_dist.items():
        pct = (count / len(df_result)) * 100
        print(f"   Clase {label}: {count:,} ({pct:.1f}%)")

    # Guardar
    try:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df_result.to_csv(args.output, index=False)
        print(f"💾 Dataset ultra-limpio guardado: {args.output}")
        return 0
    except Exception as e:
        print(f"❌ Error guardando: {e}")
        return 1


if __name__ == "__main__":
    exit(main())