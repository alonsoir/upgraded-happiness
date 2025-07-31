#!/usr/bin/env python3
"""
ANALIZADOR DE FEATURES RESTANTES
Analiza por qué sigue habiendo overfitting después de la limpieza
"""

import pandas as pd
import numpy as np
import argparse
from collections import Counter


def analyze_remaining_features(csv_path, target_column='label'):
    """
    Analiza en detalle las features que quedaron después de la limpieza inicial
    """
    print(f"🔍 ANÁLISIS PROFUNDO: {csv_path}")
    print("=" * 60)

    # Cargar datos
    try:
        df = pd.read_csv(csv_path)
        print(f"📊 Dataset cargado: {len(df):,} registros, {len(df.columns)} columnas")
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

    print(f"📋 Columnas: {list(df.columns)}")

    # Análisis por tipo de feature
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = df.select_dtypes(exclude=[np.number]).columns.tolist()

    if target_column in numeric_cols:
        numeric_cols.remove(target_column)
    if target_column in categorical_cols:
        categorical_cols.remove(target_column)

    print(f"🔢 Features numéricas: {numeric_cols}")
    print(f"🔤 Features categóricas: {categorical_cols}")

    # 1. ANÁLISIS DE FEATURES CATEGÓRICAS
    print(f"\n1. ANÁLISIS DETALLADO DE FEATURES CATEGÓRICAS")
    print("-" * 50)

    for col in categorical_cols:
        print(f"\n🔍 Analizando {col}:")

        # Valores únicos por clase
        class_value_counts = {}
        for label in df[target_column].unique():
            class_df = df[df[target_column] == label]
            unique_values = class_df[col].value_counts()
            class_value_counts[label] = unique_values
            print(f"   Clase {label}: {len(unique_values)} valores únicos")
            print(f"     Top 3: {unique_values.head(3).to_dict()}")

        # Buscar valores exclusivos por clase
        all_values_class_0 = set(class_value_counts.get(0, pd.Series()).index)
        all_values_class_1 = set(class_value_counts.get(1, pd.Series()).index)

        exclusive_0 = all_values_class_0 - all_values_class_1
        exclusive_1 = all_values_class_1 - all_values_class_0
        shared = all_values_class_0 & all_values_class_1

        print(f"   📊 Exclusivos Clase 0: {len(exclusive_0)}")
        print(f"   📊 Exclusivos Clase 1: {len(exclusive_1)}")
        print(f"   📊 Compartidos: {len(shared)}")

        if exclusive_0 or exclusive_1:
            exclusive_coverage_0 = df[(df[target_column] == 0) & (df[col].isin(exclusive_0))].shape[0]
            exclusive_coverage_1 = df[(df[target_column] == 1) & (df[col].isin(exclusive_1))].shape[0]
            total_0 = (df[target_column] == 0).sum()
            total_1 = (df[target_column] == 1).sum()

            coverage_pct_0 = (exclusive_coverage_0 / total_0 * 100) if total_0 > 0 else 0
            coverage_pct_1 = (exclusive_coverage_1 / total_1 * 100) if total_1 > 0 else 0

            print(f"   🚨 SEPARABILIDAD DETECTADA:")
            print(f"     Clase 0 exclusiva: {coverage_pct_0:.1f}% ({exclusive_coverage_0}/{total_0})")
            print(f"     Clase 1 exclusiva: {coverage_pct_1:.1f}% ({exclusive_coverage_1}/{total_1})")

            if coverage_pct_0 > 50 or coverage_pct_1 > 50:
                print(f"   🚨 FEATURE PROBLEMÁTICA: {col} permite separación perfecta!")

    # 2. ANÁLISIS DE FEATURES NUMÉRICAS RESTANTES
    print(f"\n2. ANÁLISIS DETALLADO DE FEATURES NUMÉRICAS")
    print("-" * 50)

    for col in numeric_cols:
        print(f"\n🔍 Analizando {col}:")

        # Estadísticas por clase
        class_stats = df.groupby(target_column)[col].agg(['count', 'mean', 'std', 'min', 'max', 'nunique'])
        print(f"   📊 Estadísticas por clase:")
        for label in class_stats.index:
            stats = class_stats.loc[label]
            print(f"     Clase {label}: mean={stats['mean']:.3f}, std={stats['std']:.3f}, únicos={stats['nunique']}")

        # Calcular separación
        if len(class_stats) == 2:
            means = class_stats['mean'].values
            stds = class_stats['std'].values
            mean_diff = abs(means[1] - means[0])
            pooled_std = np.sqrt(np.mean(stds ** 2))

            if pooled_std > 0:
                separation_ratio = mean_diff / pooled_std
                print(f"   📏 Separación: {separation_ratio:.1f} std deviations")

                if separation_ratio > 5:
                    print(f"   🚨 SEPARACIÓN EXTREMA DETECTADA!")

        # Verificar separabilidad perfecta restante
        if df[col].nunique() < len(df) * 0.8:  # Solo si no es muy disperso
            value_class_counts = df.groupby(col)[target_column].nunique()
            perfect_values = value_class_counts[value_class_counts == 1].index

            if len(perfect_values) > 0:
                perfect_rows = df[df[col].isin(perfect_values)]
                coverage = len(perfect_rows) / len(df)
                print(f"   🎯 Separabilidad perfecta restante: {coverage:.1%}")

                if coverage > 0.1:
                    print(f"   🚨 FEATURE AÚN PROBLEMÁTICA: {col}")

    # 3. ANÁLISIS DE COMBINACIONES
    print(f"\n3. ANÁLISIS DE COMBINACIONES DE FEATURES")
    print("-" * 50)

    # Verificar si combinaciones de 2 features pueden separar perfectamente
    all_features = numeric_cols + categorical_cols

    if len(all_features) >= 2:
        print(f"🔍 Verificando combinaciones de 2 features...")

        perfect_combinations = []

        for i, feat1 in enumerate(all_features[:5]):  # Limitar para no saturar
            for feat2 in all_features[i + 1:6]:

                # Crear combinación
                df['combo'] = df[feat1].astype(str) + "_" + df[feat2].astype(str)

                # Verificar separabilidad
                combo_class_counts = df.groupby('combo')[target_column].nunique()
                perfect_combos = combo_class_counts[combo_class_counts == 1].index

                if len(perfect_combos) > 0:
                    perfect_rows = df[df['combo'].isin(perfect_combos)]
                    coverage = len(perfect_rows) / len(df)

                    if coverage > 0.2:  # Si >20% es predecible perfectamente
                        perfect_combinations.append({
                            'features': (feat1, feat2),
                            'coverage': coverage,
                            'perfect_values': len(perfect_combos)
                        })

        # Limpiar columna temporal
        df.drop('combo', axis=1, inplace=True)

        if perfect_combinations:
            print(f"🚨 COMBINACIONES PROBLEMÁTICAS ENCONTRADAS:")
            for combo in sorted(perfect_combinations, key=lambda x: x['coverage'], reverse=True)[:3]:
                feat1, feat2 = combo['features']
                print(f"   {feat1} + {feat2}: {combo['coverage']:.1%} predecible perfectamente")
        else:
            print(f"✅ No se encontraron combinaciones problemáticas obvias")

    # 4. RECOMENDACIONES FINALES
    print(f"\n4. RECOMENDACIONES ESPECÍFICAS")
    print("-" * 50)

    recommendations = []

    # Evaluar features categóricas
    for col in categorical_cols:
        class_value_counts = {}
        for label in df[target_column].unique():
            class_df = df[df[target_column] == label]
            class_value_counts[label] = set(class_df[col].unique())

        if len(class_value_counts) == 2:
            exclusive_0 = class_value_counts[0] - class_value_counts[1]
            exclusive_1 = class_value_counts[1] - class_value_counts[0]

            if len(exclusive_0) > 0 or len(exclusive_1) > 0:
                recommendations.append(f"🗑️ ELIMINAR: {col} (valores exclusivos por clase)")

    # Evaluar features numéricas
    for col in numeric_cols:
        class_stats = df.groupby(target_column)[col].agg(['mean', 'std'])
        if len(class_stats) == 2:
            means = class_stats['mean'].values
            stds = class_stats['std'].values
            mean_diff = abs(means[1] - means[0])
            pooled_std = np.sqrt(np.mean(stds ** 2))

            if pooled_std > 0:
                separation_ratio = mean_diff / pooled_std
                if separation_ratio > 10:
                    recommendations.append(f"🗑️ ELIMINAR: {col} (separación extrema: {separation_ratio:.1f})")
                elif separation_ratio > 5:
                    recommendations.append(f"🎲 AGREGAR RUIDO: {col} (separación alta: {separation_ratio:.1f})")

    if recommendations:
        print(f"💡 ACCIONES RECOMENDADAS:")
        for rec in recommendations[:5]:  # Top 5
            print(f"   {rec}")

        print(f"\n🔧 COMANDO SUGERIDO:")
        print(f"   Usar método 'aggressive' con más parámetros restrictivos")

    else:
        print(f"❓ No se detectaron problemas obvios - posible problema conceptual")
        print(f"💡 Considera:")
        print(f"   • Los datos pueden ser fundamentalmente incompatibles")
        print(f"   • Usar solo una fuente de datos (solo UNSW-NB15)")
        print(f"   • Crear ataques sintéticos más realistas")

    return {
        'numeric_features': numeric_cols,
        'categorical_features': categorical_cols,
        'recommendations': recommendations
    }


def main():
    parser = argparse.ArgumentParser(description='Analizar Features Restantes Después de Limpieza')
    parser.add_argument('--dataset', required=True, help='Dataset CSV limpio a analizar')
    parser.add_argument('--target_column', default='label', help='Columna objetivo')

    args = parser.parse_args()

    analyze_remaining_features(args.dataset, args.target_column)


if __name__ == "__main__":
    main()