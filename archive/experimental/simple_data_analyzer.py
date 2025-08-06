#!/usr/bin/env python3
"""
ANALIZADOR SIMPLE DE CALIDAD DE DATOS
Sin dependencias complejas, solo pandas y numpy
"""

import pandas as pd
import numpy as np
import sys
import os


def analyze_basic_quality(csv_path, target_column='label'):
    """
    Análisis básico de calidad de datos
    """
    print(f"🔍 ANÁLISIS DE CALIDAD: {os.path.basename(csv_path)}")
    print("=" * 60)

    # Cargar datos
    try:
        df = pd.read_csv(csv_path)
        print(f"📊 Dataset cargado: {len(df):,} registros, {len(df.columns)} columnas")
    except Exception as e:
        print(f"❌ Error cargando dataset: {e}")
        return None

    # 1. DISTRIBUCIÓN DE ETIQUETAS
    print(f"\n1. DISTRIBUCIÓN DE ETIQUETAS")
    print("-" * 30)

    if target_column not in df.columns:
        print(f"❌ Columna '{target_column}' no encontrada")
        print(f"Columnas disponibles: {list(df.columns)}")
        return None

    label_dist = df[target_column].value_counts().sort_index()
    total = len(df)

    print(f"📋 Distribución de etiquetas:")
    for label, count in label_dist.items():
        pct = (count / total) * 100
        print(f"   Clase {label}: {count:,} ({pct:.1f}%)")

    # Balance ratio
    balance_ratio = label_dist.min() / label_dist.max()
    print(f"⚖️ Balance ratio: {balance_ratio:.3f}")

    if balance_ratio > 0.9:
        print(f"🚨 ALERTA: Dataset extremadamente balanceado - posible artificial")
    elif balance_ratio < 0.1:
        print(f"⚠️ Dataset muy desbalanceado")

    # 2. ANÁLISIS DE DUPLICADOS
    print(f"\n2. ANÁLISIS DE DUPLICADOS")
    print("-" * 30)

    # Duplicados completos
    total_duplicates = df.duplicated().sum()
    dup_pct = (total_duplicates / total) * 100
    print(f"🔄 Filas completamente duplicadas: {total_duplicates:,} ({dup_pct:.1f}%)")

    if total_duplicates > 0:
        # Duplicados por clase
        dup_by_class = df[df.duplicated()].groupby(target_column).size()
        print(f"📊 Duplicados por clase:")
        for label, count in dup_by_class.items():
            print(f"   Clase {label}: {count:,}")

    # Duplicados de features (sin considerar label)
    features_only = df.drop(columns=[target_column])
    feature_duplicates = features_only.duplicated().sum()
    feat_dup_pct = (feature_duplicates / total) * 100
    print(f"🔄 Features duplicadas (diferente label): {feature_duplicates:,} ({feat_dup_pct:.1f}%)")

    # CRÍTICO: Features idénticas con labels diferentes
    conflicting_groups = 0  # Inicializar la variable

    if feature_duplicates > 0:
        print(f"🔍 Verificando conflictos de etiquetas...")

        # Encontrar grupos de features duplicadas
        dup_mask = features_only.duplicated(keep=False)
        dup_groups = df[dup_mask].groupby(features_only.columns.tolist())

        conflict_examples = []

        for group_key, group_df in dup_groups:
            unique_labels = group_df[target_column].nunique()
            if unique_labels > 1:
                conflicting_groups += 1
                if len(conflict_examples) < 3:  # Solo mostrar 3 ejemplos
                    labels_in_group = group_df[target_column].value_counts()
                    conflict_examples.append({
                        'group_size': len(group_df),
                        'labels': dict(labels_in_group)
                    })

        if conflicting_groups > 0:
            print(f"🚨 PROBLEMA CRÍTICO: {conflicting_groups} grupos con features idénticas pero labels diferentes")
            print(f"📋 Ejemplos de conflictos:")
            for i, example in enumerate(conflict_examples, 1):
                print(f"   Grupo {i}: {example['group_size']} filas con labels {example['labels']}")
            print(f"   ⚠️ Esto causa inconsistencias y puede generar overfitting")
        else:
            print(f"✅ No hay conflictos de etiquetas en features duplicadas")

    # 3. ANÁLISIS DE FEATURES NUMÉRICAS
    print(f"\n3. ANÁLISIS DE FEATURES NUMÉRICAS")
    print("-" * 30)

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if target_column in numeric_cols:
        numeric_cols.remove(target_column)

    print(f"🔢 Features numéricas: {len(numeric_cols)}")

    # Valores faltantes
    missing_total = 0
    missing_features = []

    for col in numeric_cols:
        missing_count = df[col].isnull().sum()
        if missing_count > 0:
            missing_total += missing_count
            pct = (missing_count / total) * 100
            missing_features.append(f"   {col}: {missing_count:,} ({pct:.1f}%)")

    if missing_features:
        print(f"❗ Features con valores faltantes:")
        for feature_info in missing_features[:10]:  # Mostrar solo primeros 10
            print(feature_info)
        if len(missing_features) > 10:
            print(f"   ... y {len(missing_features) - 10} más")
    else:
        print(f"✅ No hay valores faltantes")

    # Valores infinitos
    inf_features = []
    for col in numeric_cols:
        inf_count = np.isinf(df[col]).sum()
        if inf_count > 0:
            inf_features.append(f"   {col}: {inf_count:,}")

    if inf_features:
        print(f"❗ Features con valores infinitos:")
        for feature_info in inf_features[:10]:
            print(feature_info)
    else:
        print(f"✅ No hay valores infinitos")

    # Features constantes
    constant_features = []
    for col in numeric_cols:
        if df[col].nunique() <= 1:
            unique_val = df[col].iloc[0] if len(df) > 0 else 'N/A'
            constant_features.append(f"   {col}: {unique_val}")

    if constant_features:
        print(f"⚠️ Features constantes: {len(constant_features)}")
        for feature_info in constant_features[:5]:
            print(feature_info)
    else:
        print(f"✅ No hay features constantes")

    # 4. ANÁLISIS DE SEPARABILIDAD PERFECTA
    print(f"\n4. ANÁLISIS DE SEPARABILIDAD PERFECTA")
    print("-" * 30)

    perfect_separators = []

    print(f"🔍 Verificando separabilidad por feature...")

    for col in numeric_cols[:20]:  # Limitar a 20 features para no saturar
        if df[col].nunique() > 1 and df[col].nunique() < len(df) * 0.8:  # Skip muy dispersos

            # Para cada valor único, ver si predice solo una clase
            value_class_counts = df.groupby(col)[target_column].nunique()
            perfect_values = value_class_counts[value_class_counts == 1].index

            if len(perfect_values) > 0:
                # Calcular coverage
                perfect_rows = df[df[col].isin(perfect_values)]
                coverage = len(perfect_rows) / total

                if coverage > 0.05:  # Si predice >5% perfectamente
                    perfect_separators.append({
                        'feature': col,
                        'coverage': coverage,
                        'perfect_values': len(perfect_values),
                        'total_unique': df[col].nunique()
                    })

    if perfect_separators:
        print(f"🚨 ALERTA CRÍTICA: Features con separabilidad perfecta detectadas!")
        for sep in sorted(perfect_separators, key=lambda x: x['coverage'], reverse=True)[:5]:
            coverage_pct = sep['coverage'] * 100
            print(f"   {sep['feature']}: {coverage_pct:.1f}% de datos predecible perfectamente")
            print(f"     ({sep['perfect_values']}/{sep['total_unique']} valores únicos son predictores perfectos)")
        print(f"   🎯 Causa probable del 100% de accuracy!")
        print(f"   💡 Solución: Eliminar estas features o agregar ruido")
    else:
        print(f"✅ No se detectaron separadores perfectos obvios")

    # 5. ANÁLISIS DE DISTRIBUCIONES POR CLASE
    print(f"\n5. ANÁLISIS DE DISTRIBUCIONES POR CLASE")
    print("-" * 30)

    print(f"🔍 Analizando diferencias entre clases en features numéricas...")

    # Seleccionar algunas features para análisis
    sample_features = numeric_cols[:10]  # Primeras 10

    extreme_differences = []

    for col in sample_features:
        if df[col].nunique() > 1:
            class_stats = df.groupby(target_column)[col].agg(['mean', 'std', 'min', 'max'])

            # Calcular separación entre clases
            means = class_stats['mean'].values
            if len(means) == 2:  # Solo para clasificación binaria
                mean_diff = abs(means[1] - means[0])
                pooled_std = np.sqrt(class_stats['std'].mean())  # Std promedio

                if pooled_std > 0:
                    separation_ratio = mean_diff / pooled_std
                    if separation_ratio > 3:  # Muy separadas (>3 std deviations)
                        extreme_differences.append({
                            'feature': col,
                            'separation': separation_ratio,
                            'class_means': means
                        })

    if extreme_differences:
        print(f"🚨 Features con separación extrema entre clases:")
        for diff in sorted(extreme_differences, key=lambda x: x['separation'], reverse=True)[:5]:
            print(f"   {diff['feature']}: separación = {diff['separation']:.1f} std deviations")
            print(f"     Medias por clase: {diff['class_means']}")
        print(f"   ⚠️ Separación extrema puede causar overfitting")
    else:
        print(f"✅ No se detectó separación extrema entre clases")

    # 6. RESUMEN FINAL
    print(f"\n6. DIAGNÓSTICO FINAL")
    print("-" * 30)

    issues = []
    severity_score = 0

    # Evaluar problemas
    if conflicting_groups > 0:
        issues.append("🚨 CRÍTICO: Features idénticas con labels diferentes")
        severity_score += 10

    if len(perfect_separators) > 0:
        issues.append("🚨 CRÍTICO: Features con separabilidad perfecta")
        severity_score += 10

    if len(extreme_differences) > 3:
        issues.append("⚠️ ALTO: Múltiples features con separación extrema")
        severity_score += 5

    if total_duplicates > total * 0.1:
        issues.append("⚠️ MEDIO: Alto porcentaje de duplicados")
        severity_score += 3

    if balance_ratio > 0.95:
        issues.append("⚠️ MEDIO: Dataset artificialmente balanceado")
        severity_score += 2

    if len(constant_features) > 0:
        issues.append("⚠️ BAJO: Features constantes detectadas")
        severity_score += 1

    print(f"📊 PUNTUACIÓN DE RIESGO DE OVERFITTING: {severity_score}/30")

    if severity_score >= 15:
        print(f"🚨 RIESGO CRÍTICO - Overfitting prácticamente garantizado")
    elif severity_score >= 8:
        print(f"⚠️ RIESGO ALTO - Overfitting muy probable")
    elif severity_score >= 3:
        print(f"💡 RIESGO MEDIO - Requiere precauciones")
    else:
        print(f"✅ RIESGO BAJO - Dataset relativamente limpio")

    if issues:
        print(f"\n🔧 PROBLEMAS IDENTIFICADOS:")
        for issue in issues:
            print(f"   {issue}")

        print(f"\n💡 RECOMENDACIONES ESPECÍFICAS:")
        if severity_score >= 10:
            print(f"   1. 🚫 NO usar este dataset sin correcciones")
            print(f"   2. 🔧 Eliminar features con separabilidad perfecta")
            print(f"   3. 🎲 Agregar ruido realista a los datos")
            print(f"   4. 🔄 Recrear dataset con técnicas más conservadoras")
        elif severity_score >= 5:
            print(f"   1. 📉 Usar parámetros muy conservadores en RF")
            print(f"   2. ✂️ Eliminar features problemáticas")
            print(f"   3. 🎯 Implementar validación cruzada estricta")
        else:
            print(f"   1. 📊 Usar validación cruzada")
            print(f"   2. 🎯 Monitorear métricas de overfitting")

    return {
        'total_records': total,
        'label_distribution': dict(label_dist),
        'balance_ratio': balance_ratio,
        'duplicates': total_duplicates,
        'perfect_separators': len(perfect_separators),
        'severity_score': severity_score,
        'issues': issues
    }


def compare_datasets(dataset_paths, names=None):
    """Compara múltiples datasets"""
    if names is None:
        names = [f"Dataset_{i + 1}" for i in range(len(dataset_paths))]

    print(f"\n🔄 COMPARACIÓN DE MÚLTIPLES DATASETS")
    print("=" * 80)

    results = {}
    for path, name in zip(dataset_paths, names):
        print(f"\n{'=' * 20} {name} {'=' * 20}")
        result = analyze_basic_quality(path)
        if result:
            results[name] = result

    # Tabla comparativa
    if len(results) > 1:
        print(f"\n📊 TABLA COMPARATIVA")
        print("=" * 80)

        # Headers
        print(f"{'Métrica':<25}", end="")
        for name in results.keys():
            print(f"{name:<20}", end="")
        print()
        print("-" * (25 + 20 * len(results)))

        # Filas de datos
        metrics = [
            ('Registros', 'total_records', ''),
            ('Balance Ratio', 'balance_ratio', '.3f'),
            ('Duplicados', 'duplicates', ''),
            ('Separadores Perfect.', 'perfect_separators', ''),
            ('Puntuación Riesgo', 'severity_score', ''),
        ]

        for metric_name, key, fmt in metrics:
            print(f"{metric_name:<25}", end="")
            for name, result in results.items():
                value = result.get(key, 'N/A')
                if fmt and isinstance(value, (int, float)):
                    if fmt == '.3f':
                        print(f"{value:<20.3f}", end="")
                    else:
                        print(f"{value:<20}", end="")
                else:
                    print(f"{str(value):<20}", end="")
            print()

        print()

        # Encontrar el dataset más problemático
        max_severity = max((r.get('severity_score', 0) for r in results.values()))
        worst_datasets = [name for name, r in results.items()
                          if r.get('severity_score', 0) == max_severity]

        print(f"🎯 DATASET MÁS PROBLEMÁTICO: {', '.join(worst_datasets)} (score: {max_severity})")

        # Recomendación general
        if max_severity >= 15:
            print(f"🚨 RECOMENDACIÓN: Ningún dataset es seguro para entrenar sin correcciones")
        elif max_severity >= 8:
            print(f"⚠️ RECOMENDACIÓN: Usar solo datasets con score < 8, aplicar correcciones a los demás")
        else:
            print(f"✅ RECOMENDACIÓN: Los datasets son relativamente seguros para entrenar")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Analizador Simple de Calidad de Datos')
    parser.add_argument('--datasets', nargs='+', required=True,
                        help='Rutas de datasets CSV a analizar')
    parser.add_argument('--names', nargs='+',
                        help='Nombres para los datasets')
    parser.add_argument('--target_column', default='label',
                        help='Nombre de la columna objetivo')

    args = parser.parse_args()

    if len(args.datasets) == 1:
        # Análisis de un solo dataset
        analyze_basic_quality(args.datasets[0], args.target_column)
    else:
        # Comparación de múltiples datasets
        compare_datasets(args.datasets, args.names)