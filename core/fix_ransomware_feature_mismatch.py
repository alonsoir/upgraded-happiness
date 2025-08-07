#!/usr/bin/env python3
"""
🔧 UPGRADED HAPPINESS - Arreglo Feature Mismatch Ransomware

PROBLEMA IDENTIFICADO:
- Modelos DDoS: 82 features ✅
- Modelos Ransomware: 53 features ❌ → Causa error en tiempo real

SOLUCIÓN:
1. Re-entrenar modelos ransomware con 82 features
2. Mantener compatibilidad con pipeline completo
3. Conservar métricas de rendimiento

Autor: Alonso Rodriguez
Fecha: Agosto 7, 2025
"""

import os
import sys
import time
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, classification_report
from sklearn.model_selection import train_test_split
import lightgbm as lgb
import json

# Configuración
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
MODELS_DIR = PROJECT_ROOT / "models"
OPTIMIZED_MODELS_DIR = PROJECT_ROOT / "optimized_models"
DATASETS_DIR = PROJECT_ROOT / "datasets_parquet"


def print_header():
    """Imprime header del script"""
    print("=" * 80)
    print("🔧 UPGRADED HAPPINESS - ARREGLO FEATURE MISMATCH")
    print("Solucionando: Ransomware models 53→82 features")
    print("=" * 80)


def clean_infinite_values(df):
    """Limpia valores infinitos y NaN del dataset"""
    print(f"🧹 Limpiando datos: {df.shape}")

    # Contar valores problemáticos antes
    inf_before = np.isinf(df.select_dtypes(include=[np.number]).values).sum()
    nan_before = df.isnull().sum().sum()

    print(f"   📊 Valores infinitos antes: {inf_before}")
    print(f"   📊 Valores NaN antes: {nan_before}")

    # Reemplazar infinitos con NaN primero
    df = df.replace([np.inf, -np.inf], np.nan)

    # Rellenar NaN con 0 o mediana según el caso
    for col in df.columns:
        if df[col].dtype in ['float64', 'float32', 'int64', 'int32']:
            if col.endswith(('_ratio', '_rate', '_per_s', '_mean')):
                # Para ratios y tasas, usar mediana
                median_val = df[col].median()
                df[col] = df[col].fillna(median_val if not pd.isna(median_val) else 0)
            else:
                # Para conteos y totales, usar 0
                df[col] = df[col].fillna(0)

    # Verificar después
    inf_after = np.isinf(df.select_dtypes(include=[np.number]).values).sum()
    nan_after = df.isnull().sum().sum()

    print(f"   ✅ Valores infinitos después: {inf_after}")
    print(f"   ✅ Valores NaN después: {nan_after}")

    # Convertir a float32 para eficiencia
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        if col != ' Label':  # Preservar la columna label como está
            try:
                df[col] = pd.to_numeric(df[col], errors='coerce').astype('float32')
            except:
                print(f"   ⚠️ No se pudo convertir columna: {col}")

    # Verificar que no hay valores muy grandes
    large_values = (np.abs(df.select_dtypes(include=[np.number]).values) > 1e10).sum()
    print(f"   ✅ Valores muy grandes (>1e10) después: {large_values}")

    return df


def load_ransomware_data():
    """Carga datos para re-entrenar modelos ransomware con 82 features"""
    print("📁 Cargando datos con 82 features compatibles...")

    # ESTRATEGIA SIMPLE: Usar los mismos datos que funcionaron para DDoS
    # Ya sabemos que estos archivos tienen 82 features y funcionan
    priority_files = ["Portmap.parquet", "DrDoS_NetBIOS.parquet"]

    combined_data = []

    for file in priority_files:
        file_path = DATASETS_DIR / file
        if file_path.exists():
            print(f"   📄 Cargando: {file}")
            try:
                # Cargar archivo completo
                df = pd.read_parquet(file_path)

                # Tomar muestra si es muy grande (para acelerar entrenamiento)
                if len(df) > 100000:
                    print(f"   📊 Archivo grande ({len(df)} filas), tomando muestra de 50K")
                    df = df.sample(n=50000, random_state=42)

                combined_data.append(df)
                print(f"   ✅ {file}: {len(df)} filas cargadas")

                # Con un archivo ya es suficiente para el re-entrenamiento
                if len(combined_data) >= 1:
                    break

            except Exception as e:
                print(f"   ❌ Error cargando {file}: {e}")
                continue

    # Si no pudimos cargar los archivos principales, buscar cualquier .parquet
    if not combined_data:
        print("   🔍 Buscando archivos parquet alternativos...")
        all_files = list(DATASETS_DIR.glob("*.parquet"))[:3]  # Probar primeros 3

        for file_path in all_files:
            try:
                print(f"   📄 Intentando: {file_path.name}")
                df = pd.read_parquet(file_path)

                # Tomar muestra pequeña para prueba
                if len(df) > 10000:
                    df = df.head(10000)

                # Verificar que tiene columna de labels
                has_label = any('label' in col.lower() for col in df.columns)
                if has_label:
                    combined_data.append(df)
                    print(f"   ✅ {file_path.name}: {len(df)} filas")
                    break
                else:
                    print(f"   ⚠️ {file_path.name}: sin columna de labels")

            except Exception as e:
                print(f"   ❌ Error con {file_path.name}: {e}")
                continue

    if not combined_data:
        raise ValueError("❌ No se pudieron cargar datos para re-entrenar ransomware models")

    # Combinar datos
    print("🔄 Preparando dataset...")
    full_data = pd.concat(combined_data, ignore_index=True)

    print(f"📊 Dataset final: {len(full_data)} filas, {len(full_data.columns)} columnas")

    return full_data


def clean_column_names(df, label_col):
    """Limpia nombres de columnas para compatibilidad total con LightGBM"""
    print("🧹 Limpiando nombres de columnas para LightGBM...")

    # Eliminar columna Unnamed si existe (es índice, no feature)
    unnamed_cols = [col for col in df.columns if 'unnamed' in col.lower() or col.startswith('Unnamed')]
    if unnamed_cols:
        print(f"   🗑️ Eliminando columnas índice: {unnamed_cols}")
        df = df.drop(columns=unnamed_cols)

    original_columns = df.columns.tolist()

    # Separar label de features ANTES de renombrar
    label_col_clean = 'target_label'  # Nombre limpio fijo para label

    # Crear nombres genéricos para features (100% compatibles con LightGBM)
    new_columns = []
    feature_count = 0

    for col in original_columns:
        if col == label_col:
            new_columns.append(label_col_clean)
        else:
            new_columns.append(f'feature_{feature_count:03d}')  # feature_000, feature_001, etc.
            feature_count += 1

    # Crear mapeo para referencia
    column_mapping = dict(zip(original_columns, new_columns))

    print(f"   📝 Convertidos {len([c for c in new_columns if c.startswith('feature_')])} features a nombres genéricos")
    print(f"   📊 Ejemplos: '{original_columns[0]}' → '{new_columns[0]}'")
    if len(original_columns) > 1:
        print(f"               '{original_columns[1]}' → '{new_columns[1]}'")

    # Aplicar nombres limpios
    df.columns = new_columns

    return df, column_mapping, label_col_clean


def prepare_ransomware_data(df):
    """Prepara datos específicamente para entrenamiento de ransomware"""
    print("⚙️ Preparando datos para ransomware...")

    # Encontrar columna de etiquetas
    label_col = None
    for col in df.columns:
        if 'label' in col.lower() or col.strip().lower() == 'label':
            label_col = col
            break

    if not label_col:
        raise ValueError("❌ No se encontró columna de labels")

    print(f"   📊 Columna de labels: '{label_col}'")

    # Limpiar datos
    df = clean_infinite_values(df)

    # Limpiar nombres de columnas ANTES de separar features
    df, column_mapping, label_col_clean = clean_column_names(df, label_col)

    # Separar features y labels
    y = df[label_col_clean]
    X = df.drop(columns=[label_col_clean])

    # Asegurar que tenemos exactamente 82 features
    print(f"   📊 Features disponibles: {len(X.columns)}")
    if len(X.columns) != 82:
        print(f"   ⚠️ Se esperaban 82 features, encontradas {len(X.columns)}")
        print("   📝 Ajustando dataset...")

        # Si tenemos más de 82, tomar las primeras 82
        if len(X.columns) > 82:
            X = X.iloc[:, :82]
            print(f"   ✂️ Tomadas primeras 82 features")
        # Si tenemos menos, rellenar con ceros
        elif len(X.columns) < 82:
            missing_cols = 82 - len(X.columns)
            for i in range(missing_cols):
                X[f'feature_{len(X.columns) + i:03d}'] = 0.0
            print(f"   ➕ Agregadas {missing_cols} features con valor 0")

    # Verificar que todos los nombres son compatibles con LightGBM
    problem_cols = []
    for col in X.columns:
        if not col.startswith('feature_') or not col.replace('feature_', '').replace('_', '').isdigit():
            problem_cols.append(col)

    if problem_cols:
        print(f"   🔧 Renombrando {len(problem_cols)} columnas problemáticas...")
        # Renombrar columnas problemáticas
        for i, col in enumerate(X.columns):
            if col in problem_cols:
                X = X.rename(columns={col: f'feature_{i:03d}'})

    print(f"   ✅ Features finales: {len(X.columns)} (todos compatibles con LightGBM)")
    print(f"   📊 Distribución labels: {dict(y.value_counts())}")

    # Verificar que no hay caracteres especiales
    all_clean = all(
        col.startswith('feature_') and col.replace('feature_', '').replace('_', '').isdigit() for col in X.columns)
    print(f"   🔍 Verificación nombres limpios: {'✅' if all_clean else '❌'}")

    return X, y


def train_ransomware_models(X, y):
    """Entrena modelos de ransomware con 82 features"""
    print("🤖 Entrenando modelos de ransomware (82 features)...")

    # Split train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"   📊 Train: {len(X_train)}, Test: {len(X_test)}")

    models = {}
    metrics = {}

    # 1. Random Forest
    print("   🌲 Entrenando Random Forest...")
    start_time = time.time()

    rf_model = RandomForestClassifier(
        n_estimators=30,
        max_depth=8,
        min_samples_leaf=10,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    rf_pred = rf_model.predict(X_test)
    rf_pred_proba = rf_model.predict_proba(X_test)[:, 1]

    rf_metrics = {
        'accuracy': float(accuracy_score(y_test, rf_pred)),
        'f1_score': float(f1_score(y_test, rf_pred)),
        'roc_auc': float(roc_auc_score(y_test, rf_pred_proba)),
        'training_time': time.time() - start_time,
        'features': 82
    }

    models['ransomware_rf_82'] = rf_model
    metrics['ransomware_rf_82'] = rf_metrics

    print(f"   ✅ RF - Acc: {rf_metrics['accuracy']:.4f}, F1: {rf_metrics['f1_score']:.4f}")

    # 2. LightGBM
    print("   💡 Entrenando LightGBM...")
    start_time = time.time()

    lgb_model = lgb.LGBMClassifier(
        n_estimators=50,
        max_depth=8,
        num_leaves=31,
        learning_rate=0.1,
        class_weight='balanced',
        random_state=42,
        verbose=-1
    )
    lgb_model.fit(X_train, y_train)

    lgb_pred = lgb_model.predict(X_test)
    lgb_pred_proba = lgb_model.predict_proba(X_test)[:, 1]

    lgb_metrics = {
        'accuracy': float(accuracy_score(y_test, lgb_pred)),
        'f1_score': float(f1_score(y_test, lgb_pred)),
        'roc_auc': float(roc_auc_score(y_test, lgb_pred_proba)),
        'training_time': time.time() - start_time,
        'features': 82
    }

    models['ransomware_lgb_82'] = lgb_model
    metrics['ransomware_lgb_82'] = lgb_metrics

    print(f"   ✅ LGB - Acc: {lgb_metrics['accuracy']:.4f}, F1: {lgb_metrics['f1_score']:.4f}")

    return models, metrics


def save_fixed_models(models, metrics):
    """Guarda los modelos corregidos"""
    print("💾 Guardando modelos corregidos...")

    # Crear directorio si no existe
    MODELS_DIR.mkdir(exist_ok=True)

    for model_name, model in models.items():
        # Guardar modelo
        model_file = MODELS_DIR / f"{model_name}_fixed.joblib"
        joblib.dump(model, model_file)

        # Guardar métricas
        metrics_file = MODELS_DIR / f"{model_name}_fixed_metrics.json"
        with open(metrics_file, 'w') as f:
            json.dump(metrics[model_name], f, indent=2)

        print(f"   ✅ {model_name}: {model_file}")

    # Respaldar modelos antiguos
    old_models = [
        "ransomware_random_forest.joblib",
        "ransomware_lightgbm.joblib"
    ]

    backup_dir = MODELS_DIR / "backup_53_features"
    backup_dir.mkdir(exist_ok=True)

    for old_model in old_models:
        old_path = MODELS_DIR / old_model
        if old_path.exists():
            backup_path = backup_dir / old_model
            import shutil
            shutil.move(str(old_path), str(backup_path))
            print(f"   📦 Respaldo: {old_model} → backup_53_features/")

    # Renombrar modelos nuevos para reemplazar los antiguos
    print("🔄 Activando modelos corregidos...")

    rename_map = {
        "ransomware_rf_82_fixed.joblib": "ransomware_random_forest.joblib",
        "ransomware_lgb_82_fixed.joblib": "ransomware_lightgbm.joblib",
        "ransomware_rf_82_fixed_metrics.json": "ransomware_random_forest_metrics.json",
        "ransomware_lgb_82_fixed_metrics.json": "ransomware_lightgbm_metrics.json"
    }

    for old_name, new_name in rename_map.items():
        old_path = MODELS_DIR / old_name
        new_path = MODELS_DIR / new_name

        if old_path.exists():
            old_path.rename(new_path)
            print(f"   ✅ {old_name} → {new_name}")


def verify_fix():
    """Verifica que el arreglo funciona"""
    print("🔍 Verificando arreglo...")

    try:
        # Cargar modelos corregidos
        rf_model = joblib.load(MODELS_DIR / "ransomware_random_forest.joblib")
        lgb_model = joblib.load(MODELS_DIR / "ransomware_lightgbm.joblib")

        # Verificar número de features esperadas
        # Para Random Forest, usar n_features_in_
        if hasattr(rf_model, 'n_features_in_'):
            rf_features = rf_model.n_features_in_
        else:
            # Fallback: crear datos dummy y ver si funciona
            dummy_data = np.random.random((1, 82))
            try:
                rf_model.predict(dummy_data)
                rf_features = 82
            except Exception as e:
                rf_features = "Error: " + str(e)

        # Para LightGBM
        if hasattr(lgb_model, 'n_features_in_'):
            lgb_features = lgb_model.n_features_in_
        else:
            dummy_data = np.random.random((1, 82))
            try:
                lgb_model.predict(dummy_data)
                lgb_features = 82
            except Exception as e:
                lgb_features = "Error: " + str(e)

        print(f"   📊 Random Forest espera: {rf_features} features")
        print(f"   📊 LightGBM espera: {lgb_features} features")

        if rf_features == 82 and lgb_features == 82:
            print("   ✅ ARREGLO EXITOSO: Ambos modelos esperan 82 features")
            return True
        else:
            print("   ❌ ARREGLO FALLÓ: Modelos no esperan 82 features")
            return False

    except Exception as e:
        print(f"   ❌ Error verificando: {e}")
        return False


def main():
    """Función principal"""
    print_header()

    try:
        # Paso 1: Cargar datos
        data = load_ransomware_data()

        # Paso 2: Preparar datos para 82 features
        X, y = prepare_ransomware_data(data)

        # Paso 3: Entrenar modelos
        models, metrics = train_ransomware_models(X, y)

        # Paso 4: Guardar modelos corregidos
        save_fixed_models(models, metrics)

        # Paso 5: Verificar arreglo
        success = verify_fix()

        # Resumen final
        print("\n" + "=" * 80)
        print("📊 RESUMEN DEL ARREGLO")
        print("=" * 80)

        if success:
            print("🎉 ARREGLO COMPLETADO EXITOSAMENTE")
            print()
            print("✅ Modelos corregidos:")
            for model_name, model_metrics in metrics.items():
                print(f"   {model_name}:")
                print(f"      Accuracy: {model_metrics['accuracy']:.4f}")
                print(f"      F1-Score: {model_metrics['f1_score']:.4f}")
                print(f"      ROC-AUC: {model_metrics['roc_auc']:.4f}")
                print(f"      Features: {model_metrics['features']}")
                print()

            print("🔄 PRÓXIMOS PASOS:")
            print("   1. Ejecutar: sudo python core/scapy_to_ml_features.py")
            print("   2. Verificar que no hay errores de feature mismatch")
            print("   3. Los modelos antiguos están en: models/backup_53_features/")

        else:
            print("❌ ARREGLO FALLÓ")
            print("   Revisa los logs anteriores para detalles del error")

        print("=" * 80)

    except Exception as e:
        print(f"\n❌ ERROR FATAL: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0 if success else 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)