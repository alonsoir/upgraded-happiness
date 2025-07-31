#!/usr/bin/env python3
"""
ADVANCED TRAINER FLEXIBLE - VERSIÓN MEJORADA CON BALANCEO INTELIGENTE
Resuelve los problemas de:
- Balanceo en datasets ya balanceados
- Manejo de valores NaN
- Overfitting con parámetros más conservadores
"""

import pandas as pd
import numpy as np
import argparse
import json
import joblib
import os
from pathlib import Path
from datetime import datetime
from collections import Counter
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from sklearn.impute import SimpleImputer
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline as ImbPipeline
import warnings

warnings.filterwarnings('ignore')


def load_and_validate_data(csv_path, max_rows=None):
    """Carga y valida el dataset"""
    print(f"📁 Cargando dataset: {csv_path}")

    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"No se encontró el archivo: {csv_path}")

    df = pd.read_csv(csv_path, nrows=max_rows)
    print(f"📊 Dataset cargado: {len(df):,} registros")

    # Validación básica
    if 'label' not in df.columns:
        raise ValueError("No se encontró la columna 'label' en el dataset")

    # Distribución de etiquetas
    label_dist = df['label'].value_counts().to_dict()
    print(f"📊 Distribución de etiquetas: {label_dist}")

    return df


def apply_smart_balancing(X, y, balance_threshold=0.15):
    """
    Aplica balanceo inteligente solo cuando es necesario
    """
    print(f"⚖️ Evaluando necesidad de balanceo...")

    # Manejar valores NaN primero
    nan_count = np.isnan(X).sum() if hasattr(X, 'sum') else np.isnan(X).sum()
    if nan_count > 0:
        print(f"🔧 Imputando {nan_count} valores NaN...")
        imputer = SimpleImputer(strategy='median')
        X = imputer.fit_transform(X)
        print(f"✅ Valores NaN imputados")

    # Verificar distribución
    distribution = Counter(y)
    print(f"📊 Distribución inicial: {dict(distribution)}")

    # Calcular ratio de balance
    values = list(distribution.values())
    min_count, max_count = min(values), max(values)
    balance_ratio = min_count / max_count

    print(f"📏 Ratio de balance: {balance_ratio:.3f}")

    # Si está balanceado, no hacer nada
    if balance_ratio >= (1 - balance_threshold):
        print(f"✅ Dataset suficientemente balanceado. Sin balanceo adicional.")
        return X, y

    # Aplicar balanceo gradual
    print(f"🔄 Aplicando balanceo gradual...")

    try:
        # Estrategia conservadora: solo SMOTE si hay mucho desbalance
        if balance_ratio < 0.5:
            # Muy desbalanceado - usar SMOTE + undersampling
            target_ratio = 0.7  # No perfectamente balanceado

            smote = SMOTE(
                random_state=42,
                sampling_strategy=target_ratio,
                k_neighbors=min(5, min_count - 1)
            )

            X_balanced, y_balanced = smote.fit_resample(X, y)

        else:
            # Ligeramente desbalanceado - solo SMOTE suave
            smote = SMOTE(
                random_state=42,
                sampling_strategy=0.8,  # No completamente balanceado
                k_neighbors=min(3, min_count - 1)
            )
            X_balanced, y_balanced = smote.fit_resample(X, y)

        final_distribution = Counter(y_balanced)
        print(f"📊 Distribución después de balanceo: {dict(final_distribution)}")
        return X_balanced, y_balanced

    except Exception as e:
        print(f"⚠️ Error en balanceo: {str(e)}")
        print(f"🔄 Continuando sin balanceo...")
        return X, y


def prepare_features_robust(df, target_column='label'):
    """Preparación robusta de features"""
    print(f"🔧 Preparando features...")

    # Separar target
    y = df[target_column].values
    X_df = df.drop(columns=[target_column])

    # Identificar tipos de columnas
    numeric_columns = X_df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_columns = X_df.select_dtypes(exclude=[np.number]).columns.tolist()

    print(f"🔢 Features numéricas: {len(numeric_columns)}")
    if categorical_columns:
        print(f"🔤 Codificando {len(categorical_columns)} columnas categóricas...")

    # Procesar features
    processed_X = X_df.copy()

    # Limpiar infinitos en numéricas
    if numeric_columns:
        for col in numeric_columns:
            processed_X[col] = processed_X[col].replace([np.inf, -np.inf], np.nan)

    # Codificar categóricas
    for col in categorical_columns:
        processed_X[col] = processed_X[col].fillna('unknown')
        le = LabelEncoder()
        processed_X[col] = le.fit_transform(processed_X[col].astype(str))

    # Convertir a numpy
    X = processed_X.values.astype(np.float32)

    print(f"✅ Features preparadas: X={X.shape}, y={len(y)}")

    return X, y, processed_X.columns.tolist()


def train_conservative_model(X_train, y_train):
    """Entrena modelo con parámetros conservadores para evitar overfitting"""
    print(f"🧠 Entrenando Random Forest conservador...")

    # Parámetros más conservadores
    rf = RandomForestClassifier(
        n_estimators=300,  # Reducido de 2000
        max_depth=20,  # Muy reducido de 120
        min_samples_split=20,  # Aumentado significativamente
        min_samples_leaf=10,  # Aumentado significativamente
        max_features='sqrt',  # Más conservador que 'log2'
        class_weight='balanced',  # Manejo interno de balance
        random_state=42,
        n_jobs=-1,
        oob_score=True,
        bootstrap=True,
        max_samples=0.8  # Usar solo 80% de datos en cada árbol
    )

    rf.fit(X_train, y_train)
    print(f"🎯 Modelo entrenado - OOB Score: {rf.oob_score_:.4f}")

    # Validación cruzada
    cv_scores = cross_val_score(rf, X_train, y_train, cv=3, scoring='accuracy')
    print(f"🔍 CV Scores promedio: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Alerta si hay overfitting potencial
    if rf.oob_score_ > 0.98:
        print(f"⚠️ ALERTA: OOB Score muy alto ({rf.oob_score_:.4f}) - Posible overfitting!")
        print(f"   Considera usar parámetros aún más conservadores")

    return rf


def comprehensive_evaluation(model, X_test, y_test, feature_names=None):
    """Evaluación comprehensiva del modelo"""
    print(f"📊 Evaluando modelo...")

    # Predicciones
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None

    # Métricas básicas
    print(f"\n[📊] Matriz de Confusión:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    print(f"\n[📋] Reporte de Clasificación:")
    print(classification_report(y_test, y_pred))

    # AUC si hay probabilidades
    if y_prob is not None:
        auc = roc_auc_score(y_test, y_prob)
        print(f"\n[📈] AUC-ROC: {auc:.4f}")

        # Alerta de overfitting
        if auc > 0.99:
            print(f"⚠️ ALERTA: AUC extremadamente alto ({auc:.4f}) - Probable overfitting!")

    # Feature importance
    if hasattr(model, 'feature_importances_') and feature_names:
        importances = model.feature_importances_
        feature_importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': importances
        }).sort_values('importance', ascending=False)

        print(f"\n[🔍] Top 10 Features más importantes:")
        for _, row in feature_importance_df.head(10).iterrows():
            print(f"   {row['feature']}: {row['importance']:.4f}")

    return {
        'confusion_matrix': cm,
        'auc_roc': auc if y_prob is not None else None,
        'predictions': y_pred,
        'probabilities': y_prob
    }


def save_model_artifacts(model, scaler, feature_names, metrics, output_path):
    """Guarda todos los artefactos del modelo"""
    print(f"💾 Guardando artefactos del modelo...")

    # Crear directorio si no existe
    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    # Guardar modelo
    joblib.dump(model, output_path)
    print(f"   ✅ Modelo: {output_path}")

    # Guardar scaler
    scaler_path = str(output_path).replace('.joblib', '_scaler.joblib')
    joblib.dump(scaler, scaler_path)
    print(f"   ✅ Scaler: {scaler_path}")

    # Guardar metadatos
    metadata = {
        'timestamp': datetime.now().isoformat(),
        'feature_names': feature_names,
        'model_params': model.get_params(),
        'oob_score': getattr(model, 'oob_score_', None),
        'metrics': {
            'auc_roc': metrics.get('auc_roc'),
            'confusion_matrix': metrics['confusion_matrix'].tolist()
        }
    }

    metadata_path = str(output_path).replace('.joblib', '_metadata.json')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"   ✅ Metadata: {metadata_path}")


def main():
    parser = argparse.ArgumentParser(description='Advanced Trainer - Versión Mejorada')
    parser.add_argument('--input_csv', required=True, help='Archivo CSV de entrada')
    parser.add_argument('--output_model', required=True, help='Archivo modelo de salida')
    parser.add_argument('--config_file', help='Archivo de configuración JSON')
    parser.add_argument('--max_rows', type=int, default=100000, help='Máximo número de filas')
    parser.add_argument('--balance_threshold', type=float, default=0.15,
                        help='Umbral para considerar dataset balanceado')

    args = parser.parse_args()

    print("🚀 ADVANCED TRAINER MEJORADO v2.0")
    print("=" * 60)
    print(f"🕐 Iniciado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    try:
        # 1. Cargar datos
        df = load_and_validate_data(args.input_csv, args.max_rows)

        # 2. Preparar features
        X, y, feature_names = prepare_features_robust(df)

        # 3. Balanceo inteligente
        X_balanced, y_balanced = apply_smart_balancing(X, y, args.balance_threshold)

        # 4. División train/test
        print(f"✂️ Dividiendo datos...")
        X_train, X_test, y_train, y_test = train_test_split(
            X_balanced, y_balanced,
            test_size=0.25,
            random_state=42,
            stratify=y_balanced
        )
        print(f"📊 División: {len(X_train):,} entrenamiento, {len(X_test):,} prueba")

        # 5. Escalado
        print(f"📏 Escalando features...")
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # 6. Entrenamiento
        model = train_conservative_model(X_train_scaled, y_train)

        # 7. Evaluación
        metrics = comprehensive_evaluation(model, X_test_scaled, y_test, feature_names)

        # 8. Guardar artefactos
        save_model_artifacts(model, scaler, feature_names, metrics, args.output_model)

        print(f"\n🎯 RESUMEN FINAL")
        print("=" * 60)
        print(f"📊 OOB Score: {getattr(model, 'oob_score_', 'N/A'):.4f}")
        print(f"📈 AUC-ROC: {metrics.get('auc_roc', 'N/A'):.4f}")
        print(f"💾 Modelo guardado: {args.output_model}")
        print(f"✅ ENTRENAMIENTO COMPLETADO!")

    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())