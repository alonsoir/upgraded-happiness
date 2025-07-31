#!/usr/bin/env python3
"""
Advanced Trainer Flexible - Versión con parámetros flexibles
==========================================================

Basado en advanced_trainer_no_dns.py que logró 92% accuracy con UNSW-NB15.
Ahora con capacidad de especificar datasets, configs y modelos específicos.

Uso:
    python advanced_trainer_flexible.py \
        --input_csv data/normal_traffic_hybrid.csv \
        --output_model models/rf_normal_hybrid.joblib \
        --config_file config/normal_training_config.json

    python advanced_trainer_flexible.py \
        --input_csv data/internal_traffic_hybrid.csv \
        --output_model models/rf_internal_hybrid.joblib \
        --config_file config/internal_training_config.json
"""

import argparse
import json
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from datetime import datetime
from collections import Counter
import warnings

warnings.filterwarnings('ignore')

# ML imports
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, average_precision_score
from sklearn.utils.class_weight import compute_class_weight
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline as ImbPipeline

# SHAP for model explainability
try:
    import shap

    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    print("⚠️  SHAP no disponible - saltando explicabilidad")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Advanced ML Trainer - Flexible Version')

    parser.add_argument('--input_csv',
                        required=True,
                        help='Path to input CSV dataset')

    parser.add_argument('--output_model',
                        required=True,
                        help='Path to save trained model (.joblib)')

    parser.add_argument('--config_file',
                        required=True,
                        help='Path to configuration JSON file')

    parser.add_argument('--max_rows',
                        type=int,
                        default=100000,
                        help='Maximum rows to use for training (default: 100000)')

    return parser.parse_args()


def load_config(config_path):
    """Load configuration from JSON file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        print(f"✅ Config cargado desde: {config_path}")
        return config
    except FileNotFoundError:
        print(f"❌ ERROR: Config file no encontrado: {config_path}")
        raise
    except json.JSONDecodeError as e:
        print(f"❌ ERROR: JSON inválido en {config_path}: {e}")
        raise


def load_and_validate_dataset(csv_path, max_rows=None):
    """Load and validate dataset."""
    try:
        # Check if file exists
        if not Path(csv_path).exists():
            raise FileNotFoundError(f"Dataset no encontrado: {csv_path}")

        # Load dataset
        print(f"📁 Cargando dataset: {csv_path}")
        df = pd.read_csv(csv_path)

        if max_rows and len(df) > max_rows:
            df = df.sample(n=max_rows, random_state=42)
            print(f"📊 Dataset limitado a {max_rows:,} filas")

        print(f"📊 Dataset cargado: {len(df):,} registros")

        # Validate required columns
        required_cols = ['label']
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            raise ValueError(f"Columnas faltantes: {missing_cols}")

        # Show label distribution
        label_dist = df['label'].value_counts().to_dict()
        print(f"📊 Distribución de etiquetas: {label_dist}")

        return df

    except Exception as e:
        print(f"❌ ERROR cargando dataset: {e}")
        raise


def prepare_features(df, config):
    """Prepare features for training - based on successful methodology."""
    print("🔧 Preparando features...")

    # Select numeric columns (like successful UNSW-NB15 approach)
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if 'label' in numeric_cols:
        numeric_cols.remove('label')

    print(f"🔢 Features numéricas seleccionadas: {len(numeric_cols)}")
    print(f"   {numeric_cols}")

    # Handle categorical columns if any
    categorical_cols = df.select_dtypes(include=['object']).columns.tolist()

    X = df[numeric_cols].copy()
    y = df['label'].copy()

    # Encode categorical features if present
    if categorical_cols:
        print(f"🔤 Codificando {len(categorical_cols)} columnas categóricas...")
        le_dict = {}
        for col in categorical_cols:
            if col in df.columns:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
                le_dict[col] = le
                X[col] = df[col]

    print(f"✅ Features preparadas: X={X.shape}, y={y.shape}")
    return X, y


def apply_balancing(X, y, config):
    """Apply hybrid balancing strategy - same as successful approach."""
    print("⚖️ Aplicando balanceo híbrido...")

    initial_dist = Counter(y)
    print(f"📊 Distribución inicial: {initial_dist}")

    # Same strategy that worked for UNSW-NB15
    # Combine oversampling minority + undersampling majority
    over_sampler = SMOTE(random_state=42, k_neighbors=3)
    under_sampler = RandomUnderSampler(random_state=42, sampling_strategy=1.5)

    # Create pipeline
    sampling_pipeline = ImbPipeline([
        ('over', over_sampler),
        ('under', under_sampler)
    ])

    X_balanced, y_balanced = sampling_pipeline.fit_resample(X, y)

    final_dist = Counter(y_balanced)
    print(f"📊 Distribución después de balanceo: {final_dist}")

    return X_balanced, y_balanced


def train_model(X, y, config):
    """Train Random Forest model with same parameters that achieved 92%."""
    print("🧠 Entrenando Random Forest...")

    # Same parameters that achieved 92% accuracy
    rf_params = config['ml']['models']['random_forest']

    rf = RandomForestClassifier(
        n_estimators=rf_params['n_estimators'],
        max_depth=rf_params['max_depth'],
        min_samples_split=rf_params['min_samples_split'],
        min_samples_leaf=rf_params['min_samples_leaf'],
        max_features=rf_params['max_features'],
        class_weight=rf_params['class_weight'],
        bootstrap=True,
        oob_score=True,
        n_jobs=-1,
        random_state=42,
        ccp_alpha=0.0001,
        max_samples=0.8
    )

    print(f"🎯 Parámetros RF: {rf_params}")

    # Cross-validation (same as successful approach)
    print("📊 Ejecutando validación cruzada 5-fold...")
    cv_scores = cross_val_score(rf, X, y, cv=5, scoring='accuracy', n_jobs=-1)

    print(f"🔍 CV Scores: {[f'{score:.4f}' for score in cv_scores]}")
    print(f"🏆 CV Mean: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Train final model on all data
    print("📊 Entrenando modelo final...")
    rf.fit(X, y)

    print(f"✅ Modelo entrenado - OOB Score: {rf.oob_score_:.4f}")

    return rf, cv_scores


def evaluate_model(model, X_test, y_test):
    """Evaluate model with same metrics as successful approach."""
    print("📊 Evaluando modelo...")

    # Predictions
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]

    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f"\n[📊] Matriz de Confusión:")
    print(cm)

    # Classification Report
    report = classification_report(y_test, y_pred)
    print(f"\n[📋] Reporte de Clasificación:")
    print(report)

    # AUC metrics
    auc_roc = roc_auc_score(y_test, y_pred_proba)
    auc_pr = average_precision_score(y_test, y_pred_proba)

    print(f"\n[📈] AUC-ROC: {auc_roc:.4f}")
    print(f"[📈] AUC-PR: {auc_pr:.4f}")

    # Security-specific metrics (same as successful approach)
    tn, fp, fn, tp = cm.ravel()

    fpr = fp / (fp + tn)  # False Positive Rate
    fnr = fn / (fn + tp)  # False Negative Rate
    tpr = tp / (tp + fn)  # True Positive Rate (Detection Rate)
    precision_threats = tp / (tp + fp) if (tp + fp) > 0 else 0

    print(f"\n[🔒] Métricas de Seguridad:")
    print(f"  - Tasa de Falsos Positivos (FPR): {fpr:.4f}")
    print(f"  - Tasa de Falsos Negativos (FNR): {fnr:.4f}")
    print(f"  - Tasa de Detección: {tpr:.4f}")
    print(f"  - Precisión en Amenazas: {precision_threats:.4f}")

    return {
        'accuracy': (tp + tn) / (tp + tn + fp + fn),
        'auc_roc': auc_roc,
        'auc_pr': auc_pr,
        'fpr': fpr,
        'fnr': fnr,
        'detection_rate': tpr,
        'threat_precision': precision_threats
    }


def save_model_artifacts(model, scaler, output_path, metadata, X_sample=None):
    """Save model and associated artifacts."""
    print("💾 Guardando artefactos del modelo...")

    # Create output directory
    output_path = Path(output_path)
    output_dir = output_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save main model
    joblib.dump(model, output_path)
    print(f"   ✅ Modelo guardado: {output_path}")

    # Save scaler
    scaler_path = output_dir / f"{output_path.stem}_scaler.joblib"
    joblib.dump(scaler, scaler_path)
    print(f"   ✅ Scaler guardado: {scaler_path}")

    # Save metadata
    metadata_path = output_dir / f"{output_path.stem}_metadata.json"
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2, default=str)
    print(f"   ✅ Metadata guardado: {metadata_path}")

    # Save SHAP explainer if available and sample provided
    if SHAP_AVAILABLE and X_sample is not None:
        try:
            print("   🔍 Generando explicaciones SHAP...")
            explainer = shap.TreeExplainer(model)
            shap_path = output_dir / f"{output_path.stem}_shap_explainer.joblib"
            joblib.dump(explainer, shap_path)
            print(f"   ✅ SHAP Explainer guardado: {shap_path}")
        except Exception as e:
            print(f"   ⚠️  Error generando SHAP: {e}")

    print(f"💾 Todos los artefactos guardados en: {output_dir}")
    return output_dir


def main():
    """Main training pipeline."""
    start_time = datetime.now()

    print("🚀 ADVANCED TRAINER FLEXIBLE v1.0")
    print("=" * 60)
    print(f"🕐 Iniciado: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Parse arguments
    args = parse_args()

    print(f"📋 Configuración:")
    print(f"   Input CSV: {args.input_csv}")
    print(f"   Output Model: {args.output_model}")
    print(f"   Config File: {args.config_file}")
    print(f"   Max Rows: {args.max_rows:,}")
    print()

    try:
        # Load configuration
        config = load_config(args.config_file)

        # Load dataset
        df = load_and_validate_dataset(args.input_csv, args.max_rows)

        # Prepare features
        X, y = prepare_features(df, config)

        # Apply balancing
        X_balanced, y_balanced = apply_balancing(X, y, config)

        # Split data
        print("✂️ Dividiendo datos...")
        X_train, X_test, y_train, y_test = train_test_split(
            X_balanced, y_balanced, test_size=0.25, random_state=42, stratify=y_balanced
        )
        print(f"📊 División: {len(X_train):,} entrenamiento, {len(X_test):,} prueba")

        # Scale features
        print("📏 Escalando features...")
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Train model
        model, cv_scores = train_model(X_train_scaled, y_train, config)

        # Evaluate model
        metrics = evaluate_model(model, X_test_scaled, y_test)

        # Prepare metadata
        metadata = {
            'timestamp': start_time.isoformat(),
            'input_csv': str(args.input_csv),
            'config_file': str(args.config_file),
            'dataset_info': {
                'total_rows': len(df),
                'features': X.columns.tolist(),
                'label_distribution': Counter(y),
                'balanced_distribution': Counter(y_balanced)
            },
            'model_params': config['ml']['models']['random_forest'],
            'cv_scores': cv_scores.tolist(),
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'final_metrics': metrics,
            'training_time': str(datetime.now() - start_time)
        }

        # Save model and artifacts
        save_model_artifacts(
            model, scaler, args.output_model, metadata,
            X_sample=X_test_scaled[:1000] if len(X_test_scaled) >= 1000 else X_test_scaled
        )

        # Final summary
        end_time = datetime.now()
        training_time = end_time - start_time

        print()
        print("🎯 RESUMEN FINAL")
        print("=" * 60)
        print(f"⏰ Tiempo total: {training_time}")
        print(f"📊 Accuracy: {metrics['accuracy']:.4f}")
        print(f"📈 AUC-ROC: {metrics['auc_roc']:.4f}")
        print(f"🔒 Tasa de Detección: {metrics['detection_rate']:.4f}")
        print(f"⚠️  Falsos Positivos: {metrics['fpr']:.4f}")
        print(f"💾 Modelo guardado: {args.output_model}")
        print()
        print("✅ ENTRENAMIENTO COMPLETADO CON ÉXITO!")

    except Exception as e:
        print(f"❌ ERROR durante el entrenamiento: {e}")
        raise


if __name__ == "__main__":
    main()