#!/usr/bin/env python3
"""
CICIDS-2017 Model Re-trainer
Re-entrena el modelo de detección con datos limpios de CICIDS-2017
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import os
import warnings
from datetime import datetime

warnings.filterwarnings('ignore')


def load_cicids_dataset(file_path):
    """Carga el dataset CICIDS-2017 procesado"""

    print("📥 CARGANDO DATASET CICIDS-2017")
    print("=" * 50)

    if not os.path.exists(file_path):
        print(f"❌ Archivo no encontrado: {file_path}")
        return None

    print(f"📂 Cargando: {file_path}")
    file_size_mb = os.path.getsize(file_path) / (1024 ** 2)
    print(f"📊 Tamaño: {file_size_mb:.1f} MB")

    try:
        df = pd.read_csv(file_path)
        print(f"✅ Dataset cargado exitosamente")
        print(f"📊 Filas: {len(df):,}")
        print(f"📊 Columnas: {len(df.columns)}")

        return df
    except Exception as e:
        print(f"❌ Error cargando dataset: {e}")
        return None


def select_features_for_sniffer(df):
    """Selecciona features compatibles con el sniffer ML"""

    print(f"\n🎯 SELECCIONANDO FEATURES PARA SNIFFER")
    print("=" * 50)

    # Features que nuestro sniffer puede calcular/aproximar
    sniffer_compatible_features = {
        # Básicas (directas)
        'flow_duration': ['Flow Duration'],
        'packets_fwd': ['Total Fwd Packets', 'Fwd Packet Length Total'],
        'packets_bwd': ['Total Backward Packets', 'Bwd Packet Length Total'],
        'bytes_fwd': ['Total Length of Fwd Packets'],
        'bytes_bwd': ['Total Length of Bwd Packets'],

        # Calculadas (aproximables)
        'flow_bytes_s': ['Flow Bytes/s'],
        'flow_packets_s': ['Flow Packets/s'],
        'fwd_packets_s': ['Fwd Packets/s'],
        'bwd_packets_s': ['Bwd Packets/s'],

        # Timing features
        'fwd_iat_mean': ['Fwd IAT Mean'],
        'bwd_iat_mean': ['Bwd IAT Mean'],
        'fwd_iat_std': ['Fwd IAT Std'],
        'bwd_iat_std': ['Bwd IAT Std'],

        # Packet sizes
        'fwd_pkt_len_mean': ['Fwd Packet Length Mean'],
        'bwd_pkt_len_mean': ['Bwd Packet Length Mean'],
        'fwd_pkt_len_std': ['Fwd Packet Length Std'],
        'bwd_pkt_len_std': ['Bwd Packet Length Std'],

        # TCP flags
        'fwd_psh_flags': ['Fwd PSH Flags'],
        'bwd_psh_flags': ['Bwd PSH Flags'],
        'fwd_urg_flags': ['Fwd URG Flags'],
        'bwd_urg_flags': ['Bwd URG Flags'],

        # Flow characteristics
        'flow_iat_mean': ['Flow IAT Mean'],
        'flow_iat_std': ['Flow IAT Std'],
        'active_mean': ['Active Mean'],
        'idle_mean': ['Idle Mean'],
    }

    # Encontrar features disponibles
    available_features = {}

    for feature_type, possible_names in sniffer_compatible_features.items():
        for name in possible_names:
            # Buscar coincidencias exactas o parciales
            matching_cols = [col for col in df.columns if name.lower() in col.lower()]
            if matching_cols:
                available_features[feature_type] = matching_cols[0]
                break

    print(f"🔍 Features encontradas compatibles con sniffer:")
    for feature_type, col_name in available_features.items():
        print(f"   ✅ {feature_type:<20} → {col_name}")

    # Agregar features adicionales numéricas útiles
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()

    # Excluir columnas problemáticas
    exclude_patterns = ['local', 'label', 'id', 'ip', 'port', 'timestamp']
    additional_features = []

    for col in numeric_cols:
        if col not in available_features.values():
            if not any(pattern in col.lower() for pattern in exclude_patterns):
                additional_features.append(col)

    # Tomar las mejores features adicionales (por varianza)
    if additional_features:
        feature_variances = df[additional_features].var().sort_values(ascending=False)
        top_additional = feature_variances.head(15).index.tolist()

        print(f"\n🎯 Features adicionales seleccionadas (top varianza):")
        for i, col in enumerate(top_additional, 1):
            available_features[f'additional_{i}'] = col
            print(f"   ✅ additional_{i:<12} → {col}")

    final_feature_list = list(available_features.values())
    print(f"\n📊 TOTAL FEATURES SELECCIONADAS: {len(final_feature_list)}")

    return final_feature_list, available_features


def prepare_training_data(df, feature_list):
    """Prepara datos para entrenamiento"""

    print(f"\n🚀 PREPARANDO DATOS PARA ENTRENAMIENTO")
    print("=" * 50)

    # Extraer features y labels
    X = df[feature_list].copy()
    y = df['binary_label'].copy()

    print(f"📊 Features shape: {X.shape}")
    print(f"📊 Labels shape: {y.shape}")

    # Verificar distribución de labels
    label_dist = y.value_counts()
    print(f"🏷️ Distribución de labels:")
    print(f"   Normal (0): {label_dist.get(0, 0):,} ({label_dist.get(0, 0) / len(y) * 100:.1f}%)")
    print(f"   Attack (1): {label_dist.get(1, 0):,} ({label_dist.get(1, 0) / len(y) * 100:.1f}%)")

    # Limpieza adicional
    print(f"\n🧹 Limpieza de features...")

    # Remover infinitos restantes
    X = X.replace([np.inf, -np.inf], np.nan)

    # Contar NaNs por columna
    nan_counts = X.isnull().sum()
    problematic_cols = nan_counts[nan_counts > len(X) * 0.1].index.tolist()

    if problematic_cols:
        print(f"   🗑️  Removiendo {len(problematic_cols)} columnas con >10% NaN:")
        for col in problematic_cols:
            print(f"      - {col} ({nan_counts[col]} NaNs)")
        X = X.drop(columns=problematic_cols)

    # Remover filas con NaN restantes
    before_dropna = len(X)
    mask = ~X.isnull().any(axis=1)
    X = X[mask]
    y = y[mask]
    after_dropna = len(X)

    if before_dropna != after_dropna:
        removed = before_dropna - after_dropna
        print(f"   🗑️  Filas con NaN removidas: {removed:,}")

    print(f"   ✅ Datos finales: {X.shape[0]:,} muestras, {X.shape[1]} features")

    # Mostrar estadísticas de features principales
    print(f"\n📊 ESTADÍSTICAS DE FEATURES PRINCIPALES:")

    for col in X.columns[:10]:
        stats = X[col].describe()
        print(f"   {col:<35}: min={stats['min']:.2f}, max={stats['max']:.2f}, mean={stats['mean']:.2f}")

    if len(X.columns) > 10:
        print(f"   ... y {len(X.columns) - 10} features más")

    return X, y


def train_attack_detector(X, y, feature_list):
    """Entrena el detector de ataques con Random Forest"""

    print(f"\n🤖 ENTRENANDO DETECTOR DE ATAQUES")
    print("=" * 50)

    # Split train/test
    print(f"📊 Dividiendo datos...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    print(f"   📈 Train: {len(X_train):,} muestras")
    print(f"   📉 Test:  {len(X_test):,} muestras")

    # Entrenar scaler
    print(f"\n⚖️  Escalando features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Entrenar Random Forest
    print(f"\n🌲 Entrenando Random Forest...")

    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'  # Maneja desbalance de clases
    )

    print(f"   🔄 Fitting modelo...")
    rf_model.fit(X_train_scaled, y_train)

    # Evaluación
    print(f"\n📊 EVALUANDO MODELO...")

    # Predicciones
    y_pred = rf_model.predict(X_test_scaled)
    y_pred_proba = rf_model.predict_proba(X_test_scaled)[:, 1]

    # Métricas
    auc_score = roc_auc_score(y_test, y_pred_proba)

    print(f"   🎯 AUC Score: {auc_score:.4f}")

    # Classification report
    print(f"\n📋 CLASSIFICATION REPORT:")
    report = classification_report(y_test, y_pred, target_names=['Normal', 'Attack'])
    print(report)

    # Confusion matrix
    print(f"\n🔢 CONFUSION MATRIX:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                Predicted")
    print(f"                Normal  Attack")
    print(f"   Actual Normal   {cm[0, 0]:6d}  {cm[0, 1]:6d}")
    print(f"   Actual Attack   {cm[1, 0]:6d}  {cm[1, 1]:6d}")

    # Feature importance
    print(f"\n🎯 TOP 10 FEATURES MÁS IMPORTANTES:")
    feature_importance = pd.DataFrame({
        'feature': feature_list,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)

    for i, (_, row) in enumerate(feature_importance.head(10).iterrows(), 1):
        print(f"   {i:2d}. {row['feature']:<35} ({row['importance']:.4f})")

    # Cross-validation
    print(f"\n✅ VALIDACIÓN CRUZADA (5-fold):")
    cv_scores = cross_val_score(rf_model, X_train_scaled, y_train, cv=5, scoring='roc_auc')
    print(f"   🎯 CV AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    return rf_model, scaler, feature_importance, auc_score


def save_retrained_model(model, scaler, feature_list, feature_importance, auc_score):
    """Guarda el modelo re-entrenado"""

    print(f"\n💾 GUARDANDO MODELO RE-ENTRENADO")
    print("=" * 50)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Crear directorio para modelos nuevos
    model_dir = "models_cicids"
    os.makedirs(model_dir, exist_ok=True)

    # Guardar modelo principal
    model_file = f"{model_dir}/rf_attack_detector_cicids_{timestamp}.joblib"
    scaler_file = f"{model_dir}/rf_attack_detector_cicids_{timestamp}_scaler.joblib"

    # Empaquetar modelo con metadatos
    model_package = {
        'model': model,
        'scaler': scaler,
        'feature_names': feature_list,
        'auc_score': auc_score,
        'timestamp': timestamp,
        'dataset': 'CICIDS-2017',
        'samples_trained': 'train_size_here'  # Se actualizará
    }

    joblib.dump(model_package, model_file)
    joblib.dump(scaler, scaler_file)

    print(f"✅ Modelo guardado: {model_file}")
    print(f"✅ Scaler guardado: {scaler_file}")

    # Guardar feature importance
    importance_file = f"{model_dir}/feature_importance_{timestamp}.csv"
    feature_importance.to_csv(importance_file, index=False)
    print(f"✅ Feature importance: {importance_file}")

    # Crear config para el sniffer
    config_file = f"{model_dir}/sniffer_config_{timestamp}.py"

    with open(config_file, 'w') as f:
        f.write(f"""# Configuración para sniffer ML - CICIDS-2017 Trained
# Generado automáticamente el {timestamp}

MODEL_PATH = "{model_file}"
SCALER_PATH = "{scaler_file}"
AUC_SCORE = {auc_score:.4f}
DATASET = "CICIDS-2017"
FEATURES = {feature_list}

# Instrucciones de uso:
# 1. Reemplazar modelos antiguos en tu sniffer
# 2. Usar esta lista de features
# 3. Aplicar este scaler antes de predicción
""")

    print(f"✅ Config generado: {config_file}")

    # Archivo production-ready
    production_model = f"models/rf_production_cicids.joblib"
    production_scaler = f"models/rf_production_cicids_scaler.joblib"

    joblib.dump(model_package, production_model)
    joblib.dump(scaler, production_scaler)

    print(f"\n🚀 MODELOS PRODUCTION-READY:")
    print(f"✅ {production_model}")
    print(f"✅ {production_scaler}")

    return model_file, scaler_file


def main():
    """Función principal"""

    print("🚀 CICIDS-2017 MODEL RE-TRAINER")
    print("🎯 Re-entrenando con datos limpios y realistas")
    print("=" * 60)

    # 1. Cargar dataset
    dataset_file = "cicids_2017_processed.csv"
    df = load_cicids_dataset(dataset_file)

    if df is None:
        return

    # 2. Seleccionar features compatibles con sniffer
    feature_list, feature_mapping = select_features_for_sniffer(df)

    if not feature_list:
        print("❌ No se encontraron features compatibles")
        return

    # 3. Preparar datos
    X, y = prepare_training_data(df, feature_list)

    if X is None or len(X) == 0:
        print("❌ No hay datos válidos para entrenar")
        return

    # 4. Entrenar modelo
    model, scaler, feature_importance, auc_score = train_attack_detector(X, y, feature_list)

    # 5. Guardar modelo
    model_file, scaler_file = save_retrained_model(
        model, scaler, feature_list, feature_importance, auc_score
    )

    print(f"\n🎯 ¡RE-ENTRENAMIENTO COMPLETADO!")
    print(f"✅ AUC Score: {auc_score:.4f}")
    print(f"✅ Features: {len(feature_list)}")
    print(f"✅ Modelo: {model_file}")

    if auc_score > 0.95:
        print(f"🏆 ¡EXCELENTE RENDIMIENTO! (AUC > 0.95)")
    elif auc_score > 0.90:
        print(f"✅ Buen rendimiento (AUC > 0.90)")
    else:
        print(f"⚠️  Rendimiento mejorable (AUC < 0.90)")

    print(f"\n🚀 LISTO PARA USAR EN TU SNIFFER!")
    print(f"   Reemplaza los modelos antiguos con los nuevos")
    print(f"   Los valores de sload ahora serán realistas")


if __name__ == "__main__":
    main()