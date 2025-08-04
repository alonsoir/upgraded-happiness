#!/usr/bin/env python3
"""
Sniffer-Compatible CICIDS Retrainer
Re-entrena usando SOLO las features que el sniffer actual puede calcular
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


def load_cicids_data():
    """Carga el dataset CICIDS-2017 procesado"""

    print("📥 CARGANDO CICIDS-2017 PARA SNIFFER COMPATIBILITY")
    print("=" * 60)

    df = pd.read_csv("cicids_2017_processed.csv")
    print(f"✅ Dataset cargado: {len(df):,} filas, {len(df.columns)} columnas")

    return df


def map_cicids_to_sniffer_features(df):
    """Mapea features de CICIDS-2017 a las que el sniffer puede calcular"""

    print(f"\n🔄 MAPEANDO FEATURES CICIDS → SNIFFER")
    print("=" * 50)

    # Crear nuevo dataframe con features compatibles con el sniffer
    sniffer_df = pd.DataFrame()

    # MAPEO DIRECTO: CICIDS-2017 → Sniffer features
    feature_mapping = {
        # Features básicas que el sniffer YA calcula
        'duration': 'Flow Duration',  # flow.last_time - flow.start_time
        'spkts': 'Total Fwd Packet',  # flow.spkts
        'dpkts': 'Total Bwd packets',  # flow.dpkts
        'sbytes': 'Total Length of Fwd Packet',  # flow.sbytes
        'dbytes': 'Total Length of Bwd Packet',  # flow.dbytes

        # Features calculadas que el sniffer YA puede hacer
        'sload': 'Flow Bytes/s',  # (flow.sbytes * 8) / duration
        'smean': 'Fwd Packet Length Mean',  # Mean packet size fwd
        'dmean': 'Bwd Packet Length Mean',  # Mean packet size bwd

        # Features de timing que el sniffer puede aproximar
        'flow_iat_mean': 'Flow IAT Mean',  # Inter-arrival time mean
        'flow_iat_std': 'Flow IAT Std',  # Inter-arrival time std

        # Features de protocolo/estado que el sniffer puede calcular
        'fwd_psh_flags': 'Fwd PSH Flags',  # TCP PSH flags
        'bwd_psh_flags': 'Bwd PSH Flags',  # TCP PSH flags
        'fwd_urg_flags': 'Fwd URG Flags',  # TCP URG flags
        'bwd_urg_flags': 'Bwd URG Flags',  # TCP URG flags

        # Features de tamaño de packet que el sniffer puede calcular
        'packet_len_mean': 'Packet Length Mean',  # Average packet size
        'packet_len_std': 'Packet Length Std',  # Packet size std dev
        'packet_len_var': 'Packet Length Variance',  # Packet size variance

        # Features de conteo de flags que el sniffer puede hacer
        'fin_flag_count': 'FIN Flag Count',  # FIN flags
        'syn_flag_count': 'SYN Flag Count',  # SYN flags
        'rst_flag_count': 'RST Flag Count',  # RST flags
        'psh_flag_count': 'PSH Flag Count',  # PSH flags
        'ack_flag_count': 'ACK Flag Count',  # ACK flags
        'urg_flag_count': 'URG Flag Count',  # URG flags
    }

    # Mapear features disponibles
    mapped_features = {}

    for sniffer_name, cicids_name in feature_mapping.items():
        if cicids_name in df.columns:
            sniffer_df[sniffer_name] = df[cicids_name]
            mapped_features[sniffer_name] = cicids_name
            print(f"   ✅ {sniffer_name:<20} ← {cicids_name}")
        else:
            print(f"   ❌ {sniffer_name:<20} ← {cicids_name} (no encontrada)")

    # Agregar features derivadas que el sniffer puede calcular
    print(f"\n🔧 CREANDO FEATURES DERIVADAS...")

    # Rate features (que el sniffer puede calcular)
    if 'spkts' in sniffer_df.columns and 'dpkts' in sniffer_df.columns and 'duration' in sniffer_df.columns:
        # Total packets / duration (como flow_packets_s)
        sniffer_df['total_packets_rate'] = (sniffer_df['spkts'] + sniffer_df['dpkts']) / (
                    sniffer_df['duration'] / 1000000)  # duration en microsegundos
        sniffer_df['total_packets_rate'] = sniffer_df['total_packets_rate'].replace([np.inf, -np.inf], 0)
        print(f"   ✅ total_packets_rate (packets/second)")

    # Bytes rate (equivalente a dload)
    if 'dbytes' in sniffer_df.columns and 'duration' in sniffer_df.columns:
        sniffer_df['dload'] = (sniffer_df['dbytes'] * 8) / (sniffer_df['duration'] / 1000000)  # bits per second
        sniffer_df['dload'] = sniffer_df['dload'].replace([np.inf, -np.inf], 0)
        print(f"   ✅ dload (destination load)")

    # Packet ratio features
    if 'spkts' in sniffer_df.columns and 'dpkts' in sniffer_df.columns:
        total_packets = sniffer_df['spkts'] + sniffer_df['dpkts']
        sniffer_df['fwd_pkt_ratio'] = sniffer_df['spkts'] / total_packets
        sniffer_df['bwd_pkt_ratio'] = sniffer_df['dpkts'] / total_packets
        sniffer_df['fwd_pkt_ratio'] = sniffer_df['fwd_pkt_ratio'].fillna(0)
        sniffer_df['bwd_pkt_ratio'] = sniffer_df['bwd_pkt_ratio'].fillna(0)
        print(f"   ✅ fwd_pkt_ratio, bwd_pkt_ratio")

    # Bytes ratio features
    if 'sbytes' in sniffer_df.columns and 'dbytes' in sniffer_df.columns:
        total_bytes = sniffer_df['sbytes'] + sniffer_df['dbytes']
        sniffer_df['fwd_bytes_ratio'] = sniffer_df['sbytes'] / total_bytes
        sniffer_df['bwd_bytes_ratio'] = sniffer_df['dbytes'] / total_bytes
        sniffer_df['fwd_bytes_ratio'] = sniffer_df['fwd_bytes_ratio'].fillna(0)
        sniffer_df['bwd_bytes_ratio'] = sniffer_df['bwd_bytes_ratio'].fillna(0)
        print(f"   ✅ fwd_bytes_ratio, bwd_bytes_ratio")

    # Agregar labels
    sniffer_df['binary_label'] = df['binary_label']

    print(f"\n📊 DATASET SNIFFER-COMPATIBLE:")
    print(f"   Features totales: {len(sniffer_df.columns) - 1}")  # -1 para label
    print(f"   Muestras: {len(sniffer_df):,}")

    return sniffer_df, list(mapped_features.keys())


def train_sniffer_compatible_model(df, feature_list):
    """Entrena modelo compatible con el sniffer actual"""

    print(f"\n🤖 ENTRENANDO MODELO SNIFFER-COMPATIBLE")
    print("=" * 50)

    # Preparar datos
    X = df[feature_list].copy()
    y = df['binary_label'].copy()

    # Limpieza
    X = X.replace([np.inf, -np.inf], np.nan)
    mask = ~X.isnull().any(axis=1)
    X = X[mask]
    y = y[mask]

    print(f"📊 Datos finales: {len(X):,} muestras, {len(feature_list)} features")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    print(f"   📈 Train: {len(X_train):,}")
    print(f"   📉 Test:  {len(X_test):,}")

    # Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Modelo
    print(f"\n🌲 Entrenando Random Forest...")

    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )

    rf_model.fit(X_train_scaled, y_train)

    # Evaluación
    print(f"\n📊 EVALUANDO MODELO...")

    y_pred = rf_model.predict(X_test_scaled)
    y_pred_proba = rf_model.predict_proba(X_test_scaled)[:, 1]

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
        print(f"   {i:2d}. {row['feature']:<25} ({row['importance']:.4f})")

    return rf_model, scaler, feature_importance, auc_score


def save_sniffer_model(model, scaler, feature_list, feature_importance, auc_score):
    """Guarda modelo compatible con sniffer"""

    print(f"\n💾 GUARDANDO MODELO SNIFFER-COMPATIBLE")
    print("=" * 50)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Empaquetar con las MISMAS features que usa el sniffer
    model_package = {
        'model': model,
        'scaler': scaler,
        'feature_names': feature_list,
        'auc_score': auc_score,
        'timestamp': timestamp,
        'dataset': 'CICIDS-2017-SnifferCompatible',
        'note': 'Entrenado con features que el sniffer puede calcular'
    }

    # Guardar con nombres que el sniffer reconoce
    model_file = "models/rf_production_sniffer_compatible.joblib"
    scaler_file = "models/rf_production_sniffer_compatible_scaler.joblib"

    joblib.dump(model_package, model_file)
    joblib.dump(scaler, scaler_file)

    print(f"✅ Modelo: {model_file}")
    print(f"✅ Scaler: {scaler_file}")

    # Feature mapping para el sniffer
    with open("sniffer_feature_mapping.txt", "w") as f:
        f.write(f"# SNIFFER FEATURE MAPPING\n")
        f.write(f"# Modelo entrenado: {timestamp}\n")
        f.write(f"# AUC Score: {auc_score:.4f}\n\n")
        f.write(f"FEATURES_ORDER = {feature_list}\n\n")
        f.write(f"# El sniffer debe calcular estas features en este EXACTO orden:\n")
        for i, feature in enumerate(feature_list, 1):
            f.write(f"# {i:2d}. {feature}\n")

    print(f"✅ Feature mapping: sniffer_feature_mapping.txt")

    return model_file, scaler_file


def main():
    """Función principal"""

    print("🔧 SNIFFER-COMPATIBLE CICIDS-2017 RETRAINER")
    print("🎯 Entrenando SOLO con features que el sniffer puede calcular")
    print("=" * 70)

    # 1. Cargar datos
    df = load_cicids_data()

    # 2. Mapear features
    sniffer_df, feature_list = map_cicids_to_sniffer_features(df)

    if not feature_list:
        print("❌ No se pudieron mapear features")
        return

    # 3. Entrenar modelo
    model, scaler, feature_importance, auc_score = train_sniffer_compatible_model(
        sniffer_df, feature_list
    )

    # 4. Guardar modelo
    model_file, scaler_file = save_sniffer_model(
        model, scaler, feature_list, feature_importance, auc_score
    )

    print(f"\n🎯 ¡MODELO SNIFFER-COMPATIBLE COMPLETADO!")
    print(f"✅ AUC Score: {auc_score:.4f}")
    print(f"✅ Features: {len(feature_list)}")

    if auc_score > 0.90:
        print(f"🏆 ¡EXCELENTE! Modelo listo para producción")

    print(f"\n🚀 PRÓXIMO PASO:")
    print(f"   Actualizar el sniffer para usar:")
    print(f"   - {model_file}")
    print(f"   - Features en el orden especificado")


if __name__ == "__main__":
    main()