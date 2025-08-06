import os
import json
import zipfile
import argparse
from pathlib import Path
from collections import Counter
import joblib
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from imblearn.over_sampling import SMOTE
from kaggle.api.kaggle_api_extended import KaggleApi


# -----------------------------------------------------------------------------
# 📁 CONFIGURACIÓN CENTRALIZADA
# -----------------------------------------------------------------------------
def load_config():
    config_path = Path("config-ml-trainer.json")
    if not config_path.exists():
        raise FileNotFoundError("No se encontró el archivo de configuración config.json.")
    with open(config_path, "r") as f:
        return json.load(f)


# -----------------------------------------------------------------------------
# ⬇️ CARGA O DESCARGA DEL DATASET
# -----------------------------------------------------------------------------
def load_dataset(config, dataset_path: str = None, max_rows: int = 0) -> pd.DataFrame:
    base_data_dir = Path("./data")
    base_data_dir.mkdir(exist_ok=True)

    # Configuración específica para UNSW-NB15
    default_csv = base_data_dir / "UNSW_NB15_training-set.csv"
    kaggle_dataset = "mrwellsdavid/unsw-nb15"
    zip_output = base_data_dir / "unsw-nb15.zip"

    # Opción 1: carga directa de path
    if dataset_path and Path(dataset_path).exists():
        print(f"[📁] Cargando dataset desde: {dataset_path}")
        df = pd.read_csv(dataset_path)
    # Opción 2: carga desde archivo local conocido
    elif default_csv.exists():
        print(f"[📁] Cargando dataset local desde: {default_csv}")
        df = pd.read_csv(default_csv)
    # Opción 3: descarga desde Kaggle
    else:
        try:
            print(f"[⬇️] Descargando dataset {kaggle_dataset} desde Kaggle...")
            api = KaggleApi()
            api.authenticate()
            api.dataset_download_files(kaggle_dataset, path=base_data_dir, quiet=False)

            # Verificar si se descargó el archivo zip
            if not zip_output.exists():
                raise FileNotFoundError(f"No se encontró el archivo descargado: {zip_output}")

            print(f"[📦] Extrayendo archivos de {zip_output}...")
            with zipfile.ZipFile(zip_output, 'r') as zip_ref:
                zip_ref.extractall(base_data_dir)

            # Buscar el archivo CSV en la estructura extraída
            csv_path = None
            for file in base_data_dir.glob("**/*.csv"):
                if "training-set" in file.name or "UNSW_NB15" in file.name:
                    csv_path = file
                    print(f"[🔍] Archivo CSV encontrado: {csv_path}")
                    break

            if not csv_path:
                raise FileNotFoundError("No se encontró el archivo CSV esperado en el ZIP")

            print(f"[✅] Dataset cargado desde: {csv_path}")
            df = pd.read_csv(csv_path)

            # Guardar copia local para futuras ejecuciones
            df.to_csv(default_csv, index=False)
            print(f"[💾] Guardado copia local en: {default_csv}")

        except Exception as e:
            print(f"[❌] Error al descargar dataset desde Kaggle: {e}")
            if default_csv.exists():
                print(f"[⚠️] Usando copia local de emergencia: {default_csv}")
                df = pd.read_csv(default_csv)
            else:
                raise FileNotFoundError("No se pudo obtener el dataset ni localmente ni desde Kaggle.")

    # Aplicar límite de filas si se especificó
    if max_rows > 0:
        df = df.head(max_rows)

    # Verificar columna 'label'
    if 'label' not in df.columns:
        # Intentar alternativas
        if 'Label' in df.columns:
            df.rename(columns={'Label': 'label'}, inplace=True)
            print("[ℹ️] Se renombró 'Label' → 'label'")
        elif 'labels' in df.columns:
            df.rename(columns={'labels': 'label'}, inplace=True)
            print("[ℹ️] Se renombró 'labels' → 'label'")
        elif 'attack_cat' in df.columns:
            print("[ℹ️] Creando etiqueta binaria a partir de 'attack_cat'")
            df['label'] = df['attack_cat'].apply(lambda x: 0 if x == 'Normal' else 1)
        else:
            raise ValueError("No se encontró columna 'label' ni alternativas")

    return df


# -----------------------------------------------------------------------------
# 🧹 LIMPIEZA Y PREPARACIÓN DE LOS DATOS
# -----------------------------------------------------------------------------
def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    # En clean_dataset(), añadir características derivadas
    df['packet_imbalance'] = df['spkts'] / (df['dpkts'] + 1e-5)
    df['byte_imbalance'] = df['sbytes'] / (df['dbytes'] + 1e-5)
    df['loss_ratio'] = df['sloss'] / (df['spkts'] + 1e-5)

    # Paso 1: Eliminar columnas no relevantes
    columns_to_drop = ['id', 'attack_cat']
    df = df.drop(columns=[col for col in columns_to_drop if col in df.columns], errors='ignore')

    # Paso 2: Convertir columnas categóricas a numéricas
    categorical_cols = ['proto', 'service', 'state']
    le = LabelEncoder()
    for col in categorical_cols:
        if col in df.columns:
            df[col] = le.fit_transform(df[col].astype(str))

    # Asegurar que la columna 'label' esté presente
    if 'label' not in df.columns:
        raise ValueError("Columna 'label' no encontrada en el dataset después de la limpieza inicial")

    # Paso 3: Filtrar características relevantes con manejo de errores
    scapy_features = [
        'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
        'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt'
    ]

    # Verificar que todas las características existan
    missing_features = [feat for feat in scapy_features if feat not in df.columns]
    if missing_features:
        print(f"[⚠️] Características faltantes: {missing_features}. Usando todas las columnas disponibles.")
    else:
        print("[🔍] Filtrado: Usando características relevantes para análisis de paquetes")
        # Mantener solo características relevantes, pero asegurar que 'label' permanezca
        df = df[scapy_features + ['label']]

    # Paso 4: Limpieza estándar
    original_size = len(df)
    df = df.dropna()
    df = df.drop_duplicates()
    cleaned_size = len(df)

    print(
        f"[🧹] Limpieza: {original_size} → {cleaned_size} muestras ({100 * (1 - cleaned_size / original_size):.1f}% eliminadas)")

    # Paso 5: Eliminar columnas con un solo valor (excepto 'label')
    for col in df.columns:
        if col != 'label' and df[col].nunique() == 1:
            print(f"[⚠️] Eliminando columna constante: {col}")
            df = df.drop(columns=[col])

    # Verificar clases
    class_counts = df['label'].value_counts()
    print(f"[⚖️] Distribución de clases: {class_counts.to_dict()}")

    return df


# -----------------------------------------------------------------------------
# ⚖️ BALANCEO CON SMOTE
# -----------------------------------------------------------------------------
def balance_dataset(X, y):
    counts = Counter(y)
    print(f"[⚖️] Distribución inicial: {dict(counts)}")

    if any(count < 6 for count in counts.values()) or len(counts) < 2:
        print("[⚠️] Muy pocas muestras o clases, omitiendo SMOTE.")
        return X, y

    print("[🔄] Aplicando SMOTE para balancear clases...")
    smote = SMOTE(random_state=42)
    X_res, y_res = smote.fit_resample(X, y)
    print(f"[⚖️] Distribución después de SMOTE: {Counter(y_res)}")
    return X_res, y_res


# -----------------------------------------------------------------------------
# 🧠 ENTRENAMIENTO DEL MODELO
# -----------------------------------------------------------------------------
def train_model(X_train, y_train, config):

    rf_params = config['ml'].get('random_forest', {})
    print(f"[🌲] Configuración RandomForest: {rf_params}")

    # Añadir parámetros avanzados
    advanced_params = {
        'bootstrap': True,
        'oob_score': True,
        'verbose': 1
    }
    rf_params.update(advanced_params)
    rf_params.update({
        'n_estimators': 1000,
        'max_depth': 100,
        'min_samples_split': 10,
        'min_samples_leaf': 4,
        'max_features': 'log2',
        'ccp_alpha': 0.001  # Parámetro de poda
    })

    model = RandomForestClassifier(**rf_params)
    from sklearn.model_selection import cross_val_score
    scores = cross_val_score(model, X_train, y_train, cv=5, scoring='roc_auc')
    print(f"[📊] Validación Cruzada AUC: {np.mean(scores):.4f} ± {np.std(scores):.4f}")
    print("[🔄] Entrenando modelo...")
    model.fit(X_train, y_train)

    # Reportar precisión OOB (Out-of-Bag)
    if hasattr(model, 'oob_score_'):
        print(f"[🔍] Precisión OOB: {model.oob_score_:.4f}")

    return model


# -----------------------------------------------------------------------------
# 📊 EVALUACIÓN DEL MODELO
# -----------------------------------------------------------------------------
def evaluate_model(model, X_test, y_test):
    print("[🧪] Evaluando modelo...")
    y_pred = model.predict(X_test)

    print("\n[📊] Matriz de Confusión:")
    print(confusion_matrix(y_test, y_pred))

    print("\n[📋] Reporte de Clasificación:")
    print(classification_report(y_test, y_pred))


# -----------------------------------------------------------------------------
# 💾 GUARDAR MODELO Y RECURSOS
# -----------------------------------------------------------------------------
def save_model_artifacts(model, config, features):
    os.makedirs("models", exist_ok=True)

    # Guardar modelo RandomForest
    model_path = "models/random_forest_model.pkl"
    joblib.dump(model, model_path)
    print(f"[💾] Modelo guardado: {model_path}")

    # Guardar escalador dummy para compatibilidad
    scaler_path = "models/scaler.pkl"
    scaler = StandardScaler()
    joblib.dump(scaler, scaler_path)
    print(f"[💾] Escalador dummy guardado: {scaler_path}")

    # Guardar metadatos del modelo
    metadata = {
        "training_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "features": features,
        "model_params": config['ml'].get('random_forest', {}),
        "dataset": "UNSW-NB15"
    }
    metadata_path = "models/model_metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=4)
    print(f"[💾] Metadatos guardados: {metadata_path}")


# -----------------------------------------------------------------------------
# 🚀 FUNCIÓN PRINCIPAL
# -----------------------------------------------------------------------------
def main(force_train=False, max_rows=0):
    config = load_config()
    dataset_path = config['ml'].get('dataset_path')
    df = load_dataset(config, dataset_path, max_rows)
    df = clean_dataset(df)

    if 'label' not in df.columns:
        raise ValueError("El dataset no contiene la columna 'label' necesaria para clasificación.")

    X = df.drop(columns=["label"])
    y = df["label"]

    # Guardar nombres de características para referencia futura
    feature_names = list(X.columns)

    X_resampled, y_resampled = balance_dataset(X, y)
    X_train, X_test, y_train, y_test = train_test_split(
        X_resampled, y_resampled, test_size=0.3, random_state=42
    )

    model = train_model(X_train, y_train, config)
    evaluate_model(model, X_test, y_test)

    # Guardar artefactos del modelo
    save_model_artifacts(model, config, feature_names)

    print("\n✅ Entrenamiento finalizado con éxito.")


# -----------------------------------------------------------------------------
# 🏁 EJECUCIÓN
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Entrenador de modelos para detección de amenazas")
    parser.add_argument("--force_train", action="store_true", help="Forzar reentrenamiento del modelo")
    parser.add_argument("--max_rows", type=int, default=0, help="Limitar la carga a N filas del dataset")

    args = parser.parse_args()
    main(force_train=args.force_train, max_rows=args.max_rows)