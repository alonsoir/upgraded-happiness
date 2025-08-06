import pandas as pd
import joblib
import sys
import os

# CONFIGURACIÓN
CSV_PATH = "data/events_legitimate.csv"         # <-- CSV de entrada
MODEL_PATH = "models/rf_model.joblib"           # <-- Modelo RandomForest entrenado
SCALER_PATH = "models/scaler.joblib"            # <-- Scaler original (StandardScaler)
FEATURE_ORDER_PATH = "models/feature_order.txt" # <-- Orden de columnas usada en el entrenamiento

def validate():
    print("⏳ Validando CSV...")

    # 1. Carga CSV
    try:
        df = pd.read_csv(CSV_PATH)
        print(f"✅ CSV cargado: {CSV_PATH}")
    except Exception as e:
        print(f"❌ Error al leer el CSV: {e}")
        sys.exit(1)

    # 2. Carga orden de columnas
    try:
        with open(FEATURE_ORDER_PATH, "r") as f:
            expected_columns = [line.strip() for line in f.readlines()]
        print("✅ Orden de columnas cargado")
    except Exception as e:
        print(f"❌ No se pudo cargar el orden de columnas esperado: {e}")
        sys.exit(1)

    # 3. Verifica columnas faltantes o extra
    missing = set(expected_columns) - set(df.columns)
    extra = set(df.columns) - set(expected_columns)

    if missing:
        print(f"❌ Columnas faltantes en el CSV: {sorted(missing)}")
    if extra:
        print(f"⚠️ Columnas inesperadas (se ignorarán): {sorted(extra)}")

    if missing:
        sys.exit(1)

    # 4. Reordenar columnas
    df = df[expected_columns]

    # 5. Tipos de dato
    non_numeric = df.select_dtypes(exclude=["number"]).columns
    if len(non_numeric) > 0:
        print(f"❌ Columnas no numéricas: {list(non_numeric)}")
        sys.exit(1)

    # 6. Valores nulos
    if df.isnull().any().any():
        print("❌ Hay valores nulos en el CSV:")
        print(df.isnull().sum()[df.isnull().sum() > 0])
        sys.exit(1)

    # 7. Verifica número de columnas vs modelo
    try:
        model = joblib.load(MODEL_PATH)
        if hasattr(model, "n_features_in_") and model.n_features_in_ != df.shape[1]:
            print(f"❌ El modelo espera {model.n_features_in_} columnas, pero el CSV tiene {df.shape[1]}")
            sys.exit(1)
        print("✅ Modelo cargado y número de columnas verificado")
    except Exception as e:
        print(f"❌ No se pudo cargar el modelo: {e}")
        sys.exit(1)

    # 8. Escalado con scaler original
    try:
        scaler = joblib.load(SCALER_PATH)
        _ = scaler.transform(df)
        print("✅ Escalado exitoso con el scaler original")
    except Exception as e:
        print(f"❌ Error al aplicar el scaler: {e}")
        sys.exit(1)

    print("✅✅ Validación completa. El CSV es compatible con el modelo.")

if __name__ == "__main__":
    validate()
