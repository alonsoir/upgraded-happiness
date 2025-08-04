import pandas as pd
import joblib
import sys

# Parámetros
CSV_PATH = "your_input.csv"  # <-- Cambia esto
MODEL_PATH = "models/rf_model.joblib"
SCALER_PATH = "models/scaler.joblib"
FEATURE_ORDER_PATH = "models/feature_order.txt"

# 1. Carga el CSV
try:
    df = pd.read_csv(CSV_PATH)
    print(f"[✓] CSV cargado: {CSV_PATH}")
except Exception as e:
    print(f"[✗] Error al leer el CSV: {e}")
    sys.exit(1)

# 2. Carga el orden esperado de columnas
try:
    with open(FEATURE_ORDER_PATH) as f:
        expected_columns = [line.strip() for line in f]
    print(f"[✓] Orden de columnas esperado cargado")
except Exception as e:
    print(f"[✗] No se pudo leer el archivo de orden de columnas: {e}")
    sys.exit(1)

# 3. Verifica columnas faltantes o extra
missing = set(expected_columns) - set(df.columns)
extra = set(df.columns) - set(expected_columns)

if missing:
    print(f"[✗] Columnas faltantes: {missing}")
if extra:
    print(f"[✗] Columnas inesperadas: {extra}")

if missing:
    sys.exit(1)

# 4. Reordena columnas
df = df[expected_columns]

# 5. Verifica tipos de datos
non_numeric = df.select_dtypes(exclude=["number"]).columns
if len(non_numeric) > 0:
    print(f"[✗] Columnas no numéricas encontradas: {non_numeric.tolist()}")
    sys.exit(1)

# 6. Verifica valores nulos
if df.isnull().any().any():
    print(f"[✗] Hay valores nulos en el CSV. Usa df.dropna() o df.fillna().")
    print(df.isnull().sum()[df.isnull().sum() > 0])
    sys.exit(1)

# 7. Verifica el número de columnas frente al modelo
try:
    model = joblib.load(MODEL_PATH)
    if hasattr(model, "n_features_in_") and model.n_features_in_ != df.shape[1]:
        print(f"[✗] El modelo espera {model.n_features_in_} columnas, pero el CSV tiene {df.shape[1]}.")
        sys.exit(1)
except Exception as e:
    print(f"[✗] No se pudo cargar el modelo para verificar dimensiones: {e}")
    sys.exit(1)

# 8. Verifica escalado
try:
    scaler = joblib.load(SCALER_PATH)
    _ = scaler.transform(df)
    print(f"[✓] Escalado exitoso con StandardScaler")
except Exception as e:
    print(f"[✗] Error al aplicar scaler: {e}")
    sys.exit(1)

print("[✓] Todo correcto: puedes usar este CSV con el modelo.")

