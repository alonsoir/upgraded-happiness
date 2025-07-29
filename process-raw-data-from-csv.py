import pandas as pd

# Carga original
df = pd.read_csv("data/UNSW-NB15.csv")

# Selecciona las columnas numéricas que el modelo usa
numerical_features = [
    "dur",
    "proto",
    "service",
    "state",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "src_country",
    "src_asn",
    "country_risk",
    "distance_km"
]


# Codifica las columnas categóricas si las hay (por ejemplo, 'proto', 'service', 'state')
# Esto debe ser exactamente igual que en entrenamiento (usualmente LabelEncoder o OneHotEncoder)
from sklearn.preprocessing import LabelEncoder

for col in ['proto', 'service', 'state']:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
# Agregar columnas faltantes si no existen
for col, default in {
    "src_country": "unknown",       # Categoría ficticia, se codificará más adelante
    "src_asn": -1,                  # ASN desconocido
    "country_risk": 0.5,            # Riesgo medio
    "distance_km": 500.0            # Distancia media
}.items():
    if col not in df.columns:
        df[col] = default

# Ahora selecciona solo las columnas que necesitas
df_num = df[numerical_features]

# Guarda CSV para inferencia
df_num.to_csv("data/UNSW-NB15_preprocessed.csv", index=False)
