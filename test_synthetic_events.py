import os
import numpy as np
import pandas as pd
import joblib
import json
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Características compatibles con UNSW-NB15 (tras limpieza)
used_columns = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt'
]


def get_risk_score(X_new, models, columns, weights=None, config=None):
    """Calcula el riesgo usando múltiples modelos de detección"""
    X_new = X_new[columns].fillna(0)
    scores = {}

    # Calcular scores para cada modelo disponible
    if models.get("isolation_forest"):
        if_score = models["isolation_forest"].decision_function(X_new)
        scores["isolation_forest"] = np.clip((if_score + 1) / 2, 0, 1)

    if models.get("kmeans"):
        km_distances = models["kmeans"].transform(X_new)
        km_score = np.min(km_distances, axis=1)
        threshold_path = "models/kmeans_anomaly_threshold.pkl"
        if os.path.exists(threshold_path):
            anomaly_threshold = joblib.load(threshold_path)
        else:
            anomaly_threshold = np.percentile(km_score, 95)
        scores["kmeans"] = np.clip(1 - (km_score / (anomaly_threshold + 1e-10)), 0, 1)

    if models.get("one_class_svm"):
        svm_score = models["one_class_svm"].decision_function(X_new)
        scores["one_class_svm"] = np.clip((svm_score + 1) / 2, 0, 1)

    if models.get("random_forest"):
        rf_score = models["random_forest"].predict_proba(X_new)[:, 1]
        scores["random_forest"] = rf_score

    if not scores:
        logging.error("No se encontraron modelos válidos para calcular el score de riesgo.")
        raise ValueError("No hay modelos habilitados.")

    # Ajustar pesos al número de modelos disponibles
    n_models = len(scores)
    if weights:
        # Tomar solo los primeros n_models pesos si hay más de los necesarios
        weights = weights[:n_models]
        # Normalizar los pesos para que sumen 1
        total_weight = sum(weights)
        weights = [w / total_weight for w in weights]
    else:
        # Usar pesos uniformes si no se especifican
        weights = [1 / n_models] * n_models

    # Calcular risk_score como promedio ponderado
    scores_list = list(scores.values())
    risk_score = np.average(scores_list, axis=0, weights=weights)

    # Calcular flags de riesgo
    is_anomaly = risk_score > config["ml"]["anomaly_threshold"]
    is_high_risk = risk_score > config["ml"]["high_risk_threshold"]

    return risk_score, is_anomaly, is_high_risk, scores


def main():
    """Función principal para probar eventos sintéticos"""
    print("Función principal para probar eventos sintéticos...")
    # Cargar modelos disponibles
    models = {}
    model_names = ["isolation_forest", "kmeans", "one_class_svm", "random_forest"]

    for model_name in model_names:
        model_path = f"models/{model_name}_model.pkl"
        if os.path.exists(model_path):
            models[model_name] = joblib.load(model_path)
            logging.info(f"Modelo {model_name} cargado correctamente")
        else:
            logging.warning(f"Modelo {model_name} no encontrado. Saltando.")

    if not models:
        logging.error("No se pudo cargar ningún modelo. Verifica el directorio 'models/'")
        return

    # Cargar configuración
    with open("config-ml-trainer.json") as f:
        config = json.load(f)

    # Definir eventos sintéticos compatibles con UNSW-NB15
    events = [
        {
            'type': 'Normal',
            'data': [
                1.0,  # dur (duración)
                6,  # proto (TCP codificado)
                0,  # service (HTTP codificado)
                0,  # state (estado de conexión)
                2,  # spkts (paquetes origen)
                2,  # dpkts (paquetes destino)
                200,  # sbytes (bytes origen)
                200,  # dbytes (bytes destino)
                1.0,  # rate (tasa de paquetes)
                255,  # sttl (TTL origen)
                255,  # dttl (TTL destino)
                100.0,  # sload (carga origen)
                100.0,  # dload (carga destino)
                0,  # sloss (pérdidas origen)
                0,  # dloss (pérdidas destino)
                0.5,  # sinpkt (intervalo paquetes origen)
                0.5  # dinpkt (intervalo paquetes destino)
            ]
        },
        {
            'type': 'DDoS',
            'data': [
                0.05,  # dur (más corto)
                6,  # proto (TCP)
                0,  # service (HTTP)
                0,  # state
                50000,  # spkts (mucho más alto)
                0,  # dpkts
                2000000,  # sbytes (20x mayor)
                0,  # dbytes
                50000.0,  # rate (5x mayor)
                32,  # sttl (más bajo)
                0,  # dttl
                1000000.0,  # sload (más extremo)
                0.0,  # dload
                100,  # sloss (pérdidas altas)
                0,  # dloss
                0.0001,  # sinpkt (muy pequeño)
                0  # dinpkt
            ]
        },
        {
            'type': 'Port_Scan',
            'data': [
                0.1,  # dur
                6,  # proto (TCP)
                0,  # service (HTTP)
                0,  # state
                5000,  # spkts (más alto)
                0,  # dpkts
                500000,  # sbytes (5x mayor)
                0,  # dbytes
                20000.0,  # rate (4x mayor)
                64,  # sttl (más bajo)
                0,  # dttl
                1000000.0,  # sload (más extremo)
                0.0,  # dload
                50,  # sloss (pérdidas)
                0,  # dloss
                0.00005,  # sinpkt (muy pequeño)
                0  # dinpkt
            ]
        },
        {
            'type': 'Web_Attack',
            'data': [
                10.0,  # dur
                6,  # proto (TCP)
                1,  # service (otro servicio)
                1,  # state
                10,  # spkts
                10,  # dpkts
                5000,  # sbytes
                5000,  # dbytes
                1.0,  # rate
                255,  # sttl
                255,  # dttl
                500.0,  # sload
                500.0,  # dload
                0,  # sloss
                0,  # dloss
                1.0,  # sinpkt
                1.0  # dinpkt
            ]
        }
    ]

    new_events_path = "data/new_events.csv"

    # Ajustar pesos según los modelos disponibles
    n_models = len(models)
    if n_models == 1:
        weights = [1.0]  # Peso completo al único modelo disponible
    elif n_models == 2:
        weights = [0.3, 0.7]  # Mayor peso al segundo modelo
    elif n_models == 3:
        weights = [0.2, 0.3, 0.5]  # Mayor peso al último modelo
    else:
        weights = [0.1, 0.1, 0.1, 0.7]  # Pesos predeterminados para 4 modelos

    # Crear directorio si no existe
    os.makedirs(os.path.dirname(new_events_path), exist_ok=True)

    for event in events:
        df_event = pd.DataFrame([event['data']], columns=used_columns)

        risk_score, is_anomaly, is_high_risk, scores = get_risk_score(
            df_event, models, used_columns, weights, config
        )

        logging.info(
            f"Evento: {event['type']}, "
            f"Risk Score: {risk_score[0]:.4f}, "
            f"Anomaly: {is_anomaly[0]}, "
            f"High Risk: {is_high_risk[0]}"
        )

        logging.info(f"Scores por modelo: { {k: f'{v[0]:.4f}' for k, v in scores.items()} }")

        # Añadir metadatos
        df_event['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        df_event['src_ip'] = '192.168.1.10'
        df_event['dst_ip'] = '10.0.0.1'
        df_event['event_type'] = event['type']
        df_event['risk_score'] = risk_score[0]
        df_event['is_anomaly'] = is_anomaly[0]
        df_event['is_high_risk'] = is_high_risk[0]

        # Guardar en CSV (añadir si existe)
        df_event.to_csv(
            new_events_path,
            mode='a',
            header=not os.path.exists(new_events_path),
            index=False
        )

    logging.info(f"Eventos sintéticos guardados en {new_events_path}")


if __name__ == "__main__":
    main()