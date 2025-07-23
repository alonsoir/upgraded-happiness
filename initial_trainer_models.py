import json
import argparse
import logging
import os
import subprocess
from datetime import datetime
import pandas as pd
import numpy as np
from kaggle.api.kaggle_api_extended import KaggleApi
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.ensemble import RandomForestClassifier
import joblib

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Columnas numéricas del dataset Edge-IIoTset
used_columns = [
    'arp.opcode', 'arp.hw.size', 'icmp.checksum', 'icmp.seq_le', 'icmp.transmit_timestamp',
    'icmp.unused', 'http.content_length', 'http.response', 'http.tls_port', 'tcp.ack',
    'tcp.ack_raw', 'tcp.checksum', 'tcp.connection.fin', 'tcp.connection.rst',
    'tcp.connection.syn', 'tcp.connection.synack', 'tcp.dstport', 'tcp.flags',
    'tcp.flags.ack', 'tcp.len', 'tcp.seq', 'udp.port', 'udp.stream', 'udp.time_delta',
    'dns.qry.name', 'dns.qry.qu', 'dns.qry.type', 'dns.retransmission',
    'dns.retransmit_request', 'dns.retransmit_request_in', 'mqtt.conflag.cleansess',
    'mqtt.conflags', 'mqtt.hdrflags', 'mqtt.len', 'mqtt.msg_decoded_as', 'mqtt.msgtype',
    'mqtt.proto_len', 'mqtt.topic_len', 'mqtt.ver', 'mbtcp.len', 'mbtcp.trans_id', 'mbtcp.unit_id'
]


# Función para verificar la configuración de Kaggle
def check_kaggle_config():
    kaggle_json = os.path.expanduser("~/.kaggle/kaggle.json")
    if not os.path.exists(kaggle_json):
        logging.error("Archivo kaggle.json no encontrado en ~/.kaggle/")
        raise FileNotFoundError(
            "Coloca kaggle.json en ~/.kaggle/ y ajusta permisos con 'chmod 600 ~/.kaggle/kaggle.json'")
    try:
        subprocess.run(['kaggle', 'datasets', 'list'], check=True, capture_output=True)
        logging.info("Autenticación de Kaggle API exitosa")
    except subprocess.CalledProcessError:
        logging.error("Fallo en la autenticación de Kaggle. Verifica kaggle.json y conexión a internet.")
        raise


# Función para verificar si el dataset está actualizado
def is_dataset_updated(dataset_slug, csv_path):
    if not os.path.exists(csv_path):
        logging.info(f"Archivo {csv_path} no existe localmente. Se descargará.")
        return True
    try:
        api = KaggleApi()
        api.authenticate()
        metadata_path = os.path.join(os.path.dirname(csv_path), "dataset-metadata.json")
        api.dataset_metadata(dataset_slug, path=os.path.dirname(metadata_path))
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        last_updated = metadata.get('lastUpdated')
        if not last_updated:
            logging.warning("No se encontró 'lastUpdated' en el metadata. Usando archivo local.")
            return False
        remote_last_modified = datetime.strptime(last_updated, '%Y-%m-%dT%H:%M:%S.%fZ')
        local_last_modified = datetime.fromtimestamp(os.path.getmtime(csv_path))
        if remote_last_modified > local_last_modified:
            logging.info(f"Dataset remoto ({remote_last_modified}) más reciente que local ({local_last_modified}).")
            return True
        logging.info("Dataset local está actualizado.")
        return False
    except Exception as e:
        logging.warning(f"No se pudo verificar la actualización del dataset: {e}. Usando archivo local si existe.")
        return False


# Función para descargar dataset desde Kaggle
def download_kaggle_dataset(dataset_slug, output_path, force_download=False):
    target_csv = os.path.join(output_path, "dataset", "Edge-IIoTset dataset", "Selected dataset for ML and DL",
                              "DNN-EdgeIIoT-dataset.csv")
    if not force_download and os.path.exists(target_csv) and not is_dataset_updated(dataset_slug, target_csv):
        logging.info(f"Dataset ya existe en {target_csv} y está actualizado. No se descargará.")
        return os.path.dirname(target_csv)
    os.makedirs(output_path, exist_ok=True)
    try:
        logging.info(f"Descargando dataset {dataset_slug}...")
        subprocess.run(['kaggle', 'datasets', 'download', '-d', dataset_slug, '-p', output_path], check=True)
        for file in os.listdir(output_path):
            if file.endswith('.zip'):
                logging.info(f"Descomprimiendo {file}...")
                subprocess.run(['unzip', '-o', f'{output_path}/{file}', '-d', f'{output_path}/dataset'], check=True)
                os.remove(f'{output_path}/{file}')
        return f"{output_path}/dataset"
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al descargar/descomprimir el dataset: {e}")
        raise


# Función para encontrar el archivo CSV
def find_csv_file(base_path, target_file="DNN-EdgeIIoT-dataset.csv"):
    for root, _, files in os.walk(base_path):
        if target_file in files:
            csv_path = os.path.join(root, target_file)
            logging.info(f"Archivo CSV encontrado: {csv_path}")
            return csv_path
    logging.error(f"No se encontró {target_file} en {base_path}")
    raise FileNotFoundError(f"No se encontró {target_file} en {base_path}")


# Función para verificar si es necesario reentrenar
def needs_retraining(model_dir, csv_path, new_events_path=None, config=None):
    enabled_models = [f"{k}_model.pkl" for k, v in config["ml"]["models"].items() if v["enabled"]]
    if config["ml"]["models"].get("kmeans", {}).get("enabled", False):
        enabled_models.append("kmeans_anomaly_threshold.pkl")
    if not all(os.path.exists(os.path.join(model_dir, f)) for f in enabled_models):
        logging.info("Faltan algunos modelos. Se requiere reentrenamiento.")
        return True
    model_mtime = min(os.path.getmtime(os.path.join(model_dir, f)) for f in enabled_models)
    data_mtime = os.path.getmtime(csv_path)
    if new_events_path and os.path.exists(new_events_path):
        data_mtime = max(data_mtime, os.path.getmtime(new_events_path))
    if data_mtime > model_mtime:
        logging.info("Datos más recientes que los modelos. Se requiere reentrenamiento.")
        return True
    logging.info("Modelos están actualizados con los datos.")
    return False


# Función para cargar y preprocesar datos
def load_and_preprocess_data(csv_path, new_events_path=None, columns=None):
    logging.info(f"Cargando datos desde {csv_path}...")
    try:
        df = pd.read_csv(csv_path, low_memory=False)
    except FileNotFoundError:
        logging.error(f"Archivo {csv_path} no encontrado.")
        raise
    logging.info(f"Columnas disponibles en el dataset: {list(df.columns)}")
    if new_events_path and os.path.exists(new_events_path):
        df_new = pd.read_csv(new_events_path, low_memory=False)
        df = pd.concat([df, df_new], ignore_index=True)
        logging.info(f"Datos nuevos añadidos desde {new_events_path}")
    if columns is None:
        columns = used_columns
    if not set(columns).issubset(df.columns):
        logging.warning("Algunas columnas esperadas no están disponibles. Seleccionando columnas numéricas...")
        columns = [col for col in used_columns if col in df.columns]
        if not columns:
            columns = df.select_dtypes(include=[np.number]).columns.tolist()
            columns = [col for col in columns if col not in ['Attack_label', 'Attack_type']]
            logging.info(f"Columnas numéricas seleccionadas: {columns}")
    if not columns:
        logging.error("No se encontraron columnas numéricas válidas en el dataset.")
        raise ValueError("No se encontraron columnas numéricas válidas para entrenar.")
    X = df[columns].fillna(0)
    y = df['Attack_label'].fillna(0) if 'Attack_label' in df.columns else np.zeros(len(X))
    # Separar datos normales para modelos no supervisados
    X_normal = X[df['Attack_label'] == 0] if 'Attack_label' in df.columns else X
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_normal_scaled = scaler.transform(X_normal)
    joblib.dump(scaler, "models/scaler.pkl")
    logging.info(f"Datos preprocesados con columnas: {columns}")
    return X_scaled, X_normal_scaled, y, scaler, columns


# Función para entrenar modelos
def train_models(X_scaled, X_normal_scaled, y, config, columns, max_rows=0):
    os.makedirs("models", exist_ok=True)
    logging.info("Entrenando modelos...")
    X_scaled_sub = X_scaled if max_rows == 0 else X_scaled[:max_rows] if len(X_scaled) > max_rows else X_scaled
    X_normal_scaled_sub = X_normal_scaled if max_rows == 0 else X_normal_scaled[:max_rows] if len(
        X_normal_scaled) > max_rows else X_normal_scaled
    y_sub = y if max_rows == 0 else y[:max_rows] if len(y) > max_rows else y
    logging.info(f"Usando {len(X_scaled_sub)} filas para entrenamiento")
    if config["ml"]["models"]["isolation_forest"]["enabled"]:
        model = IsolationForest(
            contamination=0.2,  # Aumentado para mayor sensibilidad
            n_estimators=config["ml"]["models"]["isolation_forest"]["n_estimators"],
            random_state=config["ml"]["models"]["isolation_forest"]["random_state"],
            n_jobs=config["ml"]["models"]["isolation_forest"]["n_jobs"],
            max_samples=512
        )
        model.fit(X_normal_scaled_sub)  # Entrenar solo con datos normales
        joblib.dump(model, "models/isolation_forest_model.pkl")
        logging.info("Isolation Forest entrenado")
    if config["ml"]["models"]["kmeans"]["enabled"]:
        model = KMeans(
            n_clusters=config["ml"]["models"]["kmeans"]["n_clusters"],
            n_init=config["ml"]["models"]["kmeans"]["n_init"],
            random_state=config["ml"]["models"]["kmeans"]["random_state"]
        )
        model.fit(X_normal_scaled_sub)  # Entrenar solo con datos normales
        anomaly_threshold = np.percentile(np.min(model.transform(X_normal_scaled_sub), axis=1), 95)
        joblib.dump(model, "models/kmeans_model.pkl")
        joblib.dump(anomaly_threshold, "models/kmeans_anomaly_threshold.pkl")
        logging.info("KMeans entrenado")
    if config["ml"]["models"]["one_class_svm"]["enabled"]:
        model = OneClassSVM(
            nu=0.01,  # Aumentado para mayor sensibilidad
            kernel=config["ml"]["models"]["one_class_svm"]["kernel"],
            gamma=config["ml"]["models"]["one_class_svm"]["gamma"]
        )
        svm_rows = min(len(X_normal_scaled_sub), 100000)
        model.fit(X_normal_scaled_sub[:svm_rows])  # Entrenar solo con datos normales
        joblib.dump(model, "models/one_class_svm_model.pkl")
        logging.info("One-Class SVM entrenado")
    if config["ml"]["models"]["local_outlier_factor"]["enabled"]:
        model = LocalOutlierFactor(
            n_neighbors=config["ml"]["models"]["local_outlier_factor"]["n_neighbors"],
            contamination=0.2,  # Aumentado para mayor sensibilidad
            novelty=True
        )
        lof_rows = min(len(X_normal_scaled_sub), 100000)
        model.fit(X_normal_scaled_sub[:lof_rows])  # Entrenar solo con datos normales
        joblib.dump(model, "models/local_outlier_factor_model.pkl")
        logging.info("LOF entrenado")
    if config["ml"]["models"]["random_forest"]["enabled"]:
        model = RandomForestClassifier(
            n_estimators=config["ml"]["models"]["random_forest"]["n_estimators"],
            max_depth=config["ml"]["models"]["random_forest"]["max_depth"],
            random_state=config["ml"]["models"]["random_forest"]["random_state"],
            n_jobs=config["ml"]["models"]["random_forest"]["n_jobs"],
            class_weight="balanced_subsample"
        )
        model.fit(X_scaled_sub, y_sub)  # Usar todos los datos para Random Forest
        joblib.dump(model, "models/random_forest_model.pkl")
        logging.info("Random Forest entrenado")


# Función para calcular el score de riesgo
def get_risk_score(X_new, models, scaler, columns, weights=None, config=None):
    X_new = X_new[columns].fillna(0)
    X_scaled = scaler.transform(X_new)
    scores = {}
    if models.get("isolation_forest"):
        if_score = models["isolation_forest"].decision_function(X_scaled)
        scores["isolation_forest"] = np.clip((if_score + 1) / 2, 0, 1)  # Convertir [-1, 1] a [0, 1]
    if models.get("kmeans"):
        km_distances = models["kmeans"].transform(X_scaled)
        km_score = np.min(km_distances, axis=1)
        anomaly_threshold = joblib.load("models/kmeans_anomaly_threshold.pkl")
        scores["kmeans"] = np.clip(km_score / (anomaly_threshold + 1e-10), 0, 1)
    if models.get("one_class_svm"):
        svm_score = models["one_class_svm"].decision_function(X_scaled)
        scores["one_class_svm"] = np.clip((svm_score + 1) / 2, 0, 1)  # Convertir [-1, 1] a [0, 1]
    if models.get("local_outlier_factor"):
        lof_score = models["local_outlier_factor"].decision_function(X_scaled)
        scores["local_outlier_factor"] = np.clip((lof_score + 1) / 2, 0, 1)  # Convertir [-1, 1] a [0, 1]
    if models.get("random_forest"):
        rf_score = models["random_forest"].predict_proba(X_scaled)[:, 1]
        scores["random_forest"] = rf_score
    if not scores:
        logging.error("No se encontraron modelos válidos para calcular el score de riesgo.")
        raise ValueError("No hay modelos habilitados.")
    if not weights:
        weights = [1 / len(scores)] * len(scores)
    weights_dict = dict(zip(scores.keys(), weights))
    risk_score = np.average(list(scores.values()), axis=0, weights=weights)
    is_anomaly = risk_score > config["ml"]["anomaly_threshold"]
    is_high_risk = risk_score > config["ml"]["high_risk_threshold"]
    return risk_score, is_anomaly, is_high_risk, scores


# Función principal
def main(force_download=False, force_train=False, max_rows=0):
    check_kaggle_config()
    try:
        with open("config-ml-trainer.json") as f:
            config = json.load(f)
        if "ml" not in config or "models" not in config["ml"]:
            logging.error("El archivo config-ml-trainer.json no tiene la estructura esperada: falta 'ml' o 'models'.")
            raise ValueError("Estructura inválida en config-ml-trainer.json")
    except FileNotFoundError:
        logging.error("Archivo config-ml-trainer.json no encontrado.")
        raise
    dataset_slug = "mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot"
    dataset_path = download_kaggle_dataset(dataset_slug, "data", force_download=force_download)
    csv_path = find_csv_file(dataset_path, "DNN-EdgeIIoT-dataset.csv")
    new_events_path = "data/new_events.csv"
    columns = used_columns
    scaler = None
    models = {}
    if not force_train and not needs_retraining("models", csv_path, new_events_path, config):
        logging.info("No es necesario reentrenar. Cargando modelos existentes...")
        models = {k: joblib.load(f"models/{k}_model.pkl") for k, v in config["ml"]["models"].items() if v["enabled"]}
        scaler = joblib.load("models/scaler.pkl")
    else:
        X_scaled, X_normal_scaled, y, scaler, columns = load_and_preprocess_data(csv_path, new_events_path,
                                                                                 used_columns)
        train_models(X_scaled, X_normal_scaled, y, config, columns, max_rows=max_rows)
        models = {k: joblib.load(f"models/{k}_model.pkl") for k, v in config["ml"]["models"].items() if v["enabled"]}
        scaler = joblib.load("models/scaler.pkl")

    # Evento de prueba simulando un ataque DDoS
    new_event = pd.DataFrame(
        [[0, 0, 0, 0, 0, 0, 2000, 0, 0, 2000000, 2000000, 12345, 0, 0, 1, 0, 80, 0x02, 0, 2000, 2000,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
        columns=columns
    )  # Simula DDoS: tcp.len=2000, tcp.connection.syn=1, tcp.dstport=80
    weights = [0.1, 0.1, 0.1, 0.1, 0.6]  # Priorizar Random Forest
    risk_score, is_anomaly, is_high_risk, scores = get_risk_score(new_event, models, scaler, columns, weights, config)
    logging.info(f"Risk Score: {risk_score[0]:.2f}, Anomaly: {is_anomaly[0]}, High Risk: {is_high_risk[0]}")
    logging.info(f"Scores por modelo: { {k: v[0] for k, v in scores.items()} }")
    new_event['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_event['src_ip'] = '192.168.1.10'
    new_event['dst_ip'] = '10.0.0.1'
    new_event.to_csv(new_events_path, mode='a', header=not os.path.exists(new_events_path), index=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--force_download", action="store_true", help="Forzar la descarga del dataset")
    parser.add_argument("--force_train", action="store_true", help="Forzar el reentrenamiento de modelos")
    parser.add_argument("--max_rows", type=int, default=0, help="Número máximo de filas para entrenar (0 = todas)")
    args = parser.parse_args()
    main(force_download=args.force_download, force_train=args.force_train, max_rows=args.max_rows)