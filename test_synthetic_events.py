import os

import numpy as np
import pandas as pd
import joblib
import json
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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


def get_risk_score(X_new, models, scaler, columns, weights=None, config=None):
    X_new = X_new[columns].fillna(0)
    X_scaled = scaler.transform(X_new)
    scores = {}
    if models.get("isolation_forest"):
        if_score = models["isolation_forest"].decision_function(X_scaled)
        scores["isolation_forest"] = np.clip((if_score + 1) / 2, 0, 1)
    if models.get("kmeans"):
        km_distances = models["kmeans"].transform(X_scaled)
        km_score = np.min(km_distances, axis=1)
        anomaly_threshold = joblib.load("models/kmeans_anomaly_threshold.pkl")
        scores["kmeans"] = np.clip(km_score / (anomaly_threshold + 1e-10), 0, 1)
    if models.get("one_class_svm"):
        svm_score = models["one_class_svm"].decision_function(X_scaled)
        scores["one_class_svm"] = np.clip((svm_score + 1) / 2, 0, 1)
    if models.get("local_outlier_factor"):
        lof_score = models["local_outlier_factor"].decision_function(X_scaled)
        scores["local_outlier_factor"] = np.clip((lof_score + 1) / 2, 0, 1)
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


def main():
    models = {k: joblib.load(f"models/{k}_model.pkl") for k in
              ["isolation_forest", "kmeans", "one_class_svm", "local_outlier_factor", "random_forest"]}
    scaler = joblib.load("models/scaler.pkl")
    with open("config-ml-trainer.json") as f:
        config = json.load(f)

    events = [
        {'type': 'Normal',
         'data': [0, 0, 0, 0, 0, 0, 0, 0, 0, 1000, 1000, 12345, 0, 0, 0, 0, 80, 0x10, 1, 64, 1000, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]},
        {'type': 'DDoS',
         'data': [0, 0, 0, 0, 0, 0, 2000, 0, 0, 2000000, 2000000, 12345, 0, 0, 1, 0, 80, 0x02, 0, 2000, 2000, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]},
        {'type': 'Port_Scan',
         'data': [0, 0, 0, 0, 0, 0, 0, 0, 0, 1000, 1000, 12345, 0, 0, 1, 0, 445, 0x02, 0, 64, 1000, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]},
        {'type': 'MQTT_Attack',
         'data': [0, 0, 0, 0, 0, 0, 0, 0, 0, 1000, 1000, 12345, 0, 0, 0, 0, 1883, 0x10, 1, 128, 1000, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 1, 0x10, 0x10, 64, 0, 1, 4, 32, 3, 0, 0, 0]}
    ]

    new_events_path = "data/new_events.csv"
    weights = [0.1, 0.1, 0.1, 0.1, 0.6]
    for event in events:
        df_event = pd.DataFrame([event['data']], columns=used_columns)
        risk_score, is_anomaly, is_high_risk, scores = get_risk_score(df_event, models, scaler, used_columns, weights,
                                                                      config)
        logging.info(
            f"Evento: {event['type']}, Risk Score: {risk_score[0]:.2f}, Anomaly: {is_anomaly[0]}, High Risk: {is_high_risk[0]}")
        logging.info(f"Scores por modelo: { {k: v[0] for k, v in scores.items()} }")
        df_event['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        df_event['src_ip'] = '192.168.1.10'
        df_event['dst_ip'] = '10.0.0.1'
        df_event.to_csv(new_events_path, mode='a', header=not os.path.exists(new_events_path), index=False)

    logging.info(f"Eventos sintéticos guardados en {new_events_path}")


if __name__ == "__main__":
    main()