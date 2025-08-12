#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# scheduler-firewall-axiom.py
# ejemplo de como va a generar un json axioma para decidir si reentrenar modelos o no.

# Carga el mismo JSON de configuración y JSON de reglas que tu scheduler-firewall original (por ruta configurable).
# Escucha o recibe eventos protobuf tipo NetworkSecurityEvent (puedes adaptar la parte de entrada a cómo te llegan).
# Extrae el score ML y usa las reglas para decidir acción y regla.
# Genera un JSON "axioma candidato" y lo guarda en un fichero en el directorio ./axioms/, creando el directorio si no
# existe.
# No modifica ni toca nada de la lógica original ni de los comandos firewall, es un componente independiente para
# generar esos JSON ligeros.
# Añade un flag para decidir si reentrenar según confianza ML.

# Importa aquí tus protobuf generados, mas bien, esto es un componente como el scheduler-firewall original que recibe
# el payload protobuf 3.1 desde un topic zeroMQ, en concreto, el componente anterior es el ml_detector que lo trae completo
# junto con el score. Dicho score debe servir para decidir que recomendacion debe seguir el siguiente componente,
# simple_firewall_agent_v31.py. Esta modificacion propuesta serviría para que un componente asíncrono recoja y procese
# todos los json que esta modificacion propone, para decidir si debe reentrenar los modelos.
# from generated_protos.network_security_clean_v31_pb2 import NetworkSecurityEvent

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import zmq

# IMPORTA TU protobuf generado aquí:
# from generated_protos.network_security_clean_v31_pb2 import NetworkEvent as NetworkEventProto

# --- Configuraciones ---
CONFIG_PATH = "./config.json"
POLICY_RULES_PATH = "./firewall_rules.json"
AXIOM_TEMPLATE_PATH = "./axioms/templates/axiom_template.json"
AXIOM_OUTPUT_DIR = "./axioms"
ZMQ_ML_EVENTS_ENDPOINT = "tcp://localhost:5555"  # Cambia al endpoint real

# --- Funciones de carga ---
def load_json_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def find_rule_for_score(score: float, policy_json: dict):
    for rule in policy_json.get("rules", []):
        risk_min, risk_max = rule.get("risk_range", [0, 100])
        if risk_min <= score <= risk_max:
            return rule.get("description", "unknown_rule"), rule.get("action", "MONITOR")
    return "default_rule", "MONITOR"

def generate_axiom_candidate_from_template(event_proto, policy_json, template_path=AXIOM_TEMPLATE_PATH, proto_filename="network_security_clean_v3.1.proto", proto_version="3.1"):
    template = load_json_file(template_path)

    event_id = event_proto.event_id
    source_ip = event_proto.network_features.source_ip
    dest_ip = event_proto.network_features.destination_ip
    protocol = event_proto.network_features.protocol_name
    ml_pred = event_proto.ml_analysis.final_threat_classification
    ml_conf = event_proto.ml_analysis.ensemble_confidence

    rule, action = find_rule_for_score(ml_conf, policy_json)

    # Rellenar plantilla
    template["axiom_id"] = f"AX-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
    template["timestamp"] = datetime.utcnow().isoformat() + "Z"

    template["source_proto_info"]["proto_filename"] = proto_filename
    template["source_proto_info"]["proto_version"] = proto_version
    template["source_proto_info"]["message_type"] = "NetworkSecurityEvent"
    template["source_proto_info"]["message_id"] = event_id

    template["event"]["event_id"] = event_id
    template["event"]["source_ip"] = source_ip
    template["event"]["destination_ip"] = dest_ip
    template["event"]["protocol"] = protocol
    template["event"]["ml_prediction"] = ml_pred
    template["event"]["ml_confidence"] = ml_conf

    template["policy_context"]["rule_matched"] = rule
    template["policy_context"]["policy_action"] = action

    template["scheduler_decision"]["final_action"] = action
    template["scheduler_decision"]["reason"] = "policy override or scheduler decision"

    template["axiom"]["logic"] = f"forall e (AttackType(e) = {ml_pred} ∧ Confidence(e) > 0.9 → Action(e) = {action})"
    template["axiom"]["type"] = "dynamic"
    template["axiom"]["source"] = ["ml_prediction", "policy_context", "scheduler_decision"]

    template["training_flag"]["retrain_candidate"] = ml_conf < 0.7 and ml_pred != "BENIGN"
    template["training_flag"]["reason"] = "Low confidence on malicious prediction" if ml_conf < 0.7 and ml_pred != "BENIGN" else ""

    return template

def save_axiom(axiom: dict, output_dir=AXIOM_OUTPUT_DIR):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"{axiom['axiom_id']}.json"
    full_path = os.path.join(output_dir, filename)
    with open(full_path, "w", encoding="utf-8") as f:
        json.dump(axiom, f, indent=2)
    print(f"[INFO] Axiom saved to {full_path}")

# --- Funciones de recepción y parseo protobuf ---

def parse_ml_event(message_bytes: bytes, protobuf_cls) -> Optional[object]:
    """
    Parsea protobuf desde bytes a objeto protobuf.
    protobuf_cls es la clase protobuf (por ejemplo NetworkEventProto)
    """
    try:
        event = protobuf_cls()
        event.ParseFromString(message_bytes)
        return event
    except Exception as e:
        print(f"[WARN] Parse protobuf failed: {e}")
        return None

def ml_events_receiver_loop(zmq_context, protobuf_cls, policy_json, template_path=AXIOM_TEMPLATE_PATH):
    socket = zmq_context.socket(zmq.SUB)
    socket.connect(ZMQ_ML_EVENTS_ENDPOINT)
    socket.setsockopt_string(zmq.SUBSCRIBE, '')  # Suscribirse a todo

    print("[INFO] Starting ML events receiver loop")

    while True:
        try:
            message_bytes = socket.recv()
            event_proto = parse_ml_event(message_bytes, protobuf_cls)
            if event_proto:
                axiom = generate_axiom_candidate_from_template(event_proto, policy_json, template_path)
                save_axiom(axiom)
        except Exception as e:
            print(f"[ERROR] Error in ML events receiver loop: {e}")
        time.sleep(0.01)  # Ajustar según carga

def main():
    # Cargar configuración y reglas
    try:
        config_json = load_json_file(CONFIG_PATH)
        policy_json = load_json_file(POLICY_RULES_PATH)
    except Exception as e:
        print(f"[ERROR] Failed loading config or rules JSON: {e}")
        return

    # Inicializar ZeroMQ context
    zmq_context = zmq.Context()

    # IMPORTANTE: descomenta y ajusta el import y la clase protobuf real
    # from generated_protos.network_security_clean_v31_pb2 import NetworkEvent as NetworkEventProto

    # Llamar al receiver loop (bloqueante)
    # ml_events_receiver_loop(zmq_context, NetworkEventProto, policy_json)

if __name__ == "__main__":
    main()
