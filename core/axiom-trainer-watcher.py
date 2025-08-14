#!/usr/bin/env python3
import os
import sys
import time
import json
import shutil
import logging
from pathlib import Path
from collections import defaultdict

# axiom-trainer-watcher.py
# Va a vigilar la carpeta ./axioms, los va a procesar, para luego dejar otros ficheros json en ./axioms/processed
# Vigila constantemente la carpeta ./axioms para detectar nuevos archivos JSON (los axiomas generados).
# Los procesa (lee, parsea y acumula estadísticas relevantes como tipos de ataques, confianza ML, modelo
# implicado, etc.).
# Mueve los archivos procesados a ./axioms/processed para evitar reprocesamiento.
# Decide con reglas configurables (desde JSON config) cuándo es necesario iniciar un reentrenamiento.
# Registra logs con la decisión y razones.
# Si la regla se cumple, lanza el proceso de reentrenamiento o notifica a otro componente que lo ejecute
# (idealmente vía cola, señal o llamada REST interna).
# Su fichero json de configuracion es ./config/json/config_axiom_watcher.json

class ConfigError(Exception):
    pass

class AxiomTrainerWatcher:
    def __init__(self, config_path):
        self.config = self.load_config(config_path)
        self.setup_logging()
        self.validate_dirs()
        self.statistics = defaultdict(lambda: defaultdict(int))  # stats by model_type, attack_type, etc.

    def load_config(self, path):
        if not os.path.isfile(path):
            raise ConfigError(f"Configuration file not found: {path}")
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except Exception as e:
            raise ConfigError(f"Error parsing config JSON: {e}")

        # Validar claves esenciales y tipos
        required_keys = [
            "axioms_dir", "processed_dir", "poll_interval_seconds",
            "min_axioms_for_retrain", "confidence_threshold",
            "log_file", "rules"
        ]
        for key in required_keys:
            if key not in config:
                raise ConfigError(f"Missing required config key: {key}")

        # Validar sub-keys en rules
        rules_keys = ["model_types_to_monitor", "minimum_confidence", "require_retrain_flag"]
        for rkey in rules_keys:
            if rkey not in config["rules"]:
                raise ConfigError(f"Missing required config.rules key: {rkey}")

        # Más validaciones tipo pueden añadirse aquí

        return config

    def setup_logging(self):
        log_path = self.config["log_file"]
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            filename=log_path,
            filemode='a',
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s'
        )
        self.log = logging.getLogger("AxiomTrainerWatcher")
        self.log.info("Logger initialized")

    def validate_dirs(self):
        for d in [self.config["axioms_dir"], self.config["processed_dir"]]:
            Path(d).mkdir(parents=True, exist_ok=True)

    def load_json_file(self, filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def process_new_axioms(self):
        axioms = []
        for filename in os.listdir(self.config["axioms_dir"]):
            if filename.endswith(".json"):
                full_path = os.path.join(self.config["axioms_dir"], filename)
                try:
                    axiom = self.load_json_file(full_path)
                    axioms.append(axiom)
                    # Mover a processed para no procesar otra vez
                    dest_path = os.path.join(self.config["processed_dir"], filename)
                    shutil.move(full_path, dest_path)
                    self.log.info(f"Processed and moved axiom file: {filename}")
                except Exception as e:
                    self.log.error(f"Failed to process {filename}: {e}")
        return axioms

    def update_statistics(self, axioms):
        # Reiniciar stats cada vez
        self.statistics.clear()

        for ax in axioms:
            # Extraer info clave con seguridad
            model_type = ax.get("policy_context", {}).get("rule_matched", "UNKNOWN")
            ml_pred = ax.get("event", {}).get("ml_prediction", "UNKNOWN")
            confidence = ax.get("event", {}).get("ml_confidence", 0.0)
            retrain_flag = ax.get("training_flag", {}).get("retrain_candidate", False)

            if model_type not in self.statistics:
                self.statistics[model_type] = {"count": 0, "low_confidence": 0, "retrain_candidates": 0}
            self.statistics[model_type]["count"] += 1
            if confidence < self.config["rules"]["minimum_confidence"]:
                self.statistics[model_type]["low_confidence"] += 1
            if retrain_flag:
                self.statistics[model_type]["retrain_candidates"] += 1

    def should_retrain(self):
        # Aplicar reglas configurables
        for model_type in self.config["rules"]["model_types_to_monitor"]:
            stats = self.statistics.get(model_type, {})
            if not stats:
                continue
            if self.config["rules"]["require_retrain_flag"]:
                if stats.get("retrain_candidates", 0) >= self.config["min_axioms_for_retrain"]:
                    self.log.info(f"Re-train condition met for model {model_type} due to retrain_candidates")
                    return True
            else:
                if stats.get("low_confidence", 0) >= self.config["min_axioms_for_retrain"]:
                    self.log.info(f"Re-train condition met for model {model_type} due to low_confidence")
                    return True
        return False

    def run(self):
        self.log.info("Starting axiom-trainer-watcher main loop.")
        while True:
            try:
                axioms = self.process_new_axioms()
                if axioms:
                    self.update_statistics(axioms)
                    if self.should_retrain():
                        self.log.info("Decision: Trigger re-training process")
                        # Aquí solo logueamos. Lanzar otro componente o notificar por otro medio.
                    else:
                        self.log.info("No re-training required after evaluating axioms.")
                else:
                    self.log.info("No new axioms found.")
            except Exception as e:
                self.log.error(f"Unexpected error in main loop: {e}")

            time.sleep(self.config["poll_interval_seconds"])


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 axiom-trainer-watcher.py <config_json_path>")
        sys.exit(1)
    config_path = sys.argv[1]

    try:
        watcher = AxiomTrainerWatcher(config_path)
        watcher.run()
    except ConfigError as ce:
        print(f"[CONFIG ERROR] {ce}")
        sys.exit(2)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(3)
