
#!/usr/bin/env python3
import os
import sys
import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
import joblib  # para guardar modelos sklearn
from some_ml_library import train_model, evaluate_model  # Tu lógica ML
import etcd3  # cliente etcd3 para Python

# model-axiom-retrainer.py:
#     - registra inicio en etcd (status = running, timestamp, etc)
#     - carga modelos base y axiomas
#     - reentrena modelos
#     - evalúa calidad
#     - si pasa criterio, guarda modelo nuevo y actualiza etcd (status=done, version=XYZ, path=..., hash=...)
#    - si falla, status=error, mensaje
#     - finaliza

class ModelAxiomRetrainer:
    def __init__(self, config_path):
        self.load_config(config_path)
        self.setup_logging()
        self.etcd_client = etcd3.client(host=self.config["etcd"]["host"], port=self.config["etcd"]["port"])
        self.model_base_path = self.config["paths"]["model_base_path"]
        self.axioms_processed_dir = self.config["paths"]["axioms_processed_dir"]
        self.models_output_dir = self.config["paths"]["models_output_dir"]
        self.model_version_prefix = self.config["model"]["version_prefix"]

    def load_config(self, path):
        with open(path, "r") as f:
            self.config = json.load(f)

    def setup_logging(self):
        logging.basicConfig(level=logging.INFO)
        self.log = logging.getLogger("ModelAxiomRetrainer")

    def get_current_model_version(self):
        version, _ = self.etcd_client.get("/models/ml_detector/current_version")
        return version.decode() if version else None

    def register_training_start(self, version):
        key = f"/models/ml_detector/{version}/status"
        self.etcd_client.put(key, "training", lease=self.etcd_client.lease(ttl=3600))
        self.log.info(f"Registered training start for version {version}")

    def register_training_end(self, version, model_path, model_hash, success=True, message=""):
        base_key = f"/models/ml_detector/{version}"
        status = "ready" if success else "error"
        self.etcd_client.put(f"{base_key}/status", status)
        self.etcd_client.put(f"{base_key}/path", model_path)
        self.etcd_client.put(f"{base_key}/hash", model_hash)
        self.etcd_client.put(f"{base_key}/last_update", datetime.utcnow().isoformat() + "Z")
        if success:
            self.etcd_client.put("/models/ml_detector/current_version", version)
        if message:
            self.etcd_client.put(f"{base_key}/message", message)
        self.log.info(f"Registered training end for version {version} with status {status}")

    def compute_hash(self, filepath):
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return "sha256:" + hasher.hexdigest()

    def load_base_model(self):
        current_version = self.get_current_model_version()
        if not current_version:
            self.log.error("No current model version found in etcd.")
            sys.exit(1)
        model_path = os.path.join(self.model_base_path, f"model_{current_version}.joblib")
        if not os.path.isfile(model_path):
            self.log.error(f"Base model file not found: {model_path}")
            sys.exit(1)
        self.log.info(f"Loading base model version {current_version} from {model_path}")
        return joblib.load(model_path), current_version

    def load_axioms_data(self):
        # Aquí cargas los datos para reentrenar, desde los JSONs procesados
        # Parsear JSON, extraer features y etiquetas para reentrenar
        # Devuelve X_new, y_new
        pass

    def retrain(self):
        model, current_version = self.load_base_model()
        X_new, y_new = self.load_axioms_data()

        new_version = f"{self.model_version_prefix}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        self.register_training_start(new_version)

        try:
            # Aquí tu código real de reentreno, por ejemplo:
            model.fit(X_new, y_new)

            # Guardar modelo nuevo
            Path(self.models_output_dir).mkdir(parents=True, exist_ok=True)
            model_file = os.path.join(self.models_output_dir, f"model_{new_version}.joblib")
            joblib.dump(model, model_file)

            model_hash = self.compute_hash(model_file)
            self.log.info(f"Model retrained and saved as {model_file}")

            # Opcional: evaluar modelo
            # metrics = evaluate_model(model, X_test, y_test)
            # self.log.info(f"Evaluation metrics: {metrics}")

            self.register_training_end(new_version, model_file, model_hash, success=True)
        except Exception as e:
            self.log.error(f"Error during re-training: {e}")
            self.register_training_end(new_version, "", "", success=False, message=str(e))
            sys.exit(2)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 model-axiom-retrainer.py <config_path>")
        sys.exit(1)
    config_path = sys.argv[1]

    retrainer = ModelAxiomRetrainer(config_path)
    retrainer.retrain()

if __name__ == "__main__":
    main()
