
#!/usr/bin/env python3
# model-axiom-retrainer.py:
#     - registra inicio en etcd (status = running, timestamp, etc)
#     - carga modelos base y axiomas
#     - reentrena modelos
#     - evalúa calidad
#     - si pasa criterio, guarda modelo nuevo y actualiza etcd (status=done, version=XYZ, path=..., hash=...)
#    - si falla, status=error, mensaje
#     - finaliza

# !/usr/bin/env python3
"""
model-axiom-retrainer.py - Esquema básico
Reentrenador automático de modelos basado en axiomas
"""

import os
import json
import pickle
import gzip
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import logging

# Imports específicos de algoritmos (adaptar según inventario)
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier


class ModelAxiomRetrainer:
    """Reentrenador automático de modelos ML basado en axiomas"""

    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.algorithm_inventory = self._load_algorithm_inventory()
        self.setup_logging()

        # Directorios de trabajo
        self.staging_dir = Path(self.config["staging_dir"])
        self.production_dir = Path(self.config["production_dir"])
        self.data_dir = Path(self.config["training_data_dir"])

        # Validar y crear directorios
        for directory in [self.staging_dir, self.production_dir, self.data_dir]:
            directory.mkdir(parents=True, exist_ok=True)

    def _load_config(self, path: str) -> Dict:
        """Carga configuración de reentrenamiento"""
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _load_algorithm_inventory(self) -> Dict:
        """Carga inventario de algoritmos disponibles"""
        inventory_path = self.config["algorithm_inventory_path"]
        with open(inventory_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def setup_logging(self):
        """Configurar logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            handlers=[
                logging.FileHandler(self.config["log_file"]),
                logging.StreamHandler()
            ]
        )
        self.log = logging.getLogger("ModelAxiomRetrainer")

    def check_for_retraining_requests(self) -> List[Dict]:
        """Busca solicitudes de reentrenamiento del watcher"""
        requests = []
        notification_dir = Path(self.config["notification_dir"])

        if not notification_dir.exists():
            return requests

        for notification_file in notification_dir.glob("retrain_notification_*.json"):
            try:
                with open(notification_file, "r", encoding="utf-8") as f:
                    request = json.load(f)
                requests.append(request)

                # Mover a procesados
                processed_dir = notification_dir / "processed"
                processed_dir.mkdir(exist_ok=True)
                notification_file.rename(processed_dir / notification_file.name)

            except Exception as e:
                self.log.error(f"Error processing notification {notification_file}: {e}")

        return requests

    def load_training_data_from_axioms(self, model_type: str) -> Tuple[pd.DataFrame, np.ndarray]:
        """Carga datos de entrenamiento desde manifiestos de axiomas"""
        # Buscar manifiestos de entrenamiento para este modelo
        training_ready_dir = Path(self.config["training_ready_dir"])
        manifests = list(training_ready_dir.glob(f"training_manifest_{model_type}_*.json"))

        all_features = []
        all_labels = []

        for manifest_file in manifests:
            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest = json.load(f)

            # Cargar protobuf asociados y extraer features
            for protobuf_path in manifest["protobuf_files"]:
                if os.path.exists(protobuf_path):
                    features, label = self._extract_features_from_protobuf(protobuf_path)
                    if features is not None:
                        all_features.append(features)
                        all_labels.append(label)

        if not all_features:
            raise ValueError(f"No training data found for model {model_type}")

        # Combinar con datos históricos si está configurado
        if self.config.get("include_historical_data", True):
            historical_features, historical_labels = self._load_historical_data(model_type)
            all_features.extend(historical_features)
            all_labels.extend(historical_labels)

        X = pd.DataFrame(all_features)
        y = np.array(all_labels)

        self.log.info(f"Loaded {len(X)} samples for {model_type} retraining")
        return X, y

    def _extract_features_from_protobuf(self, protobuf_path: str) -> Tuple[Optional[List], Optional[str]]:
        """Extrae features de un archivo protobuf"""
        try:
            # Leer protobuf (adaptar según tu estructura)
            with gzip.open(protobuf_path, 'rb') if protobuf_path.endswith('.gz') else open(protobuf_path, 'rb') as f:
                protobuf_bytes = f.read()

            # Deserializar protobuf
            # event = NetworkSecurityEvent()
            # event.ParseFromString(protobuf_bytes)

            # Extraer 83 features (adaptar según tu estructura)
            # features = self._extract_83_features(event)
            # label = event.ml_analysis.final_threat_classification

            # Por ahora, retornar dummy data
            features = [0.0] * 83  # Placeholder
            label = "BENIGN"  # Placeholder

            return features, label

        except Exception as e:
            self.log.error(f"Error extracting features from {protobuf_path}: {e}")
            return None, None

    def _load_historical_data(self, model_type: str) -> Tuple[List, List]:
        """Carga datos históricos de entrenamiento"""
        # Implementar carga de datos históricos
        # Por ahora retornar listas vacías
        return [], []

    def select_optimal_algorithm(self, model_type: str, X: pd.DataFrame, y: np.ndarray) -> Dict:
        """Selecciona el algoritmo óptimo basado en datos y performance"""

        # Obtener configuración actual del modelo
        current_config = self._get_current_model_config(model_type)

        # Candidatos de algoritmos
        candidates = self.config["retraining_strategy"]["algorithm_candidates"]

        best_algorithm = None
        best_score = 0.0
        best_params = None

        for algorithm_name in candidates:
            if algorithm_name in self.algorithm_inventory["model_inventory"]["available_algorithms"][
                "supervised_learning"]:

                # Crear modelo con hiperparámetros por defecto
                model = self._create_model_instance(algorithm_name)

                # Evaluación cruzada rápida
                try:
                    scores = cross_val_score(model, X, y, cv=3, scoring='f1_weighted')
                    avg_score = scores.mean()

                    self.log.info(f"{algorithm_name} CV score: {avg_score:.3f}")

                    if avg_score > best_score:
                        best_score = avg_score
                        best_algorithm = algorithm_name
                        best_params = \
                        self.algorithm_inventory["model_inventory"]["available_algorithms"]["supervised_learning"][
                            algorithm_name]["hyperparameters"]

                except Exception as e:
                    self.log.warning(f"Failed to evaluate {algorithm_name}: {e}")

        return {
            "algorithm": best_algorithm,
            "expected_score": best_score,
            "hyperparameters": best_params,
            "improvement_over_current": best_score - current_config.get("performance_metrics", {}).get("f1_score", 0.0)
        }

    def _create_model_instance(self, algorithm_name: str):
        """Crea instancia del modelo según algoritmo"""
        if algorithm_name == "random_forest":
            return RandomForestClassifier(n_estimators=100, random_state=42)
        elif algorithm_name == "xgboost":
            return XGBClassifier(n_estimators=100, random_state=42)
        elif algorithm_name == "lightgbm":
            return LGBMClassifier(n_estimators=100, random_state=42)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm_name}")

    def _get_current_model_config(self, model_type: str) -> Dict:
        """Obtiene configuración del modelo actual en producción"""
        inventory = self.algorithm_inventory["model_inventory"]["current_production_models"]
        return inventory.get(model_type, {})

    def train_model(self, model_type: str, X: pd.DataFrame, y: np.ndarray, algorithm_config: Dict) -> Tuple[Any, Dict]:
        """Entrena modelo con algoritmo seleccionado"""

        # Dividir datos
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Crear modelo final
        model = self._create_model_instance(algorithm_config["algorithm"])

        # Entrenar
        self.log.info(f"Training {algorithm_config['algorithm']} for {model_type}")
        model.fit(X_train, y_train)

        # Evaluar
        y_pred = model.predict(X_test)

        # Métricas detalladas
        metrics = {
            "algorithm": algorithm_config["algorithm"],
            "training_samples": len(X_train),
            "test_samples": len(X_test),
            "training_date": datetime.utcnow().isoformat(),
            "classification_report": classification_report(y_test, y_pred, output_dict=True),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist()
        }

        self.log.info(
            f"Model training completed. F1-score: {metrics['classification_report']['weighted avg']['f1-score']:.3f}")

        return model, metrics

    def stage_model(self, model_type: str, model: Any, metrics: Dict) -> str:
        """Guarda modelo en staging para validación"""

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        version = f"retrained_{timestamp}"

        # Crear estructura en staging
        model_staging_dir = self.staging_dir / model_type / version
        model_staging_dir.mkdir(parents=True, exist_ok=True)

        # Guardar modelo
        model_file = model_staging_dir / "model.pkl"
        with open(model_file, "wb") as f:
            pickle.dump(model, f)

        # Guardar métricas
        metrics_file = model_staging_dir / "metrics.json"
        with open(metrics_file, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

        # Crear metadata
        metadata = {
            "model_type": model_type,
            "version": version,
            "algorithm": metrics["algorithm"],
            "staged_at": datetime.utcnow().isoformat(),
            "status": "staging",
            "files": {
                "model": str(model_file),
                "metrics": str(metrics_file)
            }
        }

        metadata_file = model_staging_dir / "metadata.json"
        with open(metadata_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        self.log.info(f"Model staged: {model_staging_dir}")
        return str(model_staging_dir)

    def run_validation_pipeline(self, staging_path: str) -> bool:
        """Ejecuta pipeline de validación en modelo staging"""

        validation_config = self.algorithm_inventory["model_inventory"]["staging_pipeline"]["validation_stages"]

        for stage_name, stage_config in validation_config.items():
            self.log.info(f"Running validation stage: {stage_name}")

            if not self._run_validation_stage(staging_path, stage_config):
                self.log.error(f"Validation failed at stage: {stage_name}")
                return False

        self.log.info("All validation stages passed")
        return True

    def _run_validation_stage(self, staging_path: str, stage_config: Dict) -> bool:
        """Ejecuta una etapa específica de validación"""

        # Implementar tests específicos
        for test_name in stage_config["tests"]:
            if test_name == "model_serialization_test":
                if not self._test_model_serialization(staging_path):
                    return False
            elif test_name == "prediction_latency_test":
                if not self._test_prediction_latency(staging_path, stage_config["pass_criteria"]):
                    return False
            # Añadir más tests según necesidad

        return True

    def _test_model_serialization(self, staging_path: str) -> bool:
        """Test de serialización del modelo"""
        try:
            model_file = Path(staging_path) / "model.pkl"
            with open(model_file, "rb") as f:
                model = pickle.load(f)
            return True
        except Exception as e:
            self.log.error(f"Serialization test failed: {e}")
            return False

    def _test_prediction_latency(self, staging_path: str, criteria: Dict) -> bool:
        """Test de latencia de predicción"""
        # Implementar test de latencia
        return True  # Placeholder

    def promote_to_production(self, staging_path: str) -> bool:
        """Promociona modelo de staging a producción"""

        try:
            staging_dir = Path(staging_path)

            # Leer metadata
            with open(staging_dir / "metadata.json", "r") as f:
                metadata = json.load(f)

            model_type = metadata["model_type"]

            # Crear directorio en producción
            prod_dir = self.production_dir / model_type
            prod_dir.mkdir(parents=True, exist_ok=True)

            # Backup modelo actual si existe
            current_model = prod_dir / "model.pkl"
            if current_model.exists():
                backup_dir = prod_dir / "backups"
                backup_dir.mkdir(exist_ok=True)
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                current_model.rename(backup_dir / f"model_backup_{timestamp}.pkl")

            # Copiar archivos de staging a producción
            for file_path in staging_dir.glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, prod_dir / file_path.name)

            # Actualizar metadata
            metadata["status"] = "production"
            metadata["promoted_at"] = datetime.utcnow().isoformat()

            with open(prod_dir / "metadata.json", "w") as f:
                json.dump(metadata, f, indent=2)

            self.log.info(f"Model promoted to production: {prod_dir}")

            # Notificar al ml-detector (cuando esté implementado)
            self._notify_ml_detector_new_model(model_type, str(prod_dir))

            return True

        except Exception as e:
            self.log.error(f"Promotion failed: {e}")
            return False

    def _notify_ml_detector_new_model(self, model_type: str, model_path: str):
        """Notifica al ml-detector sobre nuevo modelo"""
        # Crear notificación para ml-detector
        notification = {
            "event_type": "model_updated",
            "model_type": model_type,
            "model_path": model_path,
            "timestamp": datetime.utcnow().isoformat()
        }

        notification_dir = Path(self.config.get("ml_detector_notifications_dir", "./notifications/ml_detector"))
        notification_dir.mkdir(parents=True, exist_ok=True)

        notif_file = notification_dir / f"model_update_{model_type}_{int(time.time())}.json"

        with open(notif_file, "w") as f:
            json.dump(notification, f, indent=2)

        self.log.info(f"ML-detector notification sent: {notif_file}")

    def process_retraining_request(self, request: Dict):
        """Procesa una solicitud de reentrenamiento completa"""
        model_type = request["model_type"]

        try:
            self.log.info(f"Processing retraining request for {model_type}")

            # 1. Cargar datos de entrenamiento
            X, y = self.load_training_data_from_axioms(model_type)

            # 2. Seleccionar algoritmo óptimo
            algorithm_config = self.select_optimal_algorithm(model_type, X, y)

            # 3. Entrenar modelo
            model, metrics = self.train_model(model_type, X, y, algorithm_config)

            # 4. Staging
            staging_path = self.stage_model(model_type, model, metrics)

            # 5. Validación
            if self.run_validation_pipeline(staging_path):

                # 6. Promoción automática o manual según criterios
                promotion_criteria = self.algorithm_inventory["model_inventory"]["staging_pipeline"][
                    "promotion_criteria"]

                if self._should_auto_promote(algorithm_config, promotion_criteria):
                    if self.promote_to_production(staging_path):
                        self.log.info(f"Retraining completed successfully for {model_type}")
                    else:
                        self.log.error(f"Promotion failed for {model_type}")
                else:
                    self.log.info(f"Manual approval required for {model_type} promotion")
            else:
                self.log.error(f"Validation failed for {model_type}")

        except Exception as e:
            self.log.error(f"Retraining failed for {model_type}: {e}")

    def _should_auto_promote(self, algorithm_config: Dict, promotion_criteria: Dict) -> bool:
        """Decide si promover automáticamente a producción"""
        auto_criteria = promotion_criteria["automatic_promotion"]

        if not auto_criteria["enabled"]:
            return False

        # Verificar mejora mínima
        improvement = algorithm_config.get("improvement_over_current", 0.0)
        min_improvement = 0.05  # 5% mejora mínima

        return improvement >= min_improvement

    def run(self):
        """Loop principal del reentrenador"""
        self.log.info("Starting model-axiom-retrainer")

        while True:
            try:
                # Buscar solicitudes de reentrenamiento
                requests = self.check_for_retraining_requests()

                for request in requests:
                    self.process_retraining_request(request)

                # Pausa entre verificaciones
                time.sleep(self.config.get("poll_interval_seconds", 60))

            except KeyboardInterrupt:
                self.log.info("Shutting down retrainer...")
                break
            except Exception as e:
                self.log.error(f"Error in main loop: {e}")
                time.sleep(30)


if __name__ == "__main__":
    import sys
    import time
    import shutil

    if len(sys.argv) != 2:
        print("Usage: python3 model-axiom-retrainer.py <config_path>")
        sys.exit(1)

    config_path = sys.argv[1]

    try:
        retrainer = ModelAxiomRetrainer(config_path)
        retrainer.run()
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)