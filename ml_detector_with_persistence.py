#!/usr/bin/env python3
"""
Enhanced ML Detector con Sistema de Persistencia y Evaluación
- Guarda modelos automáticamente
- Evalúa performance de cada modelo
- Carga el mejor modelo automáticamente
- Versionado de modelos con timestamps
"""

import os
import json
import joblib
import pickle
from datetime import datetime
from pathlib import Path


# Agregar al inicio del archivo original, después de las importaciones existentes

class ModelPersistenceManager:
    """Gestor de persistencia y evaluación de modelos ML"""

    def __init__(self, models_dir="ml_models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)

        # Subdirectorios organizados
        self.model_versions_dir = self.models_dir / "versions"
        self.best_models_dir = self.models_dir / "best"
        self.evaluation_dir = self.models_dir / "evaluations"

        for dir_path in [self.model_versions_dir, self.best_models_dir, self.evaluation_dir]:
            dir_path.mkdir(exist_ok=True)

        self.current_version = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.metrics_history = []

        print(f"📁 Directorio de modelos: {self.models_dir}")
        print(f"🏷️  Versión actual: {self.current_version}")

    def save_models(self, models, processors, training_metrics=None):
        """Guardar modelos y procesadores con versionado"""
        version_dir = self.model_versions_dir / self.current_version
        version_dir.mkdir(exist_ok=True)

        saved_files = []

        try:
            # Guardar cada modelo individual
            for model_name, model in models.items():
                if model is not None:
                    model_file = version_dir / f"{model_name}.joblib"
                    joblib.dump(model, model_file)
                    saved_files.append(model_file)
                    print(f"💾 Guardado: {model_name} → {model_file}")

            # Guardar procesadores (scaler, pca, etc.)
            processors_file = version_dir / "processors.joblib"
            joblib.dump(processors, processors_file)
            saved_files.append(processors_file)
            print(f"💾 Guardado: Procesadores → {processors_file}")

            # Guardar metadatos del entrenamiento
            metadata = {
                "version": self.current_version,
                "timestamp": datetime.now().isoformat(),
                "training_metrics": training_metrics or {},
                "model_count": sum(1 for m in models.values() if m is not None),
                "saved_files": [str(f) for f in saved_files]
            }

            metadata_file = version_dir / "metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)

            print(f"✅ Modelos guardados en versión: {self.current_version}")
            return version_dir

        except Exception as e:
            print(f"❌ Error guardando modelos: {e}")
            return None

    def load_models(self, version=None):
        """Cargar modelos de una versión específica o la mejor"""
        if version is None:
            # Cargar el mejor modelo disponible
            best_models = list(self.best_models_dir.glob("*.joblib"))
            if best_models:
                return self._load_best_models()
            else:
                # Si no hay mejores, cargar la versión más reciente
                versions = sorted(self.model_versions_dir.glob("*"))
                if versions:
                    version = versions[-1].name
                else:
                    print("⚠️  No hay modelos guardados")
                    return None, None

        version_dir = self.model_versions_dir / version
        if not version_dir.exists():
            print(f"❌ Versión {version} no encontrada")
            return None, None

        try:
            models = {}

            # Cargar modelos individuales
            model_files = list(version_dir.glob("*.joblib"))
            for model_file in model_files:
                if model_file.name != "processors.joblib":
                    model_name = model_file.stem
                    models[model_name] = joblib.load(model_file)
                    print(f"📂 Cargado: {model_name}")

            # Cargar procesadores
            processors_file = version_dir / "processors.joblib"
            processors = None
            if processors_file.exists():
                processors = joblib.load(processors_file)
                print(f"📂 Cargado: Procesadores")

            print(f"✅ Modelos cargados de versión: {version}")
            return models, processors

        except Exception as e:
            print(f"❌ Error cargando modelos: {e}")
            return None, None

    def evaluate_models(self, models, X_test, y_test=None):
        """Evaluar performance de los modelos"""
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        from sklearn.metrics import silhouette_score
        import numpy as np

        evaluations = {}

        for model_name, model in models.items():
            if model is None:
                continue

            try:
                eval_result = {
                    "model": model_name,
                    "timestamp": datetime.now().isoformat(),
                    "test_samples": len(X_test)
                }

                if model_name == "isolation_forest":
                    # Evaluación para detección de anomalías
                    predictions = model.predict(X_test)
                    scores = model.decision_function(X_test)

                    anomaly_rate = (predictions == -1).mean()
                    eval_result.update({
                        "anomaly_rate": float(anomaly_rate),
                        "mean_score": float(scores.mean()),
                        "std_score": float(scores.std()),
                        "type": "anomaly_detection"
                    })

                elif model_name == "kmeans":
                    # Evaluación para clustering
                    predictions = model.predict(X_test)

                    if len(np.unique(predictions)) > 1:
                        silhouette = silhouette_score(X_test, predictions)
                        eval_result.update({
                            "silhouette_score": float(silhouette),
                            "n_clusters": int(model.n_clusters),
                            "inertia": float(model.inertia_),
                            "type": "clustering"
                        })

                elif y_test is not None and hasattr(model, 'predict'):
                    # Evaluación para clasificación supervisada
                    predictions = model.predict(X_test)

                    # Métricas básicas
                    accuracy = accuracy_score(y_test, predictions)

                    eval_result.update({
                        "accuracy": float(accuracy),
                        "type": "classification"
                    })

                    # Métricas adicionales si es binario
                    if len(np.unique(y_test)) == 2:
                        precision = precision_score(y_test, predictions, average='weighted', zero_division=0)
                        recall = recall_score(y_test, predictions, average='weighted', zero_division=0)
                        f1 = f1_score(y_test, predictions, average='weighted', zero_division=0)

                        eval_result.update({
                            "precision": float(precision),
                            "recall": float(recall),
                            "f1_score": float(f1)
                        })

                evaluations[model_name] = eval_result
                print(f"📊 Evaluado: {model_name} - {eval_result.get('type', 'unknown')}")

            except Exception as e:
                print(f"⚠️  Error evaluando {model_name}: {e}")
                evaluations[model_name] = {"error": str(e)}

        # Guardar evaluaciones
        eval_file = self.evaluation_dir / f"evaluation_{self.current_version}.json"
        with open(eval_file, 'w') as f:
            json.dump(evaluations, f, indent=2)

        print(f"📋 Evaluación guardada: {eval_file}")
        return evaluations

    def save_as_best(self, models, processors, evaluations):
        """Guardar como mejores modelos basado en evaluaciones"""
        try:
            # Limpiar directorio de mejores modelos
            for old_file in self.best_models_dir.glob("*"):
                old_file.unlink()

            # Copiar modelos actuales como mejores
            for model_name, model in models.items():
                if model is not None:
                    best_file = self.best_models_dir / f"{model_name}_best.joblib"
                    joblib.dump(model, best_file)

            # Copiar procesadores
            best_processors_file = self.best_models_dir / "processors_best.joblib"
            joblib.dump(processors, best_processors_file)

            # Guardar evaluaciones de los mejores
            best_eval_file = self.best_models_dir / "best_evaluation.json"
            with open(best_eval_file, 'w') as f:
                json.dump(evaluations, f, indent=2)

            print(f"🏆 Modelos marcados como mejores")
            return True

        except Exception as e:
            print(f"❌ Error guardando como mejores: {e}")
            return False

    def _load_best_models(self):
        """Cargar los mejores modelos guardados"""
        try:
            models = {}

            # Cargar mejores modelos
            for model_file in self.best_models_dir.glob("*_best.joblib"):
                if model_file.name != "processors_best.joblib":
                    model_name = model_file.stem.replace("_best", "")
                    models[model_name] = joblib.load(model_file)
                    print(f"🏆 Cargado mejor: {model_name}")

            # Cargar mejores procesadores
            processors_file = self.best_models_dir / "processors_best.joblib"
            processors = None
            if processors_file.exists():
                processors = joblib.load(processors_file)
                print(f"🏆 Cargado mejores procesadores")

            return models, processors

        except Exception as e:
            print(f"❌ Error cargando mejores modelos: {e}")
            return None, None

    def list_versions(self):
        """Listar todas las versiones disponibles"""
        versions = []
        for version_dir in sorted(self.model_versions_dir.glob("*")):
            metadata_file = version_dir / "metadata.json"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                versions.append(metadata)
        return versions

    def get_model_summary(self):
        """Resumen de modelos y evaluaciones"""
        summary = {
            "total_versions": len(list(self.model_versions_dir.glob("*"))),
            "has_best_models": len(list(self.best_models_dir.glob("*_best.joblib"))) > 0,
            "evaluation_count": len(list(self.evaluation_dir.glob("*.json"))),
            "latest_version": self.current_version
        }

        return summary


# Integración con LightweightThreatDetector
class EnhancedLightweightThreatDetector:
    """
    Versión mejorada del detector con persistencia de modelos
    """

    def __init__(self, broker_address="tcp://localhost:5559", enable_persistence=True):
        # Copiar toda la inicialización original aquí...
        # (Por brevedad, mostraré solo las partes nuevas)

        # Sistema de persistencia
        self.persistence_manager = ModelPersistenceManager() if enable_persistence else None

        # Intentar cargar modelos existentes
        if self.persistence_manager:
            print("🔍 Buscando modelos guardados...")
            loaded_models, loaded_processors = self.persistence_manager.load_models()

            if loaded_models:
                print("📂 Modelos existentes encontrados - cargando...")
                self.models.update(loaded_models)
                if loaded_processors:
                    self.processors.update(loaded_processors)
                self.models_trained = True
                print("✅ Modelos cargados desde disco")
            else:
                print("💡 No hay modelos guardados - se entrenarán nuevos")
                self.models_trained = False
        else:
            self.models_trained = False

    def train_and_save_models(self, X, y=None, auto_save=True, evaluate=True):
        """Entrenar modelos y guardarlos automáticamente"""
        print(f"🔧 Entrenando y guardando modelos con {len(X)} muestras...")

        start_time = time.time()

        # Entrenar usando método original
        X_processed = self.train_lightweight_models(X, y)

        training_time = time.time() - start_time
        training_metrics = {
            "training_time": training_time,
            "samples_count": len(X),
            "features_count": X.shape[1] if hasattr(X, 'shape') else len(X[0]),
            "has_labels": y is not None
        }

        if self.persistence_manager and auto_save:
            # Guardar modelos
            saved_version = self.persistence_manager.save_models(
                self.models,
                self.processors,
                training_metrics
            )

            if evaluate and saved_version:
                # Generar datos de test para evaluación
                X_test = X_processed[:min(200, len(X_processed))]  # Usar subset para test
                y_test = y[:min(200, len(y))] if y is not None else None

                # Evaluar modelos
                evaluations = self.persistence_manager.evaluate_models(
                    self.models, X_test, y_test
                )

                # Guardar como mejores (por ahora, siempre los últimos)
                self.persistence_manager.save_as_best(
                    self.models, self.processors, evaluations
                )

                print("📊 Evaluación completada y guardada")

        self.models_trained = True
        return X_processed

    def get_model_info(self):
        """Información sobre modelos actuales"""
        if not self.persistence_manager:
            return {"persistence": "disabled"}

        summary = self.persistence_manager.get_model_summary()

        # Añadir info de modelos en memoria
        summary["models_in_memory"] = {
            name: model is not None
            for name, model in self.models.items()
        }

        return summary


def create_model_management_demo():
    """Demo del sistema de gestión de modelos"""
    print("🎯 DEMO: Sistema de Gestión de Modelos ML")
    print("=" * 50)

    # Crear detector mejorado
    detector = EnhancedLightweightThreatDetector()

    # Datos de entrenamiento sintéticos
    X_train = np.random.rand(1000, 17)
    y_train = np.random.choice([0, 1], 1000)

    # Entrenar y guardar
    detector.train_and_save_models(X_train, y_train)

    # Mostrar información
    info = detector.get_model_info()
    print("\n📋 Información de Modelos:")
    print(json.dumps(info, indent=2))

    # Listar versiones
    if detector.persistence_manager:
        versions = detector.persistence_manager.list_versions()
        print(f"\n📁 Versiones disponibles: {len(versions)}")
        for version in versions:
            print(f"   - {version['version']}: {version['model_count']} modelos")


if __name__ == "__main__":
    create_model_management_demo()