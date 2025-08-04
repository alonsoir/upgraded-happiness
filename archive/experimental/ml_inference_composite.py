import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

class CompositeClassifier:
    def __init__(self, attack_model_path, external_model_path, internal_model_path, scaler_path):
        self.attack_model = joblib.load(attack_model_path)
        self.external_model = joblib.load(external_model_path)
        self.internal_model = joblib.load(internal_model_path)
        self.scaler = joblib.load(scaler_path)

    def preprocess(self, X):
        # Aquí puedes hacer cualquier preprocesamiento necesario
        # Por ahora solo escalamos con el scaler guardado
        return self.scaler.transform(X)

    def predict(self, X_raw):
        """
        X_raw: pandas DataFrame con features numéricas ya ordenadas correctamente

        Devuelve lista de dicts con predicciones y veredictos
        """
        X = self.preprocess(X_raw)

        # Predicción ataque/no ataque
        attack_preds = self.attack_model.predict(X)

        # Resultados finales
        results = []

        # Para filas "no ataque", predecimos comportamiento
        no_attack_indices = np.where(attack_preds == 0)[0]
        X_no_attack = X[no_attack_indices]

        # Predicciones comportamiento externo e interno (0 = normal, 1 = anómalo)
        external_preds = self.external_model.predict(X_no_attack)
        internal_preds = self.internal_model.predict(X_no_attack)

        for i, pred in enumerate(attack_preds):
            if pred == 1:
                verdict = "🚨 Ataque detectado"
                ext_behav = None
                int_behav = None
            else:
                ext_behav = "normal" if external_preds[np.where(no_attack_indices == i)[0][0]] == 0 else "anomalous"
                int_behav = "normal" if internal_preds[np.where(no_attack_indices == i)[0][0]] == 0 else "anomalous"

                # Simple lógica para veredicto basado en comportamientos
                if ext_behav == "anomalous" and int_behav == "anomalous":
                    verdict = "⚠️ Anomalía externa e interna detectada"
                elif ext_behav == "anomalous":
                    verdict = "⚠️ Anomalía externa detectada"
                elif int_behav == "anomalous":
                    verdict = "⚠️ Posible movimiento lateral detectado"
                else:
                    verdict = "✅ Tráfico legítimo"

            results.append({
                "prediction": "attack" if pred == 1 else "no_attack",
                "external_behavior": ext_behav,
                "internal_behavior": int_behav,
                "verdict": verdict
            })

        return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Inferencia compuesta para IDS")
    parser.add_argument("--input_csv", type=str, required=True, help="CSV con features para clasificar")
    parser.add_argument("--attack_model", type=str, default="models/model_20250729_125245/model.pkl", help="Modelo ataque/no ataque")
    parser.add_argument("--external_model", type=str, default="models/rf_normal_behavior.joblib", help="Modelo comportamiento externo")
    parser.add_argument("--internal_model", type=str, default="models/rf_internal_behavior.joblib", help="Modelo comportamiento interno")
    parser.add_argument("--scaler", type=str, default="models/model_20250729_125245/scaler.pkl", help="Scaler para features")
    args = parser.parse_args()

    # Cargar datos
    df = pd.read_csv(args.input_csv)
    # Aquí se asume que df ya contiene solo las columnas numéricas y en orden correcto para el modelo

    composite = CompositeClassifier(
        attack_model_path=args.attack_model,
        external_model_path=args.external_model,
        internal_model_path=args.internal_model,
        scaler_path=args.scaler,
    )

    results = composite.predict(df)
    for i, res in enumerate(results):
        print(f"Evento {i}: {res}")
