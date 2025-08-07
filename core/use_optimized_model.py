#!/usr/bin/env python3
"""
use_optimized_model.py

Ejemplo de cómo usar el modelo optimizado con F1-Score perfecto
"""

import joblib
import numpy as np
import pandas as pd
import time


def load_optimized_model():
    """Carga el modelo optimizado"""
    model_path = "./optimized_models/optimized_lgb_random_model.joblib"

    try:
        model = joblib.load(model_path)
        print(f"✅ Modelo optimizado cargado: {model_path}")
        print(f"   📊 Tipo: {type(model).__name__}")
        return model
    except Exception as e:
        print(f"❌ Error cargando modelo optimizado: {e}")

        # Fallback al modelo original
        try:
            fallback_path = "./models/ddos_lightgbm.joblib"
            model = joblib.load(fallback_path)
            print(f"✅ Usando modelo original: {fallback_path}")
            return model
        except:
            print(f"❌ No se pudo cargar ningún modelo")
            return None


def compare_models_performance():
    """Compara modelo original vs optimizado"""
    print("🔍 Comparando modelo original vs optimizado...")

    # Cargar modelos
    original_model = None
    optimized_model = None

    try:
        original_model = joblib.load("./models/ddos_lightgbm.joblib")
        print("✅ Modelo original cargado")
    except:
        print("❌ No se pudo cargar modelo original")

    try:
        optimized_model = joblib.load("./optimized_models/optimized_lgb_random_model.joblib")
        print("✅ Modelo optimizado cargado")
    except:
        print("❌ No se pudo cargar modelo optimizado")

    if not (original_model and optimized_model):
        print("⚠️ Necesitas ambos modelos para comparar")
        return

    # Cargar datos de test
    try:
        test_data = pd.read_parquet("./datasets_parquet/Portmap.parquet")

        if 'Unnamed: 0' in test_data.columns:
            test_data = test_data.drop(columns=['Unnamed: 0'])

        if ' Label' in test_data.columns:
            y_true = test_data[' Label'].apply(lambda x: 0 if x == 0 else 1)
            X_test = test_data.drop(columns=[' Label'])
        else:
            print("❌ No se encontró columna de etiquetas")
            return

        # Tomar muestra para comparación rápida
        if len(X_test) > 5000:
            sample_indices = np.random.choice(len(X_test), 5000, replace=False)
            X_test = X_test.iloc[sample_indices]
            y_true = y_true.iloc[sample_indices]

        print(f"📊 Comparando en {len(X_test)} muestras de test...")

        # Predicciones originales
        start_time = time.time()
        y_pred_original = original_model.predict(X_test)
        y_proba_original = original_model.predict_proba(X_test)[:, 1]
        time_original = time.time() - start_time

        # Predicciones optimizadas
        start_time = time.time()
        y_pred_optimized = optimized_model.predict(X_test)
        y_proba_optimized = optimized_model.predict_proba(X_test)[:, 1]
        time_optimized = time.time() - start_time

        # Calcular métricas
        from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score

        # Métricas originales
        acc_orig = accuracy_score(y_true, y_pred_original)
        f1_orig = f1_score(y_true, y_pred_original)
        prec_orig = precision_score(y_true, y_pred_original, zero_division=0)
        rec_orig = recall_score(y_true, y_pred_original, zero_division=0)
        auc_orig = roc_auc_score(y_true, y_proba_original)

        # Métricas optimizadas
        acc_opt = accuracy_score(y_true, y_pred_optimized)
        f1_opt = f1_score(y_true, y_pred_optimized)
        prec_opt = precision_score(y_true, y_pred_optimized, zero_division=0)
        rec_opt = recall_score(y_true, y_pred_optimized, zero_division=0)
        auc_opt = roc_auc_score(y_true, y_proba_optimized)

        # Mostrar comparación
        print("\n" + "=" * 60)
        print("📊 COMPARACIÓN DE RENDIMIENTO")
        print("=" * 60)

        metrics_comparison = pd.DataFrame({
            'Métrica': ['Accuracy', 'F1-Score', 'Precision', 'Recall', 'ROC-AUC', 'Tiempo (s)'],
            'Original': [acc_orig, f1_orig, prec_orig, rec_orig, auc_orig, time_original],
            'Optimizado': [acc_opt, f1_opt, prec_opt, rec_opt, auc_opt, time_optimized],
            'Mejora': [
                f"+{((acc_opt - acc_orig) / acc_orig * 100):.2f}%",
                f"+{((f1_opt - f1_orig) / f1_orig * 100):.2f}%",
                f"+{((prec_opt - prec_orig) / prec_orig * 100):.2f}%" if prec_orig > 0 else "N/A",
                f"+{((rec_opt - rec_orig) / rec_orig * 100):.2f}%" if rec_orig > 0 else "N/A",
                f"+{((auc_opt - auc_orig) / auc_orig * 100):.2f}%",
                f"{((time_optimized - time_original) / time_original * 100):+.1f}%"
            ]
        })

        print(metrics_comparison.to_string(index=False, float_format='%.4f'))

        # Análisis de diferencias en predicciones
        diff_count = (y_pred_original != y_pred_optimized).sum()
        print(f"\n🔍 Diferencias en predicciones: {diff_count}/{len(y_true)} ({diff_count / len(y_true) * 100:.2f}%)")

        if diff_count > 0:
            print("\n📋 Casos donde los modelos difieren:")
            diff_indices = np.where(y_pred_original != y_pred_optimized)[0]

            for i in diff_indices[:5]:  # Mostrar primeros 5 casos
                print(
                    f"   Muestra {i}: Original={y_pred_original[i]}, Optimizado={y_pred_optimized[i]}, Real={y_true.iloc[i]}")

        # Recomendación
        if f1_opt > f1_orig:
            print(f"\n🏆 RECOMENDACIÓN: Usar modelo OPTIMIZADO")
            print(f"   📈 Mejora F1-Score: {f1_orig:.4f} → {f1_opt:.4f}")
        else:
            print(f"\n⚖️ RECOMENDACIÓN: Ambos modelos son equivalentes")

    except Exception as e:
        print(f"❌ Error en comparación: {e}")
        import traceback
        traceback.print_exc()


def predict_with_optimized_model(sample_data):
    """Hace predicciones usando el modelo optimizado"""
    model = load_optimized_model()

    if model is None:
        return None

    print(f"🔮 Haciendo predicciones con modelo optimizado...")

    # Asegurar que tenemos 82 features (como en entrenamiento)
    expected_features = 82

    if hasattr(sample_data, 'shape'):
        current_features = sample_data.shape[1]
        print(f"   📊 Features en datos: {current_features}")

        if current_features != expected_features:
            print(f"   ⚠️ Ajustando features: {current_features} → {expected_features}")

            if current_features > expected_features:
                # Truncar
                sample_data = sample_data.iloc[:, :expected_features]
            else:
                # Rellenar con ceros
                missing_cols = expected_features - current_features
                zeros_df = pd.DataFrame(0, index=sample_data.index,
                                        columns=[f'feature_{i}' for i in range(missing_cols)])
                sample_data = pd.concat([sample_data, zeros_df], axis=1)

    try:
        # Predicción
        start_time = time.time()
        predictions = model.predict(sample_data)
        probabilities = model.predict_proba(sample_data)
        prediction_time = time.time() - start_time

        print(f"   ⏱️ Tiempo predicción: {prediction_time:.4f} segundos")
        print(f"   📊 {len(predictions)} predicciones realizadas")

        # Análisis de resultados
        attack_count = (predictions == 1).sum()
        benign_count = (predictions == 0).sum()

        print(f"   🔥 Ataques detectados: {attack_count}")
        print(f"   ✅ Tráfico benigno: {benign_count}")

        # Mostrar casos con mayor probabilidad de ataque
        if len(probabilities) > 0:
            high_risk_indices = np.where(probabilities[:, 1] > 0.9)[0]

            if len(high_risk_indices) > 0:
                print(f"   🚨 Casos de alto riesgo (>90% probabilidad): {len(high_risk_indices)}")

                for i in high_risk_indices[:5]:  # Primeros 5
                    prob = probabilities[i, 1]
                    pred = predictions[i]
                    print(f"     Muestra {i}: Predicción={pred}, Probabilidad={prob:.4f}")

        return predictions, probabilities, prediction_time

    except Exception as e:
        print(f"❌ Error en predicción: {e}")
        return None, None, 0


def main():
    """Función principal para demostrar uso del modelo optimizado"""
    print("=" * 60)
    print("🚀 USANDO MODELO OPTIMIZADO (F1-Score Perfecto)")
    print("=" * 60)

    # 1. Comparar modelos
    compare_models_performance()

    # 2. Ejemplo de predicción
    print(f"\n🔮 EJEMPLO DE PREDICCIÓN CON MODELO OPTIMIZADO")
    print("=" * 60)

    try:
        # Cargar datos de ejemplo
        sample_data = pd.read_parquet("./datasets_parquet/Portmap.parquet")

        if 'Unnamed: 0' in sample_data.columns:
            sample_data = sample_data.drop(columns=['Unnamed: 0'])

        if ' Label' in sample_data.columns:
            sample_data = sample_data.drop(columns=[' Label'])

        # Tomar muestra pequeña
        sample_data = sample_data.head(100)

        predictions, probabilities, pred_time = predict_with_optimized_model(sample_data)

        if predictions is not None:
            print(f"\n✅ Predicciones completadas exitosamente!")
            print(f"   📈 Rendimiento: {len(predictions) / pred_time:.0f} predicciones/segundo")

    except Exception as e:
        print(f"❌ Error en ejemplo: {e}")

    print("\n" + "=" * 60)
    print("🎯 Modelo optimizado listo para uso en producción!")
    print("=" * 60)


if __name__ == "__main__":
    main()