#!/usr/bin/env python3
"""
hyperparameter_optimization_fixed.py

Versión corregida que maneja valores infinitos y datasets desbalanceados
"""

import os
import time
import numpy as np
import pandas as pd
import joblib
from pathlib import Path

from sklearn.model_selection import GridSearchCV, RandomizedSearchCV, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score, roc_auc_score
from sklearn.model_selection import cross_val_score
from sklearn.utils.class_weight import compute_class_weight

try:
    import lightgbm as lgb

    HAS_LGB = True
except ImportError:
    HAS_LGB = False

try:
    import optuna

    HAS_OPTUNA = True
except ImportError:
    HAS_OPTUNA = False

import warnings

warnings.filterwarnings('ignore')


def clean_infinite_and_large_values(X, y=None):
    """Limpia valores infinitos y extremadamente grandes de los datos"""
    print(f"🧹 Limpiando datos: {X.shape}")

    # Estadísticas antes de limpiar
    inf_count = np.isinf(X).sum().sum()
    nan_count = np.isnan(X).sum().sum()

    print(f"   📊 Valores infinitos antes: {inf_count}")
    print(f"   📊 Valores NaN antes: {nan_count}")

    # Paso 1: Convertir infinitos a NaN
    X_clean = X.replace([np.inf, -np.inf], np.nan)

    # Paso 2: Encontrar valores extremadamente grandes (outliers extremos)
    # Usar percentil 99.9 como límite superior
    for col in X_clean.select_dtypes(include=[np.number]).columns:
        if X_clean[col].notna().sum() > 0:  # Solo si hay valores válidos
            # Calcular límites usando valores no-NaN
            valid_values = X_clean[col].dropna()
            if len(valid_values) > 0:
                upper_limit = valid_values.quantile(0.999)  # Percentil 99.9%
                lower_limit = valid_values.quantile(0.001)  # Percentil 0.1%

                # Clipear valores extremos
                X_clean[col] = X_clean[col].clip(lower=lower_limit, upper=upper_limit)

    # Paso 3: Rellenar valores NaN
    numeric_cols = X_clean.select_dtypes(include=[np.number]).columns

    for col in numeric_cols:
        if X_clean[col].isnull().sum() > 0:
            # Usar mediana para robustez
            median_val = X_clean[col].median()
            if pd.isna(median_val):
                median_val = 0  # Fallback si toda la columna es NaN
            X_clean[col] = X_clean[col].fillna(median_val)

    # Verificación final
    final_inf = np.isinf(X_clean).sum().sum()
    final_nan = np.isnan(X_clean).sum().sum()
    final_large = (np.abs(X_clean.select_dtypes(include=[np.number])) > 1e10).sum().sum()

    print(f"   ✅ Valores infinitos después: {final_inf}")
    print(f"   ✅ Valores NaN después: {final_nan}")
    print(f"   ✅ Valores muy grandes (>1e10) después: {final_large}")

    # Conversión a float32 segura
    try:
        X_clean = X_clean.astype(np.float32)
        print(f"   ✅ Conversión a float32 exitosa")
    except Exception as e:
        print(f"   ⚠️ Usando float64 por seguridad: {e}")

    return X_clean


def balance_dataset(X, y, method='undersample', max_samples=10000):
    """Balancea dataset extremadamente desbalanceado"""
    print(f"⚖️ Balanceando dataset...")

    unique, counts = np.unique(y, return_counts=True)
    print(f"   📊 Distribución original: {dict(zip(unique, counts))}")

    if len(unique) < 2:
        print(f"   ⚠️ Solo una clase presente, retornando sin cambios")
        return X, y

    # Encontrar clase minoritaria y mayoritaria
    minority_class = unique[np.argmin(counts)]
    majority_class = unique[np.argmax(counts)]

    minority_count = counts.min()
    majority_count = counts.max()

    print(f"   🔍 Clase minoritaria {minority_class}: {minority_count} muestras")
    print(f"   🔍 Clase mayoritaria {majority_class}: {majority_count} muestras")

    if method == 'undersample':
        # Undersampling de la clase mayoritaria
        target_majority_size = min(minority_count * 5, max_samples // 2)  # Ratio máximo 5:1

        majority_indices = np.where(y == majority_class)[0]
        minority_indices = np.where(y == minority_class)[0]

        if len(majority_indices) > target_majority_size:
            # Muestreo aleatorio de la clase mayoritaria
            np.random.seed(42)
            selected_majority = np.random.choice(
                majority_indices, target_majority_size, replace=False
            )

            # Combinar índices
            selected_indices = np.concatenate([selected_majority, minority_indices])
            np.random.shuffle(selected_indices)

            X_balanced = X.iloc[selected_indices] if hasattr(X, 'iloc') else X[selected_indices]
            y_balanced = y.iloc[selected_indices] if hasattr(y, 'iloc') else y[selected_indices]

        else:
            X_balanced, y_balanced = X, y

    else:  # 'none'
        X_balanced, y_balanced = X, y

    # Verificar resultado
    unique_new, counts_new = np.unique(y_balanced, return_counts=True)
    print(f"   ✅ Distribución balanceada: {dict(zip(unique_new, counts_new))}")

    return X_balanced, y_balanced


class ImprovedHyperparameterOptimizer:
    """Optimizador mejorado con limpieza de datos"""

    def __init__(self, X_train, y_train, X_test, y_test, random_state=42):
        # Limpiar datos antes de optimización
        print("🔧 Preparando datos para optimización...")

        self.X_train_clean = clean_infinite_and_large_values(X_train)
        self.X_test_clean = clean_infinite_and_large_values(X_test)

        # Balancear dataset si está muy desbalanceado
        self.X_train_balanced, self.y_train_balanced = balance_dataset(
            self.X_train_clean, y_train, method='undersample'
        )

        self.y_test = y_test
        self.random_state = random_state
        self.cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=random_state)  # Reducido a 3-fold
        self.results = {}

    def optimize_random_forest_fixed(self):
        """Random Forest optimización con datos limpios"""
        print("🌲 Optimizando Random Forest (versión arreglada)...")

        # Espacio de búsqueda más conservador
        param_grid = {
            'n_estimators': [10, 30, 50],
            'max_depth': [5, 8, 12],
            'min_samples_split': [10, 20, 50],
            'min_samples_leaf': [5, 10, 20],
            'max_features': ['sqrt', 'log2'],
            'class_weight': ['balanced', 'balanced_subsample']
        }

        rf = RandomForestClassifier(
            random_state=self.random_state,
            bootstrap=True,
            n_jobs=-1
        )

        grid_search = GridSearchCV(
            rf, param_grid,
            cv=self.cv,
            scoring='f1',
            n_jobs=1,  # Reducido para evitar problemas de memoria
            verbose=1
        )

        start_time = time.time()
        try:
            grid_search.fit(self.X_train_balanced, self.y_train_balanced)
            search_time = time.time() - start_time

            # Evaluar en conjunto de test limpio
            best_model = grid_search.best_estimator_
            y_pred = best_model.predict(self.X_test_clean)
            y_proba = best_model.predict_proba(self.X_test_clean)[:, 1]

            metrics = {
                'accuracy': accuracy_score(self.y_test, y_pred),
                'f1_score': f1_score(self.y_test, y_pred, zero_division=0),
                'roc_auc': roc_auc_score(self.y_test, y_proba) if len(np.unique(self.y_test)) > 1 else 0.0,
                'search_time': search_time,
                'best_params': grid_search.best_params_,
                'best_score': grid_search.best_score_,
                'model': best_model
            }

            self.results['rf_fixed'] = metrics

            print(f"✅ Random Forest arreglado completado en {search_time:.2f}s")
            print(f"📊 Mejores parámetros: {grid_search.best_params_}")
            print(f"🎯 F1-Score: {metrics['f1_score']:.4f}")

            return metrics

        except Exception as e:
            print(f"❌ Error persistente en Random Forest: {e}")
            return None

    def optimize_lightgbm_enhanced(self):
        """LightGBM con búsqueda más extensa"""
        if not HAS_LGB:
            print("❌ LightGBM no disponible")
            return None

        print("💡 Optimizando LightGBM (versión mejorada)...")

        # Espacio de búsqueda más amplio
        param_distributions = {
            'num_leaves': [5, 10, 15, 20, 31, 50],
            'max_depth': [3, 4, 5, 6, 8, 10, -1],
            'learning_rate': [0.01, 0.05, 0.1, 0.15, 0.2],
            'n_estimators': [50, 100, 150, 200, 300],
            'min_split_gain': [0.0, 0.1, 0.2],
            'min_child_weight': [0.001, 0.01, 0.1],
            'min_child_samples': [5, 10, 20, 30],
            'subsample': [0.6, 0.7, 0.8, 0.9, 1.0],
            'colsample_bytree': [0.6, 0.7, 0.8, 0.9, 1.0],
            'reg_alpha': [0.0, 0.1, 0.3, 0.5],
            'reg_lambda': [0.0, 0.1, 0.3, 0.5],
        }

        lgbm = lgb.LGBMClassifier(
            objective='binary',
            class_weight='balanced',
            random_state=self.random_state,
            verbose=-1,
            force_col_wise=True
        )

        random_search = RandomizedSearchCV(
            lgbm, param_distributions,
            n_iter=50,  # Aumentado a 50 iteraciones
            cv=self.cv,
            scoring='f1',
            n_jobs=-1,
            random_state=self.random_state,
            verbose=1
        )

        start_time = time.time()
        random_search.fit(self.X_train_balanced, self.y_train_balanced)
        search_time = time.time() - start_time

        best_model = random_search.best_estimator_
        y_pred = best_model.predict(self.X_test_clean)
        y_proba = best_model.predict_proba(self.X_test_clean)[:, 1]

        metrics = {
            'accuracy': accuracy_score(self.y_test, y_pred),
            'f1_score': f1_score(self.y_test, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(self.y_test, y_proba) if len(np.unique(self.y_test)) > 1 else 0.0,
            'search_time': search_time,
            'best_params': random_search.best_params_,
            'best_score': random_search.best_score_,
            'model': best_model
        }

        self.results['lgb_enhanced'] = metrics

        print(f"✅ LightGBM mejorado completado en {search_time:.2f}s")
        print(f"📊 Mejores parámetros: {random_search.best_params_}")
        print(f"🎯 F1-Score: {metrics['f1_score']:.4f}")

        return metrics

    def compare_and_save(self):
        """Compara resultados y guarda el mejor modelo"""
        if not self.results:
            print("❌ No hay resultados para comparar")
            return

        print("\n" + "=" * 80)
        print("📊 COMPARACIÓN FINAL - OPTIMIZACIÓN CORREGIDA")
        print("=" * 80)

        comparison_data = []
        for method, metrics in self.results.items():
            comparison_data.append({
                'Método': method,
                'F1-Score': metrics['f1_score'],
                'Accuracy': metrics['accuracy'],
                'ROC-AUC': metrics['roc_auc'],
                'Tiempo (s)': metrics['search_time'],
                'CV Score': metrics['best_score']
            })

        df = pd.DataFrame(comparison_data)
        df = df.sort_values('F1-Score', ascending=False)

        print("\n🏆 RANKING DE RENDIMIENTO:")
        print(df.to_string(index=False, float_format='%.4f'))

        # Guardar mejor modelo
        best_method = df.iloc[0]['Método']
        best_metrics = self.results[best_method]

        Path("./optimized_models").mkdir(exist_ok=True)

        model_path = f"./optimized_models/final_optimized_{best_method}_model.joblib"
        joblib.dump(best_metrics['model'], model_path)

        print(f"\n🥇 MEJOR MODELO: {best_method}")
        print(f"   📈 F1-Score: {best_metrics['f1_score']:.4f}")
        print(f"   🎯 Accuracy: {best_metrics['accuracy']:.4f}")
        print(f"   💾 Guardado en: {model_path}")

        return best_method, best_metrics


def load_real_training_data():
    """Carga datos reales con limpieza mejorada"""
    print("📁 Cargando datos reales para optimización...")

    try:
        parquet_files = [
            "./datasets_parquet/Portmap.parquet",
            "./datasets_parquet/DrDoS_NetBIOS.parquet"
        ]

        dfs = []
        for file in parquet_files:
            if os.path.exists(file):
                df = pd.read_parquet(file)
                print(f"   📄 Cargado: {os.path.basename(file)} - {len(df)} filas")

                # Procesar igual que en entrenamiento original
                if 'Unnamed: 0' in df.columns:
                    df = df.drop(columns=['Unnamed: 0'])

                if ' Label' in df.columns:
                    df['Label'] = df[' Label'].apply(lambda x: 0 if x == 0 else 1)
                    df = df.drop(columns=[' Label'])

                # Limitar tamaño para optimización
                if len(df) > 15000:
                    df = df.sample(n=15000, random_state=42)

                dfs.append(df)

        if dfs:
            full_df = pd.concat(dfs, ignore_index=True)

            # Verificar que tenemos features y labels
            if 'Label' in full_df.columns:
                X = full_df.drop(columns=['Label'])
                y = full_df['Label']

                print(f"✅ Datos cargados: {len(X)} muestras, {len(X.columns)} features")

                unique, counts = np.unique(y, return_counts=True)
                print(f"📊 Distribución: {dict(zip(unique, counts))}")

                return X, y
            else:
                print("❌ No se encontró columna 'Label'")

    except Exception as e:
        print(f"❌ Error cargando datos reales: {e}")

    return None, None


def main():
    """Función principal corregida"""
    print("=" * 80)
    print("🔧 UPGRADED HAPPINESS - OPTIMIZACIÓN CORREGIDA")
    print("Arreglos: limpieza infinitos, balance dataset, parámetros robustos")
    print("=" * 80)

    # Cargar datos
    X, y = load_real_training_data()

    if X is None:
        print("❌ No se pudieron cargar datos, terminando...")
        return

    # Split
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"🔄 Split: Train={len(X_train)}, Test={len(X_test)}")

    # Crear optimizador mejorado
    optimizer = ImprovedHyperparameterOptimizer(X_train, y_train, X_test, y_test)

    start_total = time.time()

    # Ejecutar optimizaciones
    print(f"\n🚀 Iniciando optimizaciones corregidas...")

    # 1. Random Forest arreglado
    try:
        optimizer.optimize_random_forest_fixed()
    except Exception as e:
        print(f"❌ Error en RF arreglado: {e}")

    # 2. LightGBM mejorado
    if HAS_LGB:
        try:
            optimizer.optimize_lightgbm_enhanced()
        except Exception as e:
            print(f"❌ Error en LGB mejorado: {e}")

    total_time = time.time() - start_total

    # Comparar y guardar
    best_method, best_metrics = optimizer.compare_and_save()

    print(f"\n⏱️ TIEMPO TOTAL CORREGIDO: {total_time:.2f} segundos")
    print("=" * 80)

    return optimizer


if __name__ == "__main__":
    main()