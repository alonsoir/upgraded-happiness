#!/usr/bin/env python3

# Suprimir warnings de sklearn
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", message="X does not have valid feature names")
warnings.filterwarnings("ignore", message=".*Parallel.*")

"""
🚀 UPGRADED HAPPINESS - PIPELINE ML COMPLETO DE 3 NIVELES
complete_ml_pipeline.py
ARQUITECTURA DESCUBIERTA:
- Nivel 1: RF Production (23 features) → ¿HAY ATAQUE?
- Nivel 2: DDoS/Ransomware (82 features) → ¿QUÉ TIPO?
- Nivel 3: Internal/Web Detectors (4 features) → ¿"Normal" es REALMENTE normal?

Features mapping:
- 82 → 23 (para nivel 1)
- 82 → 4 (para nivel 3)
- 82 (directo para nivel 2)

Autor: Alonso Isidoro, Claude
Fecha: Agosto 7, 2025
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
import time
import logging
from typing import Dict, List, Tuple, Optional, Union

# Configuración
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
MODELS_DIR = PROJECT_ROOT / "models"
PRODUCTION_DIR = MODELS_DIR / "production"
TRICAPA_DIR = PRODUCTION_DIR / "tricapa"


class CompleteMlPipeline:
    """Pipeline ML completo de 3 niveles para detección de ciberseguridad"""

    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_mappings = {}
        self.load_all_models()
        self.setup_feature_mappings()

    def load_all_models(self):
        """Carga todos los modelos del sistema de 3 niveles"""
        print("🔄 Cargando pipeline ML completo...")

        # NIVEL 1: Detector general de ataques (23 features)
        try:
            production_data = joblib.load(PRODUCTION_DIR / "rf_production_sniffer_compatible.joblib")
            self.models['level1_attack_detector'] = production_data['model']
            self.scalers['level1_scaler'] = production_data['scaler']
            self.feature_mappings['level1_features'] = production_data['feature_names']
            print("✅ Nivel 1: Attack Detector (23 features)")
        except Exception as e:
            print(f"❌ Error cargando Nivel 1: {e}")

        # NIVEL 2: Detectores específicos (82 features)
        level2_models = [
            ('ddos_rf', 'ddos_random_forest.joblib'),
            ('ddos_lgb', 'ddos_lightgbm.joblib'),
            ('ransomware_rf', 'ransomware_random_forest.joblib'),
            ('ransomware_lgb', 'ransomware_lightgbm.joblib')
        ]

        for model_name, filename in level2_models:
            try:
                model_path = TRICAPA_DIR / filename
                self.models[model_name] = joblib.load(model_path)
                print(f"✅ Nivel 2: {model_name} (82 features)")
            except Exception as e:
                print(f"❌ Error cargando {model_name}: {e}")

        # NIVEL 3: Detectores de normalidad (4 features)
        level3_models = [
            ('internal_detector', 'internal_normal_detector.joblib'),
            ('web_detector', 'web_normal_detector.joblib')
        ]

        for model_name, filename in level3_models:
            try:
                model_path = PRODUCTION_DIR / filename
                self.models[model_name] = joblib.load(model_path)
                print(f"✅ Nivel 3: {model_name} (4 features)")
            except Exception as e:
                print(f"❌ Error cargando {model_name}: {e}")

        print(f"🎯 Pipeline cargado: {len(self.models)} modelos activos")

    def setup_feature_mappings(self):
        """Configura los mapeos de features 82 → 23 → 4"""

        # Mapeo 82 → 23 (basado en el análisis realizado)
        # Estas son las features del modelo de 23 que corresponden a las 82
        self.feature_mappings['82_to_23_map'] = {
            'duration': ' Flow Duration',
            'spkts': ' Total Fwd Packets',
            'dpkts': ' Total Backward Packets',
            'sbytes': ' Total Length of Fwd Packets',
            'dbytes': ' Total Length of Bwd Packets',
            'sload': ' Flow Bytes/s',  # Aproximación
            'smean': ' Fwd Packet Length Mean',
            'dmean': ' Bwd Packet Length Mean',
            'flow_iat_mean': ' Flow IAT Mean',
            'flow_iat_std': ' Flow IAT Std',
            'fwd_psh_flags': ' Fwd PSH Flags',
            'bwd_psh_flags': ' Bwd PSH Flags',
            'fwd_urg_flags': ' Fwd URG Flags',
            'bwd_urg_flags': ' Bwd URG Flags',
            'packet_len_mean': ' Packet Length Mean',
            'packet_len_std': ' Packet Length Std',
            'packet_len_var': ' Packet Length Variance',
            'fin_flag_count': ' FIN Flag Count',
            'syn_flag_count': ' SYN Flag Count',
            'rst_flag_count': ' RST Flag Count',
            'psh_flag_count': ' PSH Flag Count',
            'ack_flag_count': ' ACK Flag Count',
            'urg_flag_count': ' URG Flag Count'
        }

        # Mapeo 82 → 4 (las 4 features más importantes)
        self.feature_mappings['82_to_4_map'] = {
            0: ' Flow Duration',  # duration
            1: ' Total Fwd Packets',  # spkts
            2: ' Total Backward Packets',  # dpkts
            3: ' Total Length of Fwd Packets'  # sbytes (feature dominante!)
        }

    def extract_features_23(self, features_82: np.ndarray, feature_names_82: List[str]) -> np.ndarray:
        """Extrae 23 features de las 82 features completas"""

        # Crear mapeo de nombre → índice para features de 82
        feature_name_to_idx = {name.strip(): idx for idx, name in enumerate(feature_names_82)}

        features_23 = np.zeros(23)

        # Mapear cada feature de 23 a su posición en las 82
        for i, target_feature in enumerate(self.feature_mappings['level1_features']):

            # Buscar la feature correspondiente en las 82
            source_feature = self.feature_mappings['82_to_23_map'].get(target_feature)

            if source_feature and source_feature.strip() in feature_name_to_idx:
                source_idx = feature_name_to_idx[source_feature.strip()]
                features_23[i] = features_82[source_idx]
            else:
                # Si no encontramos mapeo, usar valor por defecto
                features_23[i] = 0.0

        return features_23

    def extract_features_4(self, features_82: np.ndarray, feature_names_82: List[str]) -> np.ndarray:
        """Extrae 4 features clave de las 82 features completas"""

        # Crear mapeo de nombre → índice
        feature_name_to_idx = {name.strip(): idx for idx, name in enumerate(feature_names_82)}

        features_4 = np.zeros(4)

        # Mapear las 4 features dominantes
        for i, source_feature_name in self.feature_mappings['82_to_4_map'].items():
            if source_feature_name.strip() in feature_name_to_idx:
                source_idx = feature_name_to_idx[source_feature_name.strip()]
                features_4[i] = features_82[source_idx]
            else:
                features_4[i] = 0.0

        return features_4

    def classify_traffic_type(self, features_82: np.ndarray, feature_names_82: List[str]) -> str:
        """Clasifica el tipo de tráfico (internal, web, other) basado en las features"""

        # Mapeo de nombres a índices
        name_to_idx = {name.strip(): idx for idx, name in enumerate(feature_names_82)}

        # Heurística simple para clasificar tráfico
        # Basado en puertos y comportamiento típico

        source_port_idx = name_to_idx.get('Source Port', name_to_idx.get(' Source Port'))
        dest_port_idx = name_to_idx.get('Destination Port', name_to_idx.get(' Destination Port'))

        if source_port_idx is not None and dest_port_idx is not None:
            src_port = features_82[source_port_idx]
            dst_port = features_82[dest_port_idx]

            # Puertos web típicos
            web_ports = [80, 443, 8080, 8443]
            if src_port in web_ports or dst_port in web_ports:
                return 'web'

            # Puertos internos típicos (rangos altos, RPC, etc.)
            if (src_port > 32768 or dst_port > 32768) or \
                    (src_port < 1024 and dst_port < 1024):
                return 'internal'

        return 'other'

    def predict_complete(self, features_82: np.ndarray, feature_names_82: List[str]) -> Dict:
        """Ejecuta el pipeline completo de 3 niveles"""

        start_time = time.time()
        results = {
            'timestamp': time.time(),
            'processing_time_ms': 0,
            'level1_attack_detected': False,
            'level1_attack_probability': 0.0,
            'level2_attack_types': {},
            'level3_normal_validation': {},
            'final_classification': 'NORMAL',
            'confidence': 0.0,
            'alerts': []
        }

        try:
            # NIVEL 1: ¿HAY ATAQUE GENERAL?
            if 'level1_attack_detector' in self.models:
                features_23 = self.extract_features_23(features_82, feature_names_82)
                features_23_scaled = self.scalers['level1_scaler'].transform(features_23.reshape(1, -1))

                attack_proba = self.models['level1_attack_detector'].predict_proba(features_23_scaled)[0]
                attack_probability = attack_proba[1]  # Probabilidad de ataque

                results['level1_attack_probability'] = float(attack_probability)
                results['level1_attack_detected'] = attack_probability > 0.5

                if attack_probability > 0.5:
                    # NIVEL 2: ¿QUÉ TIPO DE ATAQUE?
                    results['final_classification'] = 'ATTACK'

                    # Probar todos los modelos de nivel 2
                    level2_predictions = {}

                    for model_name in ['ddos_rf', 'ddos_lgb', 'ransomware_rf', 'ransomware_lgb']:
                        if model_name in self.models:
                            try:
                                pred_proba = self.models[model_name].predict_proba(features_82.reshape(1, -1))[0]
                                level2_predictions[model_name] = float(pred_proba[1])
                            except Exception as e:
                                level2_predictions[model_name] = 0.0

                    results['level2_attack_types'] = level2_predictions

                    # Determinar tipo de ataque más probable
                    ddos_score = max(level2_predictions.get('ddos_rf', 0),
                                     level2_predictions.get('ddos_lgb', 0))
                    ransomware_score = max(level2_predictions.get('ransomware_rf', 0),
                                           level2_predictions.get('ransomware_lgb', 0))

                    if ddos_score > 0.5 and ddos_score >= ransomware_score:
                        results['final_classification'] = 'DDOS'
                        results['confidence'] = ddos_score
                        results['alerts'].append(f'DDoS Attack Detected (confidence: {ddos_score:.2%})')
                    elif ransomware_score > 0.5:
                        results['final_classification'] = 'RANSOMWARE'
                        results['confidence'] = ransomware_score
                        results['alerts'].append(f'Ransomware Detected (confidence: {ransomware_score:.2%})')
                    else:
                        results['final_classification'] = 'UNKNOWN_ATTACK'
                        results['confidence'] = attack_probability
                        results['alerts'].append(f'Unknown Attack Type (confidence: {attack_probability:.2%})')

                else:
                    # NIVEL 3: ¿EL TRÁFICO "NORMAL" ES REALMENTE NORMAL?
                    traffic_type = self.classify_traffic_type(features_82, feature_names_82)
                    features_4 = self.extract_features_4(features_82, feature_names_82)

                    if traffic_type == 'internal' and 'internal_detector' in self.models:
                        internal_proba = self.models['internal_detector'].predict_proba(features_4.reshape(1, -1))[0]
                        results['level3_normal_validation']['internal'] = {
                            'normal_probability': float(internal_proba[0]),
                            'anomaly_probability': float(internal_proba[1])
                        }

                        if internal_proba[1] > 0.7:  # Umbral alto para anomalías
                            results['final_classification'] = 'INTERNAL_ANOMALY'
                            results['confidence'] = internal_proba[1]
                            results['alerts'].append(f'Internal Traffic Anomaly (confidence: {internal_proba[1]:.2%})')

                    elif traffic_type == 'web' and 'web_detector' in self.models:
                        web_proba = self.models['web_detector'].predict_proba(features_4.reshape(1, -1))[0]
                        results['level3_normal_validation']['web'] = {
                            'normal_probability': float(web_proba[0]),
                            'anomaly_probability': float(web_proba[1])
                        }

                        if web_proba[1] > 0.7:  # Umbral alto para anomalías
                            results['final_classification'] = 'WEB_ANOMALY'
                            results['confidence'] = web_proba[1]
                            results['alerts'].append(f'Web Traffic Anomaly (confidence: {web_proba[1]:.2%})')

                    # Si no hay anomalías detectadas, es tráfico normal
                    if results['final_classification'] == 'NORMAL':
                        results['confidence'] = 1.0 - attack_probability

        except Exception as e:
            results['error'] = str(e)
            results['final_classification'] = 'ERROR'

        results['processing_time_ms'] = (time.time() - start_time) * 1000
        return results

    def get_pipeline_stats(self) -> Dict:
        """Retorna estadísticas del pipeline"""
        return {
            'models_loaded': len(self.models),
            'models_list': list(self.models.keys()),
            'feature_mappings': {
                '82_to_23_available': len(self.feature_mappings.get('82_to_23_map', {})),
                '82_to_4_available': len(self.feature_mappings.get('82_to_4_map', {})),
                'level1_features': len(self.feature_mappings.get('level1_features', []))
            }
        }


def test_complete_pipeline():
    """Prueba el pipeline completo con datos dummy"""
    print("\n🧪 TESTING PIPELINE COMPLETO")
    print("=" * 60)

    # Inicializar pipeline
    pipeline = CompleteMlPipeline()

    # Mostrar estadísticas
    stats = pipeline.get_pipeline_stats()
    print(f"📊 Pipeline Stats: {stats}")

    # Generar datos dummy de 82 features
    dummy_features = np.random.random(82)
    feature_names = [f' Feature_{i}' for i in range(82)]

    # Simular nombres de features reales (algunas)
    real_feature_names = [
                             ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',
                             ' Total Length of Fwd Packets', ' Total Length of Bwd Packets',
                             ' Flow Bytes/s', ' Fwd Packet Length Mean', ' Bwd Packet Length Mean',
                             ' Flow IAT Mean', ' Flow IAT Std', ' Source Port', ' Destination Port'
                         ] + [f' Feature_{i}' for i in range(12, 82)]

    # Test 1: Tráfico normal
    print("\n🔍 Test 1 - Tráfico Normal:")
    normal_features = np.random.random(82) * 0.1  # Valores pequeños = normal
    results = pipeline.predict_complete(normal_features, real_feature_names)
    print(f"   🎯 Clasificación: {results['final_classification']}")
    print(f"   📈 Confianza: {results['confidence']:.2%}")
    print(f"   ⏱️ Tiempo: {results['processing_time_ms']:.1f}ms")

    # Test 2: Posible ataque
    print("\n🔍 Test 2 - Posible Ataque:")
    attack_features = np.random.random(82)
    attack_features[3] = 100000  # sbytes muy alto = posible ataque
    attack_features[0] = 1000  # duración alta
    results = pipeline.predict_complete(attack_features, real_feature_names)
    print(f"   🎯 Clasificación: {results['final_classification']}")
    print(f"   📈 Confianza: {results['confidence']:.2%}")
    print(f"   ⏱️ Tiempo: {results['processing_time_ms']:.1f}ms")
    if results['alerts']:
        print(f"   🚨 Alertas: {results['alerts']}")


def main():
    """Función principal"""
    print("🚀 UPGRADED HAPPINESS - PIPELINE ML COMPLETO")
    print("=" * 60)

    try:
        # Probar pipeline completo
        test_complete_pipeline()

        print("\n✅ PIPELINE COMPLETO OPERATIVO")
        print("🎯 Ready para integración con scapy_to_ml_features.py")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()