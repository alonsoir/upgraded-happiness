#!/usr/bin/env python3
"""
validate_ensemble_models.py - Suite de Testing para Modelos Ensemble
Valida que los modelos .joblib entrenados funcionen correctamente antes de integrarlos
en lightweight_ml_detector_v2.py
"""

import os
import sys
import json
import joblib
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import warnings

warnings.filterwarnings("ignore")


class ModelValidationSuite:
    """
    Suite de testing para validar modelos ensemble antes de producción
    """

    def __init__(self, config_path: str = "config/model_validation_config.json"):
        """
        Inicializa la suite de validación

        Args:
            config_path: Ruta al archivo de configuración de validación
        """
        self.config = self._load_validation_config(config_path)
        self.models = {}
        self.scalers = {}
        self.feature_orders = {}
        self.metadata = {}
        self.test_results = []

        print("🧪 Model Validation Suite inicializada")
        print(f"   📋 Config: {config_path}")

    def _load_validation_config(self, config_path: str) -> Dict:
        """Carga configuración de validación o crea una por defecto"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            print(f"✅ Configuración de validación cargada: {config_path}")
            return config
        except FileNotFoundError:
            print(f"⚠️  Config no encontrado, creando por defecto...")
            return self._create_default_validation_config(config_path)

    def _create_default_validation_config(self, config_path: str) -> Dict:
        """Crea configuración por defecto para validación"""
        config = {
            "validation_info": {
                "name": "Ensemble Model Validation Suite",
                "version": "1.0.0",
                "description": "Testing suite para validar modelos antes de producción",
                "created": datetime.now().isoformat()
            },
            "models": {
                "attack_detector": {
                    "path": "models/model_20250730_081902/model.pkl",
                    "scaler_path": "models/model_20250730_081902/scaler.pkl",
                    "metadata_path": "models/model_20250730_081902/metadata.json",
                    "type": "advanced",
                    "expected_features": 21,
                    "description": "Detector general de ataques conocidos"
                },
                "normal_behavior": {
                    "path": "models/rf_normal_behavior.joblib",
                    "feature_order_path": "models/feature_order.txt",
                    "type": "simple",
                    "expected_features": 21,
                    "description": "Modelo de comportamiento normal público"
                },
                "internal_behavior": {
                    "path": "models/rf_internal_behavior.joblib",
                    "feature_order_path": "models/feature_order.txt",
                    "type": "simple",
                    "expected_features": 21,
                    "description": "Modelo de comportamiento interno privado"
                }
            },
            "test_scenarios": {
                "dns_lookup": {
                    "description": "Lookup DNS normal - NO debe ser 100% peligroso",
                    "expected_classification": "NORMAL",
                    "max_anomaly_score": 0.3
                },
                "normal_web": {
                    "description": "Tráfico web normal HTTP/HTTPS",
                    "expected_classification": "NORMAL",
                    "max_anomaly_score": 0.2
                },
                "internal_communication": {
                    "description": "Comunicación interna entre IPs privadas",
                    "expected_classification": "NORMAL_INTERNAL",
                    "max_anomaly_score": 0.25
                },
                "suspicious_scan": {
                    "description": "Posible port scan",
                    "expected_classification": "ANOMALOUS",
                    "min_anomaly_score": 0.6
                },
                "obvious_attack": {
                    "description": "Ataque obvio con patrón conocido",
                    "expected_classification": "ATTACK",
                    "min_anomaly_score": 0.8
                }
            },
            "validation_thresholds": {
                "attack_threshold": 0.75,
                "normal_threshold": 0.85,
                "anomaly_threshold": 0.25,
                "confidence_threshold": 0.7
            },
            "output": {
                "detailed_report": "validation_results/detailed_report.json",
                "summary_report": "validation_results/summary_report.txt",
                "failed_tests": "validation_results/failed_tests.json"
            }
        }

        # Crear directorio y guardar config
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✅ Configuración por defecto creada: {config_path}")
        return config

    def load_models(self) -> bool:
        """
        Carga todos los modelos configurados

        Returns:
            True si se cargaron correctamente, False en caso contrario
        """
        print("\n🔍 CARGANDO MODELOS PARA VALIDACIÓN")
        print("=" * 50)

        success = True

        for model_name, model_config in self.config["models"].items():
            print(f"\n📁 Cargando modelo: {model_name}")
            print(f"   Descripción: {model_config['description']}")
            print(f"   Tipo: {model_config['type']}")
            print(f"   Features esperadas: {model_config['expected_features']}")

            try:
                if model_config["type"] == "advanced":
                    success &= self._load_advanced_model(model_name, model_config)
                else:
                    success &= self._load_simple_model(model_name, model_config)

                if model_name in self.models:
                    print(f"   ✅ Cargado correctamente")
                else:
                    print(f"   ❌ Error en carga")
                    success = False

            except Exception as e:
                print(f"   ❌ Error cargando {model_name}: {e}")
                success = False

        print(f"\n📊 Resumen de carga:")
        print(f"   Modelos cargados: {len(self.models)}/{len(self.config['models'])}")
        print(f"   Estado general: {'✅ ÉXITO' if success else '❌ FALLOS'}")

        return success

    def _load_advanced_model(self, model_name: str, config: Dict) -> bool:
        """Carga modelo avanzado con scaler y metadata"""
        try:
            # Cargar modelo principal
            if not os.path.exists(config["path"]):
                print(f"   ⚠️  Archivo modelo no encontrado: {config['path']}")
                return False

            # Usar joblib para cargar (incluso si es .pkl, porque sklearn usa joblib internamente)
            self.models[model_name] = joblib.load(config["path"])

            # Cargar scaler si existe
            if "scaler_path" in config and os.path.exists(config["scaler_path"]):
                self.scalers[model_name] = joblib.load(config["scaler_path"])
                print(f"   📐 Scaler cargado")

            # Cargar metadata si existe
            if "metadata_path" in config and os.path.exists(config["metadata_path"]):
                with open(config["metadata_path"], 'r') as f:
                    self.metadata[model_name] = json.load(f)
                print(f"   📋 Metadata cargada")

            return True

        except Exception as e:
            print(f"   ❌ Error cargando modelo avanzado: {e}")
            return False

    def _load_simple_model(self, model_name: str, config: Dict) -> bool:
        """Carga modelo simple (.joblib)"""
        try:
            if not os.path.exists(config["path"]):
                print(f"   ⚠️  Archivo modelo no encontrado: {config['path']}")
                return False

            self.models[model_name] = joblib.load(config["path"])

            # Cargar orden de características si existe
            if "feature_order_path" in config and os.path.exists(config["feature_order_path"]):
                with open(config["feature_order_path"], 'r') as f:
                    features = [line.strip() for line in f.readlines()]
                    self.feature_orders[model_name] = features
                print(f"   📝 Feature order cargado: {len(features)} features")

            return True

        except Exception as e:
            print(f"   ❌ Error cargando modelo simple: {e}")
            return False

    def create_test_events(self) -> List[Dict]:
        """
        Crea eventos sintéticos para testing basados en los escenarios configurados

        Returns:
            Lista de eventos de prueba
        """
        print("\n🧪 CREANDO EVENTOS DE PRUEBA SINTÉTICOS")
        print("=" * 50)

        test_events = []

        # 1. DNS Lookup (EL PROBLEMÁTICO 😅)
        dns_event = {
            "event_id": "test_dns_001",
            "description": "DNS lookup normal - NO debe ser 100% peligroso",
            "expected": "NORMAL",
            "data": {
                "dur": 0.045,
                "proto": 17,  # UDP
                "service": 0,  # DNS
                "state": 3,
                "spkts": 1,
                "dpkts": 1,
                "sbytes": 64,
                "dbytes": 80,
                "rate": 1422.22,
                "sttl": 64,
                "dttl": 64,
                "sload": 1422.22,
                "dload": 1777.78,
                "sloss": 0,
                "dloss": 0,
                "sinpkt": 0.045,
                "dinpkt": 0.045,
                "packet_imbalance": 0.5,
                "byte_imbalance": 0.444,
                "loss_ratio": 0.0,
                "hour": 14,
                "day_of_week": 1,
                "is_weekend": 0,
                "src_country": "PRIVATE",
                "src_asn": 0,
                "country_risk": 0.0,
                "distance_km": 0.0,
                "conn_state_abnormal": 0,
                "high_port_activity": 1  # Puerto 53 DNS
            }
        }
        test_events.append(dns_event)

        # 2. Tráfico Web Normal HTTPS
        web_event = {
            "event_id": "test_web_001",
            "description": "Tráfico web normal HTTPS",
            "expected": "NORMAL",
            "data": {
                "dur": 0.25,
                "proto": 6,  # TCP
                "service": 1,  # Web
                "state": 3,
                "spkts": 5,
                "dpkts": 4,
                "sbytes": 512,
                "dbytes": 1024,
                "rate": 6144.0,
                "sttl": 64,
                "dttl": 64,
                "sload": 2048.0,
                "dload": 4096.0,
                "sloss": 0,
                "dloss": 0,
                "sinpkt": 0.05,
                "dinpkt": 0.0625,
                "packet_imbalance": 0.556,
                "byte_imbalance": 0.333,
                "loss_ratio": 0.0,
                "hour": 10,
                "day_of_week": 2,
                "is_weekend": 0,
                "src_country": "PRIVATE",
                "src_asn": 0,
                "country_risk": 0.0,
                "distance_km": 0.0,
                "conn_state_abnormal": 0,
                "high_port_activity": 1
            }
        }
        test_events.append(web_event)

        # 3. Comunicación Interna
        internal_event = {
            "event_id": "test_internal_001",
            "description": "Comunicación interna entre IPs privadas",
            "expected": "NORMAL_INTERNAL",
            "data": {
                "dur": 0.15,
                "proto": 6,  # TCP
                "service": 1,
                "state": 3,
                "spkts": 3,
                "dpkts": 2,
                "sbytes": 300,
                "dbytes": 150,
                "rate": 3000.0,
                "sttl": 64,
                "dttl": 64,
                "sload": 2000.0,
                "dload": 1000.0,
                "sloss": 0,
                "dloss": 0,
                "sinpkt": 0.05,
                "dinpkt": 0.075,
                "packet_imbalance": 0.6,
                "byte_imbalance": 0.667,
                "loss_ratio": 0.0,
                "hour": 9,
                "day_of_week": 1,
                "is_weekend": 0,
                "src_country": "PRIVATE",
                "src_asn": 0,
                "country_risk": 0.0,
                "distance_km": 0.0,
                "conn_state_abnormal": 0,
                "high_port_activity": 0
            }
        }
        test_events.append(internal_event)

        # 4. Posible Port Scan
        scan_event = {
            "event_id": "test_scan_001",
            "description": "Posible port scan - múltiples conexiones rápidas",
            "expected": "ANOMALOUS",
            "data": {
                "dur": 0.001,  # Muy rápido
                "proto": 6,  # TCP
                "service": 2,
                "state": 1,  # Estado anómalo
                "spkts": 1,
                "dpkts": 0,  # Sin respuesta
                "sbytes": 60,
                "dbytes": 0,
                "rate": 60000.0,  # Rate muy alto
                "sttl": 255,  # TTL sospechoso
                "dttl": 0,
                "sload": 60000.0,
                "dload": 0.0,
                "sloss": 0,
                "dloss": 0,
                "sinpkt": 0.001,
                "dinpkt": 0.0,
                "packet_imbalance": 1.0,  # Solo salida
                "byte_imbalance": 1.0,
                "loss_ratio": 0.0,
                "hour": 3,  # Hora sospechosa
                "day_of_week": 6,
                "is_weekend": 1,
                "src_country": "UNKNOWN",
                "src_asn": 0,
                "country_risk": 0.8,
                "distance_km": 5000.0,
                "conn_state_abnormal": 1,
                "high_port_activity": 1
            }
        }
        test_events.append(scan_event)

        # 5. Ataque Obvio
        attack_event = {
            "event_id": "test_attack_001",
            "description": "Ataque obvio con múltiples indicadores",
            "expected": "ATTACK",
            "data": {
                "dur": 0.005,
                "proto": 6,  # TCP
                "service": 1,
                "state": 2,  # Estado de ataque
                "spkts": 100,  # Muchos paquetes
                "dpkts": 0,
                "sbytes": 5000,  # Muchos bytes
                "dbytes": 0,
                "rate": 1000000.0,  # Rate extremo
                "sttl": 255,
                "dttl": 0,
                "sload": 1000000.0,
                "dload": 0.0,
                "sloss": 20,  # Pérdida de paquetes
                "dloss": 0,
                "sinpkt": 0.00005,
                "dinpkt": 0.0,
                "packet_imbalance": 1.0,
                "byte_imbalance": 1.0,
                "loss_ratio": 0.2,  # 20% pérdida
                "hour": 2,  # Hora muy sospechosa
                "day_of_week": 0,
                "is_weekend": 1,
                "src_country": "UNKNOWN",
                "src_asn": 0,
                "country_risk": 1.0,  # Máximo riesgo
                "distance_km": 15000.0,
                "conn_state_abnormal": 1,
                "high_port_activity": 1
            }
        }
        test_events.append(attack_event)

        print(f"📋 Eventos de prueba creados: {len(test_events)}")
        for event in test_events:
            print(f"   • {event['event_id']}: {event['description']}")

        return test_events

    def prepare_features_for_model(self, event_data: Dict, model_name: str) -> Optional[np.ndarray]:
        """
        Prepara las features de un evento para un modelo específico

        Args:
            event_data: Datos del evento
            model_name: Nombre del modelo

        Returns:
            Array numpy con las features preparadas o None si hay error
        """
        try:
            model_config = self.config["models"][model_name]

            if model_config["type"] == "advanced":
                return self._prepare_advanced_features(event_data, model_name)
            else:
                return self._prepare_simple_features(event_data, model_name)

        except Exception as e:
            print(f"   ❌ Error preparando features para {model_name}: {e}")
            return None

    def _prepare_advanced_features(self, event_data: Dict, model_name: str) -> np.ndarray:
        """Prepara features para modelo avanzado"""
        # Para el modelo avanzado, usar metadata si está disponible
        if model_name in self.metadata:
            # Usar el mismo preprocesamiento que durante entrenamiento
            # Por ahora, usar subset de features disponibles
            feature_subset = [
                'dur', 'proto', 'service', 'state', 'spkts', 'dpkts',
                'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 'sload', 'dload',
                'sloss', 'dloss', 'sinpkt', 'dinpkt', 'packet_imbalance',
                'byte_imbalance', 'loss_ratio', 'hour'
            ]
        else:
            # Fallback básico
            feature_subset = list(event_data.keys())[:21]

        features = []
        for feature in feature_subset:
            features.append(float(event_data.get(feature, 0)))

        return np.array(features)

    def _prepare_simple_features(self, event_data: Dict, model_name: str) -> np.ndarray:
        """Prepara features para modelo simple"""
        if model_name in self.feature_orders:
            # Usar orden de features guardado
            features = []
            for feature in self.feature_orders[model_name]:
                features.append(float(event_data.get(feature, 0)))
            return np.array(features)
        else:
            # Usar todas las features disponibles
            features = []
            for key, value in event_data.items():
                features.append(float(value))
            return np.array(features)

    def test_model_predictions(self, test_events: List[Dict]) -> List[Dict]:
        """
        Ejecuta predicciones en todos los modelos para todos los eventos de prueba

        Args:
            test_events: Lista de eventos de prueba

        Returns:
            Lista de resultados detallados
        """
        print(f"\n🔮 EJECUTANDO PREDICCIONES")
        print("=" * 50)

        results = []

        for event in test_events:
            print(f"\n🧪 Testing evento: {event['event_id']}")
            print(f"   📝 {event['description']}")
            print(f"   🎯 Esperado: {event['expected']}")

            event_results = {
                "event_id": event["event_id"],
                "description": event["description"],
                "expected": event["expected"],
                "predictions": {},
                "features_info": {},
                "success": True,
                "issues": []
            }

            # Probar cada modelo
            for model_name in self.models.keys():
                print(f"      🤖 Modelo: {model_name}")

                try:
                    # Preparar features
                    features = self.prepare_features_for_model(event["data"], model_name)

                    if features is None:
                        event_results["predictions"][model_name] = {
                            "error": "Error preparando features"
                        }
                        event_results["success"] = False
                        event_results["issues"].append(f"Features error en {model_name}")
                        print(f"         ❌ Error preparando features")
                        continue

                    # Guardar info de features
                    event_results["features_info"][model_name] = {
                        "feature_count": len(features),
                        "feature_shape": features.shape,
                        "has_nan": bool(np.isnan(features).any()),
                        "has_inf": bool(np.isinf(features).any())
                    }

                    # Verificar features válidas
                    if np.isnan(features).any() or np.isinf(features).any():
                        event_results["predictions"][model_name] = {
                            "error": "Features contienen NaN o Inf"
                        }
                        event_results["success"] = False
                        event_results["issues"].append(f"Features inválidas en {model_name}")
                        print(f"         ❌ Features inválidas (NaN/Inf)")
                        continue

                    # Aplicar scaler si existe
                    if model_name in self.scalers:
                        features_scaled = self.scalers[model_name].transform(features.reshape(1, -1))
                    else:
                        features_scaled = features.reshape(1, -1)

                    # Hacer predicción
                    model = self.models[model_name]

                    prediction = model.predict(features_scaled)[0]

                    # Obtener probabilidades si es posible
                    try:
                        probabilities = model.predict_proba(features_scaled)[0]
                        confidence = np.max(probabilities)
                        prob_dict = {f"class_{i}": float(p) for i, p in enumerate(probabilities)}
                    except:
                        probabilities = None
                        confidence = 0.5
                        prob_dict = {}

                    event_results["predictions"][model_name] = {
                        "prediction": int(prediction),
                        "confidence": float(confidence),
                        "probabilities": prob_dict,
                        "features_used": len(features)
                    }

                    print(f"         ✅ Predicción: {prediction}, Confianza: {confidence:.3f}")

                except Exception as e:
                    event_results["predictions"][model_name] = {
                        "error": str(e)
                    }
                    event_results["success"] = False
                    event_results["issues"].append(f"Error predicción en {model_name}: {e}")
                    print(f"         ❌ Error: {e}")

            results.append(event_results)

        return results

    def analyze_results(self, results: List[Dict]) -> Dict:
        """
        Analiza los resultados de testing y genera reporte

        Args:
            results: Resultados de las predicciones

        Returns:
            Análisis detallado
        """
        print(f"\n📊 ANÁLISIS DE RESULTADOS")
        print("=" * 50)

        analysis = {
            "summary": {
                "total_events": len(results),
                "successful_events": 0,
                "failed_events": 0,
                "models_tested": list(self.models.keys()),
                "critical_issues": []
            },
            "model_performance": {},
            "scenario_analysis": {},
            "recommendations": []
        }

        # Analizar cada modelo
        for model_name in self.models.keys():
            model_analysis = {
                "predictions_made": 0,
                "prediction_errors": 0,
                "confidence_scores": [],
                "predictions_by_class": {},
                "issues": []
            }

            for result in results:
                if model_name in result["predictions"]:
                    pred_result = result["predictions"][model_name]

                    if "error" not in pred_result:
                        model_analysis["predictions_made"] += 1
                        model_analysis["confidence_scores"].append(pred_result["confidence"])

                        pred_class = pred_result["prediction"]
                        if pred_class not in model_analysis["predictions_by_class"]:
                            model_analysis["predictions_by_class"][pred_class] = 0
                        model_analysis["predictions_by_class"][pred_class] += 1
                    else:
                        model_analysis["prediction_errors"] += 1
                        model_analysis["issues"].append(pred_result["error"])

            # Calcular estadísticas
            if model_analysis["confidence_scores"]:
                model_analysis["avg_confidence"] = np.mean(model_analysis["confidence_scores"])
                model_analysis["min_confidence"] = np.min(model_analysis["confidence_scores"])
                model_analysis["max_confidence"] = np.max(model_analysis["confidence_scores"])
            else:
                model_analysis["avg_confidence"] = 0.0
                model_analysis["min_confidence"] = 0.0
                model_analysis["max_confidence"] = 0.0

            analysis["model_performance"][model_name] = model_analysis

        # Analizar escenarios específicos
        dns_results = [r for r in results if "dns" in r["event_id"].lower()]
        if dns_results:
            dns_result = dns_results[0]
            dns_analysis = {
                "event_id": dns_result["event_id"],
                "success": dns_result["success"],
                "predictions": {}
            }

            for model_name, pred in dns_result["predictions"].items():
                if "error" not in pred:
                    dns_analysis["predictions"][model_name] = {
                        "prediction": pred["prediction"],
                        "confidence": pred["confidence"],
                        "is_problematic": pred["confidence"] > 0.8 and pred["prediction"] == 1
                    }

            analysis["scenario_analysis"]["dns_lookup"] = dns_analysis

        # Contar eventos exitosos
        analysis["summary"]["successful_events"] = sum(1 for r in results if r["success"])
        analysis["summary"]["failed_events"] = len(results) - analysis["summary"]["successful_events"]

        # Identificar problemas críticos
        for model_name, model_perf in analysis["model_performance"].items():
            if model_perf["prediction_errors"] > 0:
                analysis["summary"]["critical_issues"].append(
                    f"Modelo {model_name}: {model_perf['prediction_errors']} errores de predicción"
                )

            if model_perf["avg_confidence"] < 0.5:
                analysis["summary"]["critical_issues"].append(
                    f"Modelo {model_name}: Confianza promedio muy baja ({model_perf['avg_confidence']:.3f})"
                )

        # El DNS problemático 😅
        if "dns_lookup" in analysis["scenario_analysis"]:
            dns_data = analysis["scenario_analysis"]["dns_lookup"]
            for model_name, pred_data in dns_data["predictions"].items():
                if pred_data.get("is_problematic", False):
                    analysis["summary"]["critical_issues"].append(
                        f"🚨 CRÍTICO: Modelo {model_name} marca DNS como {pred_data['confidence'] * 100:.1f}% peligroso"
                    )

        # Generar recomendaciones
        if analysis["summary"]["critical_issues"]:
            analysis["recommendations"].append("❌ HAY PROBLEMAS CRÍTICOS - No usar en producción")
            analysis["recommendations"].append("🔧 Revisar entrenamiento de modelos con problemas")
        else:
            analysis["recommendations"].append("✅ Modelos parecen estables para testing adicional")
            analysis["recommendations"].append("🚀 Continuar con integración en lightweight_ml_detector_v2")

        return analysis

    def generate_reports(self, results: List[Dict], analysis: Dict):
        """Genera reportes detallados"""
        print(f"\n📝 GENERANDO REPORTES")
        print("=" * 50)

        # Crear directorio de reportes
        os.makedirs("validation_results", exist_ok=True)

        # Reporte detallado JSON
        detailed_report = {
            "validation_info": {
                "timestamp": datetime.now().isoformat(),
                "models_tested": list(self.models.keys()),
                "total_tests": len(results)
            },
            "test_results": results,
            "analysis": analysis
        }

        with open("validation_results/detailed_report.json", 'w') as f:
            json.dump(detailed_report, f, indent=2, default=str)

        # Reporte de resumen texto
        with open("validation_results/summary_report.txt", 'w') as f:
            f.write("ENSEMBLE MODEL VALIDATION REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Models tested: {', '.join(self.models.keys())}\n")
            f.write(f"Total events: {analysis['summary']['total_events']}\n")
            f.write(f"Successful: {analysis['summary']['successful_events']}\n")
            f.write(f"Failed: {analysis['summary']['failed_events']}\n\n")

            f.write("MODEL PERFORMANCE:\n")
            f.write("-" * 30 + "\n")
            for model_name, perf in analysis["model_performance"].items():
                f.write(f"\n{model_name}:\n")
                f.write(f"  Predictions made: {perf['predictions_made']}\n")
                f.write(f"  Prediction errors: {perf['prediction_errors']}\n")
                f.write(f"  Average confidence: {perf['avg_confidence']:.3f}\n")
                f.write(f"  Predictions by class: {perf['predictions_by_class']}\n")

            f.write(f"\nCRITICAL ISSUES:\n")
            f.write("-" * 30 + "\n")
            for issue in analysis["summary"]["critical_issues"]:
                f.write(f"• {issue}\n")

            f.write(f"\nRECOMMENDATIONS:\n")
            f.write("-" * 30 + "\n")
            for rec in analysis["recommendations"]:
                f.write(f"• {rec}\n")

        # Tests fallidos
        failed_tests = [r for r in results if not r["success"]]
        if failed_tests:
            with open("validation_results/failed_tests.json", 'w') as f:
                json.dump(failed_tests, f, indent=2, default=str)

        print(f"📁 Reportes generados:")
        print(f"   📋 Detallado: validation_results/detailed_report.json")
        print(f"   📄 Resumen: validation_results/summary_report.txt")
        if failed_tests:
            print(f"   ❌ Tests fallidos: validation_results/failed_tests.json")

    def print_summary(self, analysis: Dict):
        """Imprime resumen en consola"""
        print(f"\n🎯 RESUMEN DE VALIDACIÓN")
        print("=" * 50)

        summary = analysis["summary"]
        print(f"📊 Eventos testados: {summary['total_events']}")
        print(f"✅ Exitosos: {summary['successful_events']}")
        print(f"❌ Fallidos: {summary['failed_events']}")
        print(f"🤖 Modelos: {', '.join(summary['models_tested'])}")

        print(f"\n🔍 PERFORMANCE POR MODELO:")
        for model_name, perf in analysis["model_performance"].items():
            status = "✅" if perf["prediction_errors"] == 0 else "❌"
            print(f"   {status} {model_name}:")
            print(f"      Predicciones: {perf['predictions_made']}")
            print(f"      Errores: {perf['prediction_errors']}")
            print(f"      Confianza promedio: {perf['avg_confidence']:.3f}")

        if summary["critical_issues"]:
            print(f"\n🚨 PROBLEMAS CRÍTICOS:")
            for issue in summary["critical_issues"]:
                print(f"   • {issue}")

        print(f"\n💡 RECOMENDACIONES:")
        for rec in analysis["recommendations"]:
            print(f"   • {rec}")

    def run_validation(self) -> bool:
        """
        Ejecuta la suite completa de validación

        Returns:
            True si todo OK, False si hay problemas críticos
        """
        print("🚀 INICIANDO VALIDATION SUITE")
        print("=" * 70)

        # 1. Cargar modelos
        if not self.load_models():
            print("❌ Error cargando modelos - Abortando validación")
            return False

        # 2. Crear eventos de prueba
        test_events = self.create_test_events()

        # 3. Ejecutar predicciones
        results = self.test_model_predictions(test_events)

        # 4. Analizar resultados
        analysis = self.analyze_results(results)

        # 5. Generar reportes
        self.generate_reports(results, analysis)

        # 6. Mostrar resumen
        self.print_summary(analysis)

        # 7. Determinar si hay problemas críticos
        has_critical_issues = len(analysis["summary"]["critical_issues"]) > 0

        print(f"\n🏁 VALIDACIÓN COMPLETADA")
        print("=" * 50)

        if has_critical_issues:
            print("❌ HAY PROBLEMAS CRÍTICOS - Modelos NO listos para producción")
            print("🔧 Revisar reportes y corregir antes de integrar")
            return False
        else:
            print("✅ VALIDACIÓN EXITOSA - Modelos listos para integración")
            print("🚀 Proceder con lightweight_ml_detector_v2")
            return True


def main():
    """Función principal"""
    print("🧪 ENSEMBLE MODEL VALIDATION SUITE")
    print("Testing models before integration in lightweight_ml_detector_v2")
    print("=" * 70)

    try:
        # Crear suite de validación
        validator = ModelValidationSuite()

        # Ejecutar validación completa
        success = validator.run_validation()

        return 0 if success else 1

    except KeyboardInterrupt:
        print("\n👋 Validación cancelada por el usuario")
        return 1
    except Exception as e:
        print(f"\n❌ Error fatal en validación: {e}")
        return 1


if __name__ == "__main__":
    exit(main())