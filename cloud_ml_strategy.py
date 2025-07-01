#!/usr/bin/env python3
"""
Estrategia de ML en la nube para modelos pesados
Optimizado para presupuesto limitado
"""

import json
import time
from datetime import datetime


class CloudMLStrategy:
    def __init__(self):
        self.cloud_options = {
            "google_colab": {
                "cost": "GRATIS",
                "gpu": "Tesla T4 (12h/día)",
                "ram": "12-25GB",
                "storage": "100GB temp",
                "pros": ["Gratis", "Jupyter integrado", "GPU Tesla T4"],
                "cons": ["Límite 12h", "Desconexión automática", "No persistente"],
                "best_for": "Experimentación y prototipos",
            },
            "kaggle_notebooks": {
                "cost": "GRATIS",
                "gpu": "Tesla P100 (30h/semana)",
                "ram": "16GB",
                "storage": "20GB temp + datasets públicos",
                "pros": ["GPU P100", "30h/semana", "Datasets públicos"],
                "cons": ["Límite semanal", "No API externa"],
                "best_for": "Entrenamiento con datasets públicos",
            },
            "paperspace_gradient": {
                "cost": "$8/mes (Free tier)",
                "gpu": "M4000 gratis, V100 $0.45/h",
                "ram": "8-30GB",
                "storage": "5GB persistente gratis",
                "pros": ["Free tier generoso", "Jupyter", "Persistent storage"],
                "cons": ["Costo después de free tier"],
                "best_for": "Desarrollo serio con presupuesto bajo",
            },
            "aws_sagemaker": {
                "cost": "$0.05-2.00/hora",
                "gpu": "ml.g4dn.xlarge ($0.736/h)",
                "ram": "4-16GB",
                "storage": "Pay per use",
                "pros": ["Escalable", "Producción", "Integración AWS"],
                "cons": ["Más caro", "Complejidad setup"],
                "best_for": "Producción y modelos grandes",
            },
            "vast_ai": {
                "cost": "$0.10-0.50/hora",
                "gpu": "RTX 3090, A100 disponibles",
                "ram": "16-128GB",
                "storage": "Variable",
                "pros": ["MUY barato", "GPUs potentes", "Flexibilidad"],
                "cons": ["Menos confiable", "Setup manual"],
                "best_for": "Entrenamiento intensivo barato",
            },
        }

        self.model_strategies = {
            "lightweight_local": {
                "models": ["RandomForest", "XGBoost", "IsolationForest"],
                "hardware": "Intel i9 + 32GB RAM",
                "training_time": "5-30 minutos",
                "dataset_size": "Hasta 1M eventos",
                "accuracy": "80-85%",
            },
            "medium_cloud": {
                "models": ["Deep Neural Networks", "LSTM", "Transformers pequeños"],
                "hardware": "Tesla T4/P100 (Colab/Kaggle)",
                "training_time": "1-6 horas",
                "dataset_size": "1-10M eventos",
                "accuracy": "85-90%",
            },
            "heavy_cloud": {
                "models": ["Large Transformers", "Ensemble models", "Graph NNs"],
                "hardware": "A100/V100 (Vast.ai/AWS)",
                "training_time": "6-24 horas",
                "dataset_size": "10M+ eventos",
                "accuracy": "90-95%",
            },
        }

    def recommend_strategy(self, dataset_size, budget_monthly, accuracy_target):
        """Recomendar estrategia basada en necesidades"""

        print(f"🎯 RECOMENDACIÓN ML PERSONALIZADA")
        print("=" * 50)
        print(f"📊 Tamaño dataset: {dataset_size:,} eventos")
        print(f"💰 Presupuesto mensual: ${budget_monthly}")
        print(f"🎯 Precisión objetivo: {accuracy_target}%")
        print()

        # Lógica de recomendación
        if dataset_size < 100000 and accuracy_target < 85:
            strategy = "lightweight_local"
            cloud = None

        elif dataset_size < 1000000 and budget_monthly == 0:
            strategy = "medium_cloud"
            cloud = "google_colab"

        elif dataset_size < 5000000 and budget_monthly < 20:
            strategy = "medium_cloud"
            cloud = "paperspace_gradient"

        elif budget_monthly < 50:
            strategy = "medium_cloud"
            cloud = "vast_ai"

        else:
            strategy = "heavy_cloud"
            cloud = "aws_sagemaker"

        # Mostrar recomendación
        print(f"🔥 ESTRATEGIA RECOMENDADA: {strategy.upper()}")

        strategy_info = self.model_strategies[strategy]
        print(f"   🤖 Modelos: {', '.join(strategy_info['models'])}")
        print(f"   💻 Hardware: {strategy_info['hardware']}")
        print(f"   ⏱️  Tiempo entrenamiento: {strategy_info['training_time']}")
        print(f"   🎯 Precisión esperada: {strategy_info['accuracy']}")

        if cloud:
            print(f"\n☁️  PLATAFORMA RECOMENDADA: {cloud.upper()}")
            cloud_info = self.cloud_options[cloud]
            print(f"   💰 Costo: {cloud_info['cost']}")
            print(f"   🖥️  GPU: {cloud_info['gpu']}")
            print(f"   💾 RAM: {cloud_info['ram']}")
            print(f"   ✅ Mejor para: {cloud_info['best_for']}")

        return strategy, cloud

    def generate_training_pipeline(self, strategy, cloud_platform=None):
        """Generar pipeline de entrenamiento"""

        if strategy == "lightweight_local":
            return self._generate_local_pipeline()
        elif cloud_platform == "google_colab":
            return self._generate_colab_pipeline()
        elif cloud_platform == "vast_ai":
            return self._generate_vastai_pipeline()
        else:
            return self._generate_generic_cloud_pipeline()

    def _generate_local_pipeline(self):
        """Pipeline para entrenamiento local"""
        pipeline = """
# PIPELINE DE ENTRENAMIENTO LOCAL (Intel i9)

## 1. Preparación de datos
python lightweight_ml_detector.py --prepare-data --sample-size 100000

## 2. Entrenamiento de modelos ligeros  
python lightweight_ml_detector.py --train --models "rf,xgb,isolation"

## 3. Evaluación
python lightweight_ml_detector.py --evaluate --test-size 0.2

## 4. Despliegue
python lightweight_ml_detector.py --deploy --mode production

# Tiempo estimado: 15-30 minutos
# Recursos: 8 cores, 16GB RAM máximo
"""
        return pipeline

    def _generate_colab_pipeline(self):
        """Pipeline para Google Colab"""
        pipeline = """
# PIPELINE PARA GOOGLE COLAB (GRATIS)

## Setup inicial en Colab
!pip install xgboost sklearn torch transformers

## 1. Subir datos
from google.colab import files
uploaded = files.upload()  # Subir dataset local

## 2. Entrenamiento con GPU
import torch
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# Modelos más pesados que en local
- Neural Networks con PyTorch
- Transformers pequeños para análisis de texto
- LSTM para secuencias temporales

## 3. Guardar modelos entrenados
torch.save(model.state_dict(), 'model.pth')
files.download('model.pth')  # Descargar modelo

## 4. Integrar en sistema local
# Usar modelo pre-entrenado en detector local

# Tiempo: 2-6 horas
# Costo: GRATIS
# Limitación: 12 horas continuas
"""
        return pipeline

    def _generate_vastai_pipeline(self):
        """Pipeline para Vast.ai (barato)"""
        pipeline = """
# PIPELINE PARA VAST.AI (PRESUPUESTO BAJO)

## 1. Configuración de instancia
- Buscar RTX 3090 o A100 por ~$0.20/hora
- Ubuntu 20.04 + CUDA + PyTorch pre-instalado
- Mínimo 32GB RAM, 100GB storage

## 2. Setup remoto
ssh root@vast-instance
git clone tu-repo
pip install requirements.txt

## 3. Entrenamiento distribuido
python train_heavy_models.py \\
    --model transformer \\
    --dataset-size 10M \\
    --epochs 50 \\
    --batch-size 512

## 4. Modelos avanzados posibles:
- Transformer grande para análisis de patrones
- Graph Neural Networks para topología de red
- Ensemble de 10+ modelos
- AutoML para optimización automática

## 5. Transferir modelos
scp models/* local-machine:/models/

# Tiempo: 6-24 horas  
# Costo: $5-20 total
# Resultado: Modelos de producción de alta calidad
"""
        return pipeline

    def estimate_costs(self, training_hours, cloud_platform):
        """Estimar costos de entrenamiento"""

        costs = {
            "google_colab": 0,  # Gratis
            "kaggle_notebooks": 0,  # Gratis
            "paperspace_gradient": min(8, training_hours * 0),  # Free tier
            "aws_sagemaker": training_hours * 0.736,  # ml.g4dn.xlarge
            "vast_ai": training_hours * 0.25,  # Promedio RTX 3090
        }

        return costs.get(cloud_platform, 0)

    def show_full_comparison(self):
        """Mostrar comparación completa de opciones"""

        print(f"☁️  COMPARACIÓN COMPLETA DE OPCIONES ML")
        print("=" * 80)

        for name, info in self.cloud_options.items():
            print(f"\n🔸 {name.upper()}")
            print(f"   💰 Costo: {info['cost']}")
            print(f"   🖥️  GPU: {info['gpu']}")
            print(f"   💾 RAM: {info['ram']}")
            print(f"   📦 Storage: {info['storage']}")
            print(f"   ✅ Pros: {', '.join(info['pros'])}")
            print(f"   ❌ Cons: {', '.join(info['cons'])}")
            print(f"   🎯 Mejor para: {info['best_for']}")

        print(f"\n📊 COMPARACIÓN DE ESTRATEGIAS:")
        print("-" * 60)

        for name, info in self.model_strategies.items():
            print(f"\n🧠 {name.upper()}")
            print(f"   🤖 Modelos: {', '.join(info['models'])}")
            print(f"   💻 Hardware: {info['hardware']}")
            print(f"   ⏱️  Tiempo: {info['training_time']}")
            print(f"   📊 Dataset: {info['dataset_size']}")
            print(f"   🎯 Precisión: {info['accuracy']}")


def main():
    """Función principal interactiva"""
    strategy = CloudMLStrategy()

    print("🤖 PLANIFICADOR DE ESTRATEGIA ML")
    print("=" * 50)

    # Recopilar información del usuario
    try:
        print("📋 Cuéstame sobre tus necesidades:")

        dataset_size = int(
            input("📊 Tamaño aproximado del dataset (eventos): ") or "50000"
        )
        budget = float(input("💰 Presupuesto mensual USD (0 = gratis): ") or "0")
        accuracy = float(input("🎯 Precisión mínima deseada % (70-95): ") or "80")

        print("\n" + "=" * 50)

        # Generar recomendación
        strategy_name, cloud = strategy.recommend_strategy(
            dataset_size, budget, accuracy
        )

        # Mostrar pipeline
        print(f"\n📝 PIPELINE DE ENTRENAMIENTO:")
        print("=" * 50)
        pipeline = strategy.generate_training_pipeline(strategy_name, cloud)
        print(pipeline)

        # Estimar costos
        if cloud and budget > 0:
            estimated_hours = 6 if strategy_name == "medium_cloud" else 12
            cost = strategy.estimate_costs(estimated_hours, cloud)
            print(f"\n💰 ESTIMACIÓN DE COSTOS:")
            print(f"   ⏱️  Horas estimadas: {estimated_hours}")
            print(f"   💵 Costo total: ${cost:.2f}")
            print(f"   📅 Costo mensual (4 entrenamientos): ${cost * 4:.2f}")

        # Mostrar comparación completa si quieren
        show_all = input(f"\n¿Ver comparación completa de opciones? [y/n]: ").lower()
        if show_all == "y":
            strategy.show_full_comparison()

    except KeyboardInterrupt:
        print(f"\n👋 ¡Hasta luego!")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
