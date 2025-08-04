#!/usr/bin/env python3
"""
ENTRENADOR DE MODELOS ESPECIALIZADOS
Entrena detectores específicos de tráfico web e interno
"""

import subprocess
import os
import sys
import json
from pathlib import Path
from datetime import datetime


def run_analysis(dataset_path, name):
    """Ejecuta análisis de calidad en un dataset"""
    print(f"\n🔍 ANALIZANDO CALIDAD: {name}")
    print("-" * 50)

    cmd = f"python simple_data_analyzer.py --datasets {dataset_path}"

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
            return True
        else:
            print(f"⚠️ Advertencia en análisis: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error en análisis: {e}")
        return False


def clean_dataset(input_path, output_path, method='conservative'):
    """Limpia un dataset usando el limpiador"""
    print(f"\n🧹 LIMPIANDO DATASET: {input_path}")
    print("-" * 50)

    cmd = f"""python ultra_aggressive_cleaner.py \
        --input {input_path} \
        --output {output_path} \
        --method {method}"""

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
            return True
        else:
            print(f"❌ Error en limpieza: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Excepción en limpieza: {e}")
        return False


def train_model(dataset_path, model_path, name):
    """Entrena un modelo especializado"""
    print(f"\n🧠 ENTRENANDO MODELO: {name}")
    print("-" * 50)

    cmd = f"""python advanced_trainer_fixed.py \
        --input_csv {dataset_path} \
        --output_model {model_path} \
        --balance_threshold 0.15"""

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
            return True
        else:
            print(f"❌ Error en entrenamiento: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Excepción en entrenamiento: {e}")
        return False


def analyze_model_results(metadata_path):
    """Analiza los resultados del modelo entrenado"""
    try:
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)

        metrics = metadata.get('metrics', {})
        auc_roc = metrics.get('auc_roc', 'N/A')
        oob_score = metadata.get('oob_score', 'N/A')

        print(f"📊 Resultados del modelo:")
        print(f"   AUC-ROC: {auc_roc}")
        print(f"   OOB Score: {oob_score}")

        # Evaluar calidad
        if isinstance(auc_roc, float):
            if auc_roc > 0.95:
                status = "⚠️ POSIBLE OVERFITTING"
            elif auc_roc > 0.80:
                status = "✅ EXCELENTE"
            elif auc_roc > 0.70:
                status = "✅ BUENO"
            elif auc_roc > 0.60:
                status = "📊 ACEPTABLE"
            else:
                status = "❌ POBRE"

            print(f"   Estado: {status}")
            return auc_roc, status

        return None, "❓ NO EVALUABLE"

    except Exception as e:
        print(f"❌ Error analizando resultados: {e}")
        return None, "❌ ERROR"


def create_model_summary(results):
    """Crea un resumen de todos los modelos entrenados"""
    print(f"\n📋 RESUMEN DE MODELOS ESPECIALIZADOS")
    print("=" * 80)

    summary = {
        'timestamp': datetime.now().isoformat(),
        'models': results
    }

    print(f"{'Modelo':<25} {'AUC-ROC':<10} {'Estado':<20} {'Archivo':<30}")
    print("-" * 85)

    for model_name, info in results.items():
        auc = info.get('auc_roc', 'N/A')
        status = info.get('status', 'N/A')
        model_file = info.get('model_path', 'N/A')

        auc_str = f"{auc:.3f}" if isinstance(auc, float) else str(auc)
        model_file_short = str(model_file)[-30:] if len(str(model_file)) > 30 else str(model_file)

        print(f"{model_name:<25} {auc_str:<10} {status:<20} {model_file_short:<30}")

    # Guardar resumen
    summary_path = Path('models/specialized_models_summary.json')
    summary_path.parent.mkdir(exist_ok=True)

    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\n💾 Resumen guardado en: {summary_path}")

    return summary


def main():
    print(f"🚀 ENTRENADOR DE MODELOS ESPECIALIZADOS")
    print("=" * 80)
    print(f"🕐 Iniciado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Configuración de archivos
    datasets_config = {
        'web_detector': {
            'raw_dataset': 'data/specialized/web_normal_detector.csv',
            'clean_dataset': 'data/specialized/web_normal_detector_clean.csv',
            'model_path': 'models/web_normal_detector.joblib',
            'name': 'Detector Web Normal'
        },
        'internal_detector': {
            'raw_dataset': 'data/specialized/internal_normal_detector.csv',
            'clean_dataset': 'data/specialized/internal_normal_detector_clean.csv',
            'model_path': 'models/internal_normal_detector.joblib',
            'name': 'Detector Interno Normal'
        }
    }

    results = {}

    # Verificar que existen los datasets especializados
    print(f"🔍 VERIFICANDO DATASETS ESPECIALIZADOS...")
    missing_datasets = []

    for detector_type, config in datasets_config.items():
        if not os.path.exists(config['raw_dataset']):
            missing_datasets.append(config['raw_dataset'])

    if missing_datasets:
        print(f"❌ DATASETS FALTANTES:")
        for dataset in missing_datasets:
            print(f"   - {dataset}")
        print(f"\n💡 SOLUCIÓN: Ejecutar primero:")
        print(f"   python create_specialized_datasets.py")
        return 1

    print(f"✅ Todos los datasets especializados encontrados")

    # Crear directorios necesarios
    Path('models').mkdir(exist_ok=True)
    Path('data/specialized').mkdir(parents=True, exist_ok=True)

    # Procesar cada detector
    for detector_type, config in datasets_config.items():
        print(f"\n{'=' * 20} {config['name'].upper()} {'=' * 20}")

        detector_results = {
            'name': config['name'],
            'raw_dataset': config['raw_dataset'],
            'clean_dataset': config['clean_dataset'],
            'model_path': config['model_path']
        }

        # Paso 1: Análisis de calidad
        analysis_success = run_analysis(config['raw_dataset'], config['name'])
        detector_results['analysis_success'] = analysis_success

        # Paso 2: Limpieza (siempre intentar, incluso si análisis falla)
        clean_success = clean_dataset(
            config['raw_dataset'],
            config['clean_dataset'],
            method='conservative'  # Empezar conservador
        )
        detector_results['clean_success'] = clean_success

        # Si limpieza conservadora falla, intentar ultra-agresiva
        if not clean_success:
            print(f"🔄 Reintentando con limpieza ultra-agresiva...")
            clean_success = clean_dataset(
                config['raw_dataset'],
                config['clean_dataset'],
                method='ultra'
            )
            detector_results['clean_method'] = 'ultra'
            detector_results['clean_success'] = clean_success
        else:
            detector_results['clean_method'] = 'conservative'

        # Paso 3: Entrenamiento (solo si limpieza exitosa)
        if clean_success:
            train_success = train_model(
                config['clean_dataset'],
                config['model_path'],
                config['name']
            )
            detector_results['train_success'] = train_success

            # Paso 4: Análisis de resultados (solo si entrenamiento exitoso)
            if train_success:
                metadata_path = config['model_path'].replace('.joblib', '_metadata.json')
                auc_roc, status = analyze_model_results(metadata_path)
                detector_results['auc_roc'] = auc_roc
                detector_results['status'] = status
                detector_results['metadata_path'] = metadata_path
            else:
                detector_results['auc_roc'] = None
                detector_results['status'] = "❌ ENTRENAMIENTO FALLÓ"
        else:
            print(f"⚠️ Saltando entrenamiento - limpieza falló")
            detector_results['train_success'] = False
            detector_results['auc_roc'] = None
            detector_results['status'] = "❌ LIMPIEZA FALLÓ"

        results[detector_type] = detector_results

    # Crear resumen final
    create_model_summary(results)

    # Verificar éxito general
    successful_models = sum(1 for r in results.values() if r.get('train_success', False))
    total_models = len(results)

    print(f"\n🎯 RESULTADO FINAL")
    print("-" * 40)
    print(f"📊 Modelos exitosos: {successful_models}/{total_models}")

    if successful_models == total_models:
        print(f"🎉 ¡TODOS LOS MODELOS ESPECIALIZADOS CREADOS CON ÉXITO!")
        print(f"\n🚀 SISTEMA COMPLETO DE 3 CAPAS LISTO:")
        print(f"   1. ✅ Detector de Ataques: models/rf_production_final.joblib")
        print(f"   2. ✅ Detector Web Normal: models/web_normal_detector.joblib")
        print(f"   3. ✅ Detector Interno Normal: models/internal_normal_detector.joblib")

        return 0
    elif successful_models > 0:
        print(f"⚠️ ÉXITO PARCIAL - {successful_models} modelos funcionando")
        return 0
    else:
        print(f"❌ FALLO TOTAL - Ningún modelo se entrenó exitosamente")
        return 1


if __name__ == "__main__":
    exit(main())