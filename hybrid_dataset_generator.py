#!/usr/bin/env python3
"""
Generador de Datasets Híbridos para Modelos Especializados
========================================================

Combina tráfico normal/interno capturado con ataques de UNSW-NB15
usando solo las columnas comunes para evitar incompatibilidades.

Genera:
1. normal_traffic_hybrid.csv (tráfico normal público + ataques)
2. internal_traffic_hybrid.csv (tráfico interno + ataques)
"""

import pandas as pd
import numpy as np
from pathlib import Path


def main():
    print("🚀 GENERADOR DE DATASETS HÍBRIDOS")
    print("=" * 50)

    # Definir columnas comunes entre todos los datasets
    common_columns = [
        'dur', 'proto', 'service', 'state', 'spkts', 'dpkts',
        'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 'sload',
        'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'label'
    ]

    print(f"📋 Columnas comunes a usar: {len(common_columns)}")
    print(f"   {', '.join(common_columns)}")
    print()

    # 1. EXTRAER ATAQUES DE UNSW-NB15
    print("🔍 Extrayendo ataques de UNSW-NB15...")
    try:
        unsw_data = pd.read_csv('data/UNSW-NB15.csv')
        print(f"   ✅ UNSW-NB15 cargado: {len(unsw_data):,} registros")

        # Filtrar DNS (como hace advanced_trainer)
        unsw_no_dns = unsw_data[unsw_data['service'] != 'dns']
        print(f"   🚫 Después de filtrar DNS: {len(unsw_no_dns):,} registros")

        # Extraer solo ataques (label=1) con columnas comunes
        ataques_unsw = unsw_no_dns[unsw_no_dns['label'] == 1][common_columns].copy()
        print(f"   ⚔️  Ataques extraídos: {len(ataques_unsw):,} registros")

        # Verificar que tenemos suficientes ataques
        if len(ataques_unsw) == 0:
            raise ValueError("No se encontraron ataques en UNSW-NB15")

    except FileNotFoundError:
        print("❌ ERROR: No se encontró data/UNSW-NB15.csv")
        return
    except Exception as e:
        print(f"❌ ERROR procesando UNSW-NB15: {e}")
        return

    print()

    # 2. PROCESAR NORMAL TRAFFIC
    print("🌐 Procesando normal traffic dataset...")
    try:
        normal_traffic = pd.read_csv('normal_traffic.csv')
        print(f"   📊 Normal traffic cargado: {len(normal_traffic):,} registros")

        # Usar solo columnas comunes y asegurar label=0
        normal_traffic_clean = normal_traffic[common_columns].copy()
        normal_traffic_clean['label'] = 0

        # Determinar cuántos ataques usar (balanceado)
        n_normal = len(normal_traffic_clean)
        n_ataques_needed = min(n_normal, len(ataques_unsw))

        # Muestra aleatoria de ataques
        ataques_sample = ataques_unsw.sample(n=n_ataques_needed, random_state=42)

        # Combinar
        normal_hybrid = pd.concat([
            normal_traffic_clean,
            ataques_sample
        ], ignore_index=True)

        # Mezclar aleatoriamente
        normal_hybrid = normal_hybrid.sample(frac=1, random_state=42).reset_index(drop=True)

        # Guardar
        normal_hybrid.to_csv('data/normal_traffic_hybrid.csv', index=False)

        print(f"   ✅ Dataset híbrido creado: {len(normal_hybrid):,} registros")
        print(f"      - Normal: {n_normal:,} ({n_normal / len(normal_hybrid) * 100:.1f}%)")
        print(f"      - Ataques: {n_ataques_needed:,} ({n_ataques_needed / len(normal_hybrid) * 100:.1f}%)")
        print(f"      - Guardado en: data/normal_traffic_hybrid.csv")

    except FileNotFoundError:
        print("❌ ERROR: No se encontró normal_traffic.csv")
    except Exception as e:
        print(f"❌ ERROR procesando normal traffic: {e}")

    print()

    # 3. PROCESAR INTERNAL TRAFFIC
    print("🏢 Procesando internal traffic dataset...")
    try:
        internal_traffic = pd.read_csv('internal_traffic_dataset.csv')
        print(f"   📊 Internal traffic cargado: {len(internal_traffic):,} registros")

        # Usar solo columnas comunes y asegurar label=0
        internal_traffic_clean = internal_traffic[common_columns].copy()
        internal_traffic_clean['label'] = 0

        # Determinar cuántos ataques usar (balanceado)
        n_internal = len(internal_traffic_clean)
        n_ataques_needed = min(n_internal, len(ataques_unsw))

        # Muestra aleatoria de ataques (diferente seed para variedad)
        ataques_sample = ataques_unsw.sample(n=n_ataques_needed, random_state=123)

        # Combinar
        internal_hybrid = pd.concat([
            internal_traffic_clean,
            ataques_sample
        ], ignore_index=True)

        # Mezclar aleatoriamente
        internal_hybrid = internal_hybrid.sample(frac=1, random_state=123).reset_index(drop=True)

        # Guardar
        internal_hybrid.to_csv('data/internal_traffic_hybrid.csv', index=False)

        print(f"   ✅ Dataset híbrido creado: {len(internal_hybrid):,} registros")
        print(f"      - Interno: {n_internal:,} ({n_internal / len(internal_hybrid) * 100:.1f}%)")
        print(f"      - Ataques: {n_ataques_needed:,} ({n_ataques_needed / len(internal_hybrid) * 100:.1f}%)")
        print(f"      - Guardado en: data/internal_traffic_hybrid.csv")

    except FileNotFoundError:
        print("❌ ERROR: No se encontró internal_traffic_dataset.csv")
    except Exception as e:
        print(f"❌ ERROR procesando internal traffic: {e}")

    print()

    # 4. GUARDAR ATAQUES PUROS PARA REFERENCIA
    print("💾 Guardando ataques extraídos para referencia...")
    ataques_unsw.to_csv('data/unsw_attacks_only.csv', index=False)
    print(f"   ✅ Ataques guardados en: data/unsw_attacks_only.csv")

    print()
    print("🎯 RESUMEN DE DATASETS GENERADOS:")
    print("=" * 50)

    # Verificar archivos generados
    datasets_created = []

    if Path('data/normal_traffic_hybrid.csv').exists():
        df = pd.read_csv('data/normal_traffic_hybrid.csv')
        normal_count = len(df[df['label'] == 0])
        attack_count = len(df[df['label'] == 1])
        datasets_created.append(
            f"📊 normal_traffic_hybrid.csv: {len(df):,} registros ({normal_count:,} normal, {attack_count:,} ataques)")

    if Path('data/internal_traffic_hybrid.csv').exists():
        df = pd.read_csv('data/internal_traffic_hybrid.csv')
        normal_count = len(df[df['label'] == 0])
        attack_count = len(df[df['label'] == 1])
        datasets_created.append(
            f"📊 internal_traffic_hybrid.csv: {len(df):,} registros ({normal_count:,} interno, {attack_count:,} ataques)")

    if Path('data/unsw_attacks_only.csv').exists():
        df = pd.read_csv('data/unsw_attacks_only.csv')
        datasets_created.append(f"⚔️  unsw_attacks_only.csv: {len(df):,} ataques puros")

    if datasets_created:
        for dataset in datasets_created:
            print(f"   {dataset}")
    else:
        print("   ❌ No se crearon datasets")

    print()
    print("✅ GENERACIÓN COMPLETADA")
    print()
    print("🚀 PRÓXIMOS PASOS:")
    print("   1. Entrenar modelo normal traffic: python advanced_trainer_no_dns.py --dataset normal_traffic_hybrid")
    print("   2. Entrenar modelo internal traffic: python advanced_trainer_no_dns.py --dataset internal_traffic_hybrid")
    print("   3. Comparar métricas con modelo UNSW-NB15 (baseline 92%)")


if __name__ == "__main__":
    # Crear directorio data si no existe
    Path('data').mkdir(exist_ok=True)
    main()