#!/usr/bin/env python3
"""
UNSW-NB15 Dataset Feature Audit
Valida si las features calculadas tienen valores realistas
"""

import pandas as pd
import numpy as np


def audit_unsw_features(csv_path):
    """Audita features calculadas del dataset UNSW-NB15"""

    print("🔍 AUDIT COMPLETO DEL DATASET UNSW-NB15")
    print("=" * 50)

    # Cargar muestra del dataset
    df = pd.read_csv(csv_path, nrows=10000)
    print(f"📊 Analizando {len(df)} muestras...")

    # 1. AUDIT DE SLOAD/DLOAD (ya confirmado corrupto)
    print("\n🚨 1. SLOAD/DLOAD AUDIT:")
    print(f"   sload stats: min={df['sload'].min():.0f}, max={df['sload'].max():.0f}, mean={df['sload'].mean():.0f}")
    print(f"   dload stats: min={df['dload'].min():.0f}, max={df['dload'].max():.0f}, mean={df['dload'].mean():.0f}")

    # Calculemos sload correctamente
    df['sload_corrected'] = df['sbytes'] / df['dur']
    df['sload_corrected'] = df['sload_corrected'].replace([np.inf, -np.inf], 0)

    print(
        f"   sload CORRECTED: min={df['sload_corrected'].min():.0f}, max={df['sload_corrected'].max():.0f}, mean={df['sload_corrected'].mean():.0f}")

    # 2. AUDIT DE RATE
    print("\n🔍 2. RATE AUDIT:")
    print(f"   rate stats: min={df['rate'].min():.2f}, max={df['rate'].max():.2f}, mean={df['rate'].mean():.2f}")

    # Rate debería ser total_packets/duration
    df['rate_corrected'] = (df['spkts'] + df['dpkts']) / df['dur']
    df['rate_corrected'] = df['rate_corrected'].replace([np.inf, -np.inf], 0)

    print(
        f"   rate EXPECTED: min={df['rate_corrected'].min():.2f}, max={df['rate_corrected'].max():.2f}, mean={df['rate_corrected'].mean():.2f}")

    # 3. AUDIT DE SMEAN/DMEAN
    print("\n🔍 3. SMEAN/DMEAN AUDIT:")
    print(f"   smean stats: min={df['smean'].min():.2f}, max={df['smean'].max():.2f}, mean={df['smean'].mean():.2f}")
    print(f"   dmean stats: min={df['dmean'].min():.2f}, max={df['dmean'].max():.2f}, mean={df['dmean'].mean():.2f}")

    # Smean/dmean deberían ser mean packet size o inter-arrival time
    df['smean_corrected'] = df['sbytes'] / df['spkts']  # Mean packet size
    df['dmean_corrected'] = df['dbytes'] / df['dpkts']
    df['smean_corrected'] = df['smean_corrected'].replace([np.inf, -np.inf], 0)
    df['dmean_corrected'] = df['dmean_corrected'].replace([np.inf, -np.inf], 0)

    print(
        f"   smean AS PKT SIZE: min={df['smean_corrected'].min():.2f}, max={df['smean_corrected'].max():.2f}, mean={df['smean_corrected'].mean():.2f}")
    print(
        f"   dmean AS PKT SIZE: min={df['dmean_corrected'].min():.2f}, max={df['dmean_corrected'].max():.2f}, mean={df['dmean_corrected'].mean():.2f}")

    # 4. AUDIT DE DURATIONS
    print("\n🔍 4. DURATION AUDIT:")
    print(f"   dur stats: min={df['dur'].min():.6f}s, max={df['dur'].max():.6f}s, mean={df['dur'].mean():.6f}s")

    # Contar duraciones sospechosamente cortas
    very_short = (df['dur'] < 0.001).sum()
    extremely_short = (df['dur'] < 0.00001).sum()

    print(f"   🚨 Duraciones < 1ms: {very_short} ({very_short / len(df) * 100:.1f}%)")
    print(f"   🚨 Duraciones < 10μs: {extremely_short} ({extremely_short / len(df) * 100:.1f}%)")

    # 5. AUDIT DE CONTEXT FEATURES (CT_*)
    print("\n🔍 5. CONTEXT FEATURES AUDIT:")
    context_features = [col for col in df.columns if col.startswith('ct_')]

    for feature in context_features[:5]:  # Solo primeros 5
        stats = df[feature].describe()
        print(f"   {feature}: min={stats['min']:.2f}, max={stats['max']:.2f}, mean={stats['mean']:.2f}")

    # 6. CONSISTENCIA CHECKS
    print("\n🔍 6. CONSISTENCY CHECKS:")

    # Check: bytes vs packets consistency
    impossible_pkt_size = ((df['sbytes'] / df['spkts']) > 65535).sum()
    print(f"   🚨 Packets con size > 65KB: {impossible_pkt_size}")

    # Check: rate vs actual rate
    rate_mismatch = (abs(df['rate'] - df['rate_corrected']) > 100).sum()
    print(f"   🚨 Rate mismatches (>100 diff): {rate_mismatch}")

    # Check: sload vs corrected sload
    sload_mismatch = (abs(df['sload'] - df['sload_corrected']) > 1000000).sum()
    print(f"   🚨 Sload mismatches (>1M diff): {sload_mismatch}")

    # 7. LABELS DISTRIBUTION
    print("\n🔍 7. LABELS DISTRIBUTION:")
    label_dist = df['label'].value_counts()
    print(f"   Normal (0): {label_dist.get(0, 0)} ({label_dist.get(0, 0) / len(df) * 100:.1f}%)")
    print(f"   Attack (1): {label_dist.get(1, 0)} ({label_dist.get(1, 0) / len(df) * 100:.1f}%)")

    # 8. RECOMMENDATIONS
    print("\n💡 RECOMENDACIONES:")

    corrupted_features = []
    if sload_mismatch > len(df) * 0.5:
        corrupted_features.append("sload/dload")
    if rate_mismatch > len(df) * 0.5:
        corrupted_features.append("rate")
    if very_short > len(df) * 0.8:
        corrupted_features.append("dur (duraciones sospechosas)")

    if corrupted_features:
        print(f"   🚨 FEATURES CORRUPTAS: {', '.join(corrupted_features)}")
        print(f"   ✅ RECOMENDACIÓN: Re-calcular features desde raw data")
        print(f"   ✅ O usar otro dataset (CICIDS-2017, NSL-KDD)")
    else:
        print(f"   ✅ Dataset parece consistente")

    return {
        'corrupted_features': corrupted_features,
        'sload_issues': sload_mismatch,
        'rate_issues': rate_mismatch,
        'duration_issues': very_short
    }


if __name__ == "__main__":
    # Ejecutar audit
    results = audit_unsw_features("data/UNSW-NB15.csv")

    print(f"\n🎯 AUDIT COMPLETADO")
    print(f"   Features problemáticas detectadas: {len(results['corrupted_features'])}")