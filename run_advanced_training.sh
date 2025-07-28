#!/bin/bash
# run_advanced_training_fixed.sh

# Detener al primer error
set -e

# Limpiar modelos anteriores
rm -rf models/*

# Ejecutar entrenamiento avanzado Cogerá 1000000 filas de cada dataset. OJITO!
python advanced_trainer.py --max_rows 1000000

# Probar con eventos sintéticos # DEPRECATED
# python test_synthetic_events.py

# Listar artefactos generados
ls -lta models