#!/usr/bin/env bash
# train_all_models.sh
# Para entrenar modelos RF para cada dataset .parquet en datasets_parquet/

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" &>/dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PARQUET_DIR="$PROJECT_ROOT/datasets_parquet"
OUTPUT_DIR="$PROJECT_ROOT/models/specialized"
TRAIN_SCRIPT="$PROJECT_ROOT/tools/train_model_from_dataset.py"

echo "=== Iniciando entrenamiento de modelos por dataset ==="
echo "Entrenador utilizado: $TRAIN_SCRIPT"
echo "Carpeta de entrada: $PARQUET_DIR"
echo "Salida de modelos: $OUTPUT_DIR"
echo

mkdir -p "$OUTPUT_DIR"

for parquet_file in "$PARQUET_DIR"/*.parquet; do
  dataset_name="$(basename "$parquet_file" .parquet)"
  echo "----------------------------------------"
  echo " Entrenando modelo para dataset: $dataset_name"
  echo "----------------------------------------"

  python3 "$TRAIN_SCRIPT" \
    --input_file "$parquet_file" \
    --output_dir "$OUTPUT_DIR" \
    --target_column label \
    --balance

  echo "Modelo entrenado y guardado para: $dataset_name"
  echo
done

echo "=== Entrenamiento completo para todos los datasets ==="
