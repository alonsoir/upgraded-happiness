#!/usr/bin/env bash
# Descargar archivos PCAPs .gz de MAWI Samplepoint‑F para 2025 y almacenarlos en datasets/mawi/raw
# 🎯 ¿Cómo encaja MAWI en tu arquitectura?
# Tú tienes ya una malla de modelos:
# rf_attack_classifier.joblib: ataque/no ataque (CICIDS2017).
# rf_normal_behavior.joblib: desviaciones del tráfico externo.
# rf_internal_behavior.joblib: anomalías en la red interna.
# El dataset MAWI es útil para alimentar o refinar los dos últimos. Por ejemplo:
# Aprender el comportamiento típico de miles de flujos internacionales.
# Distinguir si un pico de tráfico es natural (como un gran mirror de Debian) o un patrón anómalo.
# Generar features estadísticas para entrenar modelos no supervisados.
# Usar MAWI no es para detectar DDoS directamente, sino para:
# Entender comportamientos legítimos y sus desviaciones.
# Entrenar o validar detectores de anomalías.
# Complementar otros datasets con tráfico real del backbone.

set -euo pipefail
IFS=$'\n\t'

BASE_URL="https://mawi.wide.ad.jp/mawi/samplepoint-F"
TARGET_DIR="datasets/mawi/raw"

months=("01" "02" "03" "04" "05" "06" "07" "08" "09" "10" "11" "12")
year="2025"

mkdir -p "$TARGET_DIR"

echo "=== Descargando archivos MAWI para $year ==="

for m in "${months[@]}"; do
  filename="${year}${m}.pcap.gz"
  url="${BASE_URL}/${year}/${filename}"
  dest="${TARGET_DIR}/${filename}"

  echo -n "Comprobando: $filename ... "

  # Validar existencia con HEAD
  if curl -sI "$url" | grep -q "200 OK"; then
    echo "Disponible. Iniciando descarga..."
    curl -# "$url" -o "$dest"
    echo "  → Guardado en: $dest"
  else
    echo "No está disponible."
  fi
done

echo "=== Proceso completado ==="
