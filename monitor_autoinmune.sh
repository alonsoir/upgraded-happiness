#!/bin/bash

# Monitor Sistema Autoinmune Digital v1.0
# Monitoring en tiempo real del pipeline

while true; do
  clear
  echo "=== SISTEMA AUTOINMUNE DIGITAL ==="
  echo "$(date)"
  echo ""

  # CPU del ML Detector
  ML_CPU=$(ps aux | grep ml_detector | grep -v grep | awk '{print $3}')
  if [ -n "$ML_CPU" ]; then
    echo "🔥 CPU ML Detector: ${ML_CPU}%"
  else
    echo "🔥 CPU ML Detector: OFFLINE"
  fi

  # Buscar métricas en cualquier log reciente
  THROUGHPUT=$(find logs/ -name "*.log" -exec tail -5 {} \; 2>/dev/null | grep -o "([0-9]\+\.[0-9]/s)" | sed 's/[()]//g' | tail -1)
  if [ -n "$THROUGHPUT" ]; then
    echo "📊 Último throughput: ${THROUGHPUT}"
  else
    echo "📊 Último throughput: N/A (revisar logs)"
  fi

  # Latencia desde cualquier log
  LATENCY=$(find logs/ -name "*.log" -exec tail -5 {} \; 2>/dev/null | grep -o "[0-9]\+\.[0-9]ms" | tail -1)
  if [ -n "$LATENCY" ]; then
    echo "⏱️ Última latencia: ${LATENCY}"
  else
    echo "⏱️ Última latencia: N/A (revisar logs)"
  fi

  # Estado de otros componentes
  echo ""
  echo "🧬 ESTADO DE COMPONENTES:"

  # Promiscuous Agent
  PROM_CPU=$(ps aux | grep promiscuous_agent | grep -v grep | awk '{print $3}' | head -1)
  if [ -n "$PROM_CPU" ]; then
    echo "├── 🫀 Promiscuous Agent: ACTIVO (${PROM_CPU}% CPU)"
  else
    echo "├── 🫀 Promiscuous Agent: OFFLINE"
  fi

  # GeoIP Enricher
  GEO_CPU=$(ps aux | grep geoip_enricher | grep -v grep | awk '{print $3}' | head -1)
  if [ -n "$GEO_CPU" ]; then
    echo "├── 🧠 GeoIP Enricher: ACTIVO (${GEO_CPU}% CPU)"
  else
    echo "├── 🧠 GeoIP Enricher: OFFLINE"
  fi

  # ML Detector
  if [ -n "$ML_CPU" ]; then
    echo "└── 🦠 ML Detector: ACTIVO (${ML_CPU}% CPU)"
  else
    echo "└── 🦠 ML Detector: OFFLINE"
  fi

  # Análisis de salud
  echo ""
  echo "🩺 ANÁLISIS DE SALUD:"

  if [ -n "$LATENCY" ]; then
    LATENCY_NUM=$(echo $LATENCY | grep -o "[0-9]\+\.[0-9]")
    if (( $(echo "$LATENCY_NUM < 20" | bc -l) )); then
      echo "⚡ Latencia: EXCELENTE (<20ms)"
    elif (( $(echo "$LATENCY_NUM < 50" | bc -l) )); then
      echo "⚡ Latencia: BUENA (<50ms)"
    else
      echo "⚡ Latencia: ATENCIÓN (>50ms)"
    fi
  fi

  if [ -n "$ML_CPU" ]; then
    if (( $(echo "$ML_CPU < 70" | bc -l) )); then
      echo "🌡️ Temperatura: NORMAL (<70% CPU)"
    else
      echo "🌡️ Temperatura: CALIENTE (>70% CPU)"
    fi
  fi

  # Eventos recientes
  echo ""
  echo "📡 ACTIVIDAD RECIENTE:"
  RECENT_EVENTS=$(find logs/ -name "*.log" -exec tail -3 {} \; 2>/dev/null | grep "📨 Recibidos" | tail -1 | grep -o "📨 Recibidos: [0-9]\+" | grep -o "[0-9]\+")
  if [ -n "$RECENT_EVENTS" ]; then
    echo "└── Últimos eventos procesados: ${RECENT_EVENTS}"
  else
    echo "└── Sin actividad reciente (verificar logs)"
  fi

  echo ""
  echo "🛑 Presiona Ctrl+C para detener el monitoreo"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  sleep 5
done