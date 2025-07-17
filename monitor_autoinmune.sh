#!/bin/bash

# Monitor Sistema Autoinmune Digital v2.0
# Monitoring en tiempo real del pipeline completo

while true; do
  clear
  echo "=== SISTEMA AUTOINMUNE DIGITAL v2.0 ==="
  echo "$(date)"
  echo ""

  # CPU del ML Detector
  ML_CPU=$(ps aux | grep ml_detector | grep -v grep | awk '{print $3}')
  if [ -n "$ML_CPU" ]; then
    echo "🔥 CPU ML Detector: ${ML_CPU}%"
  else
    echo "🔥 CPU ML Detector: OFFLINE"
  fi

  # CPU del Dashboard
  DASHBOARD_CPU=$(ps aux | grep "real_zmq_dashboard_with_firewall.py" | grep -v grep | awk '{print $3}')
  if [ -n "$DASHBOARD_CPU" ]; then
    echo "📊 CPU Dashboard: ${DASHBOARD_CPU}%"
  else
    echo "📊 CPU Dashboard: OFFLINE"
  fi

  # CPU del Firewall
  FIREWALL_CPU=$(ps aux | grep "simple_firewall_agent.py" | grep -v grep | awk '{print $3}')
  if [ -n "$FIREWALL_CPU" ]; then
    echo "🛡️ CPU Firewall: ${FIREWALL_CPU}%"
  else
    echo "🛡️ CPU Firewall: OFFLINE"
  fi

  # Buscar métricas en cualquier log reciente
  THROUGHPUT=$(find logs/ -name "*.log" -exec tail -5 {} \; 2>/dev/null | grep -o "([0-9]\+\.[0-9]/s)" | sed 's/[()]//g' | tail -1)
  if [ -n "$THROUGHPUT" ]; then
    echo "📈 Último throughput: ${THROUGHPUT}"
  else
    echo "📈 Último throughput: N/A (revisar logs)"
  fi

  # Latencia desde cualquier log
  LATENCY=$(find logs/ -name "*.log" -exec tail -5 {} \; 2>/dev/null | grep -o "[0-9]\+\.[0-9]ms" | tail -1)
  if [ -n "$LATENCY" ]; then
    echo "⏱️ Última latencia: ${LATENCY}"
  else
    echo "⏱️ Última latencia: N/A (revisar logs)"
  fi

  # Estado de todos los componentes
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
    echo "├── 🦠 ML Detector: ACTIVO (${ML_CPU}% CPU)"
  else
    echo "├── 🦠 ML Detector: OFFLINE"
  fi

  # Dashboard
  if [ -n "$DASHBOARD_CPU" ]; then
    echo "├── 📊 Dashboard: ACTIVO (${DASHBOARD_CPU}% CPU)"
  else
    echo "├── 📊 Dashboard: OFFLINE"
  fi

  # Firewall
  if [ -n "$FIREWALL_CPU" ]; then
    echo "└── 🛡️ Firewall Agent: ACTIVO (${FIREWALL_CPU}% CPU)"
  else
    echo "└── 🛡️ Firewall Agent: OFFLINE"
  fi

  # Análisis de salud del sistema
  echo ""
  echo "🩺 ANÁLISIS DE SALUD:"

  # Verificar errores de encoding en logs recientes
  ENCODING_ERRORS=$(find logs/ -name "*.log" -exec tail -20 {} \; 2>/dev/null | grep -c "utf-8.*codec.*decode" || echo "0")
  if [ "$ENCODING_ERRORS" -gt "0" ]; then
    echo "⚠️ Errores de encoding: ${ENCODING_ERRORS} detectados (revisar logs)"
  else
    echo "✅ Encoding: Sin errores detectados"
  fi

  # Verificar crashes/aborts
  CRASH_CHECK=$(ps aux | grep -E "(real_zmq_dashboard|simple_firewall)" | grep -v grep | wc -l)
  if [ "$CRASH_CHECK" -lt "2" ]; then
    echo "❌ Sistema: Componentes críticos offline"
  else
    echo "✅ Sistema: Componentes críticos activos"
  fi

  # Análisis de latencia
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

  # Análisis de temperatura general
  TOTAL_CPU=$(ps aux | grep -E "(ml_detector|dashboard|firewall|promiscuous|geoip)" | grep -v grep | awk '{sum += $3} END {print sum}' || echo "0")
  if (( $(echo "$TOTAL_CPU < 100" | bc -l) )); then
    echo "🌡️ Temperatura: NORMAL (<100% total)"
  elif (( $(echo "$TOTAL_CPU < 200" | bc -l) )); then
    echo "🌡️ Temperatura: CALIENTE (100-200% total)"
  else
    echo "🌡️ Temperatura: CRÍTICA (>200% total)"
  fi

  # Puertos ZeroMQ activos
  echo ""
  echo "🔌 PUERTOS ZEROMQ:"
  ZMQPORTS=$(netstat -tulpn 2>/dev/null | grep ":55[0-9][0-9]" | wc -l || echo "0")
  if [ "$ZMQPORTS" -gt "0" ]; then
    echo "└── Puertos ZMQ activos: ${ZMQPORTS}"
  else
    echo "└── ⚠️ Sin puertos ZMQ detectados"
  fi

  # Eventos y actividad reciente
  echo ""
  echo "📡 ACTIVIDAD RECIENTE:"

  # Eventos ML procesados
  RECENT_EVENTS=$(find logs/ -name "*.log" -exec tail -3 {} \; 2>/dev/null | grep "📨 Recibidos" | tail -1 | grep -o "📨 Recibidos: [0-9]\+" | grep -o "[0-9]\+")
  if [ -n "$RECENT_EVENTS" ]; then
    echo "├── Eventos ML procesados: ${RECENT_EVENTS}"
  else
    echo "├── Eventos ML: Sin actividad"
  fi

  # Dashboard updates
  DASHBOARD_UPDATES=$(find logs/ -name "*.log" -exec tail -5 {} \; 2>/dev/null | grep -c "dashboard.*iniciado" || echo "0")
  if [ "$DASHBOARD_UPDATES" -gt "0" ]; then
    echo "├── Dashboard: Activo y procesando"
  else
    echo "├── Dashboard: Sin updates recientes"
  fi

  # Comandos firewall
  FIREWALL_CMDS=$(find logs/ -name "*.log" -exec tail -5 {} \; 2>/dev/null | grep -c "Firewall.*Command" || echo "0")
  if [ "$FIREWALL_CMDS" -gt "0" ]; then
    echo "└── Firewall: ${FIREWALL_CMDS} comandos procesados"
  else
    echo "└── Firewall: Sin comandos recientes"
  fi

  # Alertas críticas
  echo ""
  echo "🚨 ALERTAS:"
  if [ "$ENCODING_ERRORS" -gt "5" ]; then
    echo "⚠️ CRÍTICO: Muchos errores de encoding detectados"
  fi

  if [ "$CRASH_CHECK" -lt "2" ]; then
    echo "⚠️ CRÍTICO: Dashboard o Firewall offline"
  fi

  if [ "$ZMQPORTS" -eq "0" ]; then
    echo "⚠️ ADVERTENCIA: Sin puertos ZeroMQ activos"
  fi

  echo ""
  echo "🛑 Presiona Ctrl+C para detener el monitoreo"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  sleep 10
done