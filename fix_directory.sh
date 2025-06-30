#!/bin/bash
# Quick fix para el directorio missing

echo "🔧 Arreglando directorio..."

# Asegurar que estamos en el directorio correcto
cd ~/g/upgraded-happiness

# Verificar si el directorio existe y crearlo si no
if [ ! -d "upgraded-happiness-bitdefender" ]; then
    echo "📁 Creando directorio upgraded-happiness-bitdefender..."
    mkdir -p upgraded-happiness-bitdefender
    cd upgraded-happiness-bitdefender

    # Crear entorno virtual si no existe
    if [ ! -d "venv" ]; then
        echo "🐍 Creando entorno virtual..."
        python3 -m venv venv
    fi

    # Crear directorios necesarios
    mkdir -p models logs data

    echo "✅ Directorio y estructura creados"
else
    cd upgraded-happiness-bitdefender
    echo "✅ Usando directorio existente"
fi

echo "📍 Directorio actual: $(pwd)"
echo "📁 Contenido:"
ls -la

# Crear configuración dinámica con los datos REALES detectados
echo "📝 Creando configuración..."

cat > bitdefender_config.yaml << 'EOCONF'
# Configuración DINÁMICA para BitDefender Integration en macOS
# Generada automáticamente con datos REALES detectados

zmq:
  broker_port: 5555
  dashboard_port: 5556

bitdefender:
  enabled: true
  # Rutas REALES de tu instalación BitDefender
  log_paths:
    - "/Applications/Bitdefender/AntivirusforMac.app/Contents/Resources/Logs/"
    - "/Applications/Bitdefender/CoreSecurity.app/Contents/Resources/Logs/"
    - "/Applications/Bitdefender/BitdefenderAgent.app/Contents/Resources/Logs/"
    - "/Applications/Bitdefender/Bitdefender VPN.app/Contents/Resources/Logs/"
    - "/Library/Application Support/Bitdefender/Logs/"
    - "/Library/Logs/Bitdefender/"

  # Archivos específicos de log a monitorear
  log_files:
    - "BDLDaemon.log"
    - "BDLDaemonApp.log"
    - "bdav.log"
    - "quarantine.log"
    - "real_time_protection.log"
    - "system_scan.log"
    - "antivirus.log"
    - "coresecurity.log"
    - "agent.log"

  # Procesos REALES detectados en tu sistema
  processes:
    - "AntivirusforMac"
    - "BDLDaemon"
    - "BDUpdDaemon"
    - "bdagentd"
    - "bdcredentialsd"
    - "BDCoreIssues"
    - "bdtllxpc"
    - "TLL"
    - "Bitdefender"

  # Configuración de monitoreo
  poll_interval: 30
  monitor_syslog: true
  use_fswatch: true

hybrid_ml:
  enabled: true
  model_path: "models/"
  database_path: "hybrid_ml.db"
  retrain_interval: 1800
  min_samples: 50

dashboard:
  enabled: true
  port: 8765
  host: "localhost"

system:
  use_existing_orchestrator: true
  orchestrator_path: "../system_orchestrator.py"

logging:
  level: "INFO"
  file: "bitdefender_integration.log"

# Configuración específica detectada en tu sistema
detection_info:
  installation_type: "dmg_install"
  detected_paths: 7
  detected_processes: 9  # BitDefender específicos
  zmq_port: 5555
  dashboard_port: 8765

development:
  simulate_bitdefender: false
  generate_test_events: true
  test_event_interval: 15
EOCONF

echo "✅ Configuración creada exitosamente"

# Verificar que se creó
if [ -f "bitdefender_config.yaml" ]; then
    echo "✅ Archivo bitdefender_config.yaml confirmado"
    echo "📊 Tamaño: $(ls -lh bitdefender_config.yaml | awk '{print $5}')"
else
    echo "❌ Error: No se pudo crear bitdefender_config.yaml"
    exit 1
fi

echo "🎉 Fix aplicado exitosamente"
echo "📍 Ahora estás en: $(pwd)"
echo "📋 Próximo paso: ./start_dashboard_only.sh"
