#!/bin/bash
# upgraded_happiness/scripts/run_broker.sh

# Activa el entorno virtual desde la ubicación correcta
source ./upgraded_happiness_venv/bin/activate 2>/dev/null || echo "Error: Entorno virtual no encontrado en ./upgraded_happiness_venv/, actívalo manualmente con 'source upgraded_happiness_venv/bin/activate'"

# Confirma la activación
if [ -z "$VIRTUAL_ENV" ]; then
    echo "Error: No se pudo activar el entorno virtual"
    exit 1
fi
echo "Entorno virtual activado: $VIRTUAL_ENV"

# Inicia el broker con salida informativa
echo "Iniciando broker ZeroMQ en puertos 5555 (frontend) y 5556 (backend)..."
python3 -c 'import zmq; print("Broker ZeroMQ iniciado correctamente"); context = zmq.Context(); frontend = context.socket(zmq.XSUB); frontend.bind("tcp://*:5555"); backend = context.socket(zmq.XPUB); backend.bind("tcp://*:5556"); zmq.device(zmq.FORWARDER, frontend, backend)' || echo "Error: Fallo al iniciar el broker"
echo "Broker terminado (esto no debería aparecer a menos que haya un error)"