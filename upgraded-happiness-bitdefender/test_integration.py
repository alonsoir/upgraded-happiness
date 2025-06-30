#!/usr/bin/env python3
"""Test básico de la integración BitDefender"""

import asyncio
import json
import time
from pathlib import Path

async def test_basic_functionality():
    """Test básico de funcionalidad"""
    print("🧪 Ejecutando tests básicos...")

    # Test 1: Verificar imports
    try:
        import zmq
        import websockets
        import yaml
        import sklearn
        import pandas as pd
        import numpy as np
        print("✅ Todas las dependencias se importan correctamente")
    except ImportError as e:
        print(f"❌ Error importando dependencias: {e}")
        return False

    # Test 2: Verificar configuración
    config_path = Path("bitdefender_config.yaml")
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            print("✅ Archivo de configuración válido")
        except Exception as e:
            print(f"❌ Error en configuración: {e}")
            return False
    else:
        print("❌ Archivo de configuración no encontrado")
        return False

    # Test 3: Test básico de ZeroMQ
    try:
        context = zmq.Context()
        socket = context.socket(zmq.PUB)
        socket.bind("tcp://*:5556")  # Puerto de test
        socket.close()
        context.term()
        print("✅ ZeroMQ funciona correctamente")
    except Exception as e:
        print(f"❌ Error con ZeroMQ: {e}")
        return False

    # Test 4: Verificar estructura de directorios
    required_dirs = ["models", "logs", "data"]
    for dir_name in required_dirs:
        if Path(dir_name).exists():
            print(f"✅ Directorio {dir_name} existe")
        else:
            print(f"⚠️  Directorio {dir_name} no existe")

    print("🎉 Tests básicos completados")
    return True

if __name__ == "__main__":
    asyncio.run(test_basic_functionality())
