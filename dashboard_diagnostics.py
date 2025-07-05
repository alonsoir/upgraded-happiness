#!/usr/bin/env python3
"""
🔍 Diagnóstico específico del Dashboard SCADA
Identifica exactamente por qué el dashboard se cierra
"""

import sys
import os
import traceback
import subprocess


def capture_dashboard_error():
    """Capturar error específico del dashboard"""
    print("🔍 CAPTURANDO ERROR ESPECÍFICO DEL DASHBOARD")
    print("=" * 50)

    # Comando para ejecutar el dashboard con captura completa
    cmd = [sys.executable, "enhanced_protobuf_gis_dashboard.py"]

    try:
        print(f"🚀 Ejecutando: {' '.join(cmd)}")
        print("📄 Capturando stdout y stderr...")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10  # 10 segundos máximo
        )

        print(f"\n📊 RESULTADO:")
        print(f"   Return code: {result.returncode}")
        print(f"   Stdout length: {len(result.stdout)} chars")
        print(f"   Stderr length: {len(result.stderr)} chars")

        if result.stdout:
            print(f"\n📝 STDOUT:")
            print(result.stdout)

        if result.stderr:
            print(f"\n❌ STDERR:")
            print(result.stderr)

        if result.returncode != 0:
            print(f"\n💀 El proceso falló con código: {result.returncode}")
        else:
            print(f"\n✅ El proceso terminó normalmente")

        # Guardar logs para análisis
        with open("dashboard_debug.log", "w") as f:
            f.write(f"Return code: {result.returncode}\n")
            f.write(f"STDOUT:\n{result.stdout}\n")
            f.write(f"STDERR:\n{result.stderr}\n")

        print(f"\n💾 Logs guardados en: dashboard_debug.log")

    except subprocess.TimeoutExpired:
        print("⏰ El proceso se ejecutó por más de 10 segundos (probablemente OK)")
        print("💡 Esto sugiere que el dashboard está funcionando")
    except FileNotFoundError:
        print("❌ Archivo enhanced_protobuf_gis_dashboard.py no encontrado")
    except Exception as e:
        print(f"❌ Error ejecutando diagnóstico: {e}")
        traceback.print_exc()


def check_dashboard_file():
    """Verificar el archivo del dashboard"""
    print("\n🔍 VERIFICANDO ARCHIVO DEL DASHBOARD")
    print("=" * 40)

    filename = "enhanced_protobuf_gis_dashboard.py"

    if not os.path.exists(filename):
        print(f"❌ Archivo {filename} no existe")
        return False

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()

        print(f"✅ Archivo encontrado: {filename}")
        print(f"📏 Tamaño: {len(content)} caracteres")
        print(f"📄 Líneas: {len(content.splitlines())}")

        # Verificar sintaxis básica
        try:
            compile(content, filename, 'exec')
            print("✅ Sintaxis Python básica: OK")
        except SyntaxError as e:
            print(f"❌ Error de sintaxis Python: {e}")
            print(f"   Línea {e.lineno}: {e.text}")
            return False

        # Verificar imports críticos
        critical_imports = [
            'import asyncio',
            'from fastapi import',
            'import uvicorn',
            'import zmq'
        ]

        print("\n🔍 Verificando imports críticos:")
        for imp in critical_imports:
            if imp in content:
                print(f"✅ {imp}")
            else:
                print(f"⚠️ {imp} - No encontrado")

        return True

    except Exception as e:
        print(f"❌ Error leyendo archivo: {e}")
        return False


def test_manual_imports():
    """Probar imports manualmente"""
    print("\n🔍 PROBANDO IMPORTS MANUALMENTE")
    print("=" * 35)

    imports_to_test = [
        ("asyncio", "import asyncio"),
        ("json", "import json"),
        ("sys", "import sys"),
        ("os", "import os"),
        ("datetime", "from datetime import datetime"),
        ("typing", "from typing import Dict, List, Optional, Any"),
        ("fastapi", "from fastapi import FastAPI, WebSocket, WebSocketDisconnect"),
        ("fastapi.responses", "from fastapi.responses import HTMLResponse"),
        ("uvicorn", "import uvicorn"),
        ("zmq", "import zmq"),
        ("zmq.asyncio", "import zmq.asyncio"),
        ("signal", "import signal"),
        ("logging", "import logging")
    ]

    failed_imports = []

    for name, import_stmt in imports_to_test:
        try:
            exec(import_stmt)
            print(f"✅ {name}")
        except ImportError as e:
            print(f"❌ {name} - FALTA: {e}")
            failed_imports.append(name)
        except Exception as e:
            print(f"⚠️ {name} - ERROR: {e}")
            failed_imports.append(name)

    if failed_imports:
        print(f"\n❌ IMPORTS FALTANTES: {', '.join(failed_imports)}")
        print("💡 Instalar con: pip install fastapi uvicorn pyzmq")
        return False
    else:
        print("\n✅ TODOS LOS IMPORTS DISPONIBLES")
        return True


def test_port_availability():
    """Probar disponibilidad de puertos"""
    print("\n🔍 VERIFICANDO PUERTOS")
    print("=" * 25)

    import socket

    ports_to_test = [8000, 8001, 5560, 5559]

    for port in ports_to_test:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()

            if result == 0:
                print(f"⚠️ Puerto {port} - OCUPADO")
            else:
                print(f"✅ Puerto {port} - LIBRE")

        except Exception as e:
            print(f"❌ Puerto {port} - ERROR: {e}")


def suggest_fixes():
    """Sugerir correcciones"""
    print("\n🔧 SUGERENCIAS DE CORRECCIÓN")
    print("=" * 30)

    print("1. 📦 Instalar dependencias faltantes:")
    print("   pip install fastapi uvicorn pyzmq websockets")
    print("")
    print("2. 🔄 Usar dashboard ultra-básico:")
    print("   python3 ultra_basic_dashboard.py")
    print("")
    print("3. 🧪 Probar componentes individualmente:")
    print("   python3 simple_broker.py")
    print("   python3 ip_geolocator.py")
    print("")
    print("4. 📋 Ver logs detallados:")
    print("   cat dashboard_debug.log")
    print("")
    print("5. 🌐 Probar conectividad:")
    print("   curl http://localhost:8000/health")


def main():
    """Función principal de diagnóstico"""
    print("🔍 DIAGNÓSTICO ESPECÍFICO DEL DASHBOARD SCADA")
    print("=" * 50)

    try:
        # 1. Verificar archivo
        if not check_dashboard_file():
            print("\n❌ El archivo del dashboard tiene problemas")
            suggest_fixes()
            return

        # 2. Probar imports
        if not test_manual_imports():
            print("\n❌ Faltan dependencias críticas")
            suggest_fixes()
            return

        # 3. Verificar puertos
        test_port_availability()

        # 4. Capturar error específico
        capture_dashboard_error()

        # 5. Sugerencias
        suggest_fixes()

    except KeyboardInterrupt:
        print("\n🛑 Diagnóstico interrumpido")
    except Exception as e:
        print(f"\n❌ Error durante diagnóstico: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()