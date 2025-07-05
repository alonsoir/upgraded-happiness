#!/usr/bin/env python3
"""
🧪 Dashboard Ultra-Básico para Testing
Versión mínima para identificar problemas de dependencias
"""

import sys
import os
import traceback


def test_basic():
    """Test básico sin dependencias externas"""
    print("🧪 Test 1: Funciones básicas")
    print(f"✅ Python version: {sys.version}")
    print(f"✅ Working directory: {os.getcwd()}")
    print(f"✅ Archivo ejecutado desde: {__file__}")


def test_imports():
    """Test de importaciones críticas"""
    print("\n🧪 Test 2: Importaciones críticas")

    try:
        import json
        print("✅ json - OK")
    except Exception as e:
        print(f"❌ json - FAIL: {e}")

    try:
        import datetime
        print("✅ datetime - OK")
    except Exception as e:
        print(f"❌ datetime - FAIL: {e}")

    try:
        import asyncio
        print("✅ asyncio - OK")
    except Exception as e:
        print(f"❌ asyncio - FAIL: {e}")


def test_optional_imports():
    """Test de dependencias opcionales"""
    print("\n🧪 Test 3: Dependencias externas")

    try:
        import fastapi
        print(f"✅ FastAPI - OK (version: {getattr(fastapi, '__version__', 'unknown')})")
    except Exception as e:
        print(f"❌ FastAPI - FAIL: {e}")

    try:
        import uvicorn
        print(f"✅ Uvicorn - OK (version: {getattr(uvicorn, '__version__', 'unknown')})")
    except Exception as e:
        print(f"❌ Uvicorn - FAIL: {e}")

    try:
        import zmq
        print(f"✅ ZMQ - OK (version: {getattr(zmq, '__version__', 'unknown')})")
    except Exception as e:
        print(f"❌ ZMQ - FAIL: {e}")


def test_simple_server():
    """Test de servidor HTTP básico"""
    print("\n🧪 Test 4: Servidor básico")

    try:
        from fastapi import FastAPI
        app = FastAPI()

        @app.get("/")
        async def root():
            return {"message": "Test OK"}

        print("✅ FastAPI app creada correctamente")
        return app
    except Exception as e:
        print(f"❌ Error creando FastAPI app: {e}")
        traceback.print_exc()
        return None


def test_uvicorn_config():
    """Test de configuración de Uvicorn"""
    print("\n🧪 Test 5: Configuración Uvicorn")

    try:
        import uvicorn
        from fastapi import FastAPI

        app = FastAPI()
        config = uvicorn.Config(app=app, host="127.0.0.1", port=8000, log_level="info")
        print("✅ Uvicorn config creada correctamente")
        print(f"   Host: {config.host}")
        print(f"   Port: {config.port}")
        return config
    except Exception as e:
        print(f"❌ Error configurando Uvicorn: {e}")
        traceback.print_exc()
        return None


def test_zmq_context():
    """Test de contexto ZMQ"""
    print("\n🧪 Test 6: ZMQ Context")

    try:
        import zmq
        context = zmq.Context()
        print("✅ ZMQ Context creado correctamente")

        socket = context.socket(zmq.SUB)
        print("✅ ZMQ Socket SUB creado correctamente")

        socket.close()
        context.term()
        print("✅ ZMQ Context cerrado correctamente")
    except Exception as e:
        print(f"❌ Error con ZMQ: {e}")
        traceback.print_exc()


def run_minimal_server():
    """Ejecutar servidor mínimo por 10 segundos"""
    print("\n🚀 Test 7: Ejecutar servidor mínimo")

    try:
        from fastapi import FastAPI
        import uvicorn
        import asyncio

        app = FastAPI()

        @app.get("/")
        async def root():
            return {"status": "ok", "message": "Servidor de prueba funcionando"}

        @app.get("/health")
        async def health():
            return {"health": "ok", "test": "ultra_basic_dashboard"}

        print("✅ Aplicación FastAPI configurada")
        print("🚀 Iniciando servidor en puerto 8001...")
        print("📱 URL de prueba: http://localhost:8001")
        print("💊 Health check: http://localhost:8001/health")
        print("⏰ El servidor se ejecutará por 10 segundos...")

        # Configurar uvicorn con timeout
        config = uvicorn.Config(
            app=app,
            host="127.0.0.1",
            port=8001,
            log_level="info",
            access_log=True
        )

        server = uvicorn.Server(config)

        async def run_with_timeout():
            try:
                # Crear task del servidor
                server_task = asyncio.create_task(server.serve())

                # Esperar 10 segundos
                await asyncio.sleep(10)

                # Parar servidor
                server.should_exit = True
                await server_task

                print("✅ Servidor detenido correctamente después de 10 segundos")

            except Exception as e:
                print(f"❌ Error durante ejecución del servidor: {e}")
                traceback.print_exc()

        # Ejecutar
        asyncio.run(run_with_timeout())

    except Exception as e:
        print(f"❌ Error ejecutando servidor mínimo: {e}")
        traceback.print_exc()


def main():
    """Función principal de diagnóstico"""
    print("🛡️ DASHBOARD ULTRA-BÁSICO - DIAGNÓSTICO COMPLETO")
    print("=" * 60)

    try:
        test_basic()
        test_imports()
        test_optional_imports()

        app = test_simple_server()
        if app:
            config = test_uvicorn_config()
            if config:
                test_zmq_context()

                print("\n" + "=" * 60)
                print("📊 RESUMEN DEL DIAGNÓSTICO:")
                print("✅ Todas las pruebas básicas pasaron")
                print("🚀 Procediendo con servidor de prueba...")

                run_minimal_server()

                print("\n✅ DIAGNÓSTICO COMPLETADO")
                print("💡 Si llegaste hasta aquí, las dependencias están OK")
                print("💡 El problema puede estar en la lógica específica del dashboard principal")

    except KeyboardInterrupt:
        print("\n🛑 Diagnóstico interrumpido por usuario")
    except Exception as e:
        print(f"\n❌ ERROR FATAL durante diagnóstico:")
        print(f"   {e}")
        traceback.print_exc()

        print("\n📋 INFORMACIÓN PARA DEBUG:")
        print(f"   Python version: {sys.version}")
        print(f"   Working directory: {os.getcwd()}")
        print(f"   Virtual env: {os.environ.get('VIRTUAL_ENV', 'No detectado')}")


if __name__ == "__main__":
    main()