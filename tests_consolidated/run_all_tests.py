#!/usr/bin/env python3
"""
Master Test Runner para Upgraded Happiness
==========================================
Ejecuta todos los tests y genera reporte
"""

import unittest
import sys
import time
import os
from pathlib import Path

def run_all_tests():
    """Ejecuta todos los tests y genera reporte"""

    print("🧪 INICIANDO SUITE DE TESTS - UPGRADED HAPPINESS")
    print("="*50)

    # Cambiar al directorio de tests
    os.chdir(Path(__file__).parent)
    print(f"📁 Directorio de trabajo: {os.getcwd()}")

    # Verificar archivos objetivo antes de los tests
    print("\n🔍 Verificando archivos objetivo...")
    target_files = [
        "../system_orchestrator.py",
        "../lightweight_ml_detector.py", 
        "../promiscuous_agent.py"
    ]

    for file_path in target_files:
        if Path(file_path).exists():
            print(f"   ✅ {file_path}")
        else:
            print(f"   ❌ {file_path}")

    print("\n" + "="*30)

    # Descubrir todos los tests
    loader = unittest.TestLoader()
    suite = loader.discover('.', pattern='test_*.py')

    # Ejecutar tests con reporte detallado
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "="*50)
    print("📊 RESUMEN DE TESTS:")
    print(f"   Tests ejecutados: {result.testsRun}")
    print(f"   Fallos: {len(result.failures)}")
    print(f"   Errores: {len(result.errors)}")

    if result.failures:
        print("\n❌ FALLOS:")
        for test, traceback in result.failures:
            # Mostrar solo la línea más relevante del error
            error_lines = traceback.splitlines()
            relevant_line = error_lines[-1] if error_lines else "Error desconocido"
            print(f"   - {test}: {relevant_line}")

    if result.errors:
        print("\n💥 ERRORES:")
        for test, traceback in result.errors:
            error_lines = traceback.splitlines()
            relevant_line = error_lines[-1] if error_lines else "Error desconocido"
            print(f"   - {test}: {relevant_line}")

    # Determinar estado general
    if result.wasSuccessful():
        print("\n🎉 ¡TODOS LOS TESTS PASARON!")
        return True
    else:
        print("\n⚠️  ALGUNOS TESTS FALLARON")

        # Sugerencias de corrección
        if result.failures or result.errors:
            print("\n💡 SUGERENCIAS:")
            print("   - Verificar que todos los archivos están en el directorio padre")
            print("   - Ejecutar desde el directorio raíz del proyecto")
            print("   - Revisar permisos de archivos")

        return False

if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
