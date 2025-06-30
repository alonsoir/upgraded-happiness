
#!/usr/bin/env python3
"""
Master Test Runner para Upgraded Happiness
==========================================
Ejecuta todos los tests y genera reporte
"""

import unittest
import sys
import time
from pathlib import Path

def run_all_tests():
    """Ejecuta todos los tests y genera reporte"""
    
    print("🧪 INICIANDO SUITE DE TESTS - UPGRADED HAPPINESS")
    print("="*50)
    
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
            print(f"   - {test}: {traceback.splitlines()[-1]}")
    
    if result.errors:
        print("\n💥 ERRORES:")
        for test, traceback in result.errors:
            print(f"   - {test}: {traceback.splitlines()[-1]}")
    
    # Determinar estado general
    if result.wasSuccessful():
        print("\n🎉 ¡TODOS LOS TESTS PASARON!")
        return True
    else:
        print("\n⚠️  ALGUNOS TESTS FALLARON")
        return False

if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
