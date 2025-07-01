#!/usr/bin/env python3
"""
Corrección Final de Tests de Sintaxis
===================================
Arregla los últimos 2 tests que fallan
"""

from pathlib import Path


def fix_syntax_tests():
    """Corrige los tests de sintaxis que usan subprocess incorrectamente"""

    test_dir = Path("tests_consolidated")

    # 1. Corregir test_ml_detector.py - test de sintaxis
    ml_test_path = test_dir / "test_ml_detector.py"
    if ml_test_path.exists():
        print("🔧 Corrigiendo test de sintaxis ML...")

        ml_test_content = '''import unittest
import subprocess
import os
from pathlib import Path

class TestMLDetector(unittest.TestCase):
    """Tests para el detector ML"""

    def setUp(self):
        # RUTA CORREGIDA: buscar en directorio padre
        self.ml_path = Path("../lightweight_ml_detector.py")

    def test_ml_detector_exists(self):
        """Verifica que el detector ML existe"""
        self.assertTrue(self.ml_path.exists(), f"No se encuentra {self.ml_path}")

    def test_ml_syntax(self):
        """Verifica sintaxis del detector ML"""
        # CORRECCIÓN: usar ruta absoluta para subprocess
        abs_path = self.ml_path.resolve()
        result = subprocess.run(['python', '-m', 'py_compile', str(abs_path)], 
                              capture_output=True)
        self.assertEqual(result.returncode, 0, f"Syntax error: {result.stderr}")

    def test_ml_has_model_methods(self):
        """Verifica que tiene métodos de modelo"""
        with open(self.ml_path) as f:
            content = f.read()

        # Verificar métodos esenciales
        self.assertIn("def train", content.lower())
        self.assertIn("def predict", content.lower())

if __name__ == '__main__':
    unittest.main()
'''
        ml_test_path.write_text(ml_test_content)
        print("✅ test_ml_detector.py corregido (sintaxis)")

    # 2. Corregir test_system_orchestrator.py - test de sintaxis
    orchestrator_test_path = test_dir / "test_system_orchestrator.py"
    if orchestrator_test_path.exists():
        print("🔧 Corrigiendo test de sintaxis del orquestador...")

        orchestrator_test_content = '''import unittest
import subprocess
import time
import psutil
from pathlib import Path
import sys
import os

class TestSystemOrchestrator(unittest.TestCase):
    """Tests para el orquestador del sistema"""

    def setUp(self):
        # RUTA CORREGIDA: buscar en directorio padre
        self.orchestrator_path = Path("../system_orchestrator.py")

    def test_orchestrator_exists(self):
        """Verifica que el orquestador existe"""
        self.assertTrue(self.orchestrator_path.exists(), f"No se encuentra {self.orchestrator_path}")

    def test_orchestrator_syntax(self):
        """Verifica sintaxis del orquestador"""
        # CORRECCIÓN: usar ruta absoluta para subprocess
        abs_path = self.orchestrator_path.resolve()
        result = subprocess.run(['python', '-m', 'py_compile', str(abs_path)], 
                              capture_output=True)
        self.assertEqual(result.returncode, 0, f"Syntax error: {result.stderr}")

    def test_components_defined(self):
        """Verifica que los componentes estén definidos"""
        with open(self.orchestrator_path) as f:
            content = f.read()

        # Verificar que menciona componentes clave
        self.assertIn("broker", content.lower())
        self.assertIn("agent", content.lower()) 
        self.assertIn("ml", content.lower())

    def test_can_import_orchestrator(self):
        """Verifica que se puede importar el módulo"""
        try:
            # Agregar directorio padre al path
            parent_dir = os.path.abspath('..')
            if parent_dir not in sys.path:
                sys.path.insert(0, parent_dir)

            import system_orchestrator
            self.assertTrue(True, "Módulo importado exitosamente")
        except ImportError as e:
            self.fail(f"Cannot import orchestrator: {e}")

if __name__ == '__main__':
    unittest.main()
'''
        orchestrator_test_path.write_text(orchestrator_test_content)
        print("✅ test_system_orchestrator.py corregido (sintaxis)")

    print("\n🎉 ¡Corrección final completada!")
    print("\n📋 Cambios realizados:")
    print("   ✅ Tests de sintaxis usan rutas absolutas")
    print("   ✅ Eliminado cwd='..' problemático")
    print("   ✅ Usar .resolve() para rutas absolutas")

    return True


if __name__ == "__main__":
    print("🚀 Ejecutando corrección final de tests de sintaxis...")
    fix_syntax_tests()
    print("\n✅ ¡Listo! Ejecuta los tests de nuevo:")
    print("   cd tests_consolidated")
    print("   python run_all_tests.py")