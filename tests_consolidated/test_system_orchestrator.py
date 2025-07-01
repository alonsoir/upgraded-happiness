import unittest
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
