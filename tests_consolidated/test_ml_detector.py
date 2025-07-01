import unittest
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
