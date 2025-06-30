#!/usr/bin/env python3
"""
Creador de Suite de Tests para Upgraded Happiness
================================================
Crea tests para cada componente esencial identificado
"""

import os
from pathlib import Path

def create_test_suite():
    """Crea estructura completa de tests"""
    
    # Crear directorio de tests
    test_dir = Path("tests_consolidated")
    test_dir.mkdir(exist_ok=True)
    
    # Test para sistema principal
    (test_dir / "test_system_orchestrator.py").write_text('''
import unittest
import subprocess
import time
import psutil
from pathlib import Path

class TestSystemOrchestrator(unittest.TestCase):
    """Tests para el orquestador del sistema"""
    
    def setUp(self):
        self.orchestrator_path = Path("system_orchestrator.py")
        
    def test_orchestrator_exists(self):
        """Verifica que el orquestador existe"""
        self.assertTrue(self.orchestrator_path.exists())
        
    def test_orchestrator_syntax(self):
        """Verifica sintaxis del orquestador"""
        result = subprocess.run(['python', '-m', 'py_compile', str(self.orchestrator_path)], 
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
            import sys
            sys.path.insert(0, '.')
            import system_orchestrator
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Cannot import orchestrator: {e}")

if __name__ == '__main__':
    unittest.main()
''')
    
    # Test para ML detector
    (test_dir / "test_ml_detector.py").write_text('''
import unittest
import subprocess
from pathlib import Path

class TestMLDetector(unittest.TestCase):
    """Tests para el detector ML"""
    
    def setUp(self):
        self.ml_path = Path("lightweight_ml_detector.py")
        
    def test_ml_detector_exists(self):
        """Verifica que el detector ML existe"""
        self.assertTrue(self.ml_path.exists())
        
    def test_ml_syntax(self):
        """Verifica sintaxis del detector ML"""
        result = subprocess.run(['python', '-m', 'py_compile', str(self.ml_path)], 
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
''')
    
    # Test para integración BitDefender
    (test_dir / "test_bitdefender_integration.py").write_text('''
import unittest
import subprocess
import json
from pathlib import Path

class TestBitDefenderIntegration(unittest.TestCase):
    """Tests para la integración BitDefender"""
    
    def setUp(self):
        self.bd_dir = Path("upgraded-happiness-bitdefender")
        
    def test_integration_directory_exists(self):
        """Verifica que el directorio de integración existe"""
        self.assertTrue(self.bd_dir.exists())
        
    def test_config_file_exists(self):
        """Verifica archivo de configuración"""
        config_file = self.bd_dir / "bitdefender_config.yaml"
        self.assertTrue(config_file.exists())
        
    def test_bitdefender_processes_detected(self):
        """Verifica que se detectan procesos BitDefender"""
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        bd_count = len([line for line in result.stdout.splitlines() 
                       if 'bitdefender' in line.lower()])
        self.assertGreater(bd_count, 0, "No BitDefender processes detected")
        
    def test_dashboard_components(self):
        """Verifica componentes del dashboard"""
        dashboard_file = self.bd_dir / "dashboard_server.py"
        if dashboard_file.exists():
            with open(dashboard_file) as f:
                content = f.read()
            self.assertIn("websocket", content.lower())
            self.assertIn("html", content.lower())

if __name__ == '__main__':
    unittest.main()
''')
    
    # Master test runner
    (test_dir / "run_all_tests.py").write_text('''
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
    
    print("\\n" + "="*50)
    print("📊 RESUMEN DE TESTS:")
    print(f"   Tests ejecutados: {result.testsRun}")
    print(f"   Fallos: {len(result.failures)}")
    print(f"   Errores: {len(result.errors)}")
    
    if result.failures:
        print("\\n❌ FALLOS:")
        for test, traceback in result.failures:
            print(f"   - {test}: {traceback.splitlines()[-1]}")
    
    if result.errors:
        print("\\n💥 ERRORES:")
        for test, traceback in result.errors:
            print(f"   - {test}: {traceback.splitlines()[-1]}")
    
    # Determinar estado general
    if result.wasSuccessful():
        print("\\n🎉 ¡TODOS LOS TESTS PASARON!")
        return True
    else:
        print("\\n⚠️  ALGUNOS TESTS FALLARON")
        return False

if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
''')
    
    print(f"✅ Suite de tests creada en: {test_dir}")
    print("📋 Tests incluidos:")
    print("   - test_system_orchestrator.py")
    print("   - test_ml_detector.py") 
    print("   - test_bitdefender_integration.py")
    print("   - run_all_tests.py (master runner)")

if __name__ == "__main__":
    create_test_suite()
