
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
