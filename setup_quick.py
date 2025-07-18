#!/usr/bin/env python3
"""
Setup rápido para Upgraded-Happiness
Configura el entorno y verifica que todo esté listo para funcionar.
"""

import os
import sys
import subprocess
import json
import logging
from pathlib import Path


def check_python_version():
    """Verifica la versión de Python"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ requerido")
        print(f"   Versión actual: {sys.version}")
        return False

    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} OK")
    return True


def check_and_install_dependencies():
    """Verifica e instala dependencias necesarias"""
    print("🔍 Checking dependencies...")

    # Solo verificar ZeroMQ ya que el resto son built-in
    try:
        import zmq
        print(f"✅ pyzmq {zmq.zmq_version()} available")
        return True
    except ImportError:
        print("❌ pyzmq not found")

        install = input("Install pyzmq? (y/N): ").strip().lower()
        if install == 'y':
            try:
                print("📦 Installing pyzmq...")
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyzmq'])
                print("✅ pyzmq installed successfully")
                return True
            except subprocess.CalledProcessError:
                print("❌ Failed to install pyzmq")
                return False
        else:
            print("❌ pyzmq is required")
            return False


def create_directory_structure():
    """Crea estructura de directorios"""
    directories = [
        'logs',
        'config',
        'tests',
        'backups'
    ]

    print("📁 Creating directory structure...")

    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"   ✅ {directory}/")

    return True


def verify_required_files():
    """Verifica que todos los archivos necesarios estén presentes"""
    required_files = [
        'rule_engine.py',
        'simple_system_detection.py',
        'simple_firewall_agent.py',
        'event_analyzer.py',
        'integration_test.py',
        'start_security_platform.py',
        'rule_engine_config.json'
    ]

    print("📄 Checking required files...")

    missing_files = []
    for file in required_files:
        if os.path.exists(file):
            print(f"   ✅ {file}")
        else:
            print(f"   ❌ {file} - MISSING")
            missing_files.append(file)

    if missing_files:
        print(f"\n⚠️  Missing files detected:")
        for file in missing_files:
            print(f"   - {file}")
        print(f"\nPlease ensure all required files are in the current directory.")
        return False

    return True


def test_system_detection():
    """Prueba la detección del sistema"""
    print("🖥️  Testing system detection...")

    try:
        from simple_system_detection import SimpleSystemDetector

        detector = SimpleSystemDetector()
        summary = detector.get_system_summary()

        print(f"   ✅ Node ID: {summary['node_id'][:8]}...")
        print(f"   ✅ OS: {summary['os_name']} {summary['os_version']}")
        print(f"   ✅ Firewall: {summary['firewall_type']} ({summary['firewall_status']})")

        return True

    except Exception as e:
        print(f"   ❌ System detection failed: {e}")
        return False


def test_rule_engine():
    """Prueba el motor de reglas"""
    print("🧠 Testing rule engine...")

    try:
        from rule_engine import RuleEngine, create_test_event

        engine = RuleEngine('rule_engine_config.json')

        # Test con evento de anomalía alta
        test_event = create_test_event('192.168.1.100', 22, 0.95)
        recommendations = engine.analyze_event(test_event)

        if recommendations:
            rec = recommendations[0]
            print(f"   ✅ Generated recommendation: {rec.action} for {rec.target_ip}")
            print(f"   ✅ Confidence: {rec.confidence:.2f}")
        else:
            print(f"   ⚠️  No recommendations generated (this might be normal)")

        return True

    except Exception as e:
        print(f"   ❌ Rule engine test failed: {e}")
        return False


def create_test_config():
    """Crea archivos de configuración de ejemplo"""
    print("⚙️  Creating configuration files...")

    # Configuración del agente (ejemplo)
    agent_config = {
        "name": "upgraded_happiness_agent",
        "interfaces": ["eth0", "wlan0"],
        "capture_filter": "not arp and not icmp",
        "batch_size": 100,
        "zeromq_endpoint": "tcp://localhost:5559"
    }

    config_path = "config/agent_config.json"
    try:
        with open(config_path, 'w') as f:
            json.dump(agent_config, f, indent=2)
        print(f"   ✅ {config_path}")
    except Exception as e:
        print(f"   ⚠️  Could not create {config_path}: {e}")

    return True


def create_startup_scripts():
    """Crea scripts de arranque para diferentes plataformas"""
    print("📜 Creating startup scripts...")

    # Script para Linux/macOS
    bash_script = '''#!/bin/bash
# Upgraded-Happiness Quick Start Script

echo "🚀 Starting Upgraded-Happiness Security Platform..."

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found"
    exit 1
fi

# Ir al directorio del script
cd "$(dirname "$0")"

# Verificar archivos
if [ ! -f "start_security_platform.py" ]; then
    echo "❌ start_security_platform.py not found"
    exit 1
fi

# Ejecutar plataforma
python3 start_security_platform.py

echo "👋 Platform stopped"
'''

    try:
        with open('start.sh', 'w') as f:
            f.write(bash_script)
        os.chmod('start.sh', 0o755)
        print(f"   ✅ start.sh (Linux/macOS)")
    except Exception as e:
        print(f"   ⚠️  Could not create start.sh: {e}")

    # Script para Windows
    batch_script = '''@echo off
REM Upgraded-Happiness Quick Start Script

echo 🚀 Starting Upgraded-Happiness Security Platform...

REM Verificar Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found
    pause
    exit /b 1
)

REM Ir al directorio del script
cd /d "%~dp0"

REM Verificar archivos
if not exist "start_security_platform.py" (
    echo ❌ start_security_platform.py not found
    pause
    exit /b 1
)

REM Ejecutar plataforma
python start_security_platform.py

echo 👋 Platform stopped
pause
'''

    try:
        with open('start.bat', 'w') as f:
            f.write(batch_script)
        print(f"   ✅ start.bat (Windows)")
    except Exception as e:
        print(f"   ⚠️  Could not create start.bat: {e}")

    return True


def create_readme():
    """Crea README básico"""
    readme_content = '''# Upgraded-Happiness Security Platform

## 🚀 Quick Start

### Automatic Setup
```bash
python setup_quick.py
```

### Manual Start
```bash
# Linux/macOS
./start.sh

# Windows  
start.bat

# Or directly with Python
python start_security_platform.py
```

## 🧪 Testing

```bash
# Test integration
python integration_test.py

# Test with automation
python integration_test.py --auto
```

## 📊 System Components

- **Rule Engine**: Analiza eventos y genera recomendaciones
- **Firewall Agent**: Ejecuta comandos de firewall (display-only por defecto)
- **Event Analyzer**: Coordina análisis y decisiones
- **System Detection**: Detecta SO y firewall automáticamente

## ⚙️ Configuration

Edit `rule_engine_config.json` to adjust:
- Anomaly thresholds
- Rate limiting settings
- Port protection rules
- Response actions

## 🔒 Security

**IMPORTANTE**: Sistema inicia en modo DISPLAY-ONLY por seguridad.
Para activar aplicación real de reglas usar flag `--apply-real`.

## 📝 Logs

Check `logs/` directory for detailed operation logs.

---
*Built with ❤️ for the protection of humans and AIs alike*
'''

    try:
        with open('README.md', 'w') as f:
            f.write(readme_content)
        print(f"   ✅ README.md")
    except Exception as e:
        print(f"   ⚠️  Could not create README.md: {e}")

    return True


def run_quick_test():
    """Ejecuta una prueba rápida del sistema"""
    print("🧪 Running quick system test...")

    try:
        # Verificar que se pueda importar todo
        print("   🔍 Testing imports...")

        # Test imports uno por uno para mejor debugging
        try:
            from rule_engine import RuleEngine
            print("     ✅ rule_engine")
        except Exception as e:
            print(f"     ❌ rule_engine: {e}")
            return False

        try:
            from simple_system_detection import SimpleSystemDetector
            print("     ✅ simple_system_detection")
        except Exception as e:
            print(f"     ❌ simple_system_detection: {e}")
            return False

        try:
            from simple_firewall_agent import SimpleFirewallAgent
            print("     ✅ simple_firewall_agent")
        except Exception as e:
            print(f"     ❌ simple_firewall_agent: {e}")
            return False

        try:
            from event_analyzer import EventAnalyzer
            print("     ✅ event_analyzer")
        except Exception as e:
            print(f"     ❌ event_analyzer: {e}")
            return False

        print("   ✅ All modules import successfully")

        # Test básico de detección
        detector = SimpleSystemDetector()
        node_id = detector.node_id
        print(f"   ✅ System detection works (Node: {node_id[:8]}...)")

        # Test básico de reglas
        engine = RuleEngine('rule_engine_config.json')
        stats = engine.get_statistics()
        print(f"   ✅ Rule engine initialized")

        return True

    except Exception as e:
        print(f"   ❌ Quick test failed: {e}")
        return False


def print_final_instructions():
    """Imprime instrucciones finales"""
    print(f"\n🎉 Setup completed successfully!")
    print(f"=" * 50)
    print(f"")
    print(f"📋 Next steps:")
    print(f"")
    print(f"1️⃣  Start the platform:")
    print(f"   ./start.sh                    # Linux/macOS")
    print(f"   start.bat                     # Windows")
    print(f"   python start_security_platform.py  # Direct")
    print(f"")
    print(f"2️⃣  Test the system:")
    print(f"   python integration_test.py")
    print(f"")
    print(f"3️⃣  Configure rules:")
    print(f"   Edit rule_engine_config.json")
    print(f"")
    print(f"4️⃣  Monitor logs:")
    print(f"   Check logs/ directory")
    print(f"")
    print(f"⚠️  IMPORTANT: System starts in SAFE mode")
    print(f"   All firewall commands are display-only")
    print(f"   Use --apply-real flag only after thorough testing")
    print(f"")
    print(f"🛡️  Ready to protect critical infrastructure!")


def main():
    """Función principal"""
    print(f"⚙️  Upgraded-Happiness Quick Setup")
    print(f"=" * 40)
    print(f"")

    steps = [
        ("Checking Python version", check_python_version),
        ("Installing dependencies", check_and_install_dependencies),
        ("Creating directories", create_directory_structure),
        ("Verifying required files", verify_required_files),
        ("Testing system detection", test_system_detection),
        ("Testing rule engine", test_rule_engine),
        ("Creating config files", create_test_config),
        ("Creating startup scripts", create_startup_scripts),
        ("Creating documentation", create_readme),
        ("Running quick test", run_quick_test),
    ]

    failed_steps = []

    for step_name, step_func in steps:
        print(f"\n{step_name}...")
        try:
            if not step_func():
                failed_steps.append(step_name)
                print(f"   ⚠️  {step_name} had issues")
        except Exception as e:
            print(f"   💥 Unexpected error in {step_name}: {e}")
            failed_steps.append(step_name)

    print(f"\n" + "=" * 40)

    if failed_steps:
        print(f"⚠️  Setup completed with warnings:")
        for step in failed_steps:
            print(f"   - {step}")
        print(f"\nYou may still be able to run the system.")
        print(f"Check the error messages above for details.")
    else:
        print(f"✅ All setup steps completed successfully!")

    print_final_instructions()

    return 0 if not failed_steps else 1


if __name__ == "__main__":
    sys.exit(main())