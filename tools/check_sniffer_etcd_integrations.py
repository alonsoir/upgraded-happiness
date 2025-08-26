#!/usr/bin/env python3
"""
🧪 SCRIPT DE VERIFICACIÓN - Sniffer ETCD Integration
check_sniffer_etcd_integrations.py
Verificar que todo está listo antes de modificar el código principal
"""

import asyncio
import json
import os
import sys
import subprocess
from pathlib import Path


def check_file_exists(file_path: str, description: str) -> bool:
    """Verificar que un archivo existe"""
    if os.path.exists(file_path):
        print(f"✅ {description}: {file_path}")
        return True
    else:
        print(f"❌ {description}: {file_path} - NOT FOUND")
        return False


def check_import(module_name: str, description: str) -> bool:
    """Verificar que un módulo se puede importar"""
    try:
        __import__(module_name)
        print(f"✅ {description}: {module_name}")
        return True
    except ImportError as e:
        print(f"❌ {description}: {module_name} - {e}")
        return False


def check_etcd_running() -> bool:
    """Verificar que ETCD está corriendo"""
    try:
        import subprocess
        result = subprocess.run(['curl', '-s', 'http://localhost:2379/health'],
                                capture_output=True, timeout=5)
        if result.returncode == 0:
            print("✅ ETCD running on localhost:2379")
            return True
        else:
            print("❌ ETCD not responding on localhost:2379")
            return False
    except Exception as e:
        print(f"❌ ETCD check failed: {e}")
        return False


def validate_json_config(config_path: str) -> bool:
    """Validar estructura del JSON config"""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)

        print(f"✅ JSON valid: {config_path}")

        # Verificar campos obligatorios
        required_fields = [
            "node_id", "network", "capture", "processing",
            "time_windows", "logging", "monitoring", "etcd_crypto"
        ]

        missing = []
        for field in required_fields:
            if field not in config:
                missing.append(field)

        if missing:
            print(f"❌ Missing required fields: {missing}")
            return False

        # Verificar etcd_crypto específicamente
        etcd_crypto = config.get("etcd_crypto", {})
        etcd_required = ["etcd_host", "etcd_port", "cluster_name", "node_id"]
        etcd_missing = []

        for field in etcd_required:
            if field not in etcd_crypto:
                etcd_missing.append(f"etcd_crypto.{field}")

        if etcd_missing:
            print(f"❌ Missing etcd_crypto fields: {etcd_missing}")
            return False

        print("✅ JSON config structure valid")
        print(f"   📡 ETCD: {etcd_crypto['etcd_host']}:{etcd_crypto['etcd_port']}")
        print(f"   🆔 Node ID: {etcd_crypto['node_id']}")

        return True

    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON: {e}")
        return False
    except Exception as e:
        print(f"❌ Config validation failed: {e}")
        return False


async def test_etcd_crypto_client(config_path: str) -> bool:
    """Test del cliente crypto específico del sniffer"""
    try:
        # Import el cliente
        from core.etcd_crypto_client_sniffer import (
            setup_sniffer_crypto,
            get_sniffer_pipeline_key,
            get_sniffer_crypto_status
        )

        print("✅ ETCD crypto client imports successful")

        # Test setup
        print("🧪 Testing sniffer crypto setup...")
        success = await setup_sniffer_crypto(config_path)

        if success:
            print("✅ Sniffer crypto setup successful!")

            # Test key retrieval
            pipeline_key = get_sniffer_pipeline_key()
            if pipeline_key:
                print(f"✅ Pipeline key retrieved: {pipeline_key[:32]}...")

                # Test status
                status = get_sniffer_crypto_status()
                print(f"✅ Status: {status}")

                return True
            else:
                print("❌ Failed to retrieve pipeline key")
                return False
        else:
            print("❌ Sniffer crypto setup failed!")
            return False

    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False


def check_crypto_zmq_interface() -> bool:
    """Verificar interfaz de CryptoZMQV31"""
    try:
        # Intentar diferentes paths de import
        try:
            from core.crypto.crypto_zmq_v31 import CryptoZMQV31
            import_path = "core.crypto.crypto_zmq_v31"
        except ImportError:
            from crypto.crypto_zmq_v31 import CryptoZMQV31
            import_path = "crypto.crypto_zmq_v31"

        print(f"✅ CryptoZMQV31 import successful: {import_path}")

        # Verificar interfaz del constructor
        import inspect
        sig = inspect.signature(CryptoZMQV31.__init__)
        params = list(sig.parameters.keys())

        print(f"✅ CryptoZMQV31 constructor parameters: {params}")

        # Dar recomendaciones basadas en la interfaz
        if 'pipeline_key' in params:
            print("✅ CryptoZMQV31 supports pipeline_key parameter")
        elif len(params) == 2:  # self + 1 param
            print("✅ CryptoZMQV31 takes 1 parameter (likely pipeline_key)")
        else:
            print(f"⚠️  CryptoZMQV31 interface may need adjustment")
            print(f"    Parameters: {params}")

        return True

    except ImportError as e:
        print(f"❌ CryptoZMQV31 import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ CryptoZMQV31 check failed: {e}")
        return False


async def main():
    """Verificación completa"""
    print("🧪 SNIFFER ETCD INTEGRATION - VERIFICATION")
    print("=" * 50)
    print()

    checks_passed = 0
    total_checks = 0

    # 1. Verificar archivos necesarios
    print("📁 1. Checking required files:")
    files_to_check = [
        ("core/etcd_crypto_client_sniffer.py", "ETCD crypto client for sniffer"),
        ("core/etcd_coordinator.py", "ETCD coordinator"),
        ("config/json/evolutionary_sniffer_config_v31.json", "Sniffer config file")
    ]

    for file_path, description in files_to_check:
        if check_file_exists(file_path, description):
            checks_passed += 1
        total_checks += 1

    print()

    # 2. Verificar imports
    print("📦 2. Checking Python imports:")
    imports_to_check = [
        ("etcd3", "ETCD client library"),
        ("cryptography", "Cryptography library"),
        ("scapy", "Packet capture library"),
        ("zmq", "ZeroMQ library")
    ]

    for module, description in imports_to_check:
        if check_import(module, description):
            checks_passed += 1
        total_checks += 1

    print()

    # 3. Verificar CryptoZMQV31
    print("🔐 3. Checking CryptoZMQV31 interface:")
    if check_crypto_zmq_interface():
        checks_passed += 1
    total_checks += 1

    print()

    # 4. Verificar ETCD
    print("📡 4. Checking ETCD server:")
    if check_etcd_running():
        checks_passed += 1
    total_checks += 1

    print()

    # 5. Validar config
    config_path = "config/json/evolutionary_sniffer_config_v31.json"
    print("📋 5. Validating JSON config:")
    if os.path.exists(config_path):
        if validate_json_config(config_path):
            checks_passed += 1
        total_checks += 1

        print()

        # 6. Test ETCD crypto client
        print("🧪 6. Testing ETCD crypto integration:")
        if await test_etcd_crypto_client(config_path):
            checks_passed += 1
        total_checks += 1
    else:
        print(f"❌ Config file not found: {config_path}")
        total_checks += 2  # Skip config validation and crypto test

    # Resumen
    print()
    print("=" * 50)
    print(f"📊 VERIFICATION SUMMARY: {checks_passed}/{total_checks} checks passed")

    if checks_passed == total_checks:
        print("🎉 ALL CHECKS PASSED!")
        print("✅ Ready to modify evolutionary_sniffer_v31.py")
        print()
        print("📋 NEXT STEPS:")
        print("   1. Apply changes to evolutionary_sniffer_v31.py")
        print("   2. Test: python evolutionary_sniffer_v31.py config/json/evolutionary_sniffer_config_v31.json")
        return True
    else:
        print("⚠️  SOME CHECKS FAILED")
        print("🔧 Fix the issues above before proceeding")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)