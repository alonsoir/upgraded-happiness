#!/usr/bin/env python3
"""
test_sniffer_integration.py
🧪 Test de integración paso a paso para evolutionary sniffer con ETCD
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path


def create_test_config():
    """Crear configuración mínima para testing"""
    config = {
        "component": {
            "name": "evolutionary_sniffer",
            "version": "3.1.0",
            "mode": "distributed_advanced"
        },

        "node_id": "evolutionary_sniffer_test_001",
        "version": "3.1.0",
        "cluster_name": "upgraded-happiness-cluster",

        "etcd_crypto": {
            "etcd_host": "localhost",
            "etcd_port": 2379,
            "cluster_name": "upgraded-happiness-cluster",
            "node_id": "evolutionary_sniffer_test_001"
        },

        "network": {
            "output_socket": {
                "address": "localhost",
                "port": 5570,
                "mode": "bind",
                "socket_type": "PUSH"
            }
        },

        "zmq": {
            "sndhwm": 2000,
            "linger_ms": 1000,
            "send_timeout_ms": 100
        },

        "time_windows": {
            "test_window": {
                "window_size_seconds": 10.0,
                "slide_interval_seconds": 2.0,
                "max_flows_per_window": 100,
                "features_required": ["flow_duration", "total_forward_packets"],
                "model_types": ["test_model"],
                "description": "Test window"
            }
        },

        "capture": {
            "mode": "real",
            "interface": "lo",  # loopback for testing
            "promiscuous_mode": False,
            "filter_expression": "tcp port 22",  # minimal traffic
            "buffer_size": 65536
        },

        "processing": {
            "internal_queue_size": 100,
            "processing_threads": 1,
            "window_processing_threads": 1,
            "queue_timeout_seconds": 1.0
        },

        "features": {
            "extraction_enabled": True,
            "ddos_features_count": 83
        },

        "logging": {
            "level": "INFO",
            "file": None  # Solo console para testing
        },

        "monitoring": {
            "stats_interval_seconds": 10
        },

        "distributed": {
            "cluster_name": "upgraded-happiness-cluster",
            "node_role": "packet_sniffer"
        },

        "protobuf": {
            "schema_version": "v3.1.0"
        },

        "crypto": {
            "enabled": True,
            "role": "sender",
            "use_etcd_pipeline_key": True
        }
    }

    return config


async def test_step_1_dependencies():
    """Test 1: Verificar dependencias"""
    print("🔍 STEP 1: Testing dependencies...")

    issues = []

    # Test protobuf
    try:
        import google.protobuf
        print(f"✅ protobuf: {google.protobuf.__version__}")
    except ImportError as e:
        issues.append(f"❌ protobuf: {e}")

    # Test etcd3 con workaround
    try:
        os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'
        import etcd3
        print("✅ etcd3: available")
    except ImportError as e:
        print(f"⚠️  etcd3: {e}")
        issues.append("etcd3 not available - will use mock mode")

    # Test zmq
    try:
        import zmq
        print(f"✅ zmq: {zmq.zmq_version()}")
    except ImportError as e:
        issues.append(f"❌ zmq: {e}")

    # Test scapy
    try:
        from scapy.all import sniff
        print("✅ scapy: available")
    except ImportError as e:
        issues.append(f"❌ scapy: {e}")

    if issues:
        print("\n⚠️  Issues found:")
        for issue in issues:
            print(f"   {issue}")
        return False

    print("✅ All dependencies OK")
    return True


async def test_step_2_config():
    """Test 2: Crear y validar configuración"""
    print("\n🔍 STEP 2: Testing configuration...")

    try:
        config = create_test_config()

        # Crear archivo temporal
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f, indent=2)
            config_path = f.name

        print(f"✅ Config created: {config_path}")

        # Validar estructura
        required_sections = ['etcd_crypto', 'network', 'capture', 'crypto']
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Missing section: {section}")

        print("✅ Config structure valid")
        return config_path

    except Exception as e:
        print(f"❌ Config test failed: {e}")
        return None


async def test_step_3_crypto_client():
    """Test 3: Cliente crypto"""
    print("\n🔍 STEP 3: Testing crypto client...")

    config_path = await test_step_2_config()
    if not config_path:
        return False

    try:
        # Enable dev mode
        os.environ['UPGRADED_HAPPINESS_DEV_MODE'] = 'true'

        # Import fixed client
        from etcd_crypto_client_sniffer_fixed import setup_sniffer_crypto, get_sniffer_pipeline_key

        # Test setup
        success = await setup_sniffer_crypto(config_path, testing_mode=True)

        if success:
            print("✅ Crypto client setup successful")

            # Test key retrieval
            pipeline_key = get_sniffer_pipeline_key()
            if pipeline_key:
                print(f"✅ Pipeline key obtained: {pipeline_key[:16]}...")
                return True
            else:
                print("❌ Failed to get pipeline key")
                return False
        else:
            print("❌ Crypto client setup failed")
            return False

    except Exception as e:
        print(f"❌ Crypto client test failed: {e}")
        return False
    finally:
        # Cleanup
        if config_path and os.path.exists(config_path):
            os.unlink(config_path)


async def test_step_4_sniffer_import():
    """Test 4: Import del sniffer principal"""
    print("\n🔍 STEP 4: Testing sniffer import...")

    try:
        # Test import de componentes clave

        # NetworkFeaturesExtractor
        try:
            from evolutionary_sniffer_v31_etcd import NetworkFeaturesExtractor
            print("✅ NetworkFeaturesExtractor imported")
        except ImportError as e:
            print(f"⚠️  NetworkFeaturesExtractor: {e}")

        # TimeWindowManager
        try:
            from evolutionary_sniffer_v31_etcd import TimeWindowManager
            print("✅ TimeWindowManager imported")
        except ImportError as e:
            print(f"⚠️  TimeWindowManager: {e}")

        # Main sniffer class
        try:
            from evolutionary_sniffer_v31_etcd import EvolutionarySniffer
            print("✅ EvolutionarySniffer imported")
            return True
        except ImportError as e:
            print(f"❌ EvolutionarySniffer import failed: {e}")
            return False

    except Exception as e:
        print(f"❌ Sniffer import test failed: {e}")
        return False


async def test_step_5_minimal_run():
    """Test 5: Ejecución mínima del sniffer"""
    print("\n🔍 STEP 5: Testing minimal sniffer run...")

    config_path = await test_step_2_config()
    if not config_path:
        return False

    try:
        # Enable dev mode
        os.environ['UPGRADED_HAPPINESS_DEV_MODE'] = 'true'

        # Setup crypto first
        from etcd_crypto_client_sniffer_fixed import setup_sniffer_crypto, get_sniffer_pipeline_key

        success = await setup_sniffer_crypto(config_path, testing_mode=True)
        if not success:
            print("❌ Crypto setup failed")
            return False

        pipeline_key = get_sniffer_pipeline_key()
        if not pipeline_key:
            print("❌ No pipeline key")
            return False

        print("✅ Crypto ready for sniffer")

        # Try to create sniffer instance (without running)
        from evolutionary_sniffer_v31_etcd import EvolutionarySniffer

        sniffer = EvolutionarySniffer(config_path, pipeline_key)
        print("✅ Sniffer instance created successfully")

        # Test configuration parsing
        print(f"✅ Node ID: {sniffer.node_id}")
        print(f"✅ Time windows: {len(sniffer.time_window_manager.window_configs)}")
        print(f"✅ Pipeline key available: {bool(sniffer.pipeline_key)}")

        return True

    except Exception as e:
        print(f"❌ Minimal run test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        if config_path and os.path.exists(config_path):
            os.unlink(config_path)


async def run_all_tests():
    """Ejecutar todos los tests"""
    print("🚀 EVOLUTIONARY SNIFFER INTEGRATION TESTS")
    print("=" * 50)

    tests = [
        ("Dependencies", test_step_1_dependencies),
        ("Configuration", test_step_2_config),
        ("Crypto Client", test_step_3_crypto_client),
        ("Sniffer Import", test_step_4_sniffer_import),
        ("Minimal Run", test_step_5_minimal_run)
    ]

    results = []

    for name, test_func in tests:
        try:
            result = await test_func()
            results.append((name, result))

            if not result:
                print(f"\n❌ Test '{name}' failed - stopping here")
                break

        except Exception as e:
            print(f"\n❌ Test '{name}' crashed: {e}")
            results.append((name, False))
            break

    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST RESULTS SUMMARY:")

    for name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"   {status} {name}")

    all_passed = all(result for _, result in results)

    if all_passed:
        print("\n🎉 ALL TESTS PASSED!")
        print("🚀 Ready to run evolutionary sniffer!")
        print("\nNext steps:")
        print("1. export UPGRADED_HAPPINESS_DEV_MODE=true")
        print("2. python core/evolutionary_sniffer_v31_etcd.py config/json/evolutionary_sniffer_config_v31_etcd.json")
    else:
        print("\n❌ Some tests failed. Fix issues before proceeding.")
        print("\n💡 Quick fixes:")
        print("1. pip install 'protobuf<=3.20.3'")
        print("2. pip install scapy")
        print("3. Check that all files are in the right place")


if __name__ == "__main__":
    # Set up environment for testing
    os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

    if len(sys.argv) > 1:
        step = sys.argv[1]

        if step == "1":
            asyncio.run(test_step_1_dependencies())
        elif step == "2":
            asyncio.run(test_step_2_config())
        elif step == "3":
            asyncio.run(test_step_3_crypto_client())
        elif step == "4":
            asyncio.run(test_step_4_sniffer_import())
        elif step == "5":
            asyncio.run(test_step_5_minimal_run())
        else:
            print("❌ Invalid step. Use 1-5 or no argument for all tests")
    else:
        asyncio.run(run_all_tests())