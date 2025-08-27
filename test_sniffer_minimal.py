#!/usr/bin/env python3
"""
test_sniffer_minimal.py
🧪 Minimal test for sniffer with real config
Diagnostica problemas de configuración y crypto sync
"""

import asyncio
import os
import sys
import json


def check_environment():
    """Check environment setup"""
    print("🌍 ENVIRONMENT CHECK:")

    env_vars = {
        'PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION': 'python',
        'UPGRADED_HAPPINESS_DEV_MODE': 'true',
        'PYTHONPATH': f"{os.getcwd()}/core"
    }

    for var, expected in env_vars.items():
        current = os.environ.get(var, 'NOT SET')
        if var == 'PYTHONPATH':
            status = "✅" if 'core' in current else "⚠️"
        else:
            status = "✅" if current == expected else "⚠️"
        print(f"   {status} {var}: {current}")

        # Set if not set
        if current == 'NOT SET' or (var == 'PYTHONPATH' and 'core' not in current):
            os.environ[var] = expected
            print(f"      → Set to: {expected}")


def check_config_file():
    """Check the actual config file being used"""
    config_file = "config/json/evolutionary_sniffer_config_v31_etcd.json"

    print(f"\n📁 CONFIG FILE CHECK: {config_file}")

    if not os.path.exists(config_file):
        print(f"❌ Config file not found!")
        return None

    try:
        with open(config_file, 'r') as f:
            config = json.load(f)

        print("✅ Config file loaded successfully")

        # Check critical sections
        sections_to_check = {
            'node_id': config.get('node_id', 'NOT SET'),
            'etcd_crypto': 'present' if 'etcd_crypto' in config else 'MISSING',
            'network': 'present' if 'network' in config else 'MISSING',
            'crypto': 'present' if 'crypto' in config else 'MISSING'
        }

        for section, value in sections_to_check.items():
            status = "✅" if value not in ['NOT SET', 'MISSING'] else "❌"
            print(f"   {status} {section}: {value}")

        # Show ETCD config details
        if 'etcd_crypto' in config:
            etcd_config = config['etcd_crypto']
            print(f"\n🔧 ETCD CONFIG DETAILS:")
            print(f"   📡 Host: {etcd_config.get('etcd_host', 'NOT SET')}")
            print(f"   🔌 Port: {etcd_config.get('etcd_port', 'NOT SET')}")
            print(f"   🏢 Cluster: {etcd_config.get('cluster_name', 'NOT SET')}")
            print(f"   🆔 Node ID: {etcd_config.get('node_id', 'NOT SET')}")

        return config

    except Exception as e:
        print(f"❌ Error reading config: {e}")
        return None


def test_imports():
    """Test all required imports"""
    print(f"\n📦 IMPORT TESTS:")

    # Add core to path
    core_path = os.path.join(os.getcwd(), 'core')
    if core_path not in sys.path:
        sys.path.insert(0, core_path)
        print(f"   📁 Added to path: {core_path}")

    imports_to_test = [
        ('sniffer_components', 'Sniffer components'),
        ('etcd_crypto_client_sniffer_fixed', 'ETCD crypto client'),
        ('evolutionary_sniffer_standalone', 'Standalone sniffer')
    ]

    imported_modules = {}

    for module_name, description in imports_to_test:
        try:
            module = __import__(module_name)
            imported_modules[module_name] = module
            print(f"   ✅ {description}: OK")
        except Exception as e:
            print(f"   ❌ {description}: {e}")
            imported_modules[module_name] = None

    return imported_modules


async def test_crypto_setup(config_file):
    """Test crypto setup with real config"""
    print(f"\n🔐 CRYPTO SETUP TEST:")

    try:
        from etcd_crypto_client_sniffer_fixed import setup_sniffer_crypto, get_sniffer_pipeline_key, \
            get_sniffer_crypto_status

        print(f"   📋 Config file: {config_file}")
        print(f"   🧪 Testing mode: True")

        # Setup crypto
        print("   🔄 Setting up crypto...")
        success = await setup_sniffer_crypto(config_file, testing_mode=True)

        if success:
            print("   ✅ Crypto setup successful!")

            # Get pipeline key
            pipeline_key = get_sniffer_pipeline_key()
            if pipeline_key:
                print(f"   🔑 Pipeline key: {pipeline_key[:16]}... (length: {len(pipeline_key)})")
            else:
                print("   ❌ No pipeline key available")
                return False, None

            # Get status
            status = get_sniffer_crypto_status()
            print(f"   📊 Crypto status: {status.get('ready', 'unknown')}")

            return True, pipeline_key

        else:
            print("   ❌ Crypto setup failed")
            return False, None

    except Exception as e:
        print(f"   ❌ Crypto test failed: {e}")
        import traceback
        traceback.print_exc()
        return False, None


def test_sniffer_creation(config_file, pipeline_key):
    """Test sniffer instance creation"""
    print(f"\n🚀 SNIFFER CREATION TEST:")

    try:
        from evolutionary_sniffer_standalone import EvolutionarySnifferStandalone

        print("   🔄 Creating sniffer instance...")
        sniffer = EvolutionarySnifferStandalone(config_file, pipeline_key)

        print("   ✅ Sniffer created successfully!")

        # Test basic properties
        print(f"   🆔 Node ID: {sniffer.node_id}")
        print(f"   🔑 Pipeline key present: {'✅' if sniffer.pipeline_key else '❌'}")
        print(f"   ⏰ Time windows: {len(sniffer.time_window_manager.window_configs)}")
        print(f"   📊 Features extractor: {type(sniffer.features_extractor).__name__}")

        # Test window configs
        for window_type, config in sniffer.time_window_manager.window_configs.items():
            print(f"      📊 {window_type}: {config.window_size_seconds}s, models: {config.model_types}")

        return True, sniffer

    except Exception as e:
        print(f"   ❌ Sniffer creation failed: {e}")
        import traceback
        traceback.print_exc()
        return False, None


def test_event_creation(sniffer):
    """Test event creation capabilities"""
    print(f"\n📤 EVENT CREATION TEST:")

    try:
        # Create test packet and flow
        from sniffer_components import PacketInfo, FlowInfo

        test_packet = PacketInfo(
            timestamp=1234567890.0,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=80,
            dst_port=12345,
            protocol_number=6,
            protocol_name="TCP",
            packet_size=1500,
            tcp_flags={'S': True, 'A': False, 'P': False, 'F': False, 'R': False, 'U': False},
            flow_id="test_flow_1"
        )

        test_flow = FlowInfo(
            flow_id="test_flow_1",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=80,
            dst_port=12345,
            protocol="TCP",
            start_time=1234567890.0,
            last_seen=1234567891.0,
            forward_packets=[test_packet],
            backward_packets=[],
            total_forward_bytes=1500,
            total_backward_bytes=0
        )

        print("   🔄 Testing feature extraction...")
        features = sniffer.features_extractor.extract_all_features(test_flow)
        print(f"   ✅ Extracted {len(features)} features")

        # Test window data creation
        window_data = {
            'window_type': 'test_window',
            'config': list(sniffer.time_window_manager.window_configs.values())[0],
            'start_time': 1234567890.0,
            'end_time': 1234567891.0,
            'flows': [test_flow],
            'flow_count': 1
        }

        print("   🔄 Testing event creation...")
        event_data = sniffer._create_network_security_event(test_flow, features, window_data, "ddos_83")

        if event_data:
            print(f"   ✅ Event created successfully! Size: {len(event_data)} bytes")
            return True
        else:
            print("   ❌ Event creation returned None")
            return False

    except Exception as e:
        print(f"   ❌ Event creation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Main test function"""
    print("🧪 SNIFFER MINIMAL TEST")
    print("=" * 50)

    # Test sequence
    tests = []

    # 1. Environment check
    check_environment()

    # 2. Config file check
    config = check_config_file()
    if not config:
        print("\n❌ Cannot proceed without valid config")
        return False

    config_file = "config/json/evolutionary_sniffer_config_v31_etcd.json"

    # 3. Import tests
    imports = test_imports()
    if not all(imports.values()):
        print("\n❌ Cannot proceed with failed imports")
        return False

    # 4. Crypto setup test
    crypto_success, pipeline_key = await test_crypto_setup(config_file)
    tests.append(("Crypto Setup", crypto_success))

    if not crypto_success:
        print("\n❌ Cannot proceed without crypto")
        return False

    # 5. Sniffer creation test
    sniffer_success, sniffer = test_sniffer_creation(config_file, pipeline_key)
    tests.append(("Sniffer Creation", sniffer_success))

    if not sniffer_success:
        print("\n❌ Cannot proceed without sniffer")
        return False

    # 6. Event creation test
    event_success = test_event_creation(sniffer)
    tests.append(("Event Creation", event_success))

    # Results summary
    print("\n" + "=" * 50)
    print("📊 TEST RESULTS:")

    all_passed = True
    for test_name, result in tests:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {status} {test_name}")
        if not result:
            all_passed = False

    print("\n" + "=" * 50)

    if all_passed:
        print("🎉 ALL TESTS PASSED!")
        print("\n🚀 READY TO RUN FULL SNIFFER:")
        print(
            "sudo -E python3 core/evolutionary_sniffer_standalone.py config/json/sniffer_config.json")
        print("\n📊 Expected to see:")
        print("   📦 Packets: >0 (capturing)")
        print("   📤 Events: >0 (processing)")
        print("   🗑️ Drops: 0 (no errors)")
    else:
        print("❌ SOME TESTS FAILED!")
        print("\n🔧 Check the errors above and fix before running full sniffer")
        print("\n💡 Common fixes:")
        print("   - Ensure all files are saved in core/")
        print("   - Check config file syntax")
        print("   - Verify environment variables")

    return all_passed


if __name__ == "__main__":
    try:
        result = asyncio.run(main())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test crashed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)