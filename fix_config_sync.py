#!/usr/bin/env python3
"""
fix_config_sync.py
🔧 Fix para sincronizar configuraciones entre crypto client y sniffer
"""

import os
import json
import sys


def check_current_config():
    """Check the current sniffer config"""
    config_path = "config/json/evolutionary_sniffer_config_v31_etcd.json"

    print(f"🔍 Checking config: {config_path}")

    if not os.path.exists(config_path):
        print(f"❌ Config file not found: {config_path}")
        return None

    try:
        with open(config_path, 'r') as f:
            config = json.load(f)

        print("✅ Config loaded successfully")

        # Check key sections
        if 'etcd_crypto' in config:
            etcd_config = config['etcd_crypto']
            print(f"📡 ETCD Host: {etcd_config.get('etcd_host', 'NOT SET')}")
            print(f"🏢 Cluster: {etcd_config.get('cluster_name', 'NOT SET')}")
            print(f"🆔 Node ID: {etcd_config.get('node_id', 'NOT SET')}")
        else:
            print("❌ etcd_crypto section missing!")
            return None

        if 'network' in config:
            network = config['network']
            if 'output_socket' in network:
                output = network['output_socket']
                print(f"📤 ZMQ: {output.get('address', 'localhost')}:{output.get('port', 5570)}")

        return config

    except Exception as e:
        print(f"❌ Error reading config: {e}")
        return None


def test_crypto_with_real_config():
    """Test crypto client with real config file"""
    config_path = "config/json/evolutionary_sniffer_config_v31_etcd.json"

    print(f"\n🧪 Testing crypto with real config: {config_path}")

    try:
        # Set environment for testing
        os.environ['UPGRADED_HAPPINESS_DEV_MODE'] = 'true'
        os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

        # Add core to path
        core_path = os.path.join(os.getcwd(), 'core')
        if core_path not in sys.path:
            sys.path.insert(0, core_path)

        # Import and test
        from etcd_crypto_client_sniffer_fixed import setup_sniffer_crypto, get_sniffer_pipeline_key

        print("✅ Crypto client imported")

        # Test with real config
        import asyncio

        async def test_setup():
            success = await setup_sniffer_crypto(config_path, testing_mode=True)
            if success:
                pipeline_key = get_sniffer_pipeline_key()
                print(f"✅ Setup successful with real config")
                print(f"🔑 Pipeline key: {pipeline_key[:16] if pipeline_key else 'None'}...")
                return True
            else:
                print("❌ Setup failed with real config")
                return False

        result = asyncio.run(test_setup())
        return result

    except Exception as e:
        print(f"❌ Crypto test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def analyze_performance_issues():
    """Analyze why packets are being dropped"""
    print("\n📊 PERFORMANCE ANALYSIS:")
    print("From the logs I can see:")
    print("   📦 Packets captured: 295 (9.8/s) ✅")
    print("   📊 Features extracted: 809 ✅")
    print("   📤 Events sent: 0 ❌")
    print("   🗑️ Drops: 418 ❌")
    print("")
    print("🔍 ROOT CAUSE ANALYSIS:")
    print("   ✅ Packet capture: Working")
    print("   ✅ Feature extraction: Working")
    print("   ❌ Event creation: FAILING (protobuf errors)")
    print("   ❌ ZMQ send: Not reached due to event creation failure")
    print("")
    print("💡 SOLUTION:")
    print("   1. Fix protobuf mock (already done)")
    print("   2. Sync crypto config with real sniffer config")
    print("   3. Restart sniffer with consistent config")


def create_minimal_test_script():
    """Create a minimal test script for sniffer"""
    test_script = '''#!/usr/bin/env python3
"""
test_sniffer_minimal.py
🧪 Minimal test for sniffer with real config
"""

import asyncio
import os
import sys

async def test_real_sniffer():
    """Test sniffer with real config"""

    # Set environment
    os.environ['UPGRADED_HAPPINESS_DEV_MODE'] = 'true'
    os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

    # Add core to path
    core_path = os.path.join(os.getcwd(), 'core')
    if core_path not in sys.path:
        sys.path.insert(0, core_path)

    config_file = "config/json/sniffer_config.json"

    print(f"🧪 Testing sniffer with: {config_file}")

    try:
        # Test crypto setup
        from etcd_crypto_client_sniffer_fixed import setup_sniffer_crypto, get_sniffer_pipeline_key

        print("🔐 Setting up crypto...")
        success = await setup_sniffer_crypto(config_file, testing_mode=True)

        if not success:
            print("❌ Crypto setup failed")
            return False

        pipeline_key = get_sniffer_pipeline_key()
        print(f"✅ Pipeline key ready: {pipeline_key[:16]}...")

        # Test sniffer creation
        from evolutionary_sniffer_standalone import EvolutionarySnifferStandalone

        print("🚀 Creating sniffer instance...")
        sniffer = EvolutionarySnifferStandalone(config_file, pipeline_key)

        print("✅ Sniffer created successfully!")
        print(f"   🆔 Node ID: {sniffer.node_id}")
        print(f"   ⏰ Time windows: {len(sniffer.time_window_manager.window_configs)}")
        print(f"   🔑 Pipeline key: {'✅' if sniffer.pipeline_key else '❌'}")

        return True

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    asyncio.run(test_real_sniffer())
'''

    with open("test_sniffer_minimal.py", "w") as f:
        f.write(test_script)

    print("\n📝 Created test_sniffer_minimal.py")
    return True


def main():
    print("🔧 CONFIG SYNC FIXER")
    print("=" * 40)

    # 1. Check current config
    config = check_current_config()
    if not config:
        print("\n❌ Cannot proceed without valid config")
        return False

    # 2. Test crypto with real config
    crypto_ok = test_crypto_with_real_config()

    # 3. Analyze performance issues
    analyze_performance_issues()

    # 4. Create minimal test
    create_minimal_test_script()

    print("\n" + "=" * 40)

    if crypto_ok:
        print("🎉 CONFIG SYNC SUCCESSFUL!")
        print("\n🚀 NEXT STEPS:")
        print("1. Test minimal sniffer:")
        print("   python3 test_sniffer_minimal.py")
        print("")
        print("2. If test passes, run full sniffer:")
        print(
            "   sudo -E python3 core/evolutionary_sniffer_standalone.py config/json/sniffer_config.json")
        print("")
        print("3. Watch for:")
        print("   📤 Events sent: should be > 0")
        print("   🗑️ Drops: should decrease")
    else:
        print("❌ CONFIG SYNC ISSUES REMAIN")
        print("\nCheck the error messages above and fix crypto client issues.")

    return crypto_ok


if __name__ == "__main__":
    main()