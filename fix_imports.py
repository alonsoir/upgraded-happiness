#!/usr/bin/env python3
"""
fix_imports.py
🔧 Quick fix para problemas de import path
"""

import sys
import os


def fix_python_path():
    """Add core directory to Python path"""

    # Get current directory
    current_dir = os.getcwd()
    core_dir = os.path.join(current_dir, 'core')

    print(f"🔧 Current directory: {current_dir}")
    print(f"📁 Core directory: {core_dir}")

    # Add to Python path
    if core_dir not in sys.path:
        sys.path.insert(0, core_dir)
        print(f"✅ Added {core_dir} to Python path")
    else:
        print(f"✅ {core_dir} already in Python path")

    # Test imports
    print("\n🧪 Testing imports...")

    try:
        import sniffer_components
        print("✅ sniffer_components import OK")
    except ImportError as e:
        print(f"❌ sniffer_components import failed: {e}")
        return False

    try:
        import etcd_crypto_client_sniffer_fixed
        print("✅ etcd_crypto_client_sniffer_fixed import OK")
    except ImportError as e:
        print(f"❌ etcd_crypto_client_sniffer_fixed import failed: {e}")
        return False

    try:
        import evolutionary_sniffer_standalone
        print("✅ evolutionary_sniffer_standalone import OK")
    except ImportError as e:
        print(f"❌ evolutionary_sniffer_standalone import failed: {e}")
        return False

    return True


def test_crypto_setup():
    """Test crypto setup quickly"""
    print("\n🔐 Testing crypto setup...")

    try:
        from etcd_crypto_client_sniffer_fixed import setup_sniffer_crypto, get_sniffer_pipeline_key
        print("✅ Crypto functions imported")
        return True
    except ImportError as e:
        print(f"❌ Crypto import failed: {e}")
        return False


def main():
    print("🔧 IMPORT PATH FIXER")
    print("=" * 30)

    # Fix Python path
    success = fix_python_path()

    if success:
        # Test crypto setup
        crypto_ok = test_crypto_setup()

        if crypto_ok:
            print("\n🎉 ALL IMPORTS WORKING!")
            print("\n🚀 Ready to run sniffer:")
            print(
                "sudo python3 core/evolutionary_sniffer_standalone.py config/json/evolutionary_sniffer_config_v31_etcd.json")

            # Export PYTHONPATH for shell
            core_dir = os.path.join(os.getcwd(), 'core')
            print(f"\n📝 Export this in your shell:")
            print(f"export PYTHONPATH=\"{core_dir}:$PYTHONPATH\"")

        else:
            print("\n❌ Crypto imports still failing")
    else:
        print("\n❌ Component imports failing")

    return success


if __name__ == "__main__":
    main()