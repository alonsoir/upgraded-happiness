#!/usr/bin/env python3
"""
quick_fix_sending.py
🔧 Quick fix for ZMQ sending issues
"""

import os
import subprocess
import sys

def kill_existing_sniffer():
    """Kill existing sniffer process"""
    print("🔄 Killing existing sniffer processes...")

    try:
        # Find processes using port 5570
        result = subprocess.run(['lsof', '-t', '-i', ':5570'], capture_output=True, text=True)
        if result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                try:
                    subprocess.run(['kill', '-9', pid], check=True)
                    print(f"✅ Killed process {pid}")
                except:
                    print(f"⚠️  Could not kill process {pid}")
        else:
            print("✅ No processes found using port 5570")
    except Exception as e:
        print(f"⚠️  Error checking processes: {e}")

def fix_config_port():
    """Change config to use different port"""
    config_file = "config/json/evolutionary_sniffer_config_v31_etcd.json"

    if not os.path.exists(config_file):
        print(f"❌ Config file not found: {config_file}")
        return False

    print(f"🔧 Updating config port from 5570 to 5571...")

    with open(config_file, 'r') as f:
        content = f.read()

    # Replace port
    new_content = content.replace('"port": 5570', '"port": 5571')

    if new_content != content:
        with open(config_file, 'w') as f:
            f.write(new_content)
        print("✅ Port updated to 5571")
        return True
    else:
        print("⚠️  Port not found in config")
        return False

def main():
    print("🔧 QUICK FIX - ZMQ SENDING ISSUES")
    print("=" * 40)

    # Option 1: Kill existing processes
    kill_existing_sniffer()

    # Option 2: Change port in config
    fix_config_port()

    print("\n🚀 NOW TRY RUNNING SNIFFER AGAIN:")
    print("sudo -E python3 core/evolutionary_sniffer_standalone.py config/json/sniffer_config.json")

if __name__ == "__main__":
    main()
