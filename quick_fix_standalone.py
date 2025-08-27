#!/usr/bin/env python3
"""
quick_fix_standalone.py
🔧 Quick fix para el problema de typing en evolutionary_sniffer_standalone.py
"""

import os


def fix_typing_import():
    """Fix the missing Optional import"""

    file_path = "core/evolutionary_sniffer_standalone.py"

    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return False

    print(f"🔧 Fixing typing imports in {file_path}...")

    # Read the file
    with open(file_path, 'r') as f:
        content = f.read()

    # Check if Optional is already imported
    if "from typing import" in content and "Optional" in content:
        print("✅ Optional already imported")
        return True

    # Find the imports section and add Optional
    lines = content.split('\n')
    fixed_lines = []
    typing_import_found = False

    for line in lines:
        if line.startswith("from typing import") and not typing_import_found:
            # Add Optional to existing typing import
            if "Optional" not in line:
                if line.endswith("Dict, Any, Optional"):
                    # Already has Optional at end
                    fixed_lines.append(line)
                elif "Dict, Any" in line:
                    # Add Optional after Dict, Any
                    line = line.replace("Dict, Any", "Dict, Any, Optional")
                    fixed_lines.append(line)
                else:
                    # Add Optional at the end
                    if line.endswith(")"):
                        line = line[:-1] + ", Optional)"
                    else:
                        line = line + ", Optional"
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)
            typing_import_found = True
        elif "from queue import Queue, Empty" in line and not typing_import_found:
            # Add typing import before queue import
            fixed_lines.append("from typing import Dict, Any, Optional")
            fixed_lines.append(line)
            typing_import_found = True
        else:
            fixed_lines.append(line)

    # If we didn't find any typing import, add it at the beginning of imports
    if not typing_import_found:
        for i, line in enumerate(fixed_lines):
            if line.startswith("import ") and not line.startswith("import os"):
                fixed_lines.insert(i, "from typing import Dict, Any, Optional")
                break

    # Write the fixed content
    fixed_content = '\n'.join(fixed_lines)

    with open(file_path, 'w') as f:
        f.write(fixed_content)

    print("✅ Fixed typing imports")
    return True


def test_import_after_fix():
    """Test import after fixing"""
    print("\n🧪 Testing import after fix...")

    try:
        import sys
        # Remove from cache if already imported
        if 'evolutionary_sniffer_standalone' in sys.modules:
            del sys.modules['evolutionary_sniffer_standalone']

        # Add core to path
        core_path = os.path.join(os.getcwd(), 'core')
        if core_path not in sys.path:
            sys.path.insert(0, core_path)

        # Try import
        import evolutionary_sniffer_standalone
        print("✅ evolutionary_sniffer_standalone import successful")
        return True

    except Exception as e:
        print(f"❌ Import still failing: {e}")
        return False


def main():
    print("🔧 QUICK FIX - Typing Import")
    print("=" * 30)

    # Fix the typing import
    success = fix_typing_import()

    if success:
        # Test the import
        import_success = test_import_after_fix()

        if import_success:
            print("\n🎉 FIX SUCCESSFUL!")
            print("\n🚀 Now run the sniffer:")
            print(
                "sudo python3 core/evolutionary_sniffer_standalone.py config/json/sniffer_config.json")
        else:
            print("\n❌ Import still failing after fix")
    else:
        print("\n❌ Failed to fix typing import")

    return success


if __name__ == "__main__":
    main()