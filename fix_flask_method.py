#!/usr/bin/env python3
"""
fix_flask_imports.py - Arreglar imports corruptos de Flask
Problema detectado: from flask import Flask, jso, render_template, jsonify, request, send_from_directorynify...
"""

import re
from pathlib import Path


def fix_flask_imports():
    backend_file = Path("core/dashboard_v31_etcd.py")

    print("🔧 Arreglando imports corruptos de Flask...")

    try:
        with open(backend_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Backup
        backup_path = backend_file.with_suffix('.py.backup5')
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"💾 Backup creado: {backup_path}")

        # Buscar la línea problemática de imports Flask
        flask_import_pattern = r'from flask import [^\\n]+'
        matches = list(re.finditer(flask_import_pattern, content))

        if matches:
            for match in matches:
                old_import = match.group(0)
                print(f"🔍 Import actual: {old_import}")

                # Verificar si tiene los typos conocidos
                if 'jso,' in old_import or 'send_from_directorynify' in old_import:
                    # Reemplazar con import correcto
                    correct_import = 'from flask import Flask, render_template, jsonify, request, send_from_directory'
                    content = content.replace(old_import, correct_import)
                    print(f"✅ Corregido a: {correct_import}")
                    break
        else:
            print("🔍 No se encontraron imports de Flask, buscando manualmente...")

            # Buscar línea por línea
            lines = content.split('\n')
            fixed_lines = []

            for i, line in enumerate(lines):
                if line.strip().startswith('from flask import'):
                    print(f"📍 Línea {i + 1}: {line}")

                    if 'jso,' in line or 'send_from_directorynify' in line or 'request, request' in line:
                        # Reemplazar línea problemática
                        fixed_line = '    from flask import Flask, render_template, jsonify, request, send_from_directory'
                        fixed_lines.append(fixed_line)
                        print(f"✅ Línea {i + 1} corregida")
                    else:
                        fixed_lines.append(line)
                else:
                    fixed_lines.append(line)

            content = '\n'.join(fixed_lines)

        # También arreglar import de CORS si está mal
        if 'from flask_cors import CORS' not in content:
            # Buscar si existe y está mal
            cors_pattern = r'from flask_cors import [^\\n]+'
            if not re.search(cors_pattern, content):
                # Agregar import CORS después del import Flask
                flask_line = 'from flask import Flask, render_template, jsonify, request, send_from_directory'
                if flask_line in content:
                    content = content.replace(
                        flask_line,
                        flask_line + '\n    from flask_cors import CORS'
                    )
                    print("✅ Import CORS agregado")

        # Guardar archivo corregido
        with open(backend_file, 'w', encoding='utf-8') as f:
            f.write(content)

        print("✅ Imports Flask corregidos y guardados")
        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def validate_flask_imports():
    """Validar que los imports Flask funcionan"""
    print("\n🔍 Validando imports Flask...")

    try:
        # Probar imports uno por uno
        test_code = """
try:
    from flask import Flask, render_template, jsonify, request, send_from_directory
    print("✅ Flask imports OK")
except ImportError as e:
    print(f"❌ Flask import error: {e}")

try:
    from flask_cors import CORS
    print("✅ CORS import OK")
except ImportError as e:
    print(f"❌ CORS import error: {e}")
"""

        exec(test_code)
        return True

    except Exception as e:
        print(f"❌ Error validando imports: {e}")
        return False


def validate_syntax_again():
    """Validar sintaxis Python completa"""
    backend_file = Path("core/dashboard_v31_etcd.py")

    print("\n🔍 Validación final de sintaxis...")

    try:
        with open(backend_file, 'r', encoding='utf-8') as f:
            content = f.read()

        compile(content, str(backend_file), 'exec')
        print("✅ Sintaxis Python válida")
        return True

    except SyntaxError as e:
        print(f"❌ Error de sintaxis en línea {e.lineno}: {e.msg}")
        print(f"   Texto: '{e.text.strip() if e.text else 'N/A'}'")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


if __name__ == "__main__":
    print("🧬 Upgraded Happiness V3.1 - Arreglar Imports Flask")
    print("=" * 60)

    if fix_flask_imports():
        validate_flask_imports()

        if validate_syntax_again():
            print("\n🎉 ¡IMPORTS FLASK CORREGIDOS!")
            print("\n📋 Ahora sí debería funcionar:")
            print(
                "   python3 core/dashboard_v31_etcd.py config/json/dashboard_config.json config/json/firewall_rules.json")
        else:
            print("\n⚠️  Imports corregidos, pero hay otros errores de sintaxis")
    else:
        print("\n❌ Error corrigiendo imports Flask")