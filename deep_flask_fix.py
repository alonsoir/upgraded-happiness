#!/usr/bin/env python3
"""
deep_flask_fix.py - Limpieza profunda de imports Flask corruptos
Error detectado: 'send_from_directorynder_template' - claramente corrupto
"""

import re
from pathlib import Path


def deep_clean_flask_imports():
    backend_file = Path("core/dashboard_v31_etcd.py")

    print("🧹 Limpieza profunda de imports Flask...")

    try:
        with open(backend_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Backup
        backup_path = backend_file.with_suffix('.py.backup6')
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"💾 Backup creado: {backup_path}")

        # Encontrar TODOS los imports Flask (pueden estar partidos en múltiples líneas)
        lines = content.split('\n')
        fixed_lines = []
        flask_import_found = False

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Detectar línea de import Flask corrupta
            if line.startswith('from flask import') or 'from flask import' in line:
                print(f"🔍 Línea {i + 1}: {line}")

                # Reemplazar completamente con import limpio
                indent = len(lines[i]) - len(lines[i].lstrip())
                clean_import = ' ' * indent + 'from flask import Flask, render_template, jsonify, request, send_from_directory'
                fixed_lines.append(clean_import)
                flask_import_found = True
                print(f"✅ Reemplazado con import limpio")

                # Saltar líneas adicionales que puedan ser parte del import corrupto
                j = i + 1
                while j < len(lines) and (
                        lines[j].strip().startswith(('render_template', 'jsonify', 'request', 'send_from_directory')) or
                        'send_from_director' in lines[j] or
                        'nder_template' in lines[j]
                ):
                    print(f"⏭️  Saltando línea corrupta {j + 1}: {lines[j].strip()}")
                    j += 1
                i = j - 1

            # Detectar import CORS
            elif line.startswith('from flask_cors import') or 'from flask_cors import' in line:
                if 'CORS' not in line:
                    indent = len(lines[i]) - len(lines[i].lstrip())
                    clean_cors = ' ' * indent + 'from flask_cors import CORS'
                    fixed_lines.append(clean_cors)
                    print(f"✅ Import CORS limpiado")
                else:
                    fixed_lines.append(lines[i])

            else:
                # Línea normal
                fixed_lines.append(lines[i])

            i += 1

        # Si no encontramos import Flask, agregarlo
        if not flask_import_found:
            print("⚠️  No se encontró import Flask, agregándolo...")
            # Buscar donde insertar (después de otros imports)
            insert_pos = 0
            for idx, line in enumerate(fixed_lines):
                if line.strip().startswith('import ') or line.strip().startswith('from '):
                    insert_pos = idx + 1

            fixed_lines.insert(insert_pos,
                               'from flask import Flask, render_template, jsonify, request, send_from_directory')
            fixed_lines.insert(insert_pos + 1, 'from flask_cors import CORS')

        # Reconstruir contenido
        content = '\n'.join(fixed_lines)

        # Limpieza adicional: remover cualquier referencia corrupta restante
        corrupted_patterns = [
            r'send_from_directoryn[a-z]*',
            r'jso[^n]',  # jso que no sea json
            r'render_template[a-z_]+string',
            r'from flask import[^\\n]*send_from_director[^\\n]*template[^\\n]*'
        ]

        for pattern in corrupted_patterns:
            matches = re.findall(pattern, content)
            if matches:
                print(f"🧹 Limpiando patrones corruptos: {matches}")
                content = re.sub(pattern, '', content)

        # Guardar
        with open(backend_file, 'w', encoding='utf-8') as f:
            f.write(content)

        print("✅ Limpieza profunda completada")
        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def verify_clean_imports():
    """Verificar que los imports están completamente limpios"""
    backend_file = Path("core/dashboard_v31_etcd.py")

    print("\n🔍 Verificando imports limpios...")

    try:
        with open(backend_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Buscar posibles problemas restantes
        problems = []

        # Buscar términos corruptos
        corrupted_terms = [
            'send_from_director',
            'nder_template',
            'jso,',
            'directorynify',
            'render_template_string'
        ]

        for term in corrupted_terms:
            if term in content:
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if term in line:
                        problems.append(f"Línea {i + 1}: {line.strip()}")

        if problems:
            print("❌ Problemas encontrados:")
            for problem in problems:
                print(f"   {problem}")
            return False
        else:
            print("✅ Imports completamente limpios")
            return True

    except Exception as e:
        print(f"❌ Error verificando: {e}")
        return False


def final_syntax_check():
    """Check final de sintaxis"""
    backend_file = Path("core/dashboard_v31_etcd.py")

    print("\n🔍 Check final de sintaxis...")

    try:
        with open(backend_file, 'r', encoding='utf-8') as f:
            content = f.read()

        compile(content, str(backend_file), 'exec')
        print("✅ Sintaxis completamente válida")
        return True

    except SyntaxError as e:
        print(f"❌ Error de sintaxis en línea {e.lineno}: {e.msg}")
        if e.text:
            print(f"   Texto problemático: '{e.text.strip()}'")

        # Mostrar contexto
        lines = content.split('\n')
        if e.lineno:
            start = max(0, e.lineno - 3)
            end = min(len(lines), e.lineno + 3)

            print(f"\n📍 Contexto:")
            for i in range(start, end):
                marker = ">>> " if i == e.lineno - 1 else "    "
                print(f"   {marker}{i + 1:3d}: {lines[i]}")

        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


if __name__ == "__main__":
    print("🧬 Upgraded Happiness V3.1 - Limpieza Profunda Flask")
    print("=" * 65)

    if deep_clean_flask_imports():
        if verify_clean_imports():
            if final_syntax_check():
                print("\n🎉 ¡IMPORTS FLASK COMPLETAMENTE LIMPIOS!")
                print("\n📋 Sistema listo para ejecutar:")
                print(
                    "   python3 core/dashboard_v31_etcd.py config/json/dashboard_config.json config/json/firewall_rules.json")
            else:
                print("\n⚠️  Imports limpios, pero hay errores de sintaxis")
        else:
            print("\n⚠️  Aún hay imports corruptos")
    else:
        print("\n❌ Error en limpieza profunda")