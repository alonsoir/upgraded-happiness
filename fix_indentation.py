#!/usr/bin/env python3
"""
fix_indentation.py - Arreglar error de indentación en dashboard_v31_etcd.py
El error está en la línea 792: CORS(self.app) tiene indentación incorrecta
"""

import re
from pathlib import Path


def fix_python_indentation():
    backend_file = Path("core/dashboard_v31_etcd.py")

    print("🔧 Arreglando error de indentación...")
    print(f"   Archivo: {backend_file}")

    try:
        with open(backend_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        print(f"   📄 Total líneas: {len(lines)}")

        # Buscar la línea problemática alrededor de la 792
        fixed_lines = []
        fixes_applied = []

        for i, line in enumerate(lines):
            line_num = i + 1

            # Buscar líneas problemáticas comunes
            if 'CORS(self.app)' in line and line.startswith('    CORS(self.app)'):
                # Está mal indentada, debería estar al nivel de método de clase
                fixed_line = '        CORS(self.app)\n'  # 8 espacios para método de clase
                fixed_lines.append(fixed_line)
                fixes_applied.append(f"Línea {line_num}: Corregida indentación CORS")

            elif 'CORS(self.app)' in line and line.strip().startswith('CORS(self.app)'):
                # Verificar si está dentro de una clase o función
                # Buscar el contexto previo
                context_indent = 8  # Por defecto, método de clase
                for j in range(max(0, i - 10), i):
                    prev_line = lines[j].rstrip()
                    if prev_line.strip().startswith('def ') and not prev_line.startswith('    def '):
                        context_indent = 4  # Función global
                        break
                    elif prev_line.strip().startswith('def ') and prev_line.startswith('    def '):
                        context_indent = 8  # Método de clase
                        break
                    elif prev_line.strip().startswith('class '):
                        context_indent = 4  # Dentro de clase, primer nivel
                        break

                fixed_line = ' ' * context_indent + 'CORS(self.app)\n'
                fixed_lines.append(fixed_line)
                fixes_applied.append(f"Línea {line_num}: Corregida indentación CORS con contexto")

            else:
                # Línea normal, mantener
                fixed_lines.append(line)

        # Verificar si hay otros problemas de indentación comunes
        for i, line in enumerate(fixed_lines):
            line_num = i + 1

            # Buscar líneas que empiecen con espacios pero no sean múltiplos de 4
            if line.startswith(' ') and not line.startswith('    '):
                leading_spaces = len(line) - len(line.lstrip())
                if leading_spaces > 0 and leading_spaces % 4 != 0:
                    # Redondear a múltiplo de 4 más cercano
                    correct_indent = (leading_spaces // 4 + 1) * 4
                    fixed_line = ' ' * correct_indent + line.lstrip()
                    fixed_lines[i] = fixed_line
                    fixes_applied.append(f"Línea {line_num}: Corregida indentación no múltiplo de 4")

        if fixes_applied:
            # Crear backup
            backup_path = backend_file.with_suffix('.py.backup3')
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)  # Original
            print(f"      💾 Backup creado: {backup_path}")

            # Guardar archivo corregido
            with open(backend_file, 'w', encoding='utf-8') as f:
                f.writelines(fixed_lines)

            print("   ✅ Correcciones aplicadas:")
            for fix in fixes_applied:
                print(f"      - {fix}")

            return True
        else:
            print("   🤔 No se encontraron problemas de indentación obvios")

            # Mostrar líneas alrededor de 792 para debug
            print("   📍 Líneas alrededor de 792:")
            start_line = max(0, 790)
            end_line = min(len(lines), 795)

            for i in range(start_line, end_line):
                line_content = lines[i].rstrip()
                print(f"      {i + 1:3d}: '{line_content}'")

            return False

    except Exception as e:
        print(f"   ❌ Error arreglando indentación: {e}")
        return False


def validate_python_syntax():
    """Validar que el archivo Python tenga sintaxis correcta"""
    backend_file = Path("core/dashboard_v31_etcd.py")

    print("\n🔍 Validando sintaxis Python...")

    try:
        with open(backend_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Intentar compilar el código
        compile(content, str(backend_file), 'exec')
        print("   ✅ Sintaxis Python válida")
        return True

    except SyntaxError as e:
        print(f"   ❌ Error de sintaxis en línea {e.lineno}: {e.msg}")
        print(f"      Texto: {e.text.strip() if e.text else 'N/A'}")
        return False
    except Exception as e:
        print(f"   ❌ Error validando sintaxis: {e}")
        return False


if __name__ == "__main__":
    print("🧬 Upgraded Happiness V3.1 - Arreglar Indentación")
    print("=" * 55)

    if fix_python_indentation():
        if validate_python_syntax():
            print("\n🎉 ¡INDENTACIÓN CORREGIDA!")
            print("\n📋 Listo para probar:")
            print("   python3 core/dashboard_v31_etcd.py")
        else:
            print("\n⚠️  Indentación corregida, pero aún hay errores de sintaxis")
    else:
        print("\n🔍 Revisando manualmente...")

        # Mostrar detalles del error para solución manual
        backend_file = Path("core/dashboard_v31_etcd.py")
        try:
            with open(backend_file, 'r', encoding='utf-8') as f:
                content = f.read()
            compile(content, str(backend_file), 'exec')
        except SyntaxError as e:
            print(f"\n❌ Error específico:")
            print(f"   Línea {e.lineno}: {e.msg}")
            print(f"   Texto: '{e.text.strip() if e.text else 'N/A'}'")

            if e.lineno:
                lines = content.split('\n')
                start = max(0, e.lineno - 3)
                end = min(len(lines), e.lineno + 2)

                print(f"\n📍 Contexto alrededor de línea {e.lineno}:")
                for i in range(start, end):
                    marker = ">>> " if i == e.lineno - 1 else "    "
                    print(f"   {marker}{i + 1:3d}: {lines[i]}")