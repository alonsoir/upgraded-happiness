#!/usr/bin/env python3
"""
Script para arreglar TODOS los métodos que están fuera de la clase EvolutionarySnifferStandalone
"""

import re
import shutil


def fix_all_evolutionary_sniffer_methods():
    """Arregla todos los métodos que están fuera de la clase"""

    file_path = "core/evolutionary_sniffer_standalone.py"

    print("🔧 Arreglando TODOS los métodos de la clase EvolutionarySnifferStandalone...")

    # Leer el archivo
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        lines = content.split('\n')

    # Encontrar la clase y sus límites
    class_start_line = None
    class_end_line = None

    for i, line in enumerate(lines):
        if 'class EvolutionarySnifferStandalone:' in line:
            class_start_line = i
            break

    if class_start_line is None:
        print("❌ No se encontró la clase EvolutionarySnifferStandalone")
        return False

    # Encontrar donde debería terminar la clase (última línea con indentación de clase)
    for i in range(len(lines) - 1, class_start_line, -1):
        line = lines[i]
        if line.strip() and (line.startswith('    ') and not line.startswith('        ')):
            # Esta es una línea con indentación de método de clase
            class_end_line = i
            break
        elif line.strip() and not line.startswith(' '):
            # Encontramos una línea sin indentación después de la clase
            continue

    print(f"📍 Clase encontrada en línea {class_start_line + 1}")
    print(f"📍 Fin de clase detectado en línea {class_end_line + 1 if class_end_line else 'NO ENCONTRADO'}")

    # Encontrar todos los métodos mal ubicados (def xxxx(self):)
    misplaced_methods = []

    # Buscar métodos con 'self' que estén fuera de la clase
    for i, line in enumerate(lines):
        if i <= class_start_line:
            continue

        # Buscar definiciones de métodos que empiecen al inicio de la línea y tengan 'self'
        if re.match(r'^def\s+\w+\s*\(\s*self.*\):', line.strip()):
            method_name = re.search(r'def\s+(\w+)', line).group(1)
            print(f"🔍 Método mal ubicado encontrado: {method_name} en línea {i + 1}")
            misplaced_methods.append((i, method_name))

    if not misplaced_methods:
        print("✅ No se encontraron métodos mal ubicados")
        return True

    print(f"📋 Encontrados {len(misplaced_methods)} métodos mal ubicados")

    # Crear backup
    backup_path = f"{file_path}.backup2"
    shutil.copy2(file_path, backup_path)
    print(f"📋 Backup creado: {backup_path}")

    # Extraer cada método mal ubicado
    methods_content = {}

    for i, (line_num, method_name) in enumerate(misplaced_methods):
        start_line = line_num

        # Encontrar el final del método (siguiente def, class, o final del archivo)
        end_line = len(lines)
        for j in range(start_line + 1, len(lines)):
            next_line = lines[j].strip()
            # Si encontramos otra definición al nivel raíz, o if __name__, termina el método
            if (next_line.startswith('def ') or
                    next_line.startswith('class ') or
                    next_line.startswith('if __name__') or
                    next_line.startswith('async def ')):
                end_line = j
                break

        # Extraer el contenido del método
        method_lines = []
        for line_idx in range(start_line, end_line):
            original_line = lines[line_idx]
            if line_idx == start_line:
                # Primera línea: def method(self): -> añadir indentación de clase
                method_lines.append('    ' + original_line)
            elif original_line.strip() == '':
                # Líneas vacías mantenerlas
                method_lines.append(original_line)
            elif original_line.startswith('    '):
                # Ya tiene indentación, añadir 4 espacios más para clase
                method_lines.append('    ' + original_line)
            elif original_line.strip():
                # Línea con contenido sin indentación, añadir indentación de método
                method_lines.append('        ' + original_line)
            else:
                method_lines.append(original_line)

        methods_content[method_name] = method_lines
        print(f"✅ Extraído método '{method_name}' ({len(method_lines)} líneas)")

    # Reconstruir el archivo
    new_lines = []

    # Añadir todo hasta donde debe terminar la clase original
    if class_end_line:
        new_lines.extend(lines[:class_end_line + 1])
    else:
        # Si no encontramos el final, buscar la última línea con indentación de clase
        last_class_line = class_start_line
        for i in range(class_start_line + 1, len(lines)):
            if lines[i].startswith('    ') and not lines[i].startswith('        '):
                last_class_line = i
            elif lines[i].strip() and not lines[i].startswith(' '):
                break
        new_lines.extend(lines[:last_class_line + 1])

    # Añadir línea vacía antes de los métodos
    new_lines.append('')

    # Añadir todos los métodos extraídos dentro de la clase
    for method_name in methods_content:
        new_lines.extend(methods_content[method_name])
        new_lines.append('')  # Línea vacía entre métodos

    # Encontrar donde empieza el código después de los métodos mal ubicados
    last_method_line = misplaced_methods[-1][0] if misplaced_methods else 0

    # Buscar el final del último método mal ubicado
    for i, (line_num, _) in enumerate(misplaced_methods):
        start_line = line_num
        end_line = len(lines)
        for j in range(start_line + 1, len(lines)):
            next_line = lines[j].strip()
            if (next_line.startswith('def ') or
                    next_line.startswith('class ') or
                    next_line.startswith('if __name__') or
                    next_line.startswith('async def ')):
                end_line = j
                break
        last_method_line = max(last_method_line, end_line)

    # Añadir el resto del archivo (funciones principales, etc.)
    remaining_lines = lines[last_method_line:]

    # Filtrar líneas vacías duplicadas al inicio
    while remaining_lines and not remaining_lines[0].strip():
        remaining_lines.pop(0)

    new_lines.extend(remaining_lines)

    # Escribir el archivo corregido
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(new_lines))

    print("✅ Archivo reconstruido exitosamente!")

    # Verificación final
    print("\n🔍 Verificando resultado...")

    # Verificar que no hay métodos con self fuera de la clase
    with open(file_path, 'r', encoding='utf-8') as f:
        new_content = f.read()
        new_lines_check = new_content.split('\n')

    methods_outside = []
    in_class = False
    class_line = None

    for i, line in enumerate(new_lines_check):
        if 'class EvolutionarySnifferStandalone:' in line:
            in_class = True
            class_line = i
            continue
        elif line.strip() and not line.startswith(' ') and in_class:
            # Salimos de la clase
            in_class = False

        # Buscar métodos con self fuera de la clase
        if not in_class and re.match(r'^def\s+\w+\s*\(\s*self.*\):', line.strip()):
            method_name = re.search(r'def\s+(\w+)', line).group(1)
            methods_outside.append((i + 1, method_name))

    if methods_outside:
        print("❌ Aún hay métodos fuera de la clase:")
        for line_num, method_name in methods_outside:
            print(f"   📍 {method_name} en línea {line_num}")
    else:
        print("✅ Todos los métodos con 'self' están ahora dentro de la clase")

    # Mostrar estadísticas
    total_methods_in_class = len(re.findall(r'^\s{4}def\s+\w+\s*\(\s*self', new_content, re.MULTILINE))
    print(f"📊 Total de métodos en la clase: {total_methods_in_class}")

    return len(methods_outside) == 0


if __name__ == "__main__":
    success = fix_all_evolutionary_sniffer_methods()
    if success:
        print("\n🎉 ¡Arreglo completado exitosamente!")
        print("\n🧪 Puedes probar ahora:")
        print("   python core/evolutionary_sniffer_standalone.py")
    else:
        print("\n⚠️  Hubo problemas. Revisa el output anterior.")