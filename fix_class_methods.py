#!/usr/bin/env python3
"""
fix_class_methods.py
Script para arreglar los métodos run y shutdown que se añadieron fuera de la clase
"""


def fix_evolutionary_sniffer_methods():
    """Arregla los métodos que están fuera de la clase"""

    file_path = "core/evolutionary_sniffer_standalone.py"

    print("🔧 Arreglando métodos de la clase EvolutionarySnifferStandalone...")

    # Leer el archivo
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # Encontrar donde termina la clase y donde empiezan los métodos mal ubicados
    class_end_line = None
    run_method_start = None
    shutdown_method_start = None
    main_function_start = None

    for i, line in enumerate(lines):
        # Buscar el final de la clase (antes de los métodos mal ubicados)
        if 'def _log_performance_stats(self):' in line:
            # Buscar el final de este método para encontrar donde termina la clase
            for j in range(i + 1, len(lines)):
                if lines[j].strip() == '' and j + 1 < len(lines) and not lines[j + 1].startswith('    '):
                    class_end_line = j
                    break

        # Buscar los métodos mal ubicados
        if line.strip().startswith('def run(self):'):
            run_method_start = i
        elif line.strip().startswith('def shutdown(self, threads):'):
            shutdown_method_start = i
        elif line.strip().startswith('if __name__ == "__main__":'):
            main_function_start = i
            break

    if not all([class_end_line, run_method_start, shutdown_method_start, main_function_start]):
        print("❌ No se pudieron encontrar todas las secciones necesarias")
        print(f"class_end_line: {class_end_line}")
        print(f"run_method_start: {run_method_start}")
        print(f"shutdown_method_start: {shutdown_method_start}")
        print(f"main_function_start: {main_function_start}")
        return False

    # Extraer los métodos mal ubicados
    run_method_lines = []
    shutdown_method_lines = []

    # Extraer método run
    for i in range(run_method_start, shutdown_method_start):
        line = lines[i]
        if line.strip():  # Solo líneas no vacías
            # Añadir indentación de clase (4 espacios)
            if line.startswith('def '):
                run_method_lines.append('    ' + line)
            elif line.startswith('    '):
                run_method_lines.append('    ' + line)
            else:
                run_method_lines.append('        ' + line)
        else:
            run_method_lines.append(line)

    # Extraer método shutdown
    for i in range(shutdown_method_start, main_function_start):
        line = lines[i]
        if line.strip():  # Solo líneas no vacías
            # Añadir indentación de clase (4 espacios)
            if line.startswith('def '):
                shutdown_method_lines.append('    ' + line)
            elif line.startswith('    '):
                shutdown_method_lines.append('    ' + line)
            else:
                shutdown_method_lines.append('        ' + line)
        else:
            shutdown_method_lines.append(line)

    # Construir el nuevo archivo
    new_lines = []

    # Añadir todo hasta el final de la clase
    new_lines.extend(lines[:class_end_line + 1])

    # Añadir los métodos con la indentación correcta
    new_lines.extend(run_method_lines)
    new_lines.append('\n')
    new_lines.extend(shutdown_method_lines)
    new_lines.append('\n')

    # Añadir la función main y async main
    new_lines.append('async def main():\n')
    new_lines.append('    """Main async function"""\n')
    new_lines.append('    sniffer = EvolutionarySnifferStandalone()\n')
    new_lines.append('    sniffer.run()\n')
    new_lines.append('\n')

    # Añadir el if __name__ == "__main__":
    new_lines.extend(lines[main_function_start:])

    # Crear backup
    import shutil
    backup_path = f"{file_path}.backup"
    shutil.copy2(file_path, backup_path)
    print(f"📋 Backup creado: {backup_path}")

    # Escribir el archivo corregido
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)

    print("✅ Archivo corregido exitosamente!")
    print("\n🔍 Verificando la estructura...")

    # Verificar que los métodos ahora estén en la clase
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Buscar los métodos dentro de la clase
    import re

    # Buscar la clase
    class_match = re.search(r'class EvolutionarySnifferStandalone.*?:', content, re.DOTALL)
    if class_match:
        class_start = class_match.end()

        # Buscar el próximo "class" o "def" sin indentación para encontrar el final
        after_class = content[class_start:]
        next_top_level = re.search(r'\n(?=\S)', after_class)

        if next_top_level:
            class_content = after_class[:next_top_level.start()]
        else:
            class_content = after_class

        # Verificar que los métodos estén en la clase
        if '    def run(self):' in class_content:
            print("✅ Método 'run' encontrado dentro de la clase")
        else:
            print("❌ Método 'run' NO encontrado dentro de la clase")

        if '    def shutdown(self, threads):' in class_content:
            print("✅ Método 'shutdown' encontrado dentro de la clase")
        else:
            print("❌ Método 'shutdown' NO encontrado dentro de la clase")

    return True


if __name__ == "__main__":
    fix_evolutionary_sniffer_methods()