#!/usr/bin/env python3
"""
Diagnóstico completo de protobuf para upgraded-happiness
"""

import sys
import os
import subprocess
import importlib.util
from pathlib import Path


def print_section(title):
    print(f"\n{'=' * 60}")
    print(f"🔍 {title}")
    print('=' * 60)


def print_subsection(title):
    print(f"\n📋 {title}")
    print('-' * 40)


def run_command(cmd):
    """Ejecuta un comando y retorna la salida"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        return "", str(e), 1


def check_python_environment():
    print_section("ENTORNO PYTHON")

    print(f"Python version: {sys.version}")
    print(f"Python executable: {sys.executable}")

    # Verificar entorno virtual
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✅ Ejecutándose en entorno virtual")
        if 'VIRTUAL_ENV' in os.environ:
            print(f"Virtual env path: {os.environ['VIRTUAL_ENV']}")
    else:
        print("⚠️  NO está en un entorno virtual")

    print(f"Python path: {sys.path[:3]}...")  # Primeros 3 elementos


def check_protobuf_installation():
    print_section("INSTALACIÓN DE PROTOBUF")

    # Verificar protobuf Python
    print_subsection("Protobuf Python Runtime")
    try:
        import google.protobuf
        print(f"✅ google.protobuf version: {google.protobuf.__version__}")
        print(f"   Ubicación: {google.protobuf.__file__}")

        # Verificar componentes principales
        components = [
            ('google.protobuf.message', 'Message'),
            ('google.protobuf.timestamp_pb2', 'Timestamp'),
            ('google.protobuf.descriptor', 'Descriptor'),
        ]

        for module_name, class_name in components:
            try:
                module = __import__(module_name, fromlist=[class_name])
                print(f"✅ {module_name} disponible")
            except ImportError as e:
                print(f"❌ {module_name}: {e}")

        # Verificar runtime_version específicamente
        try:
            from google.protobuf import runtime_version
            print("✅ runtime_version disponible")
            print(f"   Ubicación: {runtime_version.__file__}")
        except ImportError:
            print("❌ runtime_version NO disponible")
            print("   Esto indica protobuf < 5.x")

    except ImportError as e:
        print(f"❌ google.protobuf no instalado: {e}")
        return False

    # Verificar protoc (compilador)
    print_subsection("Protobuf Compiler (protoc)")
    stdout, stderr, returncode = run_command("protoc --version")
    if returncode == 0:
        print(f"✅ protoc version: {stdout}")

        # Verificar ubicación
        stdout, _, _ = run_command("which protoc")
        if stdout:
            print(f"   Ubicación: {stdout}")

        # Verificar múltiples instalaciones
        stdout, _, _ = run_command("which -a protoc")
        if stdout:
            paths = stdout.split('\n')
            if len(paths) > 1:
                print(f"⚠️  Múltiples instalaciones encontradas:")
                for path in paths:
                    print(f"     {path}")

    else:
        print(f"❌ protoc no disponible: {stderr}")
        return False

    return True


def check_project_structure():
    print_section("ESTRUCTURA DEL PROYECTO")

    current_dir = Path.cwd()
    print(f"Directorio actual: {current_dir}")

    # Verificar estructura esperada
    expected_files = [
        "protocols/v3_1/network_security_clean_v31.proto",
        "protocols/v3_1/firewall_commands_v31.proto",
        "protocols/v3_1/__init__.py",
        "core/evolutionary_sniffer_standalone.py"
    ]

    for file_path in expected_files:
        full_path = current_dir / file_path
        if full_path.exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} - NO ENCONTRADO")

    # Verificar archivos generados
    print_subsection("Archivos generados de protobuf")
    generated_files = [
        "protocols/v3_1/network_security_clean_v31_pb2.py",
        "protocols/v3_1/firewall_commands_v31_pb2.py"
    ]

    for file_path in generated_files:
        full_path = current_dir / file_path
        if full_path.exists():
            print(f"✅ {file_path}")

            # Verificar contenido problemático
            try:
                with open(full_path, 'r') as f:
                    content = f.read()

                if 'runtime_version' in content:
                    print(f"⚠️  {file_path} contiene referencias a runtime_version")

                if 'PROTOBUF_VERSION' in content:
                    # Extraer la versión
                    lines = content.split('\n')
                    for line in lines:
                        if 'PROTOBUF_VERSION' in line and '!=' in line:
                            print(f"   Versión esperada en archivo: {line.strip()}")
                            break

            except Exception as e:
                print(f"❌ Error leyendo {file_path}: {e}")
        else:
            print(f"❌ {file_path} - NO ENCONTRADO")


def check_import_issues():
    print_section("PRUEBAS DE IMPORTACIÓN")

    # Prueba 1: Importación básica de protobuf
    print_subsection("Importación básica de protobuf")
    try:
        import google.protobuf
        print("✅ google.protobuf importado correctamente")
    except ImportError as e:
        print(f"❌ Error importando google.protobuf: {e}")
        return

    # Prueba 2: Importación de módulos del proyecto
    print_subsection("Importación de módulos del proyecto")

    # Añadir directorio actual al path para importaciones
    current_dir = str(Path.cwd())
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)

    import_tests = [
        ("protocols.v3_1", "Módulo protocols.v3_1"),
        ("protocols.v3_1.network_security_clean_v31_pb2", "NetworkSecurity protobuf"),
        ("protocols.v3_1.firewall_commands_v31_pb2", "Firewall protobuf")
    ]

    for module_name, description in import_tests:
        try:
            module = __import__(module_name, fromlist=[''])
            print(f"✅ {description}")

            # Si es un módulo protobuf, intentar crear instancia
            if '_pb2' in module_name:
                if hasattr(module, 'NetworkSecurityEvent'):
                    event = module.NetworkSecurityEvent()
                    print(f"   ✅ Instancia de NetworkSecurityEvent creada")
                elif hasattr(module, 'FirewallCommand'):
                    cmd = module.FirewallCommand()
                    print(f"   ✅ Instancia de FirewallCommand creada")

        except ImportError as e:
            print(f"❌ {description}: {e}")

            # Intentar diagnosticar el error específico
            if 'runtime_version' in str(e):
                print(f"   🔍 Error relacionado con runtime_version")
                print(f"      Esto indica incompatibilidad de versiones de protobuf")
        except Exception as e:
            print(f"❌ {description}: Error inesperado: {e}")


def check_file_contents():
    print_section("ANÁLISIS DE CONTENIDO DE ARCHIVOS")

    # Verificar __init__.py
    init_file = Path("protocols/v3_1/__init__.py")
    if init_file.exists():
        print_subsection("Contenido de __init__.py")
        try:
            with open(init_file, 'r') as f:
                content = f.read()
                print(f"Tamaño: {len(content)} caracteres")
                print("Contenido:")
                print("-" * 30)
                print(content[:500])  # Primeros 500 caracteres
                if len(content) > 500:
                    print("... (truncado)")
                print("-" * 30)
        except Exception as e:
            print(f"❌ Error leyendo __init__.py: {e}")

    # Verificar archivo protobuf generado
    pb2_file = Path("protocols/v3_1/network_security_clean_v31_pb2.py")
    if pb2_file.exists():
        print_subsection("Análisis de archivo protobuf generado")
        try:
            with open(pb2_file, 'r') as f:
                lines = f.readlines()
                print(f"Total de líneas: {len(lines)}")

                # Buscar líneas problemáticas
                problematic_lines = []
                for i, line in enumerate(lines[:50]):  # Primeras 50 líneas
                    if 'runtime_version' in line:
                        problematic_lines.append((i + 1, line.strip()))
                    elif 'PROTOBUF_VERSION' in line:
                        problematic_lines.append((i + 1, line.strip()))

                if problematic_lines:
                    print("⚠️  Líneas problemáticas encontradas:")
                    for line_num, line_content in problematic_lines:
                        print(f"   Línea {line_num}: {line_content}")
                else:
                    print("✅ No se encontraron líneas problemáticas en las primeras 50 líneas")

        except Exception as e:
            print(f"❌ Error analizando archivo protobuf: {e}")


def provide_recommendations():
    print_section("RECOMENDACIONES")

    print("""
📋 Basándose en el diagnóstico, estas son las recomendaciones:

1. 🔄 REGENERAR ARCHIVOS PROTOBUF:
   Los archivos actuales fueron generados con una versión incompatible.
   Ejecuta: ./regenerate_protobuf.sh

2. 🔧 VERIFICAR VERSIONES:
   Asegúrate de que protoc y protobuf Python sean compatibles.
   Versiones recomendadas:
   - protobuf 3.20.x (estable, sin runtime_version)
   - protobuf 5.27.x+ (moderna, con runtime_version)

3. 🧹 LIMPIAR ARCHIVOS ANTERIORES:
   rm protocols/v3_1/*_pb2.py
   rm -rf protocols/v3_1/__pycache__

4. 📦 REINSTALAR PROTOBUF SI ES NECESARIO:
   pip uninstall protobuf
   pip install protobuf==3.20.3

5. 🎯 PASOS ESPECÍFICOS PARA TU CASO:
   """)

    # Recomendaciones específicas basadas en el diagnóstico
    try:
        import google.protobuf
        version = google.protobuf.__version__
        major_version = int(version.split('.')[0])

        if major_version >= 5:
            print(f"   - Tienes protobuf {version} (5.x+)")
            print("   - Regenera archivos con protoc actual")
            print("   - Los archivos deberían funcionar con runtime_version")
        elif major_version == 4:
            print(f"   - Tienes protobuf {version} (4.x)")
            print("   - Considera actualizar a 5.x+ o bajar a 3.20.x")
        else:
            print(f"   - Tienes protobuf {version} (3.x)")
            print("   - Regenera archivos con protoc compatible con 3.x")
            print("   - No debería haber referencias a runtime_version")

    except ImportError:
        print("   - ❌ Instala protobuf primero: pip install protobuf")

    print("""
🚀 ORDEN DE EJECUCIÓN RECOMENDADO:
1. ./fix_protobuf_deps.sh
2. ./regenerate_protobuf.sh  
3. Probar el sniffer nuevamente
""")


def main():
    print("🔍 DIAGNÓSTICO DE PROTOBUF PARA UPGRADED-HAPPINESS")
    print("=" * 60)

    try:
        check_python_environment()
        protobuf_ok = check_protobuf_installation()
        check_project_structure()

        if protobuf_ok:
            check_import_issues()
            check_file_contents()

        provide_recommendations()

    except KeyboardInterrupt:
        print("\n\n⚠️  Diagnóstico interrumpido por el usuario")
    except Exception as e:
        print(f"\n\n❌ Error durante el diagnóstico: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()