#!/usr/bin/env python3
"""
Verificador completo del setup para Promiscuous Agent v2
Revisa todos los archivos necesarios y dependencias
"""

import os
import sys
from pathlib import Path
import importlib
import subprocess


def check_file(filepath, description, optional=False):
    """Verifica si un archivo existe"""
    path = Path(filepath)
    if path.exists():
        size = path.stat().st_size
        size_mb = size / (1024 * 1024)

        if size_mb > 1:
            print(f"  ✅ {filepath} - {size_mb:.1f} MB - {description}")
        elif size > 0:
            print(f"  ✅ {filepath} - {size} bytes - {description}")
        else:
            print(f"  ⚠️  {filepath} - VACÍO - {description}")
            return False
        return True
    else:
        if optional:
            print(f"  ⚪ {filepath} - OPCIONAL - {description}")
            return True
        else:
            print(f"  ❌ {filepath} - FALTANTE - {description}")
            return False


def check_python_module(module_name, description):
    """Verifica si un módulo de Python está disponible"""
    try:
        importlib.import_module(module_name)
        print(f"  ✅ {module_name} - {description}")
        return True
    except ImportError:
        print(f"  ❌ {module_name} - FALTANTE - {description}")
        return False


def check_system_command(command, description):
    """Verifica si un comando del sistema está disponible"""
    try:
        result = subprocess.run(['which', command],
                                capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  ✅ {command} - {description}")
            return True
        else:
            print(f"  ❌ {command} - FALTANTE - {description}")
            return False
    except:
        print(f"  ❌ {command} - ERROR - {description}")
        return False


def main():
    print("🔍 VERIFICADOR COMPLETO - Promiscuous Agent v2")
    print("=" * 60)

    all_good = True

    # 1. Verificar archivos principales
    print("\n📄 ARCHIVOS PRINCIPALES:")
    main_files = [
        ("promiscuous_agent_v2.py", "Agente principal de captura"),
        ("geoip_enricher_v2.py", "Enriquecedor de geolocalización"),
        ("traffic_generator.py", "Generador de tráfico Python", True),
        ("websites_database.csv", "Base de datos de sitios web"),
        ("quick_traffic.sh", "Generador de tráfico Bash", True),
        ("start_capture.sh", "Script de inicio completo", True),
    ]

    for file_info in main_files:
        filepath = file_info[0]
        description = file_info[1]
        optional = len(file_info) > 2 and file_info[2]

        if not check_file(filepath, description, optional):
            if not optional:
                all_good = False

    # 2. Verificar archivos GeoIP (CRÍTICOS)
    print("\n🌍 ARCHIVOS GeoIP (CRÍTICOS):")
    geodata_dir = Path("geodata")

    if not geodata_dir.exists():
        print("  ❌ directorio geodata/ - FALTANTE")
        print("     💡 Crear: mkdir geodata")
        all_good = False
    else:
        print(f"  ✅ directorio geodata/ - Existe")

    geoip_files = [
        ("geodata/GeoLite2-City.mmdb", "Base de datos de ciudades (CRÍTICO)"),
        ("geodata/GeoLite2-Country.mmdb", "Base de datos de países (CRÍTICO)"),
        ("geodata/GeoLite2-ASN-Test.mmdb", "Base de datos ASN (CRÍTICO)"),
        ("geodata/GeoLite2-ASN.mmdb", "Base de datos ASN alternativo", True),
    ]

    asn_found = False
    for file_info in geoip_files:
        filepath = file_info[0]
        description = file_info[1]
        optional = len(file_info) > 2 and file_info[2]

        if check_file(filepath, description, optional):
            if "ASN" in filepath:
                asn_found = True
        elif not optional:
            all_good = False

    if not asn_found:
        print("  ⚠️  ADVERTENCIA: No se encontró ningún archivo ASN")
        print("     💡 Necesitas GeoLite2-ASN-Test.mmdb o GeoLite2-ASN.mmdb")
        all_good = False

    # 3. Verificar archivo de configuración
    print("\n⚙️  ARCHIVOS DE CONFIGURACIÓN:")
    config_files = [
        ("promiscuous_agent_v2_config.json", "Configuración principal", True),
        (".env", "Variables de entorno (IPAPI_TOKEN)", True),
        ("config.json", "Configuración alternativa", True),
    ]

    for file_info in config_files:
        filepath = file_info[0]
        description = file_info[1]
        optional = len(file_info) > 2 and file_info[2]
        check_file(filepath, description, optional)

    # 4. Verificar dependencias Python
    print("\n🐍 DEPENDENCIAS PYTHON:")
    python_modules = [
        ("scapy", "Captura de paquetes de red"),
        ("geoip2", "Lectura de bases de datos GeoIP"),
        ("requests", "Peticiones HTTP para IPAPI"),
        ("psutil", "Información del sistema"),
        ("pandas", "Análisis de datos (para advanced-trainer)"),
        ("numpy", "Computación numérica"),
        ("sklearn", "Machine learning (para advanced-trainer)"),
        ("threading", "Hilos de ejecución"),
        ("queue", "Colas thread-safe"),
        ("json", "Manejo de JSON"),
        ("csv", "Manejo de CSV"),
        ("logging", "Sistema de logging"),
        ("ipaddress", "Manejo de direcciones IP"),
        ("socket", "Networking de bajo nivel"),
        ("time", "Manejo de tiempo"),
        ("datetime", "Fechas y horas"),
        ("pathlib", "Manejo de rutas"),
        ("collections", "Estructuras de datos"),
        ("dataclasses", "Clases de datos"),
        ("typing", "Tipado estático"),
    ]

    critical_modules = ['scapy', 'geoip2', 'requests', 'psutil']
    for module_name, description in python_modules:
        if not check_python_module(module_name, description):
            if module_name in critical_modules:
                all_good = False

    # 5. Verificar comandos del sistema
    print("\n💻 COMANDOS DEL SISTEMA:")
    system_commands = [
        ("curl", "Para generación de tráfico HTTP"),
        ("python3", "Intérprete de Python 3"),
        ("pip3", "Instalador de paquetes Python"),
        ("sudo", "Ejecución con privilegios"),
        ("ifconfig", "Configuración de interfaces de red", True),
        ("netstat", "Estadísticas de red", True),
    ]

    for cmd_info in system_commands:
        cmd_name = cmd_info[0]
        description = cmd_info[1]
        optional = len(cmd_info) > 2 and cmd_info[2]

        if not check_system_command(cmd_name, description):
            if not optional:
                all_good = False

    # 6. Verificar permisos
    print("\n🔐 PERMISOS:")
    if os.geteuid() == 0:
        print("  ✅ Root/sudo - Disponible para captura de paquetes")
    else:
        print("  ⚠️  No root - Necesitarás sudo para capturar paquetes")
        print("     💡 Ejecutar: sudo python promiscuous_agent_v2.py")

    # 7. Verificar espacio en disco
    print("\n💾 ESPACIO EN DISCO:")
    try:
        statvfs = os.statvfs('.')
        free_bytes = statvfs.f_frsize * statvfs.f_bavail
        free_mb = free_bytes / (1024 * 1024)

        if free_mb > 1000:  # 1GB
            print(f"  ✅ Espacio libre: {free_mb:.0f} MB - Suficiente")
        elif free_mb > 100:  # 100MB
            print(f"  ⚠️  Espacio libre: {free_mb:.0f} MB - Limitado pero funcional")
        else:
            print(f"  ❌ Espacio libre: {free_mb:.0f} MB - INSUFICIENTE")
            all_good = False
    except:
        print("  ⚪ No se pudo verificar espacio en disco")

    # 8. Resumen final
    print("\n" + "=" * 60)
    if all_good:
        print("🎉 ¡VERIFICACIÓN EXITOSA!")
        print("✅ Todos los componentes críticos están listos")
        print("\n🚀 Próximos pasos:")
        print("   1. sudo ./start_capture.sh")
        print("   2. O: sudo python promiscuous_agent_v2.py --interface auto")
        print("   3. Ejecutar traffic_generator.py en otra terminal")
    else:
        print("❌ VERIFICACIÓN FALLIDA")
        print("⚠️  Hay componentes críticos faltantes")
        print("\n🔧 Soluciones:")
        print("   1. Descargar archivos GeoIP desde MaxMind")
        print("   2. Instalar dependencias: pip install -r requirements.txt")
        print("   3. Verificar permisos de archivos")
        print("   4. Ejecutar: python quick_setup.py")

    print("\n💡 Para más ayuda:")
    print("   - python quick_setup.py (setup automático)")
    print("   - python promiscuous_agent_v2.py --help")
    print("   - python traffic_generator.py --help")

    return 0 if all_good else 1


if __name__ == "__main__":
    sys.exit(main())