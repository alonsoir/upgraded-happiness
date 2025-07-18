#!/usr/bin/env python3
"""
GeoLite2 Database Manager
Script independiente para gestionar bases de datos GeoLite2

Uso:
    python geolite2_manager.py --check              # Verificar estado
    python geolite2_manager.py --update             # Actualizar si es necesario
    python geolite2_manager.py --force-update       # Forzar actualización
    python geolite2_manager.py --setup-license      # Configurar license key
    python geolite2_manager.py --cleanup            # Limpiar archivos temporales
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Configuración por defecto
DEFAULT_CONFIG = {
    "geoip": {
        "auto_update": {
            "enabled": True,
            "maxmind_license_key": "YOUR_MAXMIND_LICENSE_KEY",
            "databases_to_update": ["GeoLite2-City"],
            "database_directory": ".",
            "backup_directory": "./backups",
            "temp_directory": "./temp",
            "update_frequency_days": 7,
            "force_update": False,
            "max_backups_to_keep": 5,
            "download_timeout_seconds": 300,
            "retry_attempts": 3,
            "retry_delay_seconds": 5
        }
    }
}


def setup_logging():
    """Configura logging para el script"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger('geolite2_manager')


def load_or_create_config(config_path: str = "geolite2_config.json"):
    """Carga o crea un archivo de configuración"""
    config_file = Path(config_path)

    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error cargando configuración: {e}")
            return DEFAULT_CONFIG
    else:
        # Crear configuración por defecto
        with open(config_file, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"✅ Configuración creada: {config_path}")
        return DEFAULT_CONFIG


def setup_license_key(config_path: str = "geolite2_config.json"):
    """Ayuda al usuario a configurar su license key"""
    print("\n🔑 Configuración de MaxMind License Key")
    print("=" * 50)
    print("1. Visita: https://www.maxmind.com/en/geolite2/signup")
    print("2. Crea una cuenta gratuita")
    print("3. Genera una license key")
    print("4. Copia la license key aquí:")

    license_key = input("\nLicense Key: ").strip()

    if not license_key:
        print("❌ License key vacía")
        return False

    # Cargar configuración
    config = load_or_create_config(config_path)

    # Actualizar license key
    config['geoip']['auto_update']['maxmind_license_key'] = license_key

    # Guardar configuración
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"✅ License key guardada en {config_path}")
        return True
    except Exception as e:
        print(f"❌ Error guardando configuración: {e}")
        return False


def check_database_status(updater, logger):
    """Verifica el estado de las bases de datos"""
    logger.info("📊 Estado de las bases de datos GeoLite2")
    logger.info("=" * 50)

    status = updater.get_database_status() if hasattr(updater, 'get_database_status') else {}

    if not status:
        # Status simplificado
        databases = ['GeoLite2-City']
        for db_name in databases:
            db_info = updater._get_database_info(db_name)
            if db_info:
                db_path = updater.database_dir / db_info['filename']
                exists = db_path.exists()

                logger.info(f"📁 {db_name}:")
                logger.info(f"   Archivo: {db_path}")
                logger.info(f"   Existe: {'✅ Sí' if exists else '❌ No'}")

                if exists:
                    size_mb = db_path.stat().st_size / (1024 * 1024)
                    logger.info(f"   Tamaño: {size_mb:.1f} MB")

                    # Verificar edad
                    if updater._should_update(db_path):
                        logger.info("   Estado: ⚠️  Actualización recomendada")
                    else:
                        logger.info("   Estado: ✅ Actualizada")
                else:
                    logger.info("   Estado: ❌ Requiere descarga")

                logger.info("")


def cleanup_temp_files(updater, logger):
    """Limpia archivos temporales"""
    logger.info("🧹 Limpiando archivos temporales...")

    try:
        # Limpiar directorio temporal
        temp_dir = updater.temp_dir
        if temp_dir.exists():
            for file in temp_dir.glob("*"):
                if file.is_file():
                    file.unlink()
                    logger.info(f"   🗑️  Eliminado: {file.name}")

        logger.info("✅ Limpieza completada")

    except Exception as e:
        logger.error(f"❌ Error durante limpieza: {e}")


def main():
    parser = argparse.ArgumentParser(description='Gestor de bases de datos GeoLite2')
    parser.add_argument('--config', default='geolite2_config.json',
                        help='Archivo de configuración (default: geolite2_config.json)')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true',
                       help='Verificar estado de las bases de datos')
    group.add_argument('--update', action='store_true',
                       help='Actualizar bases de datos si es necesario')
    group.add_argument('--force-update', action='store_true',
                       help='Forzar actualización de bases de datos')
    group.add_argument('--setup-license', action='store_true',
                       help='Configurar MaxMind license key')
    group.add_argument('--cleanup', action='store_true',
                       help='Limpiar archivos temporales')

    args = parser.parse_args()

    # Setup logging
    logger = setup_logging()

    if args.setup_license:
        setup_license_key(args.config)
        return

    # Cargar configuración
    config = load_or_create_config(args.config)

    # Verificar license key
    license_key = config.get('geoip', {}).get('auto_update', {}).get('maxmind_license_key')
    if not license_key or license_key == "YOUR_MAXMIND_LICENSE_KEY":
        logger.error("❌ License key no configurada")
        logger.info("💡 Ejecuta: python geolite2_manager.py --setup-license")
        sys.exit(1)

    # Importar y crear updater (requiere que el módulo esté disponible)
    try:
        # Aquí importarías la clase GeoLite2Updater del archivo principal
        # from geoip_enricher import GeoLite2Updater

        # Para este ejemplo, crearemos una versión simplificada
        sys.path.append('.')
        from geoip_enricher import GeoLite2Updater

        updater = GeoLite2Updater(config, logger)

    except ImportError as e:
        logger.error(f"❌ Error importando GeoLite2Updater: {e}")
        logger.error("💡 Asegúrate de que geoip_enricher.py esté en el directorio actual")
        sys.exit(1)

    # Ejecutar acción solicitada
    try:
        if args.check:
            check_database_status(updater, logger)

        elif args.update:
            logger.info("🔄 Verificando actualizaciones...")
            success = updater.update_database('GeoLite2-City')
            if success:
                logger.info("✅ Proceso completado")
            else:
                logger.error("❌ Error durante actualización")
                sys.exit(1)

        elif args.force_update:
            logger.info("🔄 Forzando actualización...")
            # Configurar force_update temporalmente
            original_force = config['geoip']['auto_update'].get('force_update', False)
            config['geoip']['auto_update']['force_update'] = True

            # Recrear updater con configuración modificada
            updater = GeoLite2Updater(config, logger)
            success = updater.update_database('GeoLite2-City')

            # Restaurar configuración
            config['geoip']['auto_update']['force_update'] = original_force

            if success:
                logger.info("✅ Actualización forzada completada")
            else:
                logger.error("❌ Error durante actualización forzada")
                sys.exit(1)

        elif args.cleanup:
            cleanup_temp_files(updater, logger)

    except KeyboardInterrupt:
        logger.info("\n🛑 Operación cancelada por el usuario")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Error inesperado: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()