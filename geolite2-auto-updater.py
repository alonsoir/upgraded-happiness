#!/usr/bin/env python3
"""
GeoLite2 Auto-Updater
Descarga y actualiza automáticamente las bases de datos GeoLite2 de MaxMind
"""

import os
import requests
import gzip
import tarfile
import hashlib
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from pathlib import Path
import shutil


class GeoLite2Updater:
    """
    Sistema de actualización automática para bases de datos GeoLite2
    """

    def __init__(self, config: Dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.update_config = config.get('geoip', {}).get('auto_update', {})

        # URLs y configuración de MaxMind
        self.base_url = "https://download.maxmind.com/app/geoip_download"
        self.default_license_key = "YOUR_MAXMIND_LICENSE_KEY"

        # Configuración local
        self.database_dir = Path(self.update_config.get('database_directory', '.'))
        self.backup_dir = Path(self.update_config.get('backup_directory', './backups'))
        self.temp_dir = Path(self.update_config.get('temp_directory', './temp'))

        # Configuraciones de descarga
        self.timeout = self.update_config.get('download_timeout_seconds', 300)
        self.retry_attempts = self.update_config.get('retry_attempts', 3)
        self.retry_delay = self.update_config.get('retry_delay_seconds', 5)

        # Crear directorios si no existen
        self.database_dir.mkdir(exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)
        self.temp_dir.mkdir(exist_ok=True)

    def _get_license_key(self) -> Optional[str]:
        """Obtiene la license key de MaxMind"""
        license_key = self.update_config.get('maxmind_license_key', self.default_license_key)

        if not license_key or license_key == self.default_license_key:
            self.logger.warning("⚠️  MaxMind license key NO configurada")
            self.logger.info("💡 Obtener license key gratuita en: https://www.maxmind.com/en/geolite2/signup")
            self.logger.info("💡 Configurar en: geoip.auto_update.maxmind_license_key")
            return None

        return license_key

    def _get_database_info(self, db_name: str) -> Dict:
        """Obtiene información sobre una base de datos"""
        return {
            'GeoLite2-City': {
                'filename': 'GeoLite2-City.mmdb',
                'edition_id': 'GeoLite2-City',
                'suffix': 'tar.gz'
            },
            'GeoLite2-Country': {
                'filename': 'GeoLite2-Country.mmdb',
                'edition_id': 'GeoLite2-Country',
                'suffix': 'tar.gz'
            },
            'GeoLite2-ASN': {
                'filename': 'GeoLite2-ASN.mmdb',
                'edition_id': 'GeoLite2-ASN',
                'suffix': 'tar.gz'
            }
        }.get(db_name, {})

    def _get_current_database_date(self, db_path: Path) -> Optional[datetime]:
        """Obtiene la fecha de la base de datos actual"""
        if not db_path.exists():
            return None

        try:
            # La fecha se puede obtener del timestamp del archivo
            timestamp = db_path.stat().st_mtime
            return datetime.fromtimestamp(timestamp)
        except Exception as e:
            self.logger.debug(f"Error obteniendo fecha de {db_path}: {e}")
            return None

    def _get_file_checksum(self, file_path: Path) -> str:
        """Calcula el SHA256 de un archivo"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculando checksum de {file_path}: {e}")
            return ""

    def _download_database(self, db_info: Dict, license_key: str) -> Optional[Path]:
        """Descarga una base de datos de MaxMind"""
        edition_id = db_info['edition_id']
        suffix = db_info['suffix']

        # Construir URL de descarga
        download_url = f"{self.base_url}?edition_id={edition_id}&license_key={license_key}&suffix={suffix}"

        # Archivo temporal
        temp_file = self.temp_dir / f"{edition_id}_{int(time.time())}.{suffix}"

        self.logger.info(f"📥 Descargando {edition_id}...")

        for attempt in range(self.retry_attempts):
            try:
                # Realizar descarga
                response = requests.get(download_url, timeout=self.timeout, stream=True)
                response.raise_for_status()

                # Verificar que es un archivo válido
                content_type = response.headers.get('content-type', '')
                if 'application/gzip' not in content_type and 'application/x-gzip' not in content_type:
                    self.logger.error(f"❌ Respuesta inválida de MaxMind: {content_type}")
                    if attempt == 0:  # Solo mostrar en el primer intento
                        self.logger.error("💡 Verificar license key o probar más tarde")
                    continue

                # Escribir archivo
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0

                with open(temp_file, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)

                            # Mostrar progreso cada 10MB
                            if total_size > 0 and downloaded % (10 * 1024 * 1024) == 0:
                                progress = (downloaded / total_size) * 100
                                self.logger.info(f"   📊 Progreso: {progress:.1f}%")

                self.logger.info(f"✅ Descarga completada: {downloaded / (1024 * 1024):.1f}MB")
                return temp_file

            except Exception as e:
                self.logger.warning(f"⚠️  Intento {attempt + 1} falló: {e}")
                if attempt < self.retry_attempts - 1:
                    self.logger.info(f"🔄 Reintentando en {self.retry_delay} segundos...")
                    time.sleep(self.retry_delay)
                else:
                    self.logger.error(f"❌ Descarga falló después de {self.retry_attempts} intentos")

        return None

    def _extract_database(self, archive_path: Path, db_info: Dict) -> Optional[Path]:
        """Extrae la base de datos del archivo tar.gz"""
        target_filename = db_info['filename']

        try:
            self.logger.info(f"📦 Extrayendo {target_filename}...")

            with tarfile.open(archive_path, 'r:gz') as tar:
                # Buscar el archivo .mmdb dentro del tar
                for member in tar.getmembers():
                    if member.name.endswith(target_filename):
                        # Extraer a directorio temporal
                        extracted_path = self.temp_dir / target_filename

                        with tar.extractfile(member) as source:
                            with open(extracted_path, 'wb') as target:
                                shutil.copyfileobj(source, target)

                        self.logger.info(f"✅ Extraído: {target_filename}")
                        return extracted_path

                self.logger.error(f"❌ No se encontró {target_filename} en el archivo")
                return None

        except Exception as e:
            self.logger.error(f"❌ Error extrayendo {archive_path}: {e}")
            return None

    def _backup_current_database(self, current_path: Path) -> bool:
        """Hace backup de la base de datos actual"""
        if not current_path.exists():
            return True

        try:
            # Crear nombre de backup con fecha
            current_date = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{current_path.stem}_{current_date}{current_path.suffix}"
            backup_path = self.backup_dir / backup_name

            self.logger.info(f"💾 Haciendo backup: {backup_name}")
            shutil.copy2(current_path, backup_path)

            # Limpiar backups antiguos si es necesario
            self._cleanup_old_backups(current_path.name)

            return True

        except Exception as e:
            self.logger.error(f"❌ Error haciendo backup: {e}")
            return False

    def _cleanup_old_backups(self, db_filename: str):
        """Limpia backups antiguos manteniendo solo los más recientes"""
        max_backups = self.update_config.get('max_backups_to_keep', 5)

        try:
            # Buscar todos los backups de esta base de datos
            pattern = f"{Path(db_filename).stem}_*{Path(db_filename).suffix}"
            backups = list(self.backup_dir.glob(pattern))

            # Ordenar por fecha de modificación (más recientes primero)
            backups.sort(key=lambda x: x.stat().st_mtime, reverse=True)

            # Eliminar backups excedentes
            for old_backup in backups[max_backups:]:
                self.logger.info(f"🗑️  Eliminando backup antiguo: {old_backup.name}")
                old_backup.unlink()

        except Exception as e:
            self.logger.warning(f"⚠️  Error limpiando backups: {e}")

    def _install_new_database(self, new_db_path: Path, target_path: Path) -> bool:
        """Instala la nueva base de datos"""
        try:
            self.logger.info(f"🔄 Instalando nueva base de datos...")

            # Verificar que el archivo es válido
            if new_db_path.stat().st_size < 1024:  # Muy pequeño
                self.logger.error("❌ Archivo descargado parece corrupto (muy pequeño)")
                return False

            # Mover la nueva base de datos
            shutil.move(str(new_db_path), str(target_path))

            self.logger.info(f"✅ Nueva base de datos instalada: {target_path.name}")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error instalando nueva base de datos: {e}")
            return False

    def _should_update(self, db_path: Path) -> bool:
        """Determina si se debe actualizar la base de datos"""
        if not db_path.exists():
            self.logger.info(f"📁 Base de datos {db_path.name} no existe - descarga necesaria")
            return True

        # Verificar antigüedad
        current_date = self._get_current_database_date(db_path)
        if not current_date:
            self.logger.warning(f"⚠️  No se pudo determinar fecha de {db_path.name}")
            return True

        # Configurar frecuencia de actualización
        update_frequency_days = self.update_config.get('update_frequency_days', 7)
        days_old = (datetime.now() - current_date).days

        if days_old >= update_frequency_days:
            self.logger.info(f"📅 Base de datos tiene {days_old} días - actualización recomendada")
            return True
        else:
            self.logger.info(f"📅 Base de datos tiene {days_old} días - actualización no necesaria")
            return False

    def update_database(self, db_name: str = 'GeoLite2-City') -> bool:
        """Actualiza una base de datos específica"""

        # Verificar si las actualizaciones están habilitadas
        if not self.update_config.get('enabled', False):
            self.logger.debug("🔕 Actualizaciones automáticas deshabilitadas")
            return False

        # Obtener información de la base de datos
        db_info = self._get_database_info(db_name)
        if not db_info:
            self.logger.error(f"❌ Base de datos desconocida: {db_name}")
            return False

        # Verificar license key
        license_key = self._get_license_key()
        if not license_key:
            return False

        # Rutas de archivos
        target_path = self.database_dir / db_info['filename']

        # Verificar si es necesario actualizar
        if not self.update_config.get('force_update', False):
            if not self._should_update(target_path):
                return True  # No es necesario actualizar, pero no es un error

        self.logger.info(f"🌍 Iniciando actualización de {db_name}...")

        try:
            # Descargar nueva versión
            archive_path = self._download_database(db_info, license_key)
            if not archive_path:
                return False

            # Extraer base de datos
            new_db_path = self._extract_database(archive_path, db_info)
            if not new_db_path:
                return False

            # Hacer backup de la versión actual
            if not self._backup_current_database(target_path):
                self.logger.warning("⚠️  Continuando sin backup...")

            # Instalar nueva versión
            success = self._install_new_database(new_db_path, target_path)

            # Limpiar archivos temporales
            try:
                archive_path.unlink()
                if new_db_path.exists():
                    new_db_path.unlink()
            except:
                pass

            if success:
                self.logger.info(f"🎉 {db_name} actualizada exitosamente!")
                return True
            else:
                return False

        except Exception as e:
            self.logger.error(f"❌ Error durante actualización: {e}")
            return False

    def update_all_databases(self) -> bool:
        """Actualiza todas las bases de datos configuradas"""
        databases = self.update_config.get('databases_to_update', ['GeoLite2-City'])
        success_count = 0

        for db_name in databases:
            if self.update_database(db_name):
                success_count += 1

        total = len(databases)
        self.logger.info(f"📊 Actualización completada: {success_count}/{total} bases de datos")

        return success_count == total

    def get_database_status(self) -> Dict:
        """Obtiene el estado de las bases de datos"""
        status = {}
        databases = self.update_config.get('databases_to_update', ['GeoLite2-City'])

        for db_name in databases:
            db_info = self._get_database_info(db_name)
            if db_info:
                db_path = self.database_dir / db_info['filename']
                current_date = self._get_current_database_date(db_path)

                status[db_name] = {
                    'exists': db_path.exists(),
                    'path': str(db_path),
                    'size_mb': db_path.stat().st_size / (1024 * 1024) if db_path.exists() else 0,
                    'last_modified': current_date.isoformat() if current_date else None,
                    'days_old': (datetime.now() - current_date).days if current_date else None,
                    'checksum': self._get_file_checksum(db_path) if db_path.exists() else None
                }

        return status


def integrate_auto_updater_with_enricher():
    """
    Función de ejemplo para integrar el auto-updater con el GeoIP Enricher
    """

    # Esta función se llamaría desde GeoIPEnricher.__init__()

    def __init__(self, config_file: str):
        # ... código existente ...

        # Inicializar auto-updater
        if config.get('geoip', {}).get('auto_update', {}).get('enabled', False):
            self.logger.info("🔄 Verificando actualizaciones de GeoLite2...")

            self.updater = GeoLite2Updater(self.config, self.logger)

            # Actualizar al inicio si es necesario
            if self.config.get('geoip', {}).get('auto_update', {}).get('check_on_startup', True):
                self.updater.update_all_databases()

            # Programar actualizaciones periódicas (opcional)
            if self.config.get('geoip', {}).get('auto_update', {}).get('periodic_updates', False):
                self._setup_periodic_updates()

        # ... resto del código ...