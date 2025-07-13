#!/usr/bin/env python3
"""
GeoIP Enricher con sistema de fallback multi-proveedor
Enriquece eventos de red con información geográfica usando múltiples fuentes
VERSIÓN SOLO PROTOBUF - SIN FALLBACK JSON
"""

import zmq
import json
import time
import logging
import threading
import sys
import os
import signal
import requests
import ipaddress
import gzip
import tarfile
import hashlib
import shutil
from typing import Dict, Optional, List, Any, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
import traceback

try:
    import geoip2.database
    import geoip2.errors

    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

try:
    # Agregar path de protobuf si es necesario
    sys.path.insert(0, 'src/protocols/protobuf')
    import network_event_extended_fixed_pb2

    PROTOBUF_AVAILABLE = True
except ImportError:
    PROTOBUF_AVAILABLE = False


class GeoLite2Updater:
    """Sistema de actualización automática para bases de datos GeoLite2"""

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

    def _should_update(self, db_path: Path) -> bool:
        """Determina si se debe actualizar la base de datos"""
        if not db_path.exists():
            self.logger.info(f"📁 Base de datos {db_path.name} no existe - descarga necesaria")
            return True

        # Verificar antigüedad
        try:
            timestamp = db_path.stat().st_mtime
            current_date = datetime.fromtimestamp(timestamp)
            update_frequency_days = self.update_config.get('update_frequency_days', 7)
            days_old = (datetime.now() - current_date).days

            if days_old >= update_frequency_days:
                self.logger.info(f"📅 Base de datos tiene {days_old} días - actualización recomendada")
                return True
            else:
                self.logger.info(f"📅 Base de datos actual ({days_old} días) - no requiere actualización")
                return False
        except Exception as e:
            self.logger.warning(f"⚠️  Error verificando fecha: {e}")
            return True

    def _download_and_extract(self, db_info: Dict, license_key: str) -> Optional[Path]:
        """Descarga y extrae una base de datos"""
        edition_id = db_info['edition_id']
        suffix = db_info['suffix']
        target_filename = db_info['filename']

        # Construir URL de descarga
        download_url = f"{self.base_url}?edition_id={edition_id}&license_key={license_key}&suffix={suffix}"

        # Archivo temporal
        temp_file = self.temp_dir / f"{edition_id}_{int(time.time())}.{suffix}"

        self.logger.info(f"📥 Descargando {edition_id}...")

        try:
            # Realizar descarga
            response = requests.get(download_url, timeout=self.timeout, stream=True)
            response.raise_for_status()

            # Verificar respuesta
            content_type = response.headers.get('content-type', '')
            if 'gzip' not in content_type:
                self.logger.error(f"❌ Respuesta inválida: {content_type}")
                self.logger.error("💡 Verificar license key")
                return None

            # Escribir archivo
            with open(temp_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            # Extraer
            self.logger.info(f"📦 Extrayendo {target_filename}...")
            with tarfile.open(temp_file, 'r:gz') as tar:
                for member in tar.getmembers():
                    if member.name.endswith(target_filename):
                        extracted_path = self.temp_dir / target_filename
                        with tar.extractfile(member) as source:
                            with open(extracted_path, 'wb') as target:
                                shutil.copyfileobj(source, target)

                        # Limpiar archivo temporal
                        temp_file.unlink()
                        return extracted_path

            self.logger.error(f"❌ No se encontró {target_filename}")
            return None

        except Exception as e:
            self.logger.error(f"❌ Error descargando: {e}")
            return None

    def update_database(self, db_name: str = 'GeoLite2-City') -> bool:
        """Actualiza una base de datos específica"""

        if not self.update_config.get('enabled', False):
            return False

        # Obtener información de la base de datos
        db_info = self._get_database_info(db_name)
        if not db_info:
            return False

        # Verificar license key
        license_key = self._get_license_key()
        if not license_key:
            return False

        # Rutas
        target_path = self.database_dir / db_info['filename']

        # Verificar si es necesario actualizar
        if not self.update_config.get('force_update', False):
            if not self._should_update(target_path):
                return True

        self.logger.info(f"🌍 Actualizando {db_name}...")

        try:
            # Descargar y extraer
            new_db_path = self._download_and_extract(db_info, license_key)
            if not new_db_path:
                return False

            # Hacer backup si existe versión anterior
            if target_path.exists():
                current_date = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"{target_path.stem}_{current_date}{target_path.suffix}"
                backup_path = self.backup_dir / backup_name

                self.logger.info(f"💾 Backup: {backup_name}")
                shutil.copy2(target_path, backup_path)

            # Instalar nueva versión
            shutil.move(str(new_db_path), str(target_path))

            self.logger.info(f"✅ {db_name} actualizada!")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error actualizando: {e}")
            return False


class RateLimiter:
    """Rate limiter thread-safe para APIs externas"""

    def __init__(self, requests_per_minute: int, burst_limit: int = None):
        self.requests_per_minute = requests_per_minute
        self.burst_limit = burst_limit or requests_per_minute
        self.requests = deque()
        self.lock = threading.Lock()

    def can_make_request(self) -> bool:
        """Verifica si se puede hacer una request"""
        now = time.time()

        with self.lock:
            # Limpiar requests antiguos (más de 1 minuto)
            while self.requests and self.requests[0] < now - 60:
                self.requests.popleft()

            # Verificar límites
            if len(self.requests) >= self.requests_per_minute:
                return False

            # Verificar burst limit (últimos 10 segundos)
            recent_requests = sum(1 for req_time in self.requests if req_time > now - 10)
            if recent_requests >= self.burst_limit:
                return False

            return True

    def record_request(self):
        """Registra una request realizada"""
        with self.lock:
            self.requests.append(time.time())


class GeoIPFallbackProvider:
    """Sistema de fallback para múltiples proveedores de GeoIP"""

    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.geoip_config = config.get('geoip', {})
        self.fallback_chain = self.geoip_config.get('fallback_chain', [])
        self.fallback_strategy = self.geoip_config.get('fallback_strategy', {})

        # Circuit breaker state por proveedor
        self.provider_failures = defaultdict(int)
        self.provider_last_failure = defaultdict(float)
        self.provider_locks = defaultdict(threading.Lock)
        self.provider_stats = defaultdict(lambda: {
            'requests': 0, 'successes': 0, 'failures': 0,
            'cache_hits': 0, 'response_times': []
        })

        # Cache por proveedor
        self.provider_caches = {}

        # Rate limiters por proveedor
        self.rate_limiters = {}

        # Base de datos local
        self.geoip_reader = None

        # Inicializar todo
        self._initialize_providers()
        self._validate_configuration()

    def _initialize_providers(self):
        """Inicializa los proveedores según configuración"""
        for provider_config in self.fallback_chain:
            provider_name = provider_config['provider']

            if not provider_config.get('enabled', False):
                self.logger.info(f"Proveedor {provider_name} está DESACTIVADO")
                continue

            # Inicializar cache
            cache_size = provider_config.get('config', {}).get('cache_size', 1000)
            self.provider_caches[provider_name] = {}

            # Inicializar rate limiter si es necesario
            config = provider_config.get('config', {})
            if 'rate_limit' in config:
                rate_config = config['rate_limit']
                self.rate_limiters[provider_name] = RateLimiter(
                    rate_config.get('requests_per_minute', 60),
                    rate_config.get('burst_limit', 15)
                )

            # Inicialización específica por proveedor
            if provider_name == 'local_db':
                self._initialize_local_db(provider_config)
            elif provider_name in ['ip_api', 'ipinfo', 'ipstack', 'ipgeolocation']:
                self._initialize_api_provider(provider_name, provider_config)

    def _initialize_local_db(self, provider_config):
        """Inicializa la base de datos local GeoIP2"""
        if not GEOIP2_AVAILABLE:
            self.logger.error("❌ GEOIP2 no disponible. Instalar: pip install geoip2")
            return

        try:
            db_path = provider_config['config']['database_path']
            if not os.path.exists(db_path):
                self.logger.error(f"❌ Base de datos GeoIP2 NO encontrada: {db_path}")
                self.logger.warning("💡 Descargar desde: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
                return

            self.geoip_reader = geoip2.database.Reader(db_path)
            self.logger.info(f"✅ Base de datos GeoIP2 cargada: {db_path}")

        except Exception as e:
            self.logger.error(f"❌ Error cargando base de datos GeoIP2: {e}")
            self.geoip_reader = None

    def _initialize_api_provider(self, provider_name: str, provider_config: Dict):
        """Inicializa un proveedor de API externa"""
        config = provider_config.get('config', {})

        # Verificaciones específicas por proveedor
        if provider_name == 'ip_api':
            # ip-api.com no requiere token, pero tiene rate limits estrictos
            rate_limit = config.get('rate_limit', {}).get('requests_per_minute', 45)
            if rate_limit > 45:
                self.logger.warning(
                    f"⚠️  ip-api.com: Rate limit {rate_limit}/min puede causar bloqueos (máximo sin token: 45/min)")
            self.logger.info(f"✅ ip-api.com configurado (rate limit: {rate_limit}/min)")

        elif provider_name == 'ipinfo':
            token = config.get('api_token', '')
            if not token or token == 'YOUR_API_TOKEN_HERE':
                self.logger.warning("⚠️  ipinfo.io: Token NO configurado - limitado a 1000 req/día")
                self.logger.info("💡 Obtener token gratuito en: https://ipinfo.io/signup")
            else:
                # Verificar token
                if self._test_ipinfo_token(token):
                    self.logger.info("✅ ipinfo.io configurado con token válido")
                else:
                    self.logger.error("❌ ipinfo.io: Token INVÁLIDO")

        elif provider_name == 'ipstack':
            api_key = config.get('api_key', '')
            if not api_key or api_key == 'YOUR_API_KEY_HERE':
                self.logger.error("❌ ipstack: API key NO configurada - proveedor NO funcional")
                self.logger.info("💡 Obtener API key en: https://ipstack.com/signup")
            else:
                # Verificar API key
                if self._test_ipstack_key(api_key):
                    self.logger.info("✅ ipstack configurado con API key válida")
                else:
                    self.logger.error("❌ ipstack: API key INVÁLIDA")

        elif provider_name == 'ipgeolocation':
            api_key = config.get('api_key', '')
            if not api_key or api_key == 'YOUR_API_KEY_HERE':
                self.logger.error("❌ ipgeolocation.io: API key NO configurada - proveedor NO funcional")
                self.logger.info("💡 Obtener API key en: https://ipgeolocation.io/signup.html")
            else:
                # Verificar API key
                if self._test_ipgeolocation_key(api_key):
                    self.logger.info("✅ ipgeolocation.io configurado con API key válida")
                else:
                    self.logger.error("❌ ipgeolocation.io: API key INVÁLIDA")

    def _test_ipinfo_token(self, token: str) -> bool:
        """Verifica si el token de ipinfo.io es válido"""
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get('https://ipinfo.io/8.8.8.8/json',
                                    headers=headers, timeout=5)
            return response.status_code == 200
        except:
            return False

    def _test_ipstack_key(self, api_key: str) -> bool:
        """Verifica si la API key de ipstack es válida"""
        try:
            response = requests.get(f'http://api.ipstack.com/8.8.8.8?access_key={api_key}',
                                    timeout=5)
            data = response.json()
            return 'error' not in data
        except:
            return False

    def _test_ipgeolocation_key(self, api_key: str) -> bool:
        """Verifica si la API key de ipgeolocation.io es válida"""
        try:
            response = requests.get(f'https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip=8.8.8.8',
                                    timeout=5)
            data = response.json()
            return 'message' not in data  # Si hay error, viene en 'message'
        except:
            return False

    def _validate_configuration(self):
        """Valida la configuración general"""
        enabled_providers = [p for p in self.fallback_chain if p.get('enabled', False)]

        if not enabled_providers:
            self.logger.error("❌ NO hay proveedores activados - GeoIP NO funcional")
            return

        self.logger.info(f"✅ {len(enabled_providers)} proveedores GeoIP configurados:")
        for provider in enabled_providers:
            priority = provider.get('priority', 999)
            name = provider['provider']
            self.logger.info(f"   {priority}. {name}")

    def _is_provider_available(self, provider_name: str) -> bool:
        """Verifica si un proveedor está disponible (circuit breaker)"""
        max_failures = self.fallback_strategy.get('max_failures_before_skip', 3)
        reset_time_minutes = self.fallback_strategy.get('failure_reset_time_minutes', 10)

        with self.provider_locks[provider_name]:
            failures = self.provider_failures[provider_name]
            last_failure = self.provider_last_failure[provider_name]

            if failures >= max_failures:
                if time.time() - last_failure > (reset_time_minutes * 60):
                    self.provider_failures[provider_name] = 0
                    self.logger.info(f"🔄 Circuit breaker reset para {provider_name}")
                    return True
                return False

            return True

    def _record_provider_failure(self, provider_name: str):
        """Registra un fallo del proveedor"""
        with self.provider_locks[provider_name]:
            self.provider_failures[provider_name] += 1
            self.provider_last_failure[provider_name] = time.time()
            self.provider_stats[provider_name]['failures'] += 1

            failures = self.provider_failures[provider_name]
            max_failures = self.fallback_strategy.get('max_failures_before_skip', 3)

            if failures >= max_failures:
                self.logger.warning(f"🚨 Circuit breaker activado para {provider_name} ({failures} fallos)")
            else:
                self.logger.debug(f"⚠️  Fallo en {provider_name} ({failures}/{max_failures})")

    def _record_provider_success(self, provider_name: str, response_time: float):
        """Registra un éxito del proveedor"""
        with self.provider_locks[provider_name]:
            self.provider_failures[provider_name] = 0
            self.provider_stats[provider_name]['successes'] += 1
            self.provider_stats[provider_name]['response_times'].append(response_time)

            # Limitar historial de tiempos de respuesta
            if len(self.provider_stats[provider_name]['response_times']) > 100:
                self.provider_stats[provider_name]['response_times'].pop(0)

    def _get_from_cache(self, provider_name: str, ip: str) -> Optional[Dict]:
        """Obtiene datos del cache del proveedor"""
        cache = self.provider_caches.get(provider_name, {})
        cached_data = cache.get(ip)

        if cached_data:
            cache_ttl = self._get_provider_cache_ttl(provider_name)

            if time.time() - cached_data['timestamp'] < cache_ttl:
                self.provider_stats[provider_name]['cache_hits'] += 1
                return cached_data['data']
            else:
                del cache[ip]

        return None

    def _get_provider_cache_ttl(self, provider_name: str) -> int:
        """Obtiene el TTL del cache para un proveedor"""
        for provider_config in self.fallback_chain:
            if provider_config['provider'] == provider_name:
                return provider_config.get('config', {}).get('cache_ttl_seconds', 3600)
        return 3600

    def _save_to_cache(self, provider_name: str, ip: str, data: Dict):
        """Guarda datos en el cache del proveedor"""
        cache = self.provider_caches.get(provider_name, {})
        cache[ip] = {
            'data': data,
            'timestamp': time.time()
        }

        # Limitar tamaño del cache
        max_cache_size = self._get_provider_cache_size(provider_name)

        if len(cache) > max_cache_size:
            oldest_key = min(cache.keys(), key=lambda k: cache[k]['timestamp'])
            del cache[oldest_key]

    def _get_provider_cache_size(self, provider_name: str) -> int:
        """Obtiene el tamaño máximo del cache para un proveedor"""
        for provider_config in self.fallback_chain:
            if provider_config['provider'] == provider_name:
                return provider_config.get('config', {}).get('cache_size', 1000)
        return 1000

    def _query_local_db(self, ip: str) -> Optional[Dict]:
        """Consulta la base de datos local"""
        if not self.geoip_reader:
            return None

        try:
            response = self.geoip_reader.city(ip)
            return {
                'country': response.country.iso_code,
                'region': response.subdivisions.most_specific.name,
                'city': response.city.name,
                'lat': float(response.location.latitude) if response.location.latitude else None,
                'lon': float(response.location.longitude) if response.location.longitude else None,
                'provider': 'local_db',
                'accuracy_radius': response.location.accuracy_radius
            }
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as e:
            self.logger.debug(f"Error en consulta local para {ip}: {e}")
            return None

    def _query_ip_api(self, ip: str, provider_config: Dict) -> Optional[Dict]:
        """Consulta la API de ip-api.com"""
        config = provider_config['config']

        # Verificar rate limit
        provider_name = 'ip_api'
        if provider_name in self.rate_limiters:
            if not self.rate_limiters[provider_name].can_make_request():
                self.logger.debug(f"Rate limit alcanzado para {provider_name}")
                return None

        try:
            timeout = config.get('timeout_seconds', 5.0)
            base_url = config['base_url']

            url = f"{base_url}/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,query"
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()

            # Registrar request
            if provider_name in self.rate_limiters:
                self.rate_limiters[provider_name].record_request()

            data = response.json()

            if data.get('status') == 'success':
                return {
                    'country': data.get('countryCode'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'provider': 'ip_api'
                }
            else:
                error_msg = data.get('message', 'Unknown error')
                self.logger.warning(f"ip-api.com error para {ip}: {error_msg}")
                return None

        except Exception as e:
            self.logger.debug(f"Error consultando ip-api.com para {ip}: {e}")
            return None

    def _query_ipinfo(self, ip: str, provider_config: Dict) -> Optional[Dict]:
        """Consulta la API de ipinfo.io"""
        config = provider_config['config']

        # Verificar rate limit
        provider_name = 'ipinfo'
        if provider_name in self.rate_limiters:
            if not self.rate_limiters[provider_name].can_make_request():
                self.logger.debug(f"Rate limit alcanzado para {provider_name}")
                return None

        try:
            timeout = config.get('timeout_seconds', 5.0)
            base_url = config['base_url']
            token = config.get('api_token')

            url = f"{base_url}/{ip}/json"
            headers = {}
            if token and token != 'YOUR_API_TOKEN_HERE':
                headers['Authorization'] = f'Bearer {token}'

            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()

            # Registrar request
            if provider_name in self.rate_limiters:
                self.rate_limiters[provider_name].record_request()

            data = response.json()

            # Verificar errores
            if 'error' in data:
                self.logger.warning(f"ipinfo.io error para {ip}: {data['error']}")
                return None

            # Parsear la localización "lat,lon"
            loc = data.get('loc', '').split(',')
            lat = float(loc[0]) if len(loc) > 0 and loc[0] else None
            lon = float(loc[1]) if len(loc) > 1 and loc[1] else None

            return {
                'country': data.get('country'),
                'region': data.get('region'),
                'city': data.get('city'),
                'lat': lat,
                'lon': lon,
                'provider': 'ipinfo'
            }

        except Exception as e:
            self.logger.debug(f"Error consultando ipinfo.io para {ip}: {e}")
            return None

    def _query_ipstack(self, ip: str, provider_config: Dict) -> Optional[Dict]:
        """Consulta la API de ipstack"""
        config = provider_config['config']

        # Verificar rate limit
        provider_name = 'ipstack'
        if provider_name in self.rate_limiters:
            if not self.rate_limiters[provider_name].can_make_request():
                self.logger.debug(f"Rate limit alcanzado para {provider_name}")
                return None

        try:
            timeout = config.get('timeout_seconds', 5.0)
            base_url = config['base_url']
            api_key = config.get('api_key')

            if not api_key or api_key == 'YOUR_API_KEY_HERE':
                return None

            url = f"{base_url}/{ip}?access_key={api_key}"
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()

            # Registrar request
            if provider_name in self.rate_limiters:
                self.rate_limiters[provider_name].record_request()

            data = response.json()

            # Verificar errores
            if 'error' in data:
                error_info = data['error']
                self.logger.warning(f"ipstack error para {ip}: {error_info.get('info', 'Unknown error')}")
                return None

            return {
                'country': data.get('country_code'),
                'region': data.get('region_name'),
                'city': data.get('city'),
                'lat': data.get('latitude'),
                'lon': data.get('longitude'),
                'provider': 'ipstack'
            }

        except Exception as e:
            self.logger.debug(f"Error consultando ipstack para {ip}: {e}")
            return None

    def _query_ipgeolocation(self, ip: str, provider_config: Dict) -> Optional[Dict]:
        """Consulta la API de ipgeolocation.io"""
        config = provider_config['config']

        # Verificar rate limit
        provider_name = 'ipgeolocation'
        if provider_name in self.rate_limiters:
            if not self.rate_limiters[provider_name].can_make_request():
                self.logger.debug(f"Rate limit alcanzado para {provider_name}")
                return None

        try:
            timeout = config.get('timeout_seconds', 5.0)
            base_url = config['base_url']
            api_key = config.get('api_key')

            if not api_key or api_key == 'YOUR_API_KEY_HERE':
                return None

            url = f"{base_url}?apiKey={api_key}&ip={ip}"
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()

            # Registrar request
            if provider_name in self.rate_limiters:
                self.rate_limiters[provider_name].record_request()

            data = response.json()

            # Verificar errores
            if 'message' in data:
                self.logger.warning(f"ipgeolocation.io error para {ip}: {data['message']}")
                return None

            return {
                'country': data.get('country_code2'),
                'region': data.get('state_prov'),
                'city': data.get('city'),
                'lat': float(data.get('latitude')) if data.get('latitude') else None,
                'lon': float(data.get('longitude')) if data.get('longitude') else None,
                'provider': 'ipgeolocation'
            }

        except Exception as e:
            self.logger.debug(f"Error consultando ipgeolocation.io para {ip}: {e}")
            return None

    def get_geoip_data(self, ip: str) -> Optional[Dict]:
        """Obtiene datos GeoIP usando la cadena de fallback"""

        # Estadísticas generales
        for provider_name in self.provider_stats:
            self.provider_stats[provider_name]['requests'] += 1

        # Verificar redes privadas primero
        private_mapping = self.geoip_config.get('private_network_mapping', {})
        for network, data in private_mapping.items():
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(network):
                    result = data.copy()
                    result['provider'] = 'private_network'
                    return result
            except:
                continue

        # Probar proveedores en orden de prioridad
        sorted_providers = sorted(
            [p for p in self.fallback_chain if p.get('enabled', False)],
            key=lambda x: x.get('priority', 999)
        )

        for provider_config in sorted_providers:
            provider_name = provider_config['provider']

            # Verificar circuit breaker
            if not self._is_provider_available(provider_name):
                continue

            # Verificar cache
            cached_data = self._get_from_cache(provider_name, ip)
            if cached_data:
                return cached_data

            # Consultar proveedor
            try:
                start_time = time.time()

                if provider_name == 'local_db':
                    data = self._query_local_db(ip)
                elif provider_name == 'ip_api':
                    data = self._query_ip_api(ip, provider_config)
                elif provider_name == 'ipinfo':
                    data = self._query_ipinfo(ip, provider_config)
                elif provider_name == 'ipstack':
                    data = self._query_ipstack(ip, provider_config)
                elif provider_name == 'ipgeolocation':
                    data = self._query_ipgeolocation(ip, provider_config)
                else:
                    self.logger.warning(f"Proveedor desconocido: {provider_name}")
                    continue

                response_time = time.time() - start_time

                if data:
                    self._record_provider_success(provider_name, response_time)
                    self._save_to_cache(provider_name, ip, data)
                    return data

            except Exception as e:
                self.logger.debug(f"Error en {provider_name} para {ip}: {e}")
                self._record_provider_failure(provider_name)

        return None

    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas de los proveedores"""
        stats = {}
        for provider_name, provider_stats in self.provider_stats.items():
            response_times = provider_stats['response_times']
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0

            stats[provider_name] = {
                'requests': provider_stats['requests'],
                'successes': provider_stats['successes'],
                'failures': provider_stats['failures'],
                'cache_hits': provider_stats['cache_hits'],
                'success_rate': provider_stats['successes'] / max(provider_stats['requests'], 1) * 100,
                'avg_response_time_ms': avg_response_time * 1000,
                'circuit_breaker_failures': self.provider_failures[provider_name],
                'cache_size': len(self.provider_caches.get(provider_name, {}))
            }

        return stats


class GeoIPEnricher:
    """Enriquecedor GeoIP principal - SOLO PROTOBUF"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.running = False
        self.config = self._load_config()

        # Setup logging PRIMERO
        self._setup_logging()

        # 🔍 VALIDACIÓN PROTOBUF CRÍTICA AL INICIO
        if not self._validate_protobuf_environment():
            self.logger.error("❌ ENTORNO PROTOBUF INVÁLIDO - DETENIENDO")
            sys.exit(1)

        # Auto-updater para GeoLite2 (después de logging)
        self.updater = None
        if self.config.get('geoip', {}).get('auto_update', {}).get('enabled', False):
            self.logger.info("🔄 Iniciando sistema de auto-actualización GeoLite2...")
            self.updater = GeoLite2Updater(self.config, self.logger)

            # Verificar actualizaciones al inicio
            if self.config.get('geoip', {}).get('auto_update', {}).get('check_on_startup', True):
                self.updater.update_database('GeoLite2-City')

        # ZMQ setup
        self.context = zmq.Context()
        self.input_socket = None
        self.output_socket = None

        # GeoIP provider (después del updater)
        self.geoip_provider = GeoIPFallbackProvider(self.config, self.logger)

        # Estadísticas
        self.stats = {
            'events_processed': 0,
            'events_enriched': 0,
            'protobuf_errors': 0,
            'start_time': time.time(),
            'last_event_time': None
        }

        # Threading
        self.stats_thread = None

        self.logger.info(f"🌍 GeoIP Enricher iniciado (v{self.config['agent_info']['version']})")

    def _validate_protobuf_environment(self):
        """Valida que el entorno protobuf esté correcto"""
        self.logger.info("🔍 Validando entorno protobuf...")

        if not PROTOBUF_AVAILABLE:
            self.logger.error("❌ Módulo protobuf NO disponible")
            self.logger.error("💡 Instalar con: pip install protobuf")
            return False

        try:
            # Verificar versión protobuf
            import google.protobuf
            pb_version = google.protobuf.__version__
            self.logger.info(f"📦 Versión protobuf: {pb_version}")

            # Verificar que network_event_extended_fixed_pb2 se puede importar
            import network_event_extended_fixed_pb2
            self.logger.info("✅ network_event_extended_fixed_pb2 importado correctamente")

            # Crear evento de prueba
            test_event = network_event_extended_fixed_pb2.NetworkEvent()
            test_event.event_id = "test_validation"
            test_event.timestamp = int(time.time())

            # Serializar y deserializar
            data = test_event.SerializeToString()
            parsed_event = network_event_extended_fixed_pb2.NetworkEvent()
            parsed_event.ParseFromString(data)

            self.logger.info(f"✅ Test protobuf OK: {len(data)} bytes")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error validando protobuf: {e}")
            import traceback
            self.logger.error(f"❌ Stack trace:\n{traceback.format_exc()}")
            return False

    def _load_config(self) -> Dict[str, Any]:
        """Carga la configuración desde archivo JSON"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error cargando configuración: {e}")
            sys.exit(1)

    def _setup_logging(self):
        """Configura el sistema de logging"""
        log_config = self.config.get('logging', {})

        # Crear directorio de logs si no existe
        log_file = log_config.get('file', 'logs/geoip_enricher.log')
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        # Configurar logger
        logging.basicConfig(
            level=getattr(logging, log_config.get('level', 'INFO')),
            format=log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler() if log_config.get('console_output', True) else logging.NullHandler()
            ]
        )

        self.logger = logging.getLogger('geoip_enricher')

    def _setup_zmq(self):
        """Configura los sockets ZMQ"""
        network_config = self.config['network']

        # Socket de entrada (PULL) - CONECTAR al Promiscuous Agent
        self.input_socket = self.context.socket(zmq.PULL)
        input_address = f"tcp://localhost:{network_config['input_port']}"
        self.input_socket.connect(input_address)
        self.logger.info(f"📥 Conectando a eventos desde {input_address}")

        # Socket de salida (PUSH) - SERVIR al ML Detector
        self.output_socket = self.context.socket(zmq.PUSH)
        output_address = f"tcp://{network_config['bind_address']}:{network_config['output_port']}"
        self.output_socket.bind(output_address)
        self.logger.info(f"📤 Enviando eventos enriquecidos a {output_address}")

        # Configurar timeouts y opciones
        timeout = network_config.get('socket_timeout', 3000)
        self.input_socket.setsockopt(zmq.RCVTIMEO, timeout)
        self.output_socket.setsockopt(zmq.SNDTIMEO, timeout)

        hwm = network_config.get('high_water_mark', 1000)
        self.input_socket.setsockopt(zmq.RCVHWM, hwm)
        self.output_socket.setsockopt(zmq.SNDHWM, hwm)

    def _parse_event(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parsea un evento desde bytes - SOLO PROTOBUF"""

        # ✅ Verificación inicial
        if not PROTOBUF_AVAILABLE:
            self.logger.error("❌ PROTOBUF NO DISPONIBLE - GeoIP no puede funcionar")
            return None

        if not self.config.get('protobuf', {}).get('enabled', True):
            self.logger.error("❌ PROTOBUF DESACTIVADO EN CONFIG - Pipeline requiere protobuf")
            return None

        # 🔍 Debug detallado
        self.logger.debug(f"📦 Datos recibidos: {len(data)} bytes")
        if len(data) > 0:
            self.logger.debug(f"📦 Primeros 20 bytes: {data[:20].hex()}")
        else:
            self.logger.error("❌ Datos vacíos recibidos")
            return None

        try:
            # 🚨 SOLO PROTOBUF - SIN FALLBACK
            event = network_event_extended_fixed_pb2.NetworkEvent()
            event.ParseFromString(data)

            self.logger.debug(f"✅ Protobuf parseado correctamente: event_id={getattr(event, 'event_id', 'N/A')}")
            return self._protobuf_to_dict(event)

        except Exception as e:
            # 🔍 ERROR DETALLADO
            self.logger.error(f"❌ ERROR PARSING PROTOBUF: {type(e).__name__}: {e}")
            self.logger.error(f"❌ Datos problemáticos: {len(data)} bytes")
            self.logger.error(f"❌ Hex dump (primeros 50 bytes): {data[:50].hex()}")

            # Verificar si los datos parecen ser otra cosa
            try:
                text = data.decode('utf-8', errors='ignore')[:100]
                if text.isprintable():
                    self.logger.error(f"❌ Los datos parecen ser texto: '{text}...'")
            except:
                pass

            # Información adicional de debug
            import traceback
            self.logger.error(f"❌ Stack trace completo:\n{traceback.format_exc()}")

            return None

    def _protobuf_to_dict(self, event) -> Dict[str, Any]:
        """Convierte evento protobuf a diccionario según network_event_extended_fixed.proto"""
        return {
            'event_id': event.event_id,
            'timestamp': event.timestamp,
            'src_ip': event.source_ip,  # Mapeo: source_ip -> src_ip
            'dst_ip': event.target_ip,  # Mapeo: target_ip -> dst_ip
            'packet_size': event.packet_size,
            'dst_port': event.dest_port,  # Mapeo: dest_port -> dst_port
            'src_port': event.src_port,
            'agent_id': event.agent_id,
            'anomaly_score': event.anomaly_score,
            'latitude': event.latitude,
            'longitude': event.longitude,
            'event_type': event.event_type,
            'risk_score': event.risk_score,
            'description': event.description,
            'so_identifier': event.so_identifier,
            'node_hostname': event.node_hostname,
            'os_version': event.os_version,
            'firewall_status': event.firewall_status,
            'agent_version': event.agent_version,
            'is_initial_handshake': event.is_initial_handshake
        }

    def _enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enriquece un evento con datos geográficos"""
        enriched = event.copy()

        # Enriquecer IP origen
        src_ip = event.get('src_ip')
        if src_ip:
            src_geo = self.geoip_provider.get_geoip_data(src_ip)
            if src_geo:
                enriched['src_geo'] = src_geo
                enriched['src_geoip_provider'] = src_geo.get('provider', 'unknown')

                # 🌍 POBLAMOS LOS CAMPOS PRINCIPALES DEL PROTOBUF
                # Priorizar IP origen para las coordenadas principales
                if src_geo.get('lat') is not None and src_geo.get('lon') is not None:
                    enriched['latitude'] = src_geo['lat']
                    enriched['longitude'] = src_geo['lon']

        # Enriquecer IP destino
        dst_ip = event.get('dst_ip')
        if dst_ip:
            dst_geo = self.geoip_provider.get_geoip_data(dst_ip)
            if dst_geo:
                enriched['dst_geo'] = dst_geo
                enriched['dst_geoip_provider'] = dst_geo.get('provider', 'unknown')

                # Si no hay coordenadas del origen, usar las del destino
                if 'latitude' not in enriched and dst_geo.get('lat') is not None:
                    if dst_geo.get('lon') is not None:
                        enriched['latitude'] = dst_geo['lat']
                        enriched['longitude'] = dst_geo['lon']

        # Marcar como enriquecido
        enriched['geoip_enriched'] = True
        enriched['geoip_enriched_at'] = time.time()

        # Actualizar descripción si no existe
        if 'description' not in enriched or not enriched['description']:
            geo_info = []
            if 'src_geo' in enriched:
                src_location = f"{enriched['src_geo'].get('city', 'Unknown')}, {enriched['src_geo'].get('country', 'XX')}"
                geo_info.append(f"Src: {src_location}")
            if 'dst_geo' in enriched:
                dst_location = f"{enriched['dst_geo'].get('city', 'Unknown')}, {enriched['dst_geo'].get('country', 'XX')}"
                geo_info.append(f"Dst: {dst_location}")

            if geo_info:
                enriched['description'] = f"GeoIP: {' | '.join(geo_info)}"

        return enriched

    def _dict_to_protobuf(self, event_dict: Dict[str, Any]):
        """Convierte diccionario enriquecido a protobuf según network_event_extended_fixed.proto"""
        event = network_event_extended_fixed_pb2.NetworkEvent()

        # Campos básicos del evento original
        if 'event_id' in event_dict:
            event.event_id = str(event_dict['event_id'])
        if 'timestamp' in event_dict:
            event.timestamp = int(event_dict['timestamp'])
        if 'src_ip' in event_dict:
            event.source_ip = str(event_dict['src_ip'])  # Mapeo: src_ip -> source_ip
        if 'dst_ip' in event_dict:
            event.target_ip = str(event_dict['dst_ip'])  # Mapeo: dst_ip -> target_ip
        if 'packet_size' in event_dict:
            event.packet_size = int(event_dict['packet_size'])
        if 'dst_port' in event_dict:
            event.dest_port = int(event_dict['dst_port'])  # Mapeo: dst_port -> dest_port
        if 'src_port' in event_dict:
            event.src_port = int(event_dict['src_port'])
        if 'agent_id' in event_dict:
            event.agent_id = str(event_dict['agent_id'])
        if 'event_type' in event_dict:
            event.event_type = str(event_dict['event_type'])
        if 'description' in event_dict:
            event.description = str(event_dict['description'])

        # Campos de sistema (si existen)
        if 'so_identifier' in event_dict:
            event.so_identifier = str(event_dict['so_identifier'])
        if 'node_hostname' in event_dict:
            event.node_hostname = str(event_dict['node_hostname'])
        if 'os_version' in event_dict:
            event.os_version = str(event_dict['os_version'])
        if 'firewall_status' in event_dict:
            event.firewall_status = str(event_dict['firewall_status'])
        if 'agent_version' in event_dict:
            event.agent_version = str(event_dict['agent_version'])
        if 'is_initial_handshake' in event_dict:
            event.is_initial_handshake = bool(event_dict['is_initial_handshake'])

        # Campos ML (preservar si ya existen)
        if 'anomaly_score' in event_dict:
            event.anomaly_score = float(event_dict['anomaly_score'])
        if 'risk_score' in event_dict:
            event.risk_score = float(event_dict['risk_score'])

        # 🌍 CAMPOS GEO - ENRIQUECIDOS POR ESTE COMPONENTE
        # Priorizar datos de src_geo y dst_geo si existen
        src_geo = event_dict.get('src_geo', {})
        dst_geo = event_dict.get('dst_geo', {})

        # Usar coordenadas del IP origen preferentemente
        if src_geo.get('lat') is not None and src_geo.get('lon') is not None:
            event.latitude = float(src_geo['lat'])
            event.longitude = float(src_geo['lon'])
        elif dst_geo.get('lat') is not None and dst_geo.get('lon') is not None:
            event.latitude = float(dst_geo['lat'])
            event.longitude = float(dst_geo['lon'])
        # Preservar coordenadas existentes si no hay datos geo nuevos
        elif 'latitude' in event_dict and 'longitude' in event_dict:
            if event_dict['latitude'] is not None and event_dict['longitude'] is not None:
                event.latitude = float(event_dict['latitude'])
                event.longitude = float(event_dict['longitude'])

        return event

    def _send_event(self, event: Dict[str, Any]):
        """Envía un evento enriquecido - SOLO PROTOBUF"""
        try:
            # ✅ SOLO PROTOBUF - Sin fallback JSON
            if not PROTOBUF_AVAILABLE:
                self.logger.error("❌ No se puede enviar - PROTOBUF no disponible")
                return

            # Convertir a protobuf
            protobuf_event = self._dict_to_protobuf(event)
            data = protobuf_event.SerializeToString()

            self.logger.debug(f"📤 Enviando evento protobuf: {len(data)} bytes")
            self.output_socket.send(data, zmq.NOBLOCK)

        except Exception as e:
            self.logger.error(f"❌ Error enviando evento protobuf: {e}")
            import traceback
            self.logger.error(f"❌ Stack trace:\n{traceback.format_exc()}")

    def _stats_worker(self):
        """Worker thread para estadísticas periódicas"""
        interval = self.config.get('processing', {}).get('stats_interval_seconds', 60)

        while self.running:
            try:
                time.sleep(interval)
                if self.running:
                    self._log_stats()
            except Exception as e:
                self.logger.error(f"Error en stats worker: {e}")

    def _log_stats(self):
        """Registra estadísticas del servicio"""
        uptime = time.time() - self.stats['start_time']
        events_per_sec = self.stats['events_processed'] / max(uptime, 1)
        enrichment_rate = (self.stats['events_enriched'] / max(self.stats['events_processed'], 1)) * 100
        error_rate = (self.stats['protobuf_errors'] / max(self.stats['events_processed'], 1)) * 100

        self.logger.info(f"📊 Stats: {self.stats['events_processed']} eventos, "
                         f"{events_per_sec:.2f} evt/s, {enrichment_rate:.1f}% enriquecidos")

        if self.stats['protobuf_errors'] > 0:
            self.logger.warning(f"🚨 Errores protobuf: {self.stats['protobuf_errors']} ({error_rate:.1f}%)")

        # Estadísticas de proveedores GeoIP
        provider_stats = self.geoip_provider.get_stats()
        for provider, stats in provider_stats.items():
            if stats['requests'] > 0:
                self.logger.info(f"   🌍 {provider}: {stats['successes']}/{stats['requests']} "
                                 f"({stats['success_rate']:.1f}%), cache: {stats['cache_hits']}, "
                                 f"avg: {stats['avg_response_time_ms']:.1f}ms")

    def run(self):
        """Ejecuta el bucle principal del enriquecedor"""
        try:
            self._setup_zmq()
            self.running = True

            # Iniciar thread de estadísticas
            self.stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
            self.stats_thread.start()

            self.logger.info("🚀 GeoIP Enricher corriendo...")

            while self.running:
                try:
                    # Recibir evento
                    data = self.input_socket.recv()
                    self.stats['events_processed'] += 1
                    self.stats['last_event_time'] = time.time()

                    # Parsear evento
                    event = self._parse_event(data)
                    if not event:
                        self.stats['protobuf_errors'] += 1
                        continue

                    # Enriquecer evento
                    enriched_event = self._enrich_event(event)

                    # Verificar si se enriqueció
                    if enriched_event.get('geoip_enriched', False):
                        self.stats['events_enriched'] += 1

                    # Enviar evento enriquecido
                    self._send_event(enriched_event)

                except zmq.Again:
                    # Timeout - continuar
                    continue
                except Exception as e:
                    self.logger.error(f"Error procesando evento: {e}")

        except KeyboardInterrupt:
            self.logger.info("🛑 Deteniendo GeoIP Enricher...")
        except Exception as e:
            self.logger.error(f"Error fatal: {e}")
            self.logger.error(traceback.format_exc())
        finally:
            self._cleanup()

    def _cleanup(self):
        """Limpia recursos"""
        self.running = False

        if self.input_socket:
            self.input_socket.close()
        if self.output_socket:
            self.output_socket.close()
        if self.context:
            self.context.term()

        # Cerrar base de datos GeoIP si está abierta
        if hasattr(self.geoip_provider, 'geoip_reader') and self.geoip_provider.geoip_reader:
            self.geoip_provider.geoip_reader.close()

        self.logger.info("✅ GeoIP Enricher detenido correctamente")


def signal_handler(signum, frame):
    """Manejador de señales para shutdown graceful"""
    print(f"\n🛑 Señal {signum} recibida, deteniendo...")
    global enricher
    if enricher:
        enricher.running = False


def main():
    if len(sys.argv) != 2:
        print("Uso: python geoip_enricher.py <config.json>")
        sys.exit(1)

    config_file = sys.argv[1]

    # Configurar manejadores de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    global enricher
    enricher = GeoIPEnricher(config_file)
    enricher.run()


if __name__ == "__main__":
    main()