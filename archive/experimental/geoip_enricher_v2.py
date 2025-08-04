#!/usr/bin/env python3
"""
GeoIP Enricher v2 - Sistema de geolocalización con cache para tráfico de red
Compatible con advanced-trainer.py y UNSW-NB15 features
"""

import json
import time
import math
import logging
import ipaddress
import os
from pathlib import Path
from typing import Dict, Optional, Tuple, Union
from collections import OrderedDict
from dataclasses import dataclass
import threading

# GeoIP databases
try:
    import geoip2.database
    import geoip2.errors

    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    print("Warning: geoip2 not available. Install with: pip install geoip2")

# Requests para descargas y API calls
try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Cargar variables de entorno
try:
    from dotenv import load_dotenv

    load_dotenv()
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False


# -----------------------------------------------------------------------------
# 📊 ESTRUCTURAS DE DATOS
# -----------------------------------------------------------------------------
@dataclass
class GeoData:
    """Datos de geolocalización para una IP"""
    ip: str
    country_code: str = "UNKNOWN"
    country_name: str = "Unknown"
    city: str = "Unknown"
    asn: int = 0
    asn_org: str = "Unknown"
    latitude: float = 0.0
    longitude: float = 0.0
    risk_score: float = 0.5
    distance_km: float = 0.0
    is_private: bool = False
    lookup_time: float = 0.0
    source: str = "unknown"


# -----------------------------------------------------------------------------
# 🗺️ CACHE LRU THREAD-SAFE
# -----------------------------------------------------------------------------
class ThreadSafeLRUCache:
    """Cache LRU thread-safe para datos de geolocalización"""

    def __init__(self, maxsize: int = 10000):
        self.maxsize = maxsize
        self.cache = OrderedDict()
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[GeoData]:
        """Obtiene valor del cache"""
        with self.lock:
            if key in self.cache:
                # Mover al final (más reciente)
                value = self.cache.pop(key)
                self.cache[key] = value
                self.hits += 1
                return value
            else:
                self.misses += 1
                return None

    def put(self, key: str, value: GeoData):
        """Almacena valor en cache"""
        with self.lock:
            if key in self.cache:
                # Actualizar existente
                self.cache.pop(key)
            elif len(self.cache) >= self.maxsize:
                # Eliminar el más antiguo
                self.cache.popitem(last=False)

            self.cache[key] = value

    def stats(self) -> Dict:
        """Estadísticas del cache"""
        with self.lock:
            total = self.hits + self.misses
            hit_rate = self.hits / total if total > 0 else 0.0
            return {
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': hit_rate,
                'size': len(self.cache),
                'maxsize': self.maxsize
            }

    def clear(self):
        """Limpia el cache"""
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0


# -----------------------------------------------------------------------------
# 🌍 SISTEMA DE PUNTUACIÓN DE RIESGO POR PAÍS
# -----------------------------------------------------------------------------
class CountryRiskScorer:
    """Sistema de puntuación de riesgo por país"""

    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Scores de riesgo por defecto (0.0 = muy seguro, 1.0 = muy riesgoso)
        self.default_scores = {
            # Países de bajo riesgo
            'US': 0.1, 'GB': 0.1, 'DE': 0.1, 'FR': 0.1, 'CA': 0.1,
            'AU': 0.1, 'NL': 0.1, 'SE': 0.1, 'NO': 0.1, 'DK': 0.1,
            'CH': 0.1, 'AT': 0.1, 'BE': 0.1, 'FI': 0.1, 'IE': 0.1,
            'ES': 0.15, 'IT': 0.15, 'PT': 0.15, 'JP': 0.15, 'KR': 0.15,

            # Países de riesgo medio
            'BR': 0.3, 'MX': 0.3, 'AR': 0.3, 'CL': 0.3, 'CO': 0.35,
            'IN': 0.3, 'TH': 0.3, 'MY': 0.3, 'SG': 0.2, 'ID': 0.35,
            'PH': 0.4, 'VN': 0.35, 'TR': 0.35, 'EG': 0.4, 'SA': 0.3,
            'AE': 0.25, 'IL': 0.3, 'ZA': 0.35, 'NG': 0.5, 'KE': 0.4,

            # Países de alto riesgo
            'CN': 0.6, 'RU': 0.7, 'IR': 0.8, 'KP': 0.9, 'BY': 0.7,
            'PK': 0.6, 'BD': 0.5, 'MM': 0.7, 'KH': 0.6, 'LA': 0.6,
            'AF': 0.9, 'IQ': 0.8, 'SY': 0.9, 'YE': 0.8, 'SO': 0.9,
            'SD': 0.8, 'LY': 0.8, 'CD': 0.7, 'CF': 0.8, 'TD': 0.7,

            # Países con historial de actividad maliciosa alta
            'UA': 0.5,  # Por conflicto actual
            'VE': 0.6,  # Inestabilidad política
            'CU': 0.6,  # Restricciones
        }

        # Cargar scores personalizados del config
        custom_scores = config.get('country_risk_scores', {})
        self.scores = {**self.default_scores, **custom_scores}

        self.logger.info(f"Country risk scorer inicializado con {len(self.scores)} países")

    def get_risk_score(self, country_code: str) -> float:
        """Obtiene score de riesgo para un país"""
        if not country_code or country_code == "UNKNOWN":
            return 0.5  # Riesgo neutro para desconocidos

        return self.scores.get(country_code.upper(), 0.4)  # Default: riesgo medio-bajo

    def update_score(self, country_code: str, score: float):
        """Actualiza score de riesgo para un país"""
        if 0.0 <= score <= 1.0:
            self.scores[country_code.upper()] = score
            self.logger.info(f"Risk score actualizado: {country_code} = {score}")
        else:
            raise ValueError("Risk score debe estar entre 0.0 y 1.0")


# -----------------------------------------------------------------------------
# 📍 CALCULADORA DE DISTANCIAS
# -----------------------------------------------------------------------------
class DistanceCalculator:
    """Calculadora de distancias geográficas"""

    def __init__(self, hq_coords: Tuple[float, float]):
        self.hq_lat, self.hq_lon = hq_coords
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"HQ coordinates: {self.hq_lat}, {self.hq_lon}")

    def calculate_distance(self, lat: float, lon: float) -> float:
        """Calcula distancia usando fórmula de Haversine"""
        if lat == 0.0 and lon == 0.0:
            return 0.0  # Coordenadas desconocidas

        # Convertir a radianes
        lat1_rad = math.radians(self.hq_lat)
        lon1_rad = math.radians(self.hq_lon)
        lat2_rad = math.radians(lat)
        lon2_rad = math.radians(lon)

        # Diferencias
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad

        # Fórmula de Haversine
        a = (math.sin(dlat / 2) ** 2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2)
        c = 2 * math.asin(math.sqrt(a))

        # Radio de la Tierra en km
        earth_radius_km = 6371.0
        distance = earth_radius_km * c

        return round(distance, 2)


# -----------------------------------------------------------------------------
# 🔍 DETECTOR DE IPs PRIVADAS
# -----------------------------------------------------------------------------
class PrivateIPDetector:
    """Detector de rangos de IP privadas y especiales"""

    def __init__(self):
        self.private_networks = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8'),  # Loopback
            ipaddress.IPv4Network('169.254.0.0/16'),  # Link-local
            ipaddress.IPv4Network('224.0.0.0/4'),  # Multicast
            ipaddress.IPv4Network('0.0.0.0/8'),  # Reserved
        ]

    def is_private(self, ip_str: str) -> bool:
        """Verifica si una IP es privada/especial"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return any(ip in network for network in self.private_networks)
        except (ipaddress.AddressValueError, ValueError):
            return True  # Si no es válida, considerarla "privada"


# -----------------------------------------------------------------------------
# 🌐 CLIENTE IPAPI COMO FALLBACK
# -----------------------------------------------------------------------------
class IPAPIClient:
    """Cliente para API de ipapi.co como fallback"""

    def __init__(self, api_token: Optional[str] = None):
        self.api_token = api_token or os.getenv('IPAPI_TOKEN')
        self.base_url = "https://ipapi.co"
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        self.logger = logging.getLogger(__name__)

        # Rate limiting (1000 requests/day gratis, 30000 con token)
        self.requests_made = 0
        self.daily_limit = 30000 if self.api_token else 1000

        if self.api_token:
            self.logger.info("IPAPI client inicializado con token")
        else:
            self.logger.warning("IPAPI client sin token (límite: 1000 req/día)")

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        """Busca información de IP en IPAPI"""
        if not REQUESTS_AVAILABLE or not self.session:
            return None

        if self.requests_made >= self.daily_limit:
            self.logger.warning("Límite diario de IPAPI alcanzado")
            return None

        try:
            # Construir URL
            url = f"{self.base_url}/{ip}/json/"
            params = {}

            if self.api_token:
                params['key'] = self.api_token

            # Hacer request
            response = self.session.get(url, params=params, timeout=5)
            response.raise_for_status()

            data = response.json()
            self.requests_made += 1

            # Verificar si hay error
            if 'error' in data:
                self.logger.warning(f"IPAPI error para {ip}: {data['error']}")
                return None

            # Mapear a formato estándar
            return {
                'country_code': data.get('country_code', 'UNKNOWN'),
                'country_name': data.get('country_name', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'latitude': float(data.get('latitude', 0.0)),
                'longitude': float(data.get('longitude', 0.0)),
                'asn': data.get('asn', 'AS0'),
                'org': data.get('org', 'Unknown'),
                'timezone': data.get('timezone', 'Unknown'),
                'currency': data.get('currency', 'Unknown')
            }

        except requests.RequestException as e:
            self.logger.error(f"Error en IPAPI request para {ip}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error procesando respuesta IPAPI para {ip}: {e}")
            return None

    def get_usage_stats(self) -> Dict:
        """Obtiene estadísticas de uso"""
        return {
            'requests_made': self.requests_made,
            'daily_limit': self.daily_limit,
            'remaining': self.daily_limit - self.requests_made,
            'has_token': bool(self.api_token)
        }


# -----------------------------------------------------------------------------
# 🌍 ENRIQUECEDOR GeoIP PRINCIPAL
# -----------------------------------------------------------------------------
class GeoIPEnricher:
    """Enriquecedor principal de geolocalización"""

    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Componentes
        self.cache = ThreadSafeLRUCache(config.get('cache_size', 10000))
        self.risk_scorer = CountryRiskScorer(config)
        self.distance_calc = DistanceCalculator(
            config.get('hq_coords', [37.3891, -5.9845])  # Sevilla por defecto
        )
        self.private_detector = PrivateIPDetector()

        # Cliente IPAPI como fallback
        self.ipapi_client = None
        if config.get('use_ipapi_fallback', True):
            self.ipapi_client = IPAPIClient(config.get('ipapi_token'))

        # Bases de datos GeoIP
        self.city_db = None
        self.country_db = None
        self.asn_db = None

        self._init_databases()

        # Estadísticas
        self.stats = {
            'total_lookups': 0,
            'cache_hits': 0,
            'db_lookups': 0,
            'ipapi_lookups': 0,
            'private_ips': 0,
            'unknown_ips': 0
        }

    def _init_databases(self):
        """Inicializa bases de datos GeoIP"""
        if not GEOIP2_AVAILABLE:
            self.logger.warning("geoip2 no disponible, usando datos mock")
            return

        db_paths = {
            'city': self.config.get('city_db', 'GeoLite2-City.mmdb'),
            'country': self.config.get('country_db', 'GeoLite2-Country.mmdb'),
            'asn': self.config.get('asn_db', 'GeoLite2-ASN.mmdb')
        }

        for db_type, db_path in db_paths.items():
            try:
                if Path(db_path).exists():
                    if db_type == 'city':
                        self.city_db = geoip2.database.Reader(db_path)
                        self.logger.info(f"City DB cargada: {db_path}")
                    elif db_type == 'country':
                        self.country_db = geoip2.database.Reader(db_path)
                        self.logger.info(f"Country DB cargada: {db_path}")
                    elif db_type == 'asn':
                        self.asn_db = geoip2.database.Reader(db_path)
                        self.logger.info(f"ASN DB cargada: {db_path}")
                else:
                    self.logger.warning(f"DB no encontrada: {db_path}")
            except Exception as e:
                self.logger.error(f"Error cargando {db_type} DB: {e}")

    def enrich_ip(self, ip: str) -> GeoData:
        """Enriquece una IP con datos de geolocalización"""
        start_time = time.time()
        self.stats['total_lookups'] += 1

        # Verificar cache primero
        cached = self.cache.get(ip)
        if cached:
            self.stats['cache_hits'] += 1
            return cached

        # Crear objeto GeoData
        geo_data = GeoData(ip=ip)

        # Verificar si es IP privada
        if self.private_detector.is_private(ip):
            geo_data.is_private = True
            geo_data.country_code = "PRIVATE"
            geo_data.country_name = "Private Network"
            geo_data.risk_score = 0.0  # IPs privadas son seguras
            geo_data.source = "private_detection"
            self.stats['private_ips'] += 1
        else:
            # Lookup en bases de datos
            self._lookup_databases(ip, geo_data)
            self.stats['db_lookups'] += 1

        # Calcular distancia
        if geo_data.latitude != 0.0 or geo_data.longitude != 0.0:
            geo_data.distance_km = self.distance_calc.calculate_distance(
                geo_data.latitude, geo_data.longitude
            )

        # Asignar risk score
        if not geo_data.is_private:
            geo_data.risk_score = self.risk_scorer.get_risk_score(geo_data.country_code)

        # Metadata
        geo_data.lookup_time = time.time() - start_time

        # Guardar en cache
        self.cache.put(ip, geo_data)

        return geo_data

    def _lookup_databases(self, ip: str, geo_data: GeoData):
        """Realiza lookup en bases de datos GeoIP + IPAPI fallback"""
        if not GEOIP2_AVAILABLE or not any([self.city_db, self.country_db, self.asn_db]):
            # Intentar IPAPI primero si no hay bases locales
            if self._try_ipapi_lookup(ip, geo_data):
                return
            else:
                self._mock_lookup(ip, geo_data)
                return

        found_data = False

        try:
            # Intentar city DB primero (más completo)
            if self.city_db:
                try:
                    response = self.city_db.city(ip)
                    geo_data.country_code = response.country.iso_code or "UNKNOWN"
                    geo_data.country_name = response.country.name or "Unknown"
                    geo_data.city = response.city.name or "Unknown"
                    geo_data.latitude = float(response.location.latitude or 0.0)
                    geo_data.longitude = float(response.location.longitude or 0.0)
                    geo_data.source = "city_db"
                    found_data = True

                    # ASN desde city DB si está disponible
                    if hasattr(response, 'traits') and response.traits.autonomous_system_number:
                        geo_data.asn = response.traits.autonomous_system_number
                        geo_data.asn_org = response.traits.autonomous_system_organization or "Unknown"

                except geoip2.errors.AddressNotFoundError:
                    pass

            # Fallback a country DB si city falló
            if not found_data and self.country_db:
                try:
                    response = self.country_db.country(ip)
                    geo_data.country_code = response.country.iso_code or "UNKNOWN"
                    geo_data.country_name = response.country.name or "Unknown"
                    geo_data.source = "country_db"
                    found_data = True
                except geoip2.errors.AddressNotFoundError:
                    pass

            # ASN lookup separado si tenemos ASN DB y no lo encontramos antes
            if self.asn_db and geo_data.asn == 0:
                try:
                    response = self.asn_db.asn(ip)
                    geo_data.asn = response.autonomous_system_number or 0
                    geo_data.asn_org = response.autonomous_system_organization or "Unknown"
                    if geo_data.source not in ["city_db", "country_db"]:
                        geo_data.source = "asn_db"
                    found_data = True
                except geoip2.errors.AddressNotFoundError:
                    pass

        except Exception as e:
            self.logger.error(f"Error en lookup GeoIP para {ip}: {e}")

        # Si no encontramos datos en MaxMind, intentar IPAPI
        if not found_data or geo_data.country_code == "UNKNOWN":
            if self._try_ipapi_lookup(ip, geo_data):
                return

        # Último recurso: datos mock
        if not found_data:
            self._mock_lookup(ip, geo_data)
            self.stats['unknown_ips'] += 1

    def _try_ipapi_lookup(self, ip: str, geo_data: GeoData) -> bool:
        """Intenta lookup en IPAPI como fallback"""
        if not self.ipapi_client:
            return False

        try:
            ipapi_data = self.ipapi_client.lookup_ip(ip)
            if not ipapi_data:
                return False

            # Actualizar GeoData con datos de IPAPI
            if geo_data.country_code == "UNKNOWN":
                geo_data.country_code = ipapi_data.get('country_code', 'UNKNOWN')
                geo_data.country_name = ipapi_data.get('country_name', 'Unknown')

            if geo_data.city == "Unknown":
                geo_data.city = ipapi_data.get('city', 'Unknown')

            if geo_data.latitude == 0.0 and geo_data.longitude == 0.0:
                geo_data.latitude = ipapi_data.get('latitude', 0.0)
                geo_data.longitude = ipapi_data.get('longitude', 0.0)

            if geo_data.asn == 0:
                # Extraer número ASN del formato "AS12345"
                asn_str = ipapi_data.get('asn', 'AS0')
                if asn_str.startswith('AS'):
                    try:
                        geo_data.asn = int(asn_str[2:])
                    except ValueError:
                        geo_data.asn = 0
                geo_data.asn_org = ipapi_data.get('org', 'Unknown')

            geo_data.source = "ipapi_fallback"
            self.stats['ipapi_lookups'] += 1

            self.logger.debug(f"IPAPI lookup exitoso para {ip}: {geo_data.country_code}")
            return True

        except Exception as e:
            self.logger.error(f"Error en IPAPI lookup para {ip}: {e}")
            return False

    def _mock_lookup(self, ip: str, geo_data: GeoData):
        """Lookup mock para cuando no hay bases de datos"""
        # Simulación básica basada en rangos de IP
        octets = ip.split('.')
        if len(octets) != 4:
            return

        try:
            first_octet = int(octets[0])
            second_octet = int(octets[1])

            # Simulación muy básica por rangos
            if first_octet in [8, 4]:  # Google, Level3
                geo_data.country_code = "US"
                geo_data.country_name = "United States"
                geo_data.asn = 15169 if first_octet == 8 else 3356
                geo_data.asn_org = "Google LLC" if first_octet == 8 else "Level 3"
            elif first_octet in [77, 78, 79]:  # Rangos EU comunes
                geo_data.country_code = "DE"
                geo_data.country_name = "Germany"
                geo_data.asn = 3320
                geo_data.asn_org = "Deutsche Telekom AG"
            elif first_octet in [200, 201, 190]:  # Rangos LATAM
                geo_data.country_code = "BR"
                geo_data.country_name = "Brazil"
                geo_data.asn = 7738
                geo_data.asn_org = "Telemar Norte Leste S.A."
            else:
                geo_data.country_code = "UNKNOWN"
                geo_data.country_name = "Unknown"

            geo_data.source = "mock"

        except ValueError:
            geo_data.source = "mock_error"

    def batch_enrich(self, ips: list) -> Dict[str, GeoData]:
        """Enriquece un lote de IPs"""
        results = {}
        for ip in ips:
            results[ip] = self.enrich_ip(ip)
        return results

    def get_stats(self) -> Dict:
        """Obtiene estadísticas del enriquecedor"""
        cache_stats = self.cache.stats()
        stats = {
            **self.stats,
            'cache': cache_stats
        }

        # Agregar estadísticas de IPAPI si está disponible
        if self.ipapi_client:
            stats['ipapi'] = self.ipapi_client.get_usage_stats()

        return stats

    def close(self):
        """Cierra bases de datos"""
        if self.city_db:
            self.city_db.close()
        if self.country_db:
            self.country_db.close()
        if self.asn_db:
            self.asn_db.close()

        self.logger.info("GeoIP databases cerradas")


# -----------------------------------------------------------------------------
# 📥 DESCARGADOR DE BASES DE DATOS
# -----------------------------------------------------------------------------
class GeoIPDownloader:
    """Descargador automático de bases de datos GeoLite2"""

    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.base_url = "https://download.maxmind.com/app/geoip_download"

        # URLs de bases de datos gratuitas (requieren cuenta MaxMind)
        self.databases = {
            'city': 'GeoLite2-City.mmdb',
            'country': 'GeoLite2-Country.mmdb',
            'asn': 'GeoLite2-ASN.mmdb'
        }

    def download_databases(self, license_key: str):
        """Descarga bases de datos GeoLite2"""
        if not REQUESTS_AVAILABLE:
            self.logger.error("requests no disponible para descargas")
            return False

        if not license_key:
            self.logger.error("License key requerida para descargar bases de datos")
            return False

        success = True
        for db_type, filename in self.databases.items():
            if self._download_database(db_type, filename, license_key):
                self.logger.info(f"Base de datos {db_type} descargada: {filename}")
            else:
                self.logger.error(f"Error descargando base de datos {db_type}")
                success = False

        return success

    def _download_database(self, db_type: str, filename: str, license_key: str) -> bool:
        """Descarga una base de datos específica"""
        try:
            # Construir URL
            edition_id = f"GeoLite2-{db_type.capitalize()}"
            url = f"{self.base_url}?edition_id={edition_id}&license_key={license_key}&suffix=tar.gz"

            # Descargar
            response = requests.get(url, stream=True)
            response.raise_for_status()

            # Guardar archivo temporal
            temp_file = f"{filename}.tar.gz"
            with open(temp_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            # Extraer (requiere tarfile)
            import tarfile
            with tarfile.open(temp_file, 'r:gz') as tar:
                # Buscar archivo .mmdb en el tar
                for member in tar.getmembers():
                    if member.name.endswith('.mmdb'):
                        # Extraer con nombre correcto
                        member.name = filename
                        tar.extract(member)
                        break

            # Limpiar archivo temporal
            Path(temp_file).unlink()

            return True

        except Exception as e:
            self.logger.error(f"Error descargando {db_type}: {e}")
            return False


# -----------------------------------------------------------------------------
# 🧪 UTILIDADES DE TESTING
# -----------------------------------------------------------------------------
def test_enricher():
    """Función de testing básico"""
    config = {
        'cache_size': 1000,
        'hq_coords': [37.3891, -5.9845],  # Sevilla
        'city_db': 'GeoLite2-City.mmdb',
        'country_db': 'GeoLite2-Country.mmdb',
        'asn_db': 'GeoLite2-ASN.mmdb'
    }

    enricher = GeoIPEnricher(config)

    # Test IPs
    test_ips = [
        '8.8.8.8',  # Google DNS
        '1.1.1.1',  # Cloudflare
        '192.168.1.1',  # Private
        '127.0.0.1',  # Localhost
        '77.88.8.8',  # Yandex (RU)
        '208.67.222.222',  # OpenDNS
    ]

    print("=== Test GeoIP Enricher v2 ===")
    for ip in test_ips:
        geo_data = enricher.enrich_ip(ip)
        print(f"\nIP: {ip}")
        print(f"  País: {geo_data.country_code} ({geo_data.country_name})")
        print(f"  Ciudad: {geo_data.city}")
        print(f"  ASN: {geo_data.asn} ({geo_data.asn_org})")
        print(f"  Coords: {geo_data.latitude}, {geo_data.longitude}")
        print(f"  Distancia: {geo_data.distance_km} km")
        print(f"  Risk Score: {geo_data.risk_score}")
        print(f"  Privada: {geo_data.is_private}")
        print(f"  Source: {geo_data.source}")
        print(f"  Lookup time: {geo_data.lookup_time:.4f}s")

    # Estadísticas
    stats = enricher.get_stats()
    print(f"\n=== Estadísticas ===")
    for key, value in stats.items():
        print(f"{key}: {value}")

    enricher.close()


# -----------------------------------------------------------------------------
# 🏁 EJECUCIÓN
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="GeoIP Enricher v2")
    parser.add_argument("--test", action="store_true", help="Ejecutar tests")
    parser.add_argument("--download", help="Descargar DBs con license key")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    if args.test:
        test_enricher()
    elif args.download:
        config = {}
        downloader = GeoIPDownloader(config)
        downloader.download_databases(args.download)
    else:
        print("Uso: python geoip_enricher_v2.py --test")
        print("     python geoip_enricher_v2.py --download LICENSE_KEY")