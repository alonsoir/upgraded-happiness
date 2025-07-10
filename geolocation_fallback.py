#!/usr/bin/env python3
"""
geolocation_fallback.py - Sistema de Geolocalización Robusto
Múltiples proveedores con fallback automático para resolver coordenadas
Uso: python geolocation_fallback.py <ip_address>
      python -c "from geolocation_fallback import GeolocatorManager; print(GeolocatorManager().geolocate('8.8.8.8'))"
"""

import json
import ipaddress
import sys
import time
import logging
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List
import sqlite3

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class GeoIPCache:
    """Cache persistente para resultados de geolocalización"""

    def __init__(self, db_path: str = "data/geoip_cache.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self.init_database()

    def init_database(self):
        """Inicializar base de datos SQLite para cache"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS geoip_cache (
                ip_address TEXT PRIMARY KEY,
                latitude REAL,
                longitude REAL,
                city TEXT,
                country TEXT,
                provider TEXT,
                timestamp DATETIME,
                expires DATETIME
            )
        ''')
        conn.commit()
        conn.close()

    def get(self, ip_address: str) -> Optional[Dict]:
        """Obtener entrada del cache si no ha expirado"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT latitude, longitude, city, country, provider, timestamp
            FROM geoip_cache 
            WHERE ip_address = ? AND expires > ?
        ''', (ip_address, datetime.now()))

        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                'latitude': result[0],
                'longitude': result[1],
                'city': result[2],
                'country': result[3],
                'provider': result[4],
                'cached_at': result[5]
            }
        return None

    def set(self, ip_address: str, data: Dict, ttl_hours: int = 24):
        """Guardar entrada en cache con TTL"""
        conn = sqlite3.connect(self.db_path)
        expires = datetime.now() + timedelta(hours=ttl_hours)

        conn.execute('''
            INSERT OR REPLACE INTO geoip_cache 
            (ip_address, latitude, longitude, city, country, provider, timestamp, expires)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ip_address,
            data.get('latitude', 0.0),
            data.get('longitude', 0.0),
            data.get('city', 'Unknown'),
            data.get('country', 'Unknown'),
            data.get('provider', 'Unknown'),
            datetime.now(),
            expires
        ))

        conn.commit()
        conn.close()

    def cleanup_expired(self):
        """Limpiar entradas expiradas"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('DELETE FROM geoip_cache WHERE expires < ?', (datetime.now(),))
        deleted = cursor.rowcount

        conn.commit()
        conn.close()

        if deleted > 0:
            logger.info(f"🧹 Cache limpiado: {deleted} entradas expiradas eliminadas")


class GeolocatorManager:
    """Gestor de múltiples proveedores de geolocalización con fallback"""

    def __init__(self):
        self.cache = GeoIPCache()
        self.providers = self._init_providers()
        self.fallback_coordinates = self._init_fallback_coordinates()
        self.rate_limits = {}  # Para tracking de rate limiting

    def _init_providers(self) -> List[Dict]:
        """Inicializar proveedores de geolocalización ordenados por prioridad"""
        return [
            {
                'name': 'ip-api',
                'url': 'http://ip-api.com/json/{}?fields=status,lat,lon,city,country,query',
                'free_limit': 150,  # por minuto
                'timeout': 5,
                'parse_func': self._parse_ip_api,
                'priority': 1
            },
            {
                'name': 'ipapi_co',
                'url': 'https://ipapi.co/{}/json/',
                'free_limit': 100,  # por día para IP
                'timeout': 5,
                'parse_func': self._parse_ipapi_co,
                'priority': 2
            },
            {
                'name': 'freegeoip',
                'url': 'https://freegeoip.app/json/{}',
                'free_limit': 15000,  # por hora
                'timeout': 5,
                'parse_func': self._parse_freegeoip,
                'priority': 3
            },
            {
                'name': 'ipgeolocation',
                'url': 'https://api.ipgeolocation.io/ipgeo?apiKey=free&ip={}',
                'free_limit': 1000,  # por día
                'timeout': 5,
                'parse_func': self._parse_ipgeolocation,
                'priority': 4
            }
        ]

    def _init_fallback_coordinates(self) -> Dict:
        """Coordenadas de fallback para redes conocidas"""
        return {
            # Redes privadas con coordenadas aproximadas
            '192.168.0.0/16': {
                'latitude': 40.7128, 'longitude': -74.0060,
                'city': 'Local Network NYC', 'country': 'Private'
            },
            '10.0.0.0/8': {
                'latitude': 37.7749, 'longitude': -122.4194,
                'city': 'Local Network SF', 'country': 'Private'
            },
            '172.16.0.0/12': {
                'latitude': 51.5074, 'longitude': -0.1278,
                'city': 'Local Network London', 'country': 'Private'
            },

            # DNS públicos conocidos
            '8.8.8.8': {
                'latitude': 37.4056, 'longitude': -122.0775,
                'city': 'Mountain View', 'country': 'United States'
            },
            '8.8.4.4': {
                'latitude': 37.4056, 'longitude': -122.0775,
                'city': 'Mountain View', 'country': 'United States'
            },
            '1.1.1.1': {
                'latitude': -27.4766, 'longitude': 153.0166,
                'city': 'Brisbane', 'country': 'Australia'
            },
            '1.0.0.1': {
                'latitude': -27.4766, 'longitude': 153.0166,
                'city': 'Brisbane', 'country': 'Australia'
            },
            '208.67.222.222': {
                'latitude': 37.7749, 'longitude': -122.4194,
                'city': 'San Francisco', 'country': 'United States'
            },
            '208.67.220.220': {
                'latitude': 37.7749, 'longitude': -122.4194,
                'city': 'San Francisco', 'country': 'United States'
            }
        }

    def _parse_ip_api(self, response_data: Dict) -> Optional[Dict]:
        """Parser para ip-api.com"""
        if response_data.get('status') == 'success':
            return {
                'latitude': response_data.get('lat'),
                'longitude': response_data.get('lon'),
                'city': response_data.get('city', 'Unknown'),
                'country': response_data.get('country', 'Unknown'),
                'provider': 'ip-api'
            }
        return None

    def _parse_ipapi_co(self, response_data: Dict) -> Optional[Dict]:
        """Parser para ipapi.co"""
        if 'latitude' in response_data and 'longitude' in response_data:
            return {
                'latitude': response_data.get('latitude'),
                'longitude': response_data.get('longitude'),
                'city': response_data.get('city', 'Unknown'),
                'country': response_data.get('country_name', 'Unknown'),
                'provider': 'ipapi.co'
            }
        return None

    def _parse_freegeoip(self, response_data: Dict) -> Optional[Dict]:
        """Parser para freegeoip.app"""
        if 'latitude' in response_data and 'longitude' in response_data:
            return {
                'latitude': response_data.get('latitude'),
                'longitude': response_data.get('longitude'),
                'city': response_data.get('city', 'Unknown'),
                'country': response_data.get('country_name', 'Unknown'),
                'provider': 'freegeoip'
            }
        return None

    def _parse_ipgeolocation(self, response_data: Dict) -> Optional[Dict]:
        """Parser para ipgeolocation.io"""
        if 'latitude' in response_data and 'longitude' in response_data:
            return {
                'latitude': float(response_data.get('latitude', 0)),
                'longitude': float(response_data.get('longitude', 0)),
                'city': response_data.get('city', 'Unknown'),
                'country': response_data.get('country_name', 'Unknown'),
                'provider': 'ipgeolocation'
            }
        return None

    def _is_rate_limited(self, provider_name: str) -> bool:
        """Verificar si el proveedor está rate limited"""
        if provider_name not in self.rate_limits:
            return False

        last_request, count = self.rate_limits[provider_name]

        # Reset contador si ha pasado más de 1 minuto
        if time.time() - last_request > 60:
            del self.rate_limits[provider_name]
            return False

        # Verificar límites específicos por proveedor
        provider = next(p for p in self.providers if p['name'] == provider_name)
        return count >= provider['free_limit']

    def _update_rate_limit(self, provider_name: str):
        """Actualizar contador de rate limiting"""
        current_time = time.time()

        if provider_name in self.rate_limits:
            last_request, count = self.rate_limits[provider_name]
            if current_time - last_request <= 60:
                self.rate_limits[provider_name] = (current_time, count + 1)
            else:
                self.rate_limits[provider_name] = (current_time, 1)
        else:
            self.rate_limits[provider_name] = (current_time, 1)

    def _query_provider(self, provider: Dict, ip_address: str) -> Optional[Dict]:
        """Consultar un proveedor específico"""
        if self._is_rate_limited(provider['name']):
            logger.debug(f"⏳ Proveedor {provider['name']} rate limited")
            return None

        try:
            url = provider['url'].format(ip_address)
            response = requests.get(url, timeout=provider['timeout'])

            self._update_rate_limit(provider['name'])

            if response.status_code == 200:
                data = response.json()
                result = provider['parse_func'](data)

                if result and result.get('latitude') and result.get('longitude'):
                    logger.debug(f"✅ {provider['name']}: {result['latitude']}, {result['longitude']}")
                    return result
                else:
                    logger.debug(f"⚠️ {provider['name']}: Respuesta inválida")
            else:
                logger.debug(f"⚠️ {provider['name']}: HTTP {response.status_code}")

        except requests.exceptions.Timeout:
            logger.debug(f"⏰ {provider['name']}: Timeout")
        except requests.exceptions.RequestException as e:
            logger.debug(f"❌ {provider['name']}: Error - {e}")
        except Exception as e:
            logger.debug(f"❌ {provider['name']}: Error inesperado - {e}")

        return None

    def _get_fallback_coordinates(self, ip_address: str) -> Optional[Dict]:
        """Obtener coordenadas de fallback para IPs conocidas"""
        try:
            ip = ipaddress.ip_address(ip_address)

            # Verificar IPs específicas
            if ip_address in self.fallback_coordinates:
                result = self.fallback_coordinates[ip_address].copy()
                result['provider'] = 'fallback_static'
                return result

            # Verificar redes privadas
            for network_str, coords in self.fallback_coordinates.items():
                if '/' in network_str:  # Es una red
                    try:
                        network = ipaddress.ip_network(network_str)
                        if ip in network:
                            result = coords.copy()
                            result['provider'] = 'fallback_network'
                            return result
                    except ValueError:
                        continue

            # Coordenadas por defecto para IPs públicas desconocidas
            if not ip.is_private:
                return {
                    'latitude': 39.8283,  # Centro geográfico de USA
                    'longitude': -98.5795,
                    'city': 'Unknown Location',
                    'country': 'Unknown',
                    'provider': 'fallback_default'
                }

        except ValueError:
            logger.debug(f"⚠️ IP inválida: {ip_address}")

        return None

    def geolocate(self, ip_address: str, use_cache: bool = True) -> Dict:
        """
        Geolocalizar una IP usando múltiples proveedores con fallback

        Args:
            ip_address: IP a geolocalizar
            use_cache: Si usar cache (True por defecto)

        Returns:
            Dict con latitude, longitude, city, country, provider
        """
        # Validar IP
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return {
                'latitude': 0.0, 'longitude': 0.0,
                'city': 'Invalid IP', 'country': 'Invalid',
                'provider': 'error', 'error': 'Invalid IP address'
            }

        # Verificar cache primero
        if use_cache:
            cached_result = self.cache.get(ip_address)
            if cached_result:
                logger.debug(f"📋 Cache hit para {ip_address}")
                return cached_result

        # Intentar con cada proveedor por orden de prioridad
        for provider in sorted(self.providers, key=lambda p: p['priority']):
            result = self._query_provider(provider, ip_address)
            if result:
                # Guardar en cache
                if use_cache:
                    self.cache.set(ip_address, result)
                return result

        # Si todos los proveedores fallan, usar fallback
        logger.debug(f"⚠️ Todos los proveedores fallaron para {ip_address}, usando fallback")
        fallback_result = self._get_fallback_coordinates(ip_address)

        if fallback_result:
            if use_cache:
                self.cache.set(ip_address, fallback_result, ttl_hours=1)  # TTL más corto para fallbacks
            return fallback_result

        # Último recurso: coordenadas inválidas
        return {
            'latitude': 0.0, 'longitude': 0.0,
            'city': 'Unknown', 'country': 'Unknown',
            'provider': 'fallback_failed',
            'error': 'All providers failed'
        }

    def bulk_geolocate(self, ip_addresses: List[str], max_concurrent: int = 5) -> Dict[str, Dict]:
        """Geolocalizar múltiples IPs de forma eficiente"""
        results = {}

        for ip in ip_addresses:
            results[ip] = self.geolocate(ip)
            # Pequeña pausa para evitar rate limiting agresivo
            time.sleep(0.1)

        return results

    def get_cache_stats(self) -> Dict:
        """Obtener estadísticas del cache"""
        conn = sqlite3.connect(self.cache.db_path)
        cursor = conn.cursor()

        # Total de entradas
        cursor.execute('SELECT COUNT(*) FROM geoip_cache')
        total = cursor.fetchone()[0]

        # Entradas válidas (no expiradas)
        cursor.execute('SELECT COUNT(*) FROM geoip_cache WHERE expires > ?', (datetime.now(),))
        valid = cursor.fetchone()[0]

        # Entradas por proveedor
        cursor.execute('SELECT provider, COUNT(*) FROM geoip_cache WHERE expires > ? GROUP BY provider',
                       (datetime.now(),))
        by_provider = dict(cursor.fetchall())

        conn.close()

        return {
            'total_entries': total,
            'valid_entries': valid,
            'expired_entries': total - valid,
            'by_provider': by_provider,
            'cache_file': str(self.cache.db_path)
        }


def test_geolocation_service():
    """Función de test para verificar el servicio"""
    geolocator = GeolocatorManager()

    test_ips = [
        '8.8.8.8',  # Google DNS
        '1.1.1.1',  # Cloudflare DNS
        '208.67.222.222',  # OpenDNS
        '192.168.1.1',  # IP privada
        '10.0.0.1',  # IP privada
        '127.0.0.1'  # Localhost
    ]

    print("🌍 Testing Geolocation Service")
    print("=" * 50)

    for ip in test_ips:
        result = geolocator.geolocate(ip)
        print(f"{ip:15} → {result['latitude']:8.4f}, {result['longitude']:9.4f} "
              f"({result['city']}, {result['country']}) [{result['provider']}]")

    # Mostrar estadísticas del cache
    stats = geolocator.get_cache_stats()
    print(f"\n📊 Cache Stats:")
    print(f"   Total entries: {stats['total_entries']}")
    print(f"   Valid entries: {stats['valid_entries']}")
    print(f"   By provider: {stats['by_provider']}")


def main():
    """Función principal para uso desde línea de comandos"""
    if len(sys.argv) != 2:
        print("Uso: python geolocation_fallback.py <ip_address>")
        print("     python geolocation_fallback.py test")
        sys.exit(1)

    if sys.argv[1] == 'test':
        test_geolocation_service()
        return

    ip_address = sys.argv[1]
    geolocator = GeolocatorManager()
    result = geolocator.geolocate(ip_address)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()