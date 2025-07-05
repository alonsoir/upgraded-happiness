#!/usr/bin/env python3
"""
🌍 Servicio de Geolocalización IP para Sistema SCADA
Convierte IPs a coordenadas geográficas para visualización en mapa
"""

import requests
import json
import time
import sqlite3
import os
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass
import logging


@dataclass
class GeoLocation:
    """Estructura para almacenar información geográfica"""
    latitude: float
    longitude: float
    city: str
    country: str
    isp: str
    is_private: bool = False


class IPGeoLocator:
    """
    Servicio de geolocalización IP con cache local y múltiples proveedores
    """

    def __init__(self, cache_db_path: str = "ip_cache.db"):
        self.cache_db_path = cache_db_path
        self.logger = logging.getLogger(__name__)
        self.setup_logging()
        self.setup_cache_db()

        # Configurar múltiples proveedores para redundancia
        self.providers = [
            self.geolocate_ipapi,
            self.geolocate_ipinfo,
            self.geolocate_freeipapi
        ]

        # Cache de IPs privadas comunes (coordenadas por defecto en Sevilla)
        self.private_ranges = {
            '10.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.16.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.17.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.18.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.19.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.20.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.21.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.22.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.23.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.24.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.25.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.26.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.27.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.28.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.29.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.30.': (37.3891, -5.9845, "Red Local", "Privada"),
            '172.31.': (37.3891, -5.9845, "Red Local", "Privada"),
            '192.168.': (37.3891, -5.9845, "Red Local", "Privada"),
            '127.': (37.3891, -5.9845, "Localhost", "Local"),
            '::1': (37.3891, -5.9845, "Localhost IPv6", "Local"),
            'ff02:': (37.3891, -5.9845, "IPv6 Multicast", "Multicast"),
        }

    def setup_logging(self):
        """Configurar logging básico"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    def setup_cache_db(self):
        """Configurar base de datos SQLite para cache"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_cache (
                    ip TEXT PRIMARY KEY,
                    latitude REAL,
                    longitude REAL,
                    city TEXT,
                    country TEXT,
                    isp TEXT,
                    is_private BOOLEAN,
                    timestamp INTEGER
                )
            ''')
            conn.commit()
            conn.close()
            self.logger.info(f"✅ Cache DB configurado: {self.cache_db_path}")
        except Exception as e:
            self.logger.error(f"❌ Error configurando cache DB: {e}")

    def is_private_ip(self, ip: str) -> bool:
        """Verificar si es IP privada"""
        for prefix in self.private_ranges.keys():
            if ip.startswith(prefix):
                return True
        return False

    def get_cached_location(self, ip: str) -> Optional[GeoLocation]:
        """Obtener ubicación desde cache"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT latitude, longitude, city, country, isp, is_private FROM ip_cache WHERE ip = ?',
                (ip,)
            )
            result = cursor.fetchone()
            conn.close()

            if result:
                return GeoLocation(
                    latitude=result[0],
                    longitude=result[1],
                    city=result[2],
                    country=result[3],
                    isp=result[4],
                    is_private=bool(result[5])
                )
        except Exception as e:
            self.logger.error(f"❌ Error leyendo cache: {e}")
        return None

    def cache_location(self, ip: str, location: GeoLocation):
        """Guardar ubicación en cache"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO ip_cache 
                (ip, latitude, longitude, city, country, isp, is_private, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ip, location.latitude, location.longitude,
                location.city, location.country, location.isp,
                location.is_private, int(time.time())
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"❌ Error guardando en cache: {e}")

    def geolocate_ipapi(self, ip: str) -> Optional[GeoLocation]:
        """Geolocalizar usando ip-api.com (gratuito, sin API key)"""
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return GeoLocation(
                        latitude=data.get('lat', 0),
                        longitude=data.get('lon', 0),
                        city=data.get('city', 'Unknown'),
                        country=data.get('country', 'Unknown'),
                        isp=data.get('isp', 'Unknown')
                    )
        except Exception as e:
            self.logger.error(f"❌ Error con ip-api: {e}")
        return None

    def geolocate_ipinfo(self, ip: str) -> Optional[GeoLocation]:
        """Geolocalizar usando ipinfo.io (gratuito con límites)"""
        try:
            response = requests.get(
                f"https://ipinfo.io/{ip}/json",
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()
                if 'loc' in data and data['loc']:
                    lat, lon = data['loc'].split(',')
                    return GeoLocation(
                        latitude=float(lat),
                        longitude=float(lon),
                        city=data.get('city', 'Unknown'),
                        country=data.get('country', 'Unknown'),
                        isp=data.get('org', 'Unknown')
                    )
        except Exception as e:
            self.logger.error(f"❌ Error con ipinfo: {e}")
        return None

    def geolocate_freeipapi(self, ip: str) -> Optional[GeoLocation]:
        """Geolocalizar usando freeipapi.com"""
        try:
            response = requests.get(
                f"https://freeipapi.com/api/json/{ip}",
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('latitude') and data.get('longitude'):
                    return GeoLocation(
                        latitude=data.get('latitude', 0),
                        longitude=data.get('longitude', 0),
                        city=data.get('cityName', 'Unknown'),
                        country=data.get('countryName', 'Unknown'),
                        isp=data.get('isp', 'Unknown')
                    )
        except Exception as e:
            self.logger.error(f"❌ Error con freeipapi: {e}")
        return None

    def geolocate_ip(self, ip: str) -> Optional[GeoLocation]:
        """
        Geolocalizar IP usando cache primero, luego múltiples proveedores
        """
        # Verificar cache primero
        cached = self.get_cached_location(ip)
        if cached:
            self.logger.debug(f"🎯 Cache hit para {ip}")
            return cached

        # Verificar si es IP privada
        if self.is_private_ip(ip):
            for prefix, (lat, lon, city, isp) in self.private_ranges.items():
                if ip.startswith(prefix):
                    location = GeoLocation(
                        latitude=lat,
                        longitude=lon,
                        city=city,
                        country="Local",
                        isp=isp,
                        is_private=True
                    )
                    self.cache_location(ip, location)
                    return location

        # Intentar con múltiples proveedores
        for i, provider in enumerate(self.providers):
            try:
                self.logger.debug(f"🌐 Intentando proveedor {i + 1} para {ip}")
                location = provider(ip)
                if location:
                    self.cache_location(ip, location)
                    self.logger.info(f"✅ Geolocalizado {ip}: {location.city}, {location.country}")
                    return location

                # Rate limiting entre proveedores
                time.sleep(0.5)

            except Exception as e:
                self.logger.error(f"❌ Error con proveedor {i + 1}: {e}")
                continue

        self.logger.warning(f"⚠️ No se pudo geolocalizar {ip}")
        return None

    def geolocate_batch(self, ips: list) -> Dict[str, Optional[GeoLocation]]:
        """Geolocalizar múltiples IPs con rate limiting"""
        results = {}

        for i, ip in enumerate(ips):
            results[ip] = self.geolocate_ip(ip)

            # Rate limiting para evitar bloqueos
            if i > 0 and i % 10 == 0:
                time.sleep(2)

        return results

    def get_cache_stats(self) -> Dict[str, Any]:
        """Obtener estadísticas del cache"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM ip_cache')
            total = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM ip_cache WHERE is_private = 1')
            private = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM ip_cache WHERE is_private = 0')
            public = cursor.fetchone()[0]

            conn.close()

            return {
                'total_cached': total,
                'private_ips': private,
                'public_ips': public,
                'cache_file': self.cache_db_path
            }
        except Exception as e:
            self.logger.error(f"❌ Error obteniendo stats: {e}")
            return {}


def main():
    """Función de prueba del geolocalizador"""
    print("🌍 PRUEBA DEL GEOLOCALIZADOR IP")
    print("=" * 50)

    geolocator = IPGeoLocator()

    # IPs de prueba (basadas en los logs del usuario)
    test_ips = [
        '172.224.53.8',  # IP externa del log
        '192.168.1.123',  # IP local del log
        '34.117.41.85',  # Google Cloud del log
        '8.8.8.8',  # Google DNS para prueba
        '1.1.1.1'  # Cloudflare para prueba
    ]

    for ip in test_ips:
        print(f"\n🔍 Geolocalizando {ip}...")
        location = geolocator.geolocate_ip(ip)

        if location:
            print(f"✅ {ip}:")
            print(f"   📍 Coordenadas: {location.latitude}, {location.longitude}")
            print(f"   🏙️  Ciudad: {location.city}")
            print(f"   🌍 País: {location.country}")
            print(f"   🏢 ISP: {location.isp}")
            print(f"   🔒 Privada: {location.is_private}")
        else:
            print(f"❌ No se pudo geolocalizar {ip}")

    # Mostrar estadísticas del cache
    print(f"\n📊 ESTADÍSTICAS DEL CACHE:")
    stats = geolocator.get_cache_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")


if __name__ == "__main__":
    main()