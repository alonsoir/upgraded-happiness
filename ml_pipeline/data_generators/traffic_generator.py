#!/usr/bin/env python3
"""
Traffic Generator para Promiscuous Agent v2
Genera tráfico masivo hacia sitios web legítimos para entrenar el modelo
"""

import csv
import time
import random
import requests
import threading
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import socket
from dataclasses import dataclass
from typing import List, Dict
import argparse


@dataclass
class WebSite:
    """Representación de un sitio web"""
    site: str
    country: str
    category: str
    description: str

    def get_urls(self):
        """Genera múltiples URLs para el sitio"""
        base_urls = [
            f"https://{self.site}",
            f"http://{self.site}",
            f"https://www.{self.site}",
        ]

        # URLs adicionales comunes
        paths = ['', '/', '/api', '/news', '/about', '/contact', '/search']
        urls = []

        for base in base_urls[:2]:  # Solo HTTPS y HTTP principal
            for path in paths[:3]:  # Solo las 3 primeras rutas
                urls.append(f"{base}{path}")

        return urls


class TrafficGenerator:
    """Generador de tráfico masivo controlado"""

    def __init__(self, websites_file='websites_database.csv'):
        self.websites_file = websites_file
        self.websites = []
        self.running = True
        self.stats = {
            'requests_made': 0,
            'successful': 0,
            'failed': 0,
            'countries_hit': set(),
            'categories_hit': set(),
            'start_time': time.time()
        }

        # Configuración de requests
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        # Timeouts agresivos para generar muchas conexiones rápidas
        self.session.timeout = (3, 5)  # 3s conexión, 5s lectura

        # Señales para parada limpia
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.load_websites()

    def load_websites(self):
        """Carga sitios web del CSV"""
        try:
            with open(self.websites_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    website = WebSite(
                        site=row['site'].strip(),
                        country=row['country'].strip(),
                        category=row['category'].strip(),
                        description=row['description'].strip()
                    )
                    self.websites.append(website)

            print(f"✅ Cargados {len(self.websites)} sitios web")

            # Mostrar distribución por países
            countries = {}
            for site in self.websites:
                countries[site.country] = countries.get(site.country, 0) + 1

            print(f"🌍 Países representados: {len(countries)}")
            top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]
            for country, count in top_countries:
                print(f"   {country}: {count} sitios")

        except FileNotFoundError:
            print(f"❌ No se encontró {self.websites_file}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error cargando sitios: {e}")
            sys.exit(1)

    def _signal_handler(self, signum, frame):
        """Maneja señales para parada limpia"""
        print(f"\n🛑 Recibida señal {signum}, parando generador...")
        self.running = False

    def make_request(self, url: str, website: WebSite) -> Dict:
        """Hace una request HTTP a una URL"""
        result = {
            'url': url,
            'website': website,
            'success': False,
            'status_code': None,
            'response_time': 0,
            'error': None,
            'ip_resolved': None
        }

        if not self.running:
            return result

        try:
            start_time = time.time()

            # Resolver IP para generar tráfico DNS también
            parsed = urlparse(url)
            hostname = parsed.netloc
            try:
                ip = socket.gethostbyname(hostname)
                result['ip_resolved'] = ip
            except:
                pass

            # Hacer request HTTP
            response = self.session.get(
                url,
                timeout=self.session.timeout,
                allow_redirects=True,
                stream=False  # No descargar contenido completo
            )

            result['response_time'] = time.time() - start_time
            result['status_code'] = response.status_code
            result['success'] = 200 <= response.status_code < 400

            # Solo leer primeros 1KB para generar tráfico sin sobrecargar
            content = response.content[:1024] if response.content else b''

        except requests.exceptions.Timeout:
            result['error'] = 'timeout'
        except requests.exceptions.ConnectionError:
            result['error'] = 'connection_error'
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)[:50]
        except Exception as e:
            result['error'] = f"unexpected: {str(e)[:30]}"

        return result

    def update_stats(self, result: Dict):
        """Actualiza estadísticas"""
        self.stats['requests_made'] += 1

        if result['success']:
            self.stats['successful'] += 1
            self.stats['countries_hit'].add(result['website'].country)
            self.stats['categories_hit'].add(result['website'].category)
        else:
            self.stats['failed'] += 1

    def print_stats(self):
        """Imprime estadísticas actuales"""
        elapsed = time.time() - self.stats['start_time']
        rps = self.stats['requests_made'] / elapsed if elapsed > 0 else 0

        print("\n" + "=" * 60)
        print("📊 ESTADÍSTICAS DEL GENERADOR DE TRÁFICO")
        print("=" * 60)
        print(f"⏱️  Tiempo transcurrido: {elapsed:.1f}s")
        print(f"📡 Requests totales: {self.stats['requests_made']:,}")
        print(f"✅ Exitosos: {self.stats['successful']:,}")
        print(f"❌ Fallidos: {self.stats['failed']:,}")
        print(f"🚀 Velocidad: {rps:.1f} requests/segundo")
        print(f"🌍 Países alcanzados: {len(self.stats['countries_hit'])}")
        print(f"📂 Categorías: {len(self.stats['categories_hit'])}")

        if self.stats['countries_hit']:
            countries_list = list(self.stats['countries_hit'])[:15]
            print(f"🗺️  Países: {', '.join(countries_list)}")
            if len(self.stats['countries_hit']) > 15:
                print(f"   ... y {len(self.stats['countries_hit']) - 15} más")

        print("=" * 60)

    def generate_traffic_batch(self, batch_size=50, max_workers=20):
        """Genera un lote de tráfico usando ThreadPool"""
        print(f"🚀 Generando lote de {batch_size} requests con {max_workers} workers...")

        # Seleccionar sitios aleatoriamente, priorizando diversidad de países
        selected_websites = random.sample(self.websites, min(batch_size, len(self.websites)))

        # Generar todas las URLs para este batch
        all_tasks = []
        for website in selected_websites:
            urls = website.get_urls()
            # Tomar solo 1-2 URLs por sitio para no saturar
            selected_urls = random.sample(urls, min(2, len(urls)))
            for url in selected_urls:
                all_tasks.append((url, website))

        # Mezclar tareas para mejor distribución
        random.shuffle(all_tasks)

        # Ejecutar en paralelo
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Enviar todas las tareas
            future_to_task = {
                executor.submit(self.make_request, url, website): (url, website)
                for url, website in all_tasks
            }

            # Procesar resultados conforme completan
            completed = 0
            for future in as_completed(future_to_task):
                if not self.running:
                    break

                try:
                    result = future.result()
                    self.update_stats(result)
                    completed += 1

                    # Progress cada 10 requests
                    if completed % 10 == 0:
                        print(f"📈 Progreso: {completed}/{len(all_tasks)} requests completados")

                except Exception as e:
                    print(f"⚠️ Error en future: {e}")

        print(f"✅ Lote completado: {completed} requests procesados")

    def run_continuous(self, batch_size=50, batch_interval=10, max_batches=None):
        """Ejecuta generación continua de tráfico"""
        print(f"🌐 Iniciando generación continua de tráfico...")
        print(f"📊 Configuración:")
        print(f"   - Batch size: {batch_size} requests")
        print(f"   - Intervalo: {batch_interval} segundos")
        print(f"   - Máx batches: {max_batches or 'Ilimitado'}")
        print(f"   - Sitios disponibles: {len(self.websites)}")
        print()

        batch_count = 0

        try:
            while self.running:
                batch_count += 1
                print(f"\n🔄 Ejecutando batch #{batch_count}...")

                self.generate_traffic_batch(batch_size)

                # Mostrar estadísticas cada 3 batches
                if batch_count % 3 == 0:
                    self.print_stats()

                # Verificar límite de batches
                if max_batches and batch_count >= max_batches:
                    print(f"🏁 Límite de {max_batches} batches alcanzado")
                    break

                # Pausa entre batches
                if self.running and batch_interval > 0:
                    print(f"⏸️  Pausa de {batch_interval}s antes del siguiente batch...")
                    time.sleep(batch_interval)

        except KeyboardInterrupt:
            print("\n🛑 Interrupción por usuario")
        finally:
            self.running = False
            self.print_stats()
            print("\n🎯 Generación de tráfico finalizada")

    def run_turbo_mode(self, duration_minutes=5):
        """Modo turbo: genera tráfico máximo por tiempo limitado"""
        print(f"🚀 MODO TURBO ACTIVADO - {duration_minutes} minutos")
        print("⚠️  Generando tráfico máximo para acelerar captura...")

        end_time = time.time() + (duration_minutes * 60)
        batch_count = 0

        while self.running and time.time() < end_time:
            batch_count += 1
            remaining = (end_time - time.time()) / 60

            print(f"\n⚡ Turbo batch #{batch_count} - {remaining:.1f}min restantes")

            # Batches más grandes y rápidos en modo turbo
            self.generate_traffic_batch(batch_size=100, max_workers=30)

            # Sin pausa entre batches en modo turbo
            if batch_count % 2 == 0:
                self.print_stats()

        print(f"\n🏁 Modo turbo completado - {batch_count} batches ejecutados")
        self.print_stats()


def main():
    parser = argparse.ArgumentParser(description="Generador de Tráfico para Promiscuous Agent v2")
    parser.add_argument("--mode", choices=['continuous', 'turbo', 'single'], default='continuous',
                        help="Modo de operación")
    parser.add_argument("--batch-size", type=int, default=50,
                        help="Número de requests por batch")
    parser.add_argument("--interval", type=int, default=10,
                        help="Intervalo entre batches (segundos)")
    parser.add_argument("--duration", type=int, default=5,
                        help="Duración en minutos (solo modo turbo)")
    parser.add_argument("--max-batches", type=int,
                        help="Máximo número de batches (modo continuo)")
    parser.add_argument("--websites", default="websites_database.csv",
                        help="Archivo CSV con sitios web")

    args = parser.parse_args()

    # Crear generador
    generator = TrafficGenerator(args.websites)

    if args.mode == 'single':
        print("🎯 Ejecutando un solo batch...")
        generator.generate_traffic_batch(args.batch_size)
        generator.print_stats()

    elif args.mode == 'turbo':
        generator.run_turbo_mode(args.duration)

    else:  # continuous
        generator.run_continuous(
            batch_size=args.batch_size,
            batch_interval=args.interval,
            max_batches=args.max_batches
        )


if __name__ == "__main__":
    main()
