#!/usr/bin/env python3
"""
Script para generar lista de archivos pcap.gz
"""
import os
import argparse
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Headers para simular un navegador
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}


def find_pcap_links(url, year_pattern):
    """Busca enlaces a archivos pcap.gz en páginas diarias"""
    try:
        response = requests.get(url, timeout=30, headers=HEADERS)
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Error al acceder a {url}: {str(e)}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    pcap_links = []

    # Buscar enlaces a páginas diarias
    for link in soup.find_all('a'):
        href = link.get('href')
        if not href or href in ['../', '/']:
            continue

        full_url = urljoin(url, href)
        filename = href.rstrip('/')

        # Si es una página diaria que coincide con el patrón del año
        if href.endswith('.html') and re.match(year_pattern, os.path.splitext(filename)[0]):
            logger.info(f"Encontrada página diaria: {full_url}")
            # Procesar la página diaria para encontrar archivos pcap
            pcap_links.extend(process_daily_page(full_url))

    return pcap_links


def process_daily_page(url):
    """Extrae enlaces pcap.gz de una página diaria"""
    try:
        logger.info(f"Procesando página diaria: {url}")
        response = requests.get(url, timeout=30, headers=HEADERS)
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Error al acceder a {url}: {str(e)}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    daily_pcaps = []

    # Buscar enlaces a archivos pcap en la página diaria
    for link in soup.find_all('a'):
        href = link.get('href')
        if href and (href.endswith('.pcap.gz') or href.endswith('_peap.gz')):
            full_url = urljoin(url, href)
            logger.info(f"Encontrado archivo pcap: {full_url}")
            daily_pcaps.append(full_url)

    return daily_pcaps


def main():
    parser = argparse.ArgumentParser(description='Generar lista de URLs de archivos pcap.gz del repositorio MAWI')
    parser.add_argument('--year', required=True, help='Año de los datos a descargar')
    parser.add_argument('--output-list', required=True, help='Archivo de salida para la lista de URLs')
    args = parser.parse_args()

    base_url = f"http://mawi.wide.ad.jp/mawi/samplepoint-F/{args.year}/"
    year_pattern = re.compile(rf"^{args.year}\d{{8}}$")

    logger.info(f"Buscando archivos para el año {args.year}...")
    pcap_urls = find_pcap_links(base_url, year_pattern)

    if not pcap_urls:
        logger.warning("No se encontraron archivos pcap.gz")
        return

    logger.info(f"Encontrados {len(pcap_urls)} archivos. Guardando lista en {args.output_list}")

    with open(args.output_list, 'w') as f:
        for url in pcap_urls:
            f.write(url + '\n')

    logger.info("Proceso completado. Usa 'wget -i <archivo> -P <directorio>' para descargar los archivos.")


if __name__ == "__main__":
    main()