#!/usr/bin/env python3
"""
diagnostic_script.py - Diagnóstico Automático para Sistema SCADA
Analiza y corrige problemas de eventos "unknown" y modelos ML degradados
Uso: python diagnostic_script.py [--json]
"""

import json
import requests
import subprocess
import psutil
import logging
import time
from pathlib import Path
from datetime import datetime
import zmq
import sys
import os

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SCADADiagnostic:
    def __init__(self):
        self.dashboard_url = "http://localhost:8000"
        self.zmq_ports = {
            'capture': 5559,
            'ml_enhanced': 5560,
            'firewall': 5561
        }
        self.processes = [
            'promiscuous_agent.py',
            'ml_detector_with_persistence.py',
            'real_zmq_dashboard_with_firewall.py',
            'firewall_agent.py'
        ]

    def check_system_status(self):
        """Verificar estado general del sistema"""
        logger.info("🔍 Verificando estado del sistema...")

        # 1. Verificar procesos
        running_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline'])
                for process_name in self.processes:
                    if process_name in cmdline:
                        running_processes.append({
                            'name': process_name,
                            'pid': proc.info['pid'],
                            'status': 'RUNNING'
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        logger.info(f"✅ Procesos en ejecución: {len(running_processes)}/4")
        for proc in running_processes:
            logger.info(f"   {proc['name']} (PID: {proc['pid']})")

        # 2. Verificar puertos ZeroMQ
        open_ports = []
        for name, port in self.zmq_ports.items():
            try:
                result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
                if f":{port}" in result.stdout:
                    open_ports.append(port)
                    logger.info(f"✅ Puerto {name} ({port}): ABIERTO")
                else:
                    logger.warning(f"⚠️ Puerto {name} ({port}): CERRADO")
            except Exception as e:
                logger.error(f"❌ Error verificando puerto {port}: {e}")

        return {
            'processes': running_processes,
            'ports': open_ports,
            'system_healthy': len(running_processes) >= 3 and len(open_ports) >= 2
        }

    def check_geolocation_service(self):
        """Diagnosticar servicio de geolocalización"""
        logger.info("🌍 Verificando servicio de geolocalización...")

        test_ips = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        geoip_services = [
            'http://ip-api.com/json/{}',
            'https://ipapi.co/{}/json/',
            'https://freegeoip.app/json/{}'
        ]

        results = {}
        for ip in test_ips:
            results[ip] = {'resolved': False, 'coordinates': None}

            for service_url in geoip_services:
                try:
                    response = requests.get(service_url.format(ip), timeout=5)
                    if response.status_code == 200:
                        data = response.json()

                        # Diferentes formatos de respuesta
                        lat, lon = None, None
                        if 'lat' in data and 'lon' in data:
                            lat, lon = data['lat'], data['lon']
                        elif 'latitude' in data and 'longitude' in data:
                            lat, lon = data['latitude'], data['longitude']

                        if lat is not None and lon is not None:
                            results[ip] = {
                                'resolved': True,
                                'coordinates': (lat, lon),
                                'service': service_url
                            }
                            logger.info(f"✅ {ip}: {lat}, {lon}")
                            break

                except Exception as e:
                    logger.debug(f"Error en servicio {service_url}: {e}")
                    continue

            if not results[ip]['resolved']:
                logger.warning(f"⚠️ No se pudo resolver geolocalización para {ip}")

        resolved_count = sum(1 for r in results.values() if r['resolved'])
        return {
            'results': results,
            'success_rate': resolved_count / len(test_ips),
            'service_healthy': resolved_count > 0
        }

    def check_ml_models(self):
        """Verificar estado de modelos ML"""
        logger.info("🤖 Verificando modelos ML...")

        expected_models = [
            'IsolationForest',
            'OneClassSVM',
            'EllipticEnvelope',
            'LocalOutlierFactor',
            'RandomForest',
            'XGBoost'
        ]

        # Verificar archivos de modelos
        model_files = []
        models_dir = Path('models')
        if models_dir.exists():
            model_files = list(models_dir.glob('*.pkl'))
            logger.info(f"📁 Archivos de modelos encontrados: {len(model_files)}")
            for model_file in model_files:
                logger.info(f"   {model_file.name}")
        else:
            logger.warning("⚠️ Directorio 'models' no encontrado")

        # Verificar importaciones de sklearn
        try:
            import sklearn
            from sklearn.ensemble import IsolationForest, RandomForest
            from sklearn.svm import OneClassSVM
            from sklearn.covariance import EllipticEnvelope
            from sklearn.neighbors import LocalOutlierFactor
            logger.info(f"✅ scikit-learn versión: {sklearn.__version__}")
        except ImportError as e:
            logger.error(f"❌ Error importando sklearn: {e}")
            return {'healthy': False, 'error': str(e)}

        # Verificar XGBoost
        try:
            import xgboost as xgb
            logger.info(f"✅ XGBoost versión: {xgb.__version__}")
        except ImportError:
            logger.warning("⚠️ XGBoost no disponible")

        return {
            'expected_models': expected_models,
            'model_files': [f.name for f in model_files],
            'sklearn_available': True,
            'models_count': len(model_files),
            'healthy': len(model_files) >= 4
        }

    def check_dashboard_api(self):
        """Verificar API del dashboard"""
        logger.info("📊 Verificando API del dashboard...")

        endpoints = [
            '/health',
            '/api/stats',
            '/api/events/gps',
            '/api/firewall/log'
        ]

        results = {}
        for endpoint in endpoints:
            try:
                response = requests.get(f"{self.dashboard_url}{endpoint}", timeout=5)
                results[endpoint] = {
                    'status_code': response.status_code,
                    'accessible': response.status_code == 200,
                    'response_size': len(response.text)
                }

                if endpoint == '/api/stats' and response.status_code == 200:
                    try:
                        stats = response.json()
                        results[endpoint]['unknown_ratio'] = stats.get('unknown_events_ratio', 0)
                        results[endpoint]['total_events'] = stats.get('total_events', 0)
                    except:
                        pass

                logger.info(f"✅ {endpoint}: {response.status_code}")
            except Exception as e:
                results[endpoint] = {
                    'accessible': False,
                    'error': str(e)
                }
                logger.warning(f"⚠️ {endpoint}: Error - {e}")

        accessible_count = sum(1 for r in results.values() if r.get('accessible', False))
        return {
            'results': results,
            'accessibility_rate': accessible_count / len(endpoints),
            'dashboard_healthy': accessible_count >= 2
        }

    def get_live_events_sample(self):
        """Obtener muestra de eventos en vivo"""
        logger.info("📡 Analizando eventos en vivo...")

        try:
            response = requests.get(f"{self.dashboard_url}/api/events/gps", timeout=10)
            if response.status_code == 200:
                events = response.json()

                if not events:
                    return {'error': 'No hay eventos disponibles'}

                # Analizar últimos 10 eventos
                recent_events = events[-10:] if len(events) > 10 else events

                unknown_count = 0
                coordinate_count = 0
                risk_scores = []
                anomaly_scores = []

                for event in recent_events:
                    # Verificar eventos unknown
                    if (event.get('source_ip') == 'unknown' or
                            event.get('target_ip') == 'unknown' or
                            event.get('event_type') == 'unknown'):
                        unknown_count += 1

                    # Verificar coordenadas
                    if (event.get('latitude', 0) != 0 and
                            event.get('longitude', 0) != 0):
                        coordinate_count += 1

                    # Recolectar scores
                    risk_scores.append(event.get('risk_score', 0))
                    anomaly_scores.append(event.get('anomaly_score', 0))

                return {
                    'total_events': len(recent_events),
                    'unknown_count': unknown_count,
                    'unknown_ratio': unknown_count / len(recent_events),
                    'coordinate_count': coordinate_count,
                    'coordinate_ratio': coordinate_count / len(recent_events),
                    'avg_risk_score': sum(risk_scores) / len(risk_scores),
                    'avg_anomaly_score': sum(anomaly_scores) / len(anomaly_scores),
                    'max_risk_score': max(risk_scores),
                    'sample_events': recent_events[:3]  # Muestra de 3 eventos
                }
            else:
                return {'error': f'Error API: {response.status_code}'}

        except Exception as e:
            return {'error': f'Excepción: {str(e)}'}

    def generate_recommendations(self, system_status, geo_status, ml_status, dashboard_status, events_analysis):
        """Generar recomendaciones basadas en diagnóstico"""
        recommendations = []
        priority_actions = []

        # Análisis de eventos unknown
        if 'unknown_ratio' in events_analysis and events_analysis['unknown_ratio'] > 0.5:
            priority_actions.append({
                'priority': 'HIGH',
                'issue': f"Alto ratio de eventos unknown: {events_analysis['unknown_ratio']:.1%}",
                'solution': "Revisar servicio de geolocalización en promiscuous_agent.py",
                'commands': [
                    "tail -f logs/agent.out | grep -i geolocat",
                    "python -c \"import requests; print(requests.get('http://ip-api.com/json/8.8.8.8').json())\""
                ]
            })

        # Análisis de coordenadas
        if 'coordinate_ratio' in events_analysis and events_analysis['coordinate_ratio'] < 0.1:
            priority_actions.append({
                'priority': 'HIGH',
                'issue': f"Pocas coordenadas resueltas: {events_analysis['coordinate_ratio']:.1%}",
                'solution': "Actualizar base de datos GeoIP",
                'commands': [
                    "wget -O data/GeoLite2-City.mmdb https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
                    "systemctl restart promiscuous-agent"
                ]
            })

        # Análisis de modelos ML
        if not ml_status['healthy']:
            priority_actions.append({
                'priority': 'MEDIUM',
                'issue': f"Solo {ml_status['models_count']} modelos disponibles (esperados: 6)",
                'solution': "Reentrenar modelos ML",
                'commands': [
                    "python retrain_models.py --force --all-models",
                    "python -c \"import sklearn; print('sklearn version:', sklearn.__version__)\""
                ]
            })

        # Análisis de risk scores
        if 'avg_risk_score' in events_analysis and events_analysis['avg_risk_score'] < 0.1:
            recommendations.append({
                'priority': 'MEDIUM',
                'issue': f"Risk scores muy bajos (promedio: {events_analysis['avg_risk_score']:.3f})",
                'solution': "Ajustar umbrales de detección en lightweight_ml_detector_config.json"
            })

        # Análisis de procesos
        if not system_status['system_healthy']:
            priority_actions.append({
                'priority': 'HIGH',
                'issue': f"Solo {len(system_status['processes'])}/4 procesos ejecutándose",
                'solution': "Reiniciar sistema completo",
                'commands': [
                    "make stop-firewall",
                    "make run-firewall"
                ]
            })

        return {
            'priority_actions': priority_actions,
            'recommendations': recommendations,
            'action_count': len(priority_actions) + len(recommendations)
        }

    def run_full_diagnostic(self):
        """Ejecutar diagnóstico completo"""
        logger.info("🚀 Iniciando diagnóstico completo del sistema SCADA...")
        start_time = time.time()

        # Ejecutar todas las verificaciones
        system_status = self.check_system_status()
        geo_status = self.check_geolocation_service()
        ml_status = self.check_ml_models()
        dashboard_status = self.check_dashboard_api()
        events_analysis = self.get_live_events_sample()

        # Generar recomendaciones
        recommendations = self.generate_recommendations(
            system_status, geo_status, ml_status, dashboard_status, events_analysis
        )

        # Resumen final
        duration = time.time() - start_time

        report = {
            'timestamp': datetime.now().isoformat(),
            'duration_seconds': round(duration, 2),
            'system_status': system_status,
            'geolocation_status': geo_status,
            'ml_status': ml_status,
            'dashboard_status': dashboard_status,
            'events_analysis': events_analysis,
            'recommendations': recommendations,
            'overall_health': {
                'system': system_status.get('system_healthy', False),
                'geolocation': geo_status.get('service_healthy', False),
                'ml_models': ml_status.get('healthy', False),
                'dashboard': dashboard_status.get('dashboard_healthy', False)
            }
        }

        return report

    def print_summary_report(self, report):
        """Imprimir resumen del diagnóstico"""
        print("\n" + "=" * 70)
        print("📋 RESUMEN DIAGNÓSTICO SISTEMA SCADA")
        print("=" * 70)

        print(f"⏱️  Duración: {report['duration_seconds']}s")
        print(f"📅 Timestamp: {report['timestamp']}")

        # Estado general
        print("\n🏥 ESTADO GENERAL:")
        overall = report['overall_health']
        for component, healthy in overall.items():
            status = "✅ BIEN" if healthy else "❌ PROBLEMA"
            print(f"   {component.title()}: {status}")

        # Eventos análisis
        if 'unknown_ratio' in report['events_analysis']:
            events = report['events_analysis']
            print("\n📊 ANÁLISIS DE EVENTOS:")
            print(f"   Total eventos analizados: {events['total_events']}")
            print(f"   Ratio eventos unknown: {events['unknown_ratio']:.1%}")
            print(f"   Ratio coordenadas resueltas: {events.get('coordinate_ratio', 0):.1%}")
            print(f"   Risk score promedio: {events.get('avg_risk_score', 0):.3f}")
            print(f"   Risk score máximo: {events.get('max_risk_score', 0):.3f}")

        # Acciones prioritarias
        priority_actions = report['recommendations']['priority_actions']
        if priority_actions:
            print(f"\n🚨 ACCIONES PRIORITARIAS ({len(priority_actions)}):")
            for i, action in enumerate(priority_actions, 1):
                print(f"   {i}. [{action['priority']}] {action['issue']}")
                print(f"      💡 Solución: {action['solution']}")
                if 'commands' in action:
                    print(f"      🔧 Comandos:")
                    for cmd in action['commands']:
                        print(f"         {cmd}")
                print()
        else:
            print("\n✅ No hay acciones prioritarias requeridas")

        print("=" * 70)


def main():
    """Función principal"""
    if len(sys.argv) > 1 and sys.argv[1] == '--json':
        # Modo JSON para integración con scripts
        diagnostic = SCADADiagnostic()
        report = diagnostic.run_full_diagnostic()
        print(json.dumps(report, indent=2))
    else:
        # Modo interactivo
        diagnostic = SCADADiagnostic()
        report = diagnostic.run_full_diagnostic()
        diagnostic.print_summary_report(report)

        # Guardar reporte
        report_file = f"diagnostic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n💾 Reporte guardado en: {report_file}")


if __name__ == "__main__":
    main()