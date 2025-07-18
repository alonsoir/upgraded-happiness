#!/usr/bin/env python3
"""
quick_start.py - Script de Inicio Rápido para Sistema SCADA
Diagnóstico automático, reparación y verificación del sistema completo
Uso: python quick_start.py [--auto-fix] [--skip-training] [--quick]
"""

import sys
import os
import json
import time
import subprocess
import argparse
import logging
from pathlib import Path
from datetime import datetime
import requests

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SCADAQuickStart:
    def __init__(self, auto_fix=False, skip_training=False, quick_mode=False):
        self.auto_fix = auto_fix
        self.skip_training = skip_training
        self.quick_mode = quick_mode
        self.dashboard_url = "http://localhost:8000"
        self.required_files = [
            'diagnostic_script.py',
            'config_fixer.py',
            'retrain_models.py',
            'geolocation_fallback.py'
        ]

    def print_banner(self):
        """Mostrar banner de inicio"""
        print("\n" + "=" * 70)
        print("🚀 UPGRADED HAPPINESS - SCADA QUICK START")
        print("=" * 70)
        print("🎯 Diagnóstico automático y reparación del sistema")
        print(f"⚡ Modo: {'Auto-fix' if self.auto_fix else 'Manual'}")
        print(f"🏃 Quick mode: {'Enabled' if self.quick_mode else 'Disabled'}")
        print(f"🤖 Training: {'Skipped' if self.skip_training else 'Included'}")
        print("=" * 70)

    def check_prerequisites(self):
        """Verificar prerequisitos del sistema"""
        logger.info("🔍 Verificando prerequisitos...")

        issues = []

        # Verificar Python y librerías
        try:
            import sklearn
            import zmq
            import psutil
            import requests
            import pandas
            import numpy
            logger.info("✅ Librerías Python disponibles")
        except ImportError as e:
            issues.append(f"Librería faltante: {e}")

        # Verificar archivos de script requeridos
        missing_scripts = []
        for script in self.required_files:
            if not Path(script).exists():
                missing_scripts.append(script)

        if missing_scripts:
            issues.append(f"Scripts faltantes: {missing_scripts}")
        else:
            logger.info("✅ Scripts requeridos disponibles")

        # Verificar directorios
        required_dirs = ['logs', 'models', 'data']
        for directory in required_dirs:
            Path(directory).mkdir(exist_ok=True)
        logger.info("✅ Directorios creados/verificados")

        # Verificar permisos
        if os.name != 'nt':  # No Windows
            try:
                result = subprocess.run(['sudo', '-n', 'true'], capture_output=True)
                if result.returncode != 0:
                    issues.append("Se requieren permisos sudo para captura de paquetes")
            except:
                issues.append("No se pudo verificar permisos sudo")

        if issues:
            logger.error("❌ Problemas encontrados:")
            for issue in issues:
                logger.error(f"   • {issue}")
            return False
        else:
            logger.info("✅ Todos los prerequisitos satisfechos")
            return True

    def run_diagnostic(self):
        """Ejecutar diagnóstico completo"""
        logger.info("🔍 Ejecutando diagnóstico completo...")

        try:
            result = subprocess.run([
                sys.executable, 'diagnostic_script.py', '--json'
            ], capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                diagnostic_data = json.loads(result.stdout)
                logger.info("✅ Diagnóstico completado")
                return diagnostic_data
            else:
                logger.error(f"❌ Error en diagnóstico: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error("❌ Diagnóstico timeout (>60s)")
            return None
        except Exception as e:
            logger.error(f"❌ Error ejecutando diagnóstico: {e}")
            return None

    def analyze_diagnostic_results(self, diagnostic_data):
        """Analizar resultados del diagnóstico y determinar acciones"""
        if not diagnostic_data:
            return {'critical': True, 'actions': ['manual_intervention']}

        actions = []
        critical_issues = 0

        # Analizar sistema
        if not diagnostic_data.get('overall_health', {}).get('system', False):
            actions.append('restart_system')
            critical_issues += 1

        # Analizar geolocalización
        if not diagnostic_data.get('overall_health', {}).get('geolocation', False):
            actions.append('fix_geolocation')
            critical_issues += 1

        # Analizar modelos ML
        if not diagnostic_data.get('overall_health', {}).get('ml_models', False):
            actions.append('retrain_models')
            critical_issues += 1

        # Analizar eventos
        events = diagnostic_data.get('events_analysis', {})
        if events.get('unknown_ratio', 0) > 0.5:
            actions.append('fix_geolocation')
            critical_issues += 1

        if events.get('avg_risk_score', 0) < 0.1:
            actions.append('fix_configs')
            critical_issues += 1

        return {
            'critical': critical_issues > 2,
            'actions': actions,
            'issues_count': critical_issues,
            'diagnostic_data': diagnostic_data
        }

    def fix_configurations(self):
        """Reparar configuraciones"""
        logger.info("🔧 Reparando configuraciones...")

        try:
            result = subprocess.run([
                sys.executable, 'config_fixer.py'
            ], capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                logger.info("✅ Configuraciones reparadas")
                return True
            else:
                logger.error(f"❌ Error reparando configuraciones: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"❌ Error ejecutando reparación: {e}")
            return False

    def retrain_models(self):
        """Reentrenar modelos ML"""
        if self.skip_training:
            logger.info("⏭️ Entrenamiento omitido por --skip-training")
            return True

        logger.info("🤖 Reentrenando modelos ML...")

        try:
            cmd = [sys.executable, 'retrain_models.py', '--force']
            if self.quick_mode:
                cmd.append('--quick')

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                logger.info("✅ Modelos ML reentrenados")
                return True
            else:
                logger.error(f"❌ Error reentrenando modelos: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("❌ Entrenamiento timeout (>5min)")
            return False
        except Exception as e:
            logger.error(f"❌ Error ejecutando entrenamiento: {e}")
            return False

    def fix_geolocation(self):
        """Reparar servicio de geolocalización"""
        logger.info("🌍 Reparando geolocalización...")

        # Test del servicio de geolocalización
        try:
            result = subprocess.run([
                sys.executable, 'geolocation_fallback.py', 'test'
            ], capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                logger.info("✅ Servicio de geolocalización funcionando")
                return True
            else:
                logger.warning("⚠️ Problemas en geolocalización, continuando...")
                return True  # No crítico

        except Exception as e:
            logger.warning(f"⚠️ Error verificando geolocalización: {e}")
            return True  # No crítico

    def restart_system_processes(self):
        """Reiniciar procesos del sistema"""
        logger.info("🔄 Reiniciando procesos del sistema...")

        try:
            # Intentar usar make si está disponible
            if Path('Makefile').exists():
                logger.info("📋 Usando Makefile...")

                # Stop
                subprocess.run(['make', 'stop-firewall'], timeout=30)
                time.sleep(3)

                # Start
                result = subprocess.run(['make', 'run-firewall'], timeout=30)
                if result.returncode == 0:
                    logger.info("✅ Sistema reiniciado via Makefile")
                    return True

            # Fallback manual
            logger.info("🔧 Fallback a arranque manual...")

            # Matar procesos existentes
            for process_name in ['promiscuous_agent.py', 'ml_detector_with_persistence.py',
                                 'real_zmq_dashboard_with_firewall.py', 'firewall_agent.py']:
                try:
                    subprocess.run(['pkill', '-f', process_name], timeout=10)
                except:
                    pass

            time.sleep(3)
            logger.info("✅ Procesos antiguos terminados")
            return True

        except subprocess.TimeoutExpired:
            logger.error("❌ Timeout reiniciando sistema")
            return False
        except Exception as e:
            logger.error(f"❌ Error reiniciando sistema: {e}")
            return False

    def verify_system_health(self):
        """Verificar que el sistema esté funcionando después de las reparaciones"""
        logger.info("🏥 Verificando salud del sistema...")

        # Esperar a que el sistema se inicialice
        logger.info("⏳ Esperando inicialización del sistema...")
        time.sleep(10)

        # Verificar endpoints del dashboard
        endpoints = ['/health', '/api/stats']
        working_endpoints = 0

        for endpoint in endpoints:
            try:
                response = requests.get(f"{self.dashboard_url}{endpoint}", timeout=5)
                if response.status_code == 200:
                    working_endpoints += 1
                    logger.info(f"✅ {endpoint}: OK")
                else:
                    logger.warning(f"⚠️ {endpoint}: HTTP {response.status_code}")
            except Exception as e:
                logger.warning(f"⚠️ {endpoint}: {e}")

        # Verificar eventos
        try:
            response = requests.get(f"{self.dashboard_url}/api/events/gps", timeout=5)
            if response.status_code == 200:
                events = response.json()
                logger.info(f"📊 Eventos disponibles: {len(events)}")
                working_endpoints += 1
        except Exception as e:
            logger.warning(f"⚠️ Error verificando eventos: {e}")

        health_score = working_endpoints / 3
        if health_score >= 0.66:
            logger.info(f"✅ Sistema saludable ({health_score:.1%})")
            return True
        else:
            logger.warning(f"⚠️ Sistema parcialmente funcional ({health_score:.1%})")
            return False

    def run_auto_fix(self, analysis):
        """Ejecutar reparación automática basada en análisis"""
        logger.info("🤖 Iniciando reparación automática...")

        actions = analysis['actions']
        success_count = 0

        for action in actions:
            logger.info(f"🔧 Ejecutando: {action}")

            if action == 'fix_configs':
                if self.fix_configurations():
                    success_count += 1

            elif action == 'retrain_models':
                if self.retrain_models():
                    success_count += 1

            elif action == 'fix_geolocation':
                if self.fix_geolocation():
                    success_count += 1

            elif action == 'restart_system':
                if self.restart_system_processes():
                    success_count += 1

            time.sleep(2)  # Pausa entre acciones

        success_rate = success_count / len(actions) if actions else 1.0
        logger.info(f"🎯 Reparación completada: {success_count}/{len(actions)} acciones exitosas ({success_rate:.1%})")

        return success_rate >= 0.7

    def show_manual_instructions(self, analysis):
        """Mostrar instrucciones manuales"""
        print("\n" + "=" * 60)
        print("📋 INSTRUCCIONES MANUALES")
        print("=" * 60)

        actions = analysis['actions']
        for i, action in enumerate(actions, 1):
            print(f"\n{i}. {action.upper().replace('_', ' ')}")

            if action == 'fix_configs':
                print("   🔧 python config_fixer.py")

            elif action == 'retrain_models':
                print("   🤖 python retrain_models.py --force")
                if self.quick_mode:
                    print("      (añadir --quick para modo rápido)")

            elif action == 'fix_geolocation':
                print("   🌍 python geolocation_fallback.py test")
                print("   📥 Descargar GeoIP: wget -O data/GeoLite2-City.mmdb ...")

            elif action == 'restart_system':
                print("   🔄 make stop-firewall && make run-firewall")
                print("   💡 O reiniciar procesos manualmente")

        print(f"\n🔍 Después ejecutar: python diagnostic_script.py")
        print("=" * 60)

    def run(self):
        """Ejecutar proceso completo de quick start"""
        self.print_banner()

        # 1. Verificar prerequisitos
        if not self.check_prerequisites():
            logger.error("❌ Prerequisitos no satisfechos, abortando")
            return 1

        # 2. Ejecutar diagnóstico
        diagnostic_data = self.run_diagnostic()
        if not diagnostic_data:
            logger.error("❌ No se pudo ejecutar diagnóstico")
            return 1

        # 3. Analizar resultados
        analysis = self.analyze_diagnostic_results(diagnostic_data)

        # Mostrar resumen
        print(f"\n📊 RESUMEN DEL DIAGNÓSTICO:")
        print(f"   🎯 Problemas encontrados: {analysis['issues_count']}")
        print(f"   🚨 Crítico: {'Sí' if analysis['critical'] else 'No'}")
        print(f"   🔧 Acciones requeridas: {len(analysis['actions'])}")

        if not analysis['actions']:
            logger.info("🎉 ¡Sistema en perfecto estado!")
            return 0

        # 4. Ejecutar reparaciones
        if self.auto_fix:
            success = self.run_auto_fix(analysis)

            if success:
                # 5. Verificar salud post-reparación
                if self.verify_system_health():
                    logger.info("🎉 ¡Reparación completada exitosamente!")
                    print(f"\n🌐 Dashboard disponible en: {self.dashboard_url}")
                    return 0
                else:
                    logger.warning("⚠️ Sistema reparado pero con problemas menores")
                    return 2
            else:
                logger.error("❌ Reparación automática falló")
                self.show_manual_instructions(analysis)
                return 3
        else:
            # Modo manual
            self.show_manual_instructions(analysis)
            return 1


def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description='Quick Start para Sistema SCADA')
    parser.add_argument('--auto-fix', action='store_true',
                        help='Ejecutar reparaciones automáticamente')
    parser.add_argument('--skip-training', action='store_true',
                        help='Omitir reentrenamiento de modelos ML')
    parser.add_argument('--quick', action='store_true',
                        help='Modo rápido (menos estimadores en ML)')

    args = parser.parse_args()

    quick_start = SCADAQuickStart(
        auto_fix=args.auto_fix,
        skip_training=args.skip_training,
        quick_mode=args.quick
    )

    return quick_start.run()


if __name__ == "__main__":
    sys.exit(main())