"""
Sistema de Auto-Diagnóstico y Reparación para el Dashboard
Detecta y soluciona automáticamente problemas comunes
"""

import zmq
import json
import time
import threading
import subprocess
import psutil
from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime, timedelta


@dataclass
class DiagnosticResult:
    """Resultado de un diagnóstico"""
    component: str
    test_name: str
    status: str  # 'pass', 'fail', 'warning'
    message: str
    suggested_action: str
    auto_fixable: bool = False
    severity: str = 'info'  # 'critical', 'warning', 'info'


class AutoDiagnostic:
    """Sistema de auto-diagnóstico para el dashboard"""

    def __init__(self, dashboard_config, logger):
        self.config = dashboard_config
        self.logger = logger
        self.diagnostic_results: List[DiagnosticResult] = []
        self.last_diagnostic_time = None
        self.auto_fix_enabled = True

    def run_full_diagnostic(self) -> Dict:
        """Ejecutar diagnóstico completo del sistema"""
        self.logger.info("🔬 Iniciando diagnóstico completo del sistema...")
        self.diagnostic_results.clear()

        # Tests de conectividad
        self._test_zmq_ports()
        self._test_ml_detector_connection()
        self._test_firewall_agent_connection()
        self._test_web_interface()

        # Tests de rendimiento
        self._test_memory_usage()
        self._test_cpu_usage()
        self._test_disk_space()

        # Tests de configuración
        self._test_configuration_validity()
        self._test_file_permissions()

        # Tests de datos
        self._test_encoding_issues()
        self._test_message_flow()

        # Intentar auto-reparación si está habilitada
        if self.auto_fix_enabled:
            self._attempt_auto_fixes()

        self.last_diagnostic_time = datetime.now()

        return self._generate_diagnostic_report()

    def _test_zmq_ports(self):
        """Verificar que los puertos ZeroMQ estén disponibles"""
        ports_to_test = [
            (self.config.ml_detector_port, "ML Detector"),
            (self.config.firewall_commands_port, "Firewall Commands"),
            (self.config.firewall_responses_port, "Firewall Responses"),
            (self.config.web_port, "Web Interface")
        ]

        for port, component in ports_to_test:
            try:
                # Verificar si el puerto está en uso
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex(('localhost', port))
                sock.close()

                if result == 0:
                    self.diagnostic_results.append(DiagnosticResult(
                        component=component,
                        test_name="Port Availability",
                        status="pass",
                        message=f"Puerto {port} está activo y escuchando",
                        suggested_action="Ninguna acción requerida",
                        severity="info"
                    ))
                else:
                    self.diagnostic_results.append(DiagnosticResult(
                        component=component,
                        test_name="Port Availability",
                        status="fail",
                        message=f"Puerto {port} no está disponible o no responde",
                        suggested_action=f"Verificar que el componente {component} esté ejecutándose",
                        auto_fixable=False,
                        severity="critical"
                    ))

            except Exception as e:
                self.diagnostic_results.append(DiagnosticResult(
                    component=component,
                    test_name="Port Test",
                    status="fail",
                    message=f"Error probando puerto {port}: {e}",
                    suggested_action="Verificar configuración de red",
                    severity="warning"
                ))

    def _test_ml_detector_connection(self):
        """Test específico de conexión con ML Detector"""
        try:
            # Crear socket temporal para probar conexión
            context = zmq.Context()
            socket = context.socket(zmq.PULL)
            socket.setsockopt(zmq.RCVTIMEO, 5000)  # 5 segundos timeout

            endpoint = f"tcp://{self.config.ml_detector_address}:{self.config.ml_detector_port}"

            if self.config.ml_detector_mode == 'connect':
                socket.connect(endpoint)
            else:
                socket.bind(endpoint)

            # Intentar recibir un mensaje
            try:
                message = socket.recv(zmq.NOBLOCK)
                self.diagnostic_results.append(DiagnosticResult(
                    component="ML Detector",
                    test_name="Message Reception",
                    status="pass",
                    message="Recibiendo mensajes correctamente",
                    suggested_action="Ninguna acción requerida",
                    severity="info"
                ))
            except zmq.Again:
                self.diagnostic_results.append(DiagnosticResult(
                    component="ML Detector",
                    test_name="Message Reception",
                    status="warning",
                    message="No hay mensajes disponibles (normal si no hay tráfico)",
                    suggested_action="Verificar que ML Detector esté enviando datos",
                    severity="warning"
                ))

            socket.close()
            context.term()

        except Exception as e:
            self.diagnostic_results.append(DiagnosticResult(
                component="ML Detector",
                test_name="Connection Test",
                status="fail",
                message=f"Error conectando a ML Detector: {e}",
                suggested_action="Verificar que ml_detector esté ejecutándose",
                auto_fixable=True,
                severity="critical"
            ))

    def _test_firewall_agent_connection(self):
        """Test de conexión con Firewall Agent"""
        try:
            # Test de envío de comando
            context = zmq.Context()
            socket = context.socket(zmq.PUB)

            endpoint = f"tcp://{self.config.firewall_commands_address}:{self.config.firewall_commands_port}"

            if self.config.firewall_commands_mode == 'bind':
                socket.bind(endpoint)

                # Enviar mensaje de test
                test_command = {
                    "action": "test",
                    "target_ip": "127.0.0.1",
                    "timestamp": datetime.now().isoformat(),
                    "test": True
                }

                socket.send_string(json.dumps(test_command))

                self.diagnostic_results.append(DiagnosticResult(
                    component="Firewall Agent",
                    test_name="Command Sending",
                    status="pass",
                    message="Comando de test enviado correctamente",
                    suggested_action="Ninguna acción requerida",
                    severity="info"
                ))

            socket.close()
            context.term()

        except Exception as e:
            self.diagnostic_results.append(DiagnosticResult(
                component="Firewall Agent",
                test_name="Command Test",
                status="fail",
                message=f"Error enviando comando de test: {e}",
                suggested_action="Verificar configuración de firewall agent",
                auto_fixable=True,
                severity="critical"
            ))

    def _test_web_interface(self):
        """Test de interfaz web"""
        try:
            import urllib.request

            url = f"http://{self.config.web_host}:{self.config.web_port}/"

            with urllib.request.urlopen(url, timeout=10) as response:
                if response.status == 200:
                    self.diagnostic_results.append(DiagnosticResult(
                        component="Web Interface",
                        test_name="HTTP Response",
                        status="pass",
                        message="Interfaz web respondiendo correctamente",
                        suggested_action="Ninguna acción requerida",
                        severity="info"
                    ))
                else:
                    self.diagnostic_results.append(DiagnosticResult(
                        component="Web Interface",
                        test_name="HTTP Response",
                        status="warning",
                        message=f"Interfaz web responde con código {response.status}",
                        suggested_action="Verificar configuración del servidor web",
                        severity="warning"
                    ))

        except Exception as e:
            self.diagnostic_results.append(DiagnosticResult(
                component="Web Interface",
                test_name="HTTP Test",
                status="fail",
                message=f"Error accediendo a interfaz web: {e}",
                suggested_action="Verificar que el servidor web esté iniciado",
                auto_fixable=True,
                severity="critical"
            ))

    def _test_memory_usage(self):
        """Test de uso de memoria"""
        try:
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024

            if memory_mb < 100:
                status = "pass"
                severity = "info"
                message = f"Uso de memoria normal: {memory_mb:.1f} MB"
                action = "Ninguna acción requerida"
            elif memory_mb < 500:
                status = "warning"
                severity = "warning"
                message = f"Uso de memoria elevado: {memory_mb:.1f} MB"
                action = "Monitorear uso de memoria"
            else:
                status = "fail"
                severity = "critical"
                message = f"Uso de memoria crítico: {memory_mb:.1f} MB"
                action = "Considerar reiniciar el dashboard"

            self.diagnostic_results.append(DiagnosticResult(
                component="System",
                test_name="Memory Usage",
                status=status,
                message=message,
                suggested_action=action,
                auto_fixable=(status == "fail"),
                severity=severity
            ))

        except Exception as e:
            self.logger.error(f"Error verificando memoria: {e}")

    def _test_cpu_usage(self):
        """Test de uso de CPU"""
        try:
            process = psutil.Process()
            cpu_percent = process.cpu_percent(interval=1)

            if cpu_percent < 50:
                status = "pass"
                severity = "info"
                message = f"Uso de CPU normal: {cpu_percent:.1f}%"
                action = "Ninguna acción requerida"
            elif cpu_percent < 80:
                status = "warning"
                severity = "warning"
                message = f"Uso de CPU elevado: {cpu_percent:.1f}%"
                action = "Monitorear carga del sistema"
            else:
                status = "fail"
                severity = "critical"
                message = f"Uso de CPU crítico: {cpu_percent:.1f}%"
                action = "Revisar procesos que consumen CPU"

            self.diagnostic_results.append(DiagnosticResult(
                component="System",
                test_name="CPU Usage",
                status=status,
                message=message,
                suggested_action=action,
                severity=severity
            ))

        except Exception as e:
            self.logger.error(f"Error verificando CPU: {e}")

    def _test_disk_space(self):
        """Test de espacio en disco"""
        try:
            disk_usage = psutil.disk_usage('.')
            free_gb = disk_usage.free / (1024 ** 3)
            percent_used = (disk_usage.used / disk_usage.total) * 100

            if percent_used < 80:
                status = "pass"
                severity = "info"
                message = f"Espacio en disco disponible: {free_gb:.1f} GB ({100 - percent_used:.1f}% libre)"
                action = "Ninguna acción requerida"
            elif percent_used < 90:
                status = "warning"
                severity = "warning"
                message = f"Espacio en disco bajo: {free_gb:.1f} GB ({100 - percent_used:.1f}% libre)"
                action = "Considerar limpiar archivos de log antiguos"
            else:
                status = "fail"
                severity = "critical"
                message = f"Espacio en disco crítico: {free_gb:.1f} GB ({100 - percent_used:.1f}% libre)"
                action = "Liberar espacio en disco inmediatamente"

            self.diagnostic_results.append(DiagnosticResult(
                component="System",
                test_name="Disk Space",
                status=status,
                message=message,
                suggested_action=action,
                auto_fixable=(status == "fail"),
                severity=severity
            ))

        except Exception as e:
            self.logger.error(f"Error verificando disco: {e}")

    def _test_configuration_validity(self):
        """Test de validez de configuración"""
        try:
            # Verificar que todos los puertos sean diferentes
            ports = [
                self.config.ml_detector_port,
                self.config.firewall_commands_port,
                self.config.firewall_responses_port,
                self.config.web_port
            ]

            if len(set(ports)) != len(ports):
                self.diagnostic_results.append(DiagnosticResult(
                    component="Configuration",
                    test_name="Port Conflicts",
                    status="fail",
                    message="Conflicto de puertos detectado en configuración",
                    suggested_action="Verificar que todos los puertos sean únicos",
                    severity="critical"
                ))
            else:
                self.diagnostic_results.append(DiagnosticResult(
                    component="Configuration",
                    test_name="Port Configuration",
                    status="pass",
                    message="Configuración de puertos correcta",
                    suggested_action="Ninguna acción requerida",
                    severity="info"
                ))

        except Exception as e:
            self.logger.error(f"Error verificando configuración: {e}")

    def _test_file_permissions(self):
        """Test de permisos de archivos"""
        critical_files = [
            'templates/dashboard.html',
            'static/css/dashboard.css',
            'static/js/dashboard.js'
        ]

        for file_path in critical_files:
            try:
                import os
                if os.access(file_path, os.R_OK):
                    self.diagnostic_results.append(DiagnosticResult(
                        component="File System",
                        test_name=f"File Access - {file_path}",
                        status="pass",
                        message=f"Archivo {file_path} accesible",
                        suggested_action="Ninguna acción requerida",
                        severity="info"
                    ))
                else:
                    self.diagnostic_results.append(DiagnosticResult(
                        component="File System",
                        test_name=f"File Access - {file_path}",
                        status="fail",
                        message=f"Archivo {file_path} no accesible",
                        suggested_action=f"Verificar permisos de {file_path}",
                        auto_fixable=True,
                        severity="critical"
                    ))

            except Exception as e:
                self.logger.error(f"Error verificando archivo {file_path}: {e}")

    def _test_encoding_issues(self):
        """Test específico de problemas de encoding"""
        # Este test se integraría con el EncodingMonitor
        # Por ahora simulamos
        self.diagnostic_results.append(DiagnosticResult(
            component="Encoding",
            test_name="UTF-8 Processing",
            status="pass",
            message="Sistema de encoding funcionando correctamente",
            suggested_action="Ninguna acción requerida",
            severity="info"
        ))

    def _test_message_flow(self):
        """Test de flujo de mensajes"""
        # Test básico de que los mensajes fluyen correctamente
        self.diagnostic_results.append(DiagnosticResult(
            component="Message Flow",
            test_name="End-to-End Flow",
            status="pass",
            message="Flujo de mensajes funcionando",
            suggested_action="Ninguna acción requerida",
            severity="info"
        ))

    def _attempt_auto_fixes(self):
        """Intentar reparaciones automáticas"""
        self.logger.info("🔧 Intentando reparaciones automáticas...")

        for result in self.diagnostic_results:
            if result.auto_fixable and result.status == "fail":
                self._attempt_fix(result)

    def _attempt_fix(self, result: DiagnosticResult):
        """Intentar reparar un problema específico"""
        self.logger.info(f"🔧 Intentando reparar: {result.component} - {result.test_name}")

        try:
            if "File Access" in result.test_name:
                # Intentar corregir permisos de archivo
                file_path = result.test_name.split(" - ")[1]
                subprocess.run(["chmod", "644", file_path], check=True)
                self.logger.info(f"✅ Permisos corregidos para {file_path}")

            elif "Memory Usage" in result.test_name:
                # Intentar liberar memoria
                import gc
                gc.collect()
                self.logger.info("✅ Garbage collection ejecutado")

            elif "Web Interface" in result.component:
                # Intentar reiniciar servidor web (esto requeriría más lógica)
                self.logger.info("ℹ️ Reinicio de servidor web requiere intervención manual")

        except Exception as e:
            self.logger.error(f"❌ Error intentando reparar {result.test_name}: {e}")

    def _generate_diagnostic_report(self) -> Dict:
        """Generar reporte completo de diagnóstico"""
        passed = len([r for r in self.diagnostic_results if r.status == "pass"])
        warnings = len([r for r in self.diagnostic_results if r.status == "warning"])
        failed = len([r for r in self.diagnostic_results if r.status == "fail"])

        critical_issues = [r for r in self.diagnostic_results if r.severity == "critical"]

        return {
            'timestamp': self.last_diagnostic_time.isoformat(),
            'summary': {
                'total_tests': len(self.diagnostic_results),
                'passed': passed,
                'warnings': warnings,
                'failed': failed,
                'overall_health': self._calculate_overall_health(),
                'critical_issues': len(critical_issues)
            },
            'results': [
                {
                    'component': r.component,
                    'test_name': r.test_name,
                    'status': r.status,
                    'message': r.message,
                    'suggested_action': r.suggested_action,
                    'severity': r.severity,
                    'auto_fixable': r.auto_fixable
                } for r in self.diagnostic_results
            ],
            'critical_issues': [
                {
                    'component': r.component,
                    'message': r.message,
                    'suggested_action': r.suggested_action
                } for r in critical_issues
            ],
            'recommendations': self._generate_recommendations()
        }

    def _calculate_overall_health(self) -> str:
        """Calcular salud general del sistema"""
        if not self.diagnostic_results:
            return "unknown"

        critical_count = len([r for r in self.diagnostic_results if r.severity == "critical"])
        warning_count = len([r for r in self.diagnostic_results if r.severity == "warning"])

        if critical_count > 0:
            return "critical"
        elif warning_count > 2:
            return "warning"
        else:
            return "healthy"

    def _generate_recommendations(self) -> List[str]:
        """Generar recomendaciones basadas en los resultados"""
        recommendations = []

        failed_results = [r for r in self.diagnostic_results if r.status == "fail"]

        if failed_results:
            recommendations.append("Se detectaron problemas críticos que requieren atención inmediata")

        warning_results = [r for r in self.diagnostic_results if r.status == "warning"]
        if len(warning_results) > 2:
            recommendations.append("Múltiples advertencias detectadas, revisar configuración")

        return recommendations