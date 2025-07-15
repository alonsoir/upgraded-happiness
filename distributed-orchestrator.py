# Orquestación distribuida para upgraded-happiness
# Solución para coordinación y monitoreo de toda la cadena

import json
import time
import zmq
import threading
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional
import psutil
import socket


@dataclass
class ComponentHealth:
    name: str
    node_id: str
    status: str  # 'healthy', 'degraded', 'failed'
    last_heartbeat: float
    metrics: Dict
    port: int
    process_id: Optional[int] = None


class DistributedOrchestrator:
    """
    Orquestador central para monitorear y coordinar toda la cadena
    """

    def __init__(self, config_file: str = "orchestrator_config.json"):
        self.config = self._load_config(config_file)
        self.setup_logging()

        # 🗺️ Registro de componentes
        self.components: Dict[str, ComponentHealth] = {}
        self.running = True

        # 🔌 ZeroMQ para comunicación con componentes
        self.context = zmq.Context()
        self.setup_control_sockets()

        # 📊 Métricas globales
        self.global_metrics = {
            'total_events_processed': 0,
            'total_events_dropped': 0,
            'chain_throughput': 0.0,
            'chain_latency': 0.0,
            'start_time': time.time()
        }

    def _load_config(self, config_file: str) -> Dict:
        """Carga configuración con defaults para orquestación"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except:
            config = {}

        defaults = {
            'control_port': 5555,  # Puerto para control de componentes
            'heartbeat_interval': 5,  # Intervalo de heartbeat en segundos
            'health_check_interval': 10,  # Intervalo de health checks
            'component_timeout': 30,  # Timeout para considerar componente failed
            'auto_restart': True,  # Auto-restart de componentes fallidos
            'max_restart_attempts': 3,  # Máximo intentos de restart
            'monitoring_port': 8080,  # Puerto para métricas (HTTP)

            # 🎯 Configuración de componentes esperados
            'expected_components': {
                'promiscuous_agents': {
                    'count': 1,
                    'ports': [5559],
                    'type': 'producer'
                },
                'geoip_enrichers': {
                    'count': 1,
                    'ports': [5560],
                    'type': 'processor'
                },
                'consumers': {
                    'count': 1,
                    'ports': [],
                    'type': 'consumer'
                }
            }
        }

        for key, value in defaults.items():
            config.setdefault(key, value)

        return config

    def setup_logging(self):
        """Configuración de logging para orquestador"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - ORCHESTRATOR - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def setup_control_sockets(self):
        """Configuración de sockets de control"""
        # 📡 Socket para recibir heartbeats y métricas
        self.control_socket = self.context.socket(zmq.PULL)
        control_port = self.config['control_port']
        self.control_socket.bind(f"tcp://*:{control_port}")
        self.control_socket.RCVTIMEO = 1000  # 1 segundo timeout

        self.logger.info(f"🎛️ Control socket configurado en puerto {control_port}")

    def register_component(self, component_info: Dict):
        """Registra un componente en el orquestador"""
        node_id = component_info['node_id']
        component_type = component_info['type']

        health = ComponentHealth(
            name=component_type,
            node_id=node_id,
            status='healthy',
            last_heartbeat=time.time(),
            metrics=component_info.get('metrics', {}),
            port=component_info.get('port', 0),
            process_id=component_info.get('process_id')
        )

        self.components[node_id] = health
        self.logger.info(f"✅ Componente registrado: {component_type} ({node_id})")

    def receive_heartbeats(self):
        """Thread para recibir heartbeats de componentes"""
        self.logger.info("💓 Iniciando receiver de heartbeats...")

        while self.running:
            try:
                # 📨 Recibir mensaje de control
                message = self.control_socket.recv_json(zmq.NOBLOCK)

                if message['type'] == 'heartbeat':
                    self.process_heartbeat(message)
                elif message['type'] == 'metrics':
                    self.process_metrics(message)
                elif message['type'] == 'register':
                    self.register_component(message)

            except zmq.Again:
                # Sin mensajes - continuar
                continue
            except Exception as e:
                self.logger.error(f"❌ Error procesando mensaje de control: {e}")

    def process_heartbeat(self, message: Dict):
        """Procesa heartbeat de componente"""
        node_id = message['node_id']

        if node_id in self.components:
            self.components[node_id].last_heartbeat = time.time()
            self.components[node_id].status = message.get('status', 'healthy')
        else:
            self.logger.warning(f"⚠️ Heartbeat de componente no registrado: {node_id}")

    def process_metrics(self, message: Dict):
        """Procesa métricas de componente"""
        node_id = message['node_id']

        if node_id in self.components:
            self.components[node_id].metrics.update(message.get('metrics', {}))

            # 📊 Agregar a métricas globales
            self.aggregate_global_metrics(message['metrics'])

    def aggregate_global_metrics(self, component_metrics: Dict):
        """Agrega métricas de componente a métricas globales"""
        # 📈 Sumar eventos procesados
        if 'events_processed' in component_metrics:
            self.global_metrics['total_events_processed'] += component_metrics['events_processed']

        if 'events_dropped' in component_metrics:
            self.global_metrics['total_events_dropped'] += component_metrics['events_dropped']

        # 🚀 Calcular throughput global
        runtime = time.time() - self.global_metrics['start_time']
        if runtime > 0:
            self.global_metrics['chain_throughput'] = self.global_metrics['total_events_processed'] / runtime

    def health_monitor(self):
        """Monitor de salud de componentes"""
        self.logger.info("🏥 Iniciando monitor de salud...")

        while self.running:
            time.sleep(self.config['health_check_interval'])

            if not self.running:
                break

            current_time = time.time()
            timeout = self.config['component_timeout']

            for node_id, component in self.components.items():
                # ⏰ Verificar timeout de heartbeat
                if current_time - component.last_heartbeat > timeout:
                    if component.status != 'failed':
                        self.logger.warning(f"🚨 Componente sin heartbeat: {component.name} ({node_id})")
                        component.status = 'failed'

                        # 🔄 Auto-restart si está habilitado
                        if self.config['auto_restart']:
                            self.restart_component(component)

                # 📊 Verificar métricas de salud
                self.check_component_health(component)

            # 📈 Log de estado general
            self.log_system_status()

    def check_component_health(self, component: ComponentHealth):
        """Verifica salud específica de componente basada en métricas"""
        metrics = component.metrics

        # 🚨 Verificar tasa de errores alta
        if 'error_rate' in metrics and metrics['error_rate'] > 0.1:  # >10% errores
            if component.status == 'healthy':
                component.status = 'degraded'
                self.logger.warning(f"⚠️ Componente degradado por errores: {component.name}")

        # 🔴 Verificar buffer lleno persistente
        if 'buffer_full_errors' in metrics and metrics['buffer_full_errors'] > 100:
            self.logger.warning(f"🚨 Buffer persistentemente lleno: {component.name}")

        # 💾 Verificar uso de memoria
        if component.process_id:
            try:
                process = psutil.Process(component.process_id)
                memory_percent = process.memory_percent()

                if memory_percent > 80:  # >80% memoria
                    self.logger.warning(f"🧠 Uso alto de memoria: {component.name} ({memory_percent:.1f}%)")
            except:
                pass

    def restart_component(self, component: ComponentHealth):
        """Reinicia componente fallido"""
        self.logger.info(f"🔄 Intentando restart de {component.name} ({component.node_id})")

        # 🛑 Lógica de restart específica por tipo de componente
        if component.name == 'promiscuous_agent':
            # Comando para reiniciar promiscuous agent
            restart_cmd = f"python promiscuous_agent.py enhanced_agent_config.json"
        elif component.name == 'geoip_enricher':
            # Comando para reiniciar geoip enricher
            restart_cmd = f"python geoip_enricher.py geoip_config.json"
        else:
            self.logger.warning(f"⚠️ No se conoce cómo reiniciar: {component.name}")
            return

        # 🚀 Ejecutar restart (simplificado - en producción usar subprocess/systemd)
        self.logger.info(f"📋 Comando restart: {restart_cmd}")
        # subprocess.Popen(restart_cmd.split()) # Descomentizar en producción

    def log_system_status(self):
        """Log del estado general del sistema"""
        healthy = sum(1 for c in self.components.values() if c.status == 'healthy')
        degraded = sum(1 for c in self.components.values() if c.status == 'degraded')
        failed = sum(1 for c in self.components.values() if c.status == 'failed')

        self.logger.info(f"🏥 Sistema: {healthy} sanos, {degraded} degradados, {failed} fallidos")
        self.logger.info(f"📊 Global: {self.global_metrics['total_events_processed']} eventos, "
                         f"{self.global_metrics['chain_throughput']:.1f} eventos/s")

        # 🚨 Alertas del sistema
        if failed > 0:
            self.logger.warning(f"🚨 ATENCIÓN: {failed} componentes fallidos")

        if degraded > healthy:
            self.logger.warning("🚨 ATENCIÓN: Más componentes degradados que sanos")

    def generate_health_report(self) -> Dict:
        """Genera reporte completo de salud del sistema"""
        report = {
            'timestamp': time.time(),
            'system_status': 'healthy',  # healthy, degraded, critical
            'components': {},
            'global_metrics': self.global_metrics.copy(),
            'alerts': []
        }

        # 📋 Estado de componentes
        for node_id, component in self.components.items():
            report['components'][node_id] = {
                'name': component.name,
                'status': component.status,
                'last_heartbeat': component.last_heartbeat,
                'metrics': component.metrics,
                'port': component.port
            }

        # 🎯 Determinar estado general del sistema
        failed_count = sum(1 for c in self.components.values() if c.status == 'failed')
        degraded_count = sum(1 for c in self.components.values() if c.status == 'degraded')

        if failed_count > 0:
            report['system_status'] = 'critical'
            report['alerts'].append(f"{failed_count} componentes fallidos")
        elif degraded_count > 0:
            report['system_status'] = 'degraded'
            report['alerts'].append(f"{degraded_count} componentes degradados")

        return report

    def run(self):
        """Ejecutar orquestador"""
        self.logger.info("🎭 Iniciando Distributed Orchestrator...")

        # 🧵 Threads del orquestador
        threads = [
            threading.Thread(target=self.receive_heartbeats, name="HeartbeatReceiver"),
            threading.Thread(target=self.health_monitor, name="HealthMonitor")
        ]

        for thread in threads:
            thread.start()

        self.logger.info("✅ Orquestador iniciado - Monitoreando sistema distribuido")

        try:
            while self.running:
                time.sleep(5)

                # 📊 Generar reporte periódico
                report = self.generate_health_report()

                # 💾 Guardar reporte (opcional)
                with open('system_health.json', 'w') as f:
                    json.dump(report, f, indent=2)

        except KeyboardInterrupt:
            self.logger.info("🛑 Deteniendo orquestador...")

        # 🛑 Cierre graceful
        self.shutdown(threads)

    def shutdown(self, threads):
        """Cierre graceful del orquestador"""
        self.running = False

        for thread in threads:
            thread.join(timeout=5)

        self.control_socket.close()
        self.context.term()

        self.logger.info("✅ Orquestador cerrado correctamente")


# 📋 Configuración de ejemplo para orquestador
ORCHESTRATOR_CONFIG = {
    "control_port": 5555,
    "heartbeat_interval": 5,
    "health_check_interval": 10,
    "component_timeout": 30,
    "auto_restart": True,
    "max_restart_attempts": 3,

    "expected_components": {
        "promiscuous_agents": {
            "count": 1,
            "ports": [5559],
            "type": "producer"
        },
        "geoip_enrichers": {
            "count": 1,
            "ports": [5560],
            "type": "processor"
        },
        "consumers": {
            "count": 1,
            "ports": [],
            "type": "consumer"
        }
    }
}

# 🚀 Uso del orquestador
if __name__ == "__main__":
    orchestrator = DistributedOrchestrator()
    orchestrator.run()

# 📡 Snippet para añadir a componentes existentes para enviar heartbeats
HEARTBEAT_SNIPPET = """
# Añadir a cada componente para envío de heartbeats al orquestrador

import zmq
import json
import time
import threading

class ComponentHeartbeat:
    def __init__(self, component_type: str, node_id: str, orchestrator_port: int = 5555):
        self.component_type = component_type
        self.node_id = node_id
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUSH)
        self.socket.connect(f"tcp://localhost:{orchestrator_port}")
        self.running = True

    def send_heartbeat(self, status: str = 'healthy', metrics: dict = None):
        message = {
            'type': 'heartbeat',
            'node_id': self.node_id,
            'component_type': self.component_type,
            'status': status,
            'timestamp': time.time(),
            'metrics': metrics or {}
        }

        try:
            self.socket.send_json(message, zmq.NOBLOCK)
        except:
            pass  # Orquestador no disponible

    def heartbeat_loop(self, interval: int = 5):
        while self.running:
            self.send_heartbeat()
            time.sleep(interval)

    def start_heartbeat_thread(self, interval: int = 5):
        thread = threading.Thread(target=self.heartbeat_loop, args=(interval,))
        thread.daemon = True
        thread.start()
        return thread

# Uso en cada componente:
# heartbeat = ComponentHeartbeat('promiscuous_agent', self.node_id)
# heartbeat.start_heartbeat_thread()
"""