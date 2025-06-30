#!/usr/bin/env python3
"""
BitDefender Integration Manager para macOS
==========================================
Script principal que orquesta todos los componentes
"""

import os
import sys
import json
import time
import asyncio
import threading
import subprocess
import argparse
import logging
import signal
from pathlib import Path
from typing import Dict, List, Any, Optional
import yaml
import websockets
import zmq
from datetime import datetime

class IntegrationManager:
    """Gestor principal de la integración BitDefender"""
    
    def __init__(self, config_path: str = "bitdefender_config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.running = False
        self.websocket_server = None
        self.ws_clients = set()
        
        # Configurar logging
        logging.basicConfig(
            level=getattr(logging, self.config.get('logging', {}).get('level', 'INFO')),
            format='%(asctime)s - Integration - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def _load_config(self) -> Dict[str, Any]:
        """Carga configuración desde YAML"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"❌ Error cargando configuración: {e}")
            sys.exit(1)
    
    async def start_dashboard_only(self):
        """Inicia solo el dashboard para demostración"""
        self.running = True
        self.logger.info("📊 Iniciando Dashboard en modo demostración...")
        
        try:
            # Iniciar servidor WebSocket
            await self._start_dashboard_server()
            
            # Simular datos para demo
            asyncio.create_task(self._demo_data_generator())
            
            self.logger.info("✅ Dashboard iniciado exitosamente")
            self.logger.info(f"🌐 Dashboard disponible en: http://localhost:{self.config['dashboard']['port']}")
            
            # Mantener ejecutándose
            await self._dashboard_main_loop()
            
        except Exception as e:
            self.logger.error(f"❌ Error iniciando dashboard: {e}")
            raise
    
    async def _start_dashboard_server(self):
        """Inicia el servidor WebSocket para el dashboard"""
        async def handle_client(websocket, path):
            """Maneja conexiones de clientes WebSocket"""
            self.ws_clients.add(websocket)
            self.logger.info(f"🔌 Cliente conectado: {websocket.remote_address}")
            
            try:
                # Enviar estado inicial
                await self._send_initial_state(websocket)
                
                # Mantener conexión activa
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        await self._handle_dashboard_message(websocket, data)
                    except json.JSONDecodeError:
                        await websocket.send(json.dumps({
                            'error': 'Invalid JSON format'
                        }))
            except websockets.exceptions.ConnectionClosed:
                pass
            finally:
                self.ws_clients.discard(websocket)
                self.logger.info(f"🔌 Cliente desconectado")
        
        # Iniciar servidor WebSocket
        host = self.config['dashboard']['host']
        port = self.config['dashboard']['port']
        
        self.websocket_server = await websockets.serve(
            handle_client,
            host,
            port
        )
        
        self.logger.info(f"✅ Dashboard WebSocket Server iniciado en ws://{host}:{port}")
    
    async def _send_initial_state(self, websocket):
        """Envía estado inicial al cliente del dashboard"""
        initial_state = {
            'type': 'initial_state',
            'data': {
                'system_status': 'demo_mode',
                'components': {
                    'bitdefender': self.config['bitdefender']['enabled'],
                    'hybrid_ml': self.config['hybrid_ml']['enabled'],
                    'dashboard': True
                },
                'statistics': {
                    'uptime': 0,
                    'threats_detected': 12,
                    'events_processed': 1247,
                    'active_agents': len(self.config['bitdefender']['processes'])
                },
                'bitdefender_info': {
                    'detected_paths': len(self.config['bitdefender']['log_paths']),
                    'detected_processes': len(self.config['bitdefender']['processes']),
                    'installation_type': self.config.get('detection_info', {}).get('installation_type', 'unknown')
                },
                'timestamp': datetime.now().isoformat()
            }
        }
        
        await websocket.send(json.dumps(initial_state))
    
    async def _handle_dashboard_message(self, websocket, data: Dict[str, Any]):
        """Maneja mensajes del dashboard"""
        message_type = data.get('type')
        
        if message_type == 'get_status':
            await self._send_system_status(websocket)
        elif message_type == 'get_metrics':
            await self._send_metrics(websocket)
        elif message_type == 'get_bitdefender_info':
            await self._send_bitdefender_info(websocket)
        else:
            await websocket.send(json.dumps({
                'error': f'Unknown message type: {message_type}'
            }))
    
    async def _send_system_status(self, websocket):
        """Envía estado del sistema"""
        status = {
            'type': 'system_status',
            'data': {
                'mode': 'demo',
                'bitdefender_detected': True,
                'processes_running': len(self.config['bitdefender']['processes']),
                'log_paths_available': len(self.config['bitdefender']['log_paths']),
                'timestamp': datetime.now().isoformat()
            }
        }
        
        await websocket.send(json.dumps(status))
    
    async def _send_metrics(self, websocket):
        """Envía métricas simuladas"""
        import random
        
        metrics = {
            'type': 'metrics',
            'data': {
                'threats_today': random.randint(8, 25),
                'blocked_today': random.randint(15, 30),
                'events_processed': random.randint(1000, 2000),
                'ml_accuracy': round(random.uniform(92.0, 97.0), 1),
                'bd_events': random.randint(200, 500),
                'timestamp': datetime.now().isoformat()
            }
        }
        
        await websocket.send(json.dumps(metrics))
    
    async def _send_bitdefender_info(self, websocket):
        """Envía información específica de BitDefender"""
        bd_info = {
            'type': 'bitdefender_info',
            'data': {
                'installation_type': 'dmg_install',
                'detected_components': [
                    'AntivirusforMac.app',
                    'CoreSecurity.app', 
                    'BitdefenderAgent.app',
                    'Bitdefender VPN.app'
                ],
                'log_paths': self.config['bitdefender']['log_paths'],
                'processes': self.config['bitdefender']['processes'],
                'status': 'active',
                'timestamp': datetime.now().isoformat()
            }
        }
        
        await websocket.send(json.dumps(bd_info))
    
    async def _demo_data_generator(self):
        """Genera eventos de demostración"""
        event_types = [
            'malware_detected',
            'suspicious_connection', 
            'port_scan',
            'real_time_scan',
            'signature_update'
        ]
        
        severities = ['low', 'medium', 'high']
        
        while self.running:
            try:
                # Generar evento aleatorio
                import random
                
                event = {
                    'type': 'demo_event',
                    'data': {
                        'event_type': random.choice(event_types),
                        'severity': random.choice(severities),
                        'source': 'bitdefender_demo',
                        'timestamp': datetime.now().isoformat(),
                        'details': f"Demo event from BitDefender integration",
                        'process': random.choice(self.config['bitdefender']['processes'])
                    }
                }
                
                # Enviar a todos los clientes conectados
                if self.ws_clients:
                    await self._broadcast_to_clients(json.dumps(event))
                
                # Esperar entre 10-30 segundos para el próximo evento
                await asyncio.sleep(random.randint(10, 30))
                
            except Exception as e:
                self.logger.error(f"Error generando datos demo: {e}")
                await asyncio.sleep(15)
    
    async def _broadcast_to_clients(self, message: str):
        """Envía mensaje a todos los clientes WebSocket conectados"""
        if not self.ws_clients:
            return
        
        # Enviar a todos los clientes (remover desconectados)
        disconnected_clients = set()
        
        for client in self.ws_clients.copy():
            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                disconnected_clients.add(client)
            except Exception as e:
                self.logger.error(f"Error enviando a cliente: {e}")
                disconnected_clients.add(client)
        
        # Remover clientes desconectados
        self.ws_clients -= disconnected_clients
    
    async def _dashboard_main_loop(self):
        """Bucle principal del dashboard"""
        try:
            while self.running:
                # Enviar estadísticas periódicas
                if self.ws_clients:
                    stats = {
                        'type': 'periodic_stats',
                        'data': {
                            'uptime': int(time.time()),
                            'connected_clients': len(self.ws_clients),
                            'mode': 'demo',
                            'timestamp': datetime.now().isoformat()
                        }
                    }
                    await self._broadcast_to_clients(json.dumps(stats))
                
                await asyncio.sleep(30)
                
        except KeyboardInterrupt:
            self.logger.info("🛑 Interrupción recibida")
        except Exception as e:
            self.logger.error(f"❌ Error en bucle principal: {e}")
        finally:
            await self.stop()
    
    async def stop(self):
        """Detiene la integración"""
        self.running = False
        if self.websocket_server:
            self.websocket_server.close()
        self.logger.info("✅ Dashboard detenido")
    
    def check_bitdefender_status(self):
        """Verifica el estado de BitDefender en el sistema"""
        print("🔍 Verificando estado de BitDefender en macOS...")
        
        # Verificar instalación
        bd_paths = ["/Applications/Bitdefender"]
        installed = False
        
        for path in bd_paths:
            if Path(path).exists():
                print(f"✅ BitDefender encontrado en: {path}")
                installed = True
                
                # Listar componentes
                try:
                    for item in Path(path).iterdir():
                        if item.is_dir() and item.name.endswith('.app'):
                            print(f"   📱 {item.name}")
                except PermissionError:
                    print("   ⚠️  Sin permisos para listar contenido")
                break
        
        if not installed:
            print("❌ BitDefender no está instalado")
        
        # Verificar procesos
        try:
            ps_output = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            bd_processes = []
            
            for line in ps_output.stdout.splitlines():
                if any(proc in line.lower() for proc in ['bitdefender', 'bdl']):
                    process_name = line.split()[10] if len(line.split()) > 10 else "unknown"
                    if 'bitdefender' in process_name.lower() or 'bdl' in process_name.lower():
                        bd_processes.append(process_name)
            
            if bd_processes:
                print(f"✅ {len(bd_processes)} procesos de BitDefender ejecutándose:")
                for proc in bd_processes[:10]:  # Mostrar primeros 10
                    print(f"   🔄 {proc}")
            else:
                print("⚠️  No se detectaron procesos de BitDefender")
                
        except Exception as e:
            print(f"❌ Error verificando procesos: {e}")
        
        # Verificar configuración
        if Path(self.config_path).exists():
            print(f"✅ Configuración encontrada: {self.config_path}")
            print(f"   📁 Rutas configuradas: {len(self.config['bitdefender']['log_paths'])}")
            print(f"   🔄 Procesos configurados: {len(self.config['bitdefender']['processes'])}")
        else:
            print(f"❌ Configuración no encontrada: {self.config_path}")

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description='BitDefender Integration Manager para macOS')
    parser.add_argument('--config', default='bitdefender_config.yaml',
                       help='Archivo de configuración YAML')
    parser.add_argument('--dashboard-only', action='store_true',
                       help='Solo iniciar dashboard (modo demo)')
    parser.add_argument('--check-bitdefender', action='store_true',
                       help='Verificar estado de BitDefender en macOS')
    
    args = parser.parse_args()
    
    # Verificar que existe la configuración
    if not Path(args.config).exists():
        print(f"❌ Error: No se encuentra el archivo de configuración: {args.config}")
        print("   Ejecuta primero: ./quick_setup_macos_v2.sh")
        sys.exit(1)
    
    # Crear manager
    manager = IntegrationManager(args.config)
    
    if args.check_bitdefender:
        manager.check_bitdefender_status()
        return
    
    # Configurar manejo de señales
    def signal_handler(signum, frame):
        print(f"\n🛑 Señal {signum} recibida. Deteniendo...")
        raise KeyboardInterrupt()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        if args.dashboard_only:
            print("📊 Iniciando Dashboard en modo demostración...")
            print(f"🌐 Dashboard estará disponible en: http://localhost:{manager.config['dashboard']['port']}")
            print("📱 Abre esa URL en tu navegador para ver la interfaz")
            print("⏹️  Presiona Ctrl+C para detener")
            asyncio.run(manager.start_dashboard_only())
        else:
            print("🚀 Modo integración completa no implementado aún")
            print("💡 Usa --dashboard-only para ver la demostración")
            
    except KeyboardInterrupt:
        print("\n✅ Detenido por el usuario")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
