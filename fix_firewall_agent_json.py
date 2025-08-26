#!/usr/bin/env python3
"""
fix_firewall_agent_json.py - Arreglar simple_firewall_agent_v31_etcd.json
PROBLEMA CRÍTICO: Agent sin inputs/outputs -> 0 fleet sockets
"""

import json
from pathlib import Path


def fix_firewall_agent_config():
    config_file = Path("config/json/simple_firewall_agent_v31_etcd.json")

    print("🔧 ARREGLANDO FIREWALL AGENT CONFIG...")
    print(f"📋 Archivo: {config_file}")

    if not config_file.exists():
        print(f"❌ Archivo no encontrado: {config_file}")
        return False

    try:
        # Leer config actual
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)

        # Backup
        backup_path = config_file.with_suffix('.json.backup')
        with open(backup_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        print(f"💾 Backup: {backup_path}")

        print(f"\n🔍 ESTADO ACTUAL:")
        print(f"   🆔 Node ID: {config.get('node_id', 'N/A')}")

        # Revisar network section
        network = config.get('network', {})
        print(f"   🌐 Network endpoints: {len(network)}")

        for key, value in network.items():
            if isinstance(value, dict):
                endpoint = f"tcp://{value.get('address', 'localhost')}:{value.get('port', 'N/A')}"
                print(f"      {key}: {endpoint}")

        if len(network) == 0:
            print("   ❌ NO HAY ENDPOINTS DE RED!")

        # ARREGLAR: Agregar endpoints faltantes para Scheduler
        print(f"\n🔧 AGREGANDO ENDPOINTS SCHEDULER:")

        if 'network' not in config:
            config['network'] = {}

        # INPUT: Comandos desde Scheduler (puerto 5582)
        config['network']['scheduler_commands_input'] = {
            "description": "Input for firewall commands from scheduler",
            "address": "localhost",
            "port": 5582,
            "mode": "connect",
            "socket_type": "PULL",
            "high_water_mark": 200,
            "linger_ms": 1000,
            "recv_timeout_ms": 2000
        }

        # OUTPUT: Respuestas hacia Scheduler (puerto 5581)
        config['network']['scheduler_responses_output'] = {
            "description": "Output for firewall responses to scheduler",
            "address": "localhost",
            "port": 5581,
            "mode": "connect",
            "socket_type": "PUSH",
            "high_water_mark": 200,
            "linger_ms": 1000,
            "send_timeout_ms": 1000
        }

        print(f"   ✅ scheduler_commands_input: tcp://localhost:5582 (PULL)")
        print(f"   ✅ scheduler_responses_output: tcp://localhost:5581 (PUSH)")

        # Verificar que también tenga sección para status monitoring
        if 'status_endpoint' not in config.get('network', {}):
            config['network']['status_endpoint'] = {
                "description": "Status monitoring endpoint",
                "address": "localhost",
                "port": 5585,
                "mode": "bind",
                "socket_type": "REP",
                "enabled": True
            }
            print(f"   ✅ status_endpoint: tcp://localhost:5585 (REP)")

        # Agregar processing configuration si no existe
        if 'processing' not in config:
            config['processing'] = {
                "threads": {
                    "command_processors": 2,
                    "response_senders": 1
                },
                "internal_queues": {
                    "commands_queue_size": 100,
                    "responses_queue_size": 100
                }
            }
            print(f"   ✅ processing threads configurados")

        # Guardar config actualizado
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        print(f"\n✅ FIREWALL AGENT CONFIG ACTUALIZADO")
        print(f"\n📊 NUEVOS ENDPOINTS:")
        print(f"   📥 Recibe comandos: Scheduler -> Agent (puerto 5582)")
        print(f"   📤 Envía respuestas: Agent -> Scheduler (puerto 5581)")
        print(f"   📊 Status monitoring: puerto 5585")

        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def verify_scheduler_compatibility():
    """Verificar compatibilidad con Scheduler config"""
    scheduler_config = Path("config/json/scheduler_firewall_etcd_config_dev.json")

    print(f"\n🔍 VERIFICANDO COMPATIBILIDAD SCHEDULER...")

    if not scheduler_config.exists():
        print(f"⚠️  Scheduler config no encontrado: {scheduler_config}")
        return

    try:
        with open(scheduler_config, 'r', encoding='utf-8') as f:
            config = json.load(f)

        network = config.get('network', {})
        print(f"📊 Scheduler endpoints:")

        # Buscar outputs del scheduler
        for key, value in network.items():
            if isinstance(value, dict) and 'output' in key.lower():
                port = value.get('port')
                socket_type = value.get('socket_type', 'N/A')
                print(f"   📤 {key}: puerto {port} ({socket_type})")

                if port == 5582:
                    print(f"      ✅ Coincide con Agent input")

        # Buscar inputs del scheduler
        for key, value in network.items():
            if isinstance(value, dict) and 'input' in key.lower():
                port = value.get('port')
                socket_type = value.get('socket_type', 'N/A')
                print(f"   📥 {key}: puerto {port} ({socket_type})")

                if port == 5581:
                    print(f"      ✅ Coincide con Agent output")

    except Exception as e:
        print(f"❌ Error leyendo scheduler: {e}")


if __name__ == "__main__":
    print("🧬 Upgraded Happiness V3.1 - Arreglar Firewall Agent")
    print("=" * 60)
    print("PROBLEMA: Agent sin endpoints -> 0 fleet sockets en Dashboard")

    if fix_firewall_agent_config():
        verify_scheduler_compatibility()

        print(f"\n🎯 RESULTADO ESPERADO:")
        print(f"   ✅ Scheduler -> Agent connection establecida")
        print(f"   ✅ Agent aparecerá en fleet sockets")
        print(f"   ✅ Dashboard podrá enviar comandos via Scheduler")
        print(f"\n📋 Próximos pasos:")
        print(f"   1. Verificar dashboard config (deshabilitar fleet)")
        print(f"   2. Reiniciar todos los componentes")
        print(f"   3. Probar conexión pipeline")
    else:
        print(f"\n❌ Error arreglando Firewall Agent")