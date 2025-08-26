#!/usr/bin/env python3
"""
fix_dashboard_config.py - Corregir rol del Dashboard
PROBLEMA: Dashboard configurado como controlador firewall
SOLUCIÓN: Dashboard SOLO monitor + agregar endpoints correctos
"""

import json
from pathlib import Path


def analyze_current_dashboard_config():
    """Analizar configuración actual del Dashboard"""
    config_file = Path("config/json/dashboard_config_v31_etcd.json")

    print("🔍 ANALIZANDO DASHBOARD CONFIG ACTUAL...")

    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)

        print(f"   🆔 Node ID: {config.get('node_id', 'N/A')}")

        # Analizar firewall_fleet
        fleet_config = config.get('firewall_fleet', {})
        print(f"   🔥 Fleet enabled: {fleet_config.get('enabled', False)}")
        print(f"   🤖 Agents count: {len(fleet_config.get('agents', []))}")

        agents = fleet_config.get('agents', [])
        for agent in agents:
            print(f"      Agent: {agent.get('node_id', 'N/A')}")
            endpoints = agent.get('network_endpoints', {})
            dashboard_comm = endpoints.get('dashboard_communication', {})

            if dashboard_comm:
                cmd_input = dashboard_comm.get('commands_input', 'N/A')
                resp_output = dashboard_comm.get('responses_output', 'N/A')
                print(f"         Commands: {cmd_input}")
                print(f"         Responses: {resp_output}")
            else:
                print(f"         ❌ Sin dashboard_communication")

        # Analizar network endpoints del dashboard mismo
        network = config.get('network', {})
        print(f"   🌐 Dashboard network endpoints: {len(network)}")

        for key, value in network.items():
            if isinstance(value, dict):
                endpoint = f"tcp://{value.get('address', 'localhost')}:{value.get('port', 'N/A')}"
                mode = value.get('mode', 'N/A')
                socket_type = value.get('socket_type', 'N/A')
                print(f"      {key}: {endpoint} ({mode}/{socket_type})")

        return config

    except Exception as e:
        print(f"❌ Error: {e}")
        return None


def fix_dashboard_role(config):
    """Corregir rol del Dashboard"""
    print(f"\n🔧 CORRIGIENDO ROL DEL DASHBOARD...")

    # OPCIÓN 1: Dashboard como SOLO MONITOR (recomendado)
    print(f"📊 OPCIÓN 1: Dashboard SOLO Monitor (recomendado)")
    print(f"   - Deshabilitar firewall_fleet")
    print(f"   - Solo recibir eventos ML (puerto 5580)")
    print(f"   - UI para ver comandos, pero sin enviarlos")

    # OPCIÓN 2: Dashboard como CONTROLADOR DIRECTO
    print(f"🔥 OPCIÓN 2: Dashboard como Controlador Directo")
    print(f"   - Mantener firewall_fleet habilitado")
    print(f"   - Agregar endpoints para conectar con agents")
    print(f"   - Dashboard envía comandos directamente")

    choice = input(f"\n❓ ¿Qué opción prefieres? (1=Solo Monitor, 2=Controlador) [1]: ").strip()

    if choice == '2':
        return fix_dashboard_as_controller(config)
    else:
        return fix_dashboard_as_monitor(config)


def fix_dashboard_as_monitor(config):
    """Configurar Dashboard como SOLO monitor"""
    print(f"\n📊 CONFIGURANDO DASHBOARD COMO SOLO MONITOR...")

    changes = []

    # Deshabilitar fleet management
    if 'firewall_fleet' in config:
        config['firewall_fleet']['enabled'] = False
        config['firewall_fleet']['agents'] = []
        changes.append("✅ firewall_fleet.enabled = false")
        changes.append("✅ firewall_fleet.agents = []")

    # Asegurar que solo tenga ML input
    network = config.get('network', {})

    if 'ml_events_input' not in network:
        network['ml_events_input'] = {
            "description": "ML events from detector (monitoring only)",
            "address": "localhost",
            "port": 5580,
            "mode": "connect",
            "socket_type": "SUB",
            "high_water_mark": 500
        }
        changes.append("✅ ml_events_input configurado")

    # Remover cualquier output de firewall commands
    firewall_outputs = [key for key in network.keys() if 'firewall' in key.lower() and 'output' in key.lower()]
    for key in firewall_outputs:
        del network[key]
        changes.append(f"❌ Removido {key} (dashboard no envía comandos)")

    config['network'] = network

    # Agregar nota en configuración
    if 'role_description' not in config:
        config['role_description'] = "Dashboard V3.1 ETCD - SOLO MONITOR. No envía comandos firewall."

    print(f"📊 Dashboard configurado como SOLO MONITOR:")
    for change in changes:
        print(f"   {change}")

    return config, changes


def fix_dashboard_as_controller(config):
    """Configurar Dashboard como controlador directo"""
    print(f"\n🔥 CONFIGURANDO DASHBOARD COMO CONTROLADOR DIRECTO...")

    changes = []

    # Habilitar fleet management
    if 'firewall_fleet' not in config:
        config['firewall_fleet'] = {}

    config['firewall_fleet']['enabled'] = True
    changes.append("✅ firewall_fleet.enabled = true")

    # Configurar agent con endpoints correctos
    agent_config = {
        "node_id": "simple_firewall_agent_001",
        "status": "active",
        "network_endpoints": {
            "dashboard_communication": {
                "commands_input": "tcp://localhost:5583",  # Agent escucha comandos del Dashboard
                "responses_output": "tcp://localhost:5584"  # Agent envía respuestas al Dashboard
            }
        },
        "capabilities": {
            "allowed_actions": ["BLOCK_IP", "RATE_LIMIT_IP", "LIST_RULES", "ALLOW_IP_TEMP"]
        }
    }

    config['firewall_fleet']['agents'] = [agent_config]
    changes.append("✅ Agent configurado con endpoints dashboard")

    # Agregar network endpoints en dashboard
    network = config.get('network', {})

    # Input ML events
    if 'ml_events_input' not in network:
        network['ml_events_input'] = {
            "description": "ML events input",
            "address": "localhost",
            "port": 5580,
            "mode": "connect",
            "socket_type": "SUB",
            "high_water_mark": 500
        }
        changes.append("✅ ml_events_input configurado")

    # NO agregar fleet command outputs porque el Dashboard usa fleet_manager interno
    # que maneja la comunicación automáticamente

    config['network'] = network

    # Agregar processing threads para fleet
    if 'processing' not in config:
        config['processing'] = {}

    if 'threads' not in config['processing']:
        config['processing']['threads'] = {}

    # Asegurar threads para fleet management
    threads = config['processing']['threads']
    if 'fleet_command_senders' not in threads:
        threads['fleet_command_senders'] = 1
        changes.append("✅ fleet_command_senders thread")

    if 'fleet_response_consumers' not in threads:
        threads['fleet_response_consumers'] = 1
        changes.append("✅ fleet_response_consumers thread")

    # Queues para fleet
    if 'internal_queues' not in config['processing']:
        config['processing']['internal_queues'] = {}

    queues = config['processing']['internal_queues']
    if 'fleet_commands_queue_size' not in queues:
        queues['fleet_commands_queue_size'] = 50
        changes.append("✅ fleet_commands_queue configurada")

    if 'fleet_responses_queue_size' not in queues:
        queues['fleet_responses_queue_size'] = 100
        changes.append("✅ fleet_responses_queue configurada")

    # Agregar nota
    config['role_description'] = "Dashboard V3.1 ETCD - CONTROLADOR DIRECTO. Envía comandos firewall directamente."

    print(f"🔥 Dashboard configurado como CONTROLADOR:")
    for change in changes:
        print(f"   {change}")

    return config, changes


def save_updated_config(config, config_file):
    """Guardar configuración actualizada"""
    try:
        # Backup
        backup_path = config_file.with_suffix('.json.backup_role')
        with open(backup_path, 'w', encoding='utf-8') as f:
            # Leer original para backup
            with open(config_file, 'r', encoding='utf-8') as orig:
                original = json.load(orig)
            json.dump(original, f, indent=2, ensure_ascii=False)

        print(f"💾 Backup: {backup_path}")

        # Guardar nuevo config
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        print(f"✅ Configuración guardada: {config_file}")
        return True

    except Exception as e:
        print(f"❌ Error guardando: {e}")
        return False


def main():
    print("🧬 Upgraded Happiness V3.1 - Corregir Rol Dashboard")
    print("=" * 60)
    print("PROBLEMA: Dashboard configurado como controlador firewall")
    print("DECISIÓN: ¿Solo monitor o controlador directo?")

    config_file = Path("config/json/dashboard_config_v31_etcd.json")

    if not config_file.exists():
        print(f"❌ Config no encontrado: {config_file}")
        return

    # Analizar configuración actual
    config = analyze_current_dashboard_config()
    if not config:
        return

    # Corregir rol
    updated_config, changes = fix_dashboard_role(config)

    # Guardar
    if save_updated_config(updated_config, config_file):
        print(f"\n🎯 DASHBOARD CONFIG ACTUALIZADO")
        print(f"📋 Cambios aplicados: {len(changes)}")

        print(f"\n🚀 PRÓXIMOS PASOS:")
        print(f"   1. Reiniciar dashboard: python3 core/dashboard_v31_etcd.py ...")
        print(f"   2. Verificar fleet sockets en logs")
        print(f"   3. Probar funcionalidad desde web UI")
        print(f"   4. Verificar conectividad con agents")


if __name__ == "__main__":
    main()