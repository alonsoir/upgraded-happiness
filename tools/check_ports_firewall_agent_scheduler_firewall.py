#!/usr/bin/env python3
"""
🔍 Port Configuration Checker
Verifica que los puertos del scheduler y agent coincidan
"""
import json
import sys
from pathlib import Path


def check_port_configuration(scheduler_config_file, agent_config_file):
    """Verificar configuración de puertos"""

    print("🔍 VERIFICANDO CONFIGURACIÓN DE PUERTOS...")
    print("=" * 60)

    # Cargar configuración del scheduler
    try:
        with open(scheduler_config_file, 'r') as f:
            scheduler_config = json.load(f)
        print(f"✅ Scheduler config cargado: {scheduler_config_file}")
    except Exception as e:
        print(f"❌ Error cargando scheduler config: {e}")
        return False

    # Cargar configuración del agent
    try:
        with open(agent_config_file, 'r') as f:
            agent_config = json.load(f)
        print(f"✅ Agent config cargado: {agent_config_file}")
    except Exception as e:
        print(f"❌ Error cargando agent config: {e}")
        return False

    print("\n🔍 ANÁLISIS DE CONFIGURACIÓN:")
    print("-" * 40)

    # Extraer puertos del scheduler
    network = scheduler_config.get('network', {})
    scheduler_commands_port = network.get('firewall_commands_output', {}).get('port')
    scheduler_responses_port = network.get('firewall_responses_input', {}).get('port')

    print(f"📡 SCHEDULER:")
    print(f"   Envía comandos al puerto: {scheduler_commands_port}")
    print(f"   Recibe respuestas del puerto: {scheduler_responses_port}")

    # Extraer puertos del agent
    agent_network = agent_config.get('network', {})
    agent_commands_port = agent_network.get('scheduler_commands', {}).get('port')
    agent_responses_port = agent_network.get('scheduler_responses', {}).get('port')

    print(f"🤖 AGENT:")
    print(f"   Recibe comandos en puerto: {agent_commands_port}")
    print(f"   Envía respuestas al puerto: {agent_responses_port}")

    print("\n🎯 VERIFICACIÓN DE COMPATIBILIDAD:")
    print("-" * 40)

    # Verificar compatibilidad
    errors = []

    if scheduler_commands_port != agent_commands_port:
        errors.append(
            f"❌ COMMANDS: Scheduler envía a {scheduler_commands_port}, Agent escucha en {agent_commands_port}")
    else:
        print(f"✅ COMMANDS: Puerto {scheduler_commands_port} coincide")

    if scheduler_responses_port != agent_responses_port:
        errors.append(
            f"❌ RESPONSES: Scheduler escucha en {scheduler_responses_port}, Agent envía a {agent_responses_port}")
    else:
        print(f"✅ RESPONSES: Puerto {scheduler_responses_port} coincide")

    # Verificar patrones ZMQ
    scheduler_cmd_socket = network.get('firewall_commands_output', {}).get('socket_type')
    scheduler_resp_socket = network.get('firewall_responses_input', {}).get('socket_type')

    agent_cmd_socket = agent_network.get('scheduler_commands', {}).get('socket_type')
    agent_resp_socket = agent_network.get('scheduler_responses', {}).get('socket_type')

    print(f"\n🔌 PATRONES ZMQ:")
    print(f"   Commands: Scheduler({scheduler_cmd_socket}) ↔ Agent({agent_cmd_socket})")
    print(f"   Responses: Scheduler({scheduler_resp_socket}) ↔ Agent({agent_resp_socket})")

    # Verificar compatibilidad ZMQ
    if scheduler_cmd_socket == 'PUSH' and agent_cmd_socket == 'PULL':
        print("✅ Commands pattern: PUSH/PULL compatible")
    else:
        errors.append(f"❌ Commands pattern: {scheduler_cmd_socket}/{agent_cmd_socket} incompatible")

    if scheduler_resp_socket == 'PULL' and agent_resp_socket == 'PUSH':
        print("✅ Responses pattern: PULL/PUSH compatible")
    else:
        errors.append(f"❌ Responses pattern: {scheduler_resp_socket}/{agent_resp_socket} incompatible")

    print("\n" + "=" * 60)

    if errors:
        print("💥 ERRORES ENCONTRADOS:")
        for error in errors:
            print(f"   {error}")
        print("\n🔧 SOLUCIÓN:")
        print("   1. Verificar puertos en ambos archivos de configuración")
        print("   2. Asegurar que patterns ZMQ sean compatibles")
        print("   3. Scheduler PUSH/PULL ↔ Agent PULL/PUSH")
        return False
    else:
        print("✅ CONFIGURACIÓN CORRECTA: Puertos y patterns compatibles")
        print("🚀 El scheduler y agent deberían comunicarse correctamente")
        return True


def main():
    """Función principal"""
    if len(sys.argv) != 3:
        print("❌ Uso: python check_ports.py <scheduler_config.json> <agent_config.json>")
        print("\nEjemplo:")
        print(
            "python check_ports.py config/json/scheduler_firewall_config.json config/json/simple_firewall_agent_v31_config.json")
        sys.exit(1)

    scheduler_config_file = sys.argv[1]
    agent_config_file = sys.argv[2]

    # Verificar que archivos existan
    if not Path(scheduler_config_file).exists():
        print(f"❌ Scheduler config no encontrado: {scheduler_config_file}")
        sys.exit(1)

    if not Path(agent_config_file).exists():
        print(f"❌ Agent config no encontrado: {agent_config_file}")
        sys.exit(1)

    # Verificar configuración
    success = check_port_configuration(scheduler_config_file, agent_config_file)

    if success:
        print("\n🎯 PRÓXIMOS PASOS:")
        print("   1. Iniciar scheduler: python core/scheduler-firewall.py ...")
        print("   2. Iniciar agent: python core/simple_firewall_agent_v31.py ...")
        print("   3. Verificar que se conecten correctamente")
        sys.exit(0)
    else:
        print("\n🛑 CORREGIR CONFIGURACIÓN ANTES DE CONTINUAR")
        sys.exit(1)


if __name__ == "__main__":
    main()