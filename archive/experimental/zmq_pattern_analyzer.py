#!/usr/bin/env python3
"""
Analizador de patrones ZMQ para identificar incompatibilidades
en upgraded-happiness
"""

import re
import os
from pathlib import Path


def analyze_zmq_patterns():
    """Analiza los patrones ZMQ en cada componente"""

    print("🔍 ANALIZADOR DE PATRONES ZMQ")
    print("=" * 50)

    components = [
        ("firewall_agent.py", "🔥 Firewall Agent"),
        ("ml_detector_with_persistence.py", "🤖 ML Detector"),
        ("real_zmq_dashboard_with_firewall.py", "📊 Dashboard"),
        ("promiscuous_agent.py", "🕵️ Promiscuous Agent")
    ]

    patterns = {}

    for filename, component_name in components:
        if os.path.exists(filename):
            print(f"\n{component_name}")
            print("-" * 30)

            with open(filename, 'r') as f:
                content = f.read()

            # Buscar patrones ZMQ
            zmq_patterns = {
                'PUSH': len(re.findall(r'zmq\.PUSH', content)),
                'PULL': len(re.findall(r'zmq\.PULL', content)),
                'PUB': len(re.findall(r'zmq\.PUB', content)),
                'SUB': len(re.findall(r'zmq\.SUB', content)),
                'REQ': len(re.findall(r'zmq\.REQ', content)),
                'REP': len(re.findall(r'zmq\.REP', content))
            }

            # Buscar puertos
            ports = re.findall(r':(\d{4})', content)
            unique_ports = list(set(ports))

            # Buscar bind vs connect
            binds = re.findall(r'\.bind\(["\']([^"\']+)["\']', content)
            connects = re.findall(r'\.connect\(["\']([^"\']+)["\']', content)

            patterns[filename] = {
                'component': component_name,
                'zmq_patterns': zmq_patterns,
                'ports': unique_ports,
                'binds': binds,
                'connects': connects
            }

            print(f"📡 Patrones ZMQ: {zmq_patterns}")
            print(f"🔌 Puertos: {unique_ports}")
            print(f"🎯 Bind: {binds}")
            print(f"🔗 Connect: {connects}")
        else:
            print(f"\n❌ {component_name}: Archivo {filename} no encontrado")

    return patterns


def analyze_flow_compatibility(patterns):
    """Analiza compatibilidad del flujo de datos"""

    print(f"\n{'=' * 50}")
    print("🔄 ANÁLISIS DE COMPATIBILIDAD")
    print("=" * 50)

    # Mapeo esperado del flujo
    expected_flow = {
        "promiscuous_agent.py": {
            "output_port": "5559",
            "output_pattern": "PUSH",
            "next_component": "ml_detector_with_persistence.py"
        },
        "ml_detector_with_persistence.py": {
            "input_port": "5559",
            "input_pattern": "PULL",
            "output_port": "5560",
            "output_pattern": "PUSH",  # o PUB
            "next_component": "real_zmq_dashboard_with_firewall.py"
        },
        "real_zmq_dashboard_with_firewall.py": {
            "input_port": "5560",
            "input_pattern": "PULL",  # o SUB
            "output_port": "5561",
            "output_pattern": "PUSH",
            "next_component": "firewall_agent.py"
        },
        "firewall_agent.py": {
            "input_port": "5561",
            "input_pattern": "PULL"
        }
    }

    print("🔍 Verificando flujo de datos:")
    print("Promiscuous → ML Detector → Dashboard → Firewall")

    incompatibilities = []

    for filename, expected in expected_flow.items():
        if filename in patterns:
            actual = patterns[filename]
            component = actual['component']

            print(f"\n{component}:")

            # Verificar input
            if 'input_port' in expected:
                input_port = expected['input_port']
                input_pattern = expected['input_pattern']

                if input_port in actual['ports']:
                    actual_input_patterns = [k for k, v in actual['zmq_patterns'].items() if v > 0]
                    if input_pattern in actual_input_patterns:
                        print(f"  ✅ Input: Puerto {input_port}, Patrón {input_pattern}")
                    else:
                        print(f"  ❌ Input: Puerto {input_port} encontrado, pero patrón incorrecto")
                        print(f"     Esperado: {input_pattern}, Actual: {actual_input_patterns}")
                        incompatibilities.append(f"{component}: Input pattern mismatch")
                else:
                    print(f"  ❌ Input: Puerto {input_port} no encontrado")
                    incompatibilities.append(f"{component}: Input port missing")

            # Verificar output
            if 'output_port' in expected:
                output_port = expected['output_port']
                output_pattern = expected['output_pattern']

                if output_port in actual['ports']:
                    actual_output_patterns = [k for k, v in actual['zmq_patterns'].items() if v > 0]
                    if output_pattern in actual_output_patterns:
                        print(f"  ✅ Output: Puerto {output_port}, Patrón {output_pattern}")
                    else:
                        print(f"  ❌ Output: Puerto {output_port} encontrado, pero patrón incorrecto")
                        print(f"     Esperado: {output_pattern}, Actual: {actual_output_patterns}")
                        incompatibilities.append(f"{component}: Output pattern mismatch")
                else:
                    print(f"  ❌ Output: Puerto {output_port} no encontrado")
                    incompatibilities.append(f"{component}: Output port missing")

    return incompatibilities


def suggest_fixes(incompatibilities, patterns):
    """Sugiere fixes específicos"""

    print(f"\n{'=' * 50}")
    print("🔧 SUGERENCIAS DE SOLUCIÓN")
    print("=" * 50)

    if not incompatibilities:
        print("✅ No se encontraron incompatibilidades obvias en el código")
        print("💡 El problema puede ser en la lógica de ejecución o timing")
    else:
        print("❌ Incompatibilidades encontradas:")
        for issue in incompatibilities:
            print(f"  • {issue}")

    print("\n🎯 PROBLEMAS ESPECÍFICOS DETECTADOS:")

    # Problema 1: ML Detector no envía output
    print("\n1. 🤖 ML Detector - No envía eventos procesados:")
    print("   CAUSA: El ML Detector recibe eventos pero timeout en output")
    print("   SOLUCIÓN: Verificar que el socket de output esté configurado correctamente")
    print("   COMANDO: grep -n 'bind.*5560\\|connect.*5560' ml_detector_with_persistence.py")

    # Problema 2: Puerto 5561 ocupado
    print("\n2. 🔥 Firewall Agent - Puerto 5561 ocupado:")
    print("   CAUSA: Socket no liberado correctamente o proceso zombie")
    print("   SOLUCIÓN: lsof -ti:5561 | xargs kill -9")

    # Problema 3: Posible PUSH/SUB mismatch
    print("\n3. 🔄 Patrón PUSH/SUB vs PUSH/PULL:")
    print("   PROBLEMA: Si ML Detector usa PUSH pero Dashboard usa SUB")
    print("   SOLUCIÓN: Cambiar a PUB/SUB o mantener PUSH/PULL consistente")

    print("\n💡 COMANDOS DE DIAGNÓSTICO:")
    print("# Verificar sockets ZMQ activos:")
    print("netstat -an | grep -E ':(5559|5560|5561|5562)' ")
    print()
    print("# Verificar que ML Detector esté enviando:")
    print("python3 -c \"")
    print("import zmq, time")
    print("ctx = zmq.Context()")
    print("sock = ctx.socket(zmq.SUB)")
    print("sock.connect('tcp://localhost:5560')")
    print("sock.setsockopt(zmq.SUBSCRIBE, b'')")
    print("sock.setsockopt(zmq.RCVTIMEO, 3000)")
    print("try:")
    print("    msg = sock.recv_string()")
    print("    print('✅ ML Detector enviando:', msg[:100])")
    print("except:")
    print("    print('❌ ML Detector NO está enviando')")
    print("\"")


def main():
    print("🚀 Analizando patrones ZMQ en upgraded-happiness...")

    # Analizar patrones en el código
    patterns = analyze_zmq_patterns()

    # Verificar compatibilidad
    incompatibilities = analyze_flow_compatibility(patterns)

    # Sugerir soluciones
    suggest_fixes(incompatibilities, patterns)

    print(f"\n{'=' * 50}")
    print("✅ Análisis completado")
    print("💡 Ejecuta los comandos de diagnóstico para confirmar")
    print("=" * 50)


if __name__ == "__main__":
    main()