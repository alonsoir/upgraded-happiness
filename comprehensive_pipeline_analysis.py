#!/usr/bin/env python3
"""
comprehensive_pipeline_analysis.py - Análisis sistémico completo
Revisar TODOS los componentes del pipeline V3.1 ETCD para diagnosticar problemas de conectividad
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional


class PipelineAnalyzer:
    def __init__(self):
        # Todos los archivos de configuración del pipeline
        self.config_files = {
            'evolutionary_sniffer': 'config/json/evolutionary_sniffer_config_v31.json',
            'geoip_enricher': 'config/json/geoip_enricher_config_v31.json',
            'ml_detector': 'config/json/lightweight_ml_detector_tricapa_v31_etcd_config_dev.json',
            'scheduler_firewall': 'config/json/scheduler_firewall_etcd_config_dev.json',
            'dashboard': 'config/json/dashboard_config_v31_etcd.json',
            'firewall_agent': 'config/json/simple_firewall_agent_v31_etcd.json',
            'firewall_rules': 'config/json/firewall_rules_v31.json'
        }

        self.configs = {}
        self.pipeline_map = {}

    def load_all_configs(self):
        """Cargar todos los archivos de configuración"""
        print("🔍 CARGANDO TODOS LOS CONFIGS DEL PIPELINE V3.1...")
        print("=" * 70)

        for component, file_path in self.config_files.items():
            file_p = Path(file_path)
            print(f"\n📋 {component.upper()}: {file_path}")

            if file_p.exists():
                try:
                    with open(file_p, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                        self.configs[component] = config
                        size_kb = file_p.stat().st_size / 1024
                        print(f"   ✅ Cargado exitosamente ({size_kb:.1f} KB)")

                        # Log componente info
                        node_id = config.get('node_id', 'N/A')
                        component_name = config.get('component', {}).get('name', 'N/A')
                        print(f"   🆔 Node ID: {node_id}")
                        print(f"   🏗️ Component: {component_name}")

                except Exception as e:
                    print(f"   ❌ Error cargando: {e}")
                    self.configs[component] = None
            else:
                print(f"   ❌ Archivo no encontrado")
                self.configs[component] = None

        loaded_count = len([c for c in self.configs.values() if c is not None])
        total_count = len(self.config_files)
        print(f"\n📊 RESUMEN CARGA: {loaded_count}/{total_count} configs cargados correctamente")

        return self.configs

    def map_pipeline_flow(self):
        """Mapear flujo completo del pipeline"""
        print("\n🔗 MAPEANDO FLUJO DEL PIPELINE...")
        print("=" * 70)

        pipeline_flow = {
            'evolutionary_sniffer': {'outputs_to': ['geoip_enricher'], 'receives_from': None},
            'geoip_enricher': {'outputs_to': ['ml_detector'], 'receives_from': ['evolutionary_sniffer']},
            'ml_detector': {'outputs_to': ['scheduler_firewall', 'dashboard'], 'receives_from': ['geoip_enricher']},
            'scheduler_firewall': {'outputs_to': ['firewall_agent'], 'receives_from': ['ml_detector']},
            'dashboard': {'outputs_to': [], 'receives_from': ['ml_detector']},
            'firewall_agent': {'outputs_to': ['scheduler_firewall'], 'receives_from': ['scheduler_firewall']}
        }

        print("📊 FLUJO REAL DEL PIPELINE V3.1:")
        print("   ┌─> Dashboard (Monitor/Vista)")
        print("   │")
        print("   Sniffer -> GeoIP -> ML_Detector ┤")
        print("                                   │")
        print("                                   └─> Scheduler -> Firewall_Agent")
        print()
        print("📋 CONEXIONES DETALLADAS:")
        for component, flow in pipeline_flow.items():
            receives_list = flow['receives_from'] or ['START']
            outputs_list = flow['outputs_to'] or ['END']

            receives = ' + '.join(receives_list) if isinstance(receives_list, list) else receives_list
            outputs = ' + '.join(outputs_list) if isinstance(outputs_list, list) else outputs_list

            print(f"   {receives} -> {component.upper()} -> {outputs}")

            if component == 'ml_detector':
                print("      🔍 ML_Detector tiene DUAL OUTPUT:")
                print("         📊 Puerto 5580 -> Dashboard (monitor)")
                print("         🔥 Puerto ???? -> Scheduler (acciones)")
            elif component == 'dashboard':
                print("      📊 Dashboard es SOLO MONITOR - no envía comandos firewall")
            elif component == 'scheduler_firewall':
                print("      🔥 Scheduler es quien REALMENTE maneja firewall commands")

        return pipeline_flow

    def analyze_network_endpoints(self):
        """Analizar endpoints de red de todos los componentes"""
        print("\n🌐 ANALIZANDO ENDPOINTS DE RED...")
        print("=" * 70)

        endpoints_map = {}

        for component, config in self.configs.items():
            if config is None:
                continue

            print(f"\n🔧 {component.upper()} ENDPOINTS:")
            endpoints_map[component] = {}

            # Buscar network section
            network = config.get('network', {})

            if not network:
                print(f"   ⚠️  No tiene sección 'network'")
                continue

            # Analizar inputs
            inputs = []
            for key, value in network.items():
                if 'input' in key.lower() and isinstance(value, dict):
                    port = value.get('port')
                    address = value.get('address', 'localhost')
                    mode = value.get('mode', 'unknown')
                    socket_type = value.get('socket_type', 'unknown')

                    endpoint = f"tcp://{address}:{port}"
                    inputs.append({
                        'name': key,
                        'endpoint': endpoint,
                        'mode': mode,
                        'socket_type': socket_type
                    })

                    print(f"   📥 INPUT {key}: {endpoint} ({mode}/{socket_type})")

            endpoints_map[component]['inputs'] = inputs

            # Analizar outputs
            outputs = []
            for key, value in network.items():
                if 'output' in key.lower() and isinstance(value, dict):
                    port = value.get('port')
                    address = value.get('address', 'localhost')
                    mode = value.get('mode', 'unknown')
                    socket_type = value.get('socket_type', 'unknown')

                    endpoint = f"tcp://{address}:{port}"
                    outputs.append({
                        'name': key,
                        'endpoint': endpoint,
                        'mode': mode,
                        'socket_type': socket_type
                    })

                    print(f"   📤 OUTPUT {key}: {endpoint} ({mode}/{socket_type})")

            endpoints_map[component]['outputs'] = outputs

            if not inputs and not outputs:
                print(f"   ⚠️  No se encontraron inputs/outputs definidos")

        return endpoints_map

    def verify_pipeline_connectivity(self, endpoints_map):
        """Verificar conectividad entre componentes del pipeline"""
        print("\n🔗 VERIFICANDO CONECTIVIDAD PIPELINE...")
        print("=" * 70)

        connections = []
        issues = []

        # Pipeline esperado con scheduler incluido:
        # sniffer -> geoip -> ml_detector -> {dashboard, scheduler} -> firewall_agent
        expected_connections = [
            ('evolutionary_sniffer', 'geoip_enricher'),
            ('geoip_enricher', 'ml_detector'),
            ('ml_detector', 'dashboard'),  # ML -> Dashboard (monitoring)
            ('ml_detector', 'scheduler_firewall'),  # ML -> Scheduler (actions)
            ('scheduler_firewall', 'firewall_agent')  # Scheduler -> Agent
        ]

        for source_comp, target_comp in expected_connections:
            print(f"\n🔍 Verificando: {source_comp.upper()} -> {target_comp.upper()}")

            source_config = self.configs.get(source_comp)
            target_config = self.configs.get(target_comp)

            if not source_config:
                issues.append(f"❌ {source_comp} config no encontrado")
                continue

            if not target_config:
                issues.append(f"❌ {target_comp} config no encontrado")
                continue

            # Buscar outputs del source
            source_endpoints = endpoints_map.get(source_comp, {})
            source_outputs = source_endpoints.get('outputs', [])

            # Buscar inputs del target
            target_endpoints = endpoints_map.get(target_comp, {})
            target_inputs = target_endpoints.get('inputs', [])

            print(f"   📤 {source_comp} outputs: {len(source_outputs)}")
            print(f"   📥 {target_comp} inputs: {len(target_inputs)}")

            # Buscar conexiones coincidentes
            matches = []
            for output in source_outputs:
                for input_ep in target_inputs:
                    if output['endpoint'] == input_ep['endpoint']:
                        matches.append({
                            'endpoint': output['endpoint'],
                            'output_mode': output['mode'],
                            'input_mode': input_ep['mode'],
                            'output_type': output['socket_type'],
                            'input_type': input_ep['socket_type']
                        })

            if matches:
                print(f"   ✅ {len(matches)} conexiones encontradas:")
                for match in matches:
                    print(
                        f"      🔗 {match['endpoint']} ({match['output_mode']}/{match['output_type']} -> {match['input_mode']}/{match['input_type']})")
                connections.append((source_comp, target_comp, matches))
            else:
                print(f"   ❌ No hay conexiones directas")
                issues.append(f"❌ No connection: {source_comp} -> {target_comp}")

                # Mostrar endpoints disponibles para debug
                if source_outputs:
                    print(f"      📤 Available outputs: {[o['endpoint'] for o in source_outputs]}")
                if target_inputs:
                    print(f"      📥 Available inputs: {[i['endpoint'] for i in target_inputs]}")

        return connections, issues

    def analyze_etcd_integration(self):
        """Analizar integración ETCD de todos los componentes"""
        print("\n🔐 ANALIZANDO INTEGRACIÓN ETCD...")
        print("=" * 70)

        etcd_summary = {}

        for component, config in self.configs.items():
            if config is None:
                continue

            print(f"\n🔐 {component.upper()} ETCD:")
            etcd_info = {}

            # Verificar sección crypto
            crypto = config.get('crypto', {})
            etcd_info['crypto_enabled'] = crypto.get('enabled', False)
            etcd_info['use_etcd_pipeline_key'] = crypto.get('use_etcd_pipeline_key', False)

            print(f"   🔐 crypto.enabled: {etcd_info['crypto_enabled']}")
            print(f"   🔑 use_etcd_pipeline_key: {etcd_info['use_etcd_pipeline_key']}")

            # Verificar sección etcd_crypto
            etcd_crypto = config.get('etcd_crypto', {})
            if etcd_crypto:
                etcd_info['etcd_host'] = etcd_crypto.get('etcd_host', 'N/A')
                etcd_info['etcd_port'] = etcd_crypto.get('etcd_port', 'N/A')
                etcd_info['cluster_name'] = etcd_crypto.get('cluster_name', 'N/A')
                etcd_info['node_id'] = etcd_crypto.get('node_id', 'N/A')

                print(f"   📡 ETCD: {etcd_info['etcd_host']}:{etcd_info['etcd_port']}")
                print(f"   🏢 Cluster: {etcd_info['cluster_name']}")
                print(f"   🆔 ETCD Node ID: {etcd_info['node_id']}")
            else:
                print(f"   ⚠️  No tiene sección 'etcd_crypto'")
                etcd_info['has_etcd_section'] = False

            etcd_summary[component] = etcd_info

        return etcd_summary

    def analyze_fleet_configuration(self):
        """Análisis específico de configuración fleet"""
        print("\n🔥 ANÁLISIS ESPECÍFICO FLEET MANAGEMENT...")
        print("=" * 70)

        dashboard_config = self.configs.get('dashboard')
        firewall_agent_config = self.configs.get('firewall_agent')
        firewall_rules = self.configs.get('firewall_rules')

        fleet_issues = []

        if dashboard_config:
            print("📊 DASHBOARD FLEET CONFIG:")
            fleet_config = dashboard_config.get('firewall_fleet', {})

            if not fleet_config:
                fleet_issues.append("❌ Dashboard: falta sección 'firewall_fleet'")
            else:
                enabled = fleet_config.get('enabled', False)
                agents = fleet_config.get('agents', [])

                print(f"   🔥 Fleet enabled: {enabled}")
                print(f"   🤖 Agents count: {len(agents)}")

                if not enabled:
                    fleet_issues.append("❌ Dashboard: firewall_fleet.enabled = false")

                if len(agents) == 0:
                    fleet_issues.append("❌ Dashboard: no agents in firewall_fleet.agents[]")

                for i, agent in enumerate(agents):
                    node_id = agent.get('node_id', f'agent_{i}')
                    print(f"      🤖 Agent {i + 1}: {node_id}")

                    endpoints = agent.get('network_endpoints', {})
                    dashboard_comm = endpoints.get('dashboard_communication', {})

                    if dashboard_comm:
                        cmd_input = dashboard_comm.get('commands_input')
                        resp_output = dashboard_comm.get('responses_output')
                        print(f"         📤 Commands: {cmd_input}")
                        print(f"         📥 Responses: {resp_output}")

                        if not cmd_input:
                            fleet_issues.append(f"❌ Agent {node_id}: falta commands_input")
                        if not resp_output:
                            fleet_issues.append(f"❌ Agent {node_id}: falta responses_output")
                    else:
                        fleet_issues.append(f"❌ Agent {node_id}: falta dashboard_communication")

        if firewall_agent_config:
            print(f"\n🔥 FIREWALL AGENT CONFIG:")
            node_id = firewall_agent_config.get('node_id', 'N/A')
            print(f"   🆔 Node ID: {node_id}")

            network = firewall_agent_config.get('network', {})
            dashboard_inputs = []
            dashboard_outputs = []

            for key, value in network.items():
                if 'dashboard' in key.lower() and isinstance(value, dict):
                    endpoint = f"tcp://{value.get('address', 'localhost')}:{value.get('port', 'N/A')}"
                    if 'input' in key.lower():
                        dashboard_inputs.append(endpoint)
                        print(f"   📥 Dashboard input: {endpoint}")
                    elif 'output' in key.lower():
                        dashboard_outputs.append(endpoint)
                        print(f"   📤 Dashboard output: {endpoint}")

            if not dashboard_inputs and not dashboard_outputs:
                fleet_issues.append(f"❌ Firewall agent: no dashboard communication endpoints")

        if firewall_rules:
            print(f"\n🔥 FIREWALL RULES CONFIG:")
            fw_rules = firewall_rules.get('firewall_rules', {})
            agents_fleet = fw_rules.get('agents_fleet', {})
            manual_actions = fw_rules.get('manual_actions', {})

            print(f"   🤖 agents_fleet count: {len(agents_fleet)}")
            print(f"   🔧 manual_actions count: {len(manual_actions)}")

            for agent_id, agent_config in agents_fleet.items():
                print(f"      🤖 {agent_id}: status={agent_config.get('status', 'N/A')}")

    def analyze_dashboard_role_confusion(self):
        """Analizar si Dashboard está confundido sobre su rol"""
        print("\n🔍 ANALIZANDO ROL DEL DASHBOARD...")
        print("=" * 70)

        dashboard_config = self.configs.get('dashboard')
        scheduler_config = self.configs.get('scheduler_firewall')

        role_issues = []

        if dashboard_config:
            print("📊 DASHBOARD ANÁLISIS DE ROL:")

            # ¿Dashboard intenta conectarse a firewall agents?
            fleet_config = dashboard_config.get('firewall_fleet', {})
            agents = fleet_config.get('agents', [])

            if len(agents) > 0:
                print(f"   ⚠️  Dashboard tiene {len(agents)} firewall agents configurados")
                print("   🤔 PERO: Dashboard debería ser SOLO monitor, no controlador")
                role_issues.append("❌ Dashboard configurado como controlador firewall (debería ser solo monitor)")

                for agent in agents:
                    endpoints = agent.get('network_endpoints', {})
                    dashboard_comm = endpoints.get('dashboard_communication', {})
                    if dashboard_comm:
                        print(f"      🔗 Intenta comunicarse con agent: {agent.get('node_id')}")
                        role_issues.append(
                            f"❌ Dashboard -> {agent.get('node_id')} communication (debería ser Scheduler -> Agent)")
            else:
                print("   ✅ Dashboard NO tiene agents configurados (correcto)")
                print("   📊 Dashboard ROL: Solo monitor/visualización")

        if scheduler_config:
            print(f"\n🔥 SCHEDULER ANÁLISIS DE ROL:")
            print("   ✅ Scheduler ROL: Controlador real de firewall")
            print("   🔥 Scheduler debería ser quien maneja fleet management")

            # Verificar si scheduler tiene configuración de agents
            network = scheduler_config.get('network', {})
            firewall_outputs = []
            for key, value in network.items():
                if 'firewall' in key.lower() and 'output' in key.lower():
                    firewall_outputs.append(f"{key}: {value.get('port', 'N/A')}")

            if firewall_outputs:
                print("   ✅ Scheduler tiene outputs a firewall:")
                for output in firewall_outputs:
                    print(f"      📤 {output}")
            else:
                print("   ⚠️  Scheduler no muestra outputs firewall claros")
                role_issues.append("❌ Scheduler sin outputs firewall claros")

        print(f"\n🎯 ARQUITECTURA CORRECTA ESPERADA:")
        print(f"   📊 Dashboard: SOLO recibe de ML_Detector (puerto 5580)")
        print(f"   🔥 Scheduler: Recibe de ML_Detector Y controla Firewall_Agent")
        print(f"   🤖 Firewall_Agent: Recibe comandos SOLO de Scheduler")

        return role_issues if role_issues else [] if role_issues else []

    def generate_connectivity_matrix(self, endpoints_map):
        """Generar matriz de conectividad visual"""
        print("\n📊 MATRIZ DE CONECTIVIDAD PIPELINE...")
        print("=" * 70)

        components = list(self.configs.keys())

        print("     ", end="")
        for comp in components:
            print(f"{comp[:8]:>8}", end="")
        print()

        for source in components:
            print(f"{source[:8]:>8} ", end="")

            for target in components:
                if source == target:
                    print("   -   ", end="")
                    continue

                # Buscar conexión
                source_endpoints = endpoints_map.get(source, {})
                target_endpoints = endpoints_map.get(target, {})

                source_outputs = source_endpoints.get('outputs', [])
                target_inputs = target_endpoints.get('inputs', [])

                connected = False
                for output in source_outputs:
                    for input_ep in target_inputs:
                        if output['endpoint'] == input_ep['endpoint']:
                            connected = True
                            break
                    if connected:
                        break

                print("   ✅   " if connected else "   ❌   ", end="")
            print()

    def run_comprehensive_analysis(self):
        """Ejecutar análisis completo"""
        print("🧬 Upgraded Happiness V3.1 - Análisis Sistémico Completo")
        print("=" * 80)
        print("Analizando TODOS los componentes del pipeline para diagnosticar problemas")

        # 1. Cargar todos los configs
        self.load_all_configs()

        # 2. Mapear flujo del pipeline
        pipeline_flow = self.map_pipeline_flow()

        # 3. Analizar endpoints de red
        endpoints_map = self.analyze_network_endpoints()

        # 4. Verificar conectividad
        connections, connectivity_issues = self.verify_pipeline_connectivity(endpoints_map)

        # 5. Analizar integración ETCD
        etcd_summary = self.analyze_etcd_integration()

        fleet_issues = self.analyze_fleet_configuration()
        if fleet_issues is None:
            fleet_issues = []

        # 7. Analizar rol del dashboard (nuevo)
        role_issues = self.analyze_dashboard_role_confusion()
        if role_issues is None:
            role_issues = []

        # 8. Generar matriz visual
        self.generate_connectivity_matrix(endpoints_map)

        # 8. Resumen final
        print("\n🎯 RESUMEN DIAGNÓSTICO COMPLETO...")
        print("=" * 80)

        # Contar configs cargados
        loaded_configs = len([c for c in self.configs.values() if c is not None])
        total_configs = len(self.config_files)

        # Contar componentes con ETCD
        etcd_enabled = len([info for info in etcd_summary.values()
                            if info.get('crypto_enabled', False)])

        # Contar conexiones válidas
        valid_connections = len(connections)

        print(f"📊 MÉTRICAS GENERALES:")
        print(f"   📋 Configs cargados: {loaded_configs}/{total_configs}")
        print(f"   🔐 Componentes con ETCD: {etcd_enabled}/{loaded_configs}")
        print(f"   🔗 Conexiones pipeline válidas: {valid_connections}/5")

        print(f"\n❌ PROBLEMAS ENCONTRADOS:")
        all_issues = connectivity_issues + fleet_issues

        if all_issues:
            for issue in all_issues:
                print(f"   {issue}")
        else:
            print(f"   ✅ No se encontraron problemas críticos")

        print(f"\n🔧 RECOMENDACIONES:")
        print(f"   1. Verificar que todos los componentes tengan ETCD habilitado")
        print(f"   2. Asegurar que endpoints de red coincidan entre componentes")
        print(f"   3. Confirmar que agents firewall estén registrados correctamente")
        print(f"   4. Verificar que ETCD cluster esté ejecutándose")

        return {
            'configs': self.configs,
            'endpoints': endpoints_map,
            'connections': connections,
            'issues': all_issues,
            'etcd_summary': etcd_summary
        }


def main():
    analyzer = PipelineAnalyzer()
    results = analyzer.run_comprehensive_analysis()

    print(f"\n🎉 ANÁLISIS COMPLETADO")
    print(f"Revisa los resultados arriba para identificar problemas específicos")


if __name__ == "__main__":
    main()