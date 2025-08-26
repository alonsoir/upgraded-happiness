#!/usr/bin/env python3
"""
comprehensive_etcd_verification.py - Verificación completa de ETCD integration
1. Revisar TODOS los JSON configs
2. Verificar que cada componente sube su config completo a ETCD
3. Analizar inconsistencias en endpoints
4. Validar cluster names y node IDs
5. Verificar fleet configurations entre todos los archivos
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class ETCDConfigurationVerifier:
    def __init__(self):
        # TODOS los archivos JSON del sistema
        self.config_files = {
            # Pipeline principal
            'evolutionary_sniffer': 'config/json/evolutionary_sniffer_config_v31.json',
            'geoip_enricher': 'config/json/geoip_enricher_config_v31.json',
            'ml_detector': 'config/json/lightweight_ml_detector_tricapa_v31_etcd_config_dev.json',
            'scheduler_firewall': 'config/json/scheduler_firewall_etcd_config_dev.json',
            'dashboard': 'config/json/dashboard_config_v31_etcd.json',
            'firewall_agent': 'config/json/simple_firewall_agent_v31_etcd.json',

            # Configuraciones adicionales
            'firewall_rules': 'config/json/firewall_rules_v31.json',

            # Posibles archivos adicionales que puedan existir
            'scheduler_config': 'config/json/scheduler-firewall-v31-etcd.json',
            'agent_config': 'config/json/simple_firewall_agent_config.json'
        }

        self.configs = {}
        self.etcd_issues = []
        self.endpoint_issues = []
        self.fleet_issues = []
        self.cluster_issues = []

    def load_all_available_configs(self):
        """Cargar todos los archivos de configuración disponibles"""
        print("🔍 CARGANDO TODOS LOS CONFIGS DISPONIBLES...")
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
                        print(f"   ✅ Cargado: {size_kb:.1f} KB")

                        # Info básica
                        node_id = config.get('node_id', 'N/A')
                        component_info = config.get('component', {})
                        comp_name = component_info.get('name', 'N/A') if isinstance(component_info, dict) else 'N/A'
                        print(f"   🆔 Node ID: {node_id}")
                        print(f"   🏗️ Component: {comp_name}")

                except Exception as e:
                    print(f"   ❌ Error: {e}")
                    self.configs[component] = None
            else:
                print(f"   ⚠️  No existe")
                self.configs[component] = None

        loaded = len([c for c in self.configs.values() if c is not None])
        total = len(self.config_files)
        print(f"\n📊 Cargados: {loaded}/{total} configs")

    def analyze_etcd_configurations(self):
        """Análisis detallado de configuraciones ETCD"""
        print("\n🔐 ANÁLISIS DETALLADO ETCD CONFIGURATIONS...")
        print("=" * 70)

        etcd_components = {}
        cluster_names = set()

        for component, config in self.configs.items():
            if config is None:
                continue

            print(f"\n🔐 {component.upper()} ETCD CONFIG:")
            etcd_info = {}

            # Crypto section
            crypto = config.get('crypto', {})
            etcd_info['crypto_enabled'] = crypto.get('enabled', False)
            etcd_info['use_etcd_pipeline_key'] = crypto.get('use_etcd_pipeline_key', False)
            etcd_info['algorithm'] = crypto.get('algorithm', 'N/A')

            print(f"   🔐 crypto.enabled: {etcd_info['crypto_enabled']}")
            print(f"   🔑 use_etcd_pipeline_key: {etcd_info['use_etcd_pipeline_key']}")

            if not etcd_info['crypto_enabled']:
                self.etcd_issues.append(f"❌ {component}: crypto.enabled = false")

            if not etcd_info['use_etcd_pipeline_key']:
                self.etcd_issues.append(f"❌ {component}: use_etcd_pipeline_key = false")

            # ETCD crypto section
            etcd_crypto = config.get('etcd_crypto', {})
            if etcd_crypto:
                etcd_info['etcd_host'] = etcd_crypto.get('etcd_host', 'N/A')
                etcd_info['etcd_port'] = etcd_crypto.get('etcd_port', 'N/A')
                etcd_info['cluster_name'] = etcd_crypto.get('cluster_name', 'N/A')
                etcd_info['etcd_node_id'] = etcd_crypto.get('node_id', 'N/A')

                print(f"   📡 ETCD: {etcd_info['etcd_host']}:{etcd_info['etcd_port']}")
                print(f"   🏢 Cluster: {etcd_info['cluster_name']}")
                print(f"   🆔 ETCD Node: {etcd_info['etcd_node_id']}")

                cluster_names.add(etcd_info['cluster_name'])

                # Verificar consistencia
                if etcd_info['etcd_host'] != 'localhost':
                    self.etcd_issues.append(f"⚠️ {component}: ETCD host no es localhost")

                if etcd_info['etcd_port'] != 2379:
                    self.etcd_issues.append(f"⚠️ {component}: ETCD port no es 2379")

            else:
                print(f"   ❌ Sin etcd_crypto section")
                etcd_info['has_etcd_crypto'] = False
                self.etcd_issues.append(f"❌ {component}: falta etcd_crypto section")

            # Verificar auto-upload config
            auto_upload = config.get('auto_upload_config_to_etcd', True)
            etcd_info['auto_upload'] = auto_upload
            print(f"   📤 Auto upload to ETCD: {auto_upload}")

            if not auto_upload:
                self.etcd_issues.append(f"⚠️ {component}: auto_upload_config_to_etcd = false")

            etcd_components[component] = etcd_info

        # Verificar cluster names consistency
        if len(cluster_names) > 1:
            self.cluster_issues.append(f"❌ Múltiples cluster names: {cluster_names}")
            print(f"\n❌ INCONSISTENCIA: Múltiples cluster names encontrados:")
            for name in cluster_names:
                print(f"   🏢 {name}")
        else:
            print(f"\n✅ Cluster name consistente: {cluster_names.pop() if cluster_names else 'N/A'}")

        return etcd_components

    def cross_reference_fleet_configurations(self):
        """Cross-reference de todas las configuraciones fleet"""
        print("\n🔥 CROSS-REFERENCE FLEET CONFIGURATIONS...")
        print("=" * 70)

        # Dashboard fleet config
        dashboard_config = self.configs.get('dashboard')
        dashboard_agents = {}
        if dashboard_config:
            fleet_config = dashboard_config.get('firewall_fleet', {})
            print(f"📊 DASHBOARD FLEET:")
            print(f"   Enabled: {fleet_config.get('enabled', False)}")

            agents = fleet_config.get('agents', [])
            print(f"   Agents: {len(agents)}")

            for agent in agents:
                agent_id = agent.get('node_id', 'unknown')
                dashboard_agents[agent_id] = agent
                print(f"      🤖 {agent_id}")

                endpoints = agent.get('network_endpoints', {})
                dashboard_comm = endpoints.get('dashboard_communication', {})
                if dashboard_comm:
                    print(f"         📤 Commands: {dashboard_comm.get('commands_input', 'N/A')}")
                    print(f"         📥 Responses: {dashboard_comm.get('responses_output', 'N/A')}")

        # Firewall rules config
        firewall_rules = self.configs.get('firewall_rules')
        rules_agents = {}
        if firewall_rules:
            fw_rules = firewall_rules.get('firewall_rules', {})
            agents_fleet = fw_rules.get('agents_fleet', {})
            print(f"\n🔥 FIREWALL RULES FLEET:")
            print(f"   Agents: {len(agents_fleet)}")

            for agent_id, agent_config in agents_fleet.items():
                rules_agents[agent_id] = agent_config
                print(f"      🤖 {agent_id}: {agent_config.get('status', 'N/A')}")

                # Verificar network endpoints
                endpoints = agent_config.get('network_endpoints', {})
                if endpoints:
                    dashboard_comm = endpoints.get('dashboard_communication', {})
                    scheduler_comm = endpoints.get('scheduler_communication', {})

                    if dashboard_comm:
                        print(f"         📊 Dashboard comm: {list(dashboard_comm.keys())}")
                    if scheduler_comm:
                        print(f"         🔥 Scheduler comm: {list(scheduler_comm.keys())}")

        # Agent individual configs
        agent_config = self.configs.get('firewall_agent')
        agent_network = {}
        if agent_config:
            print(f"\n🤖 INDIVIDUAL AGENT CONFIG:")
            node_id = agent_config.get('node_id', 'N/A')
            print(f"   Node ID: {node_id}")

            network = agent_config.get('network', {})
            agent_network = network
            print(f"   Network endpoints: {len(network)}")

            for key, value in network.items():
                if isinstance(value, dict):
                    endpoint = f"tcp://{value.get('address', 'localhost')}:{value.get('port', 'N/A')}"
                    mode = value.get('mode', 'N/A')
                    socket_type = value.get('socket_type', 'N/A')
                    print(f"      {key}: {endpoint} ({mode}/{socket_type})")

        # Scheduler config
        scheduler_config = self.configs.get('scheduler_firewall')
        scheduler_fleet = {}
        if scheduler_config:
            print(f"\n🔥 SCHEDULER CONFIG:")

            # Fleet management en scheduler
            fleet_config = scheduler_config.get('fleet_management', {})
            if fleet_config:
                print(f"   Fleet management: {fleet_config.get('enabled', False)}")
                agents = fleet_config.get('agents', [])
                print(f"   Agents: {len(agents)}")

                for agent in agents:
                    agent_id = agent.get('node_id', 'unknown')
                    scheduler_fleet[agent_id] = agent
                    print(f"      🤖 {agent_id}")

        # Cross-reference analysis
        print(f"\n🔍 CROSS-REFERENCE ANALYSIS:")

        all_agent_ids = set()
        all_agent_ids.update(dashboard_agents.keys())
        all_agent_ids.update(rules_agents.keys())
        all_agent_ids.update(scheduler_fleet.keys())
        if agent_config:
            all_agent_ids.add(agent_config.get('node_id', 'unknown'))

        print(f"   🤖 Total unique agent IDs: {len(all_agent_ids)}")
        for agent_id in all_agent_ids:
            print(f"      {agent_id}:")
            print(f"         Dashboard: {'✅' if agent_id in dashboard_agents else '❌'}")
            print(f"         Rules: {'✅' if agent_id in rules_agents else '❌'}")
            print(f"         Scheduler: {'✅' if agent_id in scheduler_fleet else '❌'}")

            # Verificar consistency de endpoints
            if agent_id in dashboard_agents and agent_config and agent_config.get('node_id') == agent_id:
                dashboard_comm = dashboard_agents[agent_id].get('network_endpoints', {}).get('dashboard_communication',
                                                                                             {})
                cmd_input = dashboard_comm.get('commands_input', '')
                resp_output = dashboard_comm.get('responses_output', '')

                # Buscar endpoints correspondientes en agent config
                dashboard_cmd_found = False
                dashboard_resp_found = False

                for key, value in agent_network.items():
                    if isinstance(value, dict):
                        endpoint = f"tcp://{value.get('address', 'localhost')}:{value.get('port')}"
                        if 'dashboard' in key and 'command' in key and endpoint == cmd_input:
                            dashboard_cmd_found = True
                        if 'dashboard' in key and 'response' in key and endpoint == resp_output:
                            dashboard_resp_found = True

                if not dashboard_cmd_found:
                    self.fleet_issues.append(f"❌ {agent_id}: Dashboard commands endpoint mismatch")
                if not dashboard_resp_found:
                    self.fleet_issues.append(f"❌ {agent_id}: Dashboard responses endpoint mismatch")

    def analyze_network_endpoint_consistency(self):
        """Analizar consistencia de endpoints de red entre todos los componentes"""
        print("\n🌐 ANÁLISIS DE CONSISTENCIA DE ENDPOINTS...")
        print("=" * 70)

        all_endpoints = {}  # port -> [components_using_it]
        endpoint_conflicts = []

        for component, config in self.configs.items():
            if config is None:
                continue

            network = config.get('network', {})
            if not network:
                continue

            print(f"\n🔧 {component.upper()} ENDPOINTS:")

            for key, value in network.items():
                if isinstance(value, dict):
                    port = value.get('port')
                    address = value.get('address', 'localhost')
                    mode = value.get('mode', 'N/A')
                    socket_type = value.get('socket_type', 'N/A')

                    endpoint = f"tcp://{address}:{port}"
                    print(f"   {key}: {endpoint} ({mode}/{socket_type})")

                    if port:
                        if port not in all_endpoints:
                            all_endpoints[port] = []
                        all_endpoints[port].append({
                            'component': component,
                            'key': key,
                            'mode': mode,
                            'socket_type': socket_type
                        })

        # Detectar conflictos de puertos
        print(f"\n📊 ANÁLISIS DE PUERTOS:")
        for port, users in all_endpoints.items():
            print(f"   Puerto {port}: {len(users)} usuarios")

            bind_users = [u for u in users if u['mode'] == 'bind']
            connect_users = [u for u in users if u['mode'] == 'connect']

            if len(bind_users) > 1:
                endpoint_conflicts.append(f"❌ Puerto {port}: múltiples BIND - {[u['component'] for u in bind_users]}")
                print(f"      ❌ CONFLICTO: Múltiples BIND")
                for user in bind_users:
                    print(f"         {user['component']}.{user['key']} ({user['socket_type']})")
            elif len(bind_users) == 1 and len(connect_users) > 0:
                print(f"      ✅ Válido: 1 BIND, {len(connect_users)} CONNECT")
                print(f"         BIND: {bind_users[0]['component']}.{bind_users[0]['key']}")
                for user in connect_users:
                    print(f"         CONNECT: {user['component']}.{user['key']}")
            elif len(bind_users) == 0 and len(connect_users) > 0:
                endpoint_conflicts.append(
                    f"⚠️ Puerto {port}: CONNECT sin BIND - {[u['component'] for u in connect_users]}")
                print(f"      ⚠️ PROBLEMA: CONNECT sin BIND")

        return endpoint_conflicts

    def generate_fix_recommendations(self):
        """Generar recomendaciones específicas de corrección"""
        print("\n🔧 RECOMENDACIONES DE CORRECCIÓN...")
        print("=" * 70)

        all_issues = self.etcd_issues + self.endpoint_issues + self.fleet_issues + self.cluster_issues

        if not all_issues:
            print("✅ No se encontraron problemas críticos")
            return

        # Agrupar issues por tipo
        etcd_fixes = [issue for issue in all_issues if 'crypto' in issue or 'etcd' in issue.lower()]
        endpoint_fixes = [issue for issue in all_issues if 'endpoint' in issue.lower() or 'puerto' in issue.lower()]
        fleet_fixes = [issue for issue in all_issues if 'fleet' in issue.lower() or 'agent' in issue.lower()]
        cluster_fixes = [issue for issue in all_issues if 'cluster' in issue.lower()]

        if etcd_fixes:
            print("🔐 PROBLEMAS ETCD:")
            for issue in etcd_fixes:
                print(f"   {issue}")

        if cluster_fixes:
            print("\n🏢 PROBLEMAS CLUSTER:")
            for issue in cluster_fixes:
                print(f"   {issue}")

            print("\n   🔧 SOLUCIÓN CLUSTER:")
            print("   1. Standardizar a 'upgraded-happiness-cluster-v31'")
            print("   2. Actualizar evolutionary_sniffer y geoip_enricher")

        if endpoint_fixes:
            print("\n🌐 PROBLEMAS ENDPOINTS:")
            for issue in endpoint_fixes:
                print(f"   {issue}")

        if fleet_fixes:
            print("\n🔥 PROBLEMAS FLEET:")
            for issue in fleet_fixes:
                print(f"   {issue}")

            print("\n   🔧 SOLUCIÓN FLEET:")
            print("   1. Verificar endpoints Dashboard -> Agent (5583/5584)")
            print("   2. Asegurar que Agent escucha en puertos correctos")
            print("   3. Verificar que Dashboard fleet_manager puede conectarse")

    def run_complete_verification(self):
        """Ejecutar verificación completa"""
        print("🧬 Upgraded Happiness V3.1 - Verificación Completa ETCD")
        print("=" * 80)
        print("Verificando TODOS los configs, ETCD integration, y fleet management")

        # 1. Cargar todos los configs
        self.load_all_available_configs()

        # 2. Analizar ETCD configurations
        etcd_components = self.analyze_etcd_configurations()

        # 3. Cross-reference fleet configurations
        self.cross_reference_fleet_configurations()

        # 4. Analizar network endpoints
        self.endpoint_issues = self.analyze_network_endpoint_consistency()

        # 5. Generar recomendaciones
        self.generate_fix_recommendations()

        return {
            'configs': self.configs,
            'etcd_components': etcd_components,
            'issues': {
                'etcd': self.etcd_issues,
                'endpoints': self.endpoint_issues,
                'fleet': self.fleet_issues,
                'cluster': self.cluster_issues
            }
        }


def main():
    verifier = ETCDConfigurationVerifier()
    results = verifier.run_complete_verification()

    print(f"\n🎉 VERIFICACIÓN COMPLETA TERMINADA")

    total_issues = sum(len(issues) for issues in results['issues'].values())
    if total_issues > 0:
        print(f"📊 {total_issues} problemas encontrados - revisa las recomendaciones arriba")
    else:
        print(f"✅ Sistema configurado correctamente")


if __name__ == "__main__":
    main()