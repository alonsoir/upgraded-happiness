#!/usr/bin/env python3
"""
config_audit_updated.py
Auditoría completa de configuración actual - VERSIÓN ACTUALIZADA
Usa solo los componentes correctos y detecta el problema ML Detector → Dashboard
"""

import os
import re
import json
from typing import Dict, List, Any


class ConfigAuditor:
    def __init__(self):
        # COMPONENTES CORRECTOS (sin duplicados)
        self.components = [
            "simple_firewall_agent.py",  # ✅ Usar este (NO firewall_agent.py)
            "ml_detector_with_persistence.py",  # ✅ El principal ML
            "real_zmq_dashboard_with_firewall.py",  # ✅ Dashboard con firewall
            "promiscuous_agent.py",  # ✅ Enhanced agent
            "geoip_enricher.py"  # ✅ GeoIP enricher
        ]

        # ARCHIVOS JSON CORRESPONDIENTES
        self.config_files = [
            "simple_firewall_agent_config.json",  # ✅ Para simple_firewall_agent.py
            "lightweight_ml_detector_config.json",  # ✅ Para ml_detector_with_persistence.py
            "dashboard_config.json",  # ✅ Para real_zmq_dashboard_with_firewall.py
            "enhanced_agent_config.json",  # ✅ Para promiscuous_agent.py
            "geoip_enricher_config.json"  # ✅ Para geoip_enricher.py
        ]

        # MAPEO ESPECÍFICO COMPONENTE → CONFIG
        self.component_config_map = {
            "simple_firewall_agent.py": "simple_firewall_agent_config.json",
            "ml_detector_with_persistence.py": "lightweight_ml_detector_config.json",
            "real_zmq_dashboard_with_firewall.py": "dashboard_config.json",
            "promiscuous_agent.py": "enhanced_agent_config.json",
            "geoip_enricher.py": "geoip_enricher_config.json"
        }

    def audit_component(self, component_file: str) -> Dict[str, Any]:
        """Audita un componente específico con detección avanzada"""
        if not os.path.exists(component_file):
            return {"error": f"Archivo {component_file} no encontrado"}

        with open(component_file, 'r', encoding='utf-8') as f:
            code = f.read()

        audit_result = {
            "file": component_file,
            "hardcoded_ports": [],
            "hardcoded_addresses": [],
            "json_config_usage": {},
            "default_values": {},
            "potential_conflicts": [],
            "zmq_patterns": {},
            "bind_connect_usage": {},
            "config_file_expected": self.component_config_map.get(component_file, "unknown")
        }

        # 1. BUSCAR PUERTOS HARDCODEADOS (más exhaustivo)
        port_patterns = [
            r':(\d{4})',  # :5559
            r'port.*?=.*?(\d{4})',  # port = 5559
            r'(\d{4})\s*#.*port',  # 5559 # port comment
            r'tcp://[^:]*:(\d{4})',  # tcp://localhost:5559
            r'bind\(["\']tcp://[^:]*:(\d{4})["\']',  # socket.bind("tcp://*:5559")
            r'connect\(["\']tcp://[^:]*:(\d{4})["\']',  # socket.connect("tcp://localhost:5559")
            r'(\d{4})\s*\).*#.*port',  # 5559) # puerto de salida
        ]

        for pattern in port_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            for match in matches:
                if match.isdigit() and 5000 <= int(match) <= 6000:
                    audit_result["hardcoded_ports"].append(int(match))

        # 2. BUSCAR DIRECCIONES HARDCODEADAS
        address_patterns = [
            r'["\']localhost["\']',
            r'["\']127\.0\.0\.1["\']',
            r'["\']\*["\']',
            r'tcp://([^"\':\s]+)["\']',
            r'bind_address.*?=.*?["\']([^"\']+)["\']'
        ]

        for pattern in address_patterns:
            matches = re.findall(pattern, code)
            audit_result["hardcoded_addresses"].extend(matches)

        # 3. BUSCAR USO DE CONFIGURACIÓN JSON (más específico)
        json_patterns = [
            r'config\[["\']([^"\']+)["\']\]',
            r'config\.get\(["\']([^"\']+)["\']',
            r'([a-zA-Z_]+_port)\s*=.*config',
            r'([a-zA-Z_]+_address)\s*=.*config',
            r'network_config\[["\']([^"\']+)["\']\]',
            r'self\.([a-zA-Z_]+_port)\s*=.*config'
        ]

        for pattern in json_patterns:
            matches = re.findall(pattern, code)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match[0] else match[1]
                audit_result["json_config_usage"][match] = True

        # 4. BUSCAR VALORES POR DEFECTO (crítico para detectar conflictos)
        default_patterns = [
            r'(\w+)\s*=\s*config\.get\(["\']([^"\']+)["\'],\s*([^)]+)\)',
            r'def\s+__init__.*?(\w+_port)\s*=\s*(\d+)',
            r'(\w+_port)\s*=\s*(\d+).*#.*default',
            r'input_port\s*=\s*(\d+)',
            r'output_port\s*=\s*(\d+)',
        ]

        for pattern in default_patterns:
            matches = re.findall(pattern, code)
            for match in matches:
                if len(match) >= 2:
                    if len(match) == 3:
                        var_name, json_key, default_val = match[0], match[1], match[2]
                        audit_result["default_values"][json_key] = default_val.strip()
                    else:
                        var_name, default_val = match[0], match[1]
                        audit_result["default_values"][var_name] = default_val.strip()

        # 5. BUSCAR PATRONES ZMQ
        zmq_patterns = {
            'PUSH': len(re.findall(r'zmq\.PUSH', code)),
            'PULL': len(re.findall(r'zmq\.PULL', code)),
            'PUB': len(re.findall(r'zmq\.PUB', code)),
            'SUB': len(re.findall(r'zmq\.SUB', code)),
            'REQ': len(re.findall(r'zmq\.REQ', code)),
            'REP': len(re.findall(r'zmq\.REP', code))
        }
        audit_result["zmq_patterns"] = zmq_patterns

        # 6. BUSCAR BIND vs CONNECT
        bind_matches = re.findall(r'\.bind\(["\']([^"\']+)["\']', code)
        connect_matches = re.findall(r'\.connect\(["\']([^"\']+)["\']', code)

        audit_result["bind_connect_usage"] = {
            "binds": bind_matches,
            "connects": connect_matches
        }

        # 7. ANÁLISIS ESPECÍFICO POR COMPONENTE
        if component_file == "ml_detector_with_persistence.py":
            audit_result.update(self._analyze_ml_detector_specific(code))
        elif component_file == "real_zmq_dashboard_with_firewall.py":
            audit_result.update(self._analyze_dashboard_specific(code))

        # 8. DETECTAR CONFLICTOS POTENCIALES
        conflicts = []

        if audit_result["hardcoded_ports"] and audit_result["json_config_usage"]:
            conflicts.append("❌ Puertos hardcodeados + lee JSON = posible conflicto")

        if '"localhost"' in str(audit_result["hardcoded_addresses"]):
            conflicts.append("❌ 'localhost' hardcodeado = no escalable")

        if '"*"' in str(audit_result["hardcoded_addresses"]):
            conflicts.append("❌ '*' hardcodeado = no escalable")

        if len(audit_result["default_values"]) > 3:
            conflicts.append("❌ Muchos defaults = poca dependencia del JSON")

        audit_result["potential_conflicts"] = conflicts

        return audit_result

    def _analyze_ml_detector_specific(self, code: str) -> Dict[str, Any]:
        """Análisis específico del ML Detector para detectar el bug principal"""
        ml_analysis = {
            "ml_detector_issues": [],
            "output_port_analysis": {},
            "input_port_analysis": {}
        }

        # Buscar configuración de output port específicamente
        output_patterns = [
            r'output_port\s*=\s*(\d+)',
            r'def\s+__init__.*output_port\s*=\s*(\d+)',
            r'self\.output_port\s*=.*?(\d+)',
            r'bind.*?(\d{4})',
            r'5560|5561'  # Puertos específicos del problema
        ]

        for pattern in output_patterns:
            matches = re.findall(pattern, code)
            if matches:
                ml_analysis["output_port_analysis"][pattern] = matches

        # Detectar si hay conflicto ML → Dashboard
        if '5560' in code and '5561' in code:
            ml_analysis["ml_detector_issues"].append(
                "🔥 CONFLICTO DETECTADO: Contiene tanto 5560 como 5561"
            )

        return ml_analysis

    def _analyze_dashboard_specific(self, code: str) -> Dict[str, Any]:
        """Análisis específico del Dashboard"""
        dashboard_analysis = {
            "dashboard_issues": [],
            "events_input_analysis": {},
            "multiple_ports": []
        }

        # Buscar puertos de eventos
        events_patterns = [
            r'events_input_port\s*=\s*(\d+)',
            r'events.*?(\d{4})',
            r'5560|5561'  # Puertos del problema
        ]

        for pattern in events_patterns:
            matches = re.findall(pattern, code)
            if matches:
                dashboard_analysis["events_input_analysis"][pattern] = matches

        return dashboard_analysis

    def audit_json_configs(self) -> Dict[str, Any]:
        """Audita archivos JSON con enfoque en estructura distribuida"""
        json_audit = {}

        for config_file in self.config_files:
            if not os.path.exists(config_file):
                json_audit[config_file] = {"error": "No encontrado"}
                continue

            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)

                audit = {
                    "ports": [],
                    "addresses": [],
                    "structure": {},
                    "scalability_issues": [],
                    "distribution_readiness": {}
                }

                # Extraer puertos de toda la estructura
                def extract_ports(obj, path=""):
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            current_path = f"{path}.{key}" if path else key
                            if 'port' in key.lower() and isinstance(value, int):
                                audit["ports"].append({"key": current_path, "port": value})
                            elif isinstance(value, (dict, list)):
                                extract_ports(value, current_path)

                extract_ports(config)

                # Extraer direcciones
                def extract_addresses(obj, path=""):
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            current_path = f"{path}.{key}" if path else key
                            if 'address' in key.lower() and isinstance(value, str):
                                audit["addresses"].append({"key": current_path, "address": value})
                            elif isinstance(value, (dict, list)):
                                extract_addresses(value, current_path)

                extract_addresses(config)

                # Analizar estructura para distribución
                audit["structure"] = {
                    "has_network_section": "network" in config,
                    "has_component_section": "component" in config,
                    "has_zmq_section": "zmq" in config,
                    "top_level_keys": list(config.keys()),
                    "network_structure": config.get("network", {}).keys() if "network" in config else []
                }

                # Evaluar preparación para distribución
                network_section = config.get("network", {})

                has_structured_sockets = any(
                    isinstance(v, dict) and all(k in v for k in ["address", "port", "mode"])
                    for v in network_section.values()
                )

                audit["distribution_readiness"] = {
                    "has_structured_sockets": has_structured_sockets,
                    "uses_legacy_format": not has_structured_sockets,
                    "needs_refactoring": not has_structured_sockets
                }

                # Problemas de escalabilidad
                for addr_info in audit["addresses"]:
                    addr = addr_info["address"]
                    if addr in ["localhost", "127.0.0.1", "*"]:
                        audit["scalability_issues"].append(
                            f"❌ {addr_info['key']}: '{addr}' no es escalable"
                        )

                if audit["distribution_readiness"]["needs_refactoring"]:
                    audit["scalability_issues"].append(
                        "🔧 Necesita refactoring a formato distribuido"
                    )

                json_audit[config_file] = audit

            except json.JSONDecodeError as e:
                json_audit[config_file] = {"error": f"JSON inválido: {e}"}
            except Exception as e:
                json_audit[config_file] = {"error": f"Error: {e}"}

        return json_audit

    def find_ml_dashboard_conflict(self, python_audit: Dict, json_audit: Dict) -> Dict[str, Any]:
        """Encuentra ESPECÍFICAMENTE el conflicto ML Detector → Dashboard"""

        conflict_analysis = {
            "conflict_detected": False,
            "ml_detector_ports": [],
            "dashboard_ports": [],
            "suspected_issue": None,
            "evidence": []
        }

        # Analizar ML Detector
        ml_audit = python_audit.get("ml_detector_with_persistence.py", {})
        if "error" not in ml_audit:
            ml_ports = ml_audit.get("hardcoded_ports", [])
            ml_defaults = ml_audit.get("default_values", {})

            conflict_analysis["ml_detector_ports"] = ml_ports

            if ml_ports:
                conflict_analysis["evidence"].append(
                    f"🤖 ML Detector puertos hardcodeados: {ml_ports}"
                )

        # Analizar Dashboard
        dashboard_audit = python_audit.get("real_zmq_dashboard_with_firewall.py", {})
        if "error" not in dashboard_audit:
            dashboard_ports = dashboard_audit.get("hardcoded_ports", [])

            conflict_analysis["dashboard_ports"] = dashboard_ports

            if dashboard_ports:
                conflict_analysis["evidence"].append(
                    f"📊 Dashboard puertos hardcodeados: {dashboard_ports}"
                )

        # Analizar JSONs
        ml_json = json_audit.get("lightweight_ml_detector_config.json", {})
        dashboard_json = json_audit.get("dashboard_config.json", {})

        if "error" not in ml_json:
            ml_json_ports = [p["port"] for p in ml_json.get("ports", [])]
            if ml_json_ports:
                conflict_analysis["evidence"].append(
                    f"📄 ML JSON puertos: {ml_json_ports}"
                )

        if "error" not in dashboard_json:
            dashboard_json_ports = [p["port"] for p in dashboard_json.get("ports", [])]
            if dashboard_json_ports:
                conflict_analysis["evidence"].append(
                    f"📄 Dashboard JSON puertos: {dashboard_json_ports}"
                )

        # DETECTAR EL CONFLICTO ESPECÍFICO
        ml_ports = conflict_analysis["ml_detector_ports"]
        dashboard_ports = conflict_analysis["dashboard_ports"]

        if 5560 in ml_ports and 5561 in dashboard_ports:
            conflict_analysis["conflict_detected"] = True
            conflict_analysis["suspected_issue"] = (
                "🔥 CONFLICTO DETECTADO: ML Detector usa 5560, Dashboard espera 5561"
            )
        elif 5561 in ml_ports and 5560 in dashboard_ports:
            conflict_analysis["conflict_detected"] = True
            conflict_analysis["suspected_issue"] = (
                "🔥 CONFLICTO DETECTADO: ML Detector usa 5561, Dashboard espera 5560"
            )

        return conflict_analysis

    def generate_report(self) -> str:
        """Genera reporte completo con enfoque en el problema principal"""
        print("🔍 AUDITORÍA COMPLETA DE CONFIGURACIÓN (COMPONENTES CORRECTOS)")
        print("=" * 70)

        # Auditar componentes Python
        print("\n📄 AUDITANDO COMPONENTES PYTHON...")
        python_audit = {}
        for component in self.components:
            print(f"   🔍 {component}...")
            python_audit[component] = self.audit_component(component)

        # Auditar JSONs
        print("\n📋 AUDITANDO ARCHIVOS JSON...")
        json_audit = self.audit_json_configs()

        # Buscar conflicto específico ML → Dashboard
        print("\n🎯 ANALIZANDO CONFLICTO ML DETECTOR → DASHBOARD...")
        conflict_analysis = self.find_ml_dashboard_conflict(python_audit, json_audit)

        # Generar reporte
        report = []
        report.append("🔍 REPORTE DE AUDITORÍA - COMPONENTES CORRECTOS")
        report.append("=" * 70)

        # SECCIÓN CRÍTICA: Conflicto ML → Dashboard
        report.append("\n🎯 ANÁLISIS CRÍTICO: ML DETECTOR → DASHBOARD")
        report.append("-" * 50)

        if conflict_analysis["conflict_detected"]:
            report.append(f"🔥 {conflict_analysis['suspected_issue']}")
            report.append("\n📋 Evidencia:")
            for evidence in conflict_analysis["evidence"]:
                report.append(f"   {evidence}")
        else:
            report.append("✅ No se detectó conflicto obvio en puertos")
            if conflict_analysis["evidence"]:
                report.append("\n📋 Información encontrada:")
                for evidence in conflict_analysis["evidence"]:
                    report.append(f"   {evidence}")

        # Resto del reporte...
        report.append(f"\n📄 COMPONENTES PYTHON:")
        for component, audit in python_audit.items():
            if "error" in audit:
                report.append(f"\n❌ {component}: {audit['error']}")
                continue

            report.append(f"\n🔧 {component}:")
            report.append(f"   📄 Config esperado: {audit['config_file_expected']}")

            if audit["hardcoded_ports"]:
                report.append(f"   🔴 Puertos hardcodeados: {audit['hardcoded_ports']}")

            if audit["hardcoded_addresses"]:
                report.append(f"   🔴 Direcciones hardcodeadas: {audit['hardcoded_addresses']}")

            if audit["json_config_usage"]:
                report.append(f"   ✅ Lee del JSON: {list(audit['json_config_usage'].keys())}")

            if audit["default_values"]:
                report.append(f"   ⚠️  Valores por defecto: {audit['default_values']}")

            if audit["zmq_patterns"]:
                patterns = [k for k, v in audit["zmq_patterns"].items() if v > 0]
                if patterns:
                    report.append(f"   📡 Patrones ZMQ: {patterns}")

            for conflict in audit["potential_conflicts"]:
                report.append(f"   {conflict}")

        # Sección JSONs
        report.append(f"\n📋 ARCHIVOS JSON:")
        for config_file, audit in json_audit.items():
            if "error" in audit:
                report.append(f"\n❌ {config_file}: {audit['error']}")
                continue

            report.append(f"\n📄 {config_file}:")

            if audit["ports"]:
                report.append("   🔌 Puertos definidos:")
                for port_info in audit["ports"]:
                    report.append(f"     • {port_info['key']}: {port_info['port']}")

            if audit["addresses"]:
                report.append("   🌐 Direcciones definidas:")
                for addr_info in audit["addresses"]:
                    report.append(f"     • {addr_info['key']}: {addr_info['address']}")

            # Estado de distribución
            readiness = audit["distribution_readiness"]
            if readiness["needs_refactoring"]:
                report.append("   🔧 NECESITA REFACTORING para distribución")
            else:
                report.append("   ✅ Listo para distribución")

            for issue in audit["scalability_issues"]:
                report.append(f"   {issue}")

        # Recomendaciones finales
        report.append(f"\n💡 RECOMENDACIONES PRIORITARIAS:")

        if conflict_analysis["conflict_detected"]:
            report.append(f"   🎯 CRÍTICO: {conflict_analysis['suspected_issue']}")
            report.append("   🔧 SOLUCIÓN: Unificar puertos en JSON sin defaults")

        report.append("   🎯 OBJETIVO: Eliminar TODOS los defaults hardcodeados")
        report.append("   🎯 OBJETIVO: Refactorizar JSONs a formato distribuido")
        report.append("   🎯 OBJETIVO: Un componente por vez, empezando por simple_firewall_agent")

        return "\n".join(report)


def main():
    print("🚀 Iniciando auditoría con componentes correctos...")
    print("📋 Componentes a auditar:")

    auditor = ConfigAuditor()
    for i, comp in enumerate(auditor.components, 1):
        config_file = auditor.component_config_map.get(comp, "unknown")
        print(f"   {i}. {comp} → {config_file}")

    print("\n" + "=" * 50)

    report = auditor.generate_report()

    # Mostrar en pantalla
    print(report)

    # Guardar en archivo
    with open("config_audit_report_updated.txt", "w") as f:
        f.write(report)

    print(f"\n✅ Reporte guardado en: config_audit_report_updated.txt")
    print("\n🎯 PRÓXIMO PASO:")
    print("1. Revisar conflicto ML Detector → Dashboard")
    print("2. Decidir el orden de refactoring")
    print("3. Borrar firewall_agent.py para eliminar confusión")


if __name__ == "__main__":
    main()