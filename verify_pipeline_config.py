import os
import json
import re

COMPONENTS = {
    "simple_firewall_agent": "simple_firewall_agent_config.json",
    "geoip_enricher": "geoip_enricher_config.json",
    "lightweight_ml_detector": "lightweight_ml_detector_config.json",
    "dashboard": "dashboard_config.json",
    "enhanced_agent": "enhanced_agent_config.json"
}

def extract_ports(config):
    ports = []
    if "network" in config:
        for k in ("input_port", "output_port", "commands_input_port", "confirmations_output_port"):
            if k in config["network"]:
                ports.append(config["network"][k])
    if "zmq" in config:
        for k in ("events_input_port", "commands_output_port", "confirmations_input_port"):
            if k in config["zmq"]:
                ports.append(config["zmq"][k])
    return ports

def analyze_json_configs():
    print("📦 Analizando configuración JSON...")
    port_usage = {}
    summaries = {}

    for comp, filename in COMPONENTS.items():
        if not os.path.exists(filename):
            summaries[comp] = {"error": f"❌ No se encontró {filename}"}
            continue

        with open(filename) as f:
            data = json.load(f)

        ports = extract_ports(data)
        summaries[comp] = {
            "filename": filename,
            "ports": ports,
            "bind_address": data.get("network", {}).get("bind_address", None),
            "used_localhost": False
        }

        for port in ports:
            if port not in port_usage:
                port_usage[port] = []
            port_usage[port].append(comp)

        if data.get("network", {}).get("bind_address") == "localhost":
            summaries[comp]["used_localhost"] = True

    return summaries, port_usage

def analyze_python_sources():
    print("\n🐍 Analizando fuentes Python...")
    issues = {}

    for comp in COMPONENTS.keys():
        filename = f"{comp}.py"
        if not os.path.exists(filename):
            issues[comp] = ["❌ No se encontró el archivo .py"]
            continue

        with open(filename) as f:
            code = f.read()

        findings = []

        if '--config' not in code and 'argparse' in code:
            findings.append("⚠️ No usa --config (deberías unificar la interfaz).")

        if re.search(r'"localhost"|\'localhost\'', code):
            findings.append("⚠️ Usa 'localhost' hardcodeado (mejor usar bind_address del JSON).")

        if not re.search(r'load_config|json.load|open\(', code):
            findings.append("⚠️ No parece leer configuración externa.")

        if findings:
            issues[comp] = findings

    return issues

def print_summary(json_summary, port_usage, source_issues):
    print("\n📋 Resumen de configuración por componente:")
    for comp, info in json_summary.items():
        print(f"\n🔧 {comp}")
        if "error" in info:
            print(f"   {info['error']}")
            continue

        print(f"   Config file: {info['filename']}")
        print(f"   Bind address: {info['bind_address']}")
        print(f"   Ports: {info['ports']}")
        if info["used_localhost"]:
            print("   ⚠️ Usa 'localhost' como bind_address.")

        if comp in source_issues:
            for issue in source_issues[comp]:
                print(f"   {issue}")

    print("\n📡 Puertos compartidos:")
    for port, comps in port_usage.items():
        if port is None:
            continue
        if len(comps) > 1:
            print(f"⚠️ Puerto {port} es compartido por: {', '.join(comps)}")

def main():
    json_summary, port_usage = analyze_json_configs()
    source_issues = analyze_python_sources()
    print_summary(json_summary, port_usage, source_issues)

if __name__ == "__main__":
    main()
