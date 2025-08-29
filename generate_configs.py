#!/usr/bin/env python3
"""
Script generador de configuraciones JSON usando templates Jinja2
Para el proyecto upgraded-happiness
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, TemplateError
import argparse


class ConfigGenerator:
    def __init__(self, templates_dir="infrastructure/config", output_dir="configs"):
        self.templates_dir = Path(templates_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Configurar Jinja2
        self.env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            trim_blocks=True,
            lstrip_blocks=True
        )

    def get_environment_variables(self, environment="local"):
        """Define variables por entorno"""

        base_vars = {
            "deployment_timestamp": datetime.now().isoformat(),
            "config_version": "3.1.0-generated",
            "cluster_name": "upgraded-happiness-cluster-v31",
            "etcd_service_name": "etcd",
            "etcd_port": 2379
        }

        if environment == "local":
            return {
                **base_vars,
                "environment": "local",
                "orchestrator": "docker",
                "namespace": "default",
                "pod_id": "local-pod-001",
                "container_name": "upgraded-happiness-local",
                "availability_zone": "local-zone",
                "region": "localhost",

                # Logging
                "logging": {
                    "level": "DEBUG",
                    "file_level": "DEBUG",
                    "max_size": "50MB",
                    "backup_count": 3
                },

                # Services network configuration
                "services": {
                    "sniffer": {
                        "downstream_service": "sniffer",
                        "zmq_pub_port": 5571
                    },
                    "geoip": {
                        "zmq_pub_port": 5560
                    },
                    "ml_detector": {
                        "service_name": "ml-detector",
                        "zmq_pub_port": 5580
                    },
                    "scheduler_firewall": {
                        "zmq_pull_port": 5581
                    },
                    "dashboard": {
                        "firewall_commands_port": 5590,
                        "firewall_responses_port": 5591
                    },
                    "firewall_agent": {
                        "dashboard_commands_port": 5583,
                        "dashboard_responses_port": 5584
                    },
                    "simple_firewall_agent": {
                        "scheduler_commands_port": 5582,
                        "dashboard_commands_port": 5583
                    }
                },

                # Performance settings
                "performance": {
                    "worker_threads": 2,
                    "memory_limit_mb": 512,
                    "zmq_io_threads": 2,
                    "max_sockets": 16
                },

                # Health check settings
                "health_check": {
                    "interval": 30
                },

                # Monitoring settings
                "monitoring": {
                    "prometheus_metrics": False,
                    "metrics_port": 9090
                },

                # Dashboard specific
                "dashboard": {
                    "web_port": 8080,
                    "web_host": "0.0.0.0",
                    "rate_limit_rpm": 120,
                    "fleet_management": True
                },

                # Firewall rules
                "firewall": {
                    "rules_version": "1.0.0-DEV",
                    "agent_version": "3.1.0",
                    "safety_mode": "ULTRA_SECURE_V31",
                    "agents": [
                        {
                            "node_id": "simple_firewall_agent_001",
                            "service_name": "firewall-agent-001",
                            "location": "zona_dmz_001",
                            "status": "active",
                            "scheduler_commands_port": 5582,
                            "scheduler_responses_port": 5581,
                            "dashboard_commands_port": 5583,
                            "dashboard_responses_port": 5584,
                            "max_concurrent_rules": 10,
                            "default_rule_duration": 60
                        }
                    ]
                }
            }

        elif environment == "production":
            return {
                **base_vars,
                "environment": "production",
                "orchestrator": "k8s",
                "namespace": "upgraded-happiness",
                "pod_id": "prod-pod-001",
                "container_name": "upgraded-happiness-prod",
                "availability_zone": "prod-zone-a",
                "region": "eu-west-1",

                # Logging más restrictivo
                "logging": {
                    "level": "INFO",
                    "file_level": "INFO",
                    "max_size": "100MB",
                    "backup_count": 10
                },

                # Performance optimizada
                "performance": {
                    "worker_threads": 4,
                    "memory_limit_mb": 2048,
                    "zmq_io_threads": 4,
                    "max_sockets": 32
                },

                # Monitoring habilitado
                "monitoring": {
                    "prometheus_metrics": True,
                    "metrics_port": 9090
                },

                # Firewall con más capacidades en prod
                "firewall": {
                    "rules_version": "1.0.0-PROD",
                    "enable_rate_limit_production": True,
                    "enable_block_ip_production": False,  # Aún conservador
                    "force_dry_run_production": True,  # Seguridad
                    "agents": [
                        {
                            "node_id": "simple_firewall_agent_prod_001",
                            "service_name": "firewall-agent",
                            "location": "zona_prod_001",
                            "status": "active",
                            "scheduler_commands_port": 5582,
                            "scheduler_responses_port": 5581,
                            "dashboard_commands_port": 5583,
                            "dashboard_responses_port": 5584,
                            "max_concurrent_rules": 50,
                            "default_rule_duration": 300,
                            "allowed_actions_production": ["MONITOR", "LIST_RULES", "RATE_LIMIT"],
                            "blocked_actions_production": ["BLOCK_IP", "FLUSH_RULES"]
                        }
                    ]
                }
            }

    def generate_config(self, template_name, output_name, environment="local", node_id=None):
        """Genera un archivo de configuración desde un template"""

        try:
            # Cargar template
            template = self.env.get_template(template_name)

            # Obtener variables
            variables = self.get_environment_variables(environment)

            # Añadir node_id específico si se proporciona
            if node_id:
                variables["node_id"] = node_id

            # Renderizar
            rendered = template.render(**variables)

            # Intentar parsear como JSON para validar
            try:
                parsed_json = json.loads(rendered)
            except json.JSONDecodeError as e:
                print(f"ERROR JSON en {template_name}:")
                print(f"   Línea {e.lineno}, columna {e.colno}: {e.msg}")
                print(f"   Contexto: {rendered[max(0, e.pos - 50):e.pos + 50]}")
                return False

            # Escribir archivo
            output_path = self.output_dir / output_name
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(parsed_json, f, indent=2, ensure_ascii=False)

            print(f"Validado: {template_name} -> {output_name}")
            return True

        except TemplateError as e:
            print(f"ERROR Template en {template_name}: {e}")
            return False
        except Exception as e:
            print(f"ERROR General en {template_name}: {e}")
            return False

    def discover_templates(self):
        """Descubre automáticamente archivos *_template.json"""
        templates = list(self.templates_dir.glob("*_template.json"))
        return [t.name for t in templates]

    def generate_all_configs(self, environment="local"):
        """Genera todas las configuraciones para un entorno"""

        print(f"\nValidando templates Jinja2 para entorno: {environment}")
        print("=" * 60)

        # Descubrir templates automáticamente
        template_files = self.discover_templates()

        if not template_files:
            print("No se encontraron archivos *_template.json en el directorio")
            return False

        print(f"Templates encontrados: {len(template_files)}")
        for template in template_files:
            print(f"  - {template}")
        print()

        success_count = 0
        total_count = len(template_files)

        for template_name in template_files:
            # Generar nombre de salida basado en el template
            base_name = template_name.replace("_template.json", "")
            output_name = f"{base_name}_{environment}_generated.json"

            if self.generate_config(template_name, output_name, environment):
                success_count += 1

        print(f"\nResultado: {success_count}/{total_count} templates validados correctamente")

        if success_count < total_count:
            print("Hay errores en algunos templates que necesitan corrección")
            return False
        else:
            print("Todos los templates generaron JSON válido")
            return True


def main():
    parser = argparse.ArgumentParser(
        description="Script de VALIDACIÓN de templates Jinja2 para upgraded-happiness (NO es el generador de producción)")
    parser.add_argument("--environment", "-e", default="local",
                        choices=["local", "production"],
                        help="Entorno target (local|production)")
    parser.add_argument("--template", "-t",
                        help="Template específico a generar")
    parser.add_argument("--output", "-o",
                        help="Archivo de salida específico")
    parser.add_argument("--templates-dir", default="infrastructure/config",
                        help="Directorio de templates (por defecto: infrastructure/config)")
    parser.add_argument("--output-dir", default="configs",
                        help="Directorio de salida")

    args = parser.parse_args()

    print("SCRIPT DE VALIDACIÓN - Solo para detectar errores de sintaxis JSON")
    print("El generador de producción real tendrá muchos más parámetros")
    print("-" * 60)

    # Verificar que el directorio de templates existe
    templates_path = Path(args.templates_dir)
    if not templates_path.exists():
        print(f"ERROR: Directorio de templates no encontrado: {templates_path}")
        sys.exit(1)

    # Crear generador
    generator = ConfigGenerator(args.templates_dir, args.output_dir)

    if args.template:
        # Generar template específico
        output_name = args.output or f"generated_{args.environment}.json"
        success = generator.generate_config(args.template, output_name, args.environment)
        sys.exit(0 if success else 1)
    else:
        # Generar todos
        success = generator.generate_all_configs(args.environment)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()