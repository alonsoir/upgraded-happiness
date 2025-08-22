#!/usr/bin/env python3
"""
🛡️ SAFE ZMQ PERFORMANCE OPTIMIZER v3.1 - CONSERVATIVE & INTERACTIVE
zmq_performance_optimizer_v31_safe.py

Optimizador SEGURO que:
- ✅ Pregunta antes de cambiar CUALQUIER configuración
- ✅ Muestra diff detallado de todos los cambios
- ✅ Permite rollback automático
- ✅ Modo conservador por defecto
- ✅ Validación de configuraciones existentes
- ✅ Backup automático con timestamp

NO MÁS CONFIGURACIONES AGRESIVAS SIN CONFIRMACIÓN!
"""

import json
import time
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import difflib
import shutil


class SafeZMQOptimizer:
    """Optimizador SEGURO y CONSERVADOR"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.original_config = {}
        self.proposed_config = {}
        self.backup_file = ""
        self.component_type = "unknown"
        self.is_working_well = False

    def load_and_analyze(self):
        """Cargar y analizar configuración ACTUAL"""
        print(f"🔍 Analizando configuración actual: {self.config_file}")

        if not Path(self.config_file).exists():
            raise FileNotFoundError(f"❌ Config file not found: {self.config_file}")

        with open(self.config_file, 'r') as f:
            self.original_config = json.load(f)

        # Detectar tipo de componente
        component_info = self.original_config.get("component", {})
        component_name = component_info.get("name", "").lower()

        if "simple_firewall_agent" in component_name and "etcd" in component_name:
            self.component_type = "simple_firewall_agent_v31_etcd"
        elif "scheduler" in component_name and "firewall" in component_name:
            self.component_type = "scheduler_firewall_etcd"
        elif "evolutionary_sniffer" in component_name:
            self.component_type = "evolutionary_sniffer_v31_etcd"
        elif "geoip_enricher" in component_name:
            self.component_type = "geoip_enricher_v31_etcd"
        elif "ml_detector" in component_name:
            self.component_type = "ml_detector_tricapa_v31_etcd"
        else:
            self.component_type = "generic"

        print(f"✅ Componente detectado: {self.component_type}")

        # Evaluar si la configuración actual parece estar funcionando bien
        self._evaluate_current_config()

    def _evaluate_current_config(self):
        """Evaluar si la configuración actual es conservadora/estable"""
        zmq_config = self.original_config.get("zmq", {})
        network_config = self.original_config.get("network", {})

        # Indicadores de configuración conservadora
        conservative_indicators = 0
        total_checks = 0

        # Check 1: Timeouts no muy agresivos
        recv_timeout = zmq_config.get("recv_timeout_ms", 1000)
        if recv_timeout >= 1000:  # >= 1 segundo es conservador
            conservative_indicators += 1
        total_checks += 1

        # Check 2: HWM no excesivos
        for socket_name, socket_config in network_config.items():
            if isinstance(socket_config, dict):
                hwm = socket_config.get("high_water_mark", 100)
                if hwm <= 500:  # <= 500 es conservador
                    conservative_indicators += 1
                total_checks += 1

        # Check 3: Linger configurado conservadoramente
        linger = zmq_config.get("linger_ms", 0)
        if linger == 0:  # linger=0 es bueno para cleanup
            conservative_indicators += 1
        total_checks += 1

        if total_checks > 0:
            conservative_ratio = conservative_indicators / total_checks
            self.is_working_well = conservative_ratio > 0.6

        print(f"📊 Evaluación configuración actual:")
        print(f"   🎯 Indicadores conservadores: {conservative_indicators}/{total_checks}")
        print(f"   ✅ Parece funcionar bien: {'SÍ' if self.is_working_well else 'NO'}")

        if self.is_working_well:
            print(f"   💡 La configuración actual parece ESTABLE - cambios mínimos sugeridos")
        else:
            print(f"   ⚠️ La configuración podría mejorarse - cambios conservadores disponibles")

    def generate_conservative_optimizations(self) -> Dict[str, Any]:
        """Generar optimizaciones CONSERVADORAS y seguras"""
        print(f"\n🛡️ Generando optimizaciones CONSERVADORAS para {self.component_type}...")

        optimizations = {
            "zmq": {},
            "network": {},
            "processing": {},
            "reasoning": []
        }

        current_zmq = self.original_config.get("zmq", {})
        current_network = self.original_config.get("network", {})
        current_processing = self.original_config.get("processing", {})

        # Si ya funciona bien, cambios MÍNIMOS
        if self.is_working_well:
            optimizations["reasoning"].append("🎯 Configuración actual ESTABLE - solo ajustes menores")

            # Solo ajustes críticos de seguridad
            if current_zmq.get("linger_ms", 1000) != 0:
                optimizations["zmq"]["linger_ms"] = 0
                optimizations["reasoning"].append("🔧 linger_ms=0 para cleanup rápido")

            if current_zmq.get("tcp_keepalive") != True:
                optimizations["zmq"]["tcp_keepalive"] = True
                optimizations["reasoning"].append("🔧 tcp_keepalive=true para estabilidad")

        else:
            # Configuración necesita mejoras, pero CONSERVADORAS
            optimizations["reasoning"].append("⚠️ Configuración necesita ajustes CONSERVADORES")

            # ZMQ optimizations conservadoras
            if self.component_type == "simple_firewall_agent_v31_etcd":
                optimizations.update(self._get_conservative_agent_config(current_zmq, current_network))
            elif self.component_type == "scheduler_firewall_etcd":
                optimizations.update(self._get_conservative_scheduler_config(current_zmq, current_network))
            else:
                optimizations.update(self._get_conservative_generic_config(current_zmq, current_network))

        return optimizations

    def _get_conservative_agent_config(self, current_zmq: Dict, current_network: Dict) -> Dict:
        """Configuración conservadora para simple_firewall_agent_v31_etcd"""
        config = {"zmq": {}, "network": {}, "reasoning": []}

        # ZMQ conservador para DUAL COMMUNICATION
        config["zmq"] = {
            "context_io_threads": 2,  # Para 4 sockets DUAL
            "max_sockets": 32,  # Conservador, no 64
            "tcp_keepalive": True,
            "immediate": True,
            "linger_ms": 0,  # CRÍTICO
            "recv_timeout_ms": 1000,  # 1 segundo, no 100ms
            "send_timeout_ms": 1000  # 1 segundo, no 50ms
        }
        config["reasoning"].append("🔥 DUAL COMMUNICATION: timeouts conservadores de 1 segundo")

        # Network conservador
        config["network"] = {}
        for socket_name in ["scheduler_commands", "scheduler_responses", "dashboard_commands", "dashboard_responses"]:
            if socket_name in current_network:
                current_hwm = current_network[socket_name].get("high_water_mark", 100)
                # Solo cambiar si es muy alto (>1000) o muy bajo (<50)
                if current_hwm > 1000:
                    config["network"][socket_name] = {"high_water_mark": 200}
                    config["reasoning"].append(f"🔧 {socket_name}: HWM {current_hwm}→200 (menos agresivo)")
                elif current_hwm < 50:
                    config["network"][socket_name] = {"high_water_mark": 100}
                    config["reasoning"].append(f"🔧 {socket_name}: HWM {current_hwm}→100 (mínimo sensato)")

        return config

    def _get_conservative_scheduler_config(self, current_zmq: Dict, current_network: Dict) -> Dict:
        """Configuración conservadora para scheduler_firewall_etcd"""
        config = {"zmq": {}, "network": {}, "reasoning": []}

        # ZMQ conservador para decision engine
        config["zmq"] = {
            "context_io_threads": 2,
            "max_sockets": 16,  # Conservador
            "tcp_keepalive": True,
            "immediate": False,  # False para estabilidad
            "linger_ms": 0,
            "recv_timeout_ms": 2000,  # 2 segundos, MUY conservador
            "send_timeout_ms": 1000  # 1 segundo
        }
        config["reasoning"].append("🛡️ SCHEDULER: timeouts MUY conservadores (2s/1s)")

        # Network conservador basado en tu configuración que funciona
        network_suggestions = {
            "ml_events_input": 200,  # Tu configuración estable
            "firewall_commands_output": 100,  # Tu configuración estable
            "firewall_responses_input": 150  # Tu configuración estable
        }

        config["network"] = {}
        for socket_name, suggested_hwm in network_suggestions.items():
            if socket_name in current_network:
                current_hwm = current_network[socket_name].get("high_water_mark", 100)
                if abs(current_hwm - suggested_hwm) > 50:  # Solo cambiar si hay diferencia significativa
                    config["network"][socket_name] = {"high_water_mark": suggested_hwm}
                    config["reasoning"].append(
                        f"🎯 {socket_name}: HWM {current_hwm}→{suggested_hwm} (configuración probada estable)")

        return config

    def _get_conservative_generic_config(self, current_zmq: Dict, current_network: Dict) -> Dict:
        """Configuración conservadora genérica"""
        config = {"zmq": {}, "network": {}, "reasoning": []}

        config["zmq"] = {
            "linger_ms": 0,
            "tcp_keepalive": True,
            "recv_timeout_ms": 2000,  # MUY conservador
            "send_timeout_ms": 1000
        }
        config["reasoning"].append("📊 GENERIC: Solo cambios básicos de estabilidad")

        return config

    def show_proposed_changes(self, optimizations: Dict[str, Any]) -> bool:
        """Mostrar cambios propuestos con diff detallado"""
        if not optimizations["zmq"] and not optimizations["network"] and not optimizations["processing"]:
            print("\n✅ NO SE PROPONEN CAMBIOS - La configuración actual es óptima")
            return False

        print(f"\n📋 CAMBIOS PROPUESTOS (CONSERVADORES):")
        print("=" * 60)

        # Mostrar reasoning
        if optimizations["reasoning"]:
            print(f"💡 JUSTIFICACIÓN:")
            for reason in optimizations["reasoning"]:
                print(f"   {reason}")
            print()

        # Crear configuración propuesta
        self.proposed_config = self.original_config.copy()

        # Aplicar cambios ZMQ
        if optimizations["zmq"]:
            print(f"🔧 CAMBIOS ZMQ:")
            if "zmq" not in self.proposed_config:
                self.proposed_config["zmq"] = {}
            for key, new_value in optimizations["zmq"].items():
                old_value = self.proposed_config["zmq"].get(key, "not set")
                self.proposed_config["zmq"][key] = new_value
                print(f"   {key}: {old_value} → {new_value}")

        # Aplicar cambios Network
        if optimizations["network"]:
            print(f"\n🔌 CAMBIOS NETWORK:")
            if "network" not in self.proposed_config:
                self.proposed_config["network"] = {}
            for socket_name, changes in optimizations["network"].items():
                if socket_name not in self.proposed_config["network"]:
                    self.proposed_config["network"][socket_name] = {}
                for key, new_value in changes.items():
                    old_value = self.proposed_config["network"][socket_name].get(key, "not set")
                    self.proposed_config["network"][socket_name][key] = new_value
                    print(f"   {socket_name}.{key}: {old_value} → {new_value}")

        # Mostrar diff JSON
        print(f"\n📄 DIFF COMPLETO:")
        self._show_json_diff()

        return True

    def _show_json_diff(self):
        """Mostrar diff detallado del JSON"""
        original_json = json.dumps(self.original_config, indent=2, sort_keys=True).splitlines()
        proposed_json = json.dumps(self.proposed_config, indent=2, sort_keys=True).splitlines()

        diff = list(difflib.unified_diff(
            original_json,
            proposed_json,
            fromfile=f"{self.config_file} (ORIGINAL)",
            tofile=f"{self.config_file} (PROPUESTO)",
            lineterm=""
        ))

        if diff:
            for line in diff[:20]:  # Mostrar solo primeras 20 líneas del diff
                if line.startswith('+'):
                    print(f"✅ {line}")
                elif line.startswith('-'):
                    print(f"❌ {line}")
                elif line.startswith('@@'):
                    print(f"📍 {line}")
                else:
                    print(f"   {line}")

            if len(diff) > 20:
                print(f"   ... ({len(diff) - 20} más líneas)")

    def ask_for_confirmation(self) -> bool:
        """Pedir confirmación al usuario"""
        print(f"\n❓ CONFIRMAR CAMBIOS:")
        print(f"   🎯 Componente: {self.component_type}")
        print(f"   📁 Archivo: {self.config_file}")
        print(f"   🛡️ Enfoque: CONSERVADOR")
        print(f"   💾 Backup: Se creará automáticamente")

        while True:
            response = input("\n¿Aplicar estos cambios CONSERVADORES? [y/n/d/q]: ").lower().strip()

            if response == 'y' or response == 'yes':
                return True
            elif response == 'n' or response == 'no':
                print("❌ Cambios cancelados por el usuario")
                return False
            elif response == 'd' or response == 'diff':
                print("\n📄 DIFF COMPLETO:")
                self._show_json_diff()
            elif response == 'q' or response == 'quit':
                print("🚪 Saliendo...")
                sys.exit(0)
            else:
                print("❓ Opciones: y(es), n(o), d(iff), q(uit)")

    def create_backup(self):
        """Crear backup con timestamp"""
        timestamp = int(time.time())
        self.backup_file = f"{self.config_file}.backup.{timestamp}"
        shutil.copy2(self.config_file, self.backup_file)
        print(f"💾 Backup creado: {self.backup_file}")

    def apply_changes(self):
        """Aplicar cambios de forma segura"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.proposed_config, f, indent=2)
            print(f"✅ Cambios aplicados a: {self.config_file}")

        except Exception as e:
            print(f"❌ Error aplicando cambios: {e}")
            print(f"🔄 Restaurando desde backup...")
            shutil.copy2(self.backup_file, self.config_file)
            print(f"✅ Configuración original restaurada")
            return False

        return True

    def rollback(self):
        """Hacer rollback usando el backup"""
        if not self.backup_file or not Path(self.backup_file).exists():
            print(f"❌ No hay backup disponible para rollback")
            return False

        try:
            shutil.copy2(self.backup_file, self.config_file)
            print(f"🔄 Rollback completado desde: {self.backup_file}")
            return True
        except Exception as e:
            print(f"❌ Error en rollback: {e}")
            return False

    def show_advice(self):
        """Mostrar consejos específicos y CONSERVADORES"""
        print(f"\n💡 CONSEJOS CONSERVADORES PARA {self.component_type.upper()}:")
        print("=" * 70)

        if self.is_working_well:
            print("🎉 ¡Tu configuración actual parece estar funcionando MUY BIEN!")
            print("✅ Sistema estable detectado - mantén estos valores")
            print("")
            print("🛡️ FILOSOFÍA: Si funciona, NO lo cambies")
            print("   • Solo ajusta si hay problemas específicos")
            print("   • Cambios graduales, uno a la vez")
            print("   • Monitorea después de cada cambio")
            print("   • Prioriza estabilidad sobre rendimiento")

        print(f"\n🎯 CONSEJOS ESPECÍFICOS CONSERVADORES:")

        if self.component_type == "simple_firewall_agent_v31_etcd":
            advice = [
                "🔥 SIMPLE FIREWALL AGENT - ENFOQUE CONSERVADOR:",
                "",
                "📊 Si ves 0 errores en logs → NO cambiar nada",
                "⏱️ Si latencia <200ms → configuración OK",
                "🔄 Si responses_sent = commands_received → perfecto",
                "",
                "🛡️ AJUSTES SOLO SI HAY PROBLEMAS:",
                "   • Timeouts demasiado cortos → aumentar gradualmente",
                "   • Colas llenas (>70%) → aumentar HWM ligeramente",
                "   • Conexiones perdidas → verificar network, no ZMQ",
                "   • ETCD errors → problema de infraestructura, no config"
            ]
        elif self.component_type == "scheduler_firewall_etcd":
            advice = [
                "🛡️ SCHEDULER FIREWALL - ENFOQUE CONSERVADOR:",
                "",
                "📊 Tu configuración actual (HWM 200/100/150) parece IDEAL",
                "✅ Tienes 0 errores → NO tocar configuración ZMQ",
                "⏱️ Timeouts 2000ms/1000ms son PERFECTOS para estabilidad",
                "",
                "🎯 MONITOREO EN LUGAR DE CAMBIOS:",
                "   • Events_received > 0 → ML detector funcionando",
                "   • Commands_sent > 0 → decisiones tomándose",
                "   • Queue usage <50% → configuración apropiada",
                "   • Errors = 0 → sistema estable"
            ]
        else:
            advice = [
                "📊 COMPONENTE GENÉRICO - PRINCIPIOS CONSERVADORES:",
                "",
                "🛡️ REGLA DE ORO: Si funciona, NO cambiar",
                "📈 Monitorear antes que optimizar",
                "🔧 Un cambio a la vez, nunca masivo",
                "⏱️ Timeouts largos son mejores que cortos",
                "🔄 HWM moderados evitan saturación"
            ]

        for line in advice:
            print(line)


def main():
    """Función principal SEGURA"""
    if len(sys.argv) < 2:
        print("🛡️ SAFE ZMQ OPTIMIZER - No más configuraciones agresivas!")
        print("\n❌ Uso: python zmq_performance_optimizer_v31_safe.py <config.json> [action]")
        print("\n📋 Actions disponibles:")
        print("   analyze   - Solo analizar, SIN cambios (default)")
        print("   optimize  - Proponer cambios CONSERVADORES con confirmación")
        print("   advice    - Solo mostrar consejos")
        print("   rollback  - Restaurar desde backup más reciente")
        print("\n💡 Ejemplos:")
        print("   # Solo analizar (SEGURO)")
        print("   python script.py simple_firewall_agent_v31_etcd.json")
        print("   # Proponer cambios conservadores")
        print("   python script.py simple_firewall_agent_v31_etcd.json optimize")
        print("   # Solo consejos")
        print("   python script.py simple_firewall_agent_v31_etcd.json advice")
        sys.exit(1)

    config_file = sys.argv[1]
    action = sys.argv[2] if len(sys.argv) > 2 else "analyze"

    if not Path(config_file).exists():
        print(f"❌ Config file not found: {config_file}")
        sys.exit(1)

    print("🛡️ SAFE ZMQ PERFORMANCE OPTIMIZER v3.1 - CONSERVATIVE & INTERACTIVE")
    print("=" * 80)
    print("✅ NO MÁS configuraciones agresivas sin confirmación")
    print("✅ Backup automático antes de cualquier cambio")
    print("✅ Diff detallado de todos los cambios")
    print("✅ Rollback disponible")
    print("=" * 80)

    try:
        optimizer = SafeZMQOptimizer(config_file)
        optimizer.load_and_analyze()

        if action == "rollback":
            # Buscar backup más reciente
            backup_pattern = f"{config_file}.backup.*"
            import glob
            backups = glob.glob(backup_pattern)
            if backups:
                latest_backup = max(backups, key=os.path.getctime)
                print(f"🔄 Restaurando desde backup: {latest_backup}")
                shutil.copy2(latest_backup, config_file)
                print(f"✅ Rollback completado")
            else:
                print(f"❌ No se encontraron backups para {config_file}")

        elif action == "advice":
            optimizer.show_advice()

        elif action == "optimize":
            optimizations = optimizer.generate_conservative_optimizations()

            if optimizer.show_proposed_changes(optimizations):
                if optimizer.ask_for_confirmation():
                    optimizer.create_backup()
                    if optimizer.apply_changes():
                        print(f"\n🎉 OPTIMIZACIÓN CONSERVADORA COMPLETADA")
                        print(f"💾 Backup disponible: {optimizer.backup_file}")
                        print(f"🔄 Rollback: python {sys.argv[0]} {config_file} rollback")
                        optimizer.show_advice()
                    else:
                        print(f"❌ Optimización falló - configuración original restaurada")
                else:
                    print(f"✅ Configuración sin cambios - decisión inteligente")

        else:  # analyze (default)
            optimizations = optimizer.generate_conservative_optimizations()
            optimizer.show_proposed_changes(optimizations)
            optimizer.show_advice()
            print(f"\n💡 Para aplicar cambios: python {sys.argv[0]} {config_file} optimize")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()