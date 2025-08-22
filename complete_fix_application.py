#!/usr/bin/env python3
"""
complete_fix_application.py
🚀 COMPREHENSIVE FIX - JSON Configuration + Compression Pipeline Debug
Aplica configuración menos agresiva y debug de descompresión
"""

import json
import os
import shutil
from datetime import datetime
from pathlib import Path


def backup_file(file_path):
    """Crear backup de archivo"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{file_path}.backup.{timestamp}"
    shutil.copy2(file_path, backup_path)
    print(f"📁 Backup: {backup_path}")
    return backup_path


def apply_less_aggressive_scheduler_config():
    """Aplicar configuración menos agresiva al scheduler"""
    config_file = "config/json/scheduler_firewall_etcd_config_dev.json"

    if not os.path.exists(config_file):
        print(f"❌ No encontrado: {config_file}")
        return False

    print(f"🔧 Aplicando configuración menos agresiva al scheduler...")
    backup_file(config_file)

    # Cargar configuración actual
    with open(config_file, 'r') as f:
        config = json.load(f)

    # Aplicar cambios menos agresivos
    updates = {
        "network": {
            "ml_events_input": {
                "high_water_mark": 200  # Era 100
            },
            "firewall_commands_output": {
                "high_water_mark": 100  # Era 50
            },
            "firewall_responses_input": {
                "high_water_mark": 150  # Era 100
            }
        },
        "zmq": {
            "recv_timeout_ms": 2000,  # Era 1000
            "send_timeout_ms": 1000  # Era 500
        },
        "processing": {
            "internal_queues": {
                "ml_events_queue_size": 100,  # Era 50
                "firewall_commands_queue_size": 50,  # Era 25
                "firewall_responses_queue_size": 75  # Era 50
            },
            "queue_management": {
                "max_wait_ms": 200,  # Era 100
                "emergency_drop_threshold": 90.0  # Era 80.0
            },
            "decision_engine": {
                "max_decisions_per_second": 10,  # Era 100
                "decision_timeout_ms": 100  # Era 50
            },
            "backpressure": {
                "max_retries": 3,  # Era 2
                "retry_delays_ms": [10, 25, 50],  # Era [1, 5]
                "drop_threshold_percent": 15.0,  # Era 10.0
                "activation_threshold": 25  # Era 15
            }
        },
        "monitoring": {
            "stats_interval_seconds": 30,  # Era 60
            "alerts": {
                "max_queue_usage_percent": 80.0,  # Era 70.0
                "max_processing_latency_ms": 150.0,  # Era 100.0
                "max_error_rate_percent": 8.0  # Era 5.0
            }
        }
    }

    # Aplicar updates anidados
    def apply_nested_updates(target, updates):
        for key, value in updates.items():
            if key not in target:
                target[key] = {}

            if isinstance(value, dict) and isinstance(target[key], dict):
                apply_nested_updates(target[key], value)
            else:
                old_value = target[key] if key in target else "not set"
                target[key] = value
                print(f"   {key}: {old_value} → {value}")

    apply_nested_updates(config, updates)

    # Asegurar configuración de compresión crítica
    if "crypto" in config and "channels" in config["crypto"]:
        for channel_name, channel_config in config["crypto"]["channels"].items():
            if channel_name in ["ml_events_input", "firewall_responses_input"]:
                # Canales de entrada: decrypt Y decompress
                channel_config["decrypt"] = True
                channel_config["decompress"] = True
                print(f"   🔐 {channel_name}: decrypt=true, decompress=true")
            elif channel_name == "firewall_commands_output":
                # Canal de salida: encrypt Y compress
                channel_config["encrypt"] = True
                channel_config["compress"] = True
                print(f"   🔐 {channel_name}: encrypt=true, compress=true")

    # Agregar metadata
    config["_config_metadata"] = {
        "config_version": "1.0.0-less-aggressive",
        "optimization_level": "BALANCED_SCHEDULER_ETCD",
        "rate_limiting": "RELAXED",
        "compression_awareness": "ENABLED",
        "last_modified": datetime.now().isoformat()
    }

    # Guardar configuración actualizada
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)

    print(f"✅ Configuración menos agresiva aplicada al scheduler")
    return True


def verify_agent_crypto_config():
    """Verificar configuración crypto del agent"""
    config_file = "config/json/simple_firewall_agent_v31_etcd.json"

    if not os.path.exists(config_file):
        print(f"❌ No encontrado: {config_file}")
        return False

    print(f"🔍 Verificando configuración crypto del agent...")

    with open(config_file, 'r') as f:
        config = json.load(f)

    # Verificar configuración crypto
    crypto_config = config.get("crypto", {})
    if not crypto_config.get("enabled", False):
        print(f"   ❌ Crypto no habilitado")
        return False

    channels = crypto_config.get("channels", {})
    issues = []

    for channel_name, channel_config in channels.items():
        decrypt = channel_config.get("decrypt", False)
        decompress = channel_config.get("decompress", False)

        print(f"   🔐 {channel_name}:")
        print(f"      decrypt: {decrypt}")
        print(f"      decompress: {decompress}")

        if "commands" in channel_name and "input" in channel_name:
            # Canales de entrada de comandos deben decrypt Y decompress
            if not (decrypt and decompress):
                issues.append(f"{channel_name}: needs decrypt=true, decompress=true")
        elif "responses" in channel_name and "output" in channel_name:
            # Canales de salida de respuestas deben encrypt Y compress
            encrypt = channel_config.get("encrypt", False)
            compress = channel_config.get("compress", False)
            if not (encrypt and compress):
                issues.append(f"{channel_name}: needs encrypt=true, compress=true")

    if issues:
        print(f"   ⚠️ Issues encontrados:")
        for issue in issues:
            print(f"      - {issue}")
        return False
    else:
        print(f"   ✅ Configuración crypto del agent correcta")
        return True


def create_agent_debug_code():
    """Crear código de debug para agregar al agent"""
    debug_code = '''
# 🔧 AGREGAR AL SIMPLE FIREWALL AGENT después de imports:

import gzip
import zlib
import bz2

def debug_compression_pipeline(self, command_bytes, source="unknown"):
    """Debug del pipeline de descompresión"""
    self.logger.info(f"🔍 DEBUG COMPRESSION - {source} ({len(command_bytes)} bytes)")

    if len(command_bytes) >= 4:
        hex_preview = ' '.join([f'{b:02x}' for b in command_bytes[:4]])
        self.logger.info(f"   First 4 bytes: {hex_preview}")

        # Verificar magic numbers de compresión
        magic_gzip = command_bytes[:2] == b'\\x1f\\x8b'
        magic_zlib = command_bytes[:2] in [b'\\x78\\x9c', b'\\x78\\x01', b'\\x78\\xda']

        if magic_gzip:
            self.logger.warning(f"   ⚠️ GZIP signature detected - should be decompressed by ETCD!")
        elif magic_zlib:
            self.logger.warning(f"   ⚠️ ZLIB signature detected - should be decompressed by ETCD!")
        else:
            self.logger.info(f"   ✅ No compression signature - good")

    return command_bytes

def attempt_emergency_decompression(self, data):
    """Decompresión de emergencia si ETCD falló"""
    try:
        # Intentar GZIP
        if data[:2] == b'\\x1f\\x8b':
            return gzip.decompress(data), "gzip"
    except:
        pass

    try:
        # Intentar ZLIB
        if data[:2] in [b'\\x78\\x9c', b'\\x78\\x01', b'\\x78\\xda']:
            return zlib.decompress(data), "zlib"
    except:
        pass

    return data, "no_decompression"

# 🔧 MODIFICAR _parse_scheduler_command():
def _parse_scheduler_command(self, command_bytes):
    """Parser con debug de compresión"""
    try:
        # Debug del pipeline
        command_bytes = self.debug_compression_pipeline(command_bytes, "scheduler")

        # Verificar si necesita decompresión de emergencia
        if (command_bytes[:2] == b'\\x1f\\x8b' or 
            command_bytes[:2] in [b'\\x78\\x9c', b'\\x78\\x01', b'\\x78\\xda']):

            self.logger.error(f"❌ CRITICAL: Received compressed data from scheduler!")
            self.logger.error(f"   ETCD should have decompressed but didn't")

            # Intentar decompresión de emergencia
            decompressed, method = self.attempt_emergency_decompression(command_bytes)
            if method != "no_decompression":
                self.logger.warning(f"🔧 Emergency decompression: {method}")
                command_bytes = decompressed

        # Intentar parsing protobuf
        if PROTOBUF_AVAILABLE and FirewallCommandsProto:
            pb_command = FirewallCommandsProto.FirewallCommand()
            pb_command.ParseFromString(command_bytes)

            if hasattr(pb_command, 'command_id') and pb_command.command_id:
                self.logger.info(f"✅ Protobuf parsed: {pb_command.command_id}")
                return self._convert_protobuf_to_dict(pb_command)

        self.logger.error(f"❌ Protobuf parsing failed completely")
        return None

    except Exception as e:
        if "utf-8" in str(e).lower():
            self.logger.error(f"❌ UTF-8 error: Data is likely still compressed!")
        else:
            self.logger.error(f"❌ Parsing error: {e}")
        return None
'''

    print(f"\n📝 CÓDIGO DEBUG PARA AGENT:")
    print("=" * 60)
    print(debug_code)
    print("=" * 60)


def show_testing_plan():
    """Plan de testing después de aplicar fixes"""
    plan = f'''
🧪 PLAN DE TESTING - JSON CONFIGURATION + COMPRESSION DEBUG:

1. PARAR COMPONENTES:
   pkill -f "python.*scheduler"
   pkill -f "python.*firewall"
   pkill -f "python.*zmq_performance"

2. VERIFICAR CONFIGURACIÓN:
   # El scheduler ahora tiene configuración menos agresiva
   # Las colas son más grandes: ML=100, Commands=50, Responses=75
   # Los timeouts son más permisivos: recv=2s, send=1s
   # HWM incrementados: ML=200, Commands=100, Responses=150

3. INICIAR SECUENCIALMENTE:

   Terminal 1 - Consumer:
   python core/zmq_performance_optimizer_generic.py config/json/scheduler_firewall_etcd_config_dev.json consume

   Terminal 2 - Agent (con debug de compresión):
   python core/simple_firewall_agent_v31_etcd.py config/json/simple_firewall_agent_v31_etcd.json config/json/firewall_rules_v31.json

   Terminal 3 - Scheduler:
   python core/scheduler_firewall_v31_etcd.py config/json/scheduler_firewall_etcd_config_dev.json config/json/firewall_rules_v31.json

4. VERIFICAR OUTPUT ESPERADO:

   ✅ Scheduler:
   - NO más "queue full" messages
   - Stats de cola <80% utilización
   - Decisiones más espaciadas pero constantes

   ✅ Agent:
   - "🔍 DEBUG COMPRESSION" messages
   - "✅ No compression signature - good" (si ETCD funciona)
   - "⚠️ GZIP/ZLIB signature detected" (si ETCD falla)
   - "✅ Protobuf parsed: cmd_xyz"

5. RESOLVER PROBLEMAS:

   Si ves "⚠️ signature detected":
   - ETCD no está descomprimiendo
   - Verificar configuración crypto channels
   - Aplicar decompresión de emergencia

   Si ves "❌ UTF-8 error":
   - Confirma que es problema de compresión
   - Los datos están llegando comprimidos al parser
'''

    print(plan)


def main():
    """Aplicar todas las correcciones"""
    print("🚀 COMPREHENSIVE FIX - JSON Config + Compression Pipeline")
    print("=" * 60)
    print("🎯 Objetivos:")
    print("   1. Scheduler menos agresivo (configuración JSON)")
    print("   2. Debug pipeline descompresión (agent)")
    print("   3. Verificar configuración crypto ETCD")
    print("=" * 60)

    # 1. Aplicar configuración menos agresiva al scheduler
    scheduler_fixed = apply_less_aggressive_scheduler_config()

    # 2. Verificar configuración crypto del agent
    agent_crypto_ok = verify_agent_crypto_config()

    # 3. Proporcionar código de debug
    create_agent_debug_code()

    # 4. Plan de testing
    show_testing_plan()

    print(f"\n📊 RESUMEN:")
    print(f"   Scheduler JSON: {'✅ APLICADO' if scheduler_fixed else '❌ FALLÓ'}")
    print(f"   Agent Crypto: {'✅ CORRECTO' if agent_crypto_ok else '⚠️ REVISAR'}")
    print(f"   Debug Code: 📝 PROPORCIONADO")

    print(f"\n🎯 PRÓXIMOS PASOS:")
    print(f"1. Aplicar código debug al agent (archivo simple_firewall_agent_v31_etcd.py)")
    print(f"2. Reiniciar componentes en orden")
    print(f"3. Monitorear logs de compresión")
    print(f"4. Si ves signatures de compresión → ETCD no está descomprimiendo")


if __name__ == "__main__":
    main()