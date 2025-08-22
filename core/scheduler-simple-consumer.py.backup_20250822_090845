#!/usr/bin/env python3
"""
scheduler-simple-consumer.py - CONSUMER PARA DRENAR MENSAJES DEL SCHEDULER V3.1
✅ PUERTOS CORREGIDOS: Recibe en 5582, responde en 5581
✅ Recibe comandos FirewallCommand del scheduler-firewall.py
✅ Debug de protobuf V3.1 y análisis de mensajes
✅ V3.1 PROTOBUF EXCLUSIVO - con node_id y timestamp nativos
✅ Logging detallado para troubleshooting
"""
import zmq
import json
import time
import sys
import os
import signal
import traceback
from datetime import datetime
from pathlib import Path

# Add protocols path for protobuf imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'protocols', 'current'))

# Protobuf import handling
PROTOBUF_AVAILABLE = False
FirewallCommandsProto = None


def import_consumer_protobuf_v31():
    """Importa protobuf V3.1 EXCLUSIVO para consumer - TODO O NADA"""
    global FirewallCommandsProto, PROTOBUF_AVAILABLE

    print("🔍 Consumer: Buscando protobuf V3.1 EXCLUSIVO...")

    # Estrategias de importación múltiples
    import_strategies = [
        ("firewall_commands_v31_pb2", "Importación directa"),
        ("protocols.v3_1.firewall_commands_v31_pb2", "Paquete protocols.v3_1"),
    ]

    for import_path, description in import_strategies:
        try:
            FirewallCommandsProto = network_security_clean_v31_pb2
            PROTOBUF_AVAILABLE = True
            print(f"✅ Consumer: FirewallCommands v3.1 cargado: {description}")

            # Verificar que tiene los campos V3.1
            try:
                test_command = FirewallCommandsProto.FirewallCommand()
                fields = [field.name for field in test_command.DESCRIPTOR.fields]

                if 'node_id' in fields and 'timestamp' in fields:
                    print(f"✅ Consumer: Verificado FirewallCommand V3.1 con node_id y timestamp")
                    return True
                else:
                    print(f"❌ Consumer: FirewallCommand sin campos V3.1 requeridos")
                    return False
            except Exception as e:
                print(f"❌ Consumer: Error verificando campos: {e}")
                return False

        except ImportError:
            continue

    # Estrategia 2: Búsqueda por paths dinámicos
    current_dir = os.path.dirname(os.path.abspath(__file__))
    possible_paths = [
        os.path.join(current_dir, '..', 'protocols', 'v3.1'),
        os.path.join(current_dir, 'protocols', 'v3.1'),
        current_dir,
        os.path.join(current_dir, '..'),
    ]

    for protocols_path in possible_paths:
        protocols_path = os.path.abspath(protocols_path)
        pb2_file = os.path.join(protocols_path, 'firewall_commands_v31_pb2.py')

        if os.path.exists(pb2_file):
            try:
                sys.path.insert(0, protocols_path)
                import firewall_commands_v31_pb2 as FirewallCommandsProto
                PROTOBUF_AVAILABLE = True
                print(f"✅ Consumer: FirewallCommands v3.1 cargado desde: {protocols_path}")

                # Verificar campos V3.1
                test_command = FirewallCommandsProto.FirewallCommand()
                fields = [field.name for field in test_command.DESCRIPTOR.fields]

                if 'node_id' in fields and 'timestamp' in fields:
                    print(f"✅ Consumer: Verificado V3.1 desde path")
                    return True
                else:
                    print(f"❌ Consumer: Archivo encontrado pero sin campos V3.1")
                    return False

            except ImportError as e:
                if protocols_path in sys.path:
                    sys.path.remove(protocols_path)
                continue

    print(f"❌ Consumer: Protobuf V3.1 REQUERIDO pero NO ENCONTRADO")
    print(f"📁 Archivo requerido: firewall_commands_v31_pb2.py")
    print(f"📍 Ubicaciones buscadas:")
    for path in possible_paths:
        print(f"   • {os.path.abspath(path)}")
    return False


# Ejecutar importación V3.1 EXCLUSIVA
if not import_consumer_protobuf_v31():
    print(f"💥 FATAL: Consumer requiere protobuf V3.1 para funcionar")
    print(f"🛑 PARAR EJECUCIÓN - Sin V3.1 no hay consumer")
    sys.exit(1)


class SimpleFirewallConsumer:
    """Consumer simple para recibir comandos del scheduler - PUERTOS CORREGIDOS"""

    def __init__(self, consumer_port=5582, response_port=5581):
        """
        🔧 PUERTOS CORREGIDOS POR DEFECTO:
        - consumer_port=5582: Donde scheduler PUSH envía comandos (era 5580)
        - response_port=5581: Donde scheduler PULL recibe respuestas (correcto)
        """
        self.consumer_port = consumer_port
        self.response_port = response_port
        self.running = False

        # Estadísticas
        self.stats = {
            'messages_received': 0,
            'messages_parsed': 0,
            'protobuf_command_parsed': 0,
            'protobuf_batch_parsed': 0,
            'json_parsed': 0,
            'parse_errors': 0,
            'start_time': time.time()
        }

        # Setup ZMQ
        self.context = zmq.Context()
        self.setup_sockets()

        print(f"🔥 Simple Firewall Consumer V3.1 - PUERTOS CORREGIDOS")
        print(f"📥 Commands port (BIND): {consumer_port} - 🔧 CORREGIDO: ahora 5582")
        print(f"📤 Response port (CONNECT): {response_port} - ✅ CORRECTO: mantener 5581")

    def setup_sockets(self):
        """Setup ZMQ sockets - CONFIGURACIÓN CORREGIDA"""
        try:
            # Socket para recibir comandos del scheduler (PULL)
            self.commands_socket = self.context.socket(zmq.PULL)
            self.commands_socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 second timeout
            self.commands_socket.setsockopt(zmq.LINGER, 0)

            # BIND en el puerto 5582 donde scheduler PUSH envía
            commands_endpoint = f"tcp://localhost:{self.consumer_port}"
            self.commands_socket.bind(commands_endpoint)
            print(f"✅ Commands socket BIND on {commands_endpoint} - 🔧 NUEVO PUERTO")

            # Socket para enviar respuestas al scheduler (PUSH)
            self.responses_socket = self.context.socket(zmq.PUSH)
            self.responses_socket.setsockopt(zmq.SNDTIMEO, 1000)
            self.responses_socket.setsockopt(zmq.LINGER, 0)

            # CONNECT al puerto 5581 donde scheduler PULL escucha respuestas
            responses_endpoint = f"tcp://localhost:{self.response_port}"
            self.responses_socket.connect(responses_endpoint)
            print(f"✅ Responses socket CONNECT to {responses_endpoint} - ✅ CORRECTO")

            print(f"🎯 FLUJO CORREGIDO:")
            print(f"   scheduler:5582(PUSH) → consumer:5582(PULL) ✅")
            print(f"   consumer:5581(PUSH) → scheduler:5581(PULL) ✅")

        except Exception as e:
            print(f"❌ Error setting up ZMQ sockets: {e}")
            raise

    def parse_firewall_command(self, message_bytes):
        """Parsear comando de firewall desde bytes - Soporta FirewallCommand y FirewallCommandBatch"""
        parsed_data = None
        parsing_method = "unknown"

        # Intentar protobuf primero
        if PROTOBUF_AVAILABLE and FirewallCommandsProto:
            # Intentar FirewallCommand individual
            try:
                pb_command = FirewallCommandsProto.FirewallCommand()
                pb_command.ParseFromString(message_bytes)

                # Extraer todos los campos disponibles
                parsed_data = self.extract_protobuf_fields(pb_command, "FirewallCommand")
                parsing_method = "protobuf_command"
                self.stats['protobuf_command_parsed'] += 1

                print(f"✅ FirewallCommand protobuf parsed successfully")
                return parsed_data, parsing_method

            except Exception as pb_command_error:
                print(f"🔄 FirewallCommand parsing failed: {pb_command_error}")

            # Intentar FirewallCommandBatch
            try:
                pb_batch = FirewallCommandsProto.FirewallCommandBatch()
                pb_batch.ParseFromString(message_bytes)

                # Extraer todos los campos disponibles
                parsed_data = self.extract_protobuf_fields(pb_batch, "FirewallCommandBatch")
                parsing_method = "protobuf_batch"
                self.stats['protobuf_batch_parsed'] += 1

                print(f"✅ FirewallCommandBatch protobuf parsed successfully")
                return parsed_data, parsing_method

            except Exception as pb_batch_error:
                print(f"⚠️ FirewallCommandBatch parsing failed: {pb_batch_error}")

        # Fallback a JSON
        try:
            message_text = message_bytes.decode('utf-8')
            parsed_data = json.loads(message_text)
            parsing_method = "json"
            self.stats['json_parsed'] += 1
            print(f"✅ JSON parsed successfully")
            return parsed_data, parsing_method

        except Exception as json_error:
            print(f"⚠️ JSON parsing failed: {json_error}")

        # Último recurso - datos raw
        try:
            parsed_data = {
                'raw_length': len(message_bytes),
                'raw_preview': message_bytes[:100].hex(),
                'raw_text_preview': message_bytes[:100].decode('utf-8', errors='ignore'),
                'parsing_error': 'Could not parse as protobuf or JSON'
            }
            parsing_method = "raw"
            print(f"⚠️ Using raw data fallback")
            return parsed_data, parsing_method

        except Exception as e:
            print(f"❌ Complete parsing failure: {e}")
            self.stats['parse_errors'] += 1
            return None, "failed"

    def extract_protobuf_fields(self, pb_message, message_type_name="Unknown"):
        """Extraer todos los campos del protobuf message"""
        try:
            # Obtener descriptor del mensaje para ver todos los campos
            descriptor = pb_message.DESCRIPTOR

            extracted = {
                'message_type': f"{message_type_name} ({descriptor.name})",
                'fields': {},
                'available_fields': []
            }

            # Listar todos los campos disponibles
            for field in descriptor.fields:
                field_name = field.name
                extracted['available_fields'].append(field_name)

                # Intentar obtener el valor del campo
                try:
                    if hasattr(pb_message, field_name):
                        value = getattr(pb_message, field_name)

                        # Manejar casos especiales
                        if field.type == field.TYPE_ENUM:
                            # Para enums, mostrar tanto el valor numérico como el nombre
                            enum_name = field.enum_type.values_by_number.get(value)
                            if enum_name:
                                extracted['fields'][field_name] = f"{value} ({enum_name.name})"
                            else:
                                extracted['fields'][field_name] = value
                        elif field.label == field.LABEL_REPEATED:
                            # Para campos repetidos (como commands en batch)
                            if hasattr(value, '__len__'):
                                extracted['fields'][field_name] = f"[{len(value)} items]"
                                # Si son mensajes anidados, extraer el primero como ejemplo
                                if len(value) > 0 and hasattr(value[0], 'DESCRIPTOR'):
                                    extracted['fields'][f"{field_name}_sample"] = self.extract_nested_message(value[0])
                            else:
                                extracted['fields'][field_name] = str(value)
                        elif hasattr(value, 'DESCRIPTOR'):
                            # Mensaje anidado
                            extracted['fields'][field_name] = self.extract_nested_message(value)
                        else:
                            extracted['fields'][field_name] = value
                    else:
                        extracted['fields'][field_name] = "FIELD_NOT_ACCESSIBLE"
                except Exception as e:
                    extracted['fields'][field_name] = f"ERROR_ACCESSING: {e}"

            # Campos específicos que sabemos que deberían existir para FirewallCommand
            if "FirewallCommand" in message_type_name:
                command_fields = ['command_id', 'action', 'target_ip', 'target_port',
                                  'duration_seconds', 'reason', 'priority', 'dry_run',
                                  'rate_limit_rule', 'extra_params', 'node_id', 'timestamp']
            elif "FirewallCommandBatch" in message_type_name:
                command_fields = ['batch_id', 'target_node_id', 'timestamp', 'generated_by',
                                  'dry_run_all', 'commands', 'description', 'source_event_id',
                                  'confidence_score', 'expected_execution_time']
            else:
                command_fields = []

            if command_fields:
                extracted['known_fields_status'] = {}
                for field in command_fields:
                    if hasattr(pb_message, field):
                        try:
                            value = getattr(pb_message, field)
                            extracted['known_fields_status'][field] = {'exists': True, 'value': value}
                        except Exception as e:
                            extracted['known_fields_status'][field] = {'exists': True, 'error': str(e)}
                    else:
                        extracted['known_fields_status'][field] = {'exists': False}

            return extracted

        except Exception as e:
            return {'error': f'Error extracting protobuf fields: {e}'}

    def extract_nested_message(self, nested_msg):
        """Extraer información básica de un mensaje anidado"""
        try:
            fields = {}
            for field in nested_msg.DESCRIPTOR.fields:
                if hasattr(nested_msg, field.name):
                    value = getattr(nested_msg, field.name)
                    fields[field.name] = str(value)[:50] + ("..." if len(str(value)) > 50 else "")
            return fields
        except Exception as e:
            return f"Error extracting nested: {e}"

    def send_response(self, command_data, success=True, message="Consumer received"):
        """Enviar respuesta al scheduler"""
        try:
            # Crear respuesta
            if PROTOBUF_AVAILABLE and FirewallCommandsProto:
                try:
                    # Crear respuesta protobuf
                    response = FirewallCommandsProto.FirewallResponse()

                    # Campos básicos
                    if 'fields' in command_data and 'command_id' in command_data['fields']:
                        response.command_id = str(command_data['fields']['command_id'])
                    else:
                        response.command_id = f"consumer_{int(time.time())}"

                    response.success = success
                    response.message = message
                    response.timestamp = int(time.time() * 1000)

                    # Verificar si existe campo node_id
                    if hasattr(response, 'node_id'):
                        response.node_id = "simple_consumer_001"

                    response_bytes = response.SerializeToString()

                except Exception as pb_error:
                    print(f"⚠️ Error creating protobuf response: {pb_error}")
                    # Fallback a JSON
                    response_data = {
                        'command_id': command_data.get('fields', {}).get('command_id', f"consumer_{int(time.time())}"),
                        'success': success,
                        'message': message,
                        'timestamp': int(time.time() * 1000),
                        'node_id': 'simple_consumer_001',
                        'response_type': 'json_fallback'
                    }
                    response_bytes = json.dumps(response_data).encode('utf-8')
            else:
                # JSON response
                response_data = {
                    'command_id': command_data.get('fields', {}).get('command_id', f"consumer_{int(time.time())}"),
                    'success': success,
                    'message': message,
                    'timestamp': int(time.time() * 1000),
                    'node_id': 'simple_consumer_001',
                    'response_type': 'json'
                }
                response_bytes = json.dumps(response_data).encode('utf-8')

            # Enviar respuesta
            self.responses_socket.send(response_bytes, zmq.NOBLOCK)
            print(f"📤 Response sent: {message}")

        except zmq.Again:
            print(f"⚠️ Could not send response - socket not ready")
        except Exception as e:
            print(f"❌ Error sending response: {e}")

    def display_protobuf_data(self, data, parsing_method="protobuf"):
        """Mostrar datos de protobuf V3.1 parseados - RESALTA CAMPOS NATIVOS"""
        message_type = "FirewallCommand" if "command" in parsing_method else "FirewallCommandBatch"

        print(f"📋 PROTOBUF V3.1 DATA ({message_type}) - RECIBIDO EN PUERTO 5582:")
        print(f"   Message Type: {data.get('message_type', 'unknown')}")

        # Como estamos en V3.1 exclusivo, sabemos que tiene los campos
        print(f"🎯 VERSION: V3.1 (✅ Native node_id + timestamp GUARANTEED)")

        if 'available_fields' in data:
            print(f"   Available Fields: {data['available_fields']}")

            # Verificar que efectivamente tiene los campos V3.1
            v31_fields = ['node_id', 'timestamp']
            missing_fields = [field for field in v31_fields if field not in data['available_fields']]
            if missing_fields:
                print(f"   ⚠️ WARNING: Missing expected V3.1 fields: {missing_fields}")
            else:
                print(f"   ✅ V3.1 NATIVE FIELDS CONFIRMED: node_id, timestamp")

        if 'fields' in data:
            print(f"   Field Values:")
            for field, value in data['fields'].items():
                # Destacar campos V3.1 nativos
                if field == 'node_id':
                    print(f"      🎯 {field}: {value} (V3.1 NATIVE - scheduler identifier)")
                elif field == 'timestamp':
                    # Convertir timestamp a fecha legible
                    try:
                        if isinstance(value, (int, float)) and value > 1000000000000:  # timestamp en ms
                            from datetime import datetime
                            dt = datetime.fromtimestamp(value / 1000)
                            readable_time = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                            print(f"      ⏰ {field}: {value} (V3.1 NATIVE - {readable_time})")
                        else:
                            print(f"      ⏰ {field}: {value} (V3.1 NATIVE)")
                    except:
                        print(f"      ⏰ {field}: {value} (V3.1 NATIVE)")
                elif field == 'extra_params':
                    print(f"      📦 {field}: (V3.1 ADDITIONAL METADATA)")
                    if isinstance(value, dict):
                        for key, val in value.items():
                            if key in ['scheduler_node_id', 'source_ip', 'event_id']:
                                print(f"         🔍 {key}: {val} (scheduler metadata)")
                            elif key == 'protobuf_version':
                                print(f"         📋 {key}: {val} (version confirmation)")
                            else:
                                print(f"         • {key}: {val}")
                    else:
                        print(f"         {value}")
                elif field in ['command_id', 'action', 'target_ip']:
                    print(f"      🔥 {field}: {value} (core command)")
                elif field in ['duration_seconds', 'reason', 'priority', 'dry_run']:
                    print(f"      ⚙️ {field}: {value} (execution params)")
                elif isinstance(value, dict):
                    print(f"      {field}: {json.dumps(value, indent=8, default=str)}")
                else:
                    print(f"      {field}: {value}")

        print(f"   🔧 PUERTO CONFIRMATION:")
        print(f"      ✅ Message received on corrected port 5582")
        print(f"      ✅ Will respond on port 5581 to scheduler")
        print(f"      🎯 Port configuration now matches scheduler expectations")

    def display_json_data(self, data):
        """Mostrar datos JSON"""
        print(f"📋 JSON DATA (RECIBIDO EN PUERTO 5582):")
        print(json.dumps(data, indent=2, default=str))

    def display_raw_data(self, data):
        """Mostrar datos raw"""
        print(f"📋 RAW DATA (RECIBIDO EN PUERTO 5582):")
        for key, value in data.items():
            print(f"   {key}: {value}")

    def start(self):
        """Iniciar el consumer"""
        self.running = True
        print(f"\n🚀 Starting Simple Firewall Consumer V3.1 - PUERTOS CORREGIDOS...")
        print(f"📋 Protobuf V3.1 available: {PROTOBUF_AVAILABLE}")
        print(f"🎯 Ready to receive firewall commands on port 5582...")
        print(f"📤 Will send responses to scheduler on port 5581...")
        print(f"⏹️ Press Ctrl+C to stop\n")

        try:
            while self.running:
                try:
                    # Recibir mensaje
                    message_bytes = self.commands_socket.recv(zmq.NOBLOCK)
                    self.stats['messages_received'] += 1

                    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    print(f"\n📨 [{timestamp}] Message received on port 5582 ({len(message_bytes)} bytes)")

                    # Parsear mensaje
                    parsed_data, parsing_method = self.parse_firewall_command(message_bytes)

                    if parsed_data:
                        self.stats['messages_parsed'] += 1

                        print(f"🔍 Parsing method: {parsing_method}")

                        # Mostrar contenido parseado
                        if parsing_method in ["protobuf_command", "protobuf_batch"]:
                            self.display_protobuf_data(parsed_data, parsing_method)
                        elif parsing_method == "json":
                            self.display_json_data(parsed_data)
                        else:
                            self.display_raw_data(parsed_data)

                        # Enviar respuesta de confirmación
                        self.send_response(parsed_data, success=True,
                                           message=f"Command processed by consumer on port 5582 ({parsing_method})")
                    else:
                        print(f"❌ Failed to parse message")
                        # Enviar respuesta de error
                        self.send_response({}, success=False, message="Parse error on port 5582")

                except zmq.Again:
                    # No hay mensajes, continuar
                    time.sleep(0.1)
                except Exception as e:
                    print(f"❌ Error processing message: {e}")
                    traceback.print_exc()
                    time.sleep(1)

        except KeyboardInterrupt:
            print(f"\n🛑 Interrupt received")
        finally:
            self.stop()

    def show_stats(self):
        """Mostrar estadísticas"""
        uptime = time.time() - self.stats['start_time']
        print(f"\n📊 CONSUMER STATISTICS (PUERTO 5582):")
        print(f"   ⏱️ Uptime: {uptime:.1f}s")
        print(f"   📨 Messages received: {self.stats['messages_received']}")
        print(f"   ✅ Messages parsed: {self.stats['messages_parsed']}")
        print(f"   🔄 FirewallCommand parsed: {self.stats['protobuf_command_parsed']}")
        print(f"   📦 FirewallCommandBatch parsed: {self.stats['protobuf_batch_parsed']}")
        print(f"   📝 JSON parsed: {self.stats['json_parsed']}")
        print(f"   ❌ Parse errors: {self.stats['parse_errors']}")

        if self.stats['messages_received'] > 0:
            rate = self.stats['messages_received'] / uptime
            print(f"   📈 Rate: {rate:.2f} msg/s")

    def stop(self):
        """Parar el consumer"""
        print(f"\n🛑 Stopping Simple Firewall Consumer V3.1...")
        self.running = False

        # Mostrar estadísticas finales
        self.show_stats()

        # Cerrar sockets
        try:
            self.commands_socket.setsockopt(zmq.LINGER, 0)
            self.commands_socket.close()

            self.responses_socket.setsockopt(zmq.LINGER, 0)
            self.responses_socket.close()

            self.context.term()
            print(f"✅ ZMQ sockets closed")
        except Exception as e:
            print(f"⚠️ Error closing sockets: {e}")


def signal_handler(sig, frame):
    """Manejar señales"""
    print("\n🛑 Signal received")
    sys.exit(0)


def main():
    """Función principal - PUERTOS HARDCODEADOS CORREGIDOS PARA HERRAMIENTA AUXILIAR"""
    # Setup signal handling
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("🔥 Simple Firewall Consumer V3.1 - PUERTOS CORREGIDOS")
    print("✅ Drains messages from scheduler-firewall.py on port 5582")
    print("✅ Sends responses to scheduler-firewall.py on port 5581")
    print("🔍 Debug protobuf V3.1 FirewallCommand parsing")
    print("📊 Shows detailed message analysis with native node_id/timestamp")

    # 🔧 PUERTOS HARDCODEADOS CORREGIDOS PARA HERRAMIENTAS AUXILIARES
    consumer_port = 5582  # 🔧 CORREGIDO: 5580 → 5582 (donde scheduler PUSH envía)
    response_port = 5581  # ✅ CORRECTO: Puerto donde scheduler PULL escucha

    # Permitir override por argumentos para flexibilidad
    if len(sys.argv) > 1:
        try:
            consumer_port = int(sys.argv[1])
            print(f"🔧 Consumer port overridden to: {consumer_port}")
        except ValueError:
            print(f"❌ Invalid port: {sys.argv[1]}")
            sys.exit(1)

    if len(sys.argv) > 2:
        try:
            response_port = int(sys.argv[2])
            print(f"🔧 Response port overridden to: {response_port}")
        except ValueError:
            print(f"❌ Invalid response port: {sys.argv[2]}")
            sys.exit(1)

    print(f"\n🔧 Configuration CORREGIDA:")
    print(f"   📥 Consumer port (BIND): {consumer_port} - 🔧 CORREGIDO para recibir de scheduler")
    print(f"   📤 Response port (CONNECT): {response_port} - ✅ CORRECTO para responder a scheduler")
    print(f"   🔄 Protobuf V3.1 available: {PROTOBUF_AVAILABLE}")
    print(f"\n🎯 EXPECTED FLOW:")
    print(f"   ml_detector:5580(PUB) → scheduler:5580(SUB)")
    print(f"   scheduler:5582(PUSH) → consumer:5582(PULL) ← THIS TOOL")
    print(f"   consumer:5581(PUSH) → scheduler:5581(PULL) ← THIS TOOL")

    try:
        # Crear y iniciar consumer
        consumer = SimpleFirewallConsumer(consumer_port, response_port)
        consumer.start()

    except Exception as e:
        print(f"\n💥 FATAL ERROR:")
        print(f"❌ {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()