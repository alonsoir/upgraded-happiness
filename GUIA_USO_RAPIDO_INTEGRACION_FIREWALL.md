# 🛡️ Guía de Integración Completa - SCADA Real (PROTOBUF REAL)

## 📋 Resumen de la Arquitectura

```
promiscuous_agent.py → lightweight_ml_detector.py → dashboard.py
     (puerto 5559)         (puerto 5560)         (puerto 8000)
                                ↓
                     simple_firewall_agent.py
                          (puerto 5561)
```

## 🔧 Estructuras Protobuf Reales

### **NetworkEvent** (network_event_extended_fixed_pb2)
```protobuf
message NetworkEvent {
    string event_id = 1;
    int64 timestamp = 2;
    string source_ip = 3;
    string target_ip = 4;
    int32 packet_size = 5;
    int32 dest_port = 6;
    int32 src_port = 7;
    string agent_id = 8;
    float anomaly_score = 9;           // ML enriquecido
    double latitude = 10;              // GPS enriquecido
    double longitude = 11;             // GPS enriquecido
    string event_type = 12;
    float risk_score = 13;             // ML enriquecido
    string description = 14;
    string so_identifier = 15;         // "linux_iptables", "windows_firewall", etc.
    string node_hostname = 16;
    string os_version = 17;
    string firewall_status = 18;
    string agent_version = 19;
    bool is_initial_handshake = 20;    // Handshake inicial
}
```

### **FirewallCommand** (firewall_commands_pb2)
```protobuf
enum CommandAction {
    BLOCK_IP = 0;
    UNBLOCK_IP = 1;
    BLOCK_PORT = 2;
    UNBLOCK_PORT = 3;
    RATE_LIMIT_IP = 4;
    ALLOW_IP_TEMP = 5;
    FLUSH_RULES = 6;
    LIST_RULES = 7;
    BACKUP_RULES = 8;
    RESTORE_RULES = 9;
}

enum CommandPriority {
    LOW = 0;
    MEDIUM = 1;
    HIGH = 2;
    CRITICAL = 3;
}

message FirewallCommand {
    string command_id = 1;
    CommandAction action = 2;          // Enum real
    string target_ip = 3;
    int32 target_port = 4;
    int32 duration_seconds = 5;
    string reason = 6;
    CommandPriority priority = 7;      // Enum real
    bool dry_run = 8;
    string rate_limit_rule = 9;
    map<string, string> extra_params = 10;
}

message FirewallCommandBatch {
    string batch_id = 1;
    string target_node_id = 2;
    string so_identifier = 3;
    int64 timestamp = 4;
    string generated_by = 5;
    bool dry_run_all = 6;
    repeated FirewallCommand commands = 7;
    string description = 8;
    string source_event_id = 9;
    float confidence_score = 10;
    int32 expected_execution_time = 11;
}
```

## 🔄 Flujo de Datos Completo

### 1. **Promiscuous Agent → ML Detector**
```python
# promiscuous_agent.py envía eventos básicos + handshake inicial
event = network_event_extended_fixed_pb2.NetworkEvent()
event.event_id = "evt_001"
event.source_ip = "192.168.1.100"
event.target_ip = "10.0.0.1"
event.dest_port = 22
event.agent_id = "agent_001"
event.so_identifier = "linux_iptables"
event.node_hostname = "server-01"
event.os_version = "Ubuntu 22.04"
event.firewall_status = "active"
event.agent_version = "1.0.0"
event.is_initial_handshake = True  # Solo en primer evento
socket.send(event.SerializeToString())  # → puerto 5559
```

### 2. **ML Detector → Dashboard**
```python
# lightweight_ml_detector.py enriquece y reenvía
enriched_event = network_event_extended_fixed_pb2.NetworkEvent()
enriched_event.CopyFrom(original_event)  # Copia todo
enriched_event.anomaly_score = 0.85
enriched_event.risk_score = 0.92
enriched_event.latitude = 40.7128
enriched_event.longitude = -74.0060
enriched_event.description = "ML: A:0.85 R:0.92 | Original description"
socket.send(enriched_event.SerializeToString())  # → puerto 5560
```

### 3. **Dashboard → Firewall Agent**
```python
# dashboard.py genera lotes de comandos inteligentes
batch = firewall_commands_pb2.FirewallCommandBatch()
batch.batch_id = "batch_001"
batch.target_node_id = "agent_001"
batch.so_identifier = "linux_iptables"
batch.timestamp = int(time.time() * 1000)
batch.generated_by = "dashboard"
batch.dry_run_all = True
batch.description = "High risk event response"
batch.confidence_score = 0.9

# Agregar comando al lote
command = batch.commands.add()
command.command_id = "cmd_001"
command.action = firewall_commands_pb2.BLOCK_IP  # Enum
command.target_ip = "192.168.1.100"
command.target_port = 0
command.duration_seconds = 3600
command.reason = "High risk SSH attempt"
command.priority = firewall_commands_pb2.HIGH  # Enum
command.dry_run = True

socket.send(batch.SerializeToString())  # → puerto 5561
```

### 4. **Firewall Agent → Dashboard** (confirmación)
```python
# simple_firewall_agent.py envía respuesta del lote
response = firewall_commands_pb2.FirewallResponse()
response.batch_id = batch.batch_id
response.node_id = "agent_001"
response.timestamp = int(time.time() * 1000)
response.success = True
response.message = "Batch processed: 1/1 successful"
response.total_commands = 1
response.successful_commands = 1
response.failed_commands = 0

socket.send(response.SerializeToString())  # → puerto 5560
```

## 🎯 Orden de Ejecución

### Terminal 1: Firewall Agent
```bash
cd upgraded-happiness
python simple_firewall_agent.py --port 5561
```

### Terminal 2: ML Detector
```bash
cd upgraded-happiness
python lightweight_ml_detector.py --input-port 5559 --output-port 5560
```

### Terminal 3: Dashboard
```bash
cd upgraded-happiness
python real_zmq_dashboard_with_firewall.py
```

### Terminal 4: Promiscuous Agent
```bash
cd upgraded-happiness
python promiscuous_agent.py
```

### Terminal 5: Test de Integración
```bash
cd upgraded-happiness
python integration_test.py
```

## 🔍 Verificación

### 1. **Logs a verificar**
```bash
# Dashboard
✅ Protobuf importado desde src.protocols.protobuf.network_event_extended_fixed_pb2
✅ Protobuf importado desde src.protocols.protobuf.firewall_commands_pb2
🔌 Conectado a ZeroMQ puerto 5560 (eventos enriquecidos por ML - PROTOBUF)
🔥 Firewall command sender conectado al puerto 5561 (PROTOBUF)
🤝 Handshake recibido de agent_001 (linux_iptables)
📡 Evento ML protobuf: 192.168.1.100 → 10.0.0.1 (R: 0.92, A: 0.85)

# ML Detector
✅ Protobuf network_event_extended_fixed_pb2 importado desde src.protocols.protobuf
📡 Input port: 5559
📤 Output port: 5560
🤝 Procesando handshake inicial de agent_001 (linux_iptables)
📊 Evento enriquecido: evt_001 A:0.85 R:0.92

# Firewall Agent
✅ Protobuf importado desde src.protocols.protobuf
📡 Listening on port 5561
📦 Protobuf: ✅ Available
📦 Lote recibido: batch_001
   Nodo destino: agent_001
   SO: linux_iptables
   Comandos: 1
   [1] cmd_001 - BLOCK_IP - 192.168.1.100 - HIGH priority
```

### 2. **Dashboard Web**
- Accede a `http://localhost:8000`
- Verifica indicadores de estado:
  - 🟢 ZeroMQ (eventos llegando)
  - 🟢 ML Active (scores > 0)
  - 🟢 Firewall (comandos activos)
  - 🟢 Protobuf (comunicación protobuf)
- Verifica contadores:
  - Eventos totales
  - Nodos registrados (handshakes)
  - Eventos con GPS
  - Comandos enviados

### 3. **Eventos en Dashboard**
Los eventos deben mostrar:
- `[PB]` badge (protobuf)
- `[ML]` badge (ML enriquecido)
- `[GPS]` badge (coordenadas disponibles)
- `[HS]` badge (handshake inicial)
- Scores de anomalía y riesgo
- Información del nodo (SO, hostname, etc.)

## 🧪 **Testing Automatizado**

### Ejecutar Test Completo
```bash
python integration_test.py
```

### Resultados Esperados
```
📤 Eventos enviados: 11
📥 Eventos recibidos (enriquecidos): 11
🛡️ Comandos individuales recibidos: 0
📦 Lotes de comandos recibidos: 1
📈 Tasa de éxito eventos: 100.0%
✅ Flujo ML detector → Dashboard: FUNCIONANDO
✅ Flujo Dashboard → Firewall: FUNCIONANDO
✅ Protobuf: DISPONIBLE
```

## 🐛 Resolución de Problemas

### Error: "Protobuf no disponible"
```bash
pip install protobuf
# Verificar que los archivos .proto estén compilados
python -c "import network_event_extended_fixed_pb2; print('OK')"
python -c "import firewall_commands_pb2; print('OK')"
```

### Error: "CommandAction has no attribute 'Name'"
```bash
# Recompilar archivos .proto
protoc --python_out=. network_event_extended_fixed.proto
protoc --python_out=. firewall_commands.proto
```

### Error: "Eventos no llegan al dashboard"
1. Verificar que ML Detector esté corriendo
2. Verificar logs de protobuf parsing
3. Verificar que el handshake inicial se procese
4. Verificar puertos no ocupados

### Error: "Comandos firewall no funcionan"
1. Verificar que simple_firewall_agent esté corriendo
2. Verificar conexión puerto 5561
3. Verificar que reciba FirewallCommandBatch
4. Verificar logs de enums (CommandAction, CommandPriority)

## 🆕 **Funcionalidades Nuevas**

### 1. **Handshake Inicial**
- Primer evento con `is_initial_handshake = True`
- Registra información del nodo
- Procesa información del SO y firewall
- Muestra en dashboard con badge `[HS]`

### 2. **Lotes de Comandos**
- FirewallCommandBatch con múltiples comandos
- Ejecución coordinada con `dry_run_all`
- Respuesta con FirewallResponse
- Estadísticas de lotes en dashboard

### 3. **Enums Protobuf**
- CommandAction: BLOCK_IP, RATE_LIMIT_IP, etc.
- CommandPriority: LOW, MEDIUM, HIGH, CRITICAL
- Conversión automática en interfaces web

### 4. **Información Extendida del Nodo**
- so_identifier: Tipo de firewall
- node_hostname: Nombre del nodo
- os_version: Versión del SO
- firewall_status: Estado del firewall
- agent_version: Versión del agente

## 🔒 Seguridad

### Modo Display-Only (Recomendado)
```bash
# Todos los comandos en modo simulación
python simple_firewall_agent.py  # dry_run=True por defecto
```

### Modo Producción (¡Peligroso!)
```bash
# SOLO para producción con supervisión
python simple_firewall_agent.py --apply-real
```

### Validaciones de Seguridad
- Validación de IPs en comandos
- Verificación de nodo destino
- Confirmación de SO compatible
- Timeouts en ejecución
- Logs completos de comandos

## 📊 Monitoreo

### APIs de Estadísticas
- `GET /api/stats` - Estadísticas completas
- `GET /api/events` - Eventos recientes
- `GET /api/firewall/log` - Log de comandos
- `GET /api/firewall/pending` - Comandos pendientes
- `GET /health` - Estado del sistema

### Métricas Clave
- `total_events` - Eventos procesados
- `nodes_registered` - Nodos registrados
- `handshakes_received` - Handshakes iniciales
- `anomaly_events` - Eventos anómalos
- `high_risk_events` - Eventos de alto riesgo
- `batches_received` - Lotes de comandos
- `commands_executed` - Comandos ejecutados

## 🎯 Validaciones de Integración

### Checklist de Verificación
- [ ] Protobuf compilado correctamente
- [ ] network_event_extended_fixed_pb2 importa sin errores
- [ ] firewall_commands_pb2 importa sin errores
- [ ] Enums (CommandAction, CommandPriority) disponibles
- [ ] Handshake inicial se procesa correctamente
- [ ] ML detector enriquece eventos
- [ ] Dashboard muestra eventos con todos los campos
- [ ] Comandos se envían como FirewallCommandBatch
- [ ] Firewall agent procesa lotes
- [ ] Confirmaciones se envían de vuelta
- [ ] APIs responden correctamente
- [ ] Test de integración pasa al 100%

## 🚀 Optimizaciones

### Rendimiento
- Buffer de eventos en ML detector
- Lotes de comandos para eficiencia
- Timeouts configurables
- Reconexión automática de sockets

### Escalabilidad
- Múltiples nodos con diferentes SO
- Balanceo de carga de comandos
- Estadísticas por nodo
- Agregación de métricas

---

**✅ Estado**: Todos los componentes actualizados con protobuf real
**🔄 Comunicación**: 100% Protobuf con enums y estructuras completas
**🛡️ Seguridad**: Modo display-only por defecto con validaciones
**📊 Monitoreo**: APIs completas y testing automatizado
**🧪 Testing**: Script de integración con verificación completa