# upgraded-happiness

Esto es una nueva feature branch de este repo, https://github.com/alonsoir/scada_programming/tree/main/scapy 
donde afrontaremos el uso de zeromq para que cada agente pueda ser desplegado en cada nodo, 
potencialmente miles de nodos, para que dicho payload superoptimizado con la alarma del evento, 
se vea notificado en un dashboard que se vea alimentado potencialmente de todos los eventos producidos por 
los agentes.

En cuanto se detecta el evento sospechoso, se crea un payload superoptimizado 
binario con la información y en el dashboard se consume.

Análisis de la Arquitectura Propuesta
Fortalezas:

Escalabilidad horizontal: ZeroMQ es excelente para miles de nodos
Bajo overhead: Payloads binarios optimizados minimizan el tráfico
Tiempo real: Detección y notificación inmediata de eventos
Distribución: Descentralización de la carga de procesamiento

Puntos Débiles y Desafíos Críticos
1. Gestión de Falsos Positivos/Negativos

Riesgo: Alertas innecesarias saturan al personal de seguridad
Mitigación: Implementar ML adaptativo y umbrales dinámicos
Implementación: Sistema de feedback para entrenar el modelo

2. Saturación de Red y Recursos

Problema: Miles de agentes pueden colapsar la infraestructura
Soluciones:

Rate limiting inteligente por agente
Agregación local antes del envío
Priorización de eventos (crítico vs informativo)
Circuit breakers para degradación elegante



3. Persistencia y Forense Digital

Desafío: Almacenar TB de datos para investigación posterior
Estrategia:

Almacenamiento jerárquico (hot/warm/cold)
Compresión inteligente de eventos similares
Índices temporales para búsqueda eficiente
Retención basada en políticas de compliance



4. Capacidad de "Time Travel" / Replay

Complejidad: Reconstruir estado histórico
Implementación:

Event sourcing pattern
Snapshots periódicos del estado
Logs estructurados con timestamps precisos
Índices por tiempo/evento/dispositivo



5. Otros Puntos Críticos que Debes Considerar:
Seguridad:

Autenticación/autorización de agentes
Cifrado de payloads sensibles
Prevención de ataques de denegación de servicio
Validación de integridad de eventos

Disponibilidad:

Tolerancia a fallos de agentes individuales
Redundancia del sistema central
Mecanismos de reconexión automática
Heartbeats para detectar agentes caídos

Observabilidad:

Métricas de salud del sistema distribuido
Monitoreo de la latencia end-to-end
Alertas sobre agentes desconectados
Dashboard de estado de la infraestructura

Gestión de Configuración:

Actualización de reglas de detección en caliente
Versionado de configuraciones de agentes
Rollback automático ante errores

Propuesta de Arquitectura Refinada

┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│   Agentes       │    │   ZeroMQ     │    │   Dashboard     │
│   (Nodos)       │────│   Broker     │────│   + Storage     │
│                 │    │   Layer      │    │                 │
└─────────────────┘    └──────────────┘    └─────────────────┘
        │                       │                     │
        │              ┌────────▼──────────┐         │
        │              │  Event Store      │         │
        │              │  (Time Series)    │         │
        │              └───────────────────┘         │
        │                                            │
        └──────────────  Feedback Loop  ─────────────┘

scapy/
├── zeromq_agents/                    # Nueva feature branch
│   ├── agents/                       # Agentes distribidos
│   │   ├── __init__.py
│   │   ├── base_agent.py            # Clase base del agente
│   │   ├── network_monitor_agent.py # Agente monitor de red
│   │   └── config/
│   │       ├── agent_config.yaml
│   │       └── detection_rules.yaml
│   ├── common/                       # Código compartido
│   │   ├── __init__.py
│   │   ├── payload.py               # Formato de payload optimizado
│   │   ├── zmq_utils.py             # Utilidades ZeroMQ
│   │   └── event_types.py           # Tipos de eventos SCADA
│   ├── dashboard/                    # Dashboard receptor (futuro)
│   │   ├── __init__.py
│   │   └── receiver.py
│   ├── storage/                      # Persistencia (futuro)
│   │   ├── __init__.py
│   │   └── event_store.py
│   ├── tests/                        # Tests unitarios
│   │   ├── __init__.py
│   │   ├── test_base_agent.py
│   │   └── test_payload.py
│   ├── requirements.txt              # Dependencias
│   ├── README.md                     # Documentación
│   └── run_agent.py                  # Script principal

# Sistema de Agentes Distribuidos SCADA con ZeroMQ

## 🎯 Descripción

Sistema distribuido para monitoreo de seguridad en redes SCADA utilizando agentes ligeros que detectan anomalías y envían eventos optimizados a través de ZeroMQ a un dashboard centralizado.

## 🏗️ Arquitectura

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│   Agentes       │────│   ZeroMQ     │────│   Dashboard     │
│  (Nodos SCADA)  │    │   Broker     │    │  Centralizado   │
└─────────────────┘    └──────────────┘    └─────────────────┘
```

### Componentes

- **Agentes**: Monitores distribuidos en cada nodo
- **ZeroMQ**: Bus de mensajes de alta performance  
- **Payloads Optimizados**: Eventos binarios comprimidos
- **Dashboard**: Receptor centralizado (próxima iteración)

## 🚀 Instalación y Configuración

### 1. Crear la Feature Branch

```bash
git checkout main
git pull origin main
git checkout -b feature/zeromq-distributed-agents
```

### 2. Crear Estructura de Directorios

```bash
mkdir -p zeromq_agents/{agents/config,common,dashboard,storage,tests}
cd zeromq_agents
```

### 3. Instalar Dependencias

```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
pyzmq>=25.1.0
scapy>=2.5.0
pyyaml>=6.0
click>=8.1.0
colorama>=0.4.6
msgpack>=1.0.5
psutil>=5.9.0
```

## 🖥️ Uso del Sistema

### Ejecutar un Agente Básico

```bash
# Agente de monitoreo de red básico
sudo python run_agent.py --agent-id network-001 --interface eth0

# Con configuración personalizada
sudo python run_agent.py \
  --agent-id scada-monitor-01 \
  --interface enp0s3 \
  --zmq-endpoint tcp://192.168.1.100:5555 \
  --log-level DEBUG
```

### Opciones Disponibles

- `--agent-id`: Identificador único del agente
- `--interface`: Interfaz de red a monitorear (opcional)
- `--zmq-endpoint`: Endpoint del broker ZeroMQ
- `--log-level`: Nivel de logging (DEBUG, INFO, WARNING, ERROR)

## 🔍 Eventos Detectados

### Alertas de Seguridad

- **Port Scan**: Escaneo de puertos desde IPs externas
- **Connection Flood**: Exceso de conexiones desde una IP
- **Suspicious Port Access**: Acceso a puertos sensibles (SSH, RDP, Modbus, etc.)
- **Protocol Anomalies**: Violaciones de protocolos SCADA

### Métricas del Sistema

- **Heartbeats**: Estado de salud de agentes
- **Performance**: CPU, memoria, red
- **Agent Lifecycle**: Inicio/parada de agentes

## 📊 Formato de Payload Optimizado

### Estructura del Evento

```json
{
  "timestamp": "2025-06-25T10:30:00.000Z",
  "agent_id": "network-001",
  "node_info": {
    "hostname": "scada-node-01",
    "ip_address": "192.168.1.50"
  },
  "event_type": "SECURITY_ALERT",
  "severity": "HIGH",
  "data": {
    "type": "port_scan",
    "source_ip": "10.0.1.100",
    "ports_scanned": [22, 23, 502, 3389],
    "scan_count": 15
  },
  "sequence": 1234
}
```

### Codificación Binaria

- **JSON Comprimido**: Para desarrollo y debug
- **MessagePack**: Formato binario eficiente 
- **Custom Binary**: Ultra-optimizado para eventos críticos

## 🧪 Testing

### Tests Básicos

```python
# tests/test_basic_functionality.py
import unittest
import time
from agents.network_monitor_agent import NetworkMonitorAgent
from common.payload import PayloadEncoder, EventPayload

class TestBasicFunctionality(unittest.TestCase):
    
    def test_agent_initialization(self):
        """Test que el agente se inicializa correctamente."""
        agent = NetworkMonitorAgent("test-001")
        self.assertEqual(agent.agent_id, "test-001")
        self.assertIsNotNone(agent.node_info)
    
    def test_payload_encoding(self):
        """Test de codificación/decodificación de payloads."""
        payload = EventPayload(
            timestamp="2025-06-25T10:30:00.000Z",
            agent_id="test-001",
            node_id="node-001",
            event_type="TEST",
            severity="INFO",
            data={"test": "data"},
            sequence=1
        )
        
        # Test MessagePack
        encoded = PayloadEncoder.encode_msgpack(payload)
        self.assertIsInstance(encoded, bytes)
        
        # Test optimizado
        encoded_opt = PayloadEncoder.encode_optimized(payload)
        decoded = PayloadEncoder.decode_optimized(encoded_opt)
        self.assertEqual(decoded.agent_id, payload.agent_id)

if __name__ == '__main__':
    unittest.main()
```

### Ejecutar Tests

```bash
python -m pytest tests/ -v
```

## 🔧 Configuración Avanzada

### agent_config.yaml

```yaml
agent:
  heartbeat_interval: 30
  max_events_per_second: 100

network_monitor:
  detection:
    max_connections_per_ip: 50
    port_scan_threshold: 10
    
    suspicious_ports:
      - 22    # SSH
      - 502   # Modbus
      - 3389  # RDP
    
    scada_ports:
      - 502   # Modbus
      - 2404  # IEC 61850
      - 44818 # EtherNet/IP

zeromq:
  publisher:
    endpoint: "tcp://localhost:5555"
    high_water_mark: 1000
```

## 📈 Monitoreo y Métricas

### Logs de Ejemplo

```
2025-06-25 10:30:15 - Agent[network-001] - INFO - Iniciando agente network-001
2025-06-25 10:30:15 - Agent[network-001] - INFO - ZeroMQ conectado a tcp://localhost:5555
2025-06-25 10:30:15 - Agent[network-001] - INFO - Monitor de red configurado en interfaz: eth0
2025-06-25 10:30:45 - Agent[network-001] - WARNING - Evento enviado: SECURITY_ALERT - HIGH
```

### Heartbeat del Sistema

Cada agente envía heartbeats cada 30 segundos con:
- Tiempo de actividad
- Número de eventos enviados  
- Uso de CPU y memoria
- Estado de conectividad

## 🔒 Consideraciones de Seguridad

### Permisos Requeridos

- **Root/Admin**: Para captura de paquetes de red
- **Firewall**: Abrir puertos ZeroMQ (ej: 5555)
- **SELinux/AppArmor**: Configurar políticas si están activos

### Recomendaciones

- Ejecutar agentes en entornos aislados
- Usar certificados TLS para ZeroMQ en producción
- Implementar rate limiting a nivel de red
- Logs centralizados para auditoría

## 🎯 Próximos Pasos

### Iteración 1 ✅
- [x] Agente básico con ZeroMQ
- [x] Detección de anomalías de red
- [x] Payload optimizado
- [x] Configuración YAML

### Iteración 2 📋
- [ ] Dashboard receptor con WebSocket
- [ ] Persistencia en base de datos
- [ ] Interfaz web de monitoreo
- [ ] Alertas por email/Slack

### Iteración 3 📋  
- [ ] Machine Learning para detección
- [ ] Correlación de eventos
- [ ] Capacidad de "replay" histórico
- [ ] API REST para gestión

## 🐛 Troubleshooting

### Problemas Comunes

**Error de permisos:**
```bash
sudo python run_agent.py --agent-id network-001
```

**ZeroMQ no conecta:**
- Verificar que el puerto 5555 esté abierto
- Comprobar firewall y configuración de red

**Alta CPU:**
- Reducir umbral de detección en configuración
- Usar filtros de red más específicos

## 🤝 Contribución

```bash
# Crear rama feature
git checkout -b feature/nueva-funcionalidad

# Hacer commits
git add .
git commit -m "feat: nueva funcionalidad"

# Push y PR
git push origin feature/nueva-funcionalidad
# Crear Pull Request en GitHub
```

---

Test básico local:

# Terminal 1: Simular broker ZeroMQ (temporal)
python -c "import zmq; c=zmq.Context(); s=c.socket(zmq.SUB); s.bind('tcp://*:5555'); s.setsockopt_string(zmq.SUBSCRIBE, ''); [print(s.recv_multipart()) for _ in range(10)]"

# Terminal 2: Ejecutar agente
sudo python run_agent.py --agent-id test-001

![Captura de pantalla 2025-06-30 a las 10.46.24.png](../../Desktop/Captura%20de%20pantalla%202025-06-30%20a%20las%2010.46.24.png)