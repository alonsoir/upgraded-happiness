# 🚀 GUÍA COMPLETA DE ARRANQUE - Sistema Integrado JSON

## ✅ ARCHIVOS COMPLETADOS

### 📄 Archivos de Configuración JSON
1. **simple_firewall_agent_config.json** ✅ - Nuclear option OFF por defecto
2. **lightweight_ml_detector_config.json** ✅ - Puertos 5559→5560 
3. **dashboard_config.json** ✅ - Configuración completa del dashboard
4. **enhanced_agent_config.json** ✅ - Agente promiscuo con GPS

### 🐍 Archivos Python REFACTORIZADOS
1. **simple_firewall_agent.py** ✅ - 100% configuración JSON
2. **lightweight_ml_detector.py** ✅ - 100% configuración JSON
3. **real_zmq_dashboard_with_firewall.py** ✅ - 100% configuración JSON
4. **promiscuous_agent.py** ✅ - Mejorado y 100% configuración JSON

## 🔧 CAMBIOS IMPLEMENTADOS

### ✅ Cada archivo Python ahora:
- **Lee TODA su configuración desde JSON** (no hay valores hardcodeados)
- **Configura logging desde JSON** (nivel, archivo, formato, rotación)
- **Valida configuración** con `--test-config`
- **Muestra estadísticas** incluyendo qué configuración se usó
- **Maneja errores** de configuración graciosamente
- **Usa merge recursivo** para configuraciones por defecto + usuario
- **Crea directorios** automáticamente (logs/, data/)

### ✅ Funcionalidades nuevas:
- **Rate limiting configurable** en firewall agent
- **Persistencia de estado** configurable  
- **Performance monitoring** en ML detector
- **Threat rules dinámicas** desde JSON en dashboard
- **GPS detection configurable** en promiscuous agent
- **Filtrado avanzado** de paquetes por configuración
- **Handshakes periódicos** configurables
- **Auto-save** de estados y modelos ML

## 🎯 FLUJO DE DATOS CONFIGURADO

```
Terminal 2: promiscuous_agent.py enhanced_agent_config.json
    ↓ Puerto 5559 (configurable)
    ↓ [network_event_extended_fixed protobuf + GPS + handshake]
    ↓
Terminal 3: lightweight_ml_detector.py lightweight_ml_detector_config.json  
    ↓ Puerto 5560 (configurable)
    ↓ [protobuf + ML scores + GeoIP enrichment]
    ↓
Terminal 4: real_zmq_dashboard_with_firewall.py dashboard_config.json
    ↓ Puerto 5561 (configurable) 
    ↓ [firewall_commands_pb2 batch con threat rules configurables]
    ↓
Terminal 1: simple_firewall_agent.py simple_firewall_agent_config.json
    ↓ Puerto 5560 (configurable)
    ↓ [firewall_response protobuf]
    ↓
Dashboard (confirma ejecución)
```

## 🚀 ORDEN DE ARRANQUE CORRECTO

### 1️⃣ **Terminal 1** - Firewall Agent (Primero - receptor)
```bash
# Validar configuración primero
python simple_firewall_agent.py simple_firewall_agent_config.json --test-config

# Arrancar en modo seguro (nuclear option OFF)
python simple_firewall_agent.py simple_firewall_agent_config.json
```
**Debe mostrar:**
- ✅ Puerto escucha: 5561 (configurado desde JSON)
- ✅ Puerto respuesta: 5560 (configurado desde JSON)  
- ✅ Nuclear option: FALSE (seguro)
- ✅ Dry run mode: TRUE (simulación)
- ✅ Display-only mode: SAFE

### 2️⃣ **Terminal 3** - ML Detector (Segundo - procesador)
```bash
# Validar configuración primero
python lightweight_ml_detector.py lightweight_ml_detector_config.json --test-config

# Arrancar detector ML
python lightweight_ml_detector.py lightweight_ml_detector_config.json
```
**Debe mostrar:**
- ✅ Input port: 5559 (recibe de promiscuous_agent)
- ✅ Output port: 5560 (envía al dashboard)
- ✅ ML modelo configurado desde JSON
- ✅ GeoIP path configurado

### 3️⃣ **Terminal 4** - Dashboard (Tercero - interfaz)
```bash
# Validar configuración primero  
python real_zmq_dashboard_with_firewall.py dashboard_config.json --test-config

# Arrancar dashboard
python real_zmq_dashboard_with_firewall.py dashboard_config.json
```
**Debe mostrar:**
- ✅ HTTP: 127.0.0.1:8000 (configurado desde JSON)
- ✅ ZMQ Input: 5560 (recibe eventos ML)
- ✅ ZMQ Output: 5561 (envía comandos firewall)
- ✅ Threat rules cargadas desde JSON
- ✅ Firewall integration enabled

### 4️⃣ **Terminal 2** - Promiscuous Agent (Último - generador)
```bash
# Validar configuración primero
python promiscuous_agent.py enhanced_agent_config.json --test-config

# Arrancar con privilegios (requiere sudo)
sudo python promiscuous_agent.py enhanced_agent_config.json
```
**Debe mostrar:**
- ✅ ZMQ Port: 5559 (configurado desde JSON)
- ✅ GPS Detection: Enabled (desde JSON)
- ✅ GeoIP: Enabled/Disabled (según configuración)
- ✅ Handshake: Enabled (para identificar nodos)
- ✅ Timestamp: CORREGIDO

## 🔍 VERIFICACIONES POST-ARRANQUE

### ✅ Dashboard Web (http://127.0.0.1:8000)
- **Indicadores de estado:** Todos verdes
- **Config Status:** Verde (configuración JSON cargada)
- **Eventos llegando:** Con badges JSON, PB, GPS, HS
- **Nodos registrados:** >= 1 (promiscuous agent)
- **Threat rules:** Cargadas desde JSON
- **Comandos firewall:** Pendientes y logs disponibles

### ✅ APIs de verificación:
```bash
# Health check completo
curl http://127.0.0.1:8000/health

# Estadísticas del sistema  
curl http://127.0.0.1:8000/api/stats

# Eventos GPS
curl http://127.0.0.1:8000/api/events/gps

# Log de comandos firewall
curl http://127.0.0.1:8000/api/firewall/log

# Comandos pendientes
curl http://127.0.0.1:8000/api/firewall/pending
```

## ⚙️ PERSONALIZACIÓN DE CONFIGURACIÓN

### 🔥 Para activar modo "NUCLEAR" en firewall:
Editar `simple_firewall_agent_config.json`:
```json
{
  "firewall": {
    "enable_firewall_modifications": true,
    "nuclear_option": {
      "enabled": true,
      "description": "PELIGRO: Permite aplicar cambios reales en el firewall del sistema"
    },
    "dry_run_mode": false
  }
}
```

### 🎯 Para ajustar umbrales de amenazas:
Editar `dashboard_config.json`:
```json
{
  "firewall_integration": {
    "threat_thresholds": {
      "high_risk_score": 0.7,
      "critical_risk_score": 0.85,
      "anomaly_threshold": 0.6,
      "auto_block_enabled": false
    }
  }
}
```

### 📡 Para cambiar puertos:
Editar el JSON correspondiente:
```json
{
  "network": {
    "listen_port": 5559,  // Puerto de escucha
    "publish_port": 5560, // Puerto de envío
    "zmq_input_port": 5560,  // En dashboard
    "zmq_output_port": 5561  // En dashboard
  }
}
```

## 🐛 TROUBLESHOOTING

### ❌ "Protobuf no disponible"
```bash
pip install protobuf
```

### ❌ "ZMQ no disponible"  
```bash
pip install pyzmq
```

### ❌ "Error parsing protobuf"
- **Verificar:** Todos los archivos usan el timestamp corregido (segundos Unix)
- **Verificar:** Misma versión de protobuf en todos los componentes

### ❌ "Permission denied" (promiscuous_agent)
```bash
sudo python promiscuous_agent.py enhanced_agent_config.json
```

### ❌ "Puerto ocupado"
- **Dashboard:** Cambiará automáticamente al puerto +1
- **Otros:** Editar configuración JSON

### ❌ "No hay eventos en dashboard"
1. Verificar que promiscuous_agent esté enviando (Terminal 2)
2. Verificar que ML detector esté procesando (Terminal 3)  
3. Verificar logs en archivos configurados

### ❌ "Comandos firewall no llegan"
1. Verificar firewall_agent escuchando puerto 5561
2. Verificar dashboard enviando a puerto 5561
3. Verificar protobuf compatible en ambos extremos

## 🎉 ÉXITO - Sistema Operativo

### ✅ Cuando todo funciona verás:
- **Terminal 1:** Eventos PROTOBUF recibidos y simulados
- **Terminal 2:** Paquetes capturados y enviados con GPS
- **Terminal 3:** Eventos ML enriquecidos procesados  
- **Terminal 4:** Dashboard con eventos en tiempo real
- **Web Browser:** Mapa con eventos georeferenciales
- **Comandos:** Firewall commands en modo dry-run seguro

### ✅ Características funcionando:
- 🔥 **Firewall agent** recibe comandos protobuf y los simula (seguro)
- 🤖 **ML detector** entrena modelos y detecta anomalías
- 🗺️ **Dashboard** muestra eventos en mapa con geolocalización
- 📡 **Promiscuous agent** captura tráfico con detección GPS
- ⚙️ **Configuración JSON** controla todos los parámetros
- 🛡️ **Modo seguro** por defecto (dry_run=true, nuclear=false)
- 📊 **Estadísticas** completas en todos los componentes
- 🔔 **Alertas** configurables por tipo de amenaza
- 🤝 **Handshakes** automáticos para identificar nodos

## 📚 PRÓXIMOS PASOS

1. **Probar el sistema** en modo seguro
2. **Verificar detección** GPS y geolocalización  
3. **Configurar threat rules** específicas
4. **Ajustar umbrales** ML según tu entorno
5. **Configurar GeoIP** database si está disponible
6. **Solo cuando estés seguro:** activar modo nuclear

---

**🎯 El sistema está listo para su primer arranque con configuración JSON completa y modo seguro por defecto.**