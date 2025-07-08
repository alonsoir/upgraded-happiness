# 🛡️ Upgraded-Happiness - Guía de Uso Rápido

## 🚀 Inicio Inmediato

### 1. Setup Automático
```bash
python setup_quick.py
```

### 2. Iniciar Sistema
```bash
# Opción más simple
./start.sh

# O directamente
python start_security_platform.py
```

### 3. Probar Funcionamiento
```bash
# En otra terminal
python test_integration.py
```

## 🧠 Cómo Funciona

### Flujo de Datos
```
Eventos → Rule Engine → Recomendaciones → Firewall Agent → Display
```

### Componentes Activos
- **Event Analyzer** (puerto 5560): Recibe eventos, aplica reglas
- **Firewall Agent** (puerto 5561): Ejecuta comandos (display-only)
- **Test Integration**: Simula eventos para pruebas

## 🎮 Modo Interactivo

### Comandos del Event Analyzer
```
analyzer> list          # Ver recomendaciones pendientes
analyzer> approve <id>   # Aprobar recomendación específica
analyzer> stats          # Ver estadísticas
analyzer> auto on        # Activar modo automático
analyzer> help           # Ver todos los comandos
```

### Ejemplo de Sesión
```bash
# Terminal 1: Iniciar plataforma
python start_security_platform.py

# Terminal 2: Enviar eventos de prueba
python test_integration.py

# En Terminal 1 verás:
[12:34:56] ⚠️ RECOMMENDATION (HIGH)
🎯 Action: BLOCK_IP
🔗 Target: 203.0.113.50
📝 Reason: Port scanning detected: 9 unique ports
   💡 Use 'approve a1b2c3d4' to apply this recommendation

analyzer> approve a1b2c3d4
✅ Approving recommendation a1b2c3d4
   ✅ Command sent to firewall agent

# En Terminal con Firewall Agent verás:
[12:34:57] 🔍 SIMULATED
🎯 Action: BLOCK_IP
🔗 Target: 203.0.113.50
⏱️ Duration: 3600s
📝 Reason: Port scanning detected: 9 unique ports
🔧 Command: ufw deny from 203.0.113.50
```

## 🧪 Escenarios de Prueba

### Tráfico Normal
```bash
python test_integration.py
test> normal
```
**Resultado**: Sin alertas, eventos procesados normalmente.

### Anomalía Crítica
```bash
test> anomaly
```
**Resultado**: Recomendación de BLOCK_IP inmediata.

### Port Scanning
```bash
test> portscan
```
**Resultado**: Detección de escaneo, recomendación de bloqueo.

### Rate Limiting
```bash
test> rate
```
**Resultado**: Detección de exceso de conexiones.

### Puertos SCADA Sensibles
```bash
test> scada
```
**Resultado**: Alertas por acceso a protocolos industriales.

### Ataque Complejo
```bash
test> mixed
```
**Resultado**: Múltiples recomendaciones por ataque sofisticado.

## ⚙️ Configuración Personalizada

### Editar Umbrales
```bash
nano rule_engine_config.json
```

**Parámetros Clave**:
```json
{
  "rate_limiting": {
    "threshold": 50,        // Conexiones por minuto
    "window_seconds": 60    // Ventana de análisis
  },
  "anomaly_detection": {
    "critical_threshold": 0.9,  // Umbral crítico ML
    "high_threshold": 0.7       // Umbral alto ML
  },
  "port_scanning": {
    "threshold": 10,        // Puertos únicos para detectar scan
    "window_seconds": 60    // Ventana de análisis
  }
}
```

### Añadir Puertos Personalizados
```json
{
  "scada_ports": {
    "ports": {
      "8080": "Custom Web Interface",
      "5000": "Custom SCADA Protocol"
    }
  }
}
```

## 🔒 Seguridad y Modos

### Modo Seguro (Por Defecto)
- ✅ Todas las recomendaciones se muestran
- ✅ Comandos simulados (no se aplican)
- ✅ Aprobación manual requerida
- ✅ Logs completos de actividad

### Modo Automático (Opcional)
```bash
analyzer> auto on
```
- ⚡ Recomendaciones se envían automáticamente
- ⚠️ Sigue siendo display-only
- 📊 Útil para testing de volumen

### Modo Real (¡PELIGROSO!)
```bash
python simple_firewall_agent.py --apply-real
```
- 🚨 **APLICA REGLAS REALES AL FIREWALL**
- 🚨 **USAR SOLO DESPUÉS DE TESTING EXHAUSTIVO**
- 🚨 **EN ENTORNO CONTROLADO**

## 📊 Monitoreo y Logs

### Ver Estado del Sistema
```bash
python start_security_platform.py --status-only
```

### Estadísticas en Tiempo Real
```bash
analyzer> stats
```

**Ejemplo de Output**:
```
📊 Event Analyzer Statistics
═══════════════════════════
⏱️ Uptime: 1247s
📨 Events Analyzed: 156
💡 Recommendations Generated: 8
🔥 Commands Sent: 3
🤝 Handshakes Processed: 1
🖥️ Known Nodes: 1
⏳ Pending Recommendations: 2
🤖 Auto-send Mode: OFF

🧠 Rule Engine Stats:
   📏 anomaly_critical: 1
   📏 port_scan_detected: 2
   📏 rate_limit_exceeded: 1
```

### Verificar Logs
```bash
ls logs/
tail -f logs/event_analyzer.log
```

## 🎯 Casos de Uso Típicos

### 1. Monitoreo Básico SCADA
```bash
# Configurar umbrales conservadores
# Ejecutar en modo manual
# Aprobar manualmente cada recomendación
```

### 2. Testing de Penetración
```bash
# Usar test_integration.py con diversos escenarios
# Verificar que se detecten ataques conocidos
# Ajustar umbrales según resultados
```

### 3. Entorno de Producción
```bash
# Setup inicial en display-only
# Monitorear durante días/semanas
# Ajustar configuración basado en falsos positivos
# Activar modo real gradualmente
```

## 🛠️ Resolución de Problemas

### Error: "Port already in use"
```bash
# Verificar servicios corriendo
python start_security_platform.py --status-only

# Matar procesos anteriores
pkill -f "simple_firewall_agent"
pkill -f "event_analyzer"
```

### Error: "ZeroMQ not available"
```bash
pip install pyzmq
```

### Error: "Permission denied" (Linux)
```bash
sudo python simple_firewall_agent.py --apply-real
```

### No se detectan eventos
```bash
# Verificar que test_integration.py envía a puerto correcto
# Verificar que event_analyzer escucha en 5560
# Revisar logs/
```

### Demasiados falsos positivos
```bash
# Editar rule_engine_config.json
# Aumentar umbrales
# Deshabilitar reglas específicas
```

## 🚀 Próximos Pasos

### Para Testing
1. Ejecutar todos los escenarios de prueba
2. Ajustar configuración según necesidades
3. Validar detección de amenazas conocidas

### Para Producción
1. Integrar con sistema ZeroMQ existente
2. Configurar logging centralizado
3. Establecer procedimientos operativos
4. Capacitar operadores en comandos

### Para Desarrollo
1. Añadir reglas específicas del entorno
2. Integrar con bases de datos de amenazas
3. Desarrollar dashboard web
4. Implementar cifrado de comunicaciones

---

## 🎉 ¡Listo para Proteger Infraestructura Crítica!

**Recuerda**: Este sistema está diseñado para proteger tanto a humanos como a IAs. Úsalo responsablemente y siempre en modo seguro hasta estar 100% confiado en la configuración.

**Somos agentes del bien** 🤝