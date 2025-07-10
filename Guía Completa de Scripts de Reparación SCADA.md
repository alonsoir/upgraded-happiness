# 🚀 Guía Completa de Scripts de Reparación SCADA

## 📋 Scripts Disponibles

### 1. **`diagnostic_script.py`** - Diagnóstico Automático
**Propósito**: Analiza el estado completo del sistema y detecta problemas

```bash
# Diagnóstico básico con reporte legible
python diagnostic_script.py

# Diagnóstico en formato JSON para scripts
python diagnostic_script.py --json
```

**Qué verifica**:
- ✅ Procesos en ejecución (4/4 esperados)
- ✅ Puertos ZeroMQ abiertos (5559, 5560, 5561)
- ✅ Servicio de geolocalización
- ✅ Modelos ML disponibles
- ✅ API del dashboard funcionando
- ✅ Análisis de eventos en vivo

---

### 2. **`config_fixer.py`** - Reparador de Configuraciones
**Propósito**: Crea/repara configuraciones optimizadas para ML y firewall

```bash
# Reparar todas las configuraciones
python config_fixer.py
```

**Qué hace**:
- 🔧 Crea `lightweight_ml_detector_config.json` con 6 modelos ML
- 🔧 Crea `dashboard_config.json` con reglas de alto riesgo
- 🔧 Crea `enhanced_agent_config.json` optimizado
- 🔧 Genera scripts auxiliares (fallback, reentrenamiento)
- 📁 Crea directorios necesarios
- 💾 Backup de configuraciones existentes

---

### 3. **`retrain_models.py`** - Reentrenamiento de Modelos ML
**Propósito**: Entrena los 6 modelos ML requeridos

```bash
# Entrenamiento completo (producción)
python retrain_models.py --force

# Entrenamiento rápido (desarrollo/testing)
python retrain_models.py --force --quick

# Usar datos reales si están disponibles
python retrain_models.py --force --real-data
```

**Modelos que entrena**:
- 🌲 **IsolationForest** - Detección de anomalías no supervisada
- 🔮 **OneClassSVM** - Clasificación de una clase
- 📐 **EllipticEnvelope** - Detección de outliers gaussianos
- 🎯 **LocalOutlierFactor** - Anomalías locales
- 🌳 **RandomForest** - Clasificación supervisada
- 🚀 **XGBoost** - Gradient boosting (si disponible)

---

### 4. **`geolocation_fallback.py`** - Sistema de Geolocalización Robusto
**Propósito**: Resuelve coordenadas GPS con múltiples proveedores y fallbacks

```bash
# Test del servicio
python geolocation_fallback.py test

# Geolocalizar IP específica
python geolocation_fallback.py 8.8.8.8

# Uso desde Python
python -c "
from geolocation_fallback import GeolocatorManager
gm = GeolocatorManager()
print(gm.geolocate('1.1.1.1'))
"
```

**Proveedores incluidos**:
- 🌍 **ip-api.com** (150/min gratuito)
- 🌍 **ipapi.co** (100/día gratuito)
- 🌍 **freegeoip.app** (15k/hora gratuito)
- 🌍 **ipgeolocation.io** (1k/día gratuito)
- 📍 **Fallbacks locales** para IPs privadas/conocidas

---

### 5. **`quick_start.py`** - Inicio Rápido y Reparación Automática
**Propósito**: Script todo-en-uno para diagnóstico y reparación automática

```bash
# Modo automático - repara todo automáticamente
python quick_start.py --auto-fix

# Modo rápido (menos tiempo de entrenamiento)
python quick_start.py --auto-fix --quick

# Omitir reentrenamiento ML (más rápido)
python quick_start.py --auto-fix --skip-training

# Solo diagnóstico, mostrar instrucciones manuales
python quick_start.py
```

---

## 🎯 **Flujos de Trabajo Recomendados**

### ⚡ **Solución Rápida (5 minutos)**
```bash
# 1. Ejecutar quick start automático
python quick_start.py --auto-fix --quick --skip-training

# 2. Si falla, diagnóstico manual
python diagnostic_script.py
```

### 🔧 **Reparación Completa (15-30 minutos)**
```bash
# 1. Diagnóstico inicial
python diagnostic_script.py

# 2. Reparar configuraciones
python config_fixer.py

# 3. Reentrenar modelos ML
python retrain_models.py --force

# 4. Test geolocalización
python geolocation_fallback.py test

# 5. Reiniciar sistema
make stop-firewall && make run-firewall

# 6. Verificar reparación
python diagnostic_script.py
```

### 🔍 **Diagnóstico Específico de Problemas**

#### Eventos "unknown" masivos
```bash
# 1. Test geolocalización
python geolocation_fallback.py test

# 2. Verificar logs del agente
tail -f logs/agent.out | grep -i "unknown\|geolocat"

# 3. Reparar configuración del agente
python config_fixer.py

# 4. Reiniciar solo agente
pkill -f promiscuous_agent.py
python promiscuous_agent.py enhanced_agent_config.json &
```

#### Modelos ML no funcionando
```bash
# 1. Verificar modelos existentes
ls -la models/

# 2. Test de imports
python -c "import sklearn, xgboost; print('OK')"

# 3. Reentrenar forzando
python retrain_models.py --force

# 4. Verificar metadata
cat models/metadata_latest.json
```

#### Dashboard no interactivo
```bash
# 1. Verificar configuración dashboard
python config_fixer.py

# 2. Test API endpoints
curl http://localhost:8000/health
curl http://localhost:8000/api/stats

# 3. Verificar reglas de alto riesgo
python -c "
import json
with open('dashboard_config.json') as f:
    config = json.load(f)
print('Threat rules:', len(config['threat_rules']))
"
```

---

## 📊 **Interpretación de Resultados**

### Diagnóstico Saludable
```
📋 RESUMEN DIAGNÓSTICO SISTEMA SCADA
================================
⏱️  Duración: 12.3s
🏥 ESTADO GENERAL:
   System: ✅ BIEN
   Geolocation: ✅ BIEN  
   Ml_Models: ✅ BIEN
   Dashboard: ✅ BIEN

📊 ANÁLISIS DE EVENTOS:
   Total eventos analizados: 50
   Ratio eventos unknown: 5.2%
   Ratio coordenadas resueltas: 94.8%
   Risk score promedio: 0.234
   Risk score máximo: 0.876

✅ No hay acciones prioritarias requeridas
```

### Diagnóstico Problemático
```
🚨 ACCIONES PRIORITARIAS (3):
   1. [HIGH] Alto ratio de eventos unknown: 67.2%
      💡 Solución: Revisar servicio de geolocalización
      🔧 Comandos:
         python geolocation_fallback.py test
         
   2. [MEDIUM] Solo 2 modelos disponibles (esperados: 6)
      💡 Solución: Reentrenar modelos ML
      🔧 Comandos:
         python retrain_models.py --force
```

---

## ⚠️ **Troubleshooting Común**

### Error: "Scripts faltantes"
```bash
# Descargar scripts desde los artifacts de Claude
# O copiar desde esta conversación
```

### Error: "Permisos sudo"
```bash
# Configurar sudoers para captura de paquetes
sudo visudo
# Añadir: your_user ALL=(ALL) NOPASSWD: /usr/bin/tcpdump
```

### Error: "Puerto en uso"
```bash
# Verificar procesos usando puertos
netstat -tulpn | grep -E "(5559|5560|5561|8000)"

# Matar procesos conflictivos
pkill -f "python.*5560"
```

### Error: "XGBoost no disponible"
```bash
# Instalar XGBoost
pip install xgboost

# O continuar sin XGBoost (5/6 modelos)
```

---

## 🎯 **Métricas de Éxito**

Después de la reparación, deberías ver:

- ✅ **Eventos "unknown" < 10%**
- ✅ **6 modelos ML funcionando** (o 5 sin XGBoost)
- ✅ **Coordenadas GPS en > 90% eventos**
- ✅ **Risk scores variados (0.0-1.0)**
- ✅ **Eventos clickeables en dashboard**
- ✅ **Comandos firewall generándose**
- ✅ **API endpoints respondiendo**

---

## 🔄 **Mantenimiento Continuo**

### Monitoreo Automático
```bash
# Ejecutar diagnóstico diario
echo "0 6 * * * cd /path/to/upgraded-happiness && python diagnostic_script.py --json > logs/daily_health.json" | crontab -

# Alertas cuando problemas > 50%
watch -n 300 "python diagnostic_script.py --json | jq '.events_analysis.unknown_ratio' | awk '{if(\$1>0.5) print \"ALERT: Unknown ratio high\"}'"
```

### Reentrenamiento Periódico
```bash
# Reentrenar modelos semanalmente
echo "0 2 * * 0 cd /path/to/upgraded-happiness && python retrain_models.py --force --quick" | crontab -
```

---

## 📞 **Soporte**

Si los scripts no resuelven el problema:

1. **Generar reporte completo**:
   ```bash
   python diagnostic_script.py --json > debug_report.json
   python quick_start.py > debug_quickstart.log 2>&1
   ```

2. **Recopilar logs**:
   ```bash
   tar -czf debug_logs.tar.gz logs/ models/ *.json
   ```

3. **Información del sistema**:
   ```bash
   python --version
   pip list | grep -E "(sklearn|zmq|pandas|numpy|xgboost)"
   ```

---

🎉 **¡Tu sistema SCADA debería estar funcionando perfectamente después de seguir esta guía!**