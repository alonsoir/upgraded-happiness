# 🛡️ Upgraded Happiness - Advanced Network Security & ML Detection System

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![ML Pipeline](https://img.shields.io/badge/ML-Pipeline-brightgreen.svg)]()
[![Network Security](https://img.shields.io/badge/Network-Security-red.svg)]()
[![Real-time Detection](https://img.shields.io/badge/Detection-Real--time-orange.svg)]()

## 🎯 Misión del Proyecto

**Upgraded Happiness** es un sistema avanzado de detección de amenazas de red que combina técnicas de Machine Learning, análisis de tráfico en tiempo real y capacidades de firewall inteligente para crear una defensa multicapa contra amenazas de red.
![pantallazo1.png](pantallazos/pantallazo1.png)
![pantallazo2.png](pantallazos/pantallazo2.png)
![pantallazo3.png](pantallazos/pantallazo3.png)
![pantallazo4.png](pantallazos/pantallazo4.png)
![pantallazo5.png](pantallazos/pantallazo5.png)
![pantallazo6.png](pantallazos/pantallazo6.png)

## 🏆 **HITO ALCANZADO - Q3 2025**

✅ **Sistema de Detección Tricapa Operativo**: Hemos logrado entrenar exitosamente tres modelos especializados que trabajhan en conjunto:

1. **🚨 Detector de Ataques**: Identifica si hay un ataque o no en el tráfico
2. **🌐 Detector de Tráfico Web Normal**: Reconoce patrones legítimos de navegación web
3. **🏢 Detector de Tráfico Interno Normal**: Distingue comunicaciones internas legítimas

✅ **Híbrido Sniffer/ML-Detector**: Sistema integrado que escanea la red, extrae features y las procesa a través de los tres modelos para una detección precisa.

✅ **Superación de Datasets Corruptos**: Después de encontrar múltiples datasets oficiales con valores desviados incompatibles con Scapy, aplicamos método científico riguroso para crear nuestro propio pipeline de datos confiable.

## 🏗️ Arquitectura del Sistema

### 🧠 Componentes Core

#### **Sistema de Detección ML**
- `lightweight_ml_detector.py` - Motor principal de inferencia ML
- `rf_production_sniffer_compatible.joblib` - Modelo de detección de ataques (10.1MB)
- `web_normal_detector.joblib` - Modelo de tráfico web normal (2.5MB)  
- `internal_normal_detector.joblib` - Modelo de tráfico interno (2.3MB)

#### **Captura y Análisis de Red**
- `fixed_service_sniffer.py` - Sniffer de red optimizado
- `enhanced_network_feature_extractor.py` - Extractor de características de red
- `promiscuous_agent.py` / `promiscuous_agent_v2.py` - Agentes de captura promiscua

#### **Enriquecimiento y Geolocalización**
- `geoip_enricher.py` - Enriquecimiento con datos geográficos (75.6KB, 1185 líneas)
- Soporte para GeoLite2 con actualizaciones automáticas

#### **Firewall Inteligente**
- `simple_firewall_agent.py` - Agente de firewall con ML integration (51.8KB, 950 líneas)
- Reglas dinámicas basadas en predicciones ML

#### **Dashboard y Monitorización**
- `real_zmq_dashboard_with_firewall.py` - Dashboard principal (154.6KB, 2625 líneas)
- Comunicación ZeroMQ entre componentes
- Interfaz web para monitorización en tiempo real

### 🤖 Pipeline de Machine Learning

#### **Entrenamiento de Modelos**
- `advanced_trainer.py` / `advanced_trainer_fixed.py` - Entrenadores principales
- `sniffer_compatible_retrainer.py` - Re-entrenamiento con datos de sniffer
- `cicids_retrainer.py` - Entrenamiento especializado con CICIDS 2017
- `validate_ensemble_models.py` - Validación de modelos ensemble

#### **Procesamiento de Datos**
- `cicids_traditional_processor.py` - Procesador de CICIDS 2017 limpio
- `extract_required_features.py` - Extracción de features críticas
- `enhanced_network_feature_extractor.py` - Extractor compatible con Scapy

#### **Generación de Datos de Entrenamiento**
- `ml_sniffer.py` - Sniffer especializado para ML
- `fixed_ml_network_sniffer.py` - Sniffer corregido para features
- `traffic_generator.py` - Generador de tráfico para testing

## 🚀 Inicio Rápido

### Prerrequisitos
```bash
# Python 3.8+ y dependencias
pip install -r requirements.txt

# Permisos para captura de red
sudo setcap cap_net_raw+ep $(which python3)
```

### Configuración Inicial
```bash
# Crear configuraciones necesarias
make setup

# Verificar dependencias
make check-deps

# Descargar base de datos GeoIP
make check-geoip
```

### Ejecución del Sistema Completo
```bash
# Modo desarrollo - todos los componentes
make dev-start

# Solo componentes core
make start-core

# Con componentes avanzados
make start-advanced
```

### Acceso al Dashboard
- **Dashboard Principal**: http://localhost:8050
- **Estado del Sistema**: `make status`
- **Logs en Tiempo Real**: `make logs-tail`

## 📊 Modelos de Machine Learning

### 🏆 Modelos en Producción

| Modelo | Propósito | Tamaño | Estado |
|--------|-----------|---------|---------|
| `rf_production_sniffer_compatible.joblib` | Detección de ataques | 10.1MB | ✅ PRODUCCIÓN |
| `web_normal_detector.joblib` | Tráfico web normal | 2.5MB | ✅ PRODUCCIÓN |
| `internal_normal_detector.joblib` | Tráfico interno normal | 2.3MB | ✅ PRODUCCIÓN |

### 📈 Datasets Utilizados

- **CICIDS 2017** (Procesado): 1044.1MB - Dataset principal limpio y verificado
- **CSE-CIC-IDS2018**: 4051.9MB - Dataset complementario
- **TON-IoT**: 4050.9MB - Datos de IoT para casos especializados

## ⚙️ Configuración

### Archivos de Configuración Principales
- `config/lightweight_ml_detector_config.json` - Configuración del detector ML
- `config/dashboard_config.json` - Configuración del dashboard
- `config/simple_firewall_agent_config.json` - Reglas de firewall
- `config/geoip_enricher_config.json` - Configuración de geolocalización

### Variables de Entorno
```bash
export GEOIP_DB_PATH="./GeoLite2-City.mmdb"
export ML_MODEL_PATH="./models/"
export LOG_LEVEL="INFO"
```

## 🔧 Comandos Make Principales

### Operación
```bash
make start          # Iniciar sistema completo
make stop           # Parar todos los componentes
make restart        # Reiniciar sistema
make status         # Estado detallado
```

### Desarrollo
```bash
make dev-start      # Modo desarrollo
make debug          # Modo debug con logs
make test           # Ejecutar tests
make clean          # Limpiar archivos temporales
```

### Monitorización
```bash
make monitor        # Monitor en tiempo real
make logs           # Ver logs
make logs-tail      # Seguir logs en vivo
```

## 📁 Estructura del Proyecto

```
upgraded-happiness/
├── core/                          # Componentes del sistema principal
│   ├── lightweight_ml_detector.py
│   ├── simple_firewall_agent.py
│   └── geoip_enricher.py
├── ml_pipeline/                   # Pipeline de Machine Learning
│   ├── advanced_trainer.py
│   ├── model_analyzer_sniffer.py
│   └── validate_ensemble_models.py
├── data_pipeline/                 # Procesamiento de datasets
│   ├── cicids_traditional_processor.py
│   └── extract_required_features.py
├── models/                        # Modelos entrenados
│   ├── production/
│   └── archive/
├── config/                        # Configuraciones
├── logs/                          # Archivos de log
└── docs/                          # Documentación
```

## 🧪 Testing y Validación

### Tests Automatizados
```bash
# Ejecutar suite completa de tests
make test

# Validar modelos específicos
python validate_ensemble_models.py

# Benchmark de performance
make benchmark
```

### Validación Manual
```bash
# Verificar funcionamiento del sistema
make verify

# Estado detallado de componentes
make status-detailed

# Análisis de tráfico en vivo
python ml_sniffer.py --live-analysis
```

## 📈 Monitorización y Métricas

### Dashboard Web
El dashboard principal proporciona:
- **Estado en tiempo real** de todos los componentes
- **Métricas de detección** ML
- **Visualización de tráfico** de red
- **Alertas de seguridad** automáticas
- **Logs centralizados**

### Métricas Clave
- **Precisión de detección**: >95% en datasets de test
- **Latencia de procesamiento**: <100ms por paquete
- **Throughput**: 1000+ paquetes/segundo
- **False positivos**: <2%

## 🔬 Investigación y Desarrollo

### Metodología Científica Aplicada
1. **Análisis de Datasets**: Identificación de corrupción en datasets oficiales
2. **Validación Cruzada**: Múltiples sources para verificar ground truth  
3. **Feature Engineering**: Extracción de características compatibles con Scapy
4. **Model Ensemble**: Combinación de múltiples detectores especializados

### Lecciones Aprendidas
- **Datasets Oficiales**: Muchos contienen valores incompatibles con herramientas reales
- **Feature Consistency**: Crítico mantener consistency entre training y inference
- **Model Specialization**: Mejor rendimiento con modelos especializados que generalistas
- **Real-time Constraints**: Balance entre accuracy y latencia de respuesta

## 🤝 Contribución

### Desarrollo
1. Fork del repositorio
2. Crear feature branch: `git checkout -b feature/nueva-funcionalidad`
3. Commit de cambios: `git commit -am 'Agregar nueva funcionalidad'`
4. Push a branch: `git push origin feature/nueva-funcionalidad`
5. Crear Pull Request

### Estándares de Código
- **Python**: PEP 8 compliance
- **Documentación**: Docstrings para todas las funciones
- **Testing**: Unit tests para nuevas funcionalidades
- **Logging**: Uso consistente del sistema de logging

## 📚 Documentación Adicional

- [`ROADMAP.md`](ROADMAP.md) - Hoja de ruta del proyecto
- [`refactor_plan.md`](refactor_plan.md) - Plan de refactorización
- `docs/` - Documentación técnica detallada
- `config/` - Ejemplos de configuración

## 🐛 Issues Conocidos

### En Desarrollo Activo
- Optimización de memoria para datasets grandes
- Mejora de UI del dashboard
- Integración con sistemas SIEM externos

### Solicitud de Features
- Soporte para IPv6 completo
- Detección de amenazas avanzadas (APT)
- API REST para integración externa
- Exportación de alertas a formatos estándar

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo LICENSE para detalles.

## 👥 Equipo

- **Alonso** - Lead Developer & ML Engineer
- **Contributors** - Ver [contributors](../../contributors)

## 🙏 Agradecimientos

- Comunidad de seguridad de red por datasets y herramientas
- Proyectos open source que hacen posible este trabajo
- Investigadores en ML aplicado a ciberseguridad

---

**⭐ Si este proyecto te resulta útil, considera darle una estrella!**

*Última actualización: Agosto 2025 - Sistema tricapa operativo*