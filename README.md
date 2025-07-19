# 🧬 Sistema Autoinmune Digital v2.0

## 🎯 **Visión General**

El Sistema Autoinmune Digital es una plataforma de seguridad distribuida que emula el comportamiento del sistema inmunológico humano para detectar, analizar y responder automáticamente a amenazas de red en tiempo real.

### **🔥 Características Principales**

- **⚡ Procesamiento en Tiempo Real**: Pipeline distribuido con latencia < 25ms
- **🧠 Machine Learning Adaptativo**: Detección de anomalías con aprendizaje continuo
- **🔐 Cifrado Empresarial**: AES-256-GCM con rotación automática de claves
- **🌐 Arquitectura Distribuida**: Escalamiento horizontal y vertical
- **🗣️ Interfaz Conversacional**: RAG para consultas en lenguaje natural
- **📊 Observabilidad Completa**: Métricas, dashboards y alertas en tiempo real
- **🛡️ Respuesta Automática**: Integración con firewalls distribuidos
- **🔄 Auto-optimización**: Sistema que se mejora continuamente

## 🏗️ **Arquitectura del Sistema**

<img width="1575" height="766" alt="Captura de pantalla 2025-07-18 a las 13 06 34" src="https://github.com/user-attachments/assets/705e93cd-cbe3-4876-a935-232e00729818" />


```
📡 CAPTURA DE TRÁFICO
├── promiscuous_agent.py → Captura promiscua de paquetes (Puerto 5559)
├── geoip_enricher.py → Enriquecimiento geográfico (5559→5560)
└── lightweight_ml_detector.py → Detección ML (5560→5561)

📊 ORCHESTRACIÓN Y DECISIÓN
├── real_zmq_dashboard_with_firewall.py → Dashboard central (5561→5562)
├── neural_trainer_collector.py → Entrenamiento continuo
└── autoinmune_rag_engine.py → Interfaz conversacional

🛡️ RESPUESTA Y ACCIÓN
├── simple_firewall_agent.py → Agentes de firewall distribuidos (Puerto 5562)
├── etcd → Coordinación de cluster
└── monitoring → Métricas y alertas
```

## 🚀 **Estado Actual del Proyecto**

### **✅ FUNCIONALIDADES COMPLETADAS (Q3 2025)**
- ✅ **Pipeline distribuido básico**: Flujo completo promiscuous → geoip → ml → dashboard → firewall
- ✅ **Comunicación ZeroMQ/Protobuf**: Arquitectura distribuida funcionando
- ✅ **Captura de tráfico**: Agente promiscuo con Scapy operativo
- ✅ **Enriquecimiento GeoIP**: Localización geográfica de IPs
- ✅ **ML Detection básico**: Detección de anomalías con múltiples algoritmos
- ✅ **Dashboard web**: Interfaz visual en tiempo real
- ✅ **Sistema de configuración**: JSON declarativo para todos los componentes
- ✅ **Cifrado empresarial**: SecureEnvelope AES-256-GCM
- ✅ **Makefile avanzado**: Gestión completa del ciclo de vida

### **🔄 EN DESARROLLO ACTIVO**
- 🔄 **Dashboard-Firewall Integration**: Botones de bloqueo en eventos
- 🔄 **Clasificación de eventos**: Mejora de la precisión ML
- 🔄 **Auto-respuesta**: Firewall automático en eventos críticos
- 🔄 **RAG Engine**: Interfaz conversacional con Claude
- 🔄 **Neural Trainer**: Aprendizaje continuo optimizado

### **📋 PRÓXIMOS HITOS**
- 🎯 **Dashboard interactivo**: Click-to-block en eventos de alto riesgo
- 🎯 **Threat intelligence**: Feeds externos de amenazas
- 🎯 **Advanced correlation**: Análisis de patrones complejos
- 🎯 **Performance tuning**: Optimización para Intel i9

## 🚀 **Instalación y Configuración**

### **Requisitos**
- Python 3.13+
- ZeroMQ 4.3+
- etcd 3.5+
- 16GB RAM (recomendado)
- CPU multi-core (Intel i9 optimizado)
- Permisos sudo (para iptables)

### **Quick Start**
```bash
git clone https://github.com/alonsoir/upgraded-happiness.git
cd upgraded-happiness
git checkout feature/claude-integration

# Setup completo automático
make quick

# O paso a paso
make setup
make install
make setup-perms
make start
```

### **URLs del Sistema**
- **Dashboard Principal**: http://localhost:8000
- **RAG Engine**: http://localhost:8090/chat (próximamente)
- **Métricas**: http://localhost:8000/metrics
- **Health Check**: http://localhost:8000/health

## 🔧 **Componentes Principales**

### **📡 Promiscuous Agent**
```bash
sudo python promiscuous_agent.py enhanced_agent_config.json
```
**Estado**: ✅ Operativo
- Captura selectiva de paquetes con Scapy
- Filtrado BPF a nivel kernel
- Envío vía ZeroMQ puerto 5559
- Protocolos: TCP, UDP, ICMP

### **🌍 GeoIP Enricher** 
```bash
python geoip_enricher.py geoip_enricher_config.json
```
**Estado**: ✅ Operativo
- Recibe de puerto 5559, envía a 5560
- Cache LRU con alta eficiencia
- Fallback a ip-api.com
- Detección de países de alto riesgo

### **🤖 ML Detector**
```bash
python lightweight_ml_detector.py lightweight_ml_detector_config.json
```
**Estado**: ✅ Operativo (refinando)
- Recibe de puerto 5560, envía a 5561
- Isolation Forest + algoritmos adicionales
- Latencia objetivo < 15ms
- **⚠️ Mejorando clasificación de eventos**

### **📊 Dashboard Central**
```bash
python real_zmq_dashboard_with_firewall.py dashboard_config.json
```
**Estado**: 🔄 En desarrollo
- Recibe de puerto 5561, controla 5562
- Interfaz web responsive
- **⚠️ Integrando botones de bloqueo**
- **⚠️ Mejorando interacción con firewall**

### **🛡️ Firewall Agents**
```bash
python simple_firewall_agent.py firewall_agent_config.json
```
**Estado**: ✅ Básico (mejorando integración)
- Escucha en puerto 5562
- Aplicación de reglas iptables
- **⚠️ Integrando con dashboard**

### **🧠 Neural Trainer** (Próximo)
```bash
python neural_trainer_collector.py neural_trainer_config.json
```
**Estado**: 🎯 Planificado
- Entrenamiento incremental
- Distribución vía etcd
- A/B testing de modelos

### **🗣️ RAG Engine** (Próximo)
```bash
python autoinmune_rag_engine.py rag_engine_config.json
```
**Estado**: 🎯 Arquitectura definida
- **TimescaleDB + pgvector**: Series temporales + embeddings vectoriales
- **Dual Interface**: Natural language (humanos) + Function tools (IAs)
- **Stored Procedures**: Queries ultra-optimizadas en PostgreSQL
- **Real-time Updates**: Pipeline ZeroMQ → Vector DB en tiempo real
- **Multi-tier Storage**: HOT (RAM) + WARM (horas) + COLD (días)

## 🧪 **Testing y Benchmarking**

### **📊 Métricas Críticas de Performance**
```python
# Pipeline end-to-end
pipeline_latency_p95 < 25ms     # Event capture → dashboard
firewall_response_p95 < 50ms    # Event capture → firewall response
rag_query_response_p95 < 100ms  # RAG query response time
vector_search_p95 < 10ms        # Vector similarity search

# Throughput targets
sustained_events_per_sec >= 1000
concurrent_rag_queries >= 50
vector_db_writes_per_sec >= 500

# Security effectiveness
ml_precision >= 95%             # TP / (TP + FP)
ml_recall >= 90%               # TP / (TP + FN)
false_positive_rate < 5%       # Critical threshold
mean_time_to_detection < 30s   # Critical response time
```

### **🔥 Chaos Engineering**
```python
# Automated resilience testing
- Random component kills (every 5-15 minutes)
- Network partition simulation (iptables rules)
- Resource exhaustion (CPU, memory, disk)
- ZeroMQ buffer overflow scenarios
- etcd cluster failure recovery
- Extreme load spikes (10x normal traffic)
```

### **⚡ Load Testing Stack**
```bash
# Locust-based synthetic traffic
locust --headless -f attack_simulator.py \
       --users 1000 --spawn-rate 10 \
       --host http://localhost:8000

# Attack pattern simulation
- SSH brute force campaigns
- Port scanning activities  
- DDoS traffic simulation
- Botnet C2 communication
- Advanced persistent threats (APT)
```

### **📈 ZeroMQ Buffer Monitoring**
```python
# Real-time buffer health monitoring
zmq_buffer_usage_threshold = 80%  # Warning level
zmq_buffer_critical = 90%         # Backpressure activation

# Backpressure strategies
- Priority-based event dropping
- Batch processing optimization
- Emergency operator notification
- Automatic component scaling
```

## 🔐 **Sistema de Cifrado**

### **SecureEnvelope - Cifrado Empresarial**

```python
from crypto_utils import SecureEnvelope

encryption_config = {
    "enabled": True,
    "algorithm": "AES-256-GCM",
    "rotation_interval_seconds": 3600,
    "entropy_sources": ["pid", "boot_time", "random_bytes"],
    "aad_includes": ["node_id", "component_name"]
}

envelope = SecureEnvelope(encryption_config)
ciphertext = envelope.encrypt(protobuf_bytes)
plaintext = envelope.decrypt(ciphertext)
```

## 📊 **Comandos de Gestión**

### **Control del Sistema**
```bash
# Inicio completo
make start

# Estado del sistema
make status

# Monitorización
make monitor

# Parada controlada
make stop

# Parada nuclear (emergencia) funciona mejor que stop.
make stop-nuclear

# Reinicio completo
make restart

# Verificación de integridad
make verify

# Dashboard web
make show-dashboard
```

### **Debugging y Logs**
```bash
# Ver logs de todos los componentes
make logs

# Verificar configuración GeoIP
make check-geoip

# Setup de permisos
make setup-perms

# Limpiar y reinstalar
make clean && make quick
```

## 🎯 **Issues Conocidos y Roadmap**

### **🚨 Issues Críticos (En resolución)**
1. **Dashboard-Firewall Integration**
   - Los botones de bloqueo no aparecen en eventos clickados
   - La comunicación dashboard→firewall necesita refinamiento
   - **Próximo sprint**: Implementar click-to-block UI

2. **Clasificación de Eventos ML**
   - Los algoritmos necesitan ajuste fino
   - False positives/negatives en clasificación
   - **Próximo sprint**: Tuning de hiperparámetros

3. **Auto-respuesta Firewall**
   - Integración automática dashboard→firewall en desarrollo
   - **Próximo sprint**: Respuesta automática a eventos críticos

### **🔮 Roadmap Detallado**

#### **Q4 2025 - Sprint Actual**
- 🔄 **[EN PROGRESO]** Click-to-block en dashboard
- 🔄 **[EN PROGRESO]** ML classification tuning
- 🎯 **[PLANIFICADO]** Auto-respuesta firewall
- 🎯 **[PLANIFICADO]** RAG Engine con TimescaleDB + pgvector
- 🎯 **[PLANIFICADO]** Neural trainer inicial
- 🎯 **[PLANIFICADO]** Chaos engineering automation
- 🎯 **[PLANIFICADO]** Load testing con Locust

#### **Q1 2026 - Advanced Features**
- 🔮 **RAG Multi-tier Architecture**: HOT/WARM/COLD storage optimization
- 🔮 **Dual Interface RAG**: Natural language + Function tools APIs
- 🔮 **Auto-scaling inteligente**: Basado en métricas ZeroMQ
- 🔮 **Threat intelligence feeds**: Integración con feeds externos
- 🔮 **Advanced correlation engine**: Stored procedures optimizados
- 🔮 **Multi-region deployment**: Arquitectura distribuida geográficamente
- 🔮 **Comprehensive benchmarking**: Suite completa de performance tests

#### **Q2 2026 - AI Enhancement**
- 🔮 **Claude-powered threat hunting**: RAG conversacional avanzado
- 🔮 **IA-to-IA optimized protocols**: APIs ultra-eficientes para IAs
- 🔮 **Predictive threat modeling**: ML predictivo con series temporales
- 🔮 **Self-healing infrastructure**: Auto-recovery con etcd
- 🔮 **Real-time vector updates**: Pipeline streaming a vector DB
- 🔮 **Conversational security analysis**: Interface natural completa

#### **Q3 2026 - Next-Gen**
- 🔮 **Quantum-ready encryption**: Preparación post-cuántica
- 🔮 **Edge computing support**: Arquitectura híbrida edge/cloud
- 🔮 **Zero-trust architecture**: Integración completa zero-trust
- 🔮 **Autonomous security operations**: Sistema completamente autónomo
- 🔮 **Production-grade benchmarks**: Métricas para entornos críticos
- 🔮 **Global threat correlation**: Correlación inter-organizacional

## 📈 **Métricas Actuales**

### **Performance Baseline (Intel i9)**
```
Component               Estado    CPU%    Memory    Latencia    Throughput
promiscuous_agent       ✅        0.4%    108MB     0.2ms       Variable
geoip_enricher         ✅       56.9%     22MB     0.1ms       1.8/s
lightweight_ml_detector ⚠️       55.6%    146MB    14.7ms      1.8/s (tuning)
dashboard              🔄       25.0%    512MB     5.0ms       1000/s (mejorando)
firewall_agent         ✅        5.0%     32MB     1.0ms       N/A
```

### **Objetivos de Performance**
- **Pipeline Latency**: < 25ms (P95) 
- **Throughput**: 1000+ eventos/segundo ✅
- **CPU Usage**: < 70% por componente ✅
- **Memory Usage**: < 2GB por componente ✅
- **False Positive Rate**: < 5% (🔄 optimizando)

## 🔧 **Desarrollo y Contribución**

### **Branch Strategy**
- **main**: Producción estable
- **feature/claude-integration**: Desarrollo activo ⭐
- **feature/dashboard-improvements**: Dashboard enhancements
- **feature/ml-tuning**: ML algorithm improvements

### **Testing**
```bash
# Unit tests
python -m pytest tests/

# Integration tests  
python -m pytest tests/integration/

# Performance tests con Locust
python -m pytest tests/performance/
locust -f tests/load_testing/attack_simulator.py

# Chaos engineering
python tests/chaos/chaos_monkey.py --duration 1h

# ZeroMQ buffer stress testing
python tests/stress/zmq_buffer_overflow.py

# RAG Engine benchmarks
python tests/benchmarks/rag_performance.py
python tests/benchmarks/vector_db_latency.py

# End-to-end pipeline testing
python tests/e2e/full_pipeline_test.py --load 10x
```

### **Debugging Workflow**
```bash
# 1. Verificar sistema
make verify

# 2. Iniciar con logs
make start

# 3. Monitorizar en tiempo real
make monitor

# 4. Verificar logs específicos
tail -f logs/dashboard.log | grep ERROR

# 5. Debug componente específico
python -c "import dashboard; dashboard.debug_mode()"
```

## 🎯 **Casos de Uso**

### **1. Detección de Amenazas (Funcionando)**
```
Sistema: Detecta SSH brute force desde 192.168.1.100
Dashboard: Muestra evento de alto riesgo
Usuario: Click para bloquear (🔄 implementando)
Firewall: Aplica regla automáticamente
```

### **2. Análisis Geográfico (Funcionando)**
```
Sistema: IP desde China intenta conexión
GeoIP: Enriquece con ubicación y ASN
ML: Clasifica según patrones históricos
Dashboard: Visualiza en mapa tiempo real
```

### **3. Consulta RAG (Próximamente)**
```
Usuario: "¿Qué amenazas hemos visto desde China hoy?"
RAG: "Detectamos 47 eventos desde China: 23 SSH brute force, 
     15 port scanning, 9 eventos de alto riesgo..."
```

## 🗣️ **RAG Engine Arquitectura**

### **Estrategia TimescaleDB + pgvector**
```sql
-- Series temporales + embeddings vectoriales
CREATE TABLE security_events (
    time TIMESTAMPTZ NOT NULL,
    event_id UUID,
    event_vector vector(384),  -- pgvector embeddings
    source_ip INET,
    risk_score FLOAT,
    event_type TEXT,
    metadata JSONB
);

-- Hypertable para auto-partitioning temporal
SELECT create_hypertable('security_events', 'time');
```

### **Dual Interface Design**
```python
# Humanos: Lenguaje natural
Usuario: "Bloquea todas las IPs chinas que hayan hecho brute force SSH"
RAG: → Function tool → stored_procedure → firewall_command

# IAs: Function tools optimizados  
{
  "function": "rag_security_query",
  "params": {
    "query_vector": [0.1, 0.2, ...],
    "timeframe_minutes": 60,
    "similarity_threshold": 0.8
  }
}
```

### **Multi-tier Storage Strategy**
```
┌─────────────────┐
│ HOT CACHE       │ ← Últimos 15min (RAM, sin embeddings)
│ (búsqueda directa)│ ← Latencia: <1ms
└─────────────────┘
┌─────────────────┐  
│ WARM TIER       │ ← 1-24h (pgvector, batch updates)
│ (vector search) │ ← Latencia: <10ms
└─────────────────┘
┌─────────────────┐
│ COLD TIER       │ ← >24h (compressed, historical)
│ (analytics)     │ ← Latencia: <100ms
└─────────────────┘
```

### **Real-time Pipeline Integration**
```
Events → ZeroMQ → RAG Topic → TimescaleDB
   ↓
Vector embeddings → Batch processor → pgvector
   ↓
Query engine → Multi-tier search → Results
```

## 📞 **Soporte y Contribución**

### **Canal de Desarrollo**
- **Repositorio**: https://github.com/alonsoir/upgraded-happiness
- **Branch Activa**: `feature/claude-integration`
- **Issues**: [GitHub Issues](https://github.com/alonsoir/upgraded-happiness/issues)
- **Discusiones**: [GitHub Discussions](https://github.com/alonsoir/upgraded-happiness/discussions)

### **Próximos PRs**
1. **Dashboard-Firewall Integration** (Próxima semana)
2. **ML Classification Tuning** (Sprint actual)
3. **RAG Engine + TimescaleDB Foundation** (Próximo sprint)
4. **Chaos Engineering Automation** (Próximo sprint)
5. **Load Testing con Locust** (Sprint actual)
6. **ZeroMQ Buffer Monitoring** (Próximo sprint)
7. **Neural Trainer Basic** (Mes actual)

### **Cómo Contribuir**
1. Fork del repositorio
2. Checkout de `main`
3. Crear branch: `git checkout -b feature/your-feature`
4. Commit: `git commit -m 'Add your feature'`
5. Push: `git push origin feature/your-feature`
6. Crear Pull Request a `main`

---

> **"Un sistema que no solo detecta amenazas, sino que aprende, se adapta y evoluciona como un organismo digital inteligente."** 🧬✨

> **Estado Actual**: 🚀 Pipeline distribuido funcionando → 🔄 Refinando integración → 🎯 Próximo: Cifrado/Compresion integrado con etcd, RAG + Auto-respuesta, crear imágenes Docker,
> crear templates JINJA2, crear mecanismo para hablar con las máquinas virtuales y los contenedores alojados, entrenamiento de mejores redes neuronales basado en datos reales y sintéticos,
> integrar esos entrenamientos para que sean recurrentes, más allá del que pueda ocurrir con los datos que entran al sistema, hay que evitar falsos positivos, tests de stress masivos,
> conseguir tracción. Entre medias, fases de refactorizacion para que no se vaya de madre. HELP! 

**Construido con ❤️ por el equipo de Upgraded Happiness**
