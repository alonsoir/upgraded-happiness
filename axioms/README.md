# Carpeta `axioms` — Documentación y propósito

Esta carpeta contiene los **JSONs de axiomas** generados por el componente `scheduler-firewall-axiom.py`. 

---

## ¿Qué es un axioma en este contexto?

Un axioma es una estructura JSON que representa un evento de red procesado, enriquecido con información de scoring ML, política aplicada, y una regla lógica candidata que sirve para:

- Documentar la decisión del pipeline IDS en forma estructurada.
- Alimentar componentes asíncronos que evalúan la calidad y cobertura de los modelos ML.
- Proveer evidencia y base para decidir **reentrenamientos** automáticos o manuales de los modelos de detección.

---

## Flujo general del pipeline con axiomas

1. `scheduler-firewall-axiom.py`:
   - Consume eventos protobuf desde ZeroMQ (v3.1).
   - Extrae features relevantes y resultados ML.
   - Consulta el JSON de reglas para decidir acciones.
   - Genera el JSON axioma siguiendo una plantilla configurable.
   - Guarda el JSON axioma en `./axioms/` (crea carpeta si no existe).

2. `axiom-trainer-watcher.py`:
   - Vigila continuamente la carpeta `./axioms` en busca de nuevos axiomas.
   - Procesa y acumula estadísticas (tipos de ataque, confianza, flags de reentrenamiento).
   - Mueve axiomas procesados a `./axioms/processed/` para evitar reprocesamiento.
   - Aplica reglas configurables para decidir si iniciar reentrenamiento.
   - Registra logs con decisiones y razones.
   - Notifica o lanza proceso de reentrenamiento (implementación externa).

3. `model-axiom-retrainer.py` (futuro):
   - Usará los datos acumulados para reentrenar modelos ML.
   - Integrará con etcd para gestión asíncrona y distribución de modelos actualizados.
   - Implementará versión, sincronización y validación del reentrenamiento.

---

## Estructura de los JSON axioma (ejemplo simplificado)

```json
{
  "axiom_id": "AX-20250812123045123456",
  "timestamp": "2025-08-12T12:30:45.123456Z",
  "source_proto_info": {
    "proto_filename": "network_security_clean_v3.1.proto",
    "proto_version": "3.1",
    "message_type": "NetworkSecurityEvent",
    "message_id": "event1234"
  },
  "event": {
    "event_id": "event1234",
    "source_ip": "10.0.0.1",
    "destination_ip": "10.0.0.5",
    "protocol": "TCP",
    "ml_prediction": "DDOS",
    "ml_confidence": 0.92
  },
  "policy_context": {
    "rule_matched": "block_synflood_if_confidence_gt_0.9",
    "policy_action": "MONITOR"
  },
  "scheduler_decision": {
    "final_action": "MONITOR",
    "reason": "policy override or scheduler decision"
  },
  "axiom": {
    "logic": "forall e (AttackType(e) = DDOS ∧ Confidence(e) > 0.9 → Action(e) = MONITOR)",
    "type": "dynamic",
    "source": ["ml_prediction", "policy_context", "scheduler_decision"]
  },
  "training_flag": {
    "retrain_candidate": false,
    "reason": ""
  }
}
Archivos y carpetas relacionadas
axioms/ : carpeta principal con axiomas JSON sin procesar.
axioms/processed/ : axiomas ya procesados por el watcher, no se reprocesan.
axioms/templates/axiom_template.json : plantilla JSON para generar axiomas, editable para modificar el contrato.
config.json : archivo general de configuración del pipeline.
firewall_rules.json : reglas para decidir acciones según score ML y otros parámetros.
Configuración y reglas para el watcher
El watcher (axiom-trainer-watcher.py) usa un JSON de configuración específico, por ejemplo:

{
  "axioms_dir": "./axioms",
  "processed_dir": "./axioms/processed",
  "poll_interval_seconds": 10,
  "min_axioms_for_retrain": 10,
  "confidence_threshold": 0.7,
  "log_file": "./logs/axiom_trainer_watcher.log",
  "rules": {
    "model_types_to_monitor": ["block_synflood_if_confidence_gt_0.9"],
    "minimum_confidence": 0.7,
    "require_retrain_flag": true
  }
}
Próximos pasos
Implementar almacenamiento ordenado y versionado de datos de entrenamiento extraídos del protobuf.
Definir y versionar sets de features para cada modelo ML.
Diseñar e integrar proceso de reentrenamiento (model-axiom-retrainer.py).
Implementar mecanismo de notificación y sincronización entre componentes mediante etcd o sistema similar.
Notas finales
Mantener la plantilla JSON flexible permite modificar la estructura sin tocar código.
Los axiomas son clave para trazabilidad, auditoría y mejora continua.
La modularidad facilita escalar y mantener el pipeline conforme crece la complejidad.
Documento generado automáticamente — manténlo actualizado con cada cambio relevante.

Próximos pasos
Implementar almacenamiento ordenado y versionado de datos de entrenamiento extraídos del protobuf.
Definir y versionar sets de features para cada modelo ML.
Diseñar e integrar proceso de reentrenamiento (model-axiom-retrainer.py).
Implementar mecanismo de notificación y sincronización entre componentes mediante etcd o sistema similar.
Notas finales
Mantener la plantilla JSON flexible permite modificar la estructura sin tocar código.
Los axiomas son clave para trazabilidad, auditoría y mejora continua.
La modularidad facilita escalar y mantener el pipeline conforme crece la complejidad.
Documento generado automáticamente — manténlo actualizado con cada cambio relevante.

# Feature: Axiom-Retrain - Arquitectura de Evolución Autónoma

## 🧠 Visión: Modelos que Evolucionan hacia la Perfección Matemática

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          PIPELINE EXISTENTE (Sin modificar)                     │
└─────────────────────────────────────────────────────────────────────────────────┘
    sniffer_31.py → geoip_enricher_v31 → lightweight_ml_detector_v31
                                                    ↓
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    SCHEDULER_FIREWALL (Extensión MISIL)                        │
│                                                                                 │
│  ┌──────────────────┐    ┌─────────────────┐    ┌──────────────────┐           │
│  │   PROTOBUF       │    │   AXIOM         │    │   FIREWALL       │           │
│  │   STORAGE        │    │   GENERATION    │    │   COMMAND        │           │
│  │   (Ultra-fast)   │    │   (Minimal)     │    │   (Original)     │           │
│  └──────────────────┘    └─────────────────┘    └──────────────────┘           │
│           ↓                        ↓                       ↓                   │
│  protobuf_storage/         axioms/pending/        simple_firewall_agent       │
│  enriched/*.pb.gz          *.json (minimal)                                    │
└─────────────────────────────────────────────────────────────────────────────────┘
                                     ↓
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    AUTONOMOUS RETRAINER DAEMON                                 │
│                     (Orquestador + Trainers Especializados)                    │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                        ORCHESTRATOR                                     │   │
│  │  • Monitorea axiomas/pending/                                           │   │
│  │  • Crea tareas de entrenamiento                                         │   │
│  │  • Gestiona trainers especializados                                     │   │
│  │  • Monitorea recursos del sistema                                       │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                     ↓                                           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐                │
│  │ DDOS TRAINER    │  │RANSOMWARE       │  │ ENSEMBLE        │                │
│  │                 │  │TRAINER          │  │ TRAINER         │                │
│  │ • Random Forest │  │ • XGBoost       │  │ • Voting Cls    │                │
│  │ • XGBoost       │  │ • LightGBM      │  │ • Stacking      │                │
│  │ • LightGBM      │  │ • Neural Net    │  │ • Meta-learning │                │
│  │                 │  │                 │  │                 │                │
│  │ [8 CPU cores]   │  │ [12 CPU cores]  │  │ [16 CPU cores]  │                │
│  │ [16GB RAM]      │  │ [24GB RAM]      │  │ [32GB RAM]      │                │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘                │
│           ↓                     ↓                     ↓                        │
│  models/staging/       models/staging/       models/staging/                   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                     ↓
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        VALIDATION & PROMOTION PIPELINE                         │
│                                                                                 │
│  Stage 1: Basic       Stage 2: Performance    Stage 3: Production             │
│  • Serialization     • Cross-validation       • Load testing                   │
│  • Latency test      • Holdout validation     • Integration test               │
│  • Memory test       • Robustness test        • Rollback safety                │
│                                                                                 │
│                              ↓ (Auto-promotion)                                │
│                     models/production/                                          │
│                                                                                 │
│                              ↓ (Hot-reload notification)                       │
│                    ml_detector (Future integration)                            │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 🚀 Componentes Clave

### 1. SCHEDULER-FIREWALL-AXIOM (Misil Ultra-Liviano)
- **Función**: Extensión mínima del scheduler_firewall
- **Operaciones**: Solo guardar protobuf + generar axioma JSON
- **Latencia**: < 1ms adicional
- **Axioma**: Ultra-compacto (9 campos esenciales)

### 2. AUTONOMOUS RETRAINER DAEMON (Orquestador)
- **Función**: Coordina evolución autónoma de modelos
- **Arquitectura**: 1 Orchestrator + N Trainers especializados
- **Recursos**: Intensivos, configurables por modelo
- **Operación**: 24/7, asíncrono, auto-recuperación

### 3. MODEL-SPECIFIC TRAINERS (Especialización)
- **DDOS Trainer**: Random Forest, XGBoost, LightGBM
- **Ransomware Trainer**: XGBoost, LightGBM, Neural Networks  
- **Ensemble Trainer**: Voting, Stacking, Meta-learning
- **Recursos**: CPU/GPU dedicados, configuración específica

## 📊 Flujo de Evolución Autónoma

```
📈 MATHEMATICAL PERFECTION EVOLUTION LOOP:

Evento → Axioma → Acumulación → Threshold → Entrenamiento Intensivo
   ↓                                              ↓
Protobuf                                    Validación Exhaustiva
   ↓                                              ↓
Storage                                    Promoción Automática
   ↓                                              ↓
RAG Data                                   Hot-reload ml_detector
                                                  ↓
                                           🧠 MODELO MÁS PERFECTO
```

## ⚡ Características Clave

### Ultra-Eficiencia
- **Scheduler**: Solo 2 operaciones críticas
- **Axiomas**: JSON minimalista (< 200 bytes)
- **Protobuf**: Compresión gzip nivel 1
- **Asíncrono**: Cero impacto en pipeline principal

### Autonomía Total
- **Detección**: Degradación automática vía axiomas
- **Reentrenamiento**: Sin intervención humana
- **Promoción**: Validación y deploy automático
- **Recuperación**: Auto-restart, health monitoring

### Escalabilidad Intensiva
- **Recursos**: Configurables por modelo
- **Paralelismo**: Trainers independientes
- **GPU**: Aceleración opcional
- **Cooldown**: Prevención de overtraining

### Evolución Matemática
- **Objetivos**: Accuracy, Robustness, Efficiency
- **Métricas**: Convergencia, Estabilidad, Generalización
- **Tendencia**: Perfección matemática asintótica

## 🔧 Configuración de Despliegue

### Recursos Mínimos Recomendados
```
CPU: 16+ cores (para 3 trainers paralelos)
RAM: 64GB+ (32GB para ensemble trainer)
GPU: 8GB+ VRAM (opcional, aceleración)
Disk: SSD 500GB+ (protobuf storage + models)
```

### Estructura de Archivos
```
feature/axiom-retrain/
├── scheduler-firewall-axiom-missile.py  # Extensión ultra-liviana
├── autonomous-retrainer-daemon.py       # Orquestador principal
├── integration_hooks.py                 # Hooks de integración
├── deploy_axiom_retrain.sh             # Script de despliegue
├── autonomous-retrainer.service         # Systemd service
├── config/
│   ├── config_scheduler_axiom.json      # Config scheduler
│   ├── config_autonomous_retrainer.json # Config daemon
│   └── runtime_config.json              # Config runtime
├── axioms/
│   ├── templates/minimal_axiom_template.json
│   ├── pending/           # Axiomas nuevos
│   ├── processed/         # Axiomas procesados
│   └── training_ready/    # Manifiestos de entrenamiento
├── protobuf_storage/
│   ├── enriched/          # Protobuf enriquecidos
│   └── archived/          # Protobuf archivados
└── models/
    ├── staging/           # Modelos en validación
    ├── production/        # Modelos en producción
    └── retired/           # Modelos retirados
```

## 🎯 Implementación Inmediata

### Fase 1: Setup (1 día)
```bash
git checkout -b feature/axiom-retrain
./deploy_axiom_retrain.sh
```

### Fase 2: Integración (1 día)
```python
# En tu scheduler_firewall.py
from integration_hooks import AxiomIntegration
axiom_integration = AxiomIntegration()

# Después del procesamiento ML:
axiom_integration.process_event(event_proto)
```

### Fase 3: Daemon Start (Inmediato)
```bash
python3 autonomous-retrainer-daemon.py ./config/config_autonomous_retrainer.json &
```

## 🧠 Resultado Final

**MODELOS QUE EVOLUCIONAN AUTÓNOMAMENTE HACIA LA PERFECCIÓN MATEMÁTICA**

- ✅ **Cero degradación**: Los modelos nunca empeoran
- ✅ **Mejora continua**: Cada reentrenamiento es superior
- ✅ **Autonomía total**: Sin intervención humana
- ✅ **Eficiencia máxima**: Recursos optimizados
- ✅ **Escalabilidad**: Trainers especializados
- ✅ **Robustez**: Auto-recuperación y monitoring

> *"Un sistema que aprende de sí mismo, se mejora a sí mismo, y tiende asintóticamente hacia la perfección matemática en la detección de amenazas de seguridad."*