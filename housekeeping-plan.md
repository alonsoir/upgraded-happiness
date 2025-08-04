# 🧹 Plan de Housekeeping - Upgraded Happiness

## 🎯 **Objetivo**: Organizar 93 archivos sin romper el sistema tricapa funcionando

## 📋 **Estructura Propuesta** (Basada en tu audit)

```
upgraded-happiness/
├── core/                           # 8 componentes sistema principal
│   ├── lightweight_ml_detector.py
│   ├── simple_firewall_agent.py
│   ├── geoip_enricher.py
│   ├── real_zmq_dashboard_with_firewall.py
│   ├── promiscuous_agent.py
│   ├── promiscuous_agent_v2.py
│   ├── fixed_service_sniffer.py
│   └── enhanced_network_feature_extractor.py
│
├── ml_pipeline/                    # Pipeline de Machine Learning
│   ├── trainers/
│   │   ├── sniffer_compatible_retrainer.py    # → rf_production_sniffer_compatible.joblib
│   │   ├── train_specialized_models.py        # → web/internal normal detectors
│   │   ├── advanced_trainer.py
│   │   ├── cicids_retrainer.py
│   │   └── cicids_traditional_processor.py
│   ├── analyzers/
│   │   ├── model_analyzer_sniffer.py
│   │   ├── validate_ensemble_models.py
│   │   └── extract_required_features.py
│   └── data_generators/
│       ├── traffic_generator.py               # ÉPICO web crawler (?)
│       ├── create_specialized_datasets.py     # Procesador de datos raw
│       └── [sniffer interno por identificar]
│
├── models/                         # Modelos organizados por tipo
│   ├── production/                 # 🚀 PRODUCTION READY
│   │   ├── rf_production_sniffer_compatible.joblib      # 10.1MB - Detector ataques
│   │   ├── rf_production_sniffer_compatible_scaler.joblib
│   │   ├── web_normal_detector.joblib                   # 2.5MB - Tráfico web normal
│   │   └── internal_normal_detector.joblib              # 2.3MB - Tráfico interno normal
│   └── archive/                    # Modelos experimentales/corruptos
│       └── [modelos no-production]
│
├── datasets/                       # Datos organizados por fuente
│   ├── clean/                      # Datasets validados
│   │   ├── cicids_2017_processed.csv           # 1044.1MB - Para ataques
│   │   └── specialized/
│   │       ├── web_normal_detector.csv         # Generado por épico crawler
│   │       └── internal_normal_detector.csv    # Capturado localmente
│   └── corrupted/                  # Datasets problemáticos
│       ├── UNSW-NB15.csv
│       └── [otros datasets corruptos]
│
├── config/                         # 13 configuraciones JSON
├── scripts/                        # 12 scripts bash/utilidades
├── docs/                          # Documentación
│   ├── model_traceability.md      # Trazabilidad completa de modelos
│   └── data_generation_strategy.md # Tu estrategia ÉPICA de datos
└── archive/                       # 33 archivos experimentales
```

## 🚨 **ARCHIVOS CRÍTICOS** (NO TOCAR sin backup)

### Sistema Core (8 archivos)
- `lightweight_ml_detector.py` - Detector principal ML
- `promiscuous_agent_v2.py` - Sniffer principal (36.7KB)
- `real_zmq_dashboard_with_firewall.py` - Dashboard ZeroMQ

### Modelos de Producción (4 archivos)
- `rf_production_sniffer_compatible.joblib` - Modelo ataques (10.1MB)
- `web_normal_detector.joblib` - Modelo web normal (2.5MB) 
- `internal_normal_detector.joblib` - Modelo interno (2.3MB)
- `rf_production_sniffer_compatible_scaler.joblib`

### Trainers Identificados (3 archivos)
- `sniffer_compatible_retrainer.py` - Entrenó modelo de ataques
- `train_specialized_models.py` - Entrenó modelos normales
- `create_specialized_datasets.py` - Procesó datos raw

## 📋 **Secuencia de Housekeeping**

### Fase 1: Investigación (ACTUAL)
- [ ] Identificar script del épico web crawler
- [ ] Localizar sniffer de captura interna  
- [ ] Mapear datasets generados
- [ ] Verificar trazabilidad completa

### Fase 2: Backup y Preparación
- [ ] `git commit -am "Pre-housekeeping snapshot"`
- [ ] Crear rama `housekeeping/file-organization`
- [ ] Backup completo local
- [ ] Verificar que sistema tricapa funciona

### Fase 3: Reorganización Conservativa
- [ ] Crear nuevos directorios
- [ ] Mover archivos NO-CRÍTICOS primero
- [ ] Actualizar imports progresivamente
- [ ] Probar sistema después de cada batch

### Fase 4: Actualización de Documentación
- [ ] README.md con trazabilidad de modelos
- [ ] ROADMAP.md realista hacia 1.0.0
- [ ] Documentar estrategia épica de datos

## ⚠️ **Reglas de Oro**

1. **NUNCA** mover archivos CORE sin probar
2. **SIEMPRE** actualizar imports después de mover
3. **BACKUP** antes de cada cambio mayor
4. **PROBAR** sistema tricapa después de reorganizar
5. **DOCUMENTAR** cada cambio para rollback

## 🎯 **Criterio de Éxito**

✅ Sistema tricapa sigue funcionando  
✅ Trazabilidad de modelos documentada  
✅ Estructura clara y mantenible  
✅ README/ROADMAP actualizados  
✅ Base sólida para Protobuf v3.1