# Prototipos Scapy - Sistema Tricapa

## 🎯 Descripción

Prototipos experimentales que integran captura scapy con modelos ML tricapa.
Migrados automáticamente desde `core/` el 2025-08-08 08:33:54.

## 📊 Archivos Incluidos

- `complete_ml_pipeline.py` - Migrado desde `core/complete_ml_pipeline.py`
- `scapy_monitor_complete.py` - Migrado desde `core/scapy_monitor_complete_pipeline.py`
- `scapy_to_ml_features.py` - Migrado desde `core/scapy_to_ml_features.py`


## 🏗️ Arquitectura Actual

```
scapy_capture → feature_extraction → ml_models → classification
     ↓                ↓                  ↓             ↓
 raw_packets    82_features      tricapa_models   final_decision
```

## 🚀 Evolución hacia v3.1

### 🔧 Cambios Planificados

1. **Protobuf Unificado v3.1**
   - 83 features DDOS + Ransomware
   - GeoIP enrichment fields  
   - Metadatos modo distribuido

2. **Pipeline Refactorizado**
   ```
   scapy_capture → time_windows → protobuf → 
   geoip_enrichment → multi_model_scoring → 
   dashboard/no-gui → firewall_agent
   ```

3. **Multi-Model Orchestration**
   - Carga TODOS los modelos (tricapa + RF especializados)
   - Score aggregation y decisión final
   - Metadata de confianza por modelo

4. **Dual Output Paths**
   - Dashboard GUI (actual)
   - CLI/API mode → direct firewall integration

## 🧪 Estado Experimental

⚠️  **IMPORTANTE**: Estos prototipos son para investigación y desarrollo.
Para producción, usar siempre los componentes validados en `core/`.

## 📈 Métricas Actuales

- **F1-Score**: 1.0000 (Perfecto)
- **Arquitectura**: Tricapa operativa
- **Modelos**: 3 prototipos integrados
- **Pipeline**: scapy → ML → clasificación

## 🔗 Referencias

- Modelos production: `../../../models/production/tricapa/`
- Documentación sistema: `../../../models/README.md`
- Componentes core: `../../../core/`

---
*Generado automáticamente por el sistema de migración tricapa*
