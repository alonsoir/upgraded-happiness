# Feature: Axiom-based Model Retraining

## Objetivo
Implementar un sistema automático de reentrenamiento de modelos ML basado en axiomas lógicos generados del pipeline IDS, con ciclo completo de promoción de modelos.

## Componentes

### 1. scheduler-firewall-axiom (Modificación)
**Ubicación**: Extensión del `scheduler_firewall` existente
**Responsabilidades**:
- ✅ Guardar protobuf enriquecidos en `./protobuf_storage/enriched/`
- ✅ Generar axiomas JSON en `./axioms/pending/`
- ✅ Configuración via JSON para ambas funcionalidades

### 2. axiom-trainer-watcher (Nuevo)
**Responsabilidades**:
- 🔄 Vigilar `./axioms/pending/` 
- 📊 Procesar y generar estadísticas
- 🧮 Evaluar criterios de reentrenamiento
- 📝 Mover axiomas procesados
- 🚀 Disparar reentrenamiento cuando se cumplan condiciones

### 3. model-axiom-retrainer (Futuro)
**Responsabilidades**:
- 🔍 Recuperar protobuf desde axiomas seleccionados
- 🧠 Reentrenar modelos con datos históricos + nuevos
- 📦 Generar modelos en `./models/staging/`
- ✅ Ejecutar validación automática
- 🚀 Promocionar a `./models/production/` si pasan tests

### 4. model-lifecycle-manager (Futuro)
**Responsabilidades**:
- 🗄️ Integración con etcd (cuando esté disponible)
- 🔄 Actualizar configs del `ml-detector` automáticamente
- 📈 Notificar al `ml-detector` de nuevos modelos
- 🔄 Hot-reload de modelos en producción

## Pipeline de datos

```
scheduler_firewall
    ├── Guardar protobuf enriquecido
    └── Generar axioma JSON
         ↓
./axioms/pending/
         ↓
axiom-trainer-watcher
    ├── Procesar axiomas
    ├── Evaluar condiciones
    └── Disparar reentrenamiento
         ↓
model-axiom-retrainer
    ├── Recuperar protobuf relevantes
    ├── Reentrenar modelos
    └── Generar modelo staging
         ↓
./models/staging/ → Tests → ./models/production/
         ↓
model-lifecycle-manager
    ├── Actualizar etcd
    ├── Actualizar config ml-detector
    └── Notificar hot-reload
```

## Configuraciones requeridas

### scheduler_firewall (extensión)
- Rutas de almacenamiento protobuf
- Condiciones para guardar protobuf
- Configuración generación axiomas

### axiom-trainer-watcher
- Umbrales de reentrenamiento
- Modelos a monitorizar
- Intervalos de polling
- Criterios de calidad

### model-axiom-retrainer
- Algoritmos de reentrenamiento disponibles
- Configuración de validación
- Rutas de staging/production

## Criterios de reentrenamiento

1. **Por volumen**: N axiomas con `retrain_candidate=true`
2. **Por confianza**: % de predicciones con confianza < threshold
3. **Por discrepancia**: Discrepancias entre ML y política final
4. **Por tiempo**: Ventana temporal sin reentrenamiento
5. **Por geografía**: Nuevos patrones geográficos detectados

## Promoción de modelos

```
Training → Staging → Production
    ↓        ↓         ↓
   Tests   Tests    Hot-reload
```

**Tests en staging**:
- Validación cruzada con datos históricos
- Métricas de rendimiento vs modelo actual
- Tests de latencia y throughput
- Validación con datos sintéticos

## Integración con pipeline existente

**Modificaciones mínimas**:
- ✅ `scheduler_firewall`: Añadir guardado protobuf + generación axiomas
- 🔄 `ml-detector`: Preparar para hot-reload de modelos (futuro)
- 📊 Dashboard: Mostrar estadísticas de axiomas y reentrenamiento

**Sin tocar**:
- Pipeline protobuf existente (sniffer → geoip → ml-detector → scheduler)
- Comunicación ZeroMQ actual
- Lógica de firewall existente

## Fases de implementación

### Fase 1 (Actual)
- [x] Diseño de axiomas y templates
- [ ] Modificar scheduler_firewall para guardado protobuf
- [ ] Implementar axiom-trainer-watcher básico
- [ ] Testing inicial con axiomas manuales

### Fase 2 (Siguiente sprint)
- [ ] Implementar model-axiom-retrainer básico
- [ ] Pipeline de staging y validación
- [ ] Integración completa scheduler → watcher → retrainer

### Fase 3 (Futuro)
- [ ] model-lifecycle-manager con etcd
- [ ] Hot-reload en ml-detector
- [ ] Dashboard avanzado para monitoring
- [ ] RAG para consultas históricas

## Métricas de éxito

- ⏱️ Tiempo de detección de degradación del modelo < 1 hora
- 🎯 Precisión del reentrenamiento automático > 90%
- ⚡ Tiempo total de reentrenamiento + promoción < 2 horas
- 🔄 Zero downtime en hot-reload de modelos
- 📊 Cobertura de axiomas > 95% de eventos procesados