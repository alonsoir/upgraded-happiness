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
