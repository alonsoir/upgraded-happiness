#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
scheduler-firewall-axiom.py - MISIL ULTRA-LIVIANO
Solo dos funciones críticas:
1. Guardar protobuf enriquecidos
2. Generar axioma JSON minimalista
VELOCIDAD Y EFICIENCIA MÁXIMA
"""

import json
import os
import gzip
from datetime import datetime
from pathlib import Path
from typing import Optional


# IMPORTAR TU PROTOBUF REAL:
# from generated_protos.network_security_clean_v31_pb2 import NetworkSecurityEvent

class UltraLightAxiomGenerator:
    """Generador de axiomas ultra-liviano - Solo lo esencial"""

    __slots__ = ['axiom_dir', 'protobuf_dir', 'template', 'enabled']

    def __init__(self, axiom_dir: str, protobuf_dir: str, template_path: str):
        self.axiom_dir = Path(axiom_dir)
        self.protobuf_dir = Path(protobuf_dir)
        self.axiom_dir.mkdir(parents=True, exist_ok=True)
        self.protobuf_dir.mkdir(parents=True, exist_ok=True)

        # Template minimalista
        with open(template_path, 'r') as f:
            self.template = json.load(f)

        self.enabled = True

    def should_store_protobuf(self, ml_confidence: float, ml_prediction: str) -> bool:
        """Decisión ultra-rápida: ¿guardar protobuf?"""
        # Condiciones mínimas para almacenamiento
        return (
                ml_confidence < 0.8 or  # Confianza baja
                ml_prediction != "BENIGN"  # Es un ataque
        )

    def should_generate_axiom(self, ml_confidence: float) -> bool:
        """Decisión ultra-rápida: ¿generar axioma?"""
        return ml_confidence >= 0.1  # Umbral mínimo

    def store_protobuf(self, event_proto, event_id: str) -> Optional[str]:
        """Almacenamiento ultra-eficiente de protobuf"""
        if not self.enabled:
            return None

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')[:-3]  # ms precision
        filename = f"pb_{timestamp}_{event_id}.gz"
        filepath = self.protobuf_dir / filename

        # Serializar y comprimir en una sola operación
        with gzip.open(filepath, 'wb', compresslevel=1) as f:  # Compresión rápida
            f.write(event_proto.SerializeToString())

        return str(filepath)

    def generate_axiom_minimal(self, event_proto, protobuf_path: str = "") -> str:
        """Generación de axioma MINIMALISTA - Solo datos críticos"""
        if not self.enabled:
            return ""

        # Extraer solo datos esenciales
        event_id = getattr(event_proto, 'event_id', 'unknown')
        ml_pred = getattr(event_proto.ml_analysis, 'final_threat_classification', 'UNKNOWN')
        ml_conf = getattr(event_proto.ml_analysis, 'ensemble_confidence', 0.0)
        src_ip = getattr(event_proto.network_features, 'source_ip', '')
        dst_ip = getattr(event_proto.network_features, 'destination_ip', '')

        # Axioma ultra-compacto
        timestamp = datetime.utcnow()
        axiom_id = f"AX-{timestamp.strftime('%Y%m%d%H%M%S%f')[:-3]}"

        # Template mínimo
        axiom = {
            "axiom_id": axiom_id,
            "timestamp": timestamp.isoformat() + "Z",
            "event_id": event_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ml_pred": ml_pred,
            "ml_conf": ml_conf,
            "pb_path": protobuf_path,
            "retrain": ml_conf < 0.7 and ml_pred != "BENIGN"
        }

        # Guardar axioma
        axiom_file = self.axiom_dir / f"{axiom_id}.json"
        with open(axiom_file, 'w') as f:
            json.dump(axiom, f, separators=(',', ':'))  # Compacto, sin espacios

        return str(axiom_file)


class SchedulerFirewallAxiomMissile:
    """MISIL - Extensión ultra-liviana del scheduler_firewall"""

    __slots__ = ['axiom_generator', 'config']

    def __init__(self, config: dict):
        self.config = config

        # Inicializar generador ultra-liviano
        self.axiom_generator = UltraLightAxiomGenerator(
            axiom_dir=config["axiom_dir"],
            protobuf_dir=config["protobuf_dir"],
            template_path=config["template_path"]
        )

    def process_event_ultra_fast(self, event_proto) -> None:
        """Procesamiento ultra-rápido de evento - SOLO lo esencial"""

        # Extraer datos críticos una sola vez
        ml_confidence = getattr(event_proto.ml_analysis, 'ensemble_confidence', 0.0)
        ml_prediction = getattr(event_proto.ml_analysis, 'final_threat_classification', 'BENIGN')
        event_id = getattr(event_proto, 'event_id', 'unknown')

        protobuf_path = ""

        # 1. GUARDAR PROTOBUF (si es necesario)
        if self.axiom_generator.should_store_protobuf(ml_confidence, ml_prediction):
            protobuf_path = self.axiom_generator.store_protobuf(event_proto, event_id) or ""

        # 2. GENERAR AXIOMA (si es necesario)
        if self.axiom_generator.should_generate_axiom(ml_confidence):
            self.axiom_generator.generate_axiom_minimal(event_proto, protobuf_path)

        # FIN - El scheduler_firewall original continúa su flujo normal


# Función de integración MÍNIMA con scheduler_firewall existente
def integrate_axiom_generation(scheduler_firewall_instance, config_path: str):
    """
    Integración ultra-liviana con scheduler_firewall existente
    Llamar DESPUÉS del procesamiento ML, ANTES del envío al firewall
    """

    # Cargar configuración mínima
    with open(config_path, 'r') as f:
        axiom_config = json.load(f)

    # Crear instancia del misil
    axiom_missile = SchedulerFirewallAxiomMissile(axiom_config)

    # Función que se inserta en el flujo del scheduler_firewall
    def process_axiom_hook(event_proto):
        """Hook ultra-rápido - máximo 1ms de latencia"""
        try:
            axiom_missile.process_event_ultra_fast(event_proto)
        except Exception:
            pass  # Nunca fallar - el flujo principal debe continuar

    return process_axiom_hook


# Configuración ultra-minimalista
MINIMAL_CONFIG = {
    "axiom_dir": "./axioms/pending",
    "protobuf_dir": "./protobuf_storage/enriched",
    "template_path": "./axioms/templates/minimal_template.json"
}

# Template ultra-minimalista
MINIMAL_TEMPLATE = {
    "axiom_id": "",
    "timestamp": "",
    "event_id": "",
    "src_ip": "",
    "dst_ip": "",
    "ml_pred": "",
    "ml_conf": 0.0,
    "pb_path": "",
    "retrain": False
}

if __name__ == "__main__":
    # DEMO de integración ultra-rápida
    print("Axiom Generation Missile - Ultra-Light Integration")
    print("Integrar con scheduler_firewall existente:")
    print("  hook = integrate_axiom_generation(scheduler_instance, 'config.json')")
    print("  # En el flujo principal: hook(event_proto)")