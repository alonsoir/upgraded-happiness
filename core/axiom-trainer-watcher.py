#!/usr/bin/env python3

# axiom-trainer-watcher.py
# Va a vigilar la carpeta ./axioms, los va a procesar, para luego dejar otros ficheros json en ./axioms/processed
# Vigila constantemente la carpeta ./axioms para detectar nuevos archivos JSON (los axiomas generados).
# Los procesa (lee, parsea y acumula estadísticas relevantes como tipos de ataques, confianza ML, modelo
# implicado, etc.).
# Mueve los archivos procesados a ./axioms/processed para evitar reprocesamiento.
# Decide con reglas configurables (desde JSON config) cuándo es necesario iniciar un reentrenamiento.
# Registra logs con la decisión y razones.
# Si la regla se cumple, lanza el proceso de reentrenamiento o notifica a otro componente que lo ejecute
# (idealmente vía cola, señal o llamada REST interna).
# Su fichero json de configuracion es ./config/json/config_axiom_watcher.json

# !/usr/bin/env python3
"""
axiom-trainer-watcher.py - Mejorado
Vigila axiomas, procesa estadísticas y decide reentrenamientos automáticos
"""

import json
import logging
import os
import queue
import shutil
import sqlite3
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional


class ConfigError(Exception):
    pass


class AxiomDatabase:
    """Base de datos SQLite para estadísticas de axiomas"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Inicializa base de datos"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS axioms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    axiom_id TEXT UNIQUE,
                    timestamp TEXT,
                    model_type TEXT,
                    attack_type TEXT,
                    ml_confidence REAL,
                    retrain_candidate BOOLEAN,
                    priority TEXT,
                    protobuf_path TEXT,
                    processed_at TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS retraining_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trigger_time TEXT,
                    model_type TEXT,
                    trigger_reason TEXT,
                    axiom_count INTEGER,
                    status TEXT,
                    completed_at TEXT
                )
            """)

    def insert_axiom(self, axiom_data: Dict):
        """Inserta axioma en BD"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO axioms 
                (axiom_id, timestamp, model_type, attack_type, ml_confidence, 
                 retrain_candidate, priority, protobuf_path, processed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                axiom_data["axiom_id"],
                axiom_data["timestamp"],
                axiom_data.get("ml_analysis", {}).get("model_type", "unknown"),
                axiom_data.get("ml_analysis", {}).get("prediction", "unknown"),
                axiom_data.get("ml_analysis", {}).get("confidence", 0.0),
                axiom_data.get("training_flag", {}).get("retrain_candidate", False),
                axiom_data.get("training_flag", {}).get("priority", "low"),
                axiom_data.get("source_proto_info", {}).get("proto_file_path", ""),
                datetime.utcnow().isoformat()
            ))

    def get_statistics(self, hours_back: int = 24) -> Dict:
        """Obtiene estadísticas de las últimas N horas"""
        cutoff_time = (datetime.utcnow() - timedelta(hours=hours_back)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # Estadísticas generales
            general_stats = conn.execute("""
                SELECT 
                    model_type,
                    COUNT(*) as total_axioms,
                    COUNT(CASE WHEN retrain_candidate = 1 THEN 1 END) as retrain_candidates,
                    AVG(ml_confidence) as avg_confidence,
                    MIN(ml_confidence) as min_confidence,
                    COUNT(CASE WHEN ml_confidence < 0.7 THEN 1 END) as low_confidence_count
                FROM axioms 
                WHERE processed_at > ?
                GROUP BY model_type
            """, (cutoff_time,)).fetchall()

            # Distribución por tipo de ataque
            attack_stats = conn.execute("""
                SELECT attack_type, COUNT(*) as count
                FROM axioms 
                WHERE processed_at > ?
                GROUP BY attack_type
                ORDER BY count DESC
            """, (cutoff_time,)).fetchall()

            return {
                "general": [dict(row) for row in general_stats],
                "attack_distribution": [dict(row) for row in attack_stats],
                "time_window_hours": hours_back,
                "generated_at": datetime.utcnow().isoformat()
            }

    def get_retrain_candidates(self, model_type: str, limit: int = 100) -> List[Dict]:
        """Obtiene candidatos para reentrenamiento"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            results = conn.execute("""
                SELECT * FROM axioms 
                WHERE model_type = ? AND retrain_candidate = 1
                ORDER BY 
                    CASE priority 
                        WHEN 'high' THEN 1 
                        WHEN 'medium' THEN 2 
                        ELSE 3 
                    END,
                    timestamp DESC
                LIMIT ?
            """, (model_type, limit)).fetchall()

            return [dict(row) for row in results]


class RetrainingDecisionEngine:
    """Motor de decisiones para reentrenamiento"""

    def __init__(self, config: Dict, db: AxiomDatabase):
        self.config = config
        self.db = db
        self.last_retrain_times = {}

    def should_retrain(self, model_type: str) -> tuple[bool, str]:
        """Decide si reentrenar un modelo específico"""

        # Verificar cooldown period
        cooldown_hours = self.config["retraining_rules"].get("cooldown_hours", 6)
        last_retrain = self.last_retrain_times.get(model_type)

        if last_retrain:
            time_since_last = datetime.utcnow() - datetime.fromisoformat(last_retrain)
            if time_since_last < timedelta(hours=cooldown_hours):
                return False, f"Cooldown period active (last retrain: {last_retrain})"

        # Obtener candidatos
        candidates = self.db.get_retrain_candidates(model_type)

        # Regla 1: Volumen mínimo de candidatos
        min_candidates = self.config["retraining_rules"]["min_retrain_candidates"]
        if len(candidates) < min_candidates:
            return False, f"Insufficient candidates: {len(candidates)} < {min_candidates}"

        # Regla 2: Prioridad alta
        high_priority_count = sum(1 for c in candidates if c["priority"] == "high")
        high_priority_threshold = self.config["retraining_rules"]["high_priority_threshold"]

        if high_priority_count >= high_priority_threshold:
            return True, f"High priority candidates: {high_priority_count} >= {high_priority_threshold}"

        # Regla 3: Porcentaje de confianza baja
        low_confidence_count = sum(1 for c in candidates if c["ml_confidence"] < 0.7)
        low_confidence_ratio = low_confidence_count / len(candidates) if candidates else 0

        if low_confidence_ratio >= self.config["retraining_rules"]["low_confidence_ratio_threshold"]:
            return True, f"Low confidence ratio: {low_confidence_ratio:.2f}"

        # Regla 4: Diversidad de ataques
        unique_attacks = len(set(c["attack_type"] for c in candidates))
        if unique_attacks >= self.config["retraining_rules"]["min_attack_diversity"]:
            return True, f"Attack diversity threshold met: {unique_attacks} types"

        return False, "No retraining conditions met"

    def mark_retrain_triggered(self, model_type: str, reason: str, axiom_count: int):
        """Marca que se disparó reentrenamiento"""
        self.last_retrain_times[model_type] = datetime.utcnow().isoformat()

        # Registrar en BD
        with sqlite3.connect(self.db.db_path) as conn:
            conn.execute("""
                INSERT INTO retraining_history 
                (trigger_time, model_type, trigger_reason, axiom_count, status)
                VALUES (?, ?, ?, ?, 'triggered')
            """, (
                datetime.utcnow().isoformat(),
                model_type,
                reason,
                axiom_count
            ))


class AxiomTrainerWatcher:
    """Componente principal mejorado"""

    def __init__(self, config_path: str):
        self.config = self.load_config(config_path)
        self.setup_logging()
        self.validate_dirs()

        # Inicializar componentes
        db_path = self.config.get("database_path", "./data/axioms.db")
        self.db = AxiomDatabase(db_path)
        self.decision_engine = RetrainingDecisionEngine(self.config, self.db)

        # Cola para procesamiento asíncrono
        self.axiom_queue = queue.Queue()
        self.running = True

        # Métricas
        self.metrics = {
            "processed_axioms": 0,
            "retrain_triggers": 0,
            "errors": 0,
            "last_activity": datetime.utcnow()
        }

    def load_config(self, path: str) -> Dict:
        """Carga configuración con validación mejorada"""
        if not os.path.isfile(path):
            raise ConfigError(f"Configuration file not found: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except Exception as e:
            raise ConfigError(f"Error parsing config JSON: {e}")

        # Validar estructura completa
        self._validate_config(config)
        return config

    def _validate_config(self, config: Dict):
        """Validación completa de configuración"""
        required_sections = [
            "axioms_dir", "processed_dir", "training_ready_dir",
            "poll_interval_seconds", "log_file", "retraining_rules"
        ]

        for section in required_sections:
            if section not in config:
                raise ConfigError(f"Missing config section: {section}")

        # Validar reglas de reentrenamiento
        retrain_rules = config["retraining_rules"]
        required_rules = [
            "min_retrain_candidates", "high_priority_threshold",
            "low_confidence_ratio_threshold", "min_attack_diversity",
            "cooldown_hours"
        ]

        for rule in required_rules:
            if rule not in retrain_rules:
                raise ConfigError(f"Missing retraining rule: {rule}")

    def setup_logging(self):
        """Configuración de logging mejorada"""
        log_path = self.config["log_file"]
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)

        # Configurar logging con rotación
        from logging.handlers import RotatingFileHandler

        handler = RotatingFileHandler(
            log_path, maxBytes=10 * 1024 * 1024, backupCount=5
        )

        logging.basicConfig(
            level=getattr(logging, self.config.get("log_level", "INFO")),
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            handlers=[handler, logging.StreamHandler()]
        )

        self.log = logging.getLogger("AxiomTrainerWatcher")
        self.log.info("Enhanced logger initialized")

    def validate_dirs(self):
        """Validar y crear directorios"""
        dirs = [
            self.config["axioms_dir"],
            self.config["processed_dir"],
            self.config["training_ready_dir"]
        ]

        for d in dirs:
            Path(d).mkdir(parents=True, exist_ok=True)

    def process_axiom_file(self, filepath: str) -> Optional[Dict]:
        """Procesa un archivo de axioma individual"""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                axiom_data = json.load(f)

            # Validar estructura básica
            required_fields = ["axiom_id", "timestamp", "ml_analysis", "training_flag"]
            for field in required_fields:
                if field not in axiom_data:
                    self.log.warning(f"Missing field {field} in {filepath}")
                    return None

            # Insertar en BD
            self.db.insert_axiom(axiom_data)

            # Mover a procesados
            filename = Path(filepath).name
            dest_path = Path(self.config["processed_dir"]) / filename
            shutil.move(filepath, dest_path)

            self.log.info(f"Processed axiom: {axiom_data['axiom_id']}")
            self.metrics["processed_axioms"] += 1

            return axiom_data

        except Exception as e:
            self.log.error(f"Failed to process {filepath}: {e}")
            self.metrics["errors"] += 1
            return None

    def scan_for_new_axioms(self) -> List[str]:
        """Escanea nuevos archivos de axiomas"""
        axiom_files = []

        try:
            for filename in os.listdir(self.config["axioms_dir"]):
                if filename.endswith(".json"):
                    full_path = os.path.join(self.config["axioms_dir"], filename)
                    if os.path.isfile(full_path):
                        axiom_files.append(full_path)
        except Exception as e:
            self.log.error(f"Error scanning axioms directory: {e}")

        return sorted(axiom_files)  # Procesar en orden

    def evaluate_retraining_needs(self):
        """Evalúa necesidades de reentrenamiento para todos los modelos"""
        model_types = self.config["retraining_rules"]["model_types_to_monitor"]

        for model_type in model_types:
            should_retrain, reason = self.decision_engine.should_retrain(model_type)

            if should_retrain:
                self.trigger_retraining(model_type, reason)

    def trigger_retraining(self, model_type: str, reason: str):
        """Dispara proceso de reentrenamiento"""
        candidates = self.db.get_retrain_candidates(model_type)

        self.log.info(f"TRIGGERING RETRAINING for {model_type}: {reason}")
        self.log.info(f"Using {len(candidates)} candidate axioms")

        # Mover axiomas relevantes a training_ready
        self.prepare_training_data(model_type, candidates)

        # Registrar trigger
        self.decision_engine.mark_retrain_triggered(model_type, reason, len(candidates))
        self.metrics["retrain_triggers"] += 1

        # Notificar al sistema de reentrenamiento
        self.notify_retraining_system(model_type, reason, candidates)

    def prepare_training_data(self, model_type: str, candidates: List[Dict]):
        """Prepara datos para reentrenamiento"""
        training_manifest = {
            "model_type": model_type,
            "trigger_time": datetime.utcnow().isoformat(),
            "candidate_count": len(candidates),
            "protobuf_files": [],
            "axiom_ids": []
        }

        for candidate in candidates:
            training_manifest["axiom_ids"].append(candidate["axiom_id"])
            if candidate["protobuf_path"]:
                training_manifest["protobuf_files"].append(candidate["protobuf_path"])

        # Guardar manifiesto de entrenamiento
        manifest_path = Path(
            self.config["training_ready_dir"]) / f"training_manifest_{model_type}_{int(time.time())}.json"

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(training_manifest, f, indent=2)

        self.log.info(f"Training manifest created: {manifest_path}")

    def notify_retraining_system(self, model_type: str, reason: str, candidates: List[Dict]):
        """Notifica al sistema de reentrenamiento externo"""
        notification = {
            "event_type": "retraining_triggered",
            "model_type": model_type,
            "reason": reason,
            "candidate_count": len(candidates),
            "timestamp": datetime.utcnow().isoformat()
        }

        # Guardar notificación (el retrainer la recogerá)
        notification_path = Path(self.config.get("notification_dir", "./notifications"))
        notification_path.mkdir(exist_ok=True)

        notif_file = notification_path / f"retrain_notification_{model_type}_{int(time.time())}.json"

        with open(notif_file, "w", encoding="utf-8") as f:
            json.dump(notification, f, indent=2)

        self.log.info(f"Retraining notification sent: {notif_file}")

    def generate_periodic_report(self):
        """Genera reporte periódico de estadísticas"""
        stats = self.db.get_statistics(24)  # Últimas 24 horas

        report = {
            "report_type": "axiom_statistics",
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": self.metrics,
            "statistics": stats
        }

        report_dir = Path(self.config.get("reports_dir", "./reports"))
        report_dir.mkdir(exist_ok=True)

        report_file = report_dir / f"axiom_report_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.json"

        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        self.log.info(f"Periodic report generated: {report_file}")

    def run(self):
        """Loop principal mejorado"""
        self.log.info("Starting enhanced axiom-trainer-watcher")

        last_report_time = time.time()
        report_interval = self.config.get("report_interval_minutes", 60) * 60

        while self.running:
            try:
                # Procesar nuevos axiomas
                axiom_files = self.scan_for_new_axioms()

                if axiom_files:
                    self.log.info(f"Found {len(axiom_files)} new axiom files")

                    for filepath in axiom_files:
                        axiom_data = self.process_axiom_file(filepath)
                        if axiom_data:
                            self.metrics["last_activity"] = datetime.utcnow()

                    # Evaluar necesidades de reentrenamiento
                    self.evaluate_retraining_needs()

                # Generar reporte periódico
                if time.time() - last_report_time > report_interval:
                    self.generate_periodic_report()
                    last_report_time = time.time()

                # Pausa configurada
                time.sleep(self.config["poll_interval_seconds"])

            except KeyboardInterrupt:
                self.log.info("Shutting down gracefully...")
                self.running = False
                break
            except Exception as e:
                self.log.error(f"Unexpected error in main loop: {e}")
                self.metrics["errors"] += 1
                time.sleep(5)  # Pausa en caso de error


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 axiom-trainer-watcher.py <config_json_path>")
        sys.exit(1)

    config_path = sys.argv[1]

    try:
        watcher = AxiomTrainerWatcher(config_path)
        watcher.run()
    except ConfigError as ce:
        print(f"[CONFIG ERROR] {ce}")
        sys.exit(2)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(3)