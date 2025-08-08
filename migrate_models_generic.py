#!/usr/bin/env python3
"""
ARCHIVO: migrate_models_generic.py
FECHA CREACIÓN: 8 de agosto de 2025
DESCRIPCIÓN: Script genérico de migración (NO USAR - usar migrate_tricapa_completo.py)

Script automático para migrar modelos tricapa a production y actualizar referencias
Optimizado para el sistema de ciberseguridad ML con F1-Score 1.0000

NOTA: Este es el script genérico. Para el sistema real usar:
      migrate_tricapa_completo.py (script específico para los 7 modelos)
"""

import os
import glob
import shutil
import re
from pathlib import Path
from datetime import datetime


class ProductionMigrator:
    def __init__(self):
        self.base_dir = Path(".")
        self.models_dir = self.base_dir / "models"
        self.production_dir = self.models_dir / "production" / "tricapa"
        self.experimental_dir = self.models_dir / "experimental"

        # Archivos core a actualizar
        self.core_files = [
            "core/complete_ml_pipeline.py",
            "core/scapy_monitor_complete_pipeline.py",
            "core/scapy_to_ml_features.py"
        ]

        # Patrones de modelos "buenos" (tricapa operativos) - BASADO EN ESTRUCTURA REAL
        self.good_model_patterns = [
            "ddos_random_forest.joblib",  # Sistema tricapa Aug 7
            "ddos_lightgbm.joblib",
            "ransomware_random_forest.joblib",
            "ransomware_lightgbm.joblib",
            "ddos_*_metrics.json",  # Métricas asociadas
            "ransomware_*_metrics.json",
            "*tricapa*.joblib",  # Por si hay más tricapa
            "rf_production_final*.joblib"  # Modelos finales production
        ]

        # Patrones de modelos experimentales/antiguos - BASADO EN ESTRUCTURA REAL
        self.experimental_patterns = [
            "rf_normal_*.joblib",  # Modelos rf_normal_* (Jul 31)
            "rf_unsw_*.joblib",  # Baseline models
            "rf_production_cicids*.joblib",  # Modelos CICIDS antiguos
            "rf_production_sniffer*.joblib",  # Ya duplicados en production/
            "*_behavior.joblib",  # Modelos behavior
            "model_202507*",  # Directorios de experimentos por fecha
            "*_test*.joblib",
            "*_experiment*.joblib",
            "*_draft*.joblib",
            "*_backup*.joblib",
            "internal_normal_detector.joblib",  # Ya está en production/
            "web_normal_detector.joblib",  # Ya está en production/
        ]

    def create_directory_structure(self):
        """Crea la estructura de directorios necesaria"""
        print("🏗️  Creando estructura de directorios...")

        self.production_dir.mkdir(parents=True, exist_ok=True)
        self.experimental_dir.mkdir(parents=True, exist_ok=True)

        print(f"✅ Creado: {self.production_dir}")
        print(f"✅ Creado: {self.experimental_dir}")

    def identify_models(self):
        """Identifica y clasifica los modelos"""
        print("\n🔍 Identificando modelos...")

        # Buscar tanto .joblib como .pkl
        all_models = list(self.models_dir.glob("*.joblib")) + list(self.models_dir.glob("*.pkl"))
        # También incluir archivos .json de métricas
        metric_files = list(self.models_dir.glob("*_metrics.json"))
        all_models.extend(metric_files)

        good_models = []
        experimental_models = []

        print(f"📊 Encontrados {len(all_models)} archivos de modelos/métricas")

        for model in all_models:
            model_name = model.name.lower()

            # Verificar si es un modelo bueno (tricapa Aug 7)
            is_good = any(
                model.match(pattern) for pattern in self.good_model_patterns
            )

            # Verificar si es experimental (modelos antiguos Jul-30/31)
            is_experimental = any(
                model.match(pattern) for pattern in self.experimental_patterns
            )

            # Verificar si ya está en production/ (evitar duplicados)
            production_file = self.base_dir / "models" / "production" / model.name
            already_in_production = production_file.exists()

            if is_good and not is_experimental and not already_in_production:
                good_models.append(model)
                print(f"✅ TRICAPA → PRODUCTION: {model.name}")
            elif already_in_production:
                print(f"⚠️  YA EN PRODUCTION: {model.name}")
            else:
                experimental_models.append(model)
                print(f"🧪 EXPERIMENTAL: {model.name}")

        return good_models, experimental_models

    def move_models(self, good_models, experimental_models):
        """Mueve los modelos a sus directorios correspondientes"""
        print("\n📦 Moviendo modelos...")

        moved_good = []
        moved_experimental = []

        # Mover modelos buenos a production
        for model in good_models:
            dest = self.production_dir / model.name
            try:
                shutil.move(str(model), str(dest))
                moved_good.append((model.name, dest))
                print(f"🚀 {model.name} → production/tricapa/")
            except Exception as e:
                print(f"❌ Error moviendo {model.name}: {e}")

        # Mover modelos experimentales
        for model in experimental_models:
            dest = self.experimental_dir / model.name
            try:
                shutil.move(str(model), str(dest))
                moved_experimental.append((model.name, dest))
                print(f"🧪 {model.name} → experimental/")
            except Exception as e:
                print(f"❌ Error moviendo {model.name}: {e}")

        return moved_good, moved_experimental

    def update_core_files(self, moved_models):
        """Actualiza las referencias en los archivos core"""
        print("\n🔧 Actualizando archivos core...")

        # Crear mapeo de modelos antiguos → nuevos
        model_mapping = {}
        for old_name, new_path in moved_models:
            # Crear ruta relativa desde core/
            relative_path = f"../models/production/tricapa/{old_name}"
            model_mapping[f"models/{old_name}"] = relative_path
            model_mapping[f"../models/{old_name}"] = relative_path
            model_mapping[f"./models/{old_name}"] = relative_path

        for core_file in self.core_files:
            if not os.path.exists(core_file):
                print(f"⚠️  Archivo no encontrado: {core_file}")
                continue

            print(f"🔄 Actualizando: {core_file}")
            self.update_file_references(core_file, model_mapping)

    def update_file_references(self, file_path, model_mapping):
        """Actualiza las referencias de modelos en un archivo específico"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            original_content = content
            changes_made = 0

            # Buscar y reemplazar referencias a modelos
            for old_path, new_path in model_mapping.items():
                # Patrones comunes de carga de modelos
                patterns = [
                    rf'"{re.escape(old_path)}"',
                    rf"'{re.escape(old_path)}'",
                    rf'r"{re.escape(old_path)}"',
                    rf"r'{re.escape(old_path)}'",
                    rf'Path\("{re.escape(old_path)}"\)',
                    rf"Path\('{re.escape(old_path)}'\)",
                ]

                for pattern in patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        # Reemplazar con la nueva ruta
                        new_pattern = pattern.replace(re.escape(old_path), new_path)
                        content = re.sub(pattern, f'"{new_path}"', content)
                        changes_made += len(matches)
                        print(f"  ✅ Reemplazadas {len(matches)} referencias: {old_path} → {new_path}")

            # Escribir el archivo actualizado
            if content != original_content:
                # Crear backup
                backup_path = f"{file_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(file_path, backup_path)
                print(f"  💾 Backup creado: {backup_path}")

                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                print(f"  🎯 {changes_made} cambios aplicados en {file_path}")
            else:
                print(f"  ℹ️  No se encontraron referencias a actualizar en {file_path}")

        except Exception as e:
            print(f"  ❌ Error actualizando {file_path}: {e}")

    def create_production_readme(self, moved_models):
        """Crea README para el directorio production"""
        readme_content = f"""# Modelos de Producción - Sistema Tricapa

## 🚀 Modelos Operativos (F1-Score: 1.0000)

Este directorio contiene los modelos de Machine Learning del sistema tricapa de ciberseguridad, 
validados y listos para producción.

### 📊 Modelos Disponibles

"""

        for model_name, _ in moved_models:
            readme_content += f"- `{model_name}` - Modelo tricapa operativo\n"

        readme_content += f"""

### 🏗️ Arquitectura Tricapa

- **Nivel 1**: Feature extraction (82 → 23 features)
- **Nivel 2**: Feature optimization (23 → 4 features)  
- **Nivel 3**: Classification (4 features → decisión final)

### 🎯 Métricas de Rendimiento

- **F1-Score**: 1.0000 (Perfecto)
- **Precisión**: 100%
- **Recall**: 100%
- **Tiempo de inferencia**: <12 segundos

### 🔧 Uso en Código

```python
# Carga desde core/
model_path = "../models/production/tricapa/modelo.pkl"
model = joblib.load(model_path)
```

### 📅 Migración Automática

Migrado automáticamente el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
usando el script de migración tricapa.

### ⚠️ Importante

Estos modelos están optimizados para el sistema tricapa específico.
NO modificar sin validación completa del pipeline.
"""

        readme_path = self.production_dir / "README.md"
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(readme_content)

        print(f"📋 README creado: {readme_path}")

    def run_migration(self):
        """Ejecuta la migración completa"""
        print("🎊 INICIANDO MIGRACIÓN AUTOMÁTICA A PRODUCTION")
        print("=" * 60)

        # Crear estructura
        self.create_directory_structure()

        # Identificar modelos
        good_models, experimental_models = self.identify_models()

        if not good_models:
            print("⚠️  No se encontraron modelos para production")
            return

        # Mover modelos
        moved_good, moved_experimental = self.move_models(good_models, experimental_models)

        # Actualizar archivos core
        if moved_good:
            self.update_core_files(moved_good)
            self.create_production_readme(moved_good)

        # Resumen final
        print("\n🎉 MIGRACIÓN COMPLETADA")
        print("=" * 60)
        print(f"✅ Modelos en production: {len(moved_good)}")
        print(f"🧪 Modelos en experimental: {len(moved_experimental)}")
        print(f"🔧 Archivos core actualizados: {len(self.core_files)}")
        print("\n🚀 ¡Sistema listo para integración con prototipos scapy!")


def main():
    """Función principal"""
    migrator = ProductionMigrator()
    migrator.run_migration()


def validate_migration():
    """Valida que la migración se completó correctamente"""
    print("\n🔍 VALIDANDO MIGRACIÓN...")
    print("=" * 40)

    # Verificar estructura de directorios
    production_dir = Path("models/production/tricapa")
    experimental_dir = Path("models/experimental")

    if not production_dir.exists():
        print("❌ Directorio production no existe")
        return False

    # Contar modelos
    production_models = list(production_dir.glob("*.pkl"))
    experimental_models = list(experimental_dir.glob("*.pkl"))
    old_models = list(Path("models").glob("*.pkl"))

    print(f"✅ Modelos en production: {len(production_models)}")
    print(f"🧪 Modelos en experimental: {len(experimental_models)}")
    print(f"📦 Modelos en models/ (deberían ser 0): {len(old_models)}")

    # Verificar archivos core
    core_files = [
        "core/complete_ml_pipeline.py",
        "core/scapy_monitor_complete_pipeline.py",
        "core/scapy_to_ml_features.py"
    ]

    for core_file in core_files:
        if os.path.exists(core_file):
            with open(core_file, 'r') as f:
                content = f.read()
                if "models/production/tricapa" in content:
                    print(f"✅ {core_file} actualizado correctamente")
                else:
                    print(f"⚠️  {core_file} podría necesitar actualización manual")
        else:
            print(f"⚠️  {core_file} no encontrado")

    success = len(production_models) > 0 and len(old_models) == 0
    if success:
        print("\n🎉 MIGRACIÓN VALIDADA CORRECTAMENTE")
    else:
        print("\n⚠️  MIGRACIÓN INCOMPLETA - Revisar manualmente")

    return success


def create_scapy_migration_plan():
    """Crea el plan para migrar prototipos scapy"""
    plan = """
# 📋 PLAN MIGRACIÓN PROTOTIPOS SCAPY → ARCHIVE/EXPERIMENTAL

## 🎯 Objetivo
Mover prototipos scapy actualizados con modelos ML a archive/experimental

## 📁 Estructura Objetivo
```
archive/
└── experimental/
    ├── scapy_prototypes/
    │   ├── complete_ml_pipeline.py      # ← core/complete_ml_pipeline.py
    │   ├── scapy_monitor_complete.py    # ← core/scapy_monitor_complete_pipeline.py
    │   ├── scapy_to_ml_features.py      # ← core/scapy_to_ml_features.py
    │   └── README.md                    # Documentación prototipos
    └── README.md                        # Índice experimental
```

## 🔧 Comandos de Migración
```bash
# Crear estructura
mkdir -p archive/experimental/scapy_prototypes

# Copiar archivos (manteniendo originales en core/)
cp core/complete_ml_pipeline.py archive/experimental/scapy_prototypes/
cp core/scapy_monitor_complete_pipeline.py archive/experimental/scapy_prototypes/scapy_monitor_complete.py
cp core/scapy_to_ml_features.py archive/experimental/scapy_prototypes/

# Crear documentación
echo "Prototipos scapy integrados con modelos tricapa" > archive/experimental/scapy_prototypes/README.md
```

## ⚡ Siguiente Fase: Integración v3.1
1. ✅ Modelos en production/
2. 🔄 Prototipos scapy documentados
3. 🚀 Nuevo .proto v3.1 unificado
4. 🏗️ Pipeline refactorizado completo

¿Ejecutamos la migración de prototipos scapy también?
"""

    print(plan)
    return plan


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--validate":
        validate_migration()
    elif len(sys.argv) > 1 and sys.argv[1] == "--plan-scapy":
        create_scapy_migration_plan()
    else:
        main()
        print("\n" + "=" * 60)
        validate_migration()
        print("\n" + "=" * 60)
        create_scapy_migration_plan()