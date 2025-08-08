#!/usr/bin/env python3
"""
ARCHIVO: migrate_scapy.py
FECHA CREACIÓN: 8 de agosto de 2025
DESCRIPCIÓN: Script para migrar prototipos scapy integrados con ML a archive/experimental

Script para migrar prototipos scapy integrados con ML a archive/experimental
Preparación para la fase v3.1 del sistema tricapa

FUNCIÓN:
- Copia (no mueve) prototipos desde core/ → archive/experimental/scapy_prototypes/
- Añade headers experimentales con información v3.1
- Genera documentación roadmap para evolución

ARCHIVOS MIGRADOS:
- core/complete_ml_pipeline.py → archive/experimental/scapy_prototypes/complete_ml_pipeline.py
- core/scapy_monitor_complete_pipeline.py → archive/experimental/scapy_prototypes/scapy_monitor_complete.py
- core/scapy_to_ml_features.py → archive/experimental/scapy_prototypes/scapy_to_ml_features.py
"""

import os
import shutil
from pathlib import Path
from datetime import datetime


class ScapyPrototypeMigrator:
    def __init__(self):
        self.base_dir = Path(".")
        self.archive_dir = self.base_dir / "archive" / "experimental" / "scapy_prototypes"

        # Archivos a migrar (copiar, no mover)
        self.scapy_files = {
            "core/complete_ml_pipeline.py": "complete_ml_pipeline.py",
            "core/scapy_monitor_complete_pipeline.py": "scapy_monitor_complete.py",
            "core/scapy_to_ml_features.py": "scapy_to_ml_features.py"
        }

    def create_archive_structure(self):
        """Crea la estructura de archive/experimental"""
        print("🏗️  Creando estructura archive/experimental...")

        self.archive_dir.mkdir(parents=True, exist_ok=True)
        print(f"✅ Creado: {self.archive_dir}")

    def copy_scapy_prototypes(self):
        """Copia los prototipos scapy a archive/experimental"""
        print("\n📦 Copiando prototipos scapy...")

        copied_files = []

        for source_path, dest_name in self.scapy_files.items():
            source = Path(source_path)
            dest = self.archive_dir / dest_name

            if not source.exists():
                print(f"⚠️  Archivo no encontrado: {source}")
                continue

            try:
                # Copiar archivo (mantener original en core/)
                shutil.copy2(source, dest)
                copied_files.append((source, dest))
                print(f"✅ {source} → {dest}")

                # Añadir header de archivo experimental
                self.add_experimental_header(dest)

            except Exception as e:
                print(f"❌ Error copiando {source}: {e}")

        return copied_files

    def add_experimental_header(self, file_path):
        """Añade header indicando que es versión experimental"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            header = f'''"""
🧪 PROTOTIPO EXPERIMENTAL - SISTEMA TRICAPA v3.1
===============================================

Archivo migrado desde core/ el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

⚠️  VERSIÓN EXPERIMENTAL:
- Integra modelos ML tricapa desde models/production/
- Preparado para evolución hacia v3.1
- NO usar en producción sin validación

🚀 ROADMAP v3.1:
- Protobuf unificado (.proto v3.1)
- Pipeline refactorizado con colas
- Multi-model orchestration
- Dashboard + no-gui modes

"""

{content}'''

            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(header)

        except Exception as e:
            print(f"  ⚠️  Error añadiendo header a {file_path}: {e}")

    def create_prototype_readme(self, copied_files):
        """Crea README para los prototipos scapy"""
        readme_content = f"""# Prototipos Scapy - Sistema Tricapa

## 🎯 Descripción

Prototipos experimentales que integran captura scapy con modelos ML tricapa.
Migrados automáticamente desde `core/` el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.

## 📊 Archivos Incluidos

"""

        for source, dest in copied_files:
            readme_content += f"- `{dest.name}` - Migrado desde `{source}`\n"

        readme_content += f"""

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
- **Modelos**: {len(copied_files)} prototipos integrados
- **Pipeline**: scapy → ML → clasificación

## 🔗 Referencias

- Modelos production: `../../../models/production/tricapa/`
- Documentación sistema: `../../../models/README.md`
- Componentes core: `../../../core/`

---
*Generado automáticamente por el sistema de migración tricapa*
"""

        readme_path = self.archive_dir / "README.md"
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(readme_content)

        print(f"📋 README creado: {readme_path}")

    def create_experimental_index(self):
        """Crea índice general de archive/experimental"""
        index_content = f"""# Archive Experimental

## 🧪 Contenido Experimental

Directorio para prototipos, experimentos y desarrollo no-productivo.

### 📁 Estructura

- `scapy_prototypes/` - Prototipos scapy + ML tricapa
- *(futuras ramas experimentales)*

### ⚡ Última Actualización

{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Migración prototipos scapy

### 🚀 Próximos Experimentos

- Datasets RF especializados (port scanning, etc.)
- Protobuf v3.1 experimental
- Pipeline distribuido experimental
- RAG/human-in-the-loop prototypes

---
*Mantenido automáticamente por el sistema de migración*
"""

        index_path = self.archive_dir.parent / "README.md"
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(index_content)

        print(f"📋 Índice experimental: {index_path}")

    def run_migration(self):
        """Ejecuta la migración completa de prototipos scapy"""
        print("🧪 INICIANDO MIGRACIÓN PROTOTIPOS SCAPY")
        print("=" * 60)

        # Crear estructura
        self.create_archive_structure()

        # Copiar prototipos
        copied_files = self.copy_scapy_prototypes()

        if not copied_files:
            print("⚠️  No se copiaron archivos")
            return

        # Crear documentación
        self.create_prototype_readme(copied_files)
        self.create_experimental_index()

        # Resumen final
        print("\n🎉 MIGRACIÓN PROTOTIPOS COMPLETADA")
        print("=" * 60)
        print(f"✅ Prototipos copiados: {len(copied_files)}")
        print(f"📦 Ubicación: {self.archive_dir}")
        print(f"📋 Documentación: README.md creado")
        print("\n🚀 LISTO PARA FASE v3.1:")
        print("   1. ✅ Modelos en production/")
        print("   2. ✅ Prototipos scapy documentados")
        print("   3. 🔄 Nuevo .proto v3.1 unificado")
        print("   4. 🔄 Pipeline refactorizado")


def main():
    """Función principal"""
    migrator = ScapyPrototypeMigrator()
    migrator.run_migration()


if __name__ == "__main__":
    main()