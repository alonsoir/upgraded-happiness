#!/usr/bin/env python3
"""
Analizador del Proyecto Upgraded Happiness
==========================================
Identifica qué código es esencial, qué es duplicado, y qué se puede eliminar
"""

import ast
import json
import os
import re
from collections import defaultdict
from pathlib import Path


class ProjectAnalyzer:
    def __init__(self, project_root="."):
        self.project_root = Path(project_root)
        self.analysis = {
            "python_files": [],
            "fix_scripts": [],
            "backup_files": [],
            "essential_files": [],
            "duplicated_functions": {},
            "imports_analysis": {},
            "file_dependencies": {},
            "recommendations": [],
        }

    def analyze(self):
        """Ejecuta análisis completo del proyecto"""
        print("🔍 Analizando proyecto Upgraded Happiness...")

        self._scan_files()
        self._analyze_fix_scripts()
        self._analyze_dependencies()
        self._analyze_duplicates()
        self._generate_recommendations()

        return self.analysis

    def _scan_files(self):
        """Escanea todos los archivos del proyecto"""
        for file_path in self.project_root.rglob("*.py"):
            rel_path = file_path.relative_to(self.project_root)

            # Categorizar archivos
            if "fix_" in file_path.name or "patch_" in file_path.name:
                self.analysis["fix_scripts"].append(str(rel_path))
            elif ".backup" in file_path.name or ".quick" in file_path.name:
                self.analysis["backup_files"].append(str(rel_path))
            elif file_path.name in [
                "system_orchestrator.py",
                "lightweight_ml_detector.py",
            ]:
                self.analysis["essential_files"].append(str(rel_path))
            else:
                self.analysis["python_files"].append(str(rel_path))

    def _analyze_fix_scripts(self):
        """Analiza todos los scripts fix_* para ver qué hacen"""
        fix_analysis = {}

        for script_path in self.analysis["fix_scripts"]:
            full_path = self.project_root / script_path
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Extraer funciones y propósito
                functions = re.findall(r"def (\w+)", content)
                imports = re.findall(r"import (\w+)", content) + re.findall(
                    r"from (\w+) import", content
                )

                # Buscar descripción/propósito
                purpose = "Unknown"
                if '"""' in content:
                    doc_match = re.search(r'"""(.*?)"""', content, re.DOTALL)
                    if doc_match:
                        purpose = doc_match.group(1).strip()[:100]

                fix_analysis[script_path] = {
                    "functions": functions,
                    "imports": imports,
                    "purpose": purpose,
                    "size": len(content),
                    "last_modified": full_path.stat().st_mtime,
                }

            except Exception as e:
                fix_analysis[script_path] = {"error": str(e)}

        self.analysis["fix_scripts_analysis"] = fix_analysis

    def _analyze_dependencies(self):
        """Analiza dependencias entre archivos"""
        for py_file in self.analysis["python_files"] + self.analysis["essential_files"]:
            full_path = self.project_root / py_file
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read())

                imports = []
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports.append(alias.name)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            imports.append(node.module)

                self.analysis["imports_analysis"][py_file] = imports

            except Exception as e:
                self.analysis["imports_analysis"][py_file] = [f"Error: {e}"]

    def _analyze_duplicates(self):
        """Busca funciones duplicadas entre archivos"""
        function_locations = defaultdict(list)

        # Buscar todas las funciones
        all_files = (
            self.analysis["python_files"]
            + self.analysis["essential_files"]
            + self.analysis["fix_scripts"]
        )

        for py_file in all_files:
            full_path = self.project_root / py_file
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    content = f.read()

                functions = re.findall(r"def (\w+)", content)
                for func in functions:
                    function_locations[func].append(py_file)

            except Exception:
                continue

        # Identificar duplicados
        for func_name, locations in function_locations.items():
            if len(locations) > 1:
                self.analysis["duplicated_functions"][func_name] = locations

    def _generate_recommendations(self):
        """Genera recomendaciones de limpieza"""
        recs = []

        # Recomendar eliminar backups
        if self.analysis["backup_files"]:
            recs.append(
                {
                    "type": "DELETE",
                    "priority": "HIGH",
                    "action": f"Eliminar {len(self.analysis['backup_files'])} archivos backup",
                    "files": self.analysis["backup_files"],
                }
            )

        # Recomendar consolidar fix scripts
        if len(self.analysis["fix_scripts"]) > 5:
            recs.append(
                {
                    "type": "CONSOLIDATE",
                    "priority": "HIGH",
                    "action": f"Consolidar {len(self.analysis['fix_scripts'])} scripts fix_* en un solo módulo",
                    "files": self.analysis["fix_scripts"],
                }
            )

        # Recomendar eliminar duplicados
        if self.analysis["duplicated_functions"]:
            recs.append(
                {
                    "type": "DEDUPLICATE",
                    "priority": "MEDIUM",
                    "action": f"Eliminar {len(self.analysis['duplicated_functions'])} funciones duplicadas",
                    "details": self.analysis["duplicated_functions"],
                }
            )

        self.analysis["recommendations"] = recs

    def print_report(self):
        """Imprime reporte de análisis"""
        print("\n" + "=" * 60)
        print("📊 REPORTE DE ANÁLISIS - UPGRADED HAPPINESS")
        print("=" * 60)

        print(f"\n📁 ARCHIVOS ENCONTRADOS:")
        print(f"   Python files: {len(self.analysis['python_files'])}")
        print(f"   Fix scripts: {len(self.analysis['fix_scripts'])}")
        print(f"   Backup files: {len(self.analysis['backup_files'])}")
        print(f"   Essential files: {len(self.analysis['essential_files'])}")

        print(f"\n🔧 SCRIPTS FIX ANALIZADOS:")
        for script, info in self.analysis.get("fix_scripts_analysis", {}).items():
            if "error" not in info:
                print(f"   📜 {script}")
                print(f"      Funciones: {len(info['functions'])}")
                print(f"      Propósito: {info['purpose'][:50]}...")

        print(f"\n🔄 FUNCIONES DUPLICADAS:")
        for func, locations in self.analysis["duplicated_functions"].items():
            print(f"   ⚠️  {func}: en {len(locations)} archivos")

        print(f"\n🎯 RECOMENDACIONES:")
        for i, rec in enumerate(self.analysis["recommendations"], 1):
            print(f"   {i}. [{rec['priority']}] {rec['action']}")

        print("\n" + "=" * 60)


def main():
    analyzer = ProjectAnalyzer()
    analysis = analyzer.analyze()
    analyzer.print_report()

    # Guardar análisis completo
    with open("project_analysis.json", "w") as f:
        json.dump(analysis, f, indent=2, default=str)

    print(f"\n💾 Análisis guardado en: project_analysis.json")

    return analysis


if __name__ == "__main__":
    main()
