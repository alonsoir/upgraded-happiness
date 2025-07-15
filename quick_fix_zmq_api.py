# quick_fix_zmq_api.py - Corrección inmediata para API ZMQ incorrecta

import re
import sys
import os
from typing import List, Tuple


class ZMQAPIFixer:
    """
    Corrige automáticamente los errores de API ZMQ en el código
    """

    def __init__(self):
        # Mapeo de métodos incorrectos a correctos
        self.corrections = [
            # socket.set_hwm() → socket.setsockopt(zmq.HWM, value)
            (r'(\w+)\.set_hwm\(([^)]+)\)', r'\1.setsockopt(zmq.HWM, \2)'),

            # socket.set_linger() → socket.setsockopt(zmq.LINGER, value)
            (r'(\w+)\.set_linger\(([^)]+)\)', r'\1.setsockopt(zmq.LINGER, \2)'),

            # socket.set_sndhwm() → socket.setsockopt(zmq.SNDHWM, value)
            (r'(\w+)\.set_sndhwm\(([^)]+)\)', r'\1.setsockopt(zmq.SNDHWM, \2)'),

            # socket.SNDTIMEO = value → socket.setsockopt(zmq.SNDTIMEO, value)
            (r'(\w+)\.SNDTIMEO\s*=\s*([^;\n]+)', r'\1.setsockopt(zmq.SNDTIMEO, \2)'),

            # socket.RCVTIMEO = value → socket.setsockopt(zmq.RCVTIMEO, value)
            (r'(\w+)\.RCVTIMEO\s*=\s*([^;\n]+)', r'\1.setsockopt(zmq.RCVTIMEO, \2)'),

            # self.running = True en shutdown → self.running = False
            (r'def shutdown\([^)]*\):[^}]*self\.running\s*=\s*True', self._fix_shutdown_running)
        ]

    def _fix_shutdown_running(self, match):
        """Corrección específica para self.running = True en shutdown"""
        text = match.group(0)
        return text.replace('self.running = True', 'self.running = False')

    def fix_file(self, filepath: str) -> Tuple[bool, List[str]]:
        """
        Corrige un archivo específico
        Returns: (success, list_of_changes)
        """
        print(f"🔧 Corrigiendo {filepath}...")

        if not os.path.exists(filepath):
            return False, [f"❌ Archivo no existe: {filepath}"]

        # Leer archivo
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            return False, [f"❌ Error leyendo archivo: {e}"]

        # Aplicar correcciones
        changes = []
        original_content = content

        for pattern, replacement in self.corrections:
            if callable(replacement):
                # Función de reemplazo personalizada
                matches = list(re.finditer(pattern, content, re.DOTALL))
                for match in reversed(matches):  # Reverse para no alterar índices
                    old_text = match.group(0)
                    new_text = replacement(match)
                    if old_text != new_text:
                        content = content[:match.start()] + new_text + content[match.end():]
                        changes.append(f"✅ Corregido shutdown: self.running = True → False")
            else:
                # Reemplazo con regex normal
                new_content, count = re.subn(pattern, replacement, content)
                if count > 0:
                    content = new_content
                    changes.append(f"✅ {count} correcciones de patrón: {pattern}")

        # Verificar si hubo cambios
        if content == original_content:
            return True, ["ℹ️ No se necesitaron correcciones"]

        # Crear backup
        backup_path = f"{filepath}.backup"
        try:
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(original_content)
            changes.append(f"💾 Backup creado: {backup_path}")
        except Exception as e:
            changes.append(f"⚠️ No se pudo crear backup: {e}")

        # Escribir archivo corregido
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            changes.append(f"✅ Archivo corregido y guardado")
            return True, changes
        except Exception as e:
            return False, changes + [f"❌ Error escribiendo archivo: {e}"]

    def fix_project(self, project_dir: str = ".") -> bool:
        """
        Corrige todos los archivos Python del proyecto
        """
        print("🔧 CORRECCIÓN AUTOMÁTICA API ZMQ")
        print("=" * 40)

        # Buscar archivos Python
        python_files = []
        for root, dirs, files in os.walk(project_dir):
            for file in files:
                if file.endswith('.py') and not file.startswith('.'):
                    python_files.append(os.path.join(root, file))

        if not python_files:
            print("❌ No se encontraron archivos Python")
            return False

        print(f"📁 Encontrados {len(python_files)} archivos Python")

        total_success = True
        total_changes = 0

        for filepath in python_files:
            success, changes = self.fix_file(filepath)

            if success:
                print(f"\n✅ {os.path.basename(filepath)}:")
                for change in changes:
                    print(f"   {change}")
                    if "correcciones" in change.lower():
                        total_changes += 1
            else:
                print(f"\n❌ {os.path.basename(filepath)}:")
                for change in changes:
                    print(f"   {change}")
                total_success = False

        print(f"\n📊 Resumen:")
        print(f"   📄 Archivos procesados: {len(python_files)}")
        print(f"   🔧 Archivos con correcciones: {total_changes}")
        print(f"   {'✅ Éxito' if total_success else '❌ Errores encontrados'}")

        return total_success


def main():
    """Función principal"""
    print("🚀 ZMQ API Quick Fix Tool")
    print("Corrige automáticamente errores de API ZMQ en upgraded-happiness")
    print("-" * 60)

    fixer = ZMQAPIFixer()

    if len(sys.argv) > 1:
        # Corregir archivo específico
        filepath = sys.argv[1]
        success, changes = fixer.fix_file(filepath)

        print(f"\n📋 Resultado para {filepath}:")
        for change in changes:
            print(f"   {change}")

        if success:
            print(f"\n✅ {filepath} corregido exitosamente")
            print("🚀 Ahora puedes ejecutar:")
            print(f"   python {filepath} enhanced_agent_config.json")
        else:
            print(f"\n❌ Error corrigiendo {filepath}")

        return success
    else:
        # Corregir todo el proyecto
        success = fixer.fix_project()

        if success:
            print(f"\n🎉 ¡Proyecto corregido exitosamente!")
            print("🚀 Comandos listos para ejecutar:")
            print("   python promiscuous_agent.py enhanced_agent_config.json")
            print("   python geoip_enricher.py geoip_config.json")
        else:
            print(f"\n💥 Errores encontrados - revisar manualmente")

        return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)