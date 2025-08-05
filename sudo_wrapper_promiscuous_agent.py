import os
import sys
import getpass
import subprocess

# Configuración
SCRIPT_PATH = os.path.abspath("core/promiscuous_agent.py")
CONFIG_PATH = os.path.abspath("config/json/enhanced_agent_config.json")
VENV_PYTHON = os.path.abspath("upgraded_happiness_venv/bin/python")

def main():
    if os.geteuid() != 0:
        print("⏩ Elevando a root con sudo -S... (pide contraseña)")
        password = getpass.getpass("🔐 Introduce la contraseña de root: ")

        # Construir comando
        cmd = ["sudo", "-S", VENV_PYTHON, SCRIPT_PATH, CONFIG_PATH]

        print(f"👉 Ejecutando: {' '.join(cmd)}\n")

        try:
            subprocess.run(cmd, input=password + "\n", text=True)
        except Exception as e:
            print(f"❌ Error al ejecutar con sudo: {e}")

    else:
        print("✅ Ya estamos como root. Ejecutando directamente...")
        os.execv(VENV_PYTHON, [VENV_PYTHON, SCRIPT_PATH, CONFIG_PATH])

if __name__ == "__main__":
    main()
