import psutil
import jinja2
import os

# Detectar hardware
cpu_count = psutil.cpu_count(logical=True)
memory_gb = psutil.virtual_memory().total / (1024 ** 3)  # GB

# Configuración según hardware
if cpu_count >= 8 and memory_gb >= 16:  # Máquina potente
    config = {
        "n_estimators": 100,
        "n_jobs": -1,
        "n_clusters": 10,
        "n_init": 10,
        "enable_expensive_models": True,
        "n_neighbors": 20,
        "n_estimators_rf": 50,
        "max_depth": 10
    }
elif cpu_count >= 4 and memory_gb >= 8:  # Máquina media
    config = {
        "n_estimators": 50,
        "n_jobs": -1,
        "n_clusters": 5,
        "n_init": 5,
        "enable_expensive_models": True,
        "n_neighbors": 10,
        "n_estimators_rf": 20,
        "max_depth": 5
    }
else:  # Máquina básica
    config = {
        "n_estimators": 20,
        "n_jobs": 1,
        "n_clusters": 3,
        "n_init": 3,
        "enable_expensive_models": False,
        "n_neighbors": 5,
        "n_estimators_rf": 10,
        "max_depth": 3
    }

# Generar config-ml-trainer.json
env = jinja2.Environment(loader=jinja2.FileSystemLoader("."))
template = env.get_template("config-ml-trainer.j2")
with open("config-ml-trainer.json", "w") as f:
    f.write(template.render(**config))
print("Archivo config-ml-trainer.json generado.")