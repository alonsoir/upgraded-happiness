# 🛡️ Upgraded Happiness - Advanced Network Security & ML Detection System

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![ML Pipeline](https://img.shields.io/badge/ML-Pipeline-brightgreen.svg)]()
[![Network Security](https://img.shields.io/badge/Network-Security-red.svg)]()
[![Real-time Detection](https://img.shields.io/badge/Detection-Real--time-orange.svg)]()

---

## 🎯 Misión del Proyecto

**Upgraded Happiness** es un sistema avanzado de detección de amenazas de red que combina técnicas de Machine Learning, análisis de tráfico en tiempo real y capacidades de firewall inteligente para crear una defensa multicapa contra amenazas de red.

---

## 🏆 Hito Alcanzado - Q3 2025

✅ **Sistema de Detección Tricapa Operativo**:  
Tres modelos especializados operan en conjunto:  
- 🚨 Detector de Ataques (ataque/no ataque)  
- 🌐 Detector de Tráfico Web Normal  
- 🏢 Detector de Tráfico Interno Normal  

✅ **Sniffer/ML Detector Integrado**:  
Captura, extrae features y procesa en tiempo real para detección precisa.

✅ **Pipeline Propio de Datos Reales**:  
Superamos problemas de datasets corruptos creando un flujo confiable basado en tráfico real.

---

## 🏗️ Arquitectura y Organización Actualizada

### 🧠 Componentes Core

- `core/` contiene los módulos base:
  - `lightweight_ml_detector.py`  
  - `simple_firewall_agent.py`  
  - `geoip_enricher.py`  
  - `promiscuous_agent.py` y `promiscuous_agent_v2.py`  
  - `enhanced_network_feature_extractor.py`  
  - `fixed_service_sniffer.py`  

### 🤖 Pipeline de Machine Learning

- `ml_pipeline/trainers/`  
  - Entrenamiento y reentrenamiento de modelos  
- `ml_pipeline/analyzers/`  
  - Análisis, validación y extracción de features  
- `ml_pipeline/data_generators/`  
  - Generación de datasets a partir de tráfico real y sintético  

### 📁 Procesamiento y Datos

- `data_pipeline/` para procesar datasets oficiales y generar los datasets limpios usados en ML.  
- `models/` con subcarpetas `production/` y `archive/` para modelos entrenados.  
- `config/` centraliza todas las configuraciones JSON.  
- `logs/` para registros y trazas.  
- `docs/` con documentación técnica y roadmap.  

---

## 🚀 Inicio Rápido

### Requisitos

```bash
pip install -r requirements.txt
sudo setcap cap_net_raw+ep $(which python3)

Configuración

make setup
make check-deps
make check-geoip

Ejecución

make dev-start       # Todos los componentes en modo desarrollo
make start-core      # Componentes principales corriendo
make start-advanced  # Sistema completo con funcionalidades avanzadas


Dashboard disponible en http://localhost:8080

📊 Modelos en Producción

| Modelo                                    | Propósito                | Tamaño | Estado   |
| ----------------------------------------- | ------------------------ | ------ | -------- |
| `rf_production_sniffer_compatible.joblib` | Detección de ataques     | 10.1MB | ✅ Activo |
| `web_normal_detector.joblib`              | Tráfico web legítimo     | 2.5MB  | ✅ Activo |
| `internal_normal_detector.joblib`         | Tráfico interno legítimo | 2.3MB  | ✅ Activo |


🔜 Próximos Pasos (Q4 2025 - RELEASE 1.0.0)
Integrar protocolo Protobuf v3.1 con cifrado y compresión opcionales
Desarrollo de sistema distribuido con clave rotativa (etcd)
Contenerización con K3s/Docker y perfiles de seguridad (AppArmor)
Implementación del módulo RAG conversacional para detección avanzada
Auto-reentrenamiento continuo con datos generados internamente
Mejoras UI y monitorización extendida

⚙️ Configuración y Variables de Entorno
Variables recomendadas:

export GEOIP_DB_PATH="./GeoLite2-City.mmdb"
export ML_MODEL_PATH="./models/"
export LOG_LEVEL="INFO"
export IPAPI_TOKEN="tu_token_ipapi"

🔧 Comandos Make Útiles
Operación

make start
make stop
make restart
make status


Desarrollo

make dev-start
make debug
make test
make clean

Monitorización

make monitor
make logs
make logs-tail

🤝 Contribución
Fork del repositorio
Crear rama: git checkout -b feature/nueva-funcionalidad
Commit y push
Pull request describiendo cambios
Se requiere cumplir con PEP8, pruebas unitarias y documentación.

📚 Documentación Complementaria
ROADMAP.md
refactor_plan.md
Carpeta docs/ para documentación técnica detallada

🐛 Issues Actuales
Optimización de memoria para grandes datasets
Mejora del dashboard web
Soporte completo para IPv6
Integración con sistemas SIEM externos
Integracion con un sistema RAG
Integracion con k3s/docker para el modo distribuido
Integracion con el sistema evolutivo de modelos. (Próximamente)

📄 Licencia
Proyecto licenciado bajo Licencia Blanca & Marcos (LBM-1.0), basada en MIT con cláusulas éticas adicionales. 
Ver archivo LICENSE_LBM.txt.

👥 Equipo Principal
Alonso Isidoro - Lead Developer & ML Engineer
Contributors - ver contributors

🙏 Agradecimientos
Gracias a la comunidad de seguridad y ML, proyectos open source y colaboradores que hacen esto posible.

📌 Comparación con Suricata y Snort
Este proyecto se parece a Suricata y Snort, pero con diferencias notables.
Upgraded Happiness trata de averiguar lo ocurrido en una red distribuida usando agentes ligeros distribuidos y modelos 
neuronales basados inicialmente en Random Forest con reentrenamiento regular usando datos del sistema en vivo. 
La idea es que el sistema aprenda a reconocer actividades ilícitas a través de firmas digitales en forma de paquetes 
TCP/IP, UDP u otros datagramas que fluyan por la red.

## Comparativa con otras soluciones IDS/Monitorización

En el ecosistema de la ciberseguridad existen varias herramientas ampliamente conocidas para detección y monitorización de amenazas, como **Suricata**, **Snort** y **Sysdig/Falco**. Nuestro sistema, **Upgraded Happiness Network Security System**, se diferencia en varios aspectos clave, lo que aporta ventajas importantes para entornos distribuidos y basados en Machine Learning.

| Característica               | Suricata / Snort                              | Sysdig / Falco                                  | Upgraded Happiness (Nuestro sistema)             |
|-----------------------------|-----------------------------------------------|------------------------------------------------|--------------------------------------------------|
| **Tipo de herramienta**      | IDS/IPS tradicional basado en reglas y firmas| Monitorización host y contenedores basada en reglas y auditoría | IDS distribuido con agentes ligeros y ML integrado |
| **Arquitectura**             | Centralizado o con sensores perimetrales      | Centralizado o con agentes, no orquestación distribuida real | Sistema distribuido con orquestación, cifrado y sincronización de reglas y modelos |
| **Captura y análisis**       | Captura activa de paquetes TCP/IP, análisis profundo | Auditoría de llamadas al sistema y comportamiento de procesos | Captura activa de paquetes, análisis ML en tiempo real, enriquecimiento GeoIP |
| **Modelo de detección**      | Basado en reglas y firmas definidas           | Basado en reglas para eventos de sistema       | Modelos Machine Learning (Random Forest y futuros DL), scoring en tiempo real |
| **Actualización y aprendizaje** | Actualización manual o automatizada de reglas | Actualización manual de reglas                  | Reentrenamiento automático y actualización distribuida de modelos y firewalls |
| **Seguridad y comunicación**| Comunicación estándar, sin cifrado avanzado   | Comunicación estándar, sin cifrado avanzado     | Comunicación cifrada, con compresión y gestión de claves en memoria (ETCD) |
| **Distribución y escalabilidad** | Limitado a despliegues centralizados o sensores distribuidos sin sincronización | Similar a Suricata/Snort, no diseñado para mallas dinámicas | Arquitectura distribuida nativa, con sincronización dinámica y baja latencia |
| **Integración con ML**       | No integrada nativamente                       | No integrada nativamente                         | Integración nativa y centralizada de pipelines ML completos |
| **Enfoque principal**        | Defensa perimetral basada en firmas            | Auditoría y monitorización de comportamiento    | Defensa proactiva, detección temprana y reacción automática en red distribuida |

---

### Conclusión

- **Suricata y Snort** son IDS/IPS clásicos potentes para análisis de tráfico de red basados en firmas y reglas.  
- **Sysdig y Falco** ofrecen monitorización profunda a nivel host/contenedor con reglas orientadas a llamadas sistema y comportamientos, pero sin una arquitectura distribuida ni ML nativo.  
- **Upgraded Happiness** propone un enfoque innovador y distribuido, con agentes ligeros que capturan y analizan tráfico en tiempo real, integrando ML, cifrado y sincronización rápida para detectar y reaccionar ante amenazas emergentes en una red distribuida.

Esta arquitectura permite superar limitaciones de sistemas centralizados y brinda capacidad de adaptación y aprendizaje continuo para escenarios complejos y cambiantes.

---

Creemos que esta aproximación proactiva basada en detección temprana y scoring de amenazas con redes evolutivas es 
novedosa, y puede solventar en teoría, al análisis tradicional de logs que pueden ser modificados o manipulados antes 
del parsing. 
Nuestra aproximación captura paquetes, geolocaliza ips peligrosas y permite actuar muy rápido sobre los firewalls de los 
nodos afectados, habilitando una defensa perimetral mucho más efectiva.
Idealmente, esta solucion se puede integrar con multiples IDS/IPS.

⭐ Si este proyecto te es útil, por favor danos una estrella ⭐
Última actualización: Agosto 2025 - Housekeeping y reorganización