# Upgraded Happiness - Plataforma SCADA de Ciberseguridad

## 🎯 Descripción

Plataforma completa de ciberseguridad para redes SCADA que combina captura de tráfico en tiempo real, análisis con Machine Learning y comunicación distribuida mediante ZeroMQ. Sistema diseñado para detectar amenazas y anomalías en infraestructuras críticas.

## 🏗️ Arquitectura

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│   Agente        │────│   ZeroMQ     │────│   Dashboard     │
│  Promiscuo      │    │   Broker     │    │  ML Detector    │
│  (Captura)      │    │  (5555/5556) │    │  (Análisis)     │
└─────────────────┘    └──────────────┘    └─────────────────┘
        │                       │                     │
        │              ┌────────▼──────────┐         │
        │              │  Event Store      │         │
        │              │  (Time Series)    │         │
        │              └───────────────────┘         │
        │                                            │
        └──────────────  Feedback Loop  ─────────────┘
```

### 🧩 Componentes Principales

- **🔌 ZeroMQ Broker**: Bus de mensajes de alta performance (puertos 5555/5556)
- **🕵️ Promiscuous Agent**: Captura total de tráfico de red en tiempo real
- **🧠 ML Detector**: 6 algoritmos de Machine Learning para detección de anomalías
- **🎮 System Orchestrator**: Coordinador central con interfaz interactiva
- **📊 Platform Monitor**: Sistema de monitoreo avanzado en tiempo real

## 🚀 Instalación Rápida

### Opción A: Setup Automático (Recomendado)
```bash
# Clona el repositorio
git clone <tu-repo>
cd upgraded-happiness

# Setup completo automático (dependencies + sudoers + verificación)
make setup-production

# Lanzar plataforma completa
make quick-start

# Verificar funcionamiento
make monitor
```

### Opción B: Setup Manual
```bash
# Crear entorno virtual
make setup

# Instalar todas las dependencias
make install-all

# Configurar permisos sudo (necesario para captura promiscua)
make setup-sudo

# Verificar integridad del sistema
make verify

# Lanzar plataforma
make run-daemon
```

## 🎮 Comandos Principales

### 🚀 Arranque de la Plataforma

```bash
# 🌟 RECOMENDADO: Inicio rápido con orden correcto
make quick-start

# Modo daemon (componentes en background)
make run-daemon

# Modo interactivo (orquestador con menú)
make run

# Componentes individuales
make run-broker      # Solo ZeroMQ broker
make run-detector    # Solo ML detector
make run-agent       # Solo agente promiscuo
```

### 📊 Monitoreo y Verificación

```bash
# Verificación completa del sistema
make monitor

# Monitoreo en tiempo real (actualización continua)
make monitor-live

# Estado básico
make status

# Generar tráfico de prueba
make test-traffic
```

### 🛑 Control de la Plataforma

```bash
# Parar todos los componentes
make stop

# Reinicio completo
make stop && make quick-start

# Comandos rápidos
make qr              # Quick run (run-daemon)
make qs              # Quick status
make qm              # Quick monitor
```

## 🔧 Configuración del Sistema

### Dependencias del Sistema

#### macOS
```bash
# Homebrew (si no está instalado)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Python 3.13
brew install python@3.13

# Herramientas de red (opcional)
brew install nmap wireshark
```

#### Ubuntu/Debian
```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Python 3.13 y herramientas
sudo apt install python3.13 python3.13-venv python3.13-dev
sudo apt install build-essential libpcap-dev

# Herramientas de red (opcional)
sudo apt install nmap wireshark tcpdump
```

### Dependencias Python

**Principales:**
- **pyzmq**: Comunicación ZeroMQ de alta performance
- **scapy**: Captura y análisis de paquetes de red
- **scikit-learn, xgboost, lightgbm**: Machine Learning
- **pandas, numpy**: Procesamiento de datos
- **fastapi, uvicorn**: Framework web (futuro dashboard)

**Desarrollo:**
- **pytest**: Testing framework
- **black, isort**: Formateo de código
- **flake8, mypy**: Linting y type checking
- **bandit**: Security scanning

## 📊 Funcionamiento del Sistema

### 🕵️ Agente Promiscuo
- **Captura**: Todo el tráfico de red en modo promiscuo
- **Protocolos**: QUIC, HTTPS, TLS, ICMP, ARP, DNS, mDNS
- **Rate**: ~30 eventos/segundo en tráfico normal
- **Memoria**: ~120MB durante operación

### 🧠 ML Detector
- **Algoritmos**: 6 modelos entrenados (Isolation Forest, Random Forest, XGBoost, SGD, KMeans, Naive Bayes)
- **Entrenamiento**: ~0.4 segundos con 1000 muestras
- **Memoria**: ~160MB durante análisis
- **Detección**: Anomalías en tiempo real

### 🔌 ZeroMQ Broker
- **Puertos**: 5555 (primary), 5556 (secondary), 55565 (UDP)
- **Memoria**: ~15MB
- **Latencia**: <1ms para mensajes
- **Throughput**: Miles de mensajes/segundo

## 🔍 Eventos Detectados

### 🚨 Alertas de Seguridad
- **Port Scan**: Escaneo de puertos desde IPs externas
- **Connection Flood**: Exceso de conexiones desde una IP
- **Suspicious Port Access**: Acceso a puertos sensibles (SSH, RDP, Modbus)
- **Protocol Anomalies**: Violaciones de protocolos SCADA
- **Traffic Patterns**: Patrones anómalos detectados por ML

### 📈 Métricas del Sistema
- **Heartbeats**: Estado de salud de componentes
- **Performance**: CPU, memoria, red por componente
- **Network Statistics**: Throughput, latencia, pérdida de paquetes
- **ML Metrics**: Precisión, recall, falsos positivos

## 🧪 Testing y Desarrollo

### Ejecución de Tests
```bash
# Tests básicos
make test

# Tests con cobertura
make test-cov

# Tests de calidad de código
make check           # format + lint + security + test

# Tests individuales
make format          # Black + isort
make lint           # Flake8 + MyPy
make security       # Bandit security scan
```

### Desarrollo
```bash
# Setup completo de desarrollo
make dev

# Entorno de desarrollo con todas las herramientas
make install-dev

# Generar documentación
make docs

# Profiling de performance
make profile
make benchmark
```

## 🔒 Seguridad y Permisos

### Permisos Requeridos

**Agente Promiscuo (requiere sudo):**
- Acceso a `/dev/bpf*` en macOS
- Acceso a interfaces de red en modo promiscuo
- Captura de paquetes raw

**Configuración Automática:**
```bash
# El sistema configura automáticamente sudoers
make setup-sudo

# Configuración manual si es necesario:
echo "$USER ALL=(ALL) NOPASSWD: $(which python) $(pwd)/promiscuous_agent.py" | sudo tee /etc/sudoers.d/upgraded_happiness
```

### Recomendaciones de Seguridad
- Ejecutar en redes aisladas para testing
- Usar VPN o túneles cifrados en producción
- Monitorear logs de acceso regularmente
- Implementar rate limiting por IP

## 🔧 Troubleshooting

### 🚨 Problemas Comunes y Soluciones

#### 1. Dependencias Circulares (Import Errors)

**Síntomas:**
```
AttributeError: partially initialized module 'numpy'/'pandas'/'zmq' 
ImportError: cannot import name 'DataFrame' from partially initialized module
```

**Solución:**
```bash
# Limpieza automática y reinstalación en orden correcto
make fix-deps

# O manualmente:
make clean
pip uninstall numpy scipy pandas scikit-learn pyzmq -y
pip install --no-cache-dir pyzmq==25.1.2
pip install --no-cache-dir numpy==1.26.4
pip install --no-cache-dir scipy==1.16.0
pip install --no-cache-dir pandas==2.3.0
pip install --no-cache-dir scikit-learn==1.7.0
```

#### 2. Permisos del Agente Promiscuo

**Síntomas:**
```
Permission denied: could not open /dev/bpf0
sudo: a terminal is required to read the password
```

**Soluciones:**
```bash
# Configurar sudoers automáticamente
make setup-sudo

# Ejecutar manualmente con sudo
sudo python promiscuous_agent.py &

# Verificar configuración sudoers
sudo cat /etc/sudoers.d/upgraded_happiness
```

#### 3. Entorno Virtual Corrupto

**Síntomas:**
```
ModuleNotFoundError: No module named 'pip._vendor.packaging._structures'
ImportError: No module named 'packaging.version'
```

**Solución:**
```bash
# Recrear entorno virtual completo
make clean
make setup-production

# O paso a paso:
rm -rf upgraded_happiness_venv
python3 -m venv upgraded_happiness_venv
source upgraded_happiness_venv/bin/activate
pip install --upgrade pip
make install-all
```

#### 4. Problemas de Formateo (Black)

**Síntomas:**
```
error: cannot format file.py: Cannot parse: 18:7: """Encontrar..."""
```

**Soluciones:**
```bash
# Crear archivo .blackignore para excluir archivos problemáticos
echo "archivo_problematico.py" >> .blackignore

# Cambiar comentarios en español a inglés
sed -i 's/"""Encontrar.*/"""Find active broker"""/g' archivo.py

# Eliminar archivos temporales problemáticos
rm *_patch.py *_debug.py *_temp.py
```

#### 5. ZeroMQ No Conecta

**Síntomas:**
```
Platform not operational (0/3 components)
ZeroMQ Primary Port (Port 5555) - NOT LISTENING
```

**Soluciones:**
```bash
# Verificar orden de inicialización
make stop
make quick-start  # Usa orden correcto: broker → ML → agent

# Verificar puertos manualmente
netstat -an | grep 555
lsof -i :5555

# Reiniciar broker específicamente
make run-broker &
```

#### 6. Alta CPU del Agente Promiscuo

**Síntomas:**
- CPU > 80% del agente promiscuo
- Sistema lento durante captura

**Soluciones:**
```bash
# Aplicar filtros de red más específicos
# Editar promiscuous_agent.py, añadir filtros BPF:
filter_expression = "not arp and not icmp"

# Reducir rate de captura en configuración
# Usar interfaces específicas en lugar de 'any'
```

#### 7. Memoria Insuficiente

**Síntomas:**
- Sistema OOM (Out of Memory)
- Procesos matados por kernel

**Soluciones:**
```bash
# Reducir batch size del ML detector
# Editar lightweight_ml_detector.py:
BATCH_SIZE = 500  # En lugar de 1000

# Monitorear memoria en tiempo real
make monitor-live

# Configurar swap si es necesario (Linux)
sudo swapon --show
```

#### 8. Componentes No Se Inician

**Síntomas:**
```
Process starts but immediately exits
No output from components
```

**Diagnóstico:**
```bash
# Ejecutar componente individualmente para ver errores
python scripts/smart_broker.py
python lightweight_ml_detector.py
sudo python promiscuous_agent.py

# Verificar logs
tail -f logs/*.log

# Verificar dependencias
python -c "import zmq, scapy, sklearn, pandas; print('All OK')"
```

#### 9. Tests Fallan

**Síntomas:**
```
ModuleNotFoundError during testing
Import errors in test files
```

**Soluciones:**
```bash
# Instalar dependencias de desarrollo
make install-dev

# Ejecutar tests con verbose para más info
python -m pytest tests/ -v -s

# Verificar estructura de tests
make verify
```

#### 10. Dashboard/Monitoring No Responde

**Síntomas:**
- `make monitor` no funciona
- Scripts de monitoreo no existen

**Soluciones:**
```bash
# Verificar que platform_monitor.sh existe
ls -la platform_monitor.sh

# Recrear script si falta
# (usar el contenido del artefacto platform_monitor.sh anterior)

# Usar monitoreo básico mientras tanto
make status
watch "ps aux | grep -E '(smart_broker|lightweight_ml|promiscuous)' | grep -v grep"
```

### 🆘 Recuperación de Emergencia

```bash
# Limpieza completa y reinstalación
make emergency-fix

# Reset total del proyecto
make clean
rm -rf logs/ backups/ __pycache__/
make setup-production
make quick-start
```

### 🔍 Comandos de Diagnóstico

```bash
# Estado completo del sistema
make monitor

# Verificar procesos manualmente
ps aux | grep -E "(smart_broker|lightweight_ml|promiscuous)" | grep -v grep

# Verificar puertos y conexiones
netstat -an | grep 555
lsof -i -P | grep python

# Verificar memoria y CPU
top -p $(pgrep -f "upgraded-happiness" | tr '\n' ',' | sed 's/,$//')

# Logs del sistema (si existen)
tail -f /var/log/system.log | grep -i "upgraded"
```

## 📊 Métricas de Performance

### Recursos Típicos por Componente

| Componente | CPU | Memoria | Red |
|------------|-----|---------|-----|
| ZeroMQ Broker | <1% | ~15MB | Bajo |
| ML Detector | 1-5% | ~160MB | Bajo |
| Promiscuous Agent | 5-15% | ~120MB | Alto |
| **Total Sistema** | **<20%** | **~300MB** | **Variable** |

### Throughput Esperado

- **Captura**: 1,000-10,000 paquetes/segundo
- **Procesamiento ML**: 100-1,000 eventos/segundo
- **ZeroMQ**: >10,000 mensajes/segundo
- **Latencia E2E**: <10ms para eventos críticos

## 🎯 Próximos Pasos

### ✅ Completado (v1.0)
- [x] Plataforma base completamente funcional
- [x] Captura de tráfico en tiempo real
- [x] 6 algoritmos ML entrenados y activos
- [x] Sistema de monitoreo avanzado
- [x] Comunicación ZeroMQ estable
- [x] Makefile automatizado
- [x] Troubleshooting completo

### 📋 Próximas Iteraciones

#### v1.1 - Dashboard Web
- [ ] Interfaz web en tiempo real
- [ ] Visualización de eventos
- [ ] Dashboard de métricas
- [ ] API REST para control

#### v1.2 - Persistencia
- [ ] Base de datos time-series (InfluxDB)
- [ ] Almacenamiento de eventos históricos
- [ ] Capacidad de "replay"
- [ ] Análisis forense

#### v1.3 - Escalabilidad
- [ ] Múltiples agentes distribuidos
- [ ] Load balancing
- [ ] High availability
- [ ] Kubernetes deployment

## 🤝 Contribución

```bash
# Crear rama feature
git checkout -b feature/nueva-funcionalidad

# Desarrollo con verificación de calidad
make dev
make check  # format + lint + test

# Commit y push
git add .
git commit -m "feat: nueva funcionalidad"
git push origin feature/nueva-funcionalidad
```

### Estándares de Código
- **Python**: PEP 8 (enforced by black)
- **Docstrings**: Google style
- **Type hints**: Obligatorios para funciones públicas
- **Tests**: Coverage mínimo 80%

## 📜 Licencia

Este proyecto está bajo licencia MIT. Ver `LICENSE` para más detalles.

## 🆘 Soporte

### Contacto
- **Issues**: GitHub Issues para bugs y feature requests
- **Discusiones**: GitHub Discussions para preguntas generales
- **Security**: security@upgraded-happiness.com para vulnerabilidades

### Recursos Adicionales
- [Documentación Técnica](docs/)
- [Guía de Deployment](docs/deployment.md)
- [API Reference](docs/api.md)
- [Architecture Deep Dive](docs/architecture.md)

---

**Upgraded Happiness** - Plataforma de Ciberseguridad SCADA
*Built with ❤️ for Critical Infrastructure Protection*