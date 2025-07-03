# 🚀 Scripts SCADA Mejorados - Guía Completa

> **Versión 2.0** - Incorpora todas las lecciones aprendidas del troubleshooting

## 📋 **Scripts Incluidos**

### **🔧 Scripts Principales**
1. **`start-scada-platform.sh`** - Setup completo y diagnóstico avanzado
2. **`quick-start.sh`** - Inicio rápido mejorado para uso diario  
3. **`check-ports.sh`** - Verificación detallada de puertos y conectividad
4. **`fix-sudo-permissions.sh`** - Corrección de permisos sudo
5. **`monitor-platform.sh`** - Monitoreo en tiempo real
6. **`troubleshoot-scada.sh`** - Diagnóstico completo automático

---

## 🎯 **Flujo de Trabajo Recomendado**

### **📦 Primera Instalación:**
```bash
# 1. Hacer scripts ejecutables
chmod +x *.sh

# 2. Setup completo (solo primera vez)
./start-scada-platform.sh

# 3. Verificar resultado
./check-ports.sh
```

### **🔄 Uso Diario:**
```bash
# Inicio rápido
./quick-start.sh

# Monitoreo en vivo
./monitor-platform.sh --live

# Parar todo
make stop
```

### **🔧 Troubleshooting:**
```bash
# Diagnóstico automático
./troubleshoot-scada.sh

# Arreglar permisos
./fix-sudo-permissions.sh

# Verificar conectividad
./check-ports.sh
```

---

## ✨ **Mejoras Implementadas**

### **🔍 Detección de Procesos Mejorada**
- ✅ Verificación robusta de PIDs
- ✅ Timeouts ajustados para inicialización  
- ✅ Detección de procesos "zombie"
- ✅ Verificación de captura activa de datos

### **🌐 Verificación de Puertos ZeroMQ**
- ✅ Conectividad real en lugar de solo `netstat`
- ✅ Pruebas de ZeroMQ nativas
- ✅ Manejo de falsos negativos
- ✅ Verificación por múltiples métodos

### **🔒 Manejo de Sudo Mejorado**
- ✅ Configuración automática de sudoers
- ✅ Verificación post-configuración
- ✅ Manejo de errores I/O normales
- ✅ Timeouts apropiados para inicialización

### **📊 Monitoreo Más Preciso**
- ✅ Estadísticas de captura en tiempo real
- ✅ Verificación de estado real vs reportado
- ✅ Detección de componentes "medio-activos"
- ✅ Reportes detallados de rendimiento

---

## 🎛️ **Guía de Scripts**

### **1. `start-scada-platform.sh` - Setup Completo**
```bash
./start-scada-platform.sh [opciones]
```

**¿Cuándo usar?**
- ✅ Primera instalación
- ✅ Después de cambios de configuración
- ✅ Cuando otros scripts fallan
- ✅ Setup desde cero

**Características:**
- 🔧 Verificación exhaustiva de dependencias
- 🔧 Configuración automática de sudoers
- 🔧 Orden correcto de inicialización
- 🔧 Verificación post-inicio mejorada
- 🔧 Manejo de errores robusto

---

### **2. `quick-start.sh` - Inicio Rápido**
```bash
./quick-start.sh
```

**¿Cuándo usar?**
- ✅ Uso diario normal
- ✅ Después de `make stop`
- ✅ Reinicio rápido
- ✅ Cuando el entorno ya está configurado

**Características:**
- ⚡ Inicio en menos de 15 segundos
- ⚡ Verificación de limpieza previa
- ⚡ Estado detallado post-inicio
- ⚡ Diagnóstico automático de problemas

---

### **3. `check-ports.sh` - Verificación de Conectividad**
```bash
./check-ports.sh
```

**¿Cuándo usar?**
- ✅ Verificar estado después del inicio
- ✅ Diagnosticar problemas de conectividad
- ✅ Confirmar captura de datos
- ✅ Validar configuración de red

**Características:**
- 🔍 Múltiples métodos de verificación
- 🔍 Pruebas de conectividad ZeroMQ reales
- 🔍 Estadísticas de captura de datos
- 🔍 Diagnóstico automático

---

### **4. `fix-sudo-permissions.sh` - Corrección de Permisos**
```bash
./fix-sudo-permissions.sh
```

**¿Cuándo usar?**
- ✅ Problemas con agente promiscuo
- ✅ Errores de permisos sudo
- ✅ Después de cambios de usuario
- ✅ Primera configuración

**Características:**
- 🔑 Configuración automática de sudoers
- 🔑 Verificación de permisos
- 🔑 Reinicio seguro del agente
- 🔑 Diagnóstico de problemas de permisos

---

### **5. `monitor-platform.sh` - Monitoreo Avanzado**
```bash
./monitor-platform.sh [opciones]
```

**Opciones:**
- `--live` - Monitoreo continuo cada 5 segundos
- `--live 10` - Monitoreo cada 10 segundos
- `--logs` - Mostrar logs recientes
- `--diagnosis` - Diagnóstico rápido

**Características:**
- 📊 Monitoreo en tiempo real
- 📊 Estadísticas de recursos
- 📊 Estado de componentes
- 📊 Información de red

---

### **6. `troubleshoot-scada.sh` - Diagnóstico Completo**
```bash
./troubleshoot-scada.sh
```

**¿Cuándo usar?**
- ✅ Cuando algo no funciona
- ✅ Diagnóstico preventivo
- ✅ Antes de reportar problemas
- ✅ Análisis de rendimiento

**Características:**
- 🔧 Verificación de entorno completa
- 🔧 Diagnóstico de dependencias
- 🔧 Recomendaciones automáticas
- 🔧 Reporte detallado de estado

---

## 🎯 **Escenarios Comunes**

### **🚀 Inicio Normal (Todo Funciona)**
```bash
./quick-start.sh
# Output esperado: "🎉 ¡Plataforma completamente operativa!"
```

### **🔧 Problemas de Permisos**
```bash
./troubleshoot-scada.sh
# Si detecta problemas de sudo:
./fix-sudo-permissions.sh
./quick-start.sh
```

### **🔍 Verificación Post-Inicio**
```bash
./check-ports.sh
# Verificar: 3/3 componentes activos
./monitor-platform.sh --live
# Ver estadísticas en tiempo real
```

### **🚨 Problemas Graves**
```bash
make stop
./start-scada-platform.sh
# Setup completo desde cero
```

---

## 📈 **Indicadores de Éxito**

### **✅ Plataforma Funcionando Correctamente:**
- 🎯 3/3 componentes activos
- 🎯 Puertos ZeroMQ respondiendo
- 🎯 Agente capturando >10 eventos/segundo
- 🎯 ML Detector procesando datos
- 🎯 CPU <20%, RAM <300MB

### **⚠️ Problemas Menores (Operación Parcial):**
- 🎯 2/3 componentes activos
- 🎯 Funcionalidad básica disponible
- 🎯 Reparable con scripts de fix

### **❌ Problemas Graves:**
- 🎯 <2 componentes activos
- 🎯 Errores de dependencias
- 🎯 Problemas de configuración

---

## 🛠️ **Comandos de Emergencia**

### **Reset Completo:**
```bash
make stop
pkill -f "smart_broker|lightweight_ml|promiscuous"
make clean
./start-scada-platform.sh
```

### **Reinstalación de Dependencias:**
```bash
make fix-deps
./start-scada-platform.sh
```

### **Verificación Rápida:**
```bash
./troubleshoot-scada.sh | grep "📈 Estado general"
```

---

## 🎉 **Resultado Esperado**

Con estos scripts mejorados, deberías obtener:

1. **🎯 Inicio confiable** en <30 segundos
2. **🎯 Detección precisa** de todos los componentes  
3. **🎯 Diagnóstico automático** de problemas
4. **🎯 Reparación automática** de errores comunes
5. **🎯 Monitoreo en tiempo real** con estadísticas precisas

### **Ejemplo de Salida Exitosa:**
```
🎉 ¡Plataforma completamente operativa!
📊 Componentes activos: 3/3
  • ZeroMQ Broker:      ✅ ACTIVO  
  • ML Detector:        ✅ ACTIVO
  • Promiscuous Agent:  ✅ ACTIVO (1600+ eventos capturados)
```

---

## 💡 **Tips de Uso**

1. **Ejecuta siempre `./troubleshoot-scada.sh` primero** si algo no funciona
2. **Usa `./quick-start.sh` para uso diario** después del setup inicial
3. **Monitorea con `./monitor-platform.sh --live`** para ver la plataforma en acción
4. **Los scripts son idempotentes** - es seguro ejecutarlos múltiples veces
5. **Todos los scripts manejan cleanup automático** de procesos previos

---

> **🔥 Con estos scripts mejorados, tu plataforma SCADA será más confiable, fácil de usar y troubleshoot!** 🚀