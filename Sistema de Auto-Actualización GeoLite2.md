# 🌍 Sistema de Auto-Actualización GeoLite2

## 📋 **Resumen**

El sistema automáticamente descarga y actualiza las bases de datos GeoLite2 de MaxMind, manteniendo siempre la información geográfica más actualizada posible.

## ✨ **Características Principales**

### ✅ **Detección Automática de Actualizaciones**
- Verifica la edad de la base de datos actual
- Descarga nueva versión si es necesaria
- Configurable: cada N días (default: 7 días)

### ✅ **Sistema de Backup Automático**
- Backup de la versión anterior antes de actualizar
- Nombrado con fecha: `GeoLite2-City_20250712_143022.mmdb`
- Limpieza automática de backups antiguos (configurable)

### ✅ **Gestión de Errores Robusta**
- Reintentos automáticos si falla la descarga
- Verificación de integridad de archivos
- Rollback automático si hay problemas

### ✅ **Logging Detallado**
- Progreso de descarga en tiempo real
- Notificaciones de éxito/error
- Información sobre backups y limpiezas

## 🔧 **Configuración**

### **1. Obtener License Key de MaxMind (GRATUITA)**

```bash
# 1. Visitar https://www.maxmind.com/en/geolite2/signup
# 2. Crear cuenta gratuita
# 3. Generar license key
# 4. Configurar en el JSON
```

### **2. Configuración en JSON**

```json
{
  "geoip": {
    "auto_update": {
      "enabled": true,
      "maxmind_license_key": "TU_LICENSE_KEY_AQUI",
      "databases_to_update": ["GeoLite2-City"],
      "database_directory": ".",
      "backup_directory": "./backups",
      "temp_directory": "./temp",
      "update_frequency_days": 7,
      "check_on_startup": true,
      "force_update": false,
      "max_backups_to_keep": 5,
      "download_timeout_seconds": 300,
      "retry_attempts": 3,
      "retry_delay_seconds": 5
    }
  }
}
```

### **3. Parámetros de Configuración**

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `enabled` | bool | `false` | Activar/desactivar auto-updates |
| `maxmind_license_key` | string | - | License key de MaxMind (requerida) |
| `databases_to_update` | array | `["GeoLite2-City"]` | Bases de datos a actualizar |
| `database_directory` | string | `"."` | Directorio donde guardar las bases de datos |
| `backup_directory` | string | `"./backups"` | Directorio para backups |
| `temp_directory` | string | `"./temp"` | Directorio temporal para descargas |
| `update_frequency_days` | int | `7` | Cada cuántos días verificar actualizaciones |
| `check_on_startup` | bool | `true` | Verificar actualizaciones al iniciar |
| `force_update` | bool | `false` | Forzar actualización ignorando fecha |
| `max_backups_to_keep` | int | `5` | Número máximo de backups a mantener |

## 🚀 **Uso**

### **Automático (Integrado)**
```bash
# El sistema se ejecuta automáticamente cuando enabled=true
python geoip_enricher.py geoip_enricher_config.json
```

### **Manual (Script Independiente)**
```bash
# Verificar estado
python geolite2_manager.py --check

# Actualizar si es necesario
python geolite2_manager.py --update

# Forzar actualización
python geolite2_manager.py --force-update

# Configurar license key
python geolite2_manager.py --setup-license

# Limpiar archivos temporales
python geolite2_manager.py --cleanup
```

## 📊 **Ejemplo de Logs**

### **Primera Ejecución (Sin Base de Datos)**
```
2025-07-12 14:30:15 - INFO - 🔄 Iniciando sistema de auto-actualización GeoLite2...
2025-07-12 14:30:15 - INFO - ✅ MaxMind license key configurada
2025-07-12 14:30:15 - INFO - 📁 Base de datos GeoLite2-City.mmdb no existe - descarga necesaria
2025-07-12 14:30:15 - INFO - 🌍 Actualizando GeoLite2-City...
2025-07-12 14:30:15 - INFO - 📥 Descargando GeoLite2-City...
2025-07-12 14:30:18 - INFO - 📦 Extrayendo GeoLite2-City.mmdb...
2025-07-12 14:30:18 - INFO - ✅ GeoLite2-City actualizada!
```

### **Ejecución Regular (Base de Datos Actual)**
```
2025-07-12 14:30:15 - INFO - 🔄 Iniciando sistema de auto-actualización GeoLite2...
2025-07-12 14:30:15 - INFO - 📅 Base de datos actual (3 días) - no requiere actualización
```

### **Actualización Disponible**
```
2025-07-12 14:30:15 - INFO - 📅 Base de datos tiene 8 días - actualización recomendada
2025-07-12 14:30:15 - INFO - 🌍 Actualizando GeoLite2-City...
2025-07-12 14:30:15 - INFO - 📥 Descargando GeoLite2-City...
2025-07-12 14:30:18 - INFO - 📦 Extrayendo GeoLite2-City.mmdb...
2025-07-12 14:30:18 - INFO - 💾 Backup: GeoLite2-City_20250712_143018.mmdb
2025-07-12 14:30:18 - INFO - ✅ GeoLite2-City actualizada!
```

## 🗂️ **Estructura de Directorios**

```
proyecto/
├── geoip_enricher.py
├── geoip_enricher_config.json
├── geolite2_manager.py
├── GeoLite2-City.mmdb          ← Base de datos actual
├── backups/                    ← Backups automáticos
│   ├── GeoLite2-City_20250705_140000.mmdb
│   ├── GeoLite2-City_20250698_140000.mmdb
│   └── ...
└── temp/                       ← Archivos temporales (auto-limpieza)
```

## ⚠️ **Casos de Error Comunes**

### **License Key No Configurada**
```
❌ MaxMind license key NO configurada
💡 Obtener license key gratuita en: https://www.maxmind.com/en/geolite2/signup
💡 Configurar en: geoip.auto_update.maxmind_license_key
```

**Solución:**
1. Ir a https://www.maxmind.com/en/geolite2/signup
2. Crear cuenta y generar license key
3. Actualizar configuración JSON

### **Error de Descarga**
```
❌ Respuesta inválida: text/html
💡 Verificar license key
```

**Solución:**
- Verificar que la license key sea correcta
- Verificar conexión a internet
- Intentar más tarde (posible mantenimiento de MaxMind)

### **Falta de Espacio en Disco**
```
❌ Error durante actualización: [Errno 28] No space left on device
```

**Solución:**
- Liberar espacio en disco
- Configurar `max_backups_to_keep` con un valor menor
- Limpiar archivos temporales

## 🔄 **Frecuencia de Actualización Recomendada**

| Tipo de Aplicación | Frecuencia Recomendada | Configuración |
|-------------------|----------------------|---------------|
| **Desarrollo/Testing** | Mensual | `update_frequency_days: 30` |
| **Producción estándar** | Semanal | `update_frequency_days: 7` |
| **Alta precisión** | Cada 3 días | `update_frequency_days: 3` |
| **Crítico** | Diario | `update_frequency_days: 1` |

## 📈 **Tamaños de Archivos Aproximados**

| Base de Datos | Tamaño Comprimido | Tamaño Extraído |
|---------------|------------------|----------------|
| **GeoLite2-City** | ~50MB | ~70MB |
| **GeoLite2-Country** | ~6MB | ~8MB |
| **GeoLite2-ASN** | ~10MB | ~15MB |

## 🛡️ **Consideraciones de Seguridad**

1. **License Key**: Mantener segura, no compartir públicamente
2. **Permisos**: Asegurar permisos correctos en directorios
3. **Firewall**: Permitir conexiones HTTPS a `download.maxmind.com`
4. **Backups**: Los backups automáticos protegen contra actualizaciones problemáticas

## ✅ **Checklist de Configuración**

- [ ] License key de MaxMind obtenida
- [ ] License key configurada en JSON
- [ ] `enabled: true` en configuración
- [ ] Permisos de escritura en directorios configurados
- [ ] Conexión a internet disponible
- [ ] Espacio en disco suficiente (~200MB recomendado)
- [ ] Tested con `python geolite2_manager.py --check`

## 🎯 **Beneficios del Sistema**

1. **Precisión Mejorada**: Datos geográficos siempre actualizados
2. **Cero Mantenimiento**: Funciona automáticamente sin intervención
3. **Reliability**: Sistema de backup y recuperación automático
4. **Observabilidad**: Logs detallados para debugging
5. **Flexibilidad**: Configuración granular según necesidades

¡El sistema está listo para mantener tus bases de datos GeoLite2 siempre actualizadas! 🌍