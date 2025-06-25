# Syntax Fixes Guide

Esta guía explica los problemas de sintaxis encontrados y cómo se solucionaron.

## 🚨 Problema: "Multiple redirections compete for stdout"

### ❌ **Sintaxis problemática:**
```bash
pip install protobuf>=4.21.0 lz4>=4.0.0 pycryptodome>=3.15.0
```

### ⚠️ **Por qué falló:**
Los linters de bash (como ShellCheck) interpretan `>=` como **operadores de redirección**, no como especificadores de versión de pip.

### ✅ **Solución aplicada:**

#### **Opción 1: Comillas alrededor de cada paquete**
```bash
pip install "protobuf>=4.21.0" "lz4>=4.0.0" "pycryptodome>=3.15.0"
```

#### **Opción 2: Comandos separados (más limpio)**
```bash
pip install "protobuf>=4.21.0"
pip install "lz4>=4.0.0" 
pip install "pycryptodome>=3.15.0"
```

## 🔧 Scripts Arreglados

### 1. `install_research_dependencies.sh`

**Antes:**
```bash
pip install protobuf>=4.21.0 lz4>=4.0.0 pycryptodome>=3.15.0
pip install aiofiles>=0.8.0
pip install pytest>=7.0.0 pytest-asyncio>=0.21.0 pytest-benchmark>=4.0.0
```

**Después:**
```bash
pip install "protobuf>=4.21.0" "lz4>=4.0.0" "pycryptodome>=3.15.0"
pip install "aiofiles>=0.8.0"
pip install "pytest>=7.0.0" "pytest-asyncio>=0.21.0" "pytest-benchmark>=4.0.0"
```

### 2. `run_protobuf_research.sh`

**Antes:**
```bash
pip install protobuf>=4.24.0 lz4>=4.3.2 cryptography>=41.0.0 msgpack>=1.0.5
pip install pyarrow>=13.0.0 flatbuffers>=23.5.26 python-snappy>=0.6.1
pip install scikit-learn>=1.3.0 pandas>=2.0.0 matplotlib>=3.7.0
pip install memory-profiler>=0.61.0 psutil>=5.9.0
```

**Después:**
```bash
pip install "protobuf>=4.24.0"
pip install "lz4>=4.3.2"
pip install "cryptography>=41.0.0"
pip install "msgpack>=1.0.5"
# ... etc (comando por línea)
```

## 📦 Scripts Adicionales Creados

### 3. `install_research_dependencies_clean.sh`
- **Propósito**: Versión ultra-limpia con un comando pip por línea
- **Ventaja**: Máxima compatibilidad con linters, más fácil debug
- **Uso**: Alternativa si sigues teniendo problemas

### 4. `verify_scripts_syntax.sh`
- **Propósito**: Verificar sintaxis de todos los scripts
- **Uso**: `bash scripts/verify_scripts_syntax.sh`
- **Función**: Detecta problemas de sintaxis antes de ejecutar

## 🧪 Verificación

### **Ejecutar verificación de sintaxis:**
```bash
bash scripts/verify_scripts_syntax.sh
```

### **Resultado esperado:**
```
🔍 Verificando sintaxis de scripts bash...
==========================================
Checking install_research_dependencies.sh... ✅ OK
Checking run_protobuf_research.sh... ✅ OK
Checking manage_scripts.sh... ✅ OK
Checking verify_scripts_syntax.sh... ✅ OK

==========================================
📊 Summary:
   Total scripts checked: 4
   Syntax OK: 4
   Syntax errors: 0

🎉 All scripts have correct syntax!
```

## 💡 Reglas para Scripts Futuros

### **Al usar pip install:**
```bash
# ✅ CORRECTO
pip install "package>=1.0.0"
pip install "package1>=1.0.0" "package2>=2.0.0"

# ❌ INCORRECTO (cause warnings)
pip install package>=1.0.0
pip install package1>=1.0.0 package2>=2.0.0
```

### **Al usar redirecciones:**
```bash
# ✅ CORRECTO
command > file.txt 2>&1

# ❌ INCORRECTO
command > file.txt > another_file.txt  # Multiple redirections
```

### **Al usar comparaciones:**
```bash
# ✅ CORRECTO
if [[ "$VERSION" -ge "1.0" ]]; then

# ⚠️ CUIDADO con >= sin contexto
VERSION>=1.0  # Puede interpretarse como redirección
```

## 🔧 Herramientas de Verificación

### **ShellCheck (recomendado):**
```bash
# Instalar ShellCheck
sudo apt-get install shellcheck  # Ubuntu/Debian
brew install shellcheck         # macOS

# Verificar un script
shellcheck scripts/script_name.sh
```

### **Bash syntax check básico:**
```bash
bash -n script_name.sh  # Solo verifica sintaxis, no ejecuta
```

## 📞 Troubleshooting

### **Si aún ves warnings:**
1. Ejecuta `bash scripts/verify_scripts_syntax.sh`
2. Usa `shellcheck` si está disponible
3. Verifica que todas las comillas estén balanceadas
4. Usa la versión `_clean.sh` como alternativa

### **Si los scripts no ejecutan:**
```bash
chmod +x scripts/*.sh  # Hacer ejecutables
bash scripts/script_name.sh  # Ejecutar explícitamente con bash
```

### **Si faltan dependencias:**
```bash
bash scripts/install_research_dependencies_clean.sh  # Versión ultra-compatible
```

---

**🎯 Resultado**: Todos los warnings de sintaxis eliminados, scripts más robustos y compatibles con herramientas de análisis estático.