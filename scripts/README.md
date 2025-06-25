# Scripts Directory

Este directorio contiene todos los scripts de automatización para el proyecto **upgraded-happiness**.

## 📋 Lista de Scripts

### 🏗️ **Setup & Installation**

| Script | Propósito | Cuándo usar |
|--------|-----------|-------------|
| `setup_research_environment.sh` | **Setup completo** del entorno de investigación | ✅ **Primera instalación** o reset completo |
| `install_research_dependencies.sh` | Instalar **solo dependencias** de investigación | ✅ Agregar nuevas dependencias a entorno existente |

### 🔬 **Research Workflow**

| Script | Propósito | Cuándo usar |
|--------|-----------|-------------|
| `run_protobuf_research.sh` | **Workflow completo** de Protocol Buffers | ✅ Ejecutar investigación de protocolos |

### 🛠️ **Management & Help**

| Script | Propósito | Cuándo usar |
|--------|-----------|-------------|
| `manage_scripts.sh` | **Script manager** - ayuda y verificación | ✅ Cuando no sepas qué script usar |

## 🚀 Quick Start Guide

### Primera vez en el proyecto:

```bash
# Opción 1: Setup completo (recomendado para primera vez)
bash scripts/setup_research_environment.sh

# Opción 2: Solo dependencias (si ya tienes estructura)
bash scripts/install_research_dependencies.sh
```

### Verificar instalación:

```bash
# Script manager con verificación
bash scripts/manage_scripts.sh check

# Tests completos del proyecto
python test_setup.py
python verify_installation.py
```

### Ejecutar investigación:

```bash
# Workflow completo de Protocol Buffers
bash scripts/run_protobuf_research.sh all

# O paso a paso:
bash scripts/run_protobuf_research.sh test      # Test básico
bash scripts/run_protobuf_research.sh benchmark # Benchmark completo
```

## 🤔 ¿Qué script usar?

### Si eres nuevo en el proyecto:
```bash
bash scripts/setup_research_environment.sh
```

### Si ya tienes el proyecto configurado pero faltan dependencias:
```bash
bash scripts/install_research_dependencies.sh
```

### Si no estás seguro qué necesitas:
```bash
bash scripts/manage_scripts.sh
```

### Si quieres ejecutar investigación de protocolos:
```bash
bash scripts/run_protobuf_research.sh test
```

## 📊 Comparison of Setup Scripts

| Feature | `setup_research_environment.sh` | `install_research_dependencies.sh` |
|---------|--------------------------------|-----------------------------------|
| **Scope** | 🟢 Complete environment | 🔵 Dependencies only |
| **Time** | ~5-10 minutes | ~2-3 minutes |
| **Creates directories** | ✅ Yes | ❌ No |
| **Creates schemas** | ✅ Yes | ❌ No |
| **Compiles protobuf** | ✅ Yes | ❌ No |
| **Installs all deps** | ✅ Yes | ✅ Yes (core research) |
| **Creates config files** | ✅ Yes | ❌ No |

## 🔧 Troubleshooting

### Script no ejecuta:
```bash
chmod +x scripts/*.sh
```

### Problemas de dependencias:
```bash
# Check environment
bash scripts/manage_scripts.sh check

# Get fix suggestions
bash scripts/manage_scripts.sh fix
```

### Problemas de imports:
```bash
# Install in development mode
pip install -e .

# Create missing __init__.py files
touch src/__init__.py src/common/__init__.py src/protocols/__init__.py
```

### Virtual environment:
```bash
# Activate if not active
source upgraded_happiness_venv/bin/activate  # Linux/macOS
upgraded_happiness_venv\Scripts\activate     # Windows
```

## 📝 Script Development Guidelines

Si necesitas agregar nuevos scripts a este directorio:

1. **Naming convention**: `verb_noun_description.sh`
2. **Make executable**: `chmod +x script_name.sh`
3. **Add help**: Include `--help` or `-h` option
4. **Use colors**: Use the color scheme from existing scripts
5. **Error handling**: Use `set -e` and proper error messages
6. **Update this README**: Add entry to the table above

## 🔄 Script Dependencies

```
manage_scripts.sh
    ├── Uses: All other scripts
    └── Purpose: Help choose which script to run

setup_research_environment.sh
    ├── Creates: Complete environment
    └── Includes: Everything in install_research_dependencies.sh

install_research_dependencies.sh
    ├── Minimal: Core dependencies only
    └── Fast: Quick installation

run_protobuf_research.sh
    ├── Requires: Environment set up
    └── Executes: Research workflow
```

## 📞 Support

If you have issues with any script:

1. Run `bash scripts/manage_scripts.sh check` for diagnosis
2. Check the main project `test_setup.py` for overall health
3. Look at error messages carefully - they usually suggest the fix
4. Make sure your virtual environment is activated

---

**💡 Pro tip**: Start with `bash scripts/manage_scripts.sh` if you're unsure which script to run!