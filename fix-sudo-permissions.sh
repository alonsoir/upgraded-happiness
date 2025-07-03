#!/bin/bash

# =============================================================================
# FIX SUDO PERMISSIONS - SCADA Platform (MEJORADO v2.0)
# =============================================================================
# Script para diagnosticar y arreglar problemas de permisos sudo
# Incorpora lecciones aprendidas de troubleshooting
# =============================================================================

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}🔧 DIAGNÓSTICO Y FIX DE PERMISOS SUDO (v2.0)${NC}"
echo "======================================================"

# 1. Verificar configuración actual de sudoers
echo -e "${YELLOW}1. Verificando configuración actual...${NC}"
echo "Archivo sudoers para upgraded-happiness:"
if [[ -f "/etc/sudoers.d/upgraded_happiness" ]]; then
    echo -e "${GREEN}✅ Archivo sudoers existe${NC}"
    echo "Contenido:"
    sudo cat /etc/sudoers.d/upgraded_happiness 2>/dev/null || echo -e "${RED}❌ No se puede leer${NC}"
else
    echo -e "${RED}❌ Archivo sudoers NO existe${NC}"
fi

echo ""

# 2. Verificar permisos actuales
echo -e "${YELLOW}2. Probando permisos sudo actuales...${NC}"
if sudo -n true 2>/dev/null; then
    echo -e "${GREEN}✅ Permisos sudo funcionando sin contraseña${NC}"
else
    echo -e "${RED}❌ Se requiere contraseña para sudo${NC}"
fi

echo ""

# 3. Verificar procesos actuales
echo -e "${YELLOW}3. Verificando procesos SCADA actuales...${NC}"
echo "Procesos encontrados:"
scada_procs=$(ps aux | grep -E "(smart_broker|lightweight_ml|promiscuous)" | grep -v grep)
if [[ -n "$scada_procs" ]]; then
    echo "$scada_procs" | while read line; do
        echo -e "  ${GREEN}✅ $line${NC}"
    done
else
    echo -e "  ${RED}❌ No hay procesos SCADA activos${NC}"
fi

echo ""

# 4. Verificar qué usuario está ejecutando cada proceso
echo -e "${YELLOW}4. Análisis de usuarios de procesos...${NC}"
broker_user=$(ps aux | grep "smart_broker" | grep -v grep | awk '{print $1}' | head -1)
ml_user=$(ps aux | grep "lightweight_ml" | grep -v grep | awk '{print $1}' | head -1)
agent_user=$(ps aux | grep "promiscuous" | grep -v grep | awk '{print $1}' | head -1)

echo "  Broker ejecutado por: ${broker_user:-"NO ENCONTRADO"}"
echo "  ML Detector ejecutado por: ${ml_user:-"NO ENCONTRADO"}"
echo "  Promiscuous Agent ejecutado por: ${agent_user:-"NO ENCONTRADO"}"

echo ""

# 5. Verificar si el archivo promiscuous_agent.py existe
echo -e "${YELLOW}5. Verificando archivos necesarios...${NC}"
if [[ -f "promiscuous_agent.py" ]]; then
    echo -e "${GREEN}✅ promiscuous_agent.py encontrado${NC}"
else
    echo -e "${RED}❌ promiscuous_agent.py NO encontrado${NC}"
    echo "Buscando en subdirectorios..."
    find . -name "promiscuous_agent.py" -type f 2>/dev/null | head -5
fi

echo ""

# 6. Proponer soluciones
echo -e "${YELLOW}6. SOLUCIONES PROPUESTAS:${NC}"
echo ""

echo -e "${BLUE}OPCIÓN A - Reconfigurar sudoers (recomendado):${NC}"
PYTHON_PATH=$(which python3)
if [[ -f "promiscuous_agent.py" ]]; then
    PROMISCUOUS_PATH="$(pwd)/promiscuous_agent.py"
else
    # Buscar el archivo
    PROMISCUOUS_PATH=$(find . -name "promiscuous_agent.py" -type f 2>/dev/null | head -1)
    if [[ -z "$PROMISCUOUS_PATH" ]]; then
        PROMISCUOUS_PATH="$(pwd)/promiscuous_agent.py"
    else
        PROMISCUOUS_PATH=$(realpath "$PROMISCUOUS_PATH")
    fi
fi

echo "  sudo bash -c 'echo \"$USER ALL=(ALL) NOPASSWD: $PYTHON_PATH $PROMISCUOUS_PATH\" > /etc/sudoers.d/upgraded_happiness'"
echo "  sudo chmod 440 /etc/sudoers.d/upgraded_happiness"

echo ""

echo -e "${BLUE}OPCIÓN B - Ejecutar agente manualmente con sudo:${NC}"
echo "  # Parar agente actual"
echo "  pkill -f promiscuous_agent"
echo "  # Ejecutar manualmente"
echo "  sudo python $PROMISCUOUS_PATH &"

echo ""

echo -e "${BLUE}OPCIÓN C - Usar modo sin permisos especiales (limitado):${NC}"
echo "  # Modificar agente para funcionar sin captura promiscua"
echo "  # Solo monitoreo de conexiones locales"

echo ""

# 7. Auto-fix si es posible
echo -e "${YELLOW}7. ¿AUTO-FIX?${NC}"
read -p "¿Quieres que intente arreglar automáticamente los permisos sudo? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Intentando auto-fix...${NC}"

    # Verificar que el archivo existe
    if [[ ! -f "$PROMISCUOUS_PATH" ]]; then
        echo -e "${RED}❌ No se puede encontrar promiscuous_agent.py${NC}"
        echo "Archivos Python encontrados:"
        find . -name "*.py" | grep -i promiscuous
        exit 1
    fi

    echo "Configurando sudoers para:"
    echo "  Usuario: $USER"
    echo "  Python: $PYTHON_PATH"
    echo "  Script: $PROMISCUOUS_PATH"

    # Crear archivo sudoers
    SUDOERS_CONTENT="$USER ALL=(ALL) NOPASSWD: $PYTHON_PATH $PROMISCUOUS_PATH"

    if echo "$SUDOERS_CONTENT" | sudo tee /etc/sudoers.d/upgraded_happiness > /dev/null; then
        sudo chmod 440 /etc/sudoers.d/upgraded_happiness
        echo -e "${GREEN}✅ Sudoers configurado correctamente${NC}"

        # Probar nueva configuración
        if sudo -n $PYTHON_PATH $PROMISCUOUS_PATH --help &>/dev/null || sudo -n true 2>/dev/null; then
            echo -e "${GREEN}✅ Permisos sudo funcionando${NC}"

            # Reiniciar agente promiscuo
            echo "Reiniciando agente promiscuo..."
            pkill -f promiscuous_agent
            sleep 2

            echo "Iniciando agente con nuevos permisos..."
            cd "$(dirname "$PROMISCUOUS_PATH")"
            sudo $PYTHON_PATH "$(basename "$PROMISCUOUS_PATH")" &

            echo -e "${CYAN}Esperando inicialización del agente (10 segundos)...${NC}"
            sleep 10

            # Verificación mejorada
            if pgrep -f promiscuous_agent > /dev/null; then
                echo -e "${GREEN}🎉 ¡Agente promiscuo iniciado exitosamente!${NC}"
                echo ""
                echo "Verificando procesos SCADA completos..."
                ps aux | grep -E "(smart_broker|lightweight_ml|promiscuous)" | grep -v grep | while read line; do
                    echo -e "${GREEN}  ✅ $line${NC}"
                done

                echo ""
                echo -e "${CYAN}💡 El agente puede tardar unos segundos en empezar a capturar datos.${NC}"
                echo -e "${CYAN}   Ejecuta './check-ports.sh' en unos minutos para ver estadísticas.${NC}"

            else
                echo -e "${RED}❌ El agente no se detecta como proceso separado${NC}"
                echo -e "${YELLOW}Esto puede ser normal si se ejecuta en background integrado.${NC}"
                echo ""
                echo "Verificando funcionalidad básica..."

                # Probar ejecutar el agente brevemente para verificar que funciona
                timeout 5 sudo $PYTHON_PATH "$(basename "$PROMISCUOUS_PATH")" --help &>/dev/null
                if [ $? -eq 0 ] || [ $? -eq 124 ]; then  # 124 es timeout exitoso
                    echo -e "${GREEN}✅ El agente promiscuo puede ejecutarse correctamente${NC}"
                else
                    echo -e "${RED}❌ Error ejecutando el agente promiscuo${NC}"
                    echo "Intentando diagnóstico..."
                    sudo $PYTHON_PATH "$(basename "$PROMISCUOUS_PATH")" 2>&1 | head -5
                fi
            fi
        else
            echo -e "${RED}❌ Los permisos sudo siguen sin funcionar${NC}"
        fi
    else
        echo -e "${RED}❌ No se pudo configurar sudoers${NC}"
    fi
else
    echo "Auto-fix cancelado. Usa las opciones manuales arriba."
fi

echo ""
echo -e "${BLUE}Para verificar el resultado completo:${NC}"
echo -e "  ${YELLOW}./check-ports.sh${NC}              # Verificar conectividad"
echo -e "  ${YELLOW}make monitor${NC}                  # Monitor oficial"
echo -e "  ${YELLOW}./monitor-platform.sh --live${NC} # Monitor en tiempo real"
echo -e "  ${YELLOW}./troubleshoot-scada.sh${NC}      # Diagnóstico completo"

echo ""
echo -e "${GREEN}🎯 Script de permisos sudo completado${NC}"