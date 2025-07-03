#!/bin/bash

# =============================================================================
# UPGRADED HAPPINESS - Nuclear Stop Integration Script
# =============================================================================
# Integra automáticamente el sistema de parada nuclear en el proyecto
# Modifica el Makefile existente para usar métodos de parada efectivos
# =============================================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[INTEGRATE]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo -e "${BLUE}🔧 INTEGRACIÓN DE SISTEMA NUCLEAR STOP${NC}\n"

# Verificar que estamos en el directorio correcto
if [[ ! -f "Makefile" ]]; then
    error "Makefile no encontrado. Ejecuta este script desde el directorio raíz del proyecto."
    exit 1
fi

if [[ ! -f "nuclear-stop.sh" ]]; then
    error "nuclear-stop.sh no encontrado. Asegúrate de haber descargado todos los scripts."
    exit 1
fi

# 1. Hacer backup del Makefile original
log "Creando backup del Makefile original..."
cp Makefile Makefile.backup.$(date +%Y%m%d_%H%M%S)
success "✅ Backup creado: Makefile.backup.$(date +%Y%m%d_%H%M%S)"

# 2. Hacer ejecutable el script nuclear
log "Configurando permisos del script nuclear..."
chmod +x nuclear-stop.sh
success "✅ nuclear-stop.sh es ejecutable"

# 3. Detectar la regla stop actual en el Makefile
log "Analizando Makefile actual..."

if grep -q "^stop:" Makefile; then
    log "Regla 'stop' existente encontrada, renombrando a 'stop-original'"

    # Crear versión temporal del Makefile
    sed 's/^stop:/stop-original:/' Makefile > Makefile.tmp

    success "✅ Regla stop original preservada como 'stop-original'"
else
    log "No se encontró regla 'stop' existente"
    cp Makefile Makefile.tmp
fi

# 4. Añadir las nuevas reglas nuclear al Makefile
log "Integrando reglas nuclear en el Makefile..."

cat >> Makefile.tmp << 'EOF'

# =============================================================================
# NUCLEAR STOP INTEGRATION - Auto-generated
# =============================================================================
# Sistema de parada efectivo que realmente funciona con procesos root
# Integrado automáticamente por integrate-nuclear-stop.sh
# =============================================================================

# Variables nuclear stop
NUCLEAR_STOP_SCRIPT := nuclear-stop.sh

# Setup nuclear stop
.PHONY: setup-nuclear-stop
setup-nuclear-stop:
	@if [ ! -f $(NUCLEAR_STOP_SCRIPT) ]; then \
		echo "❌ $(NUCLEAR_STOP_SCRIPT) requerido para parada efectiva"; \
		exit 1; \
	fi
	@chmod +x $(NUCLEAR_STOP_SCRIPT)

# NUEVA regla stop principal (nuclear)
.PHONY: stop
stop: setup-nuclear-stop
	@echo "🛑 Ejecutando parada nuclear completa..."
	@./$(NUCLEAR_STOP_SCRIPT)

# Stop de emergencia (máximo nivel)
.PHONY: emergency-stop
emergency-stop:
	@echo "🚨 EMERGENCY STOP - Máxima agresividad"
	@sudo pkill -9 -f "python.*promiscuous" 2>/dev/null || true
	@sudo pkill -9 -f "python.*broker" 2>/dev/null || true
	@sudo pkill -9 -f "python.*detector" 2>/dev/null || true
	@sudo pkill -9 -f "uvicorn" 2>/dev/null || true
	@sudo lsof -ti :5555,5556,8766,8080 | xargs sudo kill -9 2>/dev/null || true
	@sudo rm -f *.pid /tmp/*scada* /tmp/*broker* /tmp/*zmq* 2>/dev/null || true
	@echo "💀 Emergency stop completed"

# Verificar parada completa
.PHONY: verify-stop
verify-stop:
	@echo "🔍 Verificando estado de parada..."
	@echo "Procesos SCADA activos:"
	@ps aux | grep -E "(smart_broker|ml_detector|promiscuous_agent|uvicorn)" | grep -v grep || echo "✅ Sin procesos SCADA activos"
	@echo "Puertos SCADA ocupados:"
	@lsof -i :5555,5556,8766,8080 2>/dev/null || echo "✅ Todos los puertos SCADA libres"

# Status mejorado
.PHONY: status-detailed
status-detailed:
	@echo "📊 Estado detallado del sistema..."
	@echo "=== PROCESOS ==="
	@ps aux | grep -E "(smart_broker|ml_detector|promiscuous_agent|uvicorn)" | grep -v grep || echo "Sin procesos SCADA"
	@echo "=== PUERTOS ==="
	@for port in 5555 5556 8766 8080; do \
		echo "Puerto $$port:"; \
		lsof -i :$$port 2>/dev/null || echo "  Libre ✅"; \
	done

# Reinicio nuclear completo
.PHONY: restart-nuclear
restart-nuclear: stop
	@echo "🔄 Esperando estabilización..."
	@sleep 3
	@echo "🚀 Iniciando sistema limpio..."
	$(MAKE) quick-start

# Ciclo de mantenimiento completo
.PHONY: maintenance-cycle
maintenance-cycle:
	@echo "🔧 Ejecutando ciclo de mantenimiento completo..."
	$(MAKE) stop
	$(MAKE) verify-stop
	$(MAKE) fix-deps 2>/dev/null || true
	$(MAKE) quick-start
	@sleep 8
	$(MAKE) status-detailed

# Help nuclear actualizado
.PHONY: help-nuclear
help-nuclear:
	@echo "🛑 COMANDOS DE PARADA NUCLEAR:"
	@echo "  stop              - Parada nuclear completa (NUEVO, RECOMENDADO)"
	@echo "  stop-original     - Método original (puede fallar con procesos root)"
	@echo "  emergency-stop    - Parada de emergencia máxima"
	@echo "  verify-stop       - Verificar parada completa"
	@echo ""
	@echo "🔄 REINICIO MEJORADO:"
	@echo "  restart-nuclear   - Parada nuclear + inicio limpio"
	@echo "  maintenance-cycle - Mantenimiento completo"
	@echo ""
	@echo "📊 MONITOREO:"
	@echo "  status-detailed   - Estado completo del sistema"
	@echo ""
	@echo "💡 NOTA: 'make stop' ahora usa parada nuclear efectiva"

EOF

# 5. Reemplazar el Makefile original
mv Makefile.tmp Makefile
success "✅ Makefile actualizado con sistema nuclear"

# 6. Verificar la integración
log "Verificando integración..."

if grep -q "stop: setup-nuclear-stop" Makefile; then
    success "✅ Regla nuclear stop integrada correctamente"
else
    error "❌ Error en la integración"
    log "Restaurando backup..."
    mv Makefile.backup.* Makefile
    exit 1
fi

# 7. Probar el nuevo sistema
log "Probando el nuevo sistema nuclear..."

if make setup-nuclear-stop &>/dev/null; then
    success "✅ Sistema nuclear configurado correctamente"
else
    warning "⚠️ Configuración nuclear con problemas, pero integración completada"
fi

# 8. Resumen final
echo -e "\n${GREEN}🎉 INTEGRACIÓN NUCLEAR COMPLETADA${NC}\n"

echo -e "${CYAN}✅ CAMBIOS REALIZADOS:${NC}"
echo -e "  • Makefile respaldado automáticamente"
echo -e "  • Regla 'stop' original → 'stop-original'"
echo -e "  • Nueva regla 'stop' → usa nuclear-stop.sh"
echo -e "  • Añadidas reglas: emergency-stop, verify-stop, restart-nuclear"
echo -e "  • nuclear-stop.sh configurado como ejecutable"

echo -e "\n${CYAN}🚀 NUEVOS COMANDOS DISPONIBLES:${NC}"
echo -e "  ${YELLOW}make stop${NC}              - Parada nuclear efectiva (NUEVO)"
echo -e "  ${YELLOW}make stop-original${NC}     - Método anterior (fallback)"
echo -e "  ${YELLOW}make emergency-stop${NC}    - Parada de emergencia"
echo -e "  ${YELLOW}make verify-stop${NC}       - Verificar parada completa"
echo -e "  ${YELLOW}make restart-nuclear${NC}   - Reinicio con parada nuclear"
echo -e "  ${YELLOW}make help-nuclear${NC}      - Ayuda del sistema nuclear"

echo -e "\n${CYAN}🔧 PRUEBA INMEDIATA:${NC}"
echo -e "  ${YELLOW}make help-nuclear${NC}      - Ver nuevas opciones"
echo -e "  ${YELLOW}make verify-stop${NC}       - Verificar estado actual"

echo -e "\n${BLUE}💡 El comando 'make stop' ahora realmente funciona con procesos root${NC}"
echo -e "${BLUE}🚀 Ya puedes usar el pipeline completo de parada efectiva${NC}"

# 9. Mostrar ayuda nuclear
echo -e "\n${CYAN}📖 AYUDA RÁPIDA:${NC}"
make help-nuclear 2>/dev/null || echo "Ejecuta 'make help-nuclear' para ver la ayuda completa"