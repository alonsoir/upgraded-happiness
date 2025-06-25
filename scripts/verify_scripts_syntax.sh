#!/bin/bash

# Script para verificar la sintaxis de todos los scripts bash en el directorio scripts/

echo "🔍 Verificando sintaxis de scripts bash..."
echo "=========================================="

SCRIPTS_DIR="scripts"
SUCCESS_COUNT=0
TOTAL_COUNT=0
FAILED_SCRIPTS=()

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_script_syntax() {
    local script_file="$1"
    local script_name=$(basename "$script_file")

    echo -n "Checking $script_name... "

    # Verificar sintaxis bash básica
    if bash -n "$script_file" 2>/dev/null; then
        echo -e "${GREEN}✅ OK${NC}"
        ((SUCCESS_COUNT++))
    else
        echo -e "${RED}❌ SYNTAX ERROR${NC}"
        FAILED_SCRIPTS+=("$script_name")
        echo "  Error details:"
        bash -n "$script_file" 2>&1 | sed 's/^/    /'
    fi

    ((TOTAL_COUNT++))
}

# Verificar todos los scripts .sh en el directorio scripts/
if [ -d "$SCRIPTS_DIR" ]; then
    for script in "$SCRIPTS_DIR"/*.sh; do
        if [ -f "$script" ]; then
            check_script_syntax "$script"
        fi
    done
else
    echo "❌ Directory $SCRIPTS_DIR not found"
    exit 1
fi

echo ""
echo "=========================================="
echo "📊 Summary:"
echo "   Total scripts checked: $TOTAL_COUNT"
echo "   Syntax OK: $SUCCESS_COUNT"
echo "   Syntax errors: $((TOTAL_COUNT - SUCCESS_COUNT))"

if [ ${#FAILED_SCRIPTS[@]} -eq 0 ]; then
    echo -e "\n🎉 ${GREEN}All scripts have correct syntax!${NC}"
    exit 0
else
    echo -e "\n⚠️  ${YELLOW}Scripts with syntax errors:${NC}"
    for script in "${FAILED_SCRIPTS[@]}"; do
        echo "   - $script"
    done

    echo ""
    echo "💡 Common fixes:"
    echo "   • Add quotes around version specifiers: pip install \"package>=1.0.0\""
    echo "   • Check for missing quotes or brackets"
    echo "   • Verify proper escaping of special characters"

    exit 1
fi