#!/bin/bash

# Script manager para upgraded-happiness
# Ayuda a elegir y ejecutar los scripts correctos

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_header() {
    echo -e "\n${BLUE}===========================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}===========================================${NC}\n"
}

show_available_scripts() {
    print_header "🔧 UPGRADED-HAPPINESS SCRIPT MANAGER"

    echo "📁 Available scripts in scripts/ directory:"
    echo ""

    # Core setup scripts
    echo -e "${GREEN}🏗️  SETUP & INSTALLATION${NC}"
    echo "   setup_research_environment.sh     → Complete research environment setup"
    echo "   install_research_dependencies.sh  → Install only research dependencies"
    echo ""

    # Testing and verification
    echo -e "${GREEN}🧪 TESTING & VERIFICATION${NC}"
    echo "   run_protobuf_research.sh          → Run Protocol Buffers research workflow"
    echo "   ../test_setup.py                  → Verify SCADA + Research setup"
    echo "   ../verify_installation.py         → Complete system verification"
    echo ""

    # Quick commands
    echo -e "${GREEN}⚡ QUICK COMMANDS${NC}"
    echo "   manage_scripts.sh                 → This script (shows help)"
    echo ""

    echo -e "${YELLOW}💡 USAGE RECOMMENDATIONS:${NC}"
    echo ""
    echo "🎯 First-time setup (choose ONE):"
    echo "   Option A: bash scripts/setup_research_environment.sh"
    echo "   Option B: bash scripts/install_research_dependencies.sh"
    echo ""
    echo "🔍 Verification:"
    echo "   python test_setup.py"
    echo "   python verify_installation.py"
    echo ""
    echo "🚀 Research workflow:"
    echo "   bash scripts/run_protobuf_research.sh test"
    echo "   bash scripts/run_protobuf_research.sh benchmark"
    echo ""
    echo "🧪 Testing:"
    echo "   pytest tests/unit/test_protobuf_research.py -v"
}

check_environment() {
    print_header "🔍 ENVIRONMENT CHECK"

    # Check virtual environment
    if [[ "$VIRTUAL_ENV" != "" ]]; then
        echo -e "✅ Virtual environment: ${GREEN}$(basename $VIRTUAL_ENV)${NC}"
    else
        echo -e "⚠️  Virtual environment: ${YELLOW}Not activated${NC}"
        echo "   Recommended: source upgraded_happiness_venv/bin/activate"
    fi

    # Check Python version
    PYTHON_VERSION=$(python3 --version 2>/dev/null || echo "Not found")
    echo "🐍 Python version: $PYTHON_VERSION"

    # Check if core files exist
    echo ""
    echo "📁 Project structure:"

    local files_to_check=(
        "src/common/base_interfaces.py"
        "src/protocols/protobuff/protobuf_serializer.py"
        "tests/unit/test_protobuf_research.py"
        "requirements.txt"
    )

    for file in "${files_to_check[@]}"; do
        if [ -f "$file" ]; then
            echo -e "   ✅ $file"
        else
            echo -e "   ❌ $file ${YELLOW}(missing)${NC}"
        fi
    done

    # Check key dependencies
    echo ""
    echo "📦 Key dependencies:"

    python3 -c "
import sys
deps = [
    ('lz4', 'LZ4 compression'),
    ('google.protobuf', 'Protocol Buffers'),
    ('Crypto.Cipher', 'PyCryptodome'),
    ('aiofiles', 'Async file operations'),
    ('pytest', 'Testing framework')
]

for module, desc in deps:
    try:
        __import__(module)
        print(f'   ✅ {desc}')
    except ImportError:
        print(f'   ❌ {desc} (missing)')
" 2>/dev/null || echo "   ❌ Python check failed"
}

quick_fix_suggestions() {
    print_header "🛠️  QUICK FIX SUGGESTIONS"

    echo "If you see missing files or dependencies, try these:"
    echo ""
    echo "🔧 For missing dependencies:"
    echo "   bash scripts/install_research_dependencies.sh"
    echo ""
    echo "🔧 For missing project structure:"
    echo "   bash scripts/setup_research_environment.sh"
    echo ""
    echo "🔧 For import errors:"
    echo "   pip install -e ."
    echo "   # Also create missing __init__.py files:"
    echo "   touch src/__init__.py src/common/__init__.py src/protocols/__init__.py"
    echo ""
    echo "🔧 For virtual environment:"
    echo "   source upgraded_happiness_venv/bin/activate"
}

run_quick_test() {
    print_header "⚡ QUICK FUNCTIONALITY TEST"

    echo "Running basic functionality test..."

    python3 -c "
import sys
import os
sys.path.insert(0, 'src')

try:
    # Test basic imports
    from common.base_interfaces import CompressionAlgorithm, EncryptionAlgorithm
    from protocols.protobuff.protobuf_serializer import ProtobufEventSerializer

    print('✅ Core imports successful')

    # Test serializer creation
    serializer = ProtobufEventSerializer()
    print('✅ Serializer creation successful')

    print('')
    print('🎉 Basic functionality test PASSED!')
    print('Ready to run full tests with:')
    print('   pytest tests/unit/test_protobuf_research.py -v')

except ImportError as e:
    print(f'❌ Import error: {e}')
    print('')
    print('💡 Run this to fix:')
    print('   bash scripts/install_research_dependencies.sh')
    sys.exit(1)
except Exception as e:
    print(f'❌ Error: {e}')
    sys.exit(1)
"
}

main() {
    local command=${1:-"help"}

    case $command in
        "check"|"status")
            check_environment
            ;;
        "test")
            run_quick_test
            ;;
        "fix"|"suggest")
            quick_fix_suggestions
            ;;
        "help"|"list"|*)
            show_available_scripts
            echo ""
            echo "Usage: bash scripts/manage_scripts.sh [command]"
            echo ""
            echo "Commands:"
            echo "  help     - Show this help and available scripts"
            echo "  check    - Check environment and dependencies"
            echo "  test     - Run quick functionality test"
            echo "  fix      - Show fix suggestions"
            ;;
    esac
}

main "$@"