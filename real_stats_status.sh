# En otra terminal, verificar todos los procesos
ps aux | grep -E "(smart_broker|lightweight_ml|promiscuous)" | grep -v grep

# Ver estadísticas en tiempo real
watch "ps aux | grep -E '(smart_broker|lightweight_ml|promiscuous)' | grep -v grep"

# Verificar estado del sistema
make status