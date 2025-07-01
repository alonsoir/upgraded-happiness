# Verificar que no hay procesos Python del proyecto corriendo
ps aux | grep python | grep -E "(orchestrator|dashboard|bitdefender)" | grep -v grep

# Verificar puertos libres
lsof -i :5555 2>/dev/null || echo "Puerto 5555 libre ✅"
lsof -i :8765 2>/dev/null || echo "Puerto 8765 libre ✅"
lsof -i :8766 2>/dev/null || echo "Puerto 8766 libre ✅"

# Ir al directorio principal
cd ~/git/upgraded-happiness

# Verificar estado limpio
echo "📍 Directorio actual: $(pwd)"
echo "🔍 Procesos Python activos:"
ps aux | grep python | grep -v grep | wc -l
echo "✅ Listo para análisis"