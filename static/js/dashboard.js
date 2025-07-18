/*
dashboard.js - VERSIÓN SIMPLE SIN WEBSOCKET
Usa tu sistema ZeroMQ existente via HTTP polling
*/

// ============================================================================
// VARIABLES GLOBALES
// ============================================================================

let map = null;
let markers = [];
let eventCount = 0;
let highRiskCount = 0;
let pollingInterval = null;
let currentEvents = [];
let eventsPaused = false;

// ============================================================================
// INICIALIZACIÓN PRINCIPAL
// ============================================================================

function initializeDashboard() {
    console.log('🚀 Inicializando Dashboard SCADA...');

    try {
        // Inicializar componentes principales
        initializeMap();
        initializeEventHandlers();
        initializeCollapsibleSections();

        // *** CAMBIO PRINCIPAL: HTTP Polling en lugar de WebSocket ***
        startSimplePolling();

        updateCurrentTime();
        setInterval(updateCurrentTime, 1000);

        console.log('✅ Dashboard inicializado correctamente');
        addDebugLog('info', 'Dashboard inicializado - usando HTTP polling');

    } catch (error) {
        console.error('❌ Error inicializando dashboard:', error);
        addDebugLog('error', `Error inicialización: ${error.message}`);
    }
}

// ============================================================================
// HTTP POLLING SIMPLE (REEMPLAZA WEBSOCKET)
// ============================================================================

function startSimplePolling() {
    console.log('📡 Iniciando polling HTTP simple...');

    // Llamada inicial
    fetchDataFromZeroMQ();

    // Polling cada 2 segundos
    pollingInterval = setInterval(fetchDataFromZeroMQ, 2000);

    addDebugLog('info', 'HTTP polling iniciado - conectando con ZeroMQ');
}

async function fetchDataFromZeroMQ() {
    try {
        const response = await fetch('/api/metrics', {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Cache-Control': 'no-cache'
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        if (data.success) {
            // Procesar datos de tu sistema ZeroMQ
            updateDashboardFromZeroMQ(data);
            updateConnectionStatus('api', 'connected');

            console.log('📊 Datos ZeroMQ recibidos:', data.basic_stats);

        } else {
            throw new Error(data.error || 'Error en respuesta API');
        }

    } catch (error) {
        console.error('❌ Error conectando con ZeroMQ:', error);
        updateConnectionStatus('api', 'error');
        addDebugLog('error', `Error ZeroMQ: ${error.message}`);
    }
}

function updateDashboardFromZeroMQ(data) {
    try {
        // Actualizar métricas básicas desde ZeroMQ
        if (data.basic_stats) {
            updateElement('events-per-min', data.basic_stats.events_per_minute || 0);
            updateElement('high-risk-count', data.basic_stats.high_risk_events || 0);
            updateElement('success-rate', data.basic_stats.success_rate || 0);
            updateElement('failure-count', data.basic_stats.failures || 0);

            updateElement('events-count', data.basic_stats.total_events || 0);
            updateElement('commands-count', data.basic_stats.commands_sent || 0);
            updateElement('confirmations-count', data.basic_stats.confirmations || 0);

            // Actualizar contadores en header
            updateElement('events-counter', data.basic_stats.total_events || 0);
            updateElement('confirmations-counter', data.basic_stats.confirmations || 0);

            eventCount = data.basic_stats.total_events || 0;
            highRiskCount = data.basic_stats.high_risk_events || 0;
        }

        // Actualizar estado de componentes ZeroMQ
        if (data.component_status) {
            updateComponentStatus(data.component_status);
        }

        // Actualizar conexiones ZeroMQ
        if (data.zmq_connections) {
            updateZMQStatus(data.zmq_connections);
        }

        // Procesar eventos recientes de ZeroMQ
        if (data.recent_events && data.recent_events.length > 0) {
            processEventsFromZeroMQ(data.recent_events);
        }

        addDebugLog('info', `ZeroMQ: ${data.basic_stats?.total_events || 0} eventos, ${data.basic_stats?.high_risk_events || 0} alto riesgo`);

    } catch (error) {
        console.error('❌ Error procesando datos ZeroMQ:', error);
        addDebugLog('error', `Error procesando ZeroMQ: ${error.message}`);
    }
}

function processEventsFromZeroMQ(events) {
    if (eventsPaused) return;

    try {
        // Filtrar eventos nuevos que no hemos visto
        const newEvents = events.filter(event => {
            return !currentEvents.some(existing =>
                existing.id === event.id ||
                (existing.timestamp === event.timestamp &&
                 existing.source_ip === event.source_ip)
            );
        });

        // Procesar cada evento nuevo
        newEvents.forEach(event => {
            addEventFromZeroMQ(event);
        });

        if (newEvents.length > 0) {
            console.log(`📨 ${newEvents.length} eventos nuevos desde ZeroMQ`);
        }

    } catch (error) {
        console.error('❌ Error procesando eventos ZeroMQ:', error);
        addDebugLog('error', `Error eventos ZeroMQ: ${error.message}`);
    }
}

// ============================================================================
// MANEJO DE EVENTOS DESDE ZEROMQ
// ============================================================================

function addEventFromZeroMQ(event) {
    try {
        // Validar evento
        if (!event.source_ip || !event.target_ip) {
            console.warn('⚠️ Evento ZeroMQ incompleto:', event);
            return;
        }

        // Asegurar campos requeridos
        if (typeof event.risk_score !== 'number') {
            event.risk_score = 0.5;
        }

        if (!event.timestamp) {
            event.timestamp = Date.now() / 1000;
        }

        // Añadir al mapa si tiene coordenadas
        if (event.latitude && event.longitude &&
            event.latitude !== 0 && event.longitude !== 0) {
            addEventMarkerToMap(event);
        }

        // Añadir a la lista de eventos
        addEventToEventsList(event);

        // Mostrar indicador si es alto riesgo
        if (event.risk_score > 0.8) {
            showThreatIndicator(event);
        }

        console.log('🚨 Evento ZeroMQ procesado:', event.source_ip, '→', event.target_ip);

    } catch (error) {
        console.error('❌ Error añadiendo evento ZeroMQ:', error);
        addDebugLog('error', `Error evento: ${error.message}`);
    }
}

function addEventToEventsList(event) {
    const eventsList = document.getElementById('events-list');
    if (!eventsList) return;

    try {
        // Remover placeholder si existe
        const placeholder = eventsList.querySelector('.no-events-placeholder');
        if (placeholder) {
            placeholder.remove();
        }

        const riskLevel = event.risk_score > 0.8 ? 'high' :
                         event.risk_score > 0.5 ? 'medium' : 'low';

        const eventElement = document.createElement('div');
        eventElement.className = `event-item risk-${riskLevel} new-event`;
        eventElement.onclick = () => showEventDetail(event);

        // Convertir timestamp
        const eventTime = new Date(event.timestamp * 1000);

        eventElement.innerHTML = `
            <div class="event-header">
                <span class="event-time">${eventTime.toLocaleTimeString()}</span>
                <span class="event-risk ${riskLevel}">${(event.risk_score * 100).toFixed(0)}%</span>
            </div>
            <div class="event-details">
                <div><span class="event-source">${event.source_ip}</span> → <span class="event-target">${event.target_ip}</span></div>
                <div class="event-type">${event.type || 'ZeroMQ Event'}</div>
            </div>
        `;

        // Insertar al principio
        eventsList.insertBefore(eventElement, eventsList.firstChild);

        // Mantener máximo 50 eventos
        const events = eventsList.querySelectorAll('.event-item');
        if (events.length > 50) {
            events[events.length - 1].remove();
        }

        // Actualizar contador
        updateElement('live-events-count', events.length);

        // Guardar en array
        currentEvents.unshift(event);
        if (currentEvents.length > 50) {
            currentEvents.pop();
        }

    } catch (error) {
        console.error('❌ Error añadiendo evento a lista:', error);
    }
}

function addEventMarkerToMap(event) {
    if (!map) return;

    try {
        const riskLevel = event.risk_score > 0.8 ? 'high' :
                         event.risk_score > 0.5 ? 'medium' : 'low';

        const colors = {
            high: '#ff4444',
            medium: '#ffaa00',
            low: '#00ff00'
        };

        const marker = L.circleMarker([event.latitude, event.longitude], {
            radius: 8,
            fillColor: colors[riskLevel],
            color: colors[riskLevel],
            weight: 2,
            opacity: 0.8,
            fillOpacity: 0.6
        }).bindPopup(`
            <div style="color: #000; font-family: 'Consolas', monospace; font-size: 11px;">
                <b>🚨 Evento ZeroMQ</b><br>
                <strong>Origen:</strong> ${event.source_ip}<br>
                <strong>Destino:</strong> ${event.target_ip}<br>
                <strong>Riesgo:</strong> <span style="color: ${colors[riskLevel]};">${(event.risk_score * 100).toFixed(0)}%</span><br>
                <strong>Tipo:</strong> ${event.type || 'ZeroMQ'}<br>
                <strong>Ubicación:</strong> ${event.location || 'No disponible'}<br>
                <strong>Timestamp:</strong> ${new Date(event.timestamp * 1000).toLocaleString()}
            </div>
        `).addTo(map);

        marker._isEventMarker = true;
        markers.push(marker);

        // Auto-remover después de 5 minutos
        setTimeout(() => {
            if (map.hasLayer(marker)) {
                map.removeLayer(marker);
                markers = markers.filter(m => m !== marker);
            }
        }, 5 * 60 * 1000);

        console.log('📍 Marcador ZeroMQ añadido:', event.source_ip);

    } catch (error) {
        console.error('❌ Error añadiendo marcador:', error);
    }
}

// ============================================================================
// INICIALIZACIÓN DEL MAPA (SIN CAMBIOS)
// ============================================================================

function initializeMap() {
    try {
        console.log('🗺️ Inicializando mapa Leaflet...');

        if (typeof L === 'undefined') {
            throw new Error('Leaflet no está disponible');
        }

        const mapContainer = document.getElementById('map');
        if (!mapContainer) {
            throw new Error('Contenedor del mapa no encontrado');
        }

        map = L.map('map', {
            zoomControl: true,
            attributionControl: true,
            minZoom: 2,
            maxZoom: 18
        }).setView([40.4168, -3.7038], 6);

        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors',
            maxZoom: 18,
            subdomains: ['a', 'b', 'c'],
            crossOrigin: true
        }).addTo(map);

        map.on('load', function() {
            console.log('✅ Mapa cargado');
            addInitialMarkers();
            addDebugLog('info', 'Mapa Leaflet cargado');
        });

        setTimeout(() => {
            if (map) {
                map.invalidateSize();
            }
        }, 500);

        console.log('✅ Mapa inicializado');
        addDebugLog('info', 'Mapa inicializado correctamente');

    } catch (error) {
        console.error('❌ Error inicializando mapa:', error);
        addDebugLog('error', `Error mapa: ${error.message}`);
        handleMapError(error);
    }
}

function addInitialMarkers() {
    if (!map) return;

    try {
        const madridMarker = L.marker([40.4168, -3.7038])
            .bindPopup('<b>🖥️ Dashboard Principal</b><br>Madrid, España<br>ZeroMQ Dashboard')
            .addTo(map);

        const barcelonaMarker = L.marker([41.3851, 2.1734])
            .bindPopup('<b>🔄 Nodo Remoto</b><br>Barcelona, España<br>ZeroMQ Node')
            .addTo(map);

        const sevillaMarker = L.marker([37.3886, -5.9823])
            .bindPopup('<b>🔥 Firewall Agent</b><br>Sevilla, España<br>ZeroMQ Firewall')
            .addTo(map);

        markers.push(madridMarker, barcelonaMarker, sevillaMarker);

        console.log('✅ Marcadores iniciales añadidos');

    } catch (error) {
        console.error('❌ Error añadiendo marcadores:', error);
    }
}

function handleMapError(error) {
    const mapContainer = document.getElementById('map');
    if (mapContainer) {
        mapContainer.innerHTML = `
            <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: #ff4444; font-weight: bold; text-align: center; padding: 20px;">
                <i class="fas fa-exclamation-triangle" style="font-size: 48px; margin-bottom: 20px;"></i>
                <div style="font-size: 18px; margin-bottom: 10px;">❌ Error cargando mapa</div>
                <div style="font-size: 12px; opacity: 0.8;">${error.message}</div>
                <button onclick="initializeMap()" style="margin-top: 20px; background: rgba(0, 255, 0, 0.2); border: 1px solid #00ff00; color: #00ff00; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-family: inherit;">🔄 Reintentar</button>
            </div>
        `;
    }
}

// ============================================================================
// CONTROLES DEL MAPA
// ============================================================================

function clearAllMarkers() {
    if (!map) return;

    try {
        markers.forEach(marker => {
            if (marker._isEventMarker) {
                map.removeLayer(marker);
            }
        });

        markers = markers.filter(marker => !marker._isEventMarker);

        console.log('🗺️ Marcadores de eventos limpiados');
        showToast('Marcadores limpiados', 'success');
        addDebugLog('info', 'Marcadores de eventos limpiados');

    } catch (error) {
        console.error('❌ Error limpiando marcadores:', error);
    }
}

function centerMap() {
    if (!map) return;

    try {
        map.setView([40.4168, -3.7038], 6);
        console.log('🎯 Mapa centrado');
        showToast('Mapa centrado', 'info');

    } catch (error) {
        console.error('❌ Error centrando mapa:', error);
    }
}

// ============================================================================
// FUNCIONES DE PRUEBA
// ============================================================================

async function sendTestFirewallEvent() {
    try {
        console.log('🧪 Enviando test via ZeroMQ...');
        showToast('Enviando test al firewall...', 'info');

        const response = await fetch('/api/test-firewall', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                test_type: 'zeromq_test',
                source: 'dashboard'
            })
        });

        const result = await response.json();

        if (result.success) {
            showToast('Test enviado correctamente via ZeroMQ', 'success');
            console.log('✅ Test ZeroMQ exitoso:', result);
            addDebugLog('info', 'Test firewall enviado via ZeroMQ');

            // Actualizar datos inmediatamente
            setTimeout(fetchDataFromZeroMQ, 500);
        } else {
            showToast('Error en test: ' + result.message, 'error');
            addDebugLog('error', `Error test: ${result.message}`);
        }

    } catch (error) {
        console.error('❌ Error test firewall:', error);
        showToast('Error comunicando con ZeroMQ', 'error');
        addDebugLog('error', `Error test: ${error.message}`);
    }
}

// ============================================================================
// RESTO DE FUNCIONES (UI, HELPERS, ETC.)
// ============================================================================

function updateComponentStatus(components) {
    Object.keys(components).forEach(componentName => {
        const component = components[componentName];
        const healthElement = document.getElementById(`${componentName}-health`);

        if (healthElement) {
            healthElement.textContent = component.status || 'UNKNOWN';
            healthElement.className = `component-health ${component.status?.toLowerCase() || 'unknown'}`;
        }

        if (component.metrics) {
            Object.keys(component.metrics).forEach(metric => {
                updateElement(`${componentName}-${metric}`, component.metrics[metric]);
            });
        }
    });
}

function updateZMQStatus(connections) {
    Object.keys(connections).forEach(connName => {
        const conn = connections[connName];
        const statusElement = document.getElementById(`${connName}-status`);

        if (statusElement) {
            statusElement.textContent = conn.status?.toUpperCase() || 'UNKNOWN';
            statusElement.className = `connection-status ${conn.status || 'unknown'}`;
        }
    });
}

function updateConnectionStatus(connection, status) {
    const statusElement = document.getElementById(`status-${connection}`);
    if (statusElement) {
        statusElement.className = `status-dot ${status}`;
    }
}

function updateCurrentTime() {
    const timeElement = document.getElementById('current-time');
    if (timeElement) {
        timeElement.textContent = new Date().toLocaleTimeString();
    }
}

function updateElement(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

function addDebugLog(type, message) {
    const debugLog = document.getElementById('debug-log');
    if (!debugLog) return;

    try {
        const timestamp = new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        entry.innerHTML = `[${type.toUpperCase()}] ${timestamp} - ${message}`;

        debugLog.insertBefore(entry, debugLog.firstChild);

        const entries = debugLog.querySelectorAll('.log-entry');
        if (entries.length > 100) {
            entries[entries.length - 1].remove();
        }

    } catch (error) {
        console.error('Error añadiendo debug log:', error);
    }
}

// Funciones de UI (sin cambios significativos)
function initializeEventHandlers() {
    const pauseBtn = document.getElementById('pause-events-btn');
    if (pauseBtn) {
        pauseBtn.addEventListener('click', pauseEventsUpdate);
    }

    const eventsFilter = document.getElementById('events-filter');
    if (eventsFilter) {
        eventsFilter.addEventListener('change', filterEvents);
    }
}

function initializeCollapsibleSections() {
    const sections = ['architecture', 'components', 'events', 'counters', 'zmq', 'debug'];

    sections.forEach(sectionId => {
        const toggleIcon = document.getElementById(`${sectionId}-toggle`);
        const content = document.getElementById(`${sectionId}-content`);

        if (toggleIcon && content) {
            content.classList.remove('collapsed');
            toggleIcon.classList.remove('rotated');
        }
    });
}

function toggleSection(sectionId) {
    const content = document.getElementById(`${sectionId}-content`);
    const toggle = document.getElementById(`${sectionId}-toggle`);
    const section = document.getElementById(`${sectionId}-section`);

    if (content && toggle) {
        const isCollapsed = content.classList.contains('collapsed');

        if (isCollapsed) {
            content.classList.remove('collapsed');
            toggle.classList.remove('rotated');
            if (section) section.classList.add('expanded');
        } else {
            content.classList.add('collapsed');
            toggle.classList.add('rotated');
            if (section) section.classList.remove('expanded');
        }
    }
}

function pauseEventsUpdate() {
    eventsPaused = !eventsPaused;
    const btn = document.getElementById('pause-events-btn');

    if (btn) {
        if (eventsPaused) {
            btn.innerHTML = '<i class="fas fa-play"></i>';
            btn.classList.add('paused');
            showToast('Eventos pausados', 'warning');
            addDebugLog('warning', 'Actualización de eventos pausada');
        } else {
            btn.innerHTML = '<i class="fas fa-pause"></i>';
            btn.classList.remove('paused');
            showToast('Eventos reanudados', 'success');
            addDebugLog('info', 'Actualización de eventos reanudada');
        }
    }
}

function clearEventsList() {
    const eventsList = document.getElementById('events-list');
    if (eventsList) {
        eventsList.innerHTML = `
            <div class="no-events-placeholder">
                <i class="fas fa-inbox"></i>
                <p>No hay eventos recientes</p>
                <button onclick="sendTestFirewallEvent()" class="btn btn-primary">
                    🧪 Generar Test ZeroMQ
                </button>
            </div>
        `;
        updateElement('live-events-count', 0);
        currentEvents = [];
        addDebugLog('info', 'Lista de eventos limpiada');
    }
}

function filterEvents() {
    const filter = document.getElementById('events-filter').value;
    const eventItems = document.querySelectorAll('.event-item:not(.no-events-placeholder)');

    eventItems.forEach(item => {
        const riskLevel = item.className.includes('risk-high') ? 'high' :
                         item.className.includes('risk-medium') ? 'medium' : 'low';

        if (filter === 'all' || filter === riskLevel) {
            item.style.display = 'block';
        } else {
            item.style.display = 'none';
        }
    });
}

function refreshDashboard() {
    console.log('🔄 Refrescando dashboard...');
    fetchDataFromZeroMQ();

    if (map) {
        map.invalidateSize();
    }

    showToast('Dashboard actualizado', 'success');
    addDebugLog('info', 'Dashboard refrescado - datos ZeroMQ');
}

function clearDebugLog() {
    const debugLog = document.getElementById('debug-log');
    if (debugLog) {
        debugLog.innerHTML = `
            <div class="log-entry info">[INFO] ${new Date().toLocaleTimeString()} - Log limpiado</div>
            <div class="log-entry info">[INFO] ${new Date().toLocaleTimeString()} - Dashboard ZeroMQ activo</div>
        `;
    }
    showToast('Log limpiado', 'info');
}

// Funciones de modal y toast (sin cambios)
function showModal(title, content, actions = null) {
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('detail-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const modalActions = document.getElementById('modal-actions');

    if (overlay && modal && modalTitle && modalContent) {
        modalTitle.textContent = title;
        modalContent.innerHTML = content;

        if (actions && modalActions) {
            modalActions.innerHTML = actions;
        } else if (modalActions) {
            modalActions.innerHTML = '';
        }

        overlay.style.display = 'block';
        modal.style.display = 'block';
        overlay.onclick = closeModal;
    }
}

function closeModal() {
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('detail-modal');

    if (overlay && modal) {
        overlay.style.display = 'none';
        modal.style.display = 'none';
    }
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    }, 4000);
}

function showThreatIndicator(event) {
    const indicator = document.getElementById('threat-indicator');
    if (indicator) {
        indicator.innerHTML = `
            ⚠️ Amenaza ZeroMQ detectada!<br>
            <small>${event.source_ip} → ${event.target_ip}</small>
        `;
        indicator.classList.add('show');

        setTimeout(() => {
            indicator.classList.remove('show');
        }, 5000);
    }
}

function showEventDetail(event) {
    const content = `
        <div style="font-family: 'Consolas', monospace;">
            <h4 style="color: #00ff88; margin-bottom: 15px;">🚨 Evento ZeroMQ</h4>

            <div style="margin-bottom: 10px;">
                <strong>Timestamp:</strong> ${new Date(event.timestamp * 1000).toLocaleString()}
            </div>
            <div style="margin-bottom: 10px;">
                <strong>IP Origen:</strong> <span style="color: #ff4444;">${event.source_ip}</span>
            </div>
            <div style="margin-bottom: 10px;">
                <strong>IP Destino:</strong> <span style="color: #00ff88;">${event.target_ip}</span>
            </div>
            <div style="margin-bottom: 10px;">
                <strong>Score de Riesgo:</strong> <span style="color: ${event.risk_score > 0.8 ? '#ff4444' : event.risk_score > 0.5 ? '#ffaa00' : '#00ff00'};">${(event.risk_score * 100).toFixed(1)}%</span>
            </div>

            ${event.type ? `<div style="margin-bottom: 10px;"><strong>Tipo:</strong> ${event.type}</div>` : ''}
            ${event.location ? `<div style="margin-bottom: 10px;"><strong>Ubicación:</strong> ${event.location}</div>` : ''}

            <div style="margin-top: 15px; padding: 10px; background: rgba(0,0,0,0.6); border-radius: 4px;">
                <strong>Datos ZeroMQ:</strong><br>
                <pre style="font-size: 9px; color: #666; margin-top: 5px;">${JSON.stringify(event, null, 2)}</pre>
            </div>
        </div>
    `;

    showModal('Detalle del Evento ZeroMQ', content);
}

// Funciones placeholder (sin cambios)
function toggleHeatmap() { showToast('Heatmap: en desarrollo', 'warning'); }
function showMapLegend() { showToast('Leyenda: en desarrollo', 'info'); }
function testAllConnections() { showToast('Test conexiones: en desarrollo', 'info'); }

// Funciones placeholder para handlers del HTML
function showConnectionDetails(type) { console.log('Connection details:', type); }
function showSystemInfo() { console.log('System info'); }
function showEventsSummary() { console.log('Events summary'); }
function showConfirmationsSummary() { console.log('Confirmations summary'); }
function showPortDetails(port, event) { console.log('Port details:', port); event?.stopPropagation(); }
function showEventsDetail(event) { console.log('Events detail'); event?.stopPropagation(); }
function showCommandsDetail(event) { console.log('Commands detail'); event?.stopPropagation(); }
function showConfirmationsDetail(event) { console.log('Confirmations detail'); event?.stopPropagation(); }
function showComponentDetail(component) { console.log('Component detail:', component); }
function showComponentMetric(metric, event) { console.log('Component metric:', metric); event?.stopPropagation(); }
function showTopologyLineDetail(line) { console.log('Topology line:', line); }
function showZMQConnectionDetail(connection) { console.log('ZMQ connection:', connection); }
function showEventsPerMinuteDetail() { console.log('Events per minute detail'); }
function showHighRiskEventsDetail() { console.log('High risk events detail'); }
function showSuccessRateDetail() { console.log('Success rate detail'); }
function showFailuresDetail() { console.log('Failures detail'); }
function showDebugLogDetail() { console.log('Debug log detail'); }
function showLogEntryDetail(entry, event) { console.log('Log entry:', entry); event?.stopPropagation(); }

// Cleanup
window.addEventListener('beforeunload', function() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
    }
});

// La inicialización se maneja desde HTML con DOMContentLoaded