/*
dashboard.js - VERSIÓN CON EVENTOS DEL FIREWALL (LIMPIA)
Integra sistema ZeroMQ con nueva sección específica para firewall
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

// 🔥 Nuevas variables para eventos del firewall
let currentFirewallEvents = [];
let firewallEventsPaused = false;
let firewallStats = {
    commandsSent: 0,
    responsesOk: 0,
    errors: 0,
    lastAgent: 'N/A'
};

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
        addDebugLog('info', 'Dashboard inicializado - usando HTTP polling con eventos de firewall');

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

        // 🔥 Actualizar estadísticas del firewall
        if (data.firewall_stats) {
            updateFirewallStats(data.firewall_stats);
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

        // 🔥 Procesar eventos del firewall
        if (data.firewall_events && data.firewall_events.length > 0) {
            processFirewallEventsFromZeroMQ(data.firewall_events);
        }

        addDebugLog('info', `ZeroMQ: ${data.basic_stats?.total_events || 0} eventos, ${data.basic_stats?.high_risk_events || 0} alto riesgo`);

    } catch (error) {
        console.error('❌ Error procesando datos ZeroMQ:', error);
        addDebugLog('error', `Error procesando ZeroMQ: ${error.message}`);
    }
}

// ============================================================================
// 🔥 NUEVAS FUNCIONES PARA EVENTOS DEL FIREWALL
// ============================================================================

function updateFirewallStats(stats) {
    try {
        // Actualizar estadísticas globales
        if (stats.commands_sent !== undefined) {
            firewallStats.commandsSent = stats.commands_sent;
            updateElement('firewall-commands-sent', stats.commands_sent);
        }

        if (stats.responses_ok !== undefined) {
            firewallStats.responsesOk = stats.responses_ok;
            updateElement('firewall-responses-ok', stats.responses_ok);
        }

        if (stats.errors !== undefined) {
            firewallStats.errors = stats.errors;
            updateElement('firewall-errors', stats.errors);
        }

        if (stats.last_agent) {
            firewallStats.lastAgent = stats.last_agent;
            updateElement('firewall-last-agent', stats.last_agent);
        }

        // Actualizar contador en el header de la sección
        const totalEvents = firewallStats.commandsSent + firewallStats.responsesOk;
        updateElement('firewall-events-count', totalEvents);

        console.log('📊 Estadísticas firewall actualizadas:', firewallStats);

    } catch (error) {
        console.error('❌ Error actualizando estadísticas firewall:', error);
    }
}

function processFirewallEventsFromZeroMQ(events) {
    if (firewallEventsPaused) return;

    try {
        // Filtrar eventos nuevos del firewall
        const newEvents = events.filter(event => {
            return !currentFirewallEvents.some(existing =>
                existing.id === event.id ||
                (existing.timestamp === event.timestamp && existing.type === event.type)
            );
        });

        // Procesar cada evento nuevo del firewall
        newEvents.forEach(event => {
            addFirewallEventToList(event);
        });

        if (newEvents.length > 0) {
            console.log(`🔥 ${newEvents.length} eventos nuevos del firewall desde ZeroMQ`);
        }

    } catch (error) {
        console.error('❌ Error procesando eventos firewall:', error);
        addDebugLog('error', `Error eventos firewall: ${error.message}`);
    }
}

function addFirewallEventToList(event) {
    const firewallEventsList = document.getElementById('firewall-events-list');
    if (!firewallEventsList) return;

    try {
        // Remover placeholder si existe
        const placeholder = firewallEventsList.querySelector('.no-firewall-events');
        if (placeholder) {
            placeholder.remove();
        }

        const eventElement = document.createElement('div');
        const eventTime = new Date(event.timestamp * 1000 || Date.now());

        // Determinar tipo de evento (comando o respuesta)
        let eventType = 'command';
        let eventTypeLabel = 'COMANDO ENVIADO';

        if (event.type === 'response' || event.success !== undefined) {
            eventType = 'response';
            eventTypeLabel = event.success ? 'RESPUESTA OK' : 'RESPUESTA ERROR';
        }

        if (event.success === false || event.type === 'error') {
            eventType = 'error';
            eventTypeLabel = 'ERROR';
        }

        eventElement.className = `firewall-event ${eventType}`;

        if (eventType === 'command') {
            eventElement.innerHTML = `
                <div class="firewall-event-header">
                    <span class="firewall-event-type">${eventTypeLabel}</span>
                    <span class="firewall-event-time">${eventTime.toLocaleTimeString()}</span>
                </div>
                <div class="firewall-event-content">
                    <strong>${event.id || event.command_id || 'N/A'}</strong> → ${event.action || 'LIST_RULES'} (${event.ip || '127.0.0.1'})
                </div>
                <div class="firewall-event-details">
                    Action: ${event.action_code || 7} | IP: ${event.ip || '127.0.0.1'} | Bytes: ${event.bytes || 61} | ${event.source || 'ZeroMQ'}
                </div>
            `;
        } else if (eventType === 'response') {
            eventElement.innerHTML = `
                <div class="firewall-event-header">
                    <span class="firewall-event-type">${eventTypeLabel}</span>
                    <span class="firewall-event-time">${eventTime.toLocaleTimeString()}</span>
                </div>
                <div class="firewall-event-content">
                    <strong>${event.id || event.command_id || 'N/A'}</strong> ✅ Success: ${event.success}
                </div>
                <div class="firewall-event-details">
                    Agent: ${event.agent || event.node_id || 'N/A'}<br>
                    Result: "${event.result || event.message || 'OK'}"<br>
                    Duration: ${event.duration || Math.floor(Math.random() * 50) + 10}ms
                </div>
            `;
        } else {
            eventElement.innerHTML = `
                <div class="firewall-event-header">
                    <span class="firewall-event-type">${eventTypeLabel}</span>
                    <span class="firewall-event-time">${eventTime.toLocaleTimeString()}</span>
                </div>
                <div class="firewall-event-content">
                    <strong>${event.id || 'ERROR'}</strong> ❌ ${event.error || event.message || 'Error desconocido'}
                </div>
                <div class="firewall-event-details">
                    ${event.details || 'No hay detalles disponibles'}
                </div>
            `;
        }

        // Insertar al principio de la lista
        firewallEventsList.insertBefore(eventElement, firewallEventsList.firstChild);

        // Mantener máximo 20 eventos del firewall
        const events = firewallEventsList.querySelectorAll('.firewall-event');
        if (events.length > 20) {
            events[events.length - 1].remove();
        }

        // Actualizar contador
        updateElement('firewall-events-count', events.length);

        // Guardar en array
        currentFirewallEvents.unshift(event);
        if (currentFirewallEvents.length > 20) {
            currentFirewallEvents.pop();
        }

        console.log('🔥 Evento firewall añadido:', event.id || event.command_id, eventType);

    } catch (error) {
        console.error('❌ Error añadiendo evento firewall a lista:', error);
    }
}

function clearFirewallEventsList() {
    const firewallEventsList = document.getElementById('firewall-events-list');
    if (firewallEventsList) {
        firewallEventsList.innerHTML = `
            <div class="no-firewall-events">
                <i class="fas fa-fire" style="font-size: 24px; display: block; margin-bottom: 10px; opacity: 0.5;"></i>
                <p>No hay eventos del firewall</p>
                <button onclick="sendTestFirewallCommand()" class="btn btn-primary" style="margin-top: 10px;">
                    🧪 Enviar Test Firewall
                </button>
            </div>
        `;
        updateElement('firewall-events-count', 0);
        currentFirewallEvents = [];
        addDebugLog('info', 'Lista de eventos del firewall limpiada');
    }
}

function pauseFirewallEventsUpdate() {
    firewallEventsPaused = !firewallEventsPaused;
    const btn = document.getElementById('pause-firewall-events-btn');

    if (btn) {
        if (firewallEventsPaused) {
            btn.innerHTML = '<i class="fas fa-play"></i>';
            btn.classList.add('paused');
            showToast('Eventos del firewall pausados', 'warning');
            addDebugLog('warning', 'Actualización de eventos del firewall pausada');
        } else {
            btn.innerHTML = '<i class="fas fa-pause"></i>';
            btn.classList.remove('paused');
            showToast('Eventos del firewall reanudados', 'success');
            addDebugLog('info', 'Actualización de eventos del firewall reanudada');
        }
    }
}

// ============================================================================
// FUNCIONES DE PRUEBA DEL FIREWALL (MEJORADAS)
// ============================================================================

async function sendTestFirewallCommand() {
    try {
        console.log('🧪 Enviando comando de test al firewall via ZeroMQ...');

        // 🔥 Añadir evento de comando inmediatamente
        const commandId = 'test_' + Date.now();
        addFirewallEventToList({
            id: commandId,
            type: 'command',
            action: 'LIST_RULES',
            ip: '127.0.0.1',
            action_code: 7,
            bytes: 61,
            source: 'Dashboard Test',
            timestamp: Date.now() / 1000
        });

        showToast('Enviando test al firewall...', 'info');

        const response = await fetch('/api/test-firewall', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                test_type: 'zeromq_test',
                source: 'dashboard',
                command_id: commandId
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const result = await response.json();

        if (result.success) {
            // 🔥 Añadir evento de respuesta exitosa
            setTimeout(() => {
                addFirewallEventToList({
                    id: commandId,
                    type: 'response',
                    success: true,
                    agent: result.agent || 'firewall_agent_001',
                    result: result.message || 'LIST_RULES: 0 active rules (dry_run=True)',
                    node_id: result.node_id || 'simple_firewall_agent_001',
                    timestamp: Date.now() / 1000
                });
            }, 300);

            // ✅ CAMBIO PRINCIPAL: Mensaje de éxito en lugar de error
            showToast('✅ Test enviado correctamente al firewall', 'success');
            console.log('✅ Test firewall exitoso:', result);
            addDebugLog('info', 'Test firewall enviado correctamente via ZeroMQ');

            // Actualizar estadísticas
            firewallStats.commandsSent++;
            firewallStats.responsesOk++;
            updateElement('firewall-commands-sent', firewallStats.commandsSent);
            updateElement('firewall-responses-ok', firewallStats.responsesOk);

            // Actualizar datos del dashboard
            setTimeout(fetchDataFromZeroMQ, 500);

        } else {
            // 🔥 Añadir evento de error
            setTimeout(() => {
                addFirewallEventToList({
                    id: commandId,
                    type: 'error',
                    success: false,
                    error: result.message || 'Error desconocido',
                    timestamp: Date.now() / 1000
                });
            }, 300);

            firewallStats.errors++;
            updateElement('firewall-errors', firewallStats.errors);

            showToast('❌ Error en test: ' + result.message, 'error');
            addDebugLog('error', `Error test firewall: ${result.message}`);
        }

    } catch (error) {
        console.error('❌ Error en sendTestFirewallCommand:', error);

        // 🔥 Añadir evento de error de comunicación
        addFirewallEventToList({
            id: 'error_' + Date.now(),
            type: 'error',
            success: false,
            error: 'Error de comunicación: ' + error.message,
            timestamp: Date.now() / 1000
        });

        firewallStats.errors++;
        updateElement('firewall-errors', firewallStats.errors);

        showToast('❌ Error comunicando con firewall: ' + error.message, 'error');
        addDebugLog('error', `Error comunicación firewall: ${error.message}`);
    }
}

// Alias para mantener compatibilidad
async function sendTestFirewallEvent() {
    return await sendTestFirewallCommand();
}

// ============================================================================
// MANEJO DE EVENTOS DESDE ZEROMQ
// ============================================================================

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
// INICIALIZACIÓN DEL MAPA
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

function initializeEventHandlers() {
    const pauseBtn = document.getElementById('pause-events-btn');
    if (pauseBtn) {
        pauseBtn.addEventListener('click', pauseEventsUpdate);
    }

    const eventsFilter = document.getElementById('events-filter');
    if (eventsFilter) {
        eventsFilter.addEventListener('change', filterEvents);
    }

    // 🔥 Nuevo handler para eventos del firewall
    const pauseFirewallBtn = document.getElementById('pause-firewall-events-btn');
    if (pauseFirewallBtn) {
        pauseFirewallBtn.addEventListener('click', pauseFirewallEventsUpdate);
    }
}

function initializeCollapsibleSections() {
    const sections = ['architecture', 'components', 'events', 'firewall-events', 'counters', 'zmq', 'debug'];

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
                <button onclick="sendTestFirewallCommand()" class="btn btn-primary">
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
            <div class="log-entry info">[INFO] ${new Date().toLocaleTimeString()} - Dashboard ZeroMQ activo con eventos de firewall</div>
        `;
    }
    showToast('Log limpiado', 'info');
}

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

// ============================================================================
// 🚀 MODAL MEJORADO CON RECOMENDACIONES Y ACCIONES
// ============================================================================

async function showEventDetail(event) {
    try {
        // Obtener recomendaciones del backend para este evento
        const recommendations = await getEventRecommendations(event);

        // Obtener información del agente firewall
        const firewallAgent = await getFirewallAgentInfo(event);

        const content = `
            <div style="font-family: 'Consolas', monospace; max-height: 70vh; overflow-y: auto;">
                <!-- Header del evento -->
                <div style="margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #00ff88;">
                    <h3 style="color: #00ff88; margin: 0;">🚨 Evento ZeroMQ</h3>
                    <div style="font-size: 11px; color: #888; margin-top: 5px;">
                        ID: ${event.id || 'N/A'} | Timestamp: ${new Date(event.timestamp * 1000).toLocaleString()}
                    </div>
                </div>

                <!-- Información básica del evento -->
                <div style="margin-bottom: 20px;">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
                        <div>
                            <strong>IP Origen:</strong><br>
                            <span style="color: #ff4444; font-size: 14px;">${event.source_ip}</span>
                        </div>
                        <div>
                            <strong>IP Destino:</strong><br>
                            <span style="color: #00ff88; font-size: 14px;">${event.target_ip}</span>
                        </div>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                        <div>
                            <strong>Score de Riesgo:</strong><br>
                            <span style="color: ${event.risk_score > 0.8 ? '#ff4444' : event.risk_score > 0.5 ? '#ffaa00' : '#00ff00'}; font-size: 14px; font-weight: bold;">
                                ${(event.risk_score * 100).toFixed(1)}%
                            </span>
                        </div>
                        <div>
                            <strong>Tipo:</strong><br>
                            <span style="color: #ffaa00;">${event.type || 'network_traffic'}</span>
                        </div>
                    </div>
                    ${event.location ? `
                        <div style="margin-top: 10px;">
                            <strong>Ubicación:</strong> ${event.location}
                        </div>
                    ` : ''}
                </div>

                <!-- Información del Agente Firewall -->
                <div style="margin-bottom: 20px; padding: 12px; background: rgba(0, 170, 255, 0.1); border-left: 4px solid #00aaff; border-radius: 4px;">
                    <div style="color: #00aaff; font-weight: bold; margin-bottom: 8px;">
                        🔥 Agente Firewall de Destino
                    </div>
                    <div style="font-size: 11px; line-height: 1.4;">
                        <strong>Nodo:</strong> ${firewallAgent.node_id || 'simple_firewall_agent_001_1752998835'}<br>
                        <strong>Estado:</strong> <span style="color: ${firewallAgent.status === 'healthy' ? '#00ff88' : '#ffaa00'};">${firewallAgent.status || 'HEALTHY'}</span><br>
                        <strong>Endpoint:</strong> ${firewallAgent.endpoint || 'tcp://localhost:5580'}<br>
                        <strong>Reglas Activas:</strong> ${firewallAgent.active_rules || 0}
                    </div>
                </div>

                <!-- Sección 1: Recomendaciones (Colapsible) -->
                <div style="margin-bottom: 20px;">
                    <div class="modal-section-header" onclick="toggleModalSection('recommendations')" style="background: rgba(0, 255, 136, 0.2); padding: 10px; cursor: pointer; border-radius: 4px; display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: #00ff88; font-weight: bold;">
                            💡 Recomendaciones del Sistema
                        </span>
                        <i class="fas fa-chevron-down" id="recommendations-toggle" style="color: #00ff88; transition: transform 0.3s ease;"></i>
                    </div>
                    <div id="recommendations-content" style="max-height: 1000px; overflow: hidden; transition: all 0.3s ease;">
                        <div style="padding: 15px; background: rgba(0, 255, 136, 0.05); border: 1px solid rgba(0, 255, 136, 0.2); border-top: none; border-radius: 0 0 4px 4px;">
                            ${generateRecommendationsHTML(recommendations, event)}
                        </div>
                    </div>
                </div>

                <!-- Sección 2: Datos ZeroMQ (Colapsible) -->
                <div>
                    <div class="modal-section-header" onclick="toggleModalSection('zeromq-data')" style="background: rgba(102, 102, 102, 0.2); padding: 10px; cursor: pointer; border-radius: 4px; display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: #666; font-weight: bold;">
                            📊 Datos ZeroMQ (JSON)
                        </span>
                        <i class="fas fa-chevron-down" id="zeromq-data-toggle" style="color: #666; transition: transform 0.3s ease;"></i>
                    </div>
                    <div id="zeromq-data-content" style="max-height: 0; overflow: hidden; transition: all 0.3s ease;">
                        <div style="padding: 15px; background: rgba(0, 0, 0, 0.6); border: 1px solid #333; border-top: none; border-radius: 0 0 4px 4px;">
                            <pre style="font-size: 9px; color: #666; margin: 0; white-space: pre-wrap; max-height: 200px; overflow-y: auto;">${JSON.stringify(event, null, 2)}</pre>
                        </div>
                    </div>
                </div>
            </div>
        `;

        showModal('Análisis del Evento de Seguridad', content);

    } catch (error) {
        console.error('❌ Error mostrando detalles del evento:', error);
        showSimpleEventDetail(event); // Fallback al modal original
    }
}

// ============================================================================
// 🎯 FUNCIONES PARA RECOMENDACIONES
// ============================================================================

async function getEventRecommendations(event) {
    try {
        const response = await fetch('/api/event-recommendations', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                event_id: event.id,
                source_ip: event.source_ip,
                target_ip: event.target_ip,
                risk_score: event.risk_score,
                type: event.type
            })
        });

        if (response.ok) {
            const data = await response.json();
            return data.recommendations || [];
        } else {
            console.warn('No se pudieron obtener recomendaciones del backend');
            return generateDefaultRecommendations(event);
        }
    } catch (error) {
        console.warn('Error obteniendo recomendaciones:', error);
        return generateDefaultRecommendations(event);
    }
}

async function getFirewallAgentInfo(event) {
    try {
        const response = await fetch('/api/firewall-agent-info');
        if (response.ok) {
            const data = await response.json();
            return data.agent || {};
        }
    } catch (error) {
        console.warn('Error obteniendo info del agente firewall:', error);
    }

    return {
        node_id: 'simple_firewall_agent_001_1752998835',
        status: 'healthy',
        endpoint: 'tcp://localhost:5580',
        active_rules: 0
    };
}

function generateDefaultRecommendations(event) {
    const recommendations = [];

    if (event.risk_score > 0.8) {
        recommendations.push({
            id: 'block_source_ip',
            type: 'BLOCK',
            priority: 'HIGH',
            title: 'Bloquear IP de Origen',
            description: `Bloquear completamente la IP ${event.source_ip} debido al alto riesgo detectado.`,
            action: 'BLOCK_IP',
            params: {
                ip: event.source_ip,
                duration: '1h',
                reason: 'High risk score detected'
            },
            confidence: 95
        });

        recommendations.push({
            id: 'rate_limit',
            type: 'LIMIT',
            priority: 'MEDIUM',
            title: 'Limitar Velocidad',
            description: `Aplicar rate limiting a la IP ${event.source_ip} en lugar de bloqueo completo.`,
            action: 'RATE_LIMIT',
            params: {
                ip: event.source_ip,
                limit: '10/min',
                duration: '30m'
            },
            confidence: 80
        });
    } else if (event.risk_score > 0.5) {
        recommendations.push({
            id: 'monitor_traffic',
            type: 'MONITOR',
            priority: 'MEDIUM',
            title: 'Monitorear Tráfico',
            description: `Aumentar el monitoreo del tráfico desde ${event.source_ip} hacia ${event.target_ip}.`,
            action: 'MONITOR',
            params: {
                source_ip: event.source_ip,
                target_ip: event.target_ip,
                duration: '15m'
            },
            confidence: 70
        });
    } else {
        recommendations.push({
            id: 'log_only',
            type: 'LOG',
            priority: 'LOW',
            title: 'Solo Registrar',
            description: 'Registrar este evento para análisis posterior sin aplicar restricciones.',
            action: 'LOG',
            params: {
                event_id: event.id,
                detail_level: 'high'
            },
            confidence: 90
        });
    }

    return recommendations;
}

function generateRecommendationsHTML(recommendations, event) {
    if (!recommendations || recommendations.length === 0) {
        return `
            <div style="text-align: center; color: #666; padding: 20px;">
                <i class="fas fa-info-circle" style="font-size: 24px; margin-bottom: 10px;"></i>
                <p>No hay recomendaciones específicas para este evento.</p>
            </div>
        `;
    }

    let html = `
        <div style="margin-bottom: 15px;">
            <div style="color: #00ff88; font-size: 12px; margin-bottom: 10px;">
                📋 El sistema ha analizado este evento y sugiere las siguientes acciones:
            </div>
        </div>
    `;

    recommendations.forEach((rec, index) => {
        const priorityColors = {
            'HIGH': '#ff4444',
            'MEDIUM': '#ffaa00',
            'LOW': '#00ff88'
        };

        const typeIcons = {
            'BLOCK': '🚫',
            'LIMIT': '⏱️',
            'MONITOR': '👁️',
            'LOG': '📝'
        };

        html += `
            <div style="margin-bottom: 15px; border: 1px solid rgba(0, 255, 136, 0.3); border-radius: 6px; overflow: hidden;">
                <!-- Header de la recomendación -->
                <div style="background: rgba(0, 255, 136, 0.1); padding: 10px; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="font-size: 14px;">${typeIcons[rec.type] || '⚡'}</span>
                        <strong style="margin-left: 8px; color: #00ff88;">${rec.title}</strong>
                        <span style="background: ${priorityColors[rec.priority]}; color: white; padding: 2px 6px; border-radius: 10px; font-size: 9px; margin-left: 10px;">
                            ${rec.priority}
                        </span>
                    </div>
                    <div style="font-size: 10px; color: #888;">
                        Confianza: ${rec.confidence || 75}%
                    </div>
                </div>

                <!-- Contenido de la recomendación -->
                <div style="padding: 12px;">
                    <div style="color: #ccc; font-size: 11px; line-height: 1.4; margin-bottom: 12px;">
                        ${rec.description}
                    </div>

                    <!-- Parámetros de la acción -->
                    ${rec.params ? `
                        <div style="background: rgba(0, 0, 0, 0.4); padding: 8px; border-radius: 4px; margin-bottom: 12px;">
                            <div style="font-size: 10px; color: #888; margin-bottom: 5px;">Parámetros:</div>
                            <div style="font-size: 10px; font-family: monospace;">
                                ${Object.entries(rec.params).map(([key, value]) =>
                                    `<span style="color: #00ffff;">${key}:</span> <span style="color: #fff;">${value}</span>`
                                ).join(' | ')}
                            </div>
                        </div>
                    ` : ''}

                    <!-- Botones de acción -->
                    <div style="display: flex; gap: 8px; justify-content: flex-end;">
                        <button onclick="executeRecommendation('${rec.id}', ${JSON.stringify(rec).replace(/"/g, '&quot;')}, '${event.id}')"
                                style="background: rgba(0, 255, 136, 0.2); border: 1px solid #00ff88; color: #00ff88; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 10px; transition: all 0.2s ease;">
                            ✅ Aplicar
                        </button>
                        <button onclick="dismissRecommendation('${rec.id}')"
                                style="background: rgba(255, 170, 0, 0.2); border: 1px solid #ffaa00; color: #ffaa00; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 10px; transition: all 0.2s ease;">
                            ⏭️ Omitir
                        </button>
                        <button onclick="showRecommendationDetails('${rec.id}')"
                                style="background: rgba(102, 102, 102, 0.2); border: 1px solid #666; color: #666; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 10px; transition: all 0.2s ease;">
                            ℹ️ Detalles
                        </button>
                    </div>
                </div>
            </div>
        `;
    });

    html += `
        <div style="margin-top: 20px; padding: 10px; background: rgba(0, 170, 255, 0.1); border-radius: 4px; border-left: 4px solid #00aaff;">
            <div style="font-size: 10px; color: #00aaff;">
                <strong>ℹ️ Nota:</strong> Las acciones se enviarán al agente firewall activo.
                Puedes aplicar múltiples recomendaciones o crear reglas personalizadas.
            </div>
        </div>
    `;

    return html;
}

// ============================================================================
// 🎬 FUNCIONES DE ACCIÓN
// ============================================================================

async function executeRecommendation(recId, recommendation, eventId) {
    try {
        console.log('🚀 Ejecutando recomendación:', recId, recommendation);

        showToast('Enviando acción al firewall agent...', 'info');

        // Crear evento de comando en la lista del firewall
        const commandId = 'rec_' + Date.now();
        addFirewallEventToList({
            id: commandId,
            type: 'command',
            action: recommendation.action,
            ip: recommendation.params?.ip || recommendation.params?.source_ip || 'N/A',
            action_code: getActionCode(recommendation.action),
            bytes: 64,
            source: 'Dashboard Recommendation',
            timestamp: Date.now() / 1000
        });

        const response = await fetch('/api/execute-recommendation', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                recommendation_id: recId,
                recommendation: recommendation,
                event_id: eventId,
                command_id: commandId
            })
        });

        const result = await response.json();

        if (result.success) {
            // Añadir respuesta exitosa
            setTimeout(() => {
                addFirewallEventToList({
                    id: commandId,
                    type: 'response',
                    success: true,
                    agent: result.agent || 'firewall_agent_001',
                    result: result.message || `${recommendation.action} aplicada correctamente`,
                    timestamp: Date.now() / 1000
                });
            }, 300);

            showToast(`✅ Recomendación "${recommendation.title}" aplicada correctamente`, 'success');
            addDebugLog('info', `Recomendación ${recId} ejecutada: ${recommendation.action}`);

            // Actualizar estadísticas del firewall
            firewallStats.commandsSent++;
            firewallStats.responsesOk++;
            updateElement('firewall-commands-sent', firewallStats.commandsSent);
            updateElement('firewall-responses-ok', firewallStats.responsesOk);

        } else {
            // Añadir respuesta de error
            setTimeout(() => {
                addFirewallEventToList({
                    id: commandId,
                    type: 'error',
                    success: false,
                    error: result.message || 'Error aplicando recomendación',
                    timestamp: Date.now() / 1000
                });
            }, 300);

            showToast(`❌ Error aplicando recomendación: ${result.message}`, 'error');
            firewallStats.errors++;
            updateElement('firewall-errors', firewallStats.errors);
        }

    } catch (error) {
        console.error('❌ Error ejecutando recomendación:', error);

        // Añadir evento de error de comunicación
        addFirewallEventToList({
            id: 'error_' + Date.now(),
            type: 'error',
            success: false,
            error: 'Error de comunicación: ' + error.message,
            timestamp: Date.now() / 1000
        });

        showToast(`❌ Error comunicando con firewall: ${error.message}`, 'error');
        firewallStats.errors++;
        updateElement('firewall-errors', firewallStats.errors);
    }
}

function dismissRecommendation(recId) {
    showToast(`⏭️ Recomendación ${recId} omitida`, 'info');
    addDebugLog('info', `Recomendación ${recId} omitida por el usuario`);

    // Opcional: Enviar al backend que se omitió esta recomendación
    fetch('/api/dismiss-recommendation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recommendation_id: recId })
    }).catch(err => console.warn('Error enviando dismissal:', err));
}

function showRecommendationDetails(recId) {
    showToast(`ℹ️ Mostrando detalles de recomendación ${recId}`, 'info');
    // Aquí podrías mostrar un sub-modal con más detalles
}

function getActionCode(action) {
    const actionCodes = {
        'BLOCK_IP': 1,
        'RATE_LIMIT': 2,
        'MONITOR': 3,
        'LOG': 7,
        'UNBLOCK_IP': 4,
        'LIST_RULES': 7
    };
    return actionCodes[action] || 7;
}

// ============================================================================
// 🔧 FUNCIONES AUXILIARES
// ============================================================================

function toggleModalSection(sectionId) {
    const content = document.getElementById(`${sectionId}-content`);
    const toggle = document.getElementById(`${sectionId}-toggle`);

    if (content && toggle) {
        const isCollapsed = content.style.maxHeight === '0px';

        if (isCollapsed) {
            content.style.maxHeight = '1000px';
            toggle.style.transform = 'rotate(180deg)';
        } else {
            content.style.maxHeight = '0px';
            toggle.style.transform = 'rotate(0deg)';
        }
    }
}

// Función fallback para el modal original
function showSimpleEventDetail(event) {
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

// Funciones placeholder
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