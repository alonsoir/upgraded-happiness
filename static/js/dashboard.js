/*
dashboard.js - VERSIÓN CON MODALES FUNCIONALES Y REGLAS JSON
+ BOTONES DE ACCIÓN FIREWALL OPERATIVOS
+ INFORMACIÓN DEL FIREWALL RESPONSABLE
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

// 🔥 Variables para eventos del firewall
let currentFirewallEvents = [];
let firewallEventsPaused = false;
let firewallStats = {
    commandsSent: 0,
    responsesOk: 0,
    errors: 0,
    lastAgent: 'N/A'
};

// 🔥 Variables para reglas de firewall
let firewallRulesInfo = {
    rules_count: 0,
    agents_count: 0,
    available_actions: []
};

// 🔥 Estados de componentes para indicadores
let componentStates = {
    promiscuous_agent: false,
    geoip_enricher: false,
    ml_detector: false,
    firewall_agent: false
};

// ============================================================================
// INICIALIZACIÓN PRINCIPAL
// ============================================================================

function initializeDashboard() {
    console.log('🚀 Inicializando Dashboard SCADA con Reglas JSON...');

    try {
        initializeMap();
        initializeEventHandlers();
        initializeCollapsibleSections();

        // HTTP Polling para conectar con backend
        startSimplePolling();

        updateCurrentTime();
        setInterval(updateCurrentTime, 1000);

        console.log('✅ Dashboard inicializado correctamente');
        addDebugLog('info', 'Dashboard inicializado - comunicación con backend ZeroMQ + Reglas JSON');

    } catch (error) {
        console.error('❌ Error inicializando dashboard:', error);
        addDebugLog('error', `Error inicialización: ${error.message}`);
    }
}

// ============================================================================
// HTTP POLLING PARA BACKEND
// ============================================================================

function startSimplePolling() {
    console.log('📡 Iniciando polling HTTP al backend...');

    // Llamada inicial
    fetchDataFromZeroMQ();

    // Polling cada 2 segundos
    pollingInterval = setInterval(fetchDataFromZeroMQ, 2000);

    addDebugLog('info', 'HTTP polling iniciado - conectando con backend ZeroMQ');
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
            // Procesar datos del backend
            updateDashboardFromZeroMQ(data);
            updateConnectionStatus('api', 'connected');

            console.log('📊 Datos backend recibidos:', data.basic_stats);

        } else {
            throw new Error(data.error || 'Error en respuesta API');
        }

    } catch (error) {
        console.error('❌ Error conectando con backend:', error);
        updateConnectionStatus('api', 'error');
        addDebugLog('error', `Error backend: ${error.message}`);
    }
}

function updateDashboardFromZeroMQ(data) {
    try {
        // Actualizar métricas básicas
        if (data.basic_stats) {
            updateElement('events-per-min', data.basic_stats.events_per_minute || 0);
            updateElement('high-risk-count', data.basic_stats.high_risk_events || 0);
            updateElement('success-rate', data.basic_stats.success_rate || 0);
            updateElement('failure-count', data.basic_stats.failures || 0);

            updateElement('events-count', data.basic_stats.total_events || 0);
            updateElement('commands-count', data.basic_stats.commands_sent || 0);
            updateElement('confirmations-count', data.basic_stats.confirmations || 0);

            updateElement('events-counter', data.basic_stats.total_events || 0);
            updateElement('confirmations-counter', data.basic_stats.confirmations || 0);

            eventCount = data.basic_stats.total_events || 0;
            highRiskCount = data.basic_stats.high_risk_events || 0;
        }

        // 🔥 NUEVO: Actualizar información de reglas de firewall
        if (data.firewall_rules_info) {
            firewallRulesInfo = data.firewall_rules_info;
            addDebugLog('info', `Reglas Firewall: ${firewallRulesInfo.rules_count} reglas, ${firewallRulesInfo.agents_count} agentes`);
        }

        // 🔥 Actualizar estadísticas del firewall
        if (data.firewall_stats) {
            updateFirewallStats(data.firewall_stats);
        }

        // 🔥 Actualizar estados de componentes
        updateComponentIndicators(data);

        // Actualizar estado de componentes ZeroMQ
        if (data.component_status) {
            updateComponentStatus(data.component_status);
        }

        // Actualizar conexiones ZeroMQ
        if (data.zmq_connections) {
            updateZMQStatus(data.zmq_connections);
        }

        // Procesar eventos recientes
        if (data.recent_events && data.recent_events.length > 0) {
            processEventsFromZeroMQ(data.recent_events);
        }

        // 🔥 Procesar eventos del firewall
        if (data.firewall_events && data.firewall_events.length > 0) {
            processFirewallEventsFromZeroMQ(data.firewall_events);
        }

        addDebugLog('info', `Backend: ${data.basic_stats?.total_events || 0} eventos, ${data.basic_stats?.high_risk_events || 0} alto riesgo`);

    } catch (error) {
        console.error('❌ Error procesando datos backend:', error);
        addDebugLog('error', `Error procesando backend: ${error.message}`);
    }
}

// ============================================================================
// 🔥 LÓGICA DE INDICADORES DE COMPONENTES
// ============================================================================

function updateComponentIndicators(data) {
    try {
        // 🔥 PROMISCUOUS AGENT: Verde si hay flujo de eventos
        const hasEventFlow = data.recent_events && data.recent_events.length > 0;
        componentStates.promiscuous_agent = hasEventFlow;
        updateStatusIndicator('promiscuous-agent-status', hasEventFlow);

        // 🔥 GEOIP ENRICHER: Verde si eventos tienen lat/lon
        let hasGeoData = false;
        if (data.recent_events && data.recent_events.length > 0) {
            hasGeoData = data.recent_events.some(event =>
                event.latitude && event.longitude &&
                event.latitude !== 0 && event.longitude !== 0
            );
        }
        componentStates.geoip_enricher = hasGeoData;
        updateStatusIndicator('geoip-enricher-status', hasGeoData);

        // 🔥 ML DETECTOR: Verde si hay comunicación ZeroMQ activa
        const mlConnected = data.zmq_connections &&
                           data.zmq_connections.ml_events &&
                           data.zmq_connections.ml_events.status === 'active';
        componentStates.ml_detector = mlConnected;
        updateStatusIndicator('ml-detector-status', mlConnected);

        // 🔥 FIREWALL AGENT: Verde si hay comunicación de comandos/respuestas
        const fwConnected = data.zmq_connections &&
                           data.zmq_connections.firewall_commands &&
                           data.zmq_connections.firewall_commands.status === 'active';
        componentStates.firewall_agent = fwConnected;
        updateStatusIndicator('firewall-agent-status', fwConnected);

        // 🔥 ESTADO GENERAL: Connected si todos están verdes
        updateOverallConnectionStatus();

        console.log('🔄 Estados componentes:', componentStates);

    } catch (error) {
        console.error('❌ Error actualizando indicadores componentes:', error);
    }
}

function updateOverallConnectionStatus() {
    const allConnected = Object.values(componentStates).every(state => state === true);
    const someConnected = Object.values(componentStates).some(state => state === true);

    const overallStatus = document.getElementById('overall-status');
    const overallText = document.getElementById('overall-status-text');

    if (overallStatus && overallText) {
        if (allConnected) {
            overallStatus.className = 'status-dot connected';
            overallText.textContent = 'Connected';
        } else if (someConnected) {
            overallStatus.className = 'status-dot warning';
            overallText.textContent = 'Parcial';
        } else {
            overallStatus.className = 'status-dot disconnected';
            overallText.textContent = 'Desconectado';
        }
    }
}

function updateStatusIndicator(elementId, connected) {
    const element = document.getElementById(elementId);
    if (element) {
        element.className = `status-dot ${connected ? 'connected' : 'disconnected'}`;
    }
}

// ============================================================================
// EVENTOS DEL FIREWALL (SIN CAMBIOS)
// ============================================================================

function updateFirewallStats(stats) {
    try {
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
        const newEvents = events.filter(event => {
            return !currentFirewallEvents.some(existing =>
                existing.id === event.id ||
                (existing.timestamp === event.timestamp && existing.type === event.type)
            );
        });

        newEvents.forEach(event => {
            addFirewallEventToList(event);
        });

        if (newEvents.length > 0) {
            console.log(`🔥 ${newEvents.length} eventos nuevos del firewall desde backend`);
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
        const placeholder = firewallEventsList.querySelector('.no-firewall-events');
        if (placeholder) {
            placeholder.remove();
        }

        const eventElement = document.createElement('div');
        const eventTime = new Date(event.timestamp * 1000 || Date.now());

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
                    Action: ${event.action_code || 7} | IP: ${event.ip || '127.0.0.1'} | Bytes: ${event.bytes || 61} | ${event.source || 'Backend'}
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

        firewallEventsList.insertBefore(eventElement, firewallEventsList.firstChild);

        const events = firewallEventsList.querySelectorAll('.firewall-event');
        if (events.length > 20) {
            events[events.length - 1].remove();
        }

        updateElement('firewall-events-count', events.length);

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
// TEST FIREWALL (SIN CAMBIOS)
// ============================================================================

async function sendTestFirewallCommand() {
    try {
        console.log('🧪 Enviando comando de test al firewall via backend...');

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

            showToast('✅ Test enviado correctamente al firewall', 'success');
            console.log('✅ Test firewall exitoso:', result);
            addDebugLog('info', 'Test firewall enviado correctamente via backend');

            firewallStats.commandsSent++;
            firewallStats.responsesOk++;
            updateElement('firewall-commands-sent', firewallStats.commandsSent);
            updateElement('firewall-responses-ok', firewallStats.responsesOk);

            setTimeout(fetchDataFromZeroMQ, 500);

        } else {
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

// Alias para compatibilidad
async function sendTestFirewallEvent() {
    return await sendTestFirewallCommand();
}

// ============================================================================
// MANEJO DE EVENTOS DESDE BACKEND
// ============================================================================

function processEventsFromZeroMQ(events) {
    if (eventsPaused) return;

    try {
        const newEvents = events.filter(event => {
            return !currentEvents.some(existing =>
                existing.id === event.id ||
                (existing.timestamp === event.timestamp &&
                 existing.source_ip === event.source_ip)
            );
        });

        newEvents.forEach(event => {
            addEventFromZeroMQ(event);
        });

        if (newEvents.length > 0) {
            console.log(`📨 ${newEvents.length} eventos nuevos desde backend`);
        }

    } catch (error) {
        console.error('❌ Error procesando eventos backend:', error);
        addDebugLog('error', `Error eventos backend: ${error.message}`);
    }
}

function addEventFromZeroMQ(event) {
    try {
        if (!event.source_ip || !event.target_ip) {
            console.warn('⚠️ Evento backend incompleto:', event);
            return;
        }

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

        addEventToEventsList(event);

        if (event.risk_score > 0.8) {
            showThreatIndicator(event);
        }

        console.log('🚨 Evento backend procesado:', event.source_ip, '→', event.target_ip);

    } catch (error) {
        console.error('❌ Error añadiendo evento backend:', error);
        addDebugLog('error', `Error evento: ${error.message}`);
    }
}

function addEventToEventsList(event) {
    const eventsList = document.getElementById('events-list');
    if (!eventsList) return;

    try {
        const placeholder = eventsList.querySelector('.no-events-placeholder');
        if (placeholder) {
            placeholder.remove();
        }

        const riskLevel = event.risk_score > 0.8 ? 'high' :
                         event.risk_score > 0.5 ? 'medium' : 'low';

        const eventElement = document.createElement('div');
        eventElement.className = `event-item risk-${riskLevel} new-event`;
        eventElement.onclick = () => showEventDetail(event);

        const eventTime = new Date(event.timestamp * 1000);

        eventElement.innerHTML = `
            <div class="event-header">
                <span class="event-time">${eventTime.toLocaleTimeString()}</span>
                <span class="event-risk ${riskLevel}">${(event.risk_score * 100).toFixed(0)}%</span>
            </div>
            <div class="event-details">
                <div><span class="event-source">${event.source_ip}</span> → <span class="event-target">${event.target_ip}</span></div>
                <div class="event-type">${event.type || 'Backend Event'}</div>
            </div>
        `;

        eventsList.insertBefore(eventElement, eventsList.firstChild);

        const events = eventsList.querySelectorAll('.event-item');
        if (events.length > 50) {
            events[events.length - 1].remove();
        }

        updateElement('live-events-count', events.length);

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
                <b>🚨 Evento Backend</b><br>
                <strong>Origen:</strong> ${event.source_ip}<br>
                <strong>Destino:</strong> ${event.target_ip}<br>
                <strong>Riesgo:</strong> <span style="color: ${colors[riskLevel]};">${(event.risk_score * 100).toFixed(0)}%</span><br>
                <strong>Tipo:</strong> ${event.type || 'Backend'}<br>
                <strong>Ubicación:</strong> ${event.location || 'No disponible'}<br>
                <strong>Timestamp:</strong> ${new Date(event.timestamp * 1000).toLocaleString()}
            </div>
        `).addTo(map);

        marker._isEventMarker = true;
        markers.push(marker);

        setTimeout(() => {
            if (map.hasLayer(marker)) {
                map.removeLayer(marker);
                markers = markers.filter(m => m !== marker);
            }
        }, 5 * 60 * 1000);

        console.log('📍 Marcador backend añadido:', event.source_ip);

    } catch (error) {
        console.error('❌ Error añadiendo marcador:', error);
    }
}

// ============================================================================
// 🚨 MODAL DE EVENTOS - CON INFORMACIÓN DE FIREWALL Y ACCIONES OPERATIVAS
// ============================================================================

async function showEventDetail(event) {
    try {
        // 🔥 OBTENER INFORMACIÓN DEL FIREWALL RESPONSABLE DESDE BACKEND
        const firewallInfo = await getResponsibleFirewallInfo(event);

        // 🔥 OBTENER RECOMENDACIÓN BASADA EN RISK_SCORE
        const recommendedAction = getRecommendedActionForRisk(event.risk_score);

        const content = `
            <div style="font-family: 'Consolas', monospace; max-height: 70vh; overflow-y: auto;">
                <!-- Header del evento -->
                <div style="margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #00ff88;">
                    <h3 style="color: #00ff88; margin: 0;">🚨 Evento de Seguridad</h3>
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

                <!-- 🔥 RECOMENDACIÓN DEL SISTEMA -->
                <div style="margin-bottom: 20px; padding: 15px; background: rgba(255, 170, 0, 0.1); border-left: 4px solid #ffaa00; border-radius: 4px;">
                    <div style="color: #ffaa00; font-weight: bold; margin-bottom: 8px;">
                        🎯 Recomendación del Sistema
                    </div>
                    <div style="font-size: 11px; line-height: 1.4;">
                        <strong>Acción Sugerida:</strong> <span style="color: #00ff88;">${recommendedAction.action}</span><br>
                        <strong>Razón:</strong> ${recommendedAction.description}<br>
                        <strong>Parámetros:</strong> ${JSON.stringify(recommendedAction.params)}<br>
                        <strong>Prioridad:</strong> <span style="color: ${recommendedAction.priority === 'HIGH' ? '#ff4444' : recommendedAction.priority === 'MEDIUM' ? '#ffaa00' : '#00ff88'};">${recommendedAction.priority}</span>
                    </div>
                </div>

                <!-- 🔥 INFORMACIÓN DEL FIREWALL RESPONSABLE -->
                <div style="margin-bottom: 20px; padding: 15px; background: rgba(0, 255, 136, 0.1); border-left: 4px solid #00ff88; border-radius: 4px;">
                    <div style="color: #00ff88; font-weight: bold; margin-bottom: 8px;">
                        🔥 Firewall Agent Responsable
                    </div>
                    <div style="font-size: 11px; line-height: 1.4;">
                        <strong>Node ID:</strong> ${firewallInfo.node_id}<br>
                        <strong>IP del Agente:</strong> ${firewallInfo.agent_ip}<br>
                        <strong>Estado:</strong> <span style="color: ${firewallInfo.status === 'active' ? '#00ff88' : '#ffaa00'};">${firewallInfo.status.toUpperCase()}</span><br>
                        <strong>Reglas Activas:</strong> ${firewallInfo.active_rules}<br>
                        <strong>Endpoint:</strong> ${firewallInfo.endpoint}<br>
                        <strong>Capacidades:</strong> ${firewallInfo.capabilities ? firewallInfo.capabilities.join(', ') : 'N/A'}
                    </div>
                </div>

                <!-- 🔥 ACCIONES DISPONIBLES DINÁMICAS -->
                <div style="margin-bottom: 20px; padding: 15px; background: rgba(255, 170, 0, 0.1); border-left: 4px solid #ffaa00; border-radius: 4px;">
                    <div style="color: #ffaa00; font-weight: bold; margin-bottom: 12px;">
                        ⚡ Acciones Disponibles
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                        ${generateFirewallActionButtonsFromRules(event, firewallInfo)}
                    </div>
                    <div style="margin-top: 12px; font-size: 10px; color: #888; font-style: italic;">
                        💡 Las acciones se enviarán al firewall agent: <strong style="color: #00ff88;">${firewallInfo.node_id}</strong>
                    </div>
                </div>

                <!-- Datos del evento (JSON) -->
                <div>
                    <div style="background: rgba(102, 102, 102, 0.2); padding: 10px; cursor: pointer; border-radius: 4px; margin-bottom: 10px;" onclick="toggleEventData()">
                        <span style="color: #666; font-weight: bold;">
                            📊 Datos del Evento (JSON)
                        </span>
                        <i class="fas fa-chevron-down" id="event-data-toggle" style="color: #666; float: right; transition: transform 0.3s ease;"></i>
                    </div>
                    <div id="event-data-content" style="max-height: 0; overflow: hidden; transition: all 0.3s ease;">
                        <div style="padding: 15px; background: rgba(0, 0, 0, 0.6); border: 1px solid #333; border-radius: 4px;">
                            <pre style="font-size: 9px; color: #666; margin: 0; white-space: pre-wrap; max-height: 200px; overflow-y: auto;">${JSON.stringify(event, null, 2)}</pre>
                        </div>
                    </div>
                </div>
            </div>
        `;

        showModal('Análisis del Evento de Seguridad', content);

    } catch (error) {
        console.error('❌ Error mostrando detalles del evento:', error);
        showSimpleEventDetail(event);
    }
}

// ============================================================================
// 🔥 FUNCIONES PARA FIREWALL RESPONSABLE Y ACCIONES OPERATIVAS
// ============================================================================

async function getResponsibleFirewallInfo(event) {
    try {
        // 🔥 OBTENER INFORMACIÓN REAL DEL BACKEND
        const response = await fetch('/api/firewall-agent-info', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                event_id: event.id,
                source_ip: event.source_ip,
                target_ip: event.target_ip,
                node_id: event.node_id
            })
        });

        if (response.ok) {
            const data = await response.json();
            if (data.success && data.firewall_info) {
                return data.firewall_info;
            }
        }

        // Fallback
        return {
            node_id: 'simple_firewall_agent_001',
            agent_ip: event.source_ip || '127.0.0.1',
            status: 'active',
            active_rules: 0,
            endpoint: 'tcp://localhost:5580',
            capabilities: ['BLOCK_IP', 'RATE_LIMIT', 'MONITOR', 'LIST_RULES']
        };

    } catch (error) {
        console.error('Error obteniendo información del firewall:', error);
        return {
            node_id: 'unknown_firewall',
            agent_ip: '127.0.0.1',
            status: 'unknown',
            active_rules: 0,
            endpoint: 'tcp://localhost:5580',
            capabilities: []
        };
    }
}

function getRecommendedActionForRisk(riskScore) {
    // 🔥 LÓGICA BASADA EN REGLAS JSON (simulada en frontend)
    const riskPercentage = Math.floor(riskScore * 100);

    if (riskPercentage >= 71) {
        return {
            action: 'BLOCK_IP',
            description: 'Riesgo alto - bloqueo inmediato de IP',
            params: { duration: 3600, permanent: false },
            priority: 'HIGH'
        };
    } else if (riskPercentage >= 31) {
        return {
            action: 'RATE_LIMIT',
            description: 'Riesgo medio - aplicar rate limiting',
            params: { requests_per_minute: 10, duration: 600 },
            priority: 'MEDIUM'
        };
    } else {
        return {
            action: 'MONITOR',
            description: 'Riesgo bajo - solo monitorear',
            params: { duration: 300 },
            priority: 'LOW'
        };
    }
}

function generateFirewallActionButtonsFromRules(event, firewallInfo) {
    const riskScore = event.risk_score || 0;
    const capabilities = firewallInfo.capabilities || [];

    let buttons = '';

    // 🔥 BOTONES DINÁMICOS BASADOS EN REGLAS JSON Y CAPACIDADES
    if (firewallRulesInfo.available_actions) {
        firewallRulesInfo.available_actions.forEach(action => {
            // Verificar si el firewall soporta esta acción
            if (capabilities.includes(action)) {
                buttons += generateActionButton(action, event, firewallInfo, riskScore);
            }
        });
    } else {
        // Fallback: botones básicos
        if (riskScore > 0.7 && capabilities.includes('BLOCK_IP')) {
            buttons += generateActionButton('BLOCK_IP', event, firewallInfo, riskScore);
        }
        if (riskScore > 0.4 && capabilities.includes('RATE_LIMIT')) {
            buttons += generateActionButton('RATE_LIMIT', event, firewallInfo, riskScore);
        }
        if (capabilities.includes('MONITOR')) {
            buttons += generateActionButton('MONITOR', event, firewallInfo, riskScore);
        }
        if (capabilities.includes('LIST_RULES')) {
            buttons += generateActionButton('LIST_RULES', event, firewallInfo, riskScore);
        }
    }

    return buttons || '<div style="color: #666; text-align: center;">No hay acciones disponibles</div>';
}

function generateActionButton(action, event, firewallInfo, riskScore) {
    const actionConfig = {
        'BLOCK_IP': { color: '#ff4444', icon: '🚫', label: 'Bloquear' },
        'RATE_LIMIT': { color: '#ffaa00', icon: '⏱️', label: 'Limitar' },
        'MONITOR': { color: '#00aaff', icon: '👁️', label: 'Monitorear' },
        'LIST_RULES': { color: '#00ff88', icon: '📋', label: 'Listar Reglas' }
    };

    const config = actionConfig[action] || { color: '#666', icon: '⚙️', label: action };
    const targetIp = action === 'LIST_RULES' ? 'all' : event.source_ip;

    return `
        <button onclick="executeFirewallActionFromRules('${action}', '${targetIp}', '${firewallInfo.node_id}', '${event.id}')"
                style="background: rgba(${hexToRgb(config.color)}, 0.2); border: 1px solid ${config.color}; color: ${config.color}; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-size: 10px; width: 100%; transition: all 0.3s ease;"
                onmouseover="this.style.background='rgba(${hexToRgb(config.color)}, 0.3)'"
                onmouseout="this.style.background='rgba(${hexToRgb(config.color)}, 0.2)'">
            ${config.icon} ${config.label} ${targetIp !== 'all' ? targetIp : ''}
        </button>
    `;
}

function hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ?
        `${parseInt(result[1], 16)}, ${parseInt(result[2], 16)}, ${parseInt(result[3], 16)}` :
        '128, 128, 128';
}

async function executeFirewallActionFromRules(action, targetIp, firewallNodeId, eventId) {
    try {
        console.log(`🔥 Ejecutando acción ${action} en firewall ${firewallNodeId} para IP ${targetIp}`);

        // 🔥 Mostrar feedback inmediato
        showToast(`Enviando ${action} a ${firewallNodeId}...`, 'info');

        // 🔥 Añadir evento a la lista del firewall
        const commandId = `action_${Date.now()}`;
        addFirewallEventToList({
            id: commandId,
            type: 'command',
            action: action,
            ip: targetIp,
            action_code: getFirewallActionCode(action),
            bytes: 64,
            source: 'Dashboard Action (Rules)',
            timestamp: Date.now() / 1000
        });

        // 🔥 ENVIAR ACCIÓN AL BACKEND USANDO NUEVO ENDPOINT
        const response = await fetch('/api/execute-firewall-action', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                action: action,
                target_ip: targetIp,
                firewall_node_id: firewallNodeId,
                event_id: eventId,
                command_id: commandId,
                source: 'dashboard_manual_action_rules'
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const result = await response.json();

        if (result.success) {
            // 🔥 Añadir respuesta exitosa
            setTimeout(() => {
                addFirewallEventToList({
                    id: commandId,
                    type: 'response',
                    success: true,
                    agent: result.agent || firewallNodeId,
                    result: result.message || `${action} ejecutada correctamente`,
                    timestamp: Date.now() / 1000
                });
            }, 300);

            showToast(`✅ ${action} ejecutada en ${firewallNodeId}`, 'success');
            addDebugLog('info', `Acción ${action} ejecutada para IP ${targetIp} en firewall ${firewallNodeId} usando reglas JSON`);

            // Actualizar estadísticas
            firewallStats.commandsSent++;
            firewallStats.responsesOk++;
            updateElement('firewall-commands-sent', firewallStats.commandsSent);
            updateElement('firewall-responses-ok', firewallStats.responsesOk);

            // Cerrar modal después de acción exitosa
            setTimeout(() => {
                closeModal();
            }, 2000);

        } else {
            // 🔥 Añadir respuesta de error
            setTimeout(() => {
                addFirewallEventToList({
                    id: commandId,
                    type: 'error',
                    success: false,
                    error: result.message || 'Error ejecutando acción',
                    timestamp: Date.now() / 1000
                });
            }, 300);

            showToast(`❌ Error en ${action}: ${result.message}`, 'error');
            firewallStats.errors++;
            updateElement('firewall-errors', firewallStats.errors);
        }

    } catch (error) {
        console.error(`❌ Error ejecutando acción ${action}:`, error);

        // 🔥 Añadir evento de error
        addFirewallEventToList({
            id: 'error_' + Date.now(),
            type: 'error',
            success: false,
            error: `Error comunicación: ${error.message}`,
            timestamp: Date.now() / 1000
        });

        showToast(`❌ Error comunicando con firewall: ${error.message}`, 'error');
        firewallStats.errors++;
        updateElement('firewall-errors', firewallStats.errors);
    }
}

function getFirewallActionCode(action) {
    const actionCodes = {
        'BLOCK_IP': 1,
        'RATE_LIMIT': 2,
        'MONITOR': 3,
        'LIST_RULES': 7,
        'UNBLOCK_IP': 4
    };
    return actionCodes[action] || 7;
}

function toggleEventData() {
    const content = document.getElementById('event-data-content');
    const toggle = document.getElementById('event-data-toggle');

    if (content && toggle) {
        const isCollapsed = content.style.maxHeight === '0px' || content.style.maxHeight === '';

        if (isCollapsed) {
            content.style.maxHeight = '300px';
            toggle.style.transform = 'rotate(180deg)';
        } else {
            content.style.maxHeight = '0px';
            toggle.style.transform = 'rotate(0deg)';
        }
    }
}

function showSimpleEventDetail(event) {
    const content = `
        <div style="font-family: 'Consolas', monospace;">
            <h4 style="color: #00ff88; margin-bottom: 15px;">🚨 Evento de Seguridad</h4>

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
                <strong>Datos del Evento:</strong><br>
                <pre style="font-size: 9px; color: #666; margin-top: 5px;">${JSON.stringify(event, null, 2)}</pre>
            </div>
        </div>
    `;

    showModal('Detalle del Evento', content);
}

// ============================================================================
// RESTO DE FUNCIONES (IGUAL QUE ANTES)
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
            .bindPopup('<b>🖥️ Dashboard Principal</b><br>Madrid, España<br>Backend Dashboard')
            .addTo(map);

        const barcelonaMarker = L.marker([41.3851, 2.1734])
            .bindPopup('<b>🔄 Nodo Remoto</b><br>Barcelona, España<br>ML Detector Node')
            .addTo(map);

        const sevillaMarker = L.marker([37.3886, -5.9823])
            .bindPopup('<b>🔥 Firewall Agent</b><br>Sevilla, España<br>Firewall Agent')
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
// RESTO DE FUNCIONES AUXILIARES (IGUAL QUE ANTES)
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
                    🧪 Generar Test Backend
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
    addDebugLog('info', 'Dashboard refrescado - datos backend con reglas JSON');
}

function clearDebugLog() {
    const debugLog = document.getElementById('debug-log');
    if (debugLog) {
        debugLog.innerHTML = `
            <div class="log-entry info">[INFO] ${new Date().toLocaleTimeString()} - Log limpiado</div>
            <div class="log-entry info">[INFO] ${new Date().toLocaleTimeString()} - Dashboard conectado con backend ZeroMQ + Reglas JSON</div>
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
            ⚠️ Amenaza detectada!<br>
            <small>${event.source_ip} → ${event.target_ip}</small>
        `;
        indicator.classList.add('show');

        setTimeout(() => {
            indicator.classList.remove('show');
        }, 5000);
    }
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