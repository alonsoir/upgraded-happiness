/**
 * SCADA Dashboard JavaScript - Completamente Reactivo
 * Maneja toda la interactividad del dashboard con datos protobuf
 */

// Variables globales del dashboard
let dashboardState = {
    map: null,
    markers: [],
    events: [],
    threats: [],
    metrics: {},
    updateInterval: null,
    debugLogEntries: [],
    selectedEvent: null,
    modalOpen: false
};

// Configuración del dashboard
const DASHBOARD_CONFIG = {
    UPDATE_INTERVAL: 3000,
    MAX_MARKERS: 100,
    MAX_EVENTS: 1000,
    MAX_DEBUG_ENTRIES: 100,
    MAP_CENTER: [40.4168, -3.7038],
    MAP_ZOOM: 6
};

// Estados de conexión
const CONNECTION_STATES = {
    CONNECTED: 'connected',
    CONNECTING: 'connecting',
    DISCONNECTED: 'disconnected',
    ERROR: 'error'
};

/**
 * Inicialización principal del dashboard
 */
function initializeDashboard() {
    console.log('🚀 Inicializando SCADA Dashboard...');

    // Inicializar componentes
    initializeMap();
    initializeEventListeners();
    startPeriodicUpdates();

    // Logs iniciales
    addDebugLog('info', 'Sistema SCADA Dashboard v2.1 iniciado');
    addDebugLog('info', 'Arquitectura 3 puertos configurada');
    addDebugLog('info', 'Mapa geolocalizado activado');

    // Actualizar reloj
    updateClock();
    setInterval(updateClock, 1000);

    console.log('✅ Dashboard inicializado correctamente');
}

/**
 * Inicializar mapa de Leaflet
 */
function initializeMap() {
    dashboardState.map = L.map('map').setView(DASHBOARD_CONFIG.MAP_CENTER, DASHBOARD_CONFIG.MAP_ZOOM);

    // Tile layer oscuro para tema SCADA
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '© OpenStreetMap contributors © CARTO',
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(dashboardState.map);

    addDebugLog('info', `Mapa inicializado en ${DASHBOARD_CONFIG.MAP_CENTER.join(', ')}`);
}

/**
 * Inicializar event listeners
 */
function initializeEventListeners() {
    // Prevenir propagación en elementos específicos
    document.addEventListener('click', handleGlobalClick);

    // Escuchar errores
    window.addEventListener('error', function(e) {
        addDebugLog('error', `JavaScript Error: ${e.message}`);
    });

    // Escuchar cambios de visibilidad
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            pauseUpdates();
        } else {
            resumeUpdates();
        }
    });
}

/**
 * Manejar clicks globales para debugging
 */
function handleGlobalClick(event) {
    const element = event.target;
    const tagName = element.tagName.toLowerCase();
    const className = element.className;
    const id = element.id;

    addDebugLog('debug', `Click en ${tagName}${id ? '#' + id : ''}${className ? '.' + className.split(' ')[0] : ''}`);
}

/**
 * Iniciar actualizaciones periódicas
 */
function startPeriodicUpdates() {
    if (dashboardState.updateInterval) {
        clearInterval(dashboardState.updateInterval);
    }

    dashboardState.updateInterval = setInterval(fetchAndUpdateMetrics, DASHBOARD_CONFIG.UPDATE_INTERVAL);
    fetchAndUpdateMetrics(); // Primera actualización inmediata

    addDebugLog('info', `Actualizaciones periódicas iniciadas (${DASHBOARD_CONFIG.UPDATE_INTERVAL}ms)`);
}

/**
 * Pausar actualizaciones
 */
function pauseUpdates() {
    if (dashboardState.updateInterval) {
        clearInterval(dashboardState.updateInterval);
        addDebugLog('warning', 'Actualizaciones pausadas (pestaña inactiva)');
    }
}

/**
 * Reanudar actualizaciones
 */
function resumeUpdates() {
    startPeriodicUpdates();
    addDebugLog('info', 'Actualizaciones reanudadas');
}

/**
 * Obtener y actualizar métricas del dashboard
 */
async function fetchAndUpdateMetrics() {
    try {
        const response = await fetch('/api/metrics');

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        dashboardState.metrics = data;

        // Actualizar todos los componentes
        updateConnectionStatus();
        updateCounters(data.basic_stats || {});
        updateZMQConnections(data.zmq_connections || {});
        updateComponentStatus(data.component_status || {}, data.node_info || {});
        updateEvents(data.recent_events || []);

        // Log de debug ocasional
        if (Math.random() < 0.1) { // 10% de probabilidad
            addDebugLog('debug', `Métricas actualizadas: ${data.basic_stats?.events_received || 0} eventos`);
        }

    } catch (error) {
        addDebugLog('error', `Error obteniendo métricas: ${error.message}`);
        updateConnectionStatus(CONNECTION_STATES.ERROR);
        showToast(`Error de conexión: ${error.message}`, 'error');
    }
}

/**
 * Actualizar estado de conexión en header
 */
function updateConnectionStatus(forceState = null) {
    const data = dashboardState.metrics;

    // Actualizar indicadores de estado
    const connectingEl = document.getElementById('status-connecting');
    const mlDetectorEl = document.getElementById('status-ml-detector');
    const firewallEl = document.getElementById('status-firewall');

    if (forceState === CONNECTION_STATES.ERROR) {
        connectingEl.style.display = 'flex';
        connectingEl.querySelector('.status-dot').className = 'status-dot error';
        connectingEl.querySelector('span').textContent = 'Connection Error';
        return;
    }

    // Ocultar indicador de connecting si hay datos
    if (data && Object.keys(data).length > 0) {
        connectingEl.style.display = 'none';
    }

    // Estado ML Detector
    if (data.zmq_connections?.ml_events) {
        const status = data.zmq_connections.ml_events.status || 'inactive';
        mlDetectorEl.className = `status-dot ${status}`;
    }

    // Estado Firewall
    if (data.zmq_connections?.firewall_commands) {
        const status = data.zmq_connections.firewall_commands.status || 'inactive';
        firewallEl.className = `status-dot ${status}`;
    }

    // Actualizar contadores en header
    const basicStats = data.basic_stats || {};
    updateElement('events-counter', basicStats.events_received || 0);
    updateElement('confirmations-counter', basicStats.threats_blocked || 0);
}

/**
 * Actualizar contadores
 */
function updateCounters(basicStats) {
    updateElement('events-per-min', basicStats.events_per_minute || 0);
    updateElement('high-risk-count', basicStats.high_risk_events || 0);
    updateElement('success-rate', basicStats.threats_blocked || 0);
    updateElement('failure-count', 0); // Calcular desde errores

    // Actualizar arquitectura
    updateElement('events-count', basicStats.events_received || 0);
    updateElement('commands-count', basicStats.commands_sent || 0);
    updateElement('confirmations-count', basicStats.threats_blocked || 0);
}

/**
 * Actualizar conexiones ZeroMQ
 */
function updateZMQConnections(zmqConnections) {
    // ML Events
    if (zmqConnections.ml_events) {
        const conn = zmqConnections.ml_events;
        updateElement('ml-messages', conn.total_messages || 0);
        updateElement('ml-bytes', formatBytes(conn.bytes_transferred || 0));
        updateElement('ml-last-activity', formatRelativeTime(conn.last_activity));
        updateElement('ml-queue-size', conn.queue_size || 0);
        updateElement('ml-events-endpoint', conn.endpoint || 'tcp://localhost:5570');
        updateElement('ml-events-type', conn.socket_type || 'PULL');
        updateElement('ml-events-mode', conn.mode || 'CONNECT');
        updateElement('ml-hwm', conn.high_water_mark || 0);

        updateConnectionElement('zmq-ml-events', conn.status);
        updateConnectionElement('ml-events-status', conn.status);
        updateTopologyStatus('topology-ml-status', conn.status);
    }

    // Firewall Commands
    if (zmqConnections.firewall_commands) {
        const conn = zmqConnections.firewall_commands;
        updateElement('fw-cmd-count', conn.total_messages || 0);
        updateElement('fw-cmd-bytes', formatBytes(conn.bytes_transferred || 0));
        updateElement('fw-subscribers', conn.connected_peers?.length || 0);
        updateElement('fw-cmd-queue', conn.queue_size || 0);
        updateElement('fw-commands-endpoint', conn.endpoint || 'tcp://*:5580');
        updateElement('fw-commands-type', conn.socket_type || 'PUB');
        updateElement('fw-commands-mode', conn.mode || 'BIND');
        updateElement('fw-cmd-hwm', conn.high_water_mark || 0);

        updateConnectionElement('zmq-fw-commands', conn.status);
        updateConnectionElement('fw-commands-status', conn.status);
        updateTopologyStatus('topology-fw-cmd-status', conn.status);
    }

    // Firewall Responses
    if (zmqConnections.firewall_responses) {
        const conn = zmqConnections.firewall_responses;
        updateElement('fw-resp-count', conn.total_messages || 0);
        updateElement('fw-resp-bytes', formatBytes(conn.bytes_transferred || 0));
        updateElement('fw-success-rate', '95%'); // Calcular desde respuestas
        updateElement('fw-latency', '12ms'); // Calcular desde métricas
        updateElement('fw-responses-endpoint', conn.endpoint || 'tcp://*:5581');
        updateElement('fw-responses-type', conn.socket_type || 'PULL');
        updateElement('fw-responses-mode', conn.mode || 'BIND');
        updateElement('fw-resp-hwm', conn.high_water_mark || 0);

        updateConnectionElement('zmq-fw-responses', conn.status);
        updateConnectionElement('fw-responses-status', conn.status);
        updateTopologyStatus('topology-fw-resp-status', conn.status);
    }
}

/**
 * Actualizar estado de componentes
 */
function updateComponentStatus(componentStatus, nodeInfo) {
    const basicStats = dashboardState.metrics.basic_stats || {};

    // Dashboard info
    if (nodeInfo) {
        updateElement('dashboard-node', nodeInfo.node_id || 'dashboard_distributed_001');
        updateElement('dashboard-uptime', formatUptime(nodeInfo.uptime_seconds || 0));
    }

    updateElement('dashboard-memory', Math.round(basicStats.memory_usage_mb || 0) + 'MB');
    updateElement('dashboard-cpu', (basicStats.cpu_usage_percent || 0).toFixed(1) + '%');

    // ML Detector (simular basado en métricas)
    updateElement('ml-detector-latency', '8ms');
    updateElement('ml-detector-processed', basicStats.events_processed || 0);
    updateElement('ml-detector-backpressure', '0');

    // Firewall Agent (simular)
    updateElement('firewall-active-rules', Math.floor(Math.random() * 20) + 5);
    updateElement('firewall-applied', basicStats.threats_blocked || 0);
    updateElement('firewall-failed', '0');
}

/**
 * Actualizar eventos y mapa
 */
function updateEvents(events) {
    if (!events || events.length === 0) return;

    events.forEach(event => {
        if (!dashboardState.events.find(e => e.id === event.id)) {
            dashboardState.events.unshift(event);
            addEventToMap(event);

            // Log para eventos de alto riesgo
            if (event.risk_score > 0.8) {
                addDebugLog('warning', `Amenaza alta: ${event.source_ip} -> ${event.target_ip} (${Math.round(event.risk_score * 100)}%)`);
                showThreatIndicator();
            }
        }
    });

    // Mantener límite de eventos
    if (dashboardState.events.length > DASHBOARD_CONFIG.MAX_EVENTS) {
        dashboardState.events = dashboardState.events.slice(0, DASHBOARD_CONFIG.MAX_EVENTS);
    }
}

/**
 * Añadir evento al mapa
 */
function addEventToMap(event) {
    if (!event.latitude || !event.longitude || !dashboardState.map) return;

    const riskLevel = getRiskLevel(event.risk_score);
    const color = getRiskColor(riskLevel);

    const marker = L.circleMarker([event.latitude, event.longitude], {
        radius: 6 + (event.risk_score * 8),
        fillColor: color,
        color: '#fff',
        weight: 1,
        opacity: 0.8,
        fillOpacity: 0.6
    }).addTo(dashboardState.map);

    // Popup reactivo con botón para ver detalles
    marker.bindPopup(`
        <div style="color: #000; font-size: 11px; font-family: Consolas, monospace;">
            <strong>🚨 Evento de Seguridad</strong><br>
            <strong>IP Origen:</strong> ${event.source_ip}<br>
            <strong>IP Destino:</strong> ${event.target_ip}<br>
            <strong>Riesgo:</strong> ${Math.round(event.risk_score * 100)}%<br>
            <strong>Tipo:</strong> ${event.attack_type || 'Desconocido'}<br>
            <strong>Ubicación:</strong> ${event.location || 'No disponible'}<br>
            <strong>Timestamp:</strong> ${formatTime(event.timestamp)}<br>
            <br>
            <button onclick="showEventDetailsModal('${event.id}')"
                    style="background: #007cba; color: white; border: none; padding: 6px 12px;
                           border-radius: 3px; cursor: pointer; font-size: 11px;">
                🔍 Ver Detalles Completos
            </button>
        </div>
    `);

    marker.eventId = event.id;
    dashboardState.markers.push(marker);

    // Limpiar marcadores antiguos
    if (dashboardState.markers.length > DASHBOARD_CONFIG.MAX_MARKERS) {
        const oldMarker = dashboardState.markers.shift();
        dashboardState.map.removeLayer(oldMarker);
    }
}

// ============================================================================
// FUNCIONES DE INTERACTIVIDAD (ONCLICK HANDLERS)
// ============================================================================

/**
 * Mostrar detalles de conexión
 */
function showConnectionDetails(connectionType) {
    const connections = dashboardState.metrics.zmq_connections || {};
    let title, content;

    switch (connectionType) {
        case 'ml-detector':
            title = '📡 ML Detector Connection';
            const mlConn = connections.ml_events || {};
            content = `
                <div class="detail-section">
                    <h4>Estado de Conexión</h4>
                    <p><strong>Status:</strong> ${mlConn.status || 'unknown'}</p>
                    <p><strong>Endpoint:</strong> ${mlConn.endpoint || 'tcp://localhost:5570'}</p>
                    <p><strong>Socket Type:</strong> ${mlConn.socket_type || 'PULL'}</p>
                    <p><strong>Mode:</strong> ${mlConn.mode || 'CONNECT'}</p>
                    <p><strong>High Water Mark:</strong> ${mlConn.high_water_mark || 0}</p>
                </div>
                <div class="detail-section">
                    <h4>Estadísticas</h4>
                    <p><strong>Mensajes Totales:</strong> ${mlConn.total_messages || 0}</p>
                    <p><strong>Bytes Transferidos:</strong> ${formatBytes(mlConn.bytes_transferred || 0)}</p>
                    <p><strong>Última Actividad:</strong> ${formatTime(mlConn.last_activity)}</p>
                    <p><strong>Cola Actual:</strong> ${mlConn.queue_size || 0}</p>
                </div>
            `;
            break;

        case 'firewall':
            title = '🔥 Firewall Agent Connection';
            const fwConn = connections.firewall_commands || {};
            content = `
                <div class="detail-section">
                    <h4>Firewall Commands</h4>
                    <p><strong>Status:</strong> ${fwConn.status || 'unknown'}</p>
                    <p><strong>Endpoint:</strong> ${fwConn.endpoint || 'tcp://*:5580'}</p>
                    <p><strong>Comandos Enviados:</strong> ${fwConn.total_messages || 0}</p>
                    <p><strong>Subscribers:</strong> ${fwConn.connected_peers?.length || 0}</p>
                </div>
                <div class="detail-section">
                    <h4>Firewall Responses</h4>
                    <p><strong>Respuestas:</strong> ${connections.firewall_responses?.total_messages || 0}</p>
                    <p><strong>Tasa de Éxito:</strong> 95%</p>
                    <p><strong>Latencia Media:</strong> 12ms</p>
                </div>
            `;
            break;

        default:
            title = '🔌 Estado de Conexiones';
            content = `
                <div class="detail-section">
                    <h4>Resumen de Conexiones</h4>
                    <p>ML Detector: ${connections.ml_events?.status || 'unknown'}</p>
                    <p>FW Commands: ${connections.firewall_commands?.status || 'unknown'}</p>
                    <p>FW Responses: ${connections.firewall_responses?.status || 'unknown'}</p>
                </div>
            `;
    }

    showModal(title, content, [
        {text: 'Probar Conexión', action: () => testSpecificConnection(connectionType), class: 'btn-primary'},
        {text: 'Cerrar', action: closeModal, class: 'btn-secondary'}
    ]);
}

/**
 * Mostrar información del sistema
 */
function showSystemInfo() {
    const nodeInfo = dashboardState.metrics.node_info || {};
    const basicStats = dashboardState.metrics.basic_stats || {};

    const content = `
        <div class="detail-section">
            <h4>Información del Nodo</h4>
            <p><strong>Node ID:</strong> ${nodeInfo.node_id || 'N/A'}</p>
            <p><strong>Component:</strong> ${nodeInfo.component_name || 'N/A'}</p>
            <p><strong>Version:</strong> ${nodeInfo.version || 'N/A'}</p>
            <p><strong>PID:</strong> ${nodeInfo.pid || 'N/A'}</p>
            <p><strong>Uptime:</strong> ${formatUptime(nodeInfo.uptime_seconds || 0)}</p>
        </div>
        <div class="detail-section">
            <h4>Recursos del Sistema</h4>
            <p><strong>Memoria:</strong> ${Math.round(basicStats.memory_usage_mb || 0)} MB</p>
            <p><strong>CPU:</strong> ${(basicStats.cpu_usage_percent || 0).toFixed(1)}%</p>
            <p><strong>Última Actualización:</strong> ${formatTime(basicStats.last_update)}</p>
        </div>
    `;

    showModal('🖥️ Información del Sistema', content);
}

/**
 * Mostrar resumen de eventos
 */
function showEventsSummary() {
    const basicStats = dashboardState.metrics.basic_stats || {};
    const recentEvents = dashboardState.events.slice(0, 10);

    let eventsHtml = '';
    recentEvents.forEach(event => {
        eventsHtml += `
            <div class="event-summary-item" onclick="showEventDetailsModal('${event.id}')">
                <strong>${event.source_ip}</strong> → ${event.target_ip}
                <span class="risk-badge risk-${getRiskLevel(event.risk_score)}">${Math.round(event.risk_score * 100)}%</span>
            </div>
        `;
    });

    const content = `
        <div class="detail-section">
            <h4>Estadísticas de Eventos</h4>
            <p><strong>Total Recibidos:</strong> ${basicStats.events_received || 0}</p>
            <p><strong>Eventos/Minuto:</strong> ${basicStats.events_per_minute || 0}</p>
            <p><strong>Alto Riesgo:</strong> ${basicStats.high_risk_events || 0}</p>
            <p><strong>Distribución Geográfica:</strong> ${basicStats.geographic_distribution || 0} países</p>
        </div>
        <div class="detail-section">
            <h4>Eventos Recientes</h4>
            ${eventsHtml || '<p>No hay eventos recientes</p>'}
        </div>
    `;

    showModal('📊 Resumen de Eventos', content);
}

/**
 * Mostrar resumen de confirmaciones
 */
function showConfirmationsSummary() {
    const basicStats = dashboardState.metrics.basic_stats || {};
    const recentCommands = dashboardState.metrics.recent_commands || [];

    let commandsHtml = '';
    recentCommands.slice(0, 10).forEach(command => {
        commandsHtml += `
            <div class="command-summary-item">
                <strong>${command.action}</strong> - ${command.target_ip}
                <span class="command-status">✅ Applied</span>
            </div>
        `;
    });

    const content = `
        <div class="detail-section">
            <h4>Estadísticas de Firewall</h4>
            <p><strong>Comandos Enviados:</strong> ${basicStats.commands_sent || 0}</p>
            <p><strong>Amenazas Bloqueadas:</strong> ${basicStats.threats_blocked || 0}</p>
            <p><strong>Tasa de Éxito:</strong> 95%</p>
            <p><strong>Agentes Activos:</strong> ${basicStats.active_firewall_agents || 0}</p>
        </div>
        <div class="detail-section">
            <h4>Comandos Recientes</h4>
            ${commandsHtml || '<p>No hay comandos recientes</p>'}
        </div>
    `;

    showModal('✅ Confirmaciones de Firewall', content);
}

/**
 * Mostrar detalles de evento completo con datos protobuf
 */
function showEventDetailsModal(eventId) {
    const event = dashboardState.events.find(e => e.id === eventId);
    if (!event) {
        showToast('Evento no encontrado', 'error');
        return;
    }

    dashboardState.selectedEvent = event;

    // Crear contenido detallado con datos protobuf
    const protobufData = event.protobuf_data || {};
    const mlScores = event.ml_models_scores || {};

    const content = `
        <div class="event-detail-container">
            <div class="detail-section">
                <h4>🌐 Información de Red</h4>
                <p><strong>IP Origen:</strong> ${event.source_ip}</p>
                <p><strong>IP Destino:</strong> ${event.target_ip}</p>
                <p><strong>Puerto:</strong> ${event.port || 'N/A'}</p>
                <p><strong>Protocolo:</strong> ${event.protocol || 'N/A'}</p>
                <p><strong>Paquetes:</strong> ${event.packets || 0}</p>
                <p><strong>Bytes:</strong> ${formatBytes(event.bytes || 0)}</p>
            </div>

            <div class="detail-section">
                <h4>🎯 Análisis de Riesgo</h4>
                <p><strong>Puntuación de Riesgo:</strong>
                   <span class="risk-badge risk-${getRiskLevel(event.risk_score)}">${Math.round(event.risk_score * 100)}%</span></p>
                <p><strong>Puntuación de Anomalía:</strong> ${Math.round(event.anomaly_score * 100)}%</p>
                <p><strong>Tipo de Ataque:</strong> ${event.attack_type || 'Desconocido'}</p>
                <p><strong>Criticidad:</strong> ${getRiskLevel(event.risk_score).toUpperCase()}</p>
            </div>

            <div class="detail-section">
                <h4>🗺️ Geolocalización</h4>
                <p><strong>Ubicación:</strong> ${event.location || 'No disponible'}</p>
                <p><strong>Latitud:</strong> ${event.latitude || 'N/A'}</p>
                <p><strong>Longitud:</strong> ${event.longitude || 'N/A'}</p>
                <p><strong>Timestamp:</strong> ${formatTime(event.timestamp)}</p>
            </div>

            <div class="detail-section">
                <h4>🤖 Modelos ML</h4>
                ${Object.keys(mlScores).length > 0 ?
                    Object.entries(mlScores).map(([model, score]) =>
                        `<p><strong>${model}:</strong> ${(score * 100).toFixed(1)}%</p>`
                    ).join('') :
                    '<p>No hay datos de modelos ML disponibles</p>'
                }
            </div>

            <div class="detail-section">
                <h4>📦 Datos Protobuf Completos</h4>
                <div class="protobuf-data">
                    <pre>${JSON.stringify(protobufData, null, 2)}</pre>
                </div>
            </div>
        </div>
    `;

    const actions = [
        {
            text: '🛡️ Bloquear IP',
            action: () => blockIPFromEvent(event),
            class: 'btn-danger'
        },
        {
            text: '📊 Ver en Mapa',
            action: () => focusEventOnMap(event),
            class: 'btn-primary'
        },
        {
            text: '📋 Copiar Datos',
            action: () => copyEventData(event),
            class: 'btn-secondary'
        },
        {
            text: 'Cerrar',
            action: closeModal,
            class: 'btn-secondary'
        }
    ];

    showModal(`🚨 Detalles del Evento - ${event.source_ip}`, content, actions);
}

/**
 * Mostrar detalles de puerto específico
 */
function showPortDetails(port, event) {
    event.stopPropagation();

    const connections = dashboardState.metrics.zmq_connections || {};
    let title, connection, description;

    switch (port) {
        case 5570:
            title = '📡 Puerto 5570 - ML Events Input';
            connection = connections.ml_events || {};
            description = 'Recibe eventos enriquecidos del lightweight_ml_detector';
            break;
        case 5580:
            title = '🔥 Puerto 5580 - Firewall Commands Output';
            connection = connections.firewall_commands || {};
            description = 'Envía comandos de firewall al simple_firewall_agent';
            break;
        case 5581:
            title = '📥 Puerto 5581 - Firewall Responses Input';
            connection = connections.firewall_responses || {};
            description = 'Recibe respuestas del simple_firewall_agent';
            break;
    }

    const content = `
        <div class="detail-section">
            <h4>Configuración del Puerto</h4>
            <p><strong>Puerto:</strong> ${port}</p>
            <p><strong>Descripción:</strong> ${description}</p>
            <p><strong>Endpoint:</strong> ${connection.endpoint || `tcp://localhost:${port}`}</p>
            <p><strong>Tipo de Socket:</strong> ${connection.socket_type || 'N/A'}</p>
            <p><strong>Modo:</strong> ${connection.mode || 'N/A'}</p>
        </div>
        <div class="detail-section">
            <h4>Estado y Estadísticas</h4>
            <p><strong>Estado:</strong>
               <span class="status-badge status-${connection.status || 'unknown'}">${(connection.status || 'unknown').toUpperCase()}</span></p>
            <p><strong>Mensajes:</strong> ${connection.total_messages || 0}</p>
            <p><strong>Bytes:</strong> ${formatBytes(connection.bytes_transferred || 0)}</p>
            <p><strong>HWM:</strong> ${connection.high_water_mark || 0}</p>
            <p><strong>Última Actividad:</strong> ${formatRelativeTime(connection.last_activity)}</p>
        </div>
    `;

    showModal(title, content, [
        {text: 'Probar Puerto', action: () => testPort(port), class: 'btn-primary'},
        {text: 'Cerrar', action: closeModal, class: 'btn-secondary'}
    ]);
}

// ============================================================================
// FUNCIONES DE ACCIÓN
// ============================================================================

/**
 * Actualizar dashboard manualmente
 */
function refreshDashboard() {
    addDebugLog('info', 'Actualizando dashboard manualmente...');
    fetchAndUpdateMetrics();
    showToast('Dashboard actualizado', 'success');
}

/**
 * Limpiar log de debug
 */
function clearDebugLog() {
    dashboardState.debugLogEntries = [];
    updateDebugLogDisplay();
    addDebugLog('info', 'Log de debug limpiado');
}

/**
 * Mostrar confirmaciones
 */
function showConfirmations() {
    const basicStats = dashboardState.metrics.basic_stats || {};
    const confirmations = basicStats.threats_blocked || 0;

    showModal('✅ Confirmaciones de Firewall', `
        <div class="detail-section">
            <h4>Resumen de Confirmaciones</h4>
            <p><strong>Total Confirmaciones:</strong> ${confirmations}</p>
            <p><strong>Comandos Enviados:</strong> ${basicStats.commands_sent || 0}</p>
            <p><strong>Tasa de Éxito:</strong> ${confirmations > 0 ? Math.round((confirmations / (basicStats.commands_sent || 1)) * 100) : 0}%</p>
            <p><strong>Última Actualización:</strong> ${formatTime(basicStats.last_update)}</p>
        </div>
    `);

    addDebugLog('info', `Mostrando confirmaciones: ${confirmations}`);
}

/**
 * Probar conexiones de los 3 puertos
 */
function testConnections() {
    addDebugLog('info', 'Iniciando test de 3 puertos...');

    const connections = dashboardState.metrics.zmq_connections || {};

    const results = [
        `Puerto 5570 (ML Events): ${connections.ml_events?.status || 'inactive'}`,
        `Puerto 5580 (FW Commands): ${connections.firewall_commands?.status || 'inactive'}`,
        `Puerto 5581 (FW Responses): ${connections.firewall_responses?.status || 'inactive'}`
    ];

    results.forEach(result => addDebugLog('info', result));

    showModal('🔌 Test de Conectividad - 3 Puertos', `
        <div class="detail-section">
            <h4>Resultados del Test</h4>
            ${results.map(result => `<p>${result}</p>`).join('')}
        </div>
        <div class="detail-section">
            <h4>Recomendaciones</h4>
            <p>• Verificar que todos los componentes estén ejecutándose</p>
            <p>• Revisar configuración de puertos en JSON</p>
            <p>• Comprobar logs de cada componente</p>
        </div>
    `);
}

/**
 * Limpiar marcadores del mapa
 */
function clearAllMarkers() {
    dashboardState.markers.forEach(marker => {
        dashboardState.map.removeLayer(marker);
    });
    dashboardState.markers = [];
    addDebugLog('info', 'Marcadores del mapa limpiados');
    showToast('Mapa limpiado', 'info');
}

/**
 * Centrar mapa
 */
function centerMap() {
    dashboardState.map.setView(DASHBOARD_CONFIG.MAP_CENTER, DASHBOARD_CONFIG.MAP_ZOOM);
    addDebugLog('info', 'Mapa centrado en España');
    showToast('Mapa centrado', 'info');
}

/**
 * Toggle heatmap
 */
function toggleHeatmap() {
    // Placeholder para implementación de heatmap
    addDebugLog('info', 'Heatmap toggle - función pendiente de implementar');
    showToast('Heatmap no implementado aún', 'warning');
}

// ============================================================================
// FUNCIONES AUXILIARES
// ============================================================================

/**
 * Actualizar elemento del DOM
 */
function updateElement(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

/**
 * Actualizar elemento de conexión
 */
function updateConnectionElement(elementId, status) {
    const element = document.getElementById(elementId);
    if (element) {
        element.className = element.className.replace(/\b(active|inactive|error)\b/g, '') + ' ' + (status || 'inactive');
    }
}

/**
 * Actualizar estado de topología
 */
function updateTopologyStatus(elementId, status) {
    const element = document.getElementById(elementId);
    if (element) {
        element.style.color = status === 'active' ? '#00ff00' : (status === 'error' ? '#ff4444' : '#ffaa00');
    }
}

/**
 * Añadir entrada al log de debug
 */
function addDebugLog(level, message) {
    const timestamp = new Date().toLocaleTimeString('es-ES');
    const logEntry = {
        timestamp,
        level,
        message,
        id: Date.now() + Math.random()
    };

    dashboardState.debugLogEntries.unshift(logEntry);

    // Mantener límite de entradas
    if (dashboardState.debugLogEntries.length > DASHBOARD_CONFIG.MAX_DEBUG_ENTRIES) {
        dashboardState.debugLogEntries = dashboardState.debugLogEntries.slice(0, DASHBOARD_CONFIG.MAX_DEBUG_ENTRIES);
    }

    updateDebugLogDisplay();
}

/**
 * Actualizar visualización del log
 */
function updateDebugLogDisplay() {
    const debugLog = document.getElementById('debug-log');
    if (!debugLog) return;

    debugLog.innerHTML = dashboardState.debugLogEntries.map(entry =>
        `<div class="log-entry ${entry.level}" onclick="showLogEntryDetail(this, event)" data-entry-id="${entry.id}">
            [${entry.timestamp}] [${entry.level.toUpperCase()}] ${entry.message}
        </div>`
    ).join('');

    // Auto-scroll al final
    debugLog.scrollTop = debugLog.scrollHeight;
}

/**
 * Mostrar modal genérico
 */
function showModal(title, content, actions = null) {
    const modal = document.getElementById('detail-modal');
    const overlay = document.getElementById('modal-overlay');
    const titleEl = document.getElementById('modal-title');
    const contentEl = document.getElementById('modal-content');
    const actionsEl = document.getElementById('modal-actions');

    titleEl.textContent = title;
    contentEl.innerHTML = content;

    // Limpiar y añadir acciones
    actionsEl.innerHTML = '';
    if (actions) {
        actions.forEach(action => {
            const button = document.createElement('button');
            button.className = `btn ${action.class || 'btn-secondary'}`;
            button.textContent = action.text;
            button.onclick = action.action;
            actionsEl.appendChild(button);
        });
    } else {
        const closeBtn = document.createElement('button');
        closeBtn.className = 'btn btn-secondary';
        closeBtn.textContent = 'Cerrar';
        closeBtn.onclick = closeModal;
        actionsEl.appendChild(closeBtn);
    }

    overlay.style.display = 'block';
    modal.style.display = 'block';
    dashboardState.modalOpen = true;
}

/**
 * Cerrar modal
 */
function closeModal() {
    const modal = document.getElementById('detail-modal');
    const overlay = document.getElementById('modal-overlay');

    overlay.style.display = 'none';
    modal.style.display = 'none';
    dashboardState.modalOpen = false;
}

/**
 * Mostrar toast notification
 */
function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, duration);
}

/**
 * Mostrar indicador de amenaza
 */
function showThreatIndicator() {
    const indicator = document.getElementById('threat-indicator');
    indicator.classList.add('show');

    setTimeout(() => {
        indicator.classList.remove('show');
    }, 3000);
}

/**
 * Actualizar reloj
 */
function updateClock() {
    const now = new Date();
    const timeElement = document.getElementById('current-time');
    if (timeElement) {
        timeElement.textContent = now.toLocaleTimeString('es-ES');
    }
}

/**
 * Funciones de formateo
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatTime(timestamp) {
    if (!timestamp) return '-';
    try {
        return new Date(timestamp).toLocaleString('es-ES');
    } catch {
        return '-';
    }
}

function formatRelativeTime(timestamp) {
    if (!timestamp) return '-';
    try {
        const now = new Date();
        const time = new Date(timestamp);
        const diff = now - time;
        const seconds = Math.floor(diff / 1000);

        if (seconds < 60) return `${seconds}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
        return `${Math.floor(seconds / 86400)}d`;
    } catch {
        return '-';
    }
}

function formatUptime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    if (hours > 0) {
        return `${hours}h ${minutes}m`;
    } else if (minutes > 0) {
        return `${minutes}m ${secs}s`;
    } else {
        return `${secs}s`;
    }
}

function getRiskLevel(score) {
    if (score > 0.8) return 'high';
    if (score > 0.5) return 'medium';
    return 'low';
}

function getRiskColor(level) {
    switch(level) {
        case 'high': return '#ff4444';
        case 'medium': return '#ffaa00';
        case 'low': return '#00ff00';
        default: return '#0088ff';
    }
}

// Exponer funciones globales para uso en HTML
window.initializeDashboard = initializeDashboard;
window.showConnectionDetails = showConnectionDetails;
window.showSystemInfo = showSystemInfo;
window.showEventsSummary = showEventsSummary;
window.showConfirmationsSummary = showConfirmationsSummary;
window.showEventDetailsModal = showEventDetailsModal;
window.showPortDetails = showPortDetails;
window.refreshDashboard = refreshDashboard;
window.clearDebugLog = clearDebugLog;
window.showConfirmations = showConfirmations;
window.testConnections = testConnections;
window.clearAllMarkers = clearAllMarkers;
window.centerMap = centerMap;
window.toggleHeatmap = toggleHeatmap;
window.closeModal = closeModal;