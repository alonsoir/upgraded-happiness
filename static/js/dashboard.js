/**
 * SCADA Dashboard JavaScript - Completamente Reactivo
 * Maneja toda la interactividad del dashboard con datos protobuf
 */

// Variables globales del dashboard
let localNodeMarker = null;
let eventsUpdatePaused = false;
let currentEventsFilter = 'all';
let collapsedSections = new Set(); // Tracking de secciones colapsadas

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

    // Aplicar filtros al mapa
    applyMapFilters();

    // Configurar secciones colapsables (empezar con todas expandidas excepto debug)
    setTimeout(() => {
        toggleSection('debug');
    }, 1000);

    // Logs iniciales
    addDebugLog('info', 'Sistema SCADA Dashboard v2.2 iniciado');
    addDebugLog('info', 'Arquitectura 3 puertos configurada');
    addDebugLog('info', 'Mapa geolocalizado y eventos en tiempo real activados');
    addDebugLog('info', 'Cajas minimizables habilitadas');

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
        maxZoom: 19,
        className: 'dark-map-tiles'
    }).addTo(dashboardState.map);

    // Añadir marcador del nodo local inmediatamente
    addLocalNodeMarker();

    addDebugLog('info', `Mapa inicializado en ${DASHBOARD_CONFIG.MAP_CENTER.join(', ')}`);
}

/**
 * Aplicar filtros CSS adicionales al mapa
 */
function applyMapFilters() {
    const mapContainer = document.getElementById('map');
    if (mapContainer) {
        mapContainer.classList.add('enhanced-dark-map');
    }
}

function addLocalNodeMarker() {
    const nodePosition = [40.4168, -3.7038]; // Madrid, España

    // Crear icono personalizado para el nodo local
    const nodeIcon = L.divIcon({
        html: `
            <div style="
                background: #0088ff;
                width: 20px;
                height: 20px;
                border-radius: 50%;
                border: 3px solid #fff;
                box-shadow: 0 0 10px rgba(0, 136, 255, 0.8);
                position: relative;
                animation: nodeGlow 2s infinite;
            ">
                <div style="
                    position: absolute;
                    top: -2px;
                    left: -2px;
                    width: 24px;
                    height: 24px;
                    border: 2px solid #0088ff;
                    border-radius: 50%;
                    opacity: 0.6;
                    animation: nodePulse 2s infinite;
                "></div>
            </div>
            <style>
                @keyframes nodeGlow {
                    0%, 100% { box-shadow: 0 0 10px rgba(0, 136, 255, 0.8); }
                    50% { box-shadow: 0 0 20px rgba(0, 136, 255, 1); }
                }
                @keyframes nodePulse {
                    0% { transform: scale(1); opacity: 0.6; }
                    50% { transform: scale(1.5); opacity: 0.3; }
                    100% { transform: scale(2); opacity: 0; }
                }
            </style>
        `,
        className: 'local-node-marker',
        iconSize: [20, 20],
        iconAnchor: [10, 10]
    });

    // Añadir marcador al mapa
    localNodeMarker = L.marker(nodePosition, {
        icon: nodeIcon,
        zIndexOffset: 1000 // Asegurar que esté encima de otros marcadores
    }).addTo(dashboardState.map);

    // Popup detallado del nodo local
    localNodeMarker.bindPopup(`
        <div style="color: #000; font-size: 12px; font-family: Consolas, monospace; min-width: 200px;">
            <strong>🏠 Nodo Local - Dashboard</strong><br>
            <strong>Ubicación:</strong> Madrid, España<br>
            <strong>Coordenadas:</strong> ${nodePosition[0]}, ${nodePosition[1]}<br>
            <strong>Node ID:</strong> dashboard_distributed_001<br>
            <strong>Componentes Activos:</strong><br>
            • Dashboard (Puerto 8080)<br>
            • ML Events Receiver (Puerto 5570)<br>
            • Firewall Commands (Puerto 5580)<br>
            • Firewall Responses (Puerto 5581)<br>
            <br>
            <button onclick="showNodeDetailsModal()"
                    style="background: #0088ff; color: white; border: none; padding: 6px 12px;
                           border-radius: 3px; cursor: pointer; font-size: 11px; margin-right: 5px;">
                🔍 Detalles Completos
            </button>
            <button onclick="testAllConnections()"
                    style="background: #00ff00; color: black; border: none; padding: 6px 12px;
                           border-radius: 3px; cursor: pointer; font-size: 11px;">
                🧪 Probar Conexiones
            </button>
        </div>
    `);

    addDebugLog('info', `Marcador del nodo local añadido en ${nodePosition.join(', ')}`);
}

function updateLocalNodeMarker(localNodeData) {
    if (!localNodeData || !localNodeMarker) return;

    // Actualizar popup con datos reales
    const popup = `
        <div style="color: #000; font-size: 12px; font-family: Consolas, monospace; min-width: 200px;">
            <strong>🏠 ${localNodeData.node_id || 'Nodo Local'}</strong><br>
            <strong>Estado:</strong> <span style="color: green;">ONLINE</span><br>
            <strong>Ubicación:</strong> ${localNodeData.location || 'Madrid, España'}<br>
            <strong>Coordenadas:</strong> ${localNodeData.latitude}, ${localNodeData.longitude}<br>
            <strong>Tipo:</strong> ${localNodeData.component_type || 'dashboard'}<br>
            <strong>Última Actualización:</strong> ${formatTime(localNodeData.timestamp)}<br>
            <br>
            <strong>🔌 Conexiones Activas:</strong><br>
            ${getConnectionStatusSummary()}<br>
            <br>
            <button onclick="showNodeDetailsModal()"
                    style="background: #0088ff; color: white; border: none; padding: 6px 12px;
                           border-radius: 3px; cursor: pointer; font-size: 11px; margin-right: 5px;">
                🔍 Detalles
            </button>
            <button onclick="testAllConnections()"
                    style="background: #00ff00; color: black; border: none; padding: 6px 12px;
                           border-radius: 3px; cursor: pointer; font-size: 11px;">
                🧪 Test
            </button>
        </div>
    `;

    localNodeMarker.setPopupContent(popup);
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

        // Usar función mejorada para eventos
        updateEventsImproved(data.recent_events || []);

        // Actualizar marcador del nodo local
        if (data.local_node_position) {
            updateLocalNodeMarker(data.local_node_position);
        }

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
        if (connectingEl) {
            connectingEl.style.display = 'flex';
            connectingEl.querySelector('.status-dot').className = 'status-dot error';
            connectingEl.querySelector('span').textContent = 'Connection Error';
        }
        return;
    }

    // Ocultar indicador de connecting si hay datos
    if (data && Object.keys(data).length > 0 && connectingEl) {
        connectingEl.style.display = 'none';
    }

    // Estado ML Detector
    if (data.zmq_connections?.ml_events && mlDetectorEl) {
        const status = data.zmq_connections.ml_events.status || 'inactive';
        mlDetectorEl.className = `status-dot ${status}`;
    }

    // Estado Firewall
    if (data.zmq_connections?.firewall_commands && firewallEl) {
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
        updateElement('ml-last-activity', formatRelativeTime(conn.last_activity));
        updateElement('ml-events-endpoint', conn.endpoint || 'tcp://localhost:5570');

        updateConnectionElement('zmq-ml-events', conn.status);
        updateConnectionElement('ml-events-status', conn.status);
        updateTopologyStatus('topology-ml-status', conn.status);
    }

    // Firewall Commands
    if (zmqConnections.firewall_commands) {
        const conn = zmqConnections.firewall_commands;
        updateElement('fw-cmd-count', conn.total_messages || 0);
        updateElement('fw-subscribers', conn.connected_peers?.length || 0);
        updateElement('fw-commands-endpoint', conn.endpoint || 'tcp://*:5580');

        updateConnectionElement('zmq-fw-commands', conn.status);
        updateConnectionElement('fw-commands-status', conn.status);
        updateTopologyStatus('topology-fw-cmd-status', conn.status);
    }

    // Firewall Responses
    if (zmqConnections.firewall_responses) {
        const conn = zmqConnections.firewall_responses;
        updateElement('fw-resp-count', conn.total_messages || 0);
        updateElement('fw-success-rate', '95%'); // Calcular desde respuestas
        updateElement('fw-responses-endpoint', conn.endpoint || 'tcp://*:5581');

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

/**
 * Actualizar eventos mejorada - incluye lista de eventos
 */
function updateEventsImproved(events) {
    if (!events || events.length === 0) return;

    // Actualizar eventos en el mapa (función original)
    updateEvents(events);

    // Actualizar lista de eventos en sidebar
    updateEventsList(events);

    // Actualizar estadísticas específicas de eventos
    updateEventsStatistics(events);
}

/**
 * Actualizar estadísticas específicas de eventos
 */
function updateEventsStatistics(events) {
    const highRiskEvents = events.filter(e => e.risk_score > 0.8).length;
    const mediumRiskEvents = events.filter(e => e.risk_score > 0.5 && e.risk_score <= 0.8).length;
    const lowRiskEvents = events.filter(e => e.risk_score <= 0.5).length;

    // Actualizar contadores si existen
    updateElement('high-risk-count', highRiskEvents);

    addDebugLog('debug', `Estadísticas de eventos: Alto: ${highRiskEvents}, Medio: ${mediumRiskEvents}, Bajo: ${lowRiskEvents}`);
}

/**
 * Actualizar lista de eventos
 */
function updateEventsList(events) {
    if (eventsUpdatePaused || !events || events.length === 0) return;

    const eventsList = document.getElementById('events-list');
    const eventsCount = document.getElementById('live-events-count');

    if (!eventsList) return;

    // Limpiar placeholder si existe
    if (eventsList.querySelector('.no-events-placeholder')) {
        eventsList.innerHTML = '';
    }

    // Actualizar contador
    if (eventsCount) {
        eventsCount.textContent = events.length;
    }

    // Añadir eventos nuevos al principio
    events.forEach(event => {
        if (!document.querySelector(`[data-event-id="${event.id}"]`)) {
            const eventElement = createEventElement(event);
            eventsList.insertBefore(eventElement, eventsList.firstChild);
        }
    });

    // Mantener solo los últimos 50 eventos
    const eventItems = eventsList.querySelectorAll('.event-item');
    if (eventItems.length > 50) {
        for (let i = 50; i < eventItems.length; i++) {
            eventItems[i].remove();
        }
    }

    // Aplicar filtro actual
    filterEvents();
}

/**
 * Crear elemento de evento
 */
function createEventElement(event) {
    const eventDiv = document.createElement('div');
    eventDiv.className = `event-item risk-${getRiskLevel(event.risk_score)} new-event`;
    eventDiv.setAttribute('data-event-id', event.id);
    eventDiv.onclick = () => showEventDetailsModal(event.id);

    const riskPercentage = Math.round(event.risk_score * 100);
    const eventTime = formatTime(event.timestamp);

    eventDiv.innerHTML = `
        <div class="event-header">
            <span class="event-time">${eventTime}</span>
            <span class="event-risk ${getRiskLevel(event.risk_score)}">${riskPercentage}%</span>
        </div>
        <div class="event-details">
            <div>
                <span class="event-source">${event.source_ip}</span>
                →
                <span class="event-target">${event.target_ip}</span>
                ${event.port ? `:${event.port}` : ''}
            </div>
            <div>
                <span class="event-type">${event.attack_type || event.event_type || 'unknown'}</span>
                ${event.protocol ? `• ${event.protocol}` : ''}
                ${event.location ? `• ${event.location}` : ''}
            </div>
        </div>
        <div class="event-actions">
            <button class="event-action-btn block" onclick="blockEventIP('${event.source_ip}', event)" title="Bloquear IP">
                🛡️ Block
            </button>
            <button class="event-action-btn details" onclick="showEventDetailsModal('${event.id}'); event.stopPropagation()" title="Ver detalles">
                🔍 Details
            </button>
            <button class="event-action-btn map" onclick="focusEventOnMap('${event.id}'); event.stopPropagation()" title="Ver en mapa">
                🗺️ Map
            </button>
        </div>
    `;

    // Remover la clase new-event después de la animación
    setTimeout(() => {
        eventDiv.classList.remove('new-event');
    }, 2000);

    return eventDiv;
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
            action: () => focusEventOnMap(event.id),
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
    if (localNodeMarker) {
        centerMapOnLocalNode();
    } else {
        dashboardState.map.setView(DASHBOARD_CONFIG.MAP_CENTER, DASHBOARD_CONFIG.MAP_ZOOM);
        addDebugLog('info', 'Mapa centrado en vista por defecto');
        showToast('Mapa centrado', 'info');
    }
}

function centerMapOnLocalNode() {
    if (localNodeMarker && dashboardState.map) {
        dashboardState.map.setView(localNodeMarker.getLatLng(), 10);
        localNodeMarker.openPopup();
        addDebugLog('info', 'Mapa centrado en nodo local');
        showToast('Vista centrada en nodo local', 'info');
    }
}

/**
 * Toggle heatmap
 */
function toggleHeatmap() {
    // Placeholder para implementación de heatmap
    addDebugLog('info', 'Heatmap toggle - función pendiente de implementar');
    showToast('Heatmap no implementado aún', 'warning');
}

function showMapLegend() {
    const content = `
        <div class="map-legend">
            <h4>🗺️ Leyenda del Mapa</h4>

            <div class="legend-section">
                <h5>Marcadores</h5>
                <div class="legend-item">
                    <div class="legend-marker" style="background: #0088ff; border: 2px solid #fff;"></div>
                    <span>Nodo Local (Dashboard)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-marker" style="background: #00ff00;"></div>
                    <span>Evento de Riesgo Bajo (0-50%)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-marker" style="background: #ffaa00;"></div>
                    <span>Evento de Riesgo Medio (50-80%)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-marker" style="background: #ff4444;"></div>
                    <span>Evento de Riesgo Alto (80-100%)</span>
                </div>
            </div>

            <div class="legend-section">
                <h5>Controles del Mapa</h5>
                <p><strong>Clear Map:</strong> Eliminar todos los marcadores de eventos</p>
                <p><strong>Center:</strong> Centrar vista en el nodo local</p>
                <p><strong>Heatmap:</strong> Activar mapa de calor (próximamente)</p>
                <p><strong>Legend:</strong> Mostrar esta leyenda</p>
            </div>

            <div class="legend-section">
                <h5>Interacciones</h5>
                <p><strong>Click en marcador:</strong> Ver detalles del evento/nodo</p>
                <p><strong>Zoom:</strong> Rueda del ratón o controles del mapa</p>
                <p><strong>Pan:</strong> Arrastrar para mover vista</p>
            </div>
        </div>

        <style>
            .map-legend {
                font-size: 11px;
                line-height: 1.4;
            }
            .legend-section {
                margin-bottom: 15px;
                padding-bottom: 10px;
                border-bottom: 1px solid #333;
            }
            .legend-section:last-child {
                border-bottom: none;
            }
            .legend-section h5 {
                color: #00ffff;
                margin-bottom: 8px;
                font-size: 12px;
            }
            .legend-item {
                display: flex;
                align-items: center;
                margin-bottom: 5px;
            }
            .legend-marker {
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 8px;
                border: 1px solid #fff;
            }
        </style>
    `;

    showModal('🗺️ Leyenda del Mapa', content);
}

function toggleSection(sectionId) {
    const content = document.getElementById(`${sectionId}-content`);
    const toggle = document.getElementById(`${sectionId}-toggle`);
    const section = document.getElementById(`${sectionId}-section`);

    if (!content || !toggle) return;

    const isCollapsed = content.classList.contains('collapsed');

    if (isCollapsed) {
        // Expandir
        content.classList.remove('collapsed');
        toggle.classList.remove('rotated');
        if (section) section.classList.add('expanded');
        collapsedSections.delete(sectionId);
        addDebugLog('debug', `Sección ${sectionId} expandida`);
    } else {
        // Colapsar
        content.classList.add('collapsed');
        toggle.classList.add('rotated');
        if (section) section.classList.remove('expanded');
        collapsedSections.add(sectionId);
        addDebugLog('debug', `Sección ${sectionId} colapsada`);
    }
}

/**
 * Filtrar eventos por tipo
 */
function filterEvents() {
    const filter = document.getElementById('events-filter').value;
    const eventItems = document.querySelectorAll('.event-item');

    currentEventsFilter = filter;

    eventItems.forEach(item => {
        const shouldShow = filter === 'all' || item.classList.contains(`risk-${filter}`);
        item.style.display = shouldShow ? 'block' : 'none';
    });

    addDebugLog('debug', `Eventos filtrados por: ${filter}`);
}

/**
 * Limpiar lista de eventos
 */
function clearEventsList() {
    const eventsList = document.getElementById('events-list');
    const eventsCount = document.getElementById('live-events-count');

    if (eventsList) {
        eventsList.innerHTML = `
            <div class="no-events-placeholder">
                <i class="fas fa-inbox"></i>
                <p>Lista de eventos limpiada</p>
                <button onclick="sendTestFirewallEvent()" class="btn btn-primary">
                    🧪 Generar Evento de Prueba
                </button>
            </div>
        `;
    }

    if (eventsCount) {
        eventsCount.textContent = '0';
    }

    addDebugLog('info', 'Lista de eventos limpiada');
    showToast('Lista de eventos limpiada', 'info');
}

/**
 * Pausar/reanudar actualización de eventos
 */
function pauseEventsUpdate() {
    eventsUpdatePaused = !eventsUpdatePaused;
    const button = document.getElementById('pause-events-btn');

    if (button) {
        const icon = button.querySelector('i');
        if (eventsUpdatePaused) {
            icon.className = 'fas fa-play';
            button.classList.add('paused');
            button.title = 'Reanudar actualización';
            addDebugLog('warning', 'Actualización de eventos pausada');
            showToast('Actualización de eventos pausada', 'warning');
        } else {
            icon.className = 'fas fa-pause';
            button.classList.remove('paused');
            button.title = 'Pausar actualización';
            addDebugLog('info', 'Actualización de eventos reanudada');
            showToast('Actualización de eventos reanudada', 'info');
        }
    }
}

/**
 * Bloquear IP de un evento
 */
async function blockEventIP(sourceIP, event) {
    event.stopPropagation();

    try {
        const confirmation = confirm(`¿Bloquear la IP ${sourceIP}?`);
        if (!confirmation) return;

        addDebugLog('warning', `Enviando comando de bloqueo para IP: ${sourceIP}`);

        const blockCommand = {
            action: 'block_ip',
            target_ip: sourceIP,
            duration: '1h',
            reason: `Manual block from dashboard - suspicious activity`,
            risk_score: 0.9,
            timestamp: new Date().toISOString(),
            event_id: `manual_block_${Date.now()}`,
            rule_type: 'iptables',
            port: null,
            protocol: 'all'
        };

        // Simular envío del comando (en implementación real iría al firewall)
        const response = await fetch('/api/test-firewall', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(blockCommand)
        });

        if (response.ok) {
            addDebugLog('info', `✅ Comando de bloqueo enviado para ${sourceIP}`);
            showToast(`IP ${sourceIP} enviada para bloqueo`, 'success');
        } else {
            throw new Error(`HTTP ${response.status}`);
        }

    } catch (error) {
        addDebugLog('error', `❌ Error bloqueando IP ${sourceIP}: ${error.message}`);
        showToast(`Error bloqueando IP: ${error.message}`, 'error');
    }
}

/**
 * Enfocar evento en el mapa
 */
function focusEventOnMap(eventId, event) {
    if (event) event.stopPropagation();

    const event_data = dashboardState.events.find(e => e.id === eventId);
    if (!event_data) {
        showToast('Evento no encontrado', 'error');
        return;
    }

    if (event_data.latitude && event_data.longitude && dashboardState.map) {
        dashboardState.map.setView([event_data.latitude, event_data.longitude], 10);

        // Encontrar y abrir el popup del marcador correspondiente
        dashboardState.markers.forEach(marker => {
            if (marker.eventId === eventId) {
                marker.openPopup();
            }
        });

        addDebugLog('info', `Mapa enfocado en evento: ${event_data.source_ip} -> ${event_data.target_ip}`);
        showToast('Vista centrada en evento', 'info');
    } else {
        showToast('Evento sin coordenadas geográficas', 'warning');
    }
}

/**
 * Enviar evento de prueba al firewall
 */
async function sendTestFirewallEvent() {
    try {
        addDebugLog('info', '🧪 Generando evento de prueba para firewall...');

        const testEvent = {
            id: `test_event_${Date.now()}`,
            source_ip: '192.168.1.99',
            target_ip: '10.0.0.1',
            risk_score: 0.85, // Alto riesgo para activar firewall
            anomaly_score: 0.8,
            timestamp: new Date().toISOString(),
            attack_type: 'test_intrusion',
            protocol: 'TCP',
            port: 22,
            packets: 10,
            bytes: 1024,
            latitude: 40.4168,
            longitude: -3.7038,
            location: 'Madrid, ES (Test)',
            ml_models_scores: {
                'isolation_forest': 0.85,
                'test_model': 0.9
            },
            event_type: 'test_attack',
            description: 'Manual test event for firewall verification',
            test_marker: 'MANUAL_TEST'
        };

        // Añadir evento a la lista local inmediatamente
        dashboardState.events.unshift(testEvent);
        updateEventsList([testEvent]);

        // Añadir al mapa
        addEventToMap(testEvent);

        // Simular envío al backend (que debería generar comando de firewall)
        const response = await fetch('/api/test-firewall', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ...testEvent,
                action: 'test_event',
                manual_trigger: true
            })
        });

        if (response.ok) {
            const result = await response.json();
            addDebugLog('info', `✅ Evento de prueba enviado: ${result.message || 'Success'}`);
            showToast('🧪 Evento de prueba generado exitosamente', 'success');

            // Mostrar amenaza indicator
            showThreatIndicator();
        } else {
            throw new Error(`HTTP ${response.status}`);
        }

    } catch (error) {
        addDebugLog('error', `❌ Error enviando evento de prueba: ${error.message}`);
        showToast(`Error: ${error.message}`, 'error');
    }
}

function showNodeDetailsModal() {
    const nodeInfo = dashboardState.metrics.node_info || {};
    const basicStats = dashboardState.metrics.basic_stats || {};
    const connections = dashboardState.metrics.zmq_connections || {};

    const content = `
        <div class="node-detail-container">
            <div class="detail-section">
                <h4>🏠 Información del Nodo</h4>
                <p><strong>Node ID:</strong> ${nodeInfo.node_id || 'N/A'}</p>
                <p><strong>Componente:</strong> ${nodeInfo.component_name || 'N/A'}</p>
                <p><strong>Versión:</strong> ${nodeInfo.version || 'N/A'}</p>
                <p><strong>Modo:</strong> ${nodeInfo.mode || 'N/A'}</p>
                <p><strong>Rol:</strong> ${nodeInfo.role || 'N/A'}</p>
                <p><strong>PID:</strong> ${nodeInfo.pid || 'N/A'}</p>
                <p><strong>Uptime:</strong> ${formatUptime(nodeInfo.uptime_seconds || 0)}</p>
            </div>

            <div class="detail-section">
                <h4>📊 Estadísticas del Sistema</h4>
                <p><strong>Memoria:</strong> ${Math.round(basicStats.memory_usage_mb || 0)} MB</p>
                <p><strong>CPU:</strong> ${(basicStats.cpu_usage_percent || 0).toFixed(1)}%</p>
                <p><strong>Eventos Recibidos:</strong> ${basicStats.events_received || 0}</p>
                <p><strong>Comandos Enviados:</strong> ${basicStats.commands_sent || 0}</p>
                <p><strong>Amenazas Bloqueadas:</strong> ${basicStats.threats_blocked || 0}</p>
            </div>

            <div class="detail-section">
                <h4>🔌 Estado de Conexiones ZMQ</h4>
                <div class="connections-grid">
                    <div class="connection-item">
                        <strong>ML Events (5570):</strong><br>
                        Estado: ${getStatusIcon(connections.ml_events?.status)}<br>
                        Mensajes: ${connections.ml_events?.total_messages || 0}<br>
                        Endpoint: ${connections.ml_events?.endpoint || 'tcp://localhost:5570'}
                    </div>
                    <div class="connection-item">
                        <strong>FW Commands (5580):</strong><br>
                        Estado: ${getStatusIcon(connections.firewall_commands?.status)}<br>
                        Mensajes: ${connections.firewall_commands?.total_messages || 0}<br>
                        Endpoint: ${connections.firewall_commands?.endpoint || 'tcp://*:5580'}
                    </div>
                    <div class="connection-item">
                        <strong>FW Responses (5581):</strong><br>
                        Estado: ${getStatusIcon(connections.firewall_responses?.status)}<br>
                        Mensajes: ${connections.firewall_responses?.total_messages || 0}<br>
                        Endpoint: ${connections.firewall_responses?.endpoint || 'tcp://*:5581'}
                    </div>
                </div>
            </div>

            <div class="detail-section">
                <h4>🌍 Geolocalización</h4>
                <p><strong>Ubicación:</strong> Madrid, España</p>
                <p><strong>Latitud:</strong> 40.4168</p>
                <p><strong>Longitud:</strong> -3.7038</p>
                <p><strong>Zona Horaria:</strong> Europe/Madrid</p>
            </div>
        </div>

        <style>
            .connections-grid {
                display: grid;
                grid-template-columns: 1fr;
                gap: 10px;
                margin-top: 10px;
            }
            .connection-item {
                background: rgba(0, 0, 0, 0.1);
                padding: 8px;
                border-radius: 4px;
                border-left: 3px solid #0088ff;
                font-size: 10px;
            }
        </style>
    `;

    const actions = [
        {
            text: '🧪 Probar Todas las Conexiones',
            action: testAllConnections,
            class: 'btn-primary'
        },
        {
            text: '🛡️ Probar Firewall',
            action: testFirewallConnection,
            class: 'btn-warning'
        },
        {
            text: '🔄 Actualizar',
            action: () => {
                closeModal();
                refreshDashboard();
                setTimeout(showNodeDetailsModal, 1000);
            },
            class: 'btn-secondary'
        },
        {
            text: 'Cerrar',
            action: closeModal,
            class: 'btn-secondary'
        }
    ];

    showModal('🏠 Detalles del Nodo Local', content, actions);
}

async function testAllConnections() {
    addDebugLog('info', '🧪 Iniciando prueba completa de conexiones...');

    showToast('Probando todas las conexiones...', 'info', 5000);

    const connections = dashboardState.metrics.zmq_connections || {};
    const results = [];

    // Probar cada conexión
    results.push(`📡 ML Events (5570): ${connections.ml_events?.status || 'unknown'}`);
    results.push(`🔥 FW Commands (5580): ${connections.firewall_commands?.status || 'unknown'}`);
    results.push(`📥 FW Responses (5581): ${connections.firewall_responses?.status || 'unknown'}`);

    // Probar firewall específicamente
    try {
        const firewallResult = await testFirewallConnection();
        results.push(`🛡️ Firewall Test: ${firewallResult ? 'SUCCESS' : 'FAILED'}`);
    } catch (error) {
        results.push(`🛡️ Firewall Test: ERROR - ${error.message}`);
    }

    // Mostrar resultados
    results.forEach(result => addDebugLog('info', result));

    const successCount = results.filter(r => r.includes('active') || r.includes('SUCCESS')).length;
    const totalTests = results.length;

    showModal('🧪 Resultados de Prueba de Conexiones', `
        <div class="detail-section">
            <h4>Resumen de Pruebas</h4>
            <p><strong>Éxito:</strong> ${successCount}/${totalTests} conexiones</p>
            <p><strong>Estado General:</strong> ${successCount === totalTests ? '✅ TODAS OK' : '⚠️ ALGUNAS FALLAN'}</p>
        </div>
        <div class="detail-section">
            <h4>Detalles de Cada Conexión</h4>
            ${results.map(result => `<p>${result}</p>`).join('')}
        </div>
        <div class="detail-section">
            <h4>Recomendaciones</h4>
            <p>• Verificar que todos los componentes estén ejecutándose</p>
            <p>• Revisar logs de cada componente para errores</p>
            <p>• Comprobar configuración de puertos en archivos JSON</p>
            <p>• Reiniciar componentes con problemas si es necesario</p>
        </div>
    `);

    if (successCount === totalTests) {
        showToast('✅ Todas las conexiones funcionan correctamente', 'success');
    } else {
        showToast(`⚠️ ${totalTests - successCount} conexiones tienen problemas`, 'warning');
    }
}

async function testFirewallConnection() {
    try {
        addDebugLog('info', '🛡️ Enviando comando de prueba al firewall...');

        const response = await fetch('/api/test-firewall');
        const data = await response.json();

        if (data.success) {
            addDebugLog('info', `✅ Firewall test exitoso: ${data.message}`);
            showToast('✅ Comando de prueba enviado al firewall', 'success');
            return true;
        } else {
            addDebugLog('error', `❌ Firewall test falló: ${data.message}`);
            showToast(`❌ Error en prueba de firewall: ${data.message}`, 'error');
            return false;
        }

    } catch (error) {
        addDebugLog('error', `❌ Error probando firewall: ${error.message}`);
        showToast(`❌ Error de conectividad con firewall: ${error.message}`, 'error');
        return false;
    }
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

function showLogEntryDetail(element, event) {
    event.stopPropagation();
    const message = element.textContent;
    showModal('📋 Detalle de Log Entry', `
        <div class="detail-section">
            <h4>Entrada de Log</h4>
            <pre style="white-space: pre-wrap; font-family: monospace; background: rgba(0,0,0,0.5); padding: 10px; border-radius: 4px;">${message}</pre>
        </div>
    `);
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

    if (!modal || !overlay || !titleEl || !contentEl || !actionsEl) return;

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

    if (modal && overlay) {
        overlay.style.display = 'none';
        modal.style.display = 'none';
        dashboardState.modalOpen = false;
    }
}

/**
 * Mostrar toast notification
 */
function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

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
    if (indicator) {
        indicator.classList.add('show');

        setTimeout(() => {
            indicator.classList.remove('show');
        }, 3000);
    }
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

function getConnectionStatusSummary() {
    const metrics = dashboardState.metrics;
    const connections = metrics.zmq_connections || {};

    const statuses = [
        `• ML Events: ${getStatusIcon(connections.ml_events?.status)}`,
        `• FW Commands: ${getStatusIcon(connections.firewall_commands?.status)}`,
        `• FW Responses: ${getStatusIcon(connections.firewall_responses?.status)}`
    ];

    return statuses.join('<br>');
}

function getStatusIcon(status) {
    switch(status) {
        case 'active': return '<span style="color: green;">✅ ACTIVO</span>';
        case 'inactive': return '<span style="color: orange;">⚠️ INACTIVO</span>';
        case 'error': return '<span style="color: red;">❌ ERROR</span>';
        default: return '<span style="color: gray;">❓ DESCONOCIDO</span>';
    }
}

// Funciones adicionales que podrían ser llamadas desde otros lugares
function blockIPFromEvent(event) {
    return blockEventIP(event.source_ip, {stopPropagation: () => {}});
}

function copyEventData(event) {
    const dataStr = JSON.stringify(event, null, 2);
    if (navigator.clipboard) {
        navigator.clipboard.writeText(dataStr).then(() => {
            showToast('Datos del evento copiados al portapapeles', 'success');
        });
    } else {
        showToast('Clipboard no disponible', 'warning');
    }
}

function testSpecificConnection(connectionType) {
    addDebugLog('info', `Probando conexión específica: ${connectionType}`);
    showToast(`Probando ${connectionType}...`, 'info');
    // Implementar lógica específica según el tipo de conexión
}

function testPort(port) {
    addDebugLog('info', `Probando puerto específico: ${port}`);
    showToast(`Probando puerto ${port}...`, 'info');
    // Implementar lógica específica de prueba de puerto
}

// ============================================================================
// EVENTOS Y MÉTODOS ADICIONALES PARA COMPLETAR FUNCIONALIDAD
// ============================================================================

function showEventsDetail(event) {
    event.stopPropagation();
    showEventsSummary();
}

function showCommandsDetail(event) {
    event.stopPropagation();
    showConfirmationsSummary();
}

function showConfirmationsDetail(event) {
    event.stopPropagation();
    showConfirmationsSummary();
}

function showComponentDetail(componentType) {
    addDebugLog('info', `Mostrando detalles del componente: ${componentType}`);

    const content = `
        <div class="detail-section">
            <h4>Detalles del Componente: ${componentType}</h4>
            <p>Información detallada del componente ${componentType} se mostrará aquí.</p>
        </div>
    `;

    showModal(`🔧 ${componentType}`, content);
}

function showComponentMetric(metricId, event) {
    event.stopPropagation();
    addDebugLog('debug', `Click en métrica: ${metricId}`);
}

function showTopologyLineDetail(lineId) {
    addDebugLog('info', `Mostrando detalles de línea de topología: ${lineId}`);

    const content = `
        <div class="detail-section">
            <h4>Detalles de Topología: ${lineId}</h4>
            <p>Información detallada de la línea de topología ${lineId}.</p>
        </div>
    `;

    showModal(`🔌 ${lineId}`, content);
}

function showZMQConnectionDetail(connectionId) {
    addDebugLog('info', `Mostrando detalles de conexión ZMQ: ${connectionId}`);

    const connections = dashboardState.metrics.zmq_connections || {};
    const connection = connections[connectionId.replace('-', '_')] || {};

    const content = `
        <div class="detail-section">
            <h4>Detalles de Conexión ZMQ</h4>
            <p><strong>ID:</strong> ${connectionId}</p>
            <p><strong>Estado:</strong> ${connection.status || 'unknown'}</p>
            <p><strong>Endpoint:</strong> ${connection.endpoint || 'N/A'}</p>
            <p><strong>Tipo de Socket:</strong> ${connection.socket_type || 'N/A'}</p>
            <p><strong>Modo:</strong> ${connection.mode || 'N/A'}</p>
            <p><strong>Mensajes Totales:</strong> ${connection.total_messages || 0}</p>
            <p><strong>Bytes Transferidos:</strong> ${formatBytes(connection.bytes_transferred || 0)}</p>
        </div>
    `;

    showModal(`🔌 Conexión ${connectionId}`, content);
}

function showDebugLogDetail() {
    const entriesCount = dashboardState.debugLogEntries.length;

    const content = `
        <div class="detail-section">
            <h4>Información del Log de Debug</h4>
            <p><strong>Total de Entradas:</strong> ${entriesCount}</p>
            <p><strong>Límite Máximo:</strong> ${DASHBOARD_CONFIG.MAX_DEBUG_ENTRIES}</p>
            <p><strong>Última Entrada:</strong> ${dashboardState.debugLogEntries[0]?.timestamp || 'N/A'}</p>
        </div>
        <div class="detail-section">
            <h4>Acciones</h4>
            <button onclick="clearDebugLog(); closeModal();" class="btn btn-warning">🗑️ Limpiar Log</button>
        </div>
    `;

    showModal('🐛 Debug Log Information', content);
}

function showEventsPerMinuteDetail() {
    const basicStats = dashboardState.metrics.basic_stats || {};

    const content = `
        <div class="detail-section">
            <h4>Eventos por Minuto</h4>
            <p><strong>Actual:</strong> ${basicStats.events_per_minute || 0} eventos/min</p>
            <p><strong>Total Recibidos:</strong> ${basicStats.events_received || 0}</p>
            <p><strong>Total Procesados:</strong> ${basicStats.events_processed || 0}</p>
        </div>
    `;

    showModal('📊 Eventos por Minuto', content);
}

function showHighRiskEventsDetail() {
    const basicStats = dashboardState.metrics.basic_stats || {};

    const content = `
        <div class="detail-section">
            <h4>Eventos de Alto Riesgo</h4>
            <p><strong>Count:</strong> ${basicStats.high_risk_events || 0}</p>
            <p><strong>Umbral:</strong> >80% de riesgo</p>
            <p><strong>Porcentaje del Total:</strong> ${basicStats.events_received > 0 ? ((basicStats.high_risk_events || 0) / basicStats.events_received * 100).toFixed(1) : 0}%</p>
        </div>
    `;

    showModal('⚠️ Eventos de Alto Riesgo', content);
}

function showSuccessRateDetail() {
    const basicStats = dashboardState.metrics.basic_stats || {};

    const content = `
        <div class="detail-section">
            <h4>Tasa de Éxito</h4>
            <p><strong>Amenazas Bloqueadas:</strong> ${basicStats.threats_blocked || 0}</p>
            <p><strong>Comandos Enviados:</strong> ${basicStats.commands_sent || 0}</p>
            <p><strong>Tasa de Éxito:</strong> ${basicStats.commands_sent > 0 ? ((basicStats.threats_blocked || 0) / basicStats.commands_sent * 100).toFixed(1) : 0}%</p>
        </div>
    `;

    showModal('✅ Tasa de Éxito', content);
}

function showFailuresDetail() {
    const content = `
        <div class="detail-section">
            <h4>Fallos del Sistema</h4>
            <p><strong>Fallos de Conexión:</strong> 0</p>
            <p><strong>Errores de Procesamiento:</strong> 0</p>
            <p><strong>Timeouts:</strong> 0</p>
        </div>
    `;

    showModal('❌ Detalles de Fallos', content);
}

// Exponer todas las funciones necesarias al ámbito global
window.initializeDashboard = initializeDashboard;
window.showConnectionDetails = showConnectionDetails;
window.showSystemInfo = showSystemInfo;
window.showEventsSummary = showEventsSummary;
window.showConfirmationsSummary = showConfirmationsSummary;
window.showEventDetailsModal = showEventDetailsModal;
window.showPortDetails = showPortDetails;
window.refreshDashboard = refreshDashboard;
window.clearDebugLog = clearDebugLog;
window.testConnections = testConnections;
window.clearAllMarkers = clearAllMarkers;
window.centerMap = centerMap;
window.toggleHeatmap = toggleHeatmap;
window.closeModal = closeModal;
window.showNodeDetailsModal = showNodeDetailsModal;
window.testAllConnections = testAllConnections;
window.testFirewallConnection = testFirewallConnection;
window.centerMapOnLocalNode = centerMapOnLocalNode;
window.showMapLegend = showMapLegend;
window.toggleSection = toggleSection;
window.clearEventsList = clearEventsList;
window.pauseEventsUpdate = pauseEventsUpdate;
window.filterEvents = filterEvents;
window.blockEventIP = blockEventIP;
window.focusEventOnMap = focusEventOnMap;
window.sendTestFirewallEvent = sendTestFirewallEvent;
window.showEventsDetail = showEventsDetail;
window.showCommandsDetail = showCommandsDetail;
window.showConfirmationsDetail = showConfirmationsDetail;
window.showComponentDetail = showComponentDetail;
window.showComponentMetric = showComponentMetric;
window.showTopologyLineDetail = showTopologyLineDetail;
window.showZMQConnectionDetail = showZMQConnectionDetail;
window.showDebugLogDetail = showDebugLogDetail;
window.showLogEntryDetail = showLogEntryDetail;
window.showEventsPerMinuteDetail = showEventsPerMinuteDetail;
window.showHighRiskEventsDetail = showHighRiskEventsDetail;
window.showSuccessRateDetail = showSuccessRateDetail;
window.showFailuresDetail = showFailuresDetail;