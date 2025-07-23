/*
dashboard.js - VERSIÓN V3 COMPLETA CON FIREWALL_COMMANDS.PROTO Y SISTEMA AVANZADO DE VENTANAS
+ COORDENADAS DUALES + MODAL TARGET_IP + ANIMACIONES MISIL + VENTANAS MULTI-MONITOR
*/

// ============================================================================
// VARIABLES GLOBALES
// ============================================================================

let map = null;
let markers = [];
let connectionLines = [];
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

// 🔥 Variables para configuración dual JSON
let firewallConfig = {
    agents: [],
    endpoints: {},
    capabilities: ['BLOCK_IP', 'RATE_LIMIT_IP', 'LIST_RULES', 'FLUSH_RULES']
};

let firewallRules = {
    rules: [],
    rules_count: 0,
    default_actions: ['BLOCK_IP', 'RATE_LIMIT_IP', 'LIST_RULES', 'FLUSH_RULES']
};

// 🔥 Estados de componentes para indicadores
let componentStates = {
    promiscuous_agent: false,
    geoip_enricher: false,
    ml_detector: false,
    firewall_agent: false
};

// ✅ Variables para modales draggeables avanzados
let isDragging = false;
let dragStartX = 0;
let dragStartY = 0;
let modalStartX = 0;
let modalStartY = 0;
let currentModal = null;
let modalWindowsRegistry = new Map(); // Registro de ventanas modales

// 🎯 Enum CommandAction del firewall_commands.proto
const CommandAction = {
    BLOCK_IP: 0,
    UNBLOCK_IP: 1,
    BLOCK_PORT: 2,
    UNBLOCK_PORT: 3,
    RATE_LIMIT_IP: 4,
    ALLOW_IP_TEMP: 5,
    FLUSH_RULES: 6,
    LIST_RULES: 7,
    BACKUP_RULES: 8,
    RESTORE_RULES: 9
};

// 🎯 Enum CommandPriority del firewall_commands.proto
const CommandPriority = {
    LOW: 0,
    MEDIUM: 1,
    HIGH: 2,
    CRITICAL: 3
};

// ============================================================================
// INICIALIZACIÓN PRINCIPAL
// ============================================================================

function initializeDashboard() {
    console.log('🚀 Inicializando Dashboard SCADA V3 con sistema avanzado de ventanas...');

    try {
        initializeMap();
        initializeEventHandlers();
        initializeCollapsibleSections();
        initializeAdvancedModalSystem();

        // HTTP Polling para conectar con backend
        startSimplePolling();

        updateCurrentTime();
        setInterval(updateCurrentTime, 1000);

        console.log('✅ Dashboard V3 inicializado correctamente');
        addDebugLog('info', 'Dashboard V3 inicializado - sistema avanzado + firewall_commands.proto');

    } catch (error) {
        console.error('❌ Error inicializando dashboard:', error);
        addDebugLog('error', `Error inicialización: ${error.message}`);
    }
}

// ============================================================================
// 🆕 SISTEMA AVANZADO DE VENTANAS MODALES
// ============================================================================

function initializeAdvancedModalSystem() {
    console.log('🪟 Inicializando sistema avanzado de ventanas modales...');

    document.addEventListener('mousemove', handleAdvancedMouseMove);
    document.addEventListener('mouseup', handleAdvancedMouseUp);

    // Convertir secciones existentes en ventanas avanzadas
    convertSectionsToAdvancedWindows();

    addDebugLog('info', 'Sistema avanzado de ventanas modales inicializado');
}

function convertSectionsToAdvancedWindows() {
    const sectionsToConvert = [
        { id: 'events-section', title: 'Eventos en Tiempo Real', type: 'events' },
        { id: 'firewall-events-section', title: 'Comandos Firewall', type: 'firewall' }
    ];

    sectionsToConvert.forEach(section => {
        const element = document.getElementById(section.id);
        if (element) {
            enhanceToAdvancedWindow(element, section.title, section.type);
        }
    });
}

function enhanceToAdvancedWindow(element, title, type) {
    // Agregar controles avanzados si no existen
    let header = element.querySelector('.section-header');
    if (header && !header.querySelector('.advanced-window-controls')) {
        const controlsDiv = document.createElement('div');
        controlsDiv.className = 'advanced-window-controls';
        controlsDiv.innerHTML = `
            <button class="advanced-btn minimize-adv" onclick="toggleAdvancedWindowState('${element.id}', 'minimize')" title="Minimizar">_</button>
            <button class="advanced-btn maximize-adv" onclick="toggleAdvancedWindowState('${element.id}', 'maximize')" title="Maximizar">🔲</button>
            <button class="advanced-btn fullscreen-adv" onclick="toggleAdvancedWindowState('${element.id}', 'fullscreen')" title="Pantalla Completa">⛶</button>
        `;

        header.appendChild(controlsDiv);

        // Hacer draggeable el header
        makeAdvancedWindowDraggable(element, header);
    }

    // Registrar ventana
    modalWindowsRegistry.set(element.id, {
        element: element,
        title: title,
        type: type,
        state: 'normal', // normal, minimized, maximized, fullscreen
        originalPosition: null,
        originalSize: null
    });

    console.log(`🪟 Ventana avanzada creada: ${title}`);
}

function makeAdvancedWindowDraggable(windowElement, header) {
    header.addEventListener('mousedown', function(e) {
        // Solo arrastrar si se hace clic en el header (no en botones)
        if (e.target.closest('.advanced-window-controls')) {
            return;
        }

        isDragging = true;
        currentModal = windowElement;

        dragStartX = e.clientX;
        dragStartY = e.clientY;

        const rect = windowElement.getBoundingClientRect();
        modalStartX = rect.left;
        modalStartY = rect.top;

        windowElement.classList.add('dragging-advanced');
        header.style.cursor = 'grabbing';

        e.preventDefault();

        console.log('🖱️ Iniciando drag de ventana avanzada:', windowElement.id);
    });
}

function handleAdvancedMouseMove(e) {
    if (!isDragging || !currentModal) return;

    const deltaX = e.clientX - dragStartX;
    const deltaY = e.clientY - dragStartY;

    const newX = modalStartX + deltaX;
    const newY = modalStartY + deltaY;

    // Permitir movimiento fuera de pantalla para multi-monitor
    currentModal.style.setProperty('--window-x', `${newX}px`);
    currentModal.style.setProperty('--window-y', `${newY}px`);
    currentModal.classList.add('positioned-advanced');
}

function handleAdvancedMouseUp(e) {
    if (!isDragging) return;

    isDragging = false;

    if (currentModal) {
        currentModal.classList.remove('dragging-advanced');
        const header = currentModal.querySelector('.section-header');
        if (header) {
            header.style.cursor = 'move';
        }
    }

    currentModal = null;
    console.log('🖱️ Drag de ventana avanzada finalizado');
}

function toggleAdvancedWindowState(windowId, action) {
    const windowInfo = modalWindowsRegistry.get(windowId);
    if (!windowInfo) return;

    const element = windowInfo.element;
    const currentState = windowInfo.state;

    console.log(`🪟 Cambiando estado de ${windowId}: ${currentState} → ${action}`);

    // Guardar estado original si es la primera vez
    if (currentState === 'normal' && !windowInfo.originalPosition) {
        const rect = element.getBoundingClientRect();
        windowInfo.originalPosition = { x: rect.left, y: rect.top };
        windowInfo.originalSize = { width: rect.width, height: rect.height };
    }

    // Limpiar estados anteriores
    element.classList.remove('window-minimized', 'window-maximized', 'window-fullscreen');

    switch (action) {
        case 'minimize':
            if (currentState === 'minimized') {
                // Restaurar al estado anterior
                windowInfo.state = 'normal';
                updateAdvancedWindowButton(windowId, 'minimize', '_');
            } else {
                element.classList.add('window-minimized');
                windowInfo.state = 'minimized';
                updateAdvancedWindowButton(windowId, 'minimize', '🔼');
            }
            break;

        case 'maximize':
            if (currentState === 'maximized') {
                // Restaurar posición original
                windowInfo.state = 'normal';
                element.classList.remove('positioned-advanced');
                element.style.removeProperty('--window-x');
                element.style.removeProperty('--window-y');
                updateAdvancedWindowButton(windowId, 'maximize', '🔲');
            } else {
                element.classList.add('window-maximized');
                windowInfo.state = 'maximized';
                updateAdvancedWindowButton(windowId, 'maximize', '🔽');
            }
            break;

        case 'fullscreen':
            if (currentState === 'fullscreen') {
                // Salir de pantalla completa
                windowInfo.state = 'normal';
                element.classList.remove('positioned-advanced');
                element.style.removeProperty('--window-x');
                element.style.removeProperty('--window-y');
                updateAdvancedWindowButton(windowId, 'fullscreen', '⛶');
            } else {
                element.classList.add('window-fullscreen');
                windowInfo.state = 'fullscreen';
                updateAdvancedWindowButton(windowId, 'fullscreen', '⛴');
            }
            break;
    }

    modalWindowsRegistry.set(windowId, windowInfo);
    console.log(`✅ Estado de ventana ${windowId} actualizado a: ${windowInfo.state}`);
}

function updateAdvancedWindowButton(windowId, buttonType, newIcon) {
    const windowInfo = modalWindowsRegistry.get(windowId);
    if (!windowInfo) return;

    const button = windowInfo.element.querySelector(`.${buttonType}-adv`);
    if (button) {
        button.innerHTML = newIcon;
    }
}

// ============================================================================
// HTTP POLLING PARA BACKEND
// ============================================================================

function startSimplePolling() {
    console.log('📡 Iniciando polling HTTP V3 al backend...');

    fetchDataFromZeroMQ();
    pollingInterval = setInterval(fetchDataFromZeroMQ, 2000);

    addDebugLog('info', 'HTTP polling V3 iniciado - firewall_commands.proto');
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
            updateDashboardFromZeroMQ(data);
            updateConnectionStatus('api', 'connected');

            console.log('📊 Datos backend V3 recibidos:', data.basic_stats);

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

        // 🔥 Actualizar configuración dual JSON
        if (data.firewall_config) {
            firewallConfig = {
                agents: data.firewall_config.agents || [],
                endpoints: data.firewall_config.endpoints || {},
                capabilities: data.firewall_config.capabilities || ['BLOCK_IP', 'RATE_LIMIT_IP', 'LIST_RULES']
            };
            addDebugLog('info', `Config Firewall: ${firewallConfig.agents.length} agentes`);
        }

        if (data.firewall_rules) {
            firewallRules = {
                rules: data.firewall_rules.rules || [],
                rules_count: data.firewall_rules.rules_count || 0,
                default_actions: data.firewall_rules.default_actions || ['BLOCK_IP', 'RATE_LIMIT_IP', 'LIST_RULES']
            };
            addDebugLog('info', `Reglas Firewall: ${firewallRules.rules_count} reglas activas`);
        }

        // Actualizar estadísticas del firewall
        if (data.firewall_stats) {
            updateFirewallStats(data.firewall_stats);
        }

        // Actualizar estados de componentes
        updateComponentIndicators(data);

        // Actualizar estado de componentes ZeroMQ
        if (data.component_status) {
            updateComponentStatus(data.component_status);
        }

        // Actualizar conexiones ZeroMQ
        if (data.zmq_connections) {
            updateZMQStatus(data.zmq_connections);
        }

        // 🔥 Procesar eventos recientes CON COORDENADAS DUALES - SIN LÍMITE
        if (data.recent_events && data.recent_events.length > 0) {
            processEventsFromZeroMQ(data.recent_events);
        }

        // 🔥 Procesar eventos del firewall - SIN LÍMITE
        if (data.firewall_events && data.firewall_events.length > 0) {
            processFirewallEventsFromZeroMQ(data.firewall_events);
        }

        const availableActions = getAvailableFirewallActions();
        addDebugLog('info', `Backend V3: ${data.basic_stats?.total_events || 0} eventos, ${availableActions.length} acciones disponibles`);

    } catch (error) {
        console.error('❌ Error procesando datos backend:', error);
        addDebugLog('error', `Error procesando backend: ${error.message}`);
    }
}

// 🔥 FUNCIÓN PARA OBTENER ACCIONES DISPONIBLES (BACKEND DECIDE)
function getAvailableFirewallActions() {
    // El backend decide qué acciones están disponibles
    if (firewallRules.default_actions && firewallRules.default_actions.length > 0) {
        return firewallRules.default_actions;
    }
    if (firewallConfig.capabilities && firewallConfig.capabilities.length > 0) {
        return firewallConfig.capabilities;
    }
    return ['BLOCK_IP', 'RATE_LIMIT_IP', 'LIST_RULES']; // Fallback mínimo
}

// ============================================================================
// INDICADORES DE COMPONENTES
// ============================================================================

function updateComponentIndicators(data) {
    try {
        const hasEventFlow = data.recent_events && data.recent_events.length > 0;
        componentStates.promiscuous_agent = hasEventFlow;
        updateStatusIndicator('promiscuous-agent-status', hasEventFlow);

        let hasGeoData = false;
        if (data.recent_events && data.recent_events.length > 0) {
            hasGeoData = data.recent_events.some(event =>
                (event.latitude && event.longitude && event.latitude !== 0 && event.longitude !== 0) ||
                (event.dual_geoip && (event.dual_geoip.source?.enriched || event.dual_geoip.target?.enriched))
            );
        }
        componentStates.geoip_enricher = hasGeoData;
        updateStatusIndicator('geoip-enricher-status', hasGeoData);

        const mlConnected = data.zmq_connections &&
                           data.zmq_connections.ml_events &&
                           data.zmq_connections.ml_events.status === 'active';
        componentStates.ml_detector = mlConnected;
        updateStatusIndicator('ml-detector-status', mlConnected);

        const fwConnected = data.zmq_connections &&
                           data.zmq_connections.firewall_commands &&
                           data.zmq_connections.firewall_commands.status === 'active';
        componentStates.firewall_agent = fwConnected;
        updateStatusIndicator('firewall-agent-status', fwConnected);

        updateOverallConnectionStatus();

        console.log('🔄 Estados componentes V3:', componentStates);

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
// EVENTOS DEL FIREWALL - SIN LÍMITE
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

        console.log('📊 Estadísticas firewall V3 actualizadas:', firewallStats);

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
            console.log(`🔥 ${newEvents.length} eventos nuevos del firewall V3 desde backend`);
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
                    <strong>${event.id || event.command_id || 'N/A'}</strong> → ${event.action || 'LIST_RULES'} (${event.ip || event.target_ip || '127.0.0.1'})
                </div>
                <div class="firewall-event-details">
                    Action: ${event.action_code || getFirewallActionCode(event.action || 'LIST_RULES')} | IP: ${event.ip || event.target_ip || '127.0.0.1'} | ${event.source || 'Backend V3'}
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
                    Duration: ${event.execution_time || (Math.floor(Math.random() * 50) + 10)}ms
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

        // 🆕 SIN LÍMITE: No eliminar eventos antiguos
        firewallEventsList.insertBefore(eventElement, firewallEventsList.firstChild);

        // Actualizar contador sin límite
        const events = firewallEventsList.querySelectorAll('.firewall-event');
        updateElement('firewall-events-count', events.length);

        currentFirewallEvents.unshift(event);
        // SIN LÍMITE: No eliminar eventos del array

        console.log('🔥 Evento firewall V3 añadido:', event.id || event.command_id, eventType);

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
                    🧪 Enviar Test Firewall V3
                </button>
            </div>
        `;
        updateElement('firewall-events-count', 0);
        currentFirewallEvents = [];
        addDebugLog('info', 'Lista de eventos del firewall V3 limpiada');
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
// TEST FIREWALL - USANDO FIREWALL_COMMANDS.PROTO
// ============================================================================

async function sendTestFirewallCommand() {
    try {
        console.log('🧪 Enviando comando de test firewall usando firewall_commands.proto...');

        const commandId = `test_${Date.now()}`;
        const targetAgent = getAvailableFirewallAgents()[0] || 'simple_firewall_agent_001';

        // 🔥 Crear FirewallCommand usando estructura proto correcta
        const firewallCommand = {
            command_id: commandId,
            action: CommandAction.LIST_RULES, // Usar enum correcto
            target_ip: '127.0.0.1',
            target_port: 0,
            duration_seconds: 0,
            reason: 'Dashboard test V3 - listing current rules',
            priority: CommandPriority.LOW,
            dry_run: true,
            rate_limit_rule: '',
            extra_params: {
                test_mode: 'true',
                source: 'dashboard_test'
            }
        };

        addFirewallEventToList({
            id: commandId,
            type: 'command',
            action: 'LIST_RULES',
            target_ip: '127.0.0.1',
            action_code: CommandAction.LIST_RULES,
            source: 'Dashboard Test V3 (Proto)',
            timestamp: Date.now() / 1000
        });

        showToast('Enviando test V3 al firewall (proto)...', 'info');

        // 🔥 ENVÍO CON ESTRUCTURA FIREWALL_COMMANDS.PROTO
        const response = await fetch('/api/test-firewall', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                firewall_command: firewallCommand,
                target_node_id: targetAgent,
                batch_id: `test_batch_${Date.now()}`,
                generated_by: 'dashboard',
                dry_run_all: true
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
                    agent: result.node_id || targetAgent,
                    result: result.message || 'LIST_RULES executed successfully (dry_run=true)',
                    node_id: result.node_id || targetAgent,
                    execution_time: result.execution_time || 0.05,
                    timestamp: Date.now() / 1000
                });
            }, 300);

            showToast('✅ Test V3 proto enviado correctamente al firewall', 'success');
            console.log('✅ Test firewall V3 proto exitoso:', result);
            addDebugLog('info', 'Test firewall V3 proto enviado correctamente');

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
                    error: result.message || 'Error en test proto',
                    timestamp: Date.now() / 1000
                });
            }, 300);

            firewallStats.errors++;
            updateElement('firewall-errors', firewallStats.errors);

            showToast('❌ Error en test V3 proto: ' + result.message, 'error');
            addDebugLog('error', `Error test firewall V3 proto: ${result.message}`);
        }

    } catch (error) {
        console.error('❌ Error en sendTestFirewallCommand proto:', error);

        addFirewallEventToList({
            id: `error_${Date.now()}`,
            type: 'error',
            success: false,
            error: `Error de comunicación proto: ${error.message}`,
            timestamp: Date.now() / 1000
        });

        firewallStats.errors++;
        updateElement('firewall-errors', firewallStats.errors);

        showToast('❌ Error comunicando con firewall proto: ' + error.message, 'error');
        addDebugLog('error', `Error comunicación firewall proto: ${error.message}`);
    }
}

// Alias para compatibilidad
async function sendTestFirewallEvent() {
    return await sendTestFirewallCommand();
}

// 🔥 FUNCIÓN PARA OBTENER AGENTES DISPONIBLES
function getAvailableFirewallAgents() {
    if (firewallConfig.agents && firewallConfig.agents.length > 0) {
        return firewallConfig.agents.map(agent => agent.node_id || agent.name);
    }
    return ['simple_firewall_agent_001']; // Fallback
}

// ============================================================================
// MANEJO DE EVENTOS DESDE BACKEND - SIN LÍMITE + COORDENADAS DUALES
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
            console.log(`📨 ${newEvents.length} eventos nuevos V3 desde backend`);
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

        // 🔥 USAR COORDENADAS DUALES PARA EL MAPA CON ANIMACIONES MISIL
        addEventToMapWithMissileAnimation(event);

        addEventToEventsList(event);

        if (event.risk_score > 0.8) {
            showThreatIndicator(event);
        }

        console.log('🚨 Evento backend V3 procesado:', event.source_ip, '→', event.target_ip);

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

        // 🆕 Información más completa del evento V3
        const dualGeoInfo = event.dual_geoip ?
            `<small style="color: #888;">${event.dual_geoip.distance_km}km - ${event.dual_geoip.same_country ? 'Local' : 'Internacional'}</small>` : '';

        eventElement.innerHTML = `
            <div class="event-header">
                <span class="event-time">${eventTime.toLocaleTimeString()}</span>
                <span class="event-risk ${riskLevel}">${(event.risk_score * 100).toFixed(0)}%</span>
            </div>
            <div class="event-details">
                <div><span class="event-source">${event.source_ip}</span> → <span class="event-target">${event.target_ip}</span></div>
                <div class="event-type">${event.type || 'Backend Event V3'} ${dualGeoInfo}</div>
            </div>
        `;

        // 🆕 SIN LÍMITE: No eliminar eventos antiguos
        eventsList.insertBefore(eventElement, eventsList.firstChild);

        // Actualizar contador sin límite
        const events = eventsList.querySelectorAll('.event-item');
        updateElement('live-events-count', events.length);

        currentEvents.unshift(event);
        // SIN LÍMITE: No eliminar eventos del array

    } catch (error) {
        console.error('❌ Error añadiendo evento a lista:', error);
    }
}

// 🚀 NUEVA FUNCIÓN PARA ANIMACIONES TIPO MISIL
function addEventToMapWithMissileAnimation(event) {
    if (!map) return;

    try {
        const riskLevel = event.risk_score > 0.8 ? 'high' :
                         event.risk_score > 0.5 ? 'medium' : 'low';

        const colors = {
            high: '#ff4444',
            medium: '#ffaa00',
            low: '#00ff00'
        };

        let markersAdded = [];

        // 🔥 COORDENADAS DUALES: Manejar dual_geoip si existe
        if (event.dual_geoip) {
            console.log('🗺️ Procesando evento con dual_geoip y animación misil:', event.dual_geoip);

            // Marcador SOURCE (víctima/origen) - AZUL con click handler
            if (event.dual_geoip.source && event.dual_geoip.source.enriched) {
                const sourceMarker = L.circleMarker([event.dual_geoip.source.latitude, event.dual_geoip.source.longitude], {
                    radius: 10,
                    fillColor: '#0066CC',
                    color: '#0066CC',
                    weight: 2,
                    opacity: 0.8,
                    fillOpacity: 0.6,
                    className: 'source-marker clickable-marker'
                }).bindPopup(`
                    <div style="color: #000; font-family: 'Consolas', monospace; font-size: 11px;">
                        <b>🏠 Víctima/Origen</b><br>
                        <strong>IP:</strong> ${event.source_ip}<br>
                        <strong>Ubicación:</strong> ${event.dual_geoip.source.city}, ${event.dual_geoip.source.country}<br>
                        <strong>Riesgo:</strong> <span style="color: ${colors[riskLevel]};">${(event.risk_score * 100).toFixed(0)}%</span><br>
                        <strong>Timestamp:</strong> ${new Date(event.timestamp * 1000).toLocaleString()}<br>
                        <button onclick="showSourceIPDetail('${event.source_ip}', ${JSON.stringify(event).replace(/"/g, '&quot;')})" style="margin-top: 5px; background: #0066CC; color: white; border: none; padding: 4px 8px; border-radius: 3px; cursor: pointer;">Ver Detalles</button>
                    </div>
                `).addTo(map);

                sourceMarker._isEventMarker = true;
                sourceMarker._eventData = event;
                sourceMarker._markerType = 'source';
                markersAdded.push(sourceMarker);
            }

            // 🎯 Marcador TARGET (atacante/destino) - ROJO con click handler
            if (event.dual_geoip.target && event.dual_geoip.target.enriched) {
                const targetMarker = L.circleMarker([event.dual_geoip.target.latitude, event.dual_geoip.target.longitude], {
                    radius: 10,
                    fillColor: '#CC0000',
                    color: '#CC0000',
                    weight: 2,
                    opacity: 0.8,
                    fillOpacity: 0.6,
                    className: 'target-marker clickable-marker'
                }).bindPopup(`
                    <div style="color: #000; font-family: 'Consolas', monospace; font-size: 11px;">
                        <b>🎯 Atacante/Destino</b><br>
                        <strong>IP:</strong> ${event.target_ip}<br>
                        <strong>Ubicación:</strong> ${event.dual_geoip.target.city}, ${event.dual_geoip.target.country}<br>
                        <strong>Riesgo:</strong> <span style="color: ${colors[riskLevel]};">${(event.risk_score * 100).toFixed(0)}%</span><br>
                        <strong>Timestamp:</strong> ${new Date(event.timestamp * 1000).toLocaleString()}<br>
                        <button onclick="showTargetIPDetail('${event.target_ip}', ${JSON.stringify(event).replace(/"/g, '&quot;')})" style="margin-top: 5px; background: #CC0000; color: white; border: none; padding: 4px 8px; border-radius: 3px; cursor: pointer;">🎯 Acciones Firewall</button>
                    </div>
                `).addTo(map);

                targetMarker._isEventMarker = true;
                targetMarker._eventData = event;
                targetMarker._markerType = 'target';
                markersAdded.push(targetMarker);
            }

            // 🚀 LÍNEA CURVA ANIMADA TIPO MISIL
            if (markersAdded.length === 2 && event.dual_geoip.source && event.dual_geoip.target) {
                createMissileTrajectoryAnimation(
                    [event.dual_geoip.source.latitude, event.dual_geoip.source.longitude],
                    [event.dual_geoip.target.latitude, event.dual_geoip.target.longitude],
                    event
                );
            }

        } else if (event.latitude && event.longitude && event.latitude !== 0 && event.longitude !== 0) {
            // 🔥 FALLBACK: Coordenadas legacy (solo source_ip)
            const legacyMarker = L.circleMarker([event.latitude, event.longitude], {
                radius: 8,
                fillColor: colors[riskLevel],
                color: colors[riskLevel],
                weight: 2,
                opacity: 0.8,
                fillOpacity: 0.6,
                className: 'legacy-marker clickable-marker'
            }).bindPopup(`
                <div style="color: #000; font-family: 'Consolas', monospace; font-size: 11px;">
                    <b>🚨 Evento Legacy</b><br>
                    <strong>Origen:</strong> ${event.source_ip}<br>
                    <strong>Destino:</strong> ${event.target_ip}<br>
                    <strong>Riesgo:</strong> <span style="color: ${colors[riskLevel]};">${(event.risk_score * 100).toFixed(0)}%</span><br>
                    <strong>Ubicación:</strong> ${event.location || 'No disponible'}<br>
                    <strong>Timestamp:</strong> ${new Date(event.timestamp * 1000).toLocaleString()}<br>
                    <button onclick="showEventDetail(${JSON.stringify(event).replace(/"/g, '&quot;')})" style="margin-top: 5px; background: ${colors[riskLevel]}; color: white; border: none; padding: 4px 8px; border-radius: 3px; cursor: pointer;">Ver Detalles</button>
                </div>
            `).addTo(map);

            legacyMarker._isEventMarker = true;
            legacyMarker._eventData = event;
            legacyMarker._markerType = 'legacy';
            markersAdded.push(legacyMarker);
        }

        // Agregar a la lista global y programar eliminación
        markersAdded.forEach(marker => {
            markers.push(marker);
            setTimeout(() => {
                if (map.hasLayer(marker)) {
                    map.removeLayer(marker);
                    markers = markers.filter(m => m !== marker);
                }
            }, 5 * 60 * 1000);
        });

        if (markersAdded.length > 0) {
            console.log(`📍 ${markersAdded.length} marcadores V3 con animación añadidos para evento:`, event.source_ip, '→', event.target_ip);
        }

    } catch (error) {
        console.error('❌ Error añadiendo marcadores con animación misil:', error);
    }
}

// 🚀 FUNCIÓN PARA CREAR ANIMACIÓN TIPO MISIL
function createMissileTrajectoryAnimation(sourceCoords, targetCoords, event) {
    try {
        // Calcular punto de control para curva (más alto para efecto misil)
        const midLat = (sourceCoords[0] + targetCoords[0]) / 2;
        const midLng = (sourceCoords[1] + targetCoords[1]) / 2;

        // Calcular altura de la curva basada en distancia
        const distance = Math.sqrt(Math.pow(targetCoords[0] - sourceCoords[0], 2) + Math.pow(targetCoords[1] - sourceCoords[1], 2));
        const curveHeight = distance * 0.3; // 30% de la distancia como altura

        // Punto de control para la curva (más alto)
        const controlPoint = [midLat + curveHeight, midLng];

        // Crear múltiples puntos para la curva Bézier
        const curvePoints = [];
        for (let t = 0; t <= 1; t += 0.05) {
            const lat = Math.pow(1-t, 2) * sourceCoords[0] + 2*(1-t)*t * controlPoint[0] + Math.pow(t, 2) * targetCoords[0];
            const lng = Math.pow(1-t, 2) * sourceCoords[1] + 2*(1-t)*t * controlPoint[1] + Math.pow(t, 2) * targetCoords[1];
            curvePoints.push([lat, lng]);
        }

        // Crear la línea curva
        const trajectoryLine = L.polyline(curvePoints, {
            color: event.dual_geoip?.same_country ? '#FFA500' : '#FF0000',
            weight: 3,
            opacity: 0.8,
            dashArray: '10, 5',
            className: 'missile-trajectory'
        }).bindPopup(`
            <div style="color: #000; font-family: 'Consolas', monospace; font-size: 11px;">
                <b>🚀 Trayectoria de Ataque</b><br>
                <strong>Origen:</strong> ${event.source_ip}<br>
                <strong>Destino:</strong> ${event.target_ip}<br>
                <strong>Distancia:</strong> ${event.dual_geoip?.distance_km || 'N/A'}km<br>
                <strong>Mismo País:</strong> ${event.dual_geoip?.same_country ? 'Sí' : 'No'}<br>
                <strong>Riesgo:</strong> ${(event.risk_score * 100).toFixed(0)}%
            </div>
        `).addTo(map);

        trajectoryLine._isEventMarker = true;
        trajectoryLine._trajectoryType = 'missile';
        connectionLines.push(trajectoryLine);

        // 🚀 Añadir animación de flujo
        setTimeout(() => {
            if (map.hasLayer(trajectoryLine)) {
                trajectoryLine.setStyle({
                    className: 'missile-trajectory missile-flow-animation'
                });
            }
        }, 100);

        // Auto-remover la línea después de 5 minutos
        setTimeout(() => {
            if (map.hasLayer(trajectoryLine)) {
                map.removeLayer(trajectoryLine);
                connectionLines = connectionLines.filter(l => l !== trajectoryLine);
            }
        }, 5 * 60 * 1000);

        console.log('🚀 Trayectoria misil creada:', event.source_ip, '→', event.target_ip);

    } catch (error) {
        console.error('❌ Error creando animación misil:', error);
    }
}

// ============================================================================
// 🎯 MODAL ESPECÍFICO PARA TARGET_IP
// ============================================================================

async function showTargetIPDetail(targetIP, eventData) {
    try {
        console.log('🎯 Mostrando detalle específico del target_ip:', targetIP, eventData);

        // Parsear eventData si viene como string
        const event = typeof eventData === 'string' ? JSON.parse(eventData.replace(/&quot;/g, '"')) : eventData;

        // Obtener información específica del target_ip
        const targetGeoInfo = event.dual_geoip?.target || null;

        // Obtener información del firewall responsable
        const firewallInfo = await getResponsibleFirewallInfoForTarget(targetIP, event);

        // Generar botón Street View solo para target_ip
        const targetStreetViewButton = targetGeoInfo && targetGeoInfo.enriched ?
            `<div style="margin-top: 10px;">
                <a href="https://www.google.com/maps/@${targetGeoInfo.latitude},${targetGeoInfo.longitude},3a,75y,0h,90t/data=!3m7!1e1!3m5!1s${encodeURIComponent(targetIP)}!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com!7i16384!8i8192" target="_blank" class="google-maps-btn target-streetview-btn">
                    <i class="fas fa-map-marked-alt"></i> 🎯 Street View del Atacante
                </a>
            </div>` : '';

        const content = `
            <div style="font-family: 'Consolas', monospace; max-height: 70vh; overflow-y: auto;">
                <!-- Header específico del target_ip -->
                <div style="margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #CC0000;">
                    <h3 style="color: #CC0000; margin: 0;">🎯 Información del Atacante</h3>
                    <div style="font-size: 14px; color: #CC0000; margin-top: 5px; font-weight: bold;">
                        IP: ${targetIP}
                    </div>
                    <div style="font-size: 11px; color: #888; margin-top: 5px;">
                        Evento ID: ${event.id || 'N/A'} | ${new Date(event.timestamp * 1000).toLocaleString()}
                    </div>
                    ${targetStreetViewButton}
                </div>

                <!-- Información geográfica del target_ip -->
                ${targetGeoInfo && targetGeoInfo.enriched ? `
                    <div style="margin-bottom: 20px; padding: 15px; background: rgba(204, 0, 0, 0.1); border-left: 4px solid #CC0000; border-radius: 4px;">
                        <div style="color: #CC0000; font-weight: bold; margin-bottom: 8px;">
                            🌍 Ubicación Geográfica
                        </div>
                        <div style="font-size: 11px; line-height: 1.4;">
                            <strong>Ciudad:</strong> ${targetGeoInfo.city}<br>
                            <strong>País:</strong> ${targetGeoInfo.country}<br>
                            <strong>Coordenadas:</strong> ${targetGeoInfo.latitude.toFixed(4)}, ${targetGeoInfo.longitude.toFixed(4)}<br>
                            ${targetGeoInfo.region ? `<strong>Región:</strong> ${targetGeoInfo.region}<br>` : ''}
                            ${targetGeoInfo.timezone ? `<strong>Zona Horaria:</strong> ${targetGeoInfo.timezone}<br>` : ''}
                            ${targetGeoInfo.isp ? `<strong>ISP:</strong> ${targetGeoInfo.isp}<br>` : ''}
                            ${targetGeoInfo.organization ? `<strong>Organización:</strong> ${targetGeoInfo.organization}<br>` : ''}
                        </div>
                    </div>
                ` : ''}

                <!-- Información del ataque -->
                <div style="margin-bottom: 20px; padding: 15px; background: rgba(255, 68, 68, 0.1); border-left: 4px solid #ff4444; border-radius: 4px;">
                    <div style="color: #ff4444; font-weight: bold; margin-bottom: 8px;">
                        ⚠️ Detalles del Ataque
                    </div>
                    <div style="font-size: 11px; line-height: 1.4;">
                        <strong>IP Víctima:</strong> <span style="color: #0066CC;">${event.source_ip}</span><br>
                        <strong>IP Atacante:</strong> <span style="color: #CC0000;">${targetIP}</span><br>
                        <strong>Score de Riesgo:</strong> <span style="color: ${event.risk_score > 0.8 ? '#ff4444' : event.risk_score > 0.5 ? '#ffaa00' : '#00ff00'}; font-weight: bold;">${(event.risk_score * 100).toFixed(1)}%</span><br>
                        <strong>Tipo de Evento:</strong> ${event.type || 'network_traffic'}<br>
                        ${event.dual_geoip ? `<strong>Distancia:</strong> ${event.dual_geoip.distance_km}km<br><strong>Mismo País:</strong> ${event.dual_geoip.same_country ? 'Sí' : 'No'}<br>` : ''}
                        <strong>Timestamp:</strong> ${new Date(event.timestamp * 1000).toLocaleString()}
                    </div>
                </div>

                <!-- Información del firewall responsable -->
                <div style="margin-bottom: 20px; padding: 15px; background: rgba(0, 255, 136, 0.1); border-left: 4px solid #00ff88; border-radius: 4px;">
                    <div style="color: #00ff88; font-weight: bold; margin-bottom: 8px;">
                        🔥 Firewall Agent Responsable
                    </div>
                    <div style="font-size: 11px; line-height: 1.4;">
                        <strong>Node ID:</strong> ${firewallInfo.node_id}<br>
                        <strong>Estado:</strong> <span style="color: ${firewallInfo.status === 'active' ? '#00ff88' : '#ffaa00'};">${firewallInfo.status.toUpperCase()}</span><br>
                        <strong>Reglas Activas:</strong> ${firewallInfo.active_rules}<br>
                        <strong>Endpoint:</strong> ${firewallInfo.endpoint}
                    </div>
                </div>

                <!-- 🎯 ACCIONES ESPECÍFICAS PARA TARGET_IP -->
                <div style="margin-bottom: 20px; padding: 15px; background: rgba(204, 0, 0, 0.1); border-left: 4px solid #CC0000; border-radius: 4px;">
                    <div style="color: #CC0000; font-weight: bold; margin-bottom: 12px;">
                        ⚡ Acciones Disponibles para ${targetIP}
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                        ${generateTargetIPFirewallActions(targetIP, firewallInfo, event)}
                    </div>
                    <div style="margin-top: 12px; font-size: 10px; color: #888; font-style: italic;">
                        💡 Las acciones se aplicarán específicamente a la IP atacante: <strong style="color: #CC0000;">${targetIP}</strong>
                    </div>
                </div>

                <!-- Datos técnicos del target_ip -->
                <div>
                    <div style="background: rgba(102, 102, 102, 0.2); padding: 10px; cursor: pointer; border-radius: 4px; margin-bottom: 10px;" onclick="toggleTargetIPData()">
                        <span style="color: #666; font-weight: bold;">
                            📊 Datos Técnicos del Target_IP
                        </span>
                        <i class="fas fa-chevron-down" id="target-ip-data-toggle" style="color: #666; float: right; transition: transform 0.3s ease;"></i>
                    </div>
                    <div id="target-ip-data-content" style="max-height: 0; overflow: hidden; transition: all 0.3s ease;">
                        <div style="padding: 15px; background: rgba(0, 0, 0, 0.6); border: 1px solid #333; border-radius: 4px;">
                            <pre style="font-size: 9px; color: #666; margin: 0; white-space: pre-wrap; max-height: 200px; overflow-y: auto;">${JSON.stringify({
                                target_ip: targetIP,
                                geographic_info: targetGeoInfo,
                                event_context: {
                                    source_ip: event.source_ip,
                                    risk_score: event.risk_score,
                                    timestamp: event.timestamp,
                                    type: event.type
                                },
                                dual_geoip_summary: event.dual_geoip
                            }, null, 2)}</pre>
                        </div>
                    </div>
                </div>
            </div>
        `;

        showModal(`🎯 Atacante: ${targetIP}`, content);

    } catch (error) {
        console.error('❌ Error mostrando detalle del target_ip:', error);
        showToast('Error mostrando detalles del atacante', 'error');
    }
}

function generateTargetIPFirewallActions(targetIP, firewallInfo, eventData) {
    const availableActions = getAvailableFirewallActions();
    let buttons = '';

    // 🎯 Acciones específicas para target_ip (IP atacante)
    const targetActions = availableActions.filter(action =>
        ['BLOCK_IP', 'RATE_LIMIT_IP', 'ALLOW_IP_TEMP', 'LIST_RULES'].includes(action)
    );

    targetActions.forEach(action => {
        buttons += generateTargetIPActionButton(action, targetIP, firewallInfo, eventData);
    });

    // Fallback si no hay acciones
    if (!buttons) {
        buttons = `
            <button onclick="executeFirewallActionForTargetIP('BLOCK_IP', '${targetIP}', '${firewallInfo.node_id}', '${eventData.id}')"
                    class="firewall-action-btn block-target-btn">
                🚫 Bloquear ${targetIP}
            </button>
            <button onclick="executeFirewallActionForTargetIP('LIST_RULES', '${targetIP}', '${firewallInfo.node_id}', '${eventData.id}')"
                    class="firewall-action-btn list-rules-btn">
                📋 Listar Reglas
            </button>
        `;
    }

    return buttons;
}

function generateTargetIPActionButton(action, targetIP, firewallInfo, eventData) {
    const actionConfig = {
        'BLOCK_IP': { color: '#ff4444', icon: '🚫', label: 'Bloquear IP' },
        'RATE_LIMIT_IP': { color: '#ffaa00', icon: '⏱️', label: 'Limitar Tráfico' },
        'ALLOW_IP_TEMP': { color: '#00ff88', icon: '✅', label: 'Permitir Temporal' },
        'LIST_RULES': { color: '#0066CC', icon: '📋', label: 'Listar Reglas' }
    };

    const config = actionConfig[action] || { color: '#666', icon: '⚙️', label: action };

    return `
        <button onclick="executeFirewallActionForTargetIP('${action}', '${targetIP}', '${firewallInfo.node_id}', '${eventData.id}')"
                class="firewall-action-btn target-action-btn"
                style="background: rgba(${hexToRgb(config.color)}, 0.2); border: 1px solid ${config.color}; color: ${config.color}; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-size: 10px; width: 100%; transition: all 0.3s ease;"
                onmouseover="this.style.background='rgba(${hexToRgb(config.color)}, 0.3)'"
                onmouseout="this.style.background='rgba(${hexToRgb(config.color)}, 0.2)'">
            ${config.icon} ${config.label}
        </button>
    `;
}

async function executeFirewallActionForTargetIP(action, targetIP, firewallNodeId, eventId) {
    try {
        console.log(`🎯 Ejecutando acción específica ${action} para target_ip ${targetIP}`);

        showToast(`Ejecutando ${action} en ${targetIP}...`, 'info');

        const commandId = `target_${Date.now()}`;

        // 🔥 Crear FirewallCommand específico para target_ip
        const firewallCommand = {
            command_id: commandId,
            action: CommandAction[action] || CommandAction.BLOCK_IP,
            target_ip: targetIP,
            target_port: 0,
            duration_seconds: getDurationForAction(action),
            reason: `Target IP action: ${action} applied to attacking IP ${targetIP}`,
            priority: getPriorityForAction(action),
            dry_run: false,
            rate_limit_rule: action === 'RATE_LIMIT_IP' ? '10/min' : '',
            extra_params: {
                source: 'dashboard_target_action',
                event_id: eventId,
                target_type: 'attacking_ip'
            }
        };

        // Añadir evento a la lista
        addFirewallEventToList({
            id: commandId,
            type: 'command',
            action: action,
            target_ip: targetIP,
            action_code: CommandAction[action],
            source: 'Dashboard Target Action',
            timestamp: Date.now() / 1000
        });

        // Enviar al backend
        const response = await fetch('/api/execute-firewall-action', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                firewall_command: firewallCommand,
                target_node_id: firewallNodeId,
                batch_id: `event_action_${Date.now()}`,
                generated_by: 'dashboard_event_response',
                dry_run_all: false
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
                    agent: result.node_id || firewallNodeId,
                    result: result.message || `${action} ejecutada exitosamente desde evento`,
                    execution_time: result.execution_time || 0.1,
                    timestamp: Date.now() / 1000
                });
            }, 300);

            showToast(`✅ ${action} ejecutada desde evento`, 'success');
            addDebugLog('info', `Acción evento ${action} ejecutada para IP ${targetIp}`);

            firewallStats.commandsSent++;
            firewallStats.responsesOk++;
            updateElement('firewall-commands-sent', firewallStats.commandsSent);
            updateElement('firewall-responses-ok', firewallStats.responsesOk);

            // Cerrar modal después de acción exitosa
            setTimeout(() => {
                closeModal();
            }, 2000);

        } else {
            setTimeout(() => {
                addFirewallEventToList({
                    id: commandId,
                    type: 'error',
                    success: false,
                    error: result.message || `Error ejecutando ${action} desde evento`,
                    timestamp: Date.now() / 1000
                });
            }, 300);

            showToast(`❌ Error en ${action} desde evento: ${result.message}`, 'error');
            firewallStats.errors++;
            updateElement('firewall-errors', firewallStats.errors);
        }

    } catch (error) {
        console.error(`❌ Error ejecutando acción evento ${action}:`, error);

        addFirewallEventToList({
            id: `error_event_${Date.now()}`,
            type: 'error',
            success: false,
            error: `Error comunicación evento: ${error.message}`,
            timestamp: Date.now() / 1000
        });

        showToast(`❌ Error comunicando con firewall desde evento: ${error.message}`, 'error');
        firewallStats.errors++;
        updateElement('firewall-errors', firewallStats.errors);
    }
}

// 🔥 FUNCIONES AUXILIARES PARA FIREWALL_COMMANDS.PROTO
function getFirewallActionCode(action) {
    return CommandAction[action] || CommandAction.LIST_RULES;
}

function getDurationForAction(action) {
    const durations = {
        'BLOCK_IP': 3600,        // 1 hora
        'RATE_LIMIT_IP': 1800,   // 30 minutos
        'ALLOW_IP_TEMP': 600,    // 10 minutos
        'LIST_RULES': 0,         // No aplica
        'FLUSH_RULES': 0,        // No aplica
        'BACKUP_RULES': 0        // No aplica
    };
    return durations[action] || 0;
}

function getPriorityForAction(action) {
    const priorities = {
        'BLOCK_IP': CommandPriority.HIGH,
        'RATE_LIMIT_IP': CommandPriority.MEDIUM,
        'ALLOW_IP_TEMP': CommandPriority.LOW,
        'LIST_RULES': CommandPriority.LOW,
        'FLUSH_RULES': CommandPriority.CRITICAL,
        'BACKUP_RULES': CommandPriority.MEDIUM
    };
    return priorities[action] || CommandPriority.LOW;
}

function hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ?
        `${parseInt(result[1], 16)}, ${parseInt(result[2], 16)}, ${parseInt(result[3], 16)}` :
        '128, 128, 128';
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
            <h4 style="color: #00ff88; margin-bottom: 15px;">🚨 Evento de Seguridad V3</h4>

            <div style="margin-bottom: 10px;">
                <strong>Timestamp:</strong> ${new Date(event.timestamp * 1000).toLocaleString()}
            </div>
            <div style="margin-bottom: 10px;">
                <strong>IP Origen:</strong> <span style="color: #0066CC;">${event.source_ip}</span>
            </div>
            <div style="margin-bottom: 10px;">
                <strong>IP Destino:</strong> <span style="color: #CC0000;">${event.target_ip}</span>
            </div>
            <div style="margin-bottom: 10px;">
                <strong>Score de Riesgo:</strong> <span style="color: ${event.risk_score > 0.8 ? '#ff4444' : event.risk_score > 0.5 ? '#ffaa00' : '#00ff00'};">${(event.risk_score * 100).toFixed(1)}%</span>
            </div>

            ${event.type ? `<div style="margin-bottom: 10px;"><strong>Tipo:</strong> ${event.type}</div>` : ''}

            <div style="margin-top: 15px; padding: 10px; background: rgba(0,0,0,0.6); border-radius: 4px;">
                <strong>Datos del Evento V3:</strong><br>
                <pre style="font-size: 9px; color: #666; margin-top: 5px;">${JSON.stringify(event, null, 2)}</pre>
            </div>

            <!-- Botones de acción básicos V3 -->
            <div style="margin-top: 15px; display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                <button onclick="executeEventFirewallActionV3('BLOCK_IP', '${event.target_ip}', 'simple_firewall_agent_001', '${event.id}')"
                        class="firewall-action-btn block-btn">
                    🚫 Bloquear Atacante
                </button>
                <button onclick="executeEventFirewallActionV3('LIST_RULES', 'all', 'simple_firewall_agent_001', '${event.id}')"
                        class="firewall-action-btn list-rules-btn">
                    📋 Listar Reglas
                </button>
            </div>
        </div>
    `;

    showModal('Detalle del Evento V3', content);
}

// 🆕 FUNCIÓN PARA MOSTRAR DETALLE DEL SOURCE_IP
async function showSourceIPDetail(sourceIP, eventData) {
    try {
        console.log('🏠 Mostrando detalle específico del source_ip:', sourceIP, eventData);

        const event = typeof eventData === 'string' ? JSON.parse(eventData.replace(/&quot;/g, '"')) : eventData;
        const sourceGeoInfo = event.dual_geoip?.source || null;

        const sourceStreetViewButton = sourceGeoInfo && sourceGeoInfo.enriched ?
            `<div style="margin-top: 10px;">
                <a href="https://www.google.com/maps/@${sourceGeoInfo.latitude},${sourceGeoInfo.longitude},3a,75y,0h,90t/data=!3m7!1e1!3m5!1s${encodeURIComponent(sourceIP)}!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com!7i16384!8i8192" target="_blank" class="google-maps-btn source-streetview-btn">
                    <i class="fas fa-map-marked-alt"></i> 🏠 Street View de la Víctima
                </a>
            </div>` : '';

        const content = `
            <div style="font-family: 'Consolas', monospace; max-height: 70vh; overflow-y: auto;">
                <div style="margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #0066CC;">
                    <h3 style="color: #0066CC; margin: 0;">🏠 Información de la Víctima</h3>
                    <div style="font-size: 14px; color: #0066CC; margin-top: 5px; font-weight: bold;">
                        IP: ${sourceIP}
                    </div>
                    <div style="font-size: 11px; color: #888; margin-top: 5px;">
                        Evento ID: ${event.id || 'N/A'} | ${new Date(event.timestamp * 1000).toLocaleString()}
                    </div>
                    ${sourceStreetViewButton}
                </div>

                ${sourceGeoInfo && sourceGeoInfo.enriched ? `
                    <div style="margin-bottom: 20px; padding: 15px; background: rgba(0, 102, 204, 0.1); border-left: 4px solid #0066CC; border-radius: 4px;">
                        <div style="color: #0066CC; font-weight: bold; margin-bottom: 8px;">
                            🌍 Ubicación Geográfica de la Víctima
                        </div>
                        <div style="font-size: 11px; line-height: 1.4;">
                            <strong>Ciudad:</strong> ${sourceGeoInfo.city}<br>
                            <strong>País:</strong> ${sourceGeoInfo.country}<br>
                            <strong>Coordenadas:</strong> ${sourceGeoInfo.latitude.toFixed(4)}, ${sourceGeoInfo.longitude.toFixed(4)}<br>
                            ${sourceGeoInfo.region ? `<strong>Región:</strong> ${sourceGeoInfo.region}<br>` : ''}
                            ${sourceGeoInfo.timezone ? `<strong>Zona Horaria:</strong> ${sourceGeoInfo.timezone}<br>` : ''}
                            ${sourceGeoInfo.isp ? `<strong>ISP:</strong> ${sourceGeoInfo.isp}<br>` : ''}
                        </div>
                    </div>
                ` : ''}

                <div style="margin-bottom: 20px; padding: 15px; background: rgba(0, 102, 204, 0.1); border-left: 4px solid #0066CC; border-radius: 4px;">
                    <div style="color: #0066CC; font-weight: bold; margin-bottom: 8px;">
                        🏠 Información del Ataque Recibido
                    </div>
                    <div style="font-size: 11px; line-height: 1.4;">
                        <strong>IP Víctima:</strong> <span style="color: #0066CC;">${sourceIP}</span><br>
                        <strong>IP Atacante:</strong> <span style="color: #CC0000;">${event.target_ip}</span><br>
                        <strong>Score de Riesgo:</strong> <span style="color: ${event.risk_score > 0.8 ? '#ff4444' : event.risk_score > 0.5 ? '#ffaa00' : '#00ff00'}; font-weight: bold;">${(event.risk_score * 100).toFixed(1)}%</span><br>
                        <strong>Tipo de Ataque:</strong> ${event.type || 'network_traffic'}<br>
                        ${event.dual_geoip ? `<strong>Distancia del Atacante:</strong> ${event.dual_geoip.distance_km}km<br>` : ''}
                        <strong>Timestamp:</strong> ${new Date(event.timestamp * 1000).toLocaleString()}
                    </div>
                </div>

                <div style="padding: 15px; background: rgba(0, 0, 0, 0.6); border: 1px solid #333; border-radius: 4px;">
                    <strong>Datos de la Víctima:</strong><br>
                    <pre style="font-size: 9px; color: #666; margin-top: 5px;">${JSON.stringify({
                        source_ip: sourceIP,
                        geographic_info: sourceGeoInfo,
                        attack_context: {
                            attacker_ip: event.target_ip,
                            risk_score: event.risk_score,
                            timestamp: event.timestamp,
                            type: event.type
                        }
                    }, null, 2)}</pre>
                </div>
            </div>
        `;

        showModal(`🏠 Víctima: ${sourceIP}`, content);

    } catch (error) {
        console.error('❌ Error mostrando detalle del source_ip:', error);
        showToast('Error mostrando detalles de la víctima', 'error');
    }
}

// ============================================================================
// RESTO DE FUNCIONES (ADAPTADAS PARA V3)
// ============================================================================

function initializeMap() {
    try {
        console.log('🗺️ Inicializando mapa Leaflet V3 con animaciones misil...');

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
            console.log('✅ Mapa V3 cargado');
            addInitialMarkers();
            addDebugLog('info', 'Mapa Leaflet V3 cargado con animaciones misil');
        });

        setTimeout(() => {
            if (map) {
                map.invalidateSize();
            }
        }, 500);

        console.log('✅ Mapa V3 inicializado');
        addDebugLog('info', 'Mapa V3 inicializado correctamente');

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
            .bindPopup('<b>🖥️ Dashboard Principal V3</b><br>Madrid, España<br>Backend Dashboard')
            .addTo(map);

        const barcelonaMarker = L.marker([41.3851, 2.1734])
            .bindPopup('<b>🔄 Nodo Remoto V3</b><br>Barcelona, España<br>ML Detector Node')
            .addTo(map);

        const sevillaMarker = L.marker([37.3886, -5.9823])
            .bindPopup('<b>🔥 Firewall Agent V3</b><br>Sevilla, España<br>Simple Firewall Agent')
            .addTo(map);

        markers.push(madridMarker, barcelonaMarker, sevillaMarker);

        console.log('✅ Marcadores iniciales V3 añadidos');

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
                <div style="font-size: 18px; margin-bottom: 10px;">❌ Error cargando mapa V3</div>
                <div style="font-size: 12px; opacity: 0.8;">${error.message}</div>
                <button onclick="initializeMap()" style="margin-top: 20px; background: rgba(0, 255, 0, 0.2); border: 1px solid #00ff00; color: #00ff00; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-family: inherit;">🔄 Reintentar</button>
            </div>
        `;
    }
}

// ============================================================================
// FUNCIONES AUXILIARES
// ============================================================================

function clearAllMarkers() {
    if (!map) return;

    try {
        markers.forEach(marker => {
            if (marker._isEventMarker) {
                map.removeLayer(marker);
            }
        });

        connectionLines.forEach(line => {
            if (map.hasLayer(line)) {
                map.removeLayer(line);
            }
        });

        markers = markers.filter(marker => !marker._isEventMarker);
        connectionLines = [];

        console.log('🗺️ Marcadores y líneas V3 limpiados');
        showToast('Marcadores V3 limpiados', 'success');
        addDebugLog('info', 'Marcadores y conexiones V3 limpiados');

    } catch (error) {
        console.error('❌ Error limpiando marcadores:', error);
    }
}

function centerMap() {
    if (!map) return;

    try {
        map.setView([40.4168, -3.7038], 6);
        console.log('🎯 Mapa V3 centrado');
        showToast('Mapa V3 centrado', 'info');

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
                    🧪 Generar Test Backend V3
                </button>
            </div>
        `;
        updateElement('live-events-count', 0);
        currentEvents = [];
        addDebugLog('info', 'Lista de eventos V3 limpiada');
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
    console.log('🔄 Refrescando dashboard V3...');
    fetchDataFromZeroMQ();

    if (map) {
        map.invalidateSize();
    }

    showToast('Dashboard V3 actualizado', 'success');
    addDebugLog('info', 'Dashboard V3 refrescado - firewall_commands.proto + sistema avanzado ventanas');
}

function clearDebugLog() {
    const debugLog = document.getElementById('debug-log');
    if (debugLog) {
        debugLog.innerHTML = `
            <div class="log-entry info">[INFO] ${new Date().toLocaleTimeString()} - Log limpiado</div>
            <div class="log-entry info">[INFO] ${new Date().toLocaleTimeString()} - Dashboard V3 con sistema avanzado conectado</div>
        `;
    }
    showToast('Log V3 limpiado', 'info');
}

// ✅ MODAL SYSTEM MEJORADO
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

        const modalHeader = modal.querySelector('.modal-header');
        if (modalHeader && !modalHeader.querySelector('.modal-controls')) {
            const controlsDiv = document.createElement('div');
            controlsDiv.className = 'modal-controls';
            controlsDiv.innerHTML = `
                <button class="modal-control-btn minimize" onclick="minimizeModal()" title="Minimizar">_</button>
                <button class="modal-control-btn maximize" onclick="maximizeModal()" title="Maximizar">🔲</button>
            `;

            const closeBtn = modalHeader.querySelector('.close-btn');
            if (closeBtn) {
                modalHeader.insertBefore(controlsDiv, closeBtn);
            } else {
                modalHeader.appendChild(controlsDiv);
            }
        }

        modal.classList.remove('positioned', 'minimized', 'maximized');
        modal.style.removeProperty('--modal-x');
        modal.style.removeProperty('--modal-y');

        overlay.style.display = 'block';
        modal.style.display = 'block';
        overlay.onclick = closeModal;

        makeModalDraggable(modal);

        console.log('📱 Modal V3 mostrado con controles avanzados');
    }
}

function makeModalDraggable(modal) {
    const header = modal.querySelector('.modal-header');
    if (!header) return;

    header.addEventListener('mousedown', function(e) {
        if (e.target.closest('.modal-controls') || e.target.closest('.close-btn')) {
            return;
        }

        isDragging = true;
        currentModal = modal;

        dragStartX = e.clientX;
        dragStartY = e.clientY;

        const rect = modal.getBoundingClientRect();
        modalStartX = rect.left;
        modalStartY = rect.top;

        modal.classList.add('dragging');
        header.style.cursor = 'grabbing';

        e.preventDefault();

        console.log('🖱️ Iniciando drag del modal');
    });
}

function minimizeModal() {
    const modal = document.getElementById('detail-modal');
    if (modal) {
        modal.classList.toggle('minimized');

        const btn = modal.querySelector('.minimize');
        if (btn) {
            btn.innerHTML = modal.classList.contains('minimized') ? '🔼' : '_';
        }

        console.log('📱 Modal minimizado/restaurado');
    }
}

function maximizeModal() {
    const modal = document.getElementById('detail-modal');
    if (modal) {
        modal.classList.toggle('maximized');

        const btn = modal.querySelector('.maximize');
        if (btn) {
            btn.innerHTML = modal.classList.contains('maximized') ? '🔽' : '🔲';
        }

        if (modal.classList.contains('maximized')) {
            modal.classList.remove('positioned');
            modal.style.removeProperty('--modal-x');
            modal.style.removeProperty('--modal-y');
        }

        console.log('🔲 Modal maximizado/restaurado');
    }
}

function closeModal() {
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('detail-modal');

    if (overlay && modal) {
        overlay.style.display = 'none';
        modal.style.display = 'none';

        modal.classList.remove('positioned', 'minimized', 'maximized', 'dragging');
        modal.style.removeProperty('--modal-x');
        modal.style.removeProperty('--modal-y');

        currentModal = null;
        isDragging = false;

        console.log('📱 Modal V3 cerrado');
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
            ⚠️ Amenaza V3 detectada!<br>
            <small>${event.source_ip} → ${event.target_ip}</small>
        `;
        indicator.classList.add('show');

        setTimeout(() => {
            indicator.classList.remove('show');
        }, 5000);
    }
}

// Funciones placeholder para handlers del HTML
function toggleHeatmap() { showToast('Heatmap V3: en desarrollo', 'warning'); }
function showMapLegend() { showToast('Leyenda V3: en desarrollo', 'info'); }
function testAllConnections() { showToast('Test conexiones V3: en desarrollo', 'info'); }
function showConnectionDetails(type) { console.log('Connection details V3:', type); }
function showSystemInfo() { console.log('System info V3'); }
function showEventsSummary() { console.log('Events summary V3'); }
function showConfirmationsSummary() { console.log('Confirmations summary V3'); }
function showPortDetails(port, event) { console.log('Port details V3:', port); event?.stopPropagation(); }
function showEventsDetail(event) { console.log('Events detail V3'); event?.stopPropagation(); }
function showCommandsDetail(event) { console.log('Commands detail V3'); event?.stopPropagation(); }
function showConfirmationsDetail(event) { console.log('Confirmations detail V3'); event?.stopPropagation(); }
function showComponentDetail(component) { console.log('Component detail V3:', component); }
function showComponentMetric(metric, event) { console.log('Component metric V3:', metric); event?.stopPropagation(); }
function showTopologyLineDetail(line) { console.log('Topology line V3:', line); }
function showZMQConnectionDetail(connection) { console.log('ZMQ connection V3:', connection); }
function showEventsPerMinuteDetail() { console.log('Events per minute detail V3'); }
function showHighRiskEventsDetail() { console.log('High risk events detail V3'); }
function showSuccessRateDetail() { console.log('Success rate detail V3'); }
function showFailuresDetail() { console.log('Failures detail V3'); }
function showDebugLogDetail() { console.log('Debug log detail V3'); }
function showLogEntryDetail(entry, event) { console.log('Log entry V3:', entry); event?.stopPropagation(); }

// Cleanup
window.addEventListener('beforeunload', function() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
    }
});

// La inicialización se maneja desde HTML con DOMContentLoaded_id: `target_action_${Date.now()}`,
                generated_by: 'dashboard_target_specific',
                dry_run_all: false
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
                    agent: result.node_id || firewallNodeId,
                    result: result.message || `${action} aplicada exitosamente a ${targetIP}`,
                    execution_time: result.execution_time || 0.1,
                    timestamp: Date.now() / 1000
                });
            }, 300);

            showToast(`✅ ${action} aplicada exitosamente a ${targetIP}`, 'success');
            addDebugLog('info', `Acción ${action} aplicada a target_ip ${targetIP}`);

            firewallStats.commandsSent++;
            firewallStats.responsesOk++;
            updateElement('firewall-commands-sent', firewallStats.commandsSent);
            updateElement('firewall-responses-ok', firewallStats.responsesOk);

            // Cerrar modal después de acción exitosa
            setTimeout(() => {
                closeModal();
            }, 2000);

        } else {
            setTimeout(() => {
                addFirewallEventToList({
                    id: commandId,
                    type: 'error',
                    success: false,
                    error: result.message || `Error aplicando ${action} a ${targetIP}`,
                    timestamp: Date.now() / 1000
                });
            }, 300);

            showToast(`❌ Error en ${action} para ${targetIP}: ${result.message}`, 'error');
            firewallStats.errors++;
            updateElement('firewall-errors', firewallStats.errors);
        }

    } catch (error) {
        console.error(`❌ Error ejecutando acción para target_ip ${targetIP}:`, error);

        addFirewallEventToList({
            id: `error_target_${Date.now()}`,
            type: 'error',
            success: false,
            error: `Error comunicación target_ip: ${error.message}`,
            timestamp: Date.now() / 1000
        });

        showToast(`❌ Error comunicando con firewall para ${targetIP}: ${error.message}`, 'error');
        firewallStats.errors++;
        updateElement('firewall-errors', firewallStats.errors);
    }
}

function toggleTargetIPData() {
    const content = document.getElementById('target-ip-data-content');
    const toggle = document.getElementById('target-ip-data-toggle');

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

// ============================================================================
// 🚨 MODAL DE EVENTOS COMPLETO - CON TODA LA INFORMACIÓN V3
// ============================================================================

async function showEventDetail(event) {
    try {
        console.log('🔍 Mostrando detalle completo del evento V3:', event);

        // Obtener información del firewall responsable desde backend
        const firewallInfo = await getResponsibleFirewallInfo(event);
        console.log('🔥 Info firewall responsable V3:', firewallInfo);

        // Generar botones Google Maps con coordenadas duales
        const googleMapsButtons = generateDualGoogleMapsButtons(event);

        const content = `
            <div style="font-family: 'Consolas', monospace; max-height: 70vh; overflow-y: auto;">
                <!-- Header del evento -->
                <div style="margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #00ff88;">
                    <h3 style="color: #00ff88; margin: 0;">🚨 Evento de Seguridad V3 Completo</h3>
                    <div style="font-size: 11px; color: #888; margin-top: 5px;">
                        ID: ${event.id || 'N/A'} | Timestamp: ${new Date(event.timestamp * 1000).toLocaleString()}
                    </div>
                    ${googleMapsButtons}
                </div>

                <!-- Información básica del evento -->
                <div style="margin-bottom: 20px;">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
                        <div>
                            <strong>IP Origen (Víctima):</strong><br>
                            <span style="color: #0066CC; font-size: 14px;">${event.source_ip}</span>
                            ${event.dual_geoip && event.dual_geoip.source ? `<br><small style="color: #888;">${event.dual_geoip.source.city}, ${event.dual_geoip.source.country}</small>` : ''}
                        </div>
                        <div>
                            <strong>IP Destino (Atacante):</strong><br>
                            <span style="color: #CC0000; font-size: 14px;">${event.target_ip}</span>
                            ${event.dual_geoip && event.dual_geoip.target ? `<br><small style="color: #888;">${event.dual_geoip.target.city}, ${event.dual_geoip.target.country}</small>` : ''}
                        </div>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px;">
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
                        <div>
                            <strong>Protocolo:</strong><br>
                            <span style="color: #00aaff;">${event.protocol || 'TCP'}</span>
                        </div>
                    </div>

                    <!-- 🆕 Información extendida V3 -->
                    ${event.source_port || event.target_port ? `
                        <div style="margin-top: 15px; display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                            <div>
                                <strong>Puerto Origen:</strong> <span style="color: #0066CC;">${event.source_port || 'N/A'}</span>
                            </div>
                            <div>
                                <strong>Puerto Destino:</strong> <span style="color: #CC0000;">${event.target_port || 'N/A'}</span>
                            </div>
                        </div>
                    ` : ''}

                    ${event.bytes_sent || event.packets_sent || event.duration ? `
                        <div style="margin-top: 15px; display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px;">
                            ${event.bytes_sent ? `<div><strong>Bytes:</strong> ${event.bytes_sent}</div>` : ''}
                            ${event.packets_sent ? `<div><strong>Paquetes:</strong> ${event.packets_sent}</div>` : ''}
                            ${event.duration ? `<div><strong>Duración:</strong> ${event.duration}s</div>` : ''}
                        </div>
                    ` : ''}

                    ${event.dual_geoip ? `
                        <div style="margin-top: 15px; padding: 10px; background: rgba(0, 255, 136, 0.1); border-radius: 4px;">
                            <strong style="color: #00ff88;">🗺️ Información Geográfica Dual:</strong><br>
                            <small style="color: #ccc;">
                                Distancia: ${event.dual_geoip.distance_km}km |
                                Mismo País: ${event.dual_geoip.same_country ? 'Sí' : 'No'} |
                                Enriquecimiento: ${event.dual_geoip.success ? 'Exitoso' : 'Parcial'}
                                ${event.dual_geoip.source?.enriched ? ' | Origen: ✅' : ' | Origen: ❌'}
                                ${event.dual_geoip.target?.enriched ? ' | Destino: ✅' : ' | Destino: ❌'}
                            </small>
                        </div>
                    ` : ''}
                </div>

                <!-- 🔥 Información del firewall responsable -->
                <div style="margin-bottom: 20px; padding: 15px; background: rgba(0, 255, 136, 0.1); border-left: 4px solid #00ff88; border-radius: 4px;">
                    <div style="color: #00ff88; font-weight: bold; margin-bottom: 8px;">
                        🔥 Firewall Agent Responsable V3
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

                <!-- 🔥 ACCIONES DISPONIBLES PARA EL EVENTO -->
                <div style="margin-bottom: 20px; padding: 15px; background: rgba(255, 170, 0, 0.1); border-left: 4px solid #ffaa00; border-radius: 4px;">
                    <div style="color: #ffaa00; font-weight: bold; margin-bottom: 12px;">
                        ⚡ Acciones Disponibles V3 (Backend Decide)
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                        ${generateEventFirewallActionsV3(event, firewallInfo)}
                    </div>
                    <div style="margin-top: 12px; font-size: 10px; color: #888; font-style: italic;">
                        💡 Acciones determinadas por el backend y aplicadas por: <strong style="color: #00ff88;">${firewallInfo.node_id}</strong>
                    </div>
                </div>

                <!-- Datos completos del evento (JSON) -->
                <div>
                    <div style="background: rgba(102, 102, 102, 0.2); padding: 10px; cursor: pointer; border-radius: 4px; margin-bottom: 10px;" onclick="toggleEventData()">
                        <span style="color: #666; font-weight: bold;">
                            📊 Datos Completos del Evento V3 (JSON)
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

        showModal('Análisis Completo del Evento V3', content);

    } catch (error) {
        console.error('❌ Error mostrando detalles del evento V3:', error);
        showSimpleEventDetail(event);
    }
}

// ============================================================================
// ✅ FUNCIONES PARA GOOGLE MAPS STREET VIEW - COORDENADAS DUALES
// ============================================================================

function generateDualGoogleMapsButtons(event) {
    let buttons = '';

    // 🔥 COORDENADAS DUALES: Generar botones para source y target
    if (event.dual_geoip) {
        if (event.dual_geoip.source && event.dual_geoip.source.enriched) {
            const sourceUrl = `https://www.google.com/maps/@${event.dual_geoip.source.latitude},${event.dual_geoip.source.longitude},3a,75y,0h,90t/data=!3m7!1e1!3m5!1s${encodeURIComponent(event.source_ip)}!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com!7i16384!8i8192`;

            buttons += `
                <div style="margin-top: 10px;">
                    <a href="${sourceUrl}" target="_blank" class="google-maps-btn source-btn">
                        <i class="fas fa-map-marked-alt"></i> 🏠 Street View Víctima (${event.source_ip})
                    </a>
                </div>
            `;
        }

        if (event.dual_geoip.target && event.dual_geoip.target.enriched) {
            const targetUrl = `https://www.google.com/maps/@${event.dual_geoip.target.latitude},${event.dual_geoip.target.longitude},3a,75y,0h,90t/data=!3m7!1e1!3m5!1s${encodeURIComponent(event.target_ip)}!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com!7i16384!8i8192`;

            buttons += `
                <div style="margin-top: 5px;">
                    <a href="${targetUrl}" target="_blank" class="google-maps-btn target-btn">
                        <i class="fas fa-map-marked-alt"></i> 🎯 Street View Atacante (${event.target_ip})
                    </a>
                </div>
            `;
        }

        // Botón para ver ambas ubicaciones en Google Maps
        if (event.dual_geoip.source && event.dual_geoip.target &&
            event.dual_geoip.source.enriched && event.dual_geoip.target.enriched) {

            const bothUrl = `https://www.google.com/maps/dir/${event.dual_geoip.source.latitude},${event.dual_geoip.source.longitude}/${event.dual_geoip.target.latitude},${event.dual_geoip.target.longitude}`;

            buttons += `
                <div style="margin-top: 5px;">
                    <a href="${bothUrl}" target="_blank" class="google-maps-btn both-btn">
                        <i class="fas fa-route"></i> 🗺️ Ver Ruta Completa (${event.dual_geoip.distance_km}km)
                    </a>
                </div>
            `;
        }

    } else if (event.latitude && event.longitude && event.latitude !== 0 && event.longitude !== 0) {
        // Fallback: Coordenadas legacy
        const legacyUrl = `https://www.google.com/maps/@${event.latitude},${event.longitude},3a,75y,0h,90t/data=!3m7!1e1!3m5!1s${encodeURIComponent(event.source_ip)}!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com!7i16384!8i8192`;

        buttons += `
            <div style="margin-top: 10px;">
                <a href="${legacyUrl}" target="_blank" class="google-maps-btn legacy-btn">
                    <i class="fas fa-map-marked-alt"></i> Ver en Google Maps Street View (Legacy)
                </a>
            </div>
        `;
    }

    return buttons;
}

// ============================================================================
// 🔥 FUNCIONES PARA FIREWALL - USANDO FIREWALL_COMMANDS.PROTO
// ============================================================================

async function getResponsibleFirewallInfo(event) {
    try {
        console.log('🔍 Obteniendo información del firewall responsable V3...');

        const response = await fetch('/api/firewall-agent-info', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                event_id: event.id,
                source_ip: event.source_ip,
                target_ip: event.target_ip,
                node_id: event.node_id,
                version: 'v3',
                dual_geoip: event.dual_geoip
            })
        });

        if (response.ok) {
            const data = await response.json();
            if (data.success && data.firewall_info) {
                console.log('✅ Info firewall V3 recibida del backend:', data.firewall_info);
                return data.firewall_info;
            }
        }

        console.log('⚠️ Usando fallback para info del firewall V3');
        const availableAgents = getAvailableFirewallAgents();
        return {
            node_id: availableAgents[0] || 'simple_firewall_agent_001',
            agent_ip: event.source_ip || '127.0.0.1',
            status: 'active',
            active_rules: firewallRules.rules_count || 0,
            endpoint: firewallConfig.endpoints?.firewall_commands || 'tcp://localhost:5580',
            capabilities: getAvailableFirewallActions()
        };

    } catch (error) {
        console.error('Error obteniendo información del firewall V3:', error);
        return {
            node_id: 'unknown_firewall',
            agent_ip: '127.0.0.1',
            status: 'unknown',
            active_rules: 0,
            endpoint: 'tcp://localhost:5580',
            capabilities: getAvailableFirewallActions()
        };
    }
}

async function getResponsibleFirewallInfoForTarget(targetIP, event) {
    // Similar a getResponsibleFirewallInfo pero específico para target_ip
    try {
        const response = await fetch('/api/firewall-agent-info-target', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_ip: targetIP,
                event_id: event.id,
                version: 'v3'
            })
        });

        if (response.ok) {
            const data = await response.json();
            if (data.success && data.firewall_info) {
                return data.firewall_info;
            }
        }

        return await getResponsibleFirewallInfo(event);

    } catch (error) {
        console.error('Error obteniendo info firewall para target_ip:', error);
        return await getResponsibleFirewallInfo(event);
    }
}

function generateEventFirewallActionsV3(event, firewallInfo) {
    const availableActions = getAvailableFirewallActions();
    let buttons = '';

    // El backend decide qué acciones están disponibles
    availableActions.forEach(action => {
        buttons += generateEventActionButtonV3(action, event, firewallInfo);
    });

    // Fallback si no hay acciones
    if (!buttons) {
        buttons = `
            <button onclick="executeEventFirewallActionV3('LIST_RULES', '${event.target_ip}', '${firewallInfo.node_id}', '${event.id}')"
                    class="firewall-action-btn list-rules-btn">
                📋 Listar Reglas
            </button>
            <button onclick="executeEventFirewallActionV3('BLOCK_IP', '${event.target_ip}', '${firewallInfo.node_id}', '${event.id}')"
                    class="firewall-action-btn block-btn">
                🚫 Bloquear Atacante
            </button>
        `;
    }

    return buttons;
}

function generateEventActionButtonV3(action, event, firewallInfo) {
    const actionConfig = {
        'BLOCK_IP': { color: '#ff4444', icon: '🚫', label: 'Bloquear IP' },
        'RATE_LIMIT_IP': { color: '#ffaa00', icon: '⏱️', label: 'Limitar Tráfico' },
        'LIST_RULES': { color: '#0066CC', icon: '📋', label: 'Listar Reglas' },
        'FLUSH_RULES': { color: '#ff6600', icon: '🗑️', label: 'Limpiar Reglas' },
        'BACKUP_RULES': { color: '#00ff88', icon: '💾', label: 'Backup Reglas' }
    };

    const config = actionConfig[action] || { color: '#666', icon: '⚙️', label: action };

    // Determinar IP objetivo según la acción
    let targetIp = 'all';
    if (action === 'LIST_RULES' || action === 'FLUSH_RULES' || action === 'BACKUP_RULES') {
        targetIp = 'all';
    } else {
        // Para acciones específicas, usar la IP atacante (target_ip)
        targetIp = event.target_ip;
    }

    return `
        <button onclick="executeEventFirewallActionV3('${action}', '${targetIp}', '${firewallInfo.node_id}', '${event.id}')"
                class="firewall-action-btn event-action-btn"
                style="background: rgba(${hexToRgb(config.color)}, 0.2); border: 1px solid ${config.color}; color: ${config.color}; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-size: 10px; width: 100%; transition: all 0.3s ease;"
                onmouseover="this.style.background='rgba(${hexToRgb(config.color)}, 0.3)'"
                onmouseout="this.style.background='rgba(${hexToRgb(config.color)}, 0.2)'">
            ${config.icon} ${config.label} ${targetIp !== 'all' ? `(${targetIp})` : ''}
        </button>
    `;
}

async function executeEventFirewallActionV3(action, targetIp, firewallNodeId, eventId) {
    try {
        console.log(`🔥 Ejecutando acción evento ${action} para IP ${targetIp}`);

        showToast(`Ejecutando ${action} desde evento...`, 'info');

        const commandId = `event_${Date.now()}`;

        // 🔥 Crear FirewallCommand usando estructura proto correcta
        const firewallCommand = {
            command_id: commandId,
            action: CommandAction[action] || CommandAction.LIST_RULES,
            target_ip: targetIp,
            target_port: 0,
            duration_seconds: getDurationForAction(action),
            reason: `Event-triggered action: ${action} for event ${eventId}`,
            priority: getPriorityForAction(action),
            dry_run: false,
            rate_limit_rule: action === 'RATE_LIMIT_IP' ? '5/min' : '',
            extra_params: {
                source: 'dashboard_event_action',
                event_id: eventId,
                action_type: 'event_response'
            }
        };

        // Añadir evento a la lista
        addFirewallEventToList({
            id: commandId,
            type: 'command',
            action: action,
            target_ip: targetIp,
            action_code: CommandAction[action],
            source: 'Dashboard Event Action',
            timestamp: Date.now() / 1000
        });

        // Enviar al backend
        const response = await fetch('/api/execute-firewall-action', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                firewall_command: firewallCommand,
                target_node_id: firewallNodeId,
                batch