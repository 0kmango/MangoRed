/**
 * MangoRed - Lógica de Interfaz de Usuario y Cliente REST
 * Supervisión de red local autorizada para Kali Linux
 */

// Estado global de la aplicación
const state = {
    devices: [],
    stats: {},
    config: {},
    activeStatusFilter: "all",
    searchQuery: "",
    activeTagFilter: "",
    selectedDeviceForBlock: null,
    selectedDeviceForEdit: null,
    isScanning: false,
    pollTimer: null
};

// Inicialización al cargar el DOM
document.addEventListener("DOMContentLoaded", () => {
    initApp();
});

async function initApp() {
    setupEventListeners();
    await loadConfig();
    await loadStats();
    await loadDevices();
    await loadGuide();

    // Polling regular cada 8 segundos para mantener la interfaz actualizada
    state.pollTimer = setInterval(async () => {
        if (!state.isScanning) {
            await loadStats();
            await loadDevices(false);
        }
    }, 8000);
}

function setupEventListeners() {
    // Búsqueda en tiempo real
    const searchInput = document.getElementById("search-input");
    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            state.searchQuery = e.target.value.toLowerCase();
            renderDevices();
        });
    }

    // Filtros de estado (Pills)
    document.querySelectorAll(".filter-pill").forEach(pill => {
        pill.addEventListener("click", () => {
            document.querySelectorAll(".filter-pill").forEach(p => p.classList.remove("active"));
            pill.classList.add("active");
            state.activeStatusFilter = pill.dataset.filter;
            renderDevices();
        });
    });

    // Botón Escanear Ahora
    const scanBtn = document.getElementById("btn-scan-now");
    if (scanBtn) {
        scanBtn.addEventListener("click", triggerScan);
    }

    // Botón Reconocer Todos los Nuevos
    const ackAllBtn = document.getElementById("btn-ack-all");
    if (ackAllBtn) {
        ackAllBtn.addEventListener("click", acknowledgeAllNewDevices);
    }

    // Botones de modales del encabezado
    document.getElementById("btn-open-history")?.addEventListener("click", () => openHistoryModal());
    document.getElementById("btn-open-settings")?.addEventListener("click", () => openSettingsModal());
    document.getElementById("btn-open-guide")?.addEventListener("click", () => openGuideModal());

    // Cierre de modales con botón 'X' o clic en fondo
    document.querySelectorAll(".modal-close-btn").forEach(btn => {
        btn.addEventListener("click", closeAllModals);
    });

    document.querySelectorAll(".modal-overlay").forEach(overlay => {
        overlay.addEventListener("click", (e) => {
            if (e.target === overlay) {
                closeAllModals();
            }
        });
    });

    // Formularios de modales
    document.getElementById("form-edit-device")?.addEventListener("submit", handleSaveDeviceCustom);
    document.getElementById("form-settings")?.addEventListener("submit", handleSaveSettings);
    document.getElementById("btn-test-router")?.addEventListener("click", handleTestRouterConnection);
    document.getElementById("btn-confirm-block")?.addEventListener("click", handleExecuteBlock);
}

// ============================================================================
// CARGA DE DATOS REST
// ============================================================================

async function loadConfig() {
    try {
        const res = await fetch("/api/config");
        const data = await res.json();
        if (data.success) {
            state.config = data.config;
            updateHeaderModeBadge();
        }
    } catch (err) {
        console.error("Error al cargar configuración:", err);
    }
}

async function loadStats() {
    try {
        const res = await fetch("/api/stats");
        const data = await res.json();
        if (data.success) {
            state.stats = data.stats;
            state.config.read_only = data.read_only;

            // Actualizar tarjetas de métricas
            document.getElementById("stat-online").textContent = data.stats.online_devices;
            document.getElementById("stat-total").textContent = data.stats.total_devices;
            document.getElementById("stat-new").textContent = data.stats.new_devices_count;
            document.getElementById("stat-blocked").textContent = data.stats.blocked_devices;

            // Banner de dispositivos nuevos
            const banner = document.getElementById("new-devices-banner");
            const bannerText = document.getElementById("new-devices-banner-text");
            if (data.stats.new_devices_count > 0) {
                banner.classList.remove("hidden");
                bannerText.textContent = `¡Atención! Se detectaron ${data.stats.new_devices_count} dispositivo(s) nuevo(s) en la red local.`;
            } else {
                banner.classList.add("hidden");
            }

            // Datos de red en encabezado
            document.getElementById("header-network-info").textContent = 
                `${data.network.subnet} (${data.network.interface}) | Gateway: ${data.network.gateway}`;
            
            document.getElementById("header-router-driver").textContent = 
                `Router: ${data.router_driver.name}`;

            updateHeaderModeBadge();
        }
    } catch (err) {
        console.error("Error al cargar estadísticas:", err);
    }
}

async function loadDevices(showLoading = true) {
    const tableBody = document.getElementById("devices-table-body");
    if (showLoading && state.devices.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 2rem;">Cargando inventario de red...</td></tr>`;
    }

    try {
        const res = await fetch("/api/devices");
        const data = await res.json();
        if (data.success) {
            state.devices = data.devices;
            renderDevices();
        }
    } catch (err) {
        console.error("Error al cargar dispositivos:", err);
        tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; color: var(--color-danger); padding: 2rem;">Error al comunicarse con el servicio MangoRed.</td></tr>`;
    }
}

function updateHeaderModeBadge() {
    const badge = document.getElementById("header-mode-badge");
    if (!badge) return;

    if (state.config.read_only) {
        badge.className = "badge-mode read-only";
        badge.innerHTML = `<span>🛡️</span> Modo Solo Lectura: Activo`;
    } else {
        badge.className = "badge-mode write-mode";
        badge.innerHTML = `<span>⚠️</span> Modo Modificación: Autorizado`;
    }
}

// ============================================================================
// RENDERIZADO DEL INVENTARIO Y CERTEZA DE DATOS
// ============================================================================

function renderDevices() {
    const tableBody = document.getElementById("devices-table-body");
    if (!tableBody) return;

    // Filtrado local en memoria
    let filtered = state.devices.filter(dev => {
        // Filtro por estado
        if (state.activeStatusFilter === "online" && (dev.status !== "online" || dev.is_blocked)) return false;
        if (state.activeStatusFilter === "offline" && (dev.status !== "offline" || dev.is_blocked)) return false;
        if (state.activeStatusFilter === "new" && !dev.is_new) return false;
        if (state.activeStatusFilter === "blocked" && !dev.is_blocked) return false;

        // Búsqueda por texto (IP, MAC, Hostname, Nombre, Fabricante, Etiquetas)
        if (state.searchQuery) {
            const query = state.searchQuery;
            const match = 
                (dev.ip && dev.ip.toLowerCase().includes(query)) ||
                (dev.mac && dev.mac.toLowerCase().includes(query)) ||
                (dev.hostname && dev.hostname.toLowerCase().includes(query)) ||
                (dev.custom_name && dev.custom_name.toLowerCase().includes(query)) ||
                (dev.vendor && dev.vendor.toLowerCase().includes(query)) ||
                (dev.custom_tags && dev.custom_tags.toLowerCase().includes(query)) ||
                (dev.notes && dev.notes.toLowerCase().includes(query));
            if (!match) return false;
        }

        return true;
    });

    if (filtered.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; color: var(--text-muted); padding: 2rem;">No se encontraron dispositivos que coincidan con los criterios.</td></tr>`;
        return;
    }

    tableBody.innerHTML = filtered.map(dev => {
        // Determinación de clase de estado
        let statusClass = dev.status;
        let statusLabel = "En línea";
        if (dev.is_blocked) {
            statusClass = "blocked";
            statusLabel = "Bloqueado";
        } else if (dev.status === "stale") {
            statusClass = "stale";
            statusLabel = "Inactivo";
        } else if (dev.status === "offline") {
            statusClass = "offline";
            statusLabel = "Desconectado";
        }

        // Nombre principal visible
        const displayName = dev.custom_name || dev.hostname || "Dispositivo sin nombre";
        const hasCustomName = Boolean(dev.custom_name);
        const hostnameText = dev.hostname ? dev.hostname : "No disponible";

        // Insignia de nuevo dispositivo
        const newBadgeHtml = dev.is_new 
            ? `<span class="new-badge" title="Dispositivo recién detectado">NUEVO</span>` 
            : "";

        // Formato de etiquetas
        const tagsHtml = dev.custom_tags 
            ? dev.custom_tags.split(",").map(t => `<span class="tag-badge">${escapeHtml(t.trim())}</span>`).join("")
            : `<span style="color: var(--text-muted); font-size: 0.75rem;">Sin etiquetas</span>`;

        // Formato de fecha
        const lastSeenFormatted = formatTimestamp(dev.last_seen);

        return `
            <tr>
                <td>
                    <div style="display: flex; align-items: center;">
                        <span class="status-dot ${statusClass}" title="${statusLabel}"></span>
                        <div>
                            <strong>${escapeHtml(displayName)}</strong> ${newBadgeHtml}
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 2px;">
                                Hostname: <span style="font-family: monospace;">${escapeHtml(hostnameText)}</span>
                                <span class="certainty-badge estimated" title="Resuelto vía DNS PTR o mDNS. Puede ser modificado por el propio dispositivo.">Estimado (DNS)</span>
                            </div>
                        </div>
                    </div>
                </td>
                <td>
                    <span style="font-family: monospace; font-weight: 600;">${escapeHtml(dev.ip)}</span>
                    <span class="certainty-badge confirmed" title="Confirmado por respuesta activa en capa de red (ARP/ICMP)">Confirmado</span>
                </td>
                <td>
                    <span style="font-family: monospace; color: var(--text-secondary);">${escapeHtml(dev.mac)}</span>
                    <span class="certainty-badge confirmed" title="Confirmado por dirección de capa de enlace en la tabla de vecinos">Confirmado</span>
                </td>
                <td>
                    <span style="font-size: 0.85rem;">${escapeHtml(dev.vendor || 'Desconocido')}</span>
                    <span class="certainty-badge estimated" title="Estimación basada en el prefijo OUI de 24 bits. Dispositivos modernos pueden usar MAC aleatoria.">Estimado (OUI)</span>
                </td>
                <td>
                    <div>${tagsHtml}</div>
                </td>
                <td>
                    <span style="font-size: 0.8rem; color: var(--text-secondary);">${lastSeenFormatted}</span>
                </td>
                <td>
                    <div style="display: flex; gap: 0.35rem; align-items: center;">
                        <button class="btn btn-sm" onclick="openEditModal('${dev.mac}')" title="Asignar nombre, etiquetas y notas">
                            ✏️ Editar
                        </button>
                        <button class="btn btn-sm" onclick="openHistoryModal('${dev.mac}')" title="Ver historial de conexiones">
                            🕒 Historial
                        </button>
                        ${dev.is_blocked 
                            ? `<button class="btn btn-sm btn-primary" onclick="handleUnblockClick('${dev.mac}')" title="Desbloquear en el router">
                                 🔓 Desbloquear
                               </button>`
                            : `<button class="btn btn-sm btn-danger" onclick="openBlockModal('${dev.mac}')" title="Bloquear mediante API del router">
                                 ⛔ Bloquear
                               </button>`
                        }
                    </div>
                </td>
            </tr>
        `;
    }).join("");
}

// ============================================================================
// ESCANEO MANUAL
// ============================================================================

async function triggerScan() {
    const scanBtn = document.getElementById("btn-scan-now");
    const scanIcon = document.getElementById("scan-btn-icon");
    
    if (state.isScanning) return;
    state.isScanning = true;
    scanBtn.disabled = true;
    scanIcon.classList.add("spin");
    scanBtn.querySelector("span:last-child").textContent = "Escaneando...";

    try {
        const res = await fetch("/api/scan", { method: "POST" });
        const data = await res.json();
        if (data.success) {
            await loadStats();
            await loadDevices(false);
            showToast("Escaneo completado", `Se detectaron ${data.result.devices_found} dispositivos en ${data.result.duration_seconds}s.`, "success");
        } else {
            showToast("Error en escaneo", data.error || "No se pudo completar el escaneo.", "danger");
        }
    } catch (err) {
        showToast("Error", "Fallo de comunicación durante el escaneo.", "danger");
    } finally {
        state.isScanning = false;
        scanBtn.disabled = false;
        scanIcon.classList.remove("spin");
        scanBtn.querySelector("span:last-child").textContent = "Escanear Ahora";
    }
}

async function acknowledgeAllNewDevices() {
    try {
        const res = await fetch("/api/devices/acknowledge-all", { method: "POST" });
        const data = await res.json();
        if (data.success) {
            await loadStats();
            await loadDevices(false);
            showToast("Avisos actualizados", "Todos los dispositivos nuevos han sido reconocidos.", "info");
        }
    } catch (err) {
        showToast("Error", "No se pudieron reconocer los avisos.", "danger");
    }
}

// ============================================================================
// MODAL DE EDICIÓN DE DISPOSITIVO (NOMBRE, ETIQUETAS, NOTAS)
// ============================================================================

function openEditModal(mac) {
    const dev = state.devices.find(d => d.mac === mac);
    if (!dev) return;

    state.selectedDeviceForEdit = dev;
    document.getElementById("edit-modal-title").textContent = `Editar: ${dev.custom_name || dev.hostname || dev.mac}`;
    document.getElementById("edit-mac").value = dev.mac;
    document.getElementById("edit-name").value = dev.custom_name || "";
    document.getElementById("edit-tags").value = dev.custom_tags || "";
    document.getElementById("edit-notes").value = dev.notes || "";

    openModal("modal-edit-device");
}

async function handleSaveDeviceCustom(e) {
    e.preventDefault();
    if (!state.selectedDeviceForEdit) return;

    const mac = state.selectedDeviceForEdit.mac;
    const custom_name = document.getElementById("edit-name").value.trim();
    const custom_tags = document.getElementById("edit-tags").value.trim();
    const notes = document.getElementById("edit-notes").value.trim();

    try {
        const res = await fetch(`/api/devices/${encodeURIComponent(mac)}/custom`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ custom_name, custom_tags, notes })
        });
        const data = await res.json();
        if (data.success) {
            closeAllModals();
            await loadDevices(false);
            showToast("Guardado", "Etiquetas y datos personalizados actualizados.", "success");
        } else {
            showToast("Error", data.error || "No se pudo guardar.", "danger");
        }
    } catch (err) {
        showToast("Error", "Error de red al actualizar dispositivo.", "danger");
    }
}

// ============================================================================
// MODAL DE BLOQUEO AUTORIZADO (DOBLE CONFIRMACIÓN Y COMPROBACIÓN SOLO LECTURA)
// ============================================================================

function openBlockModal(mac) {
    const dev = state.devices.find(d => d.mac === mac);
    if (!dev) return;

    state.selectedDeviceForBlock = dev;

    // Rellenar información visual del dispositivo a afectar
    document.getElementById("block-preview-name").textContent = dev.custom_name || dev.hostname || "Dispositivo sin nombre";
    document.getElementById("block-preview-ip").textContent = dev.ip;
    document.getElementById("block-preview-mac").textContent = dev.mac;
    document.getElementById("block-preview-vendor").textContent = dev.vendor || "Desconocido";
    document.getElementById("block-reason").value = "";
    document.getElementById("block-confirm-checkbox").checked = false;

    // Mostrar controlador de router que se invocará
    document.getElementById("block-preview-driver").textContent = state.config.router_type.toUpperCase();

    // Comprobación de Modo Solo Lectura
    const readOnlyWarning = document.getElementById("block-readonly-warning");
    const confirmBtn = document.getElementById("btn-confirm-block");

    if (state.config.read_only) {
        readOnlyWarning.classList.remove("hidden");
        confirmBtn.disabled = true;
        confirmBtn.title = "Desactiva el Modo Solo Lectura en Ajustes para habilitar bloqueos.";
    } else {
        readOnlyWarning.classList.add("hidden");
        confirmBtn.disabled = false;
        confirmBtn.title = "";
    }

    openModal("modal-block-device");
}

async function handleExecuteBlock() {
    if (!state.selectedDeviceForBlock) return;

    const checkbox = document.getElementById("block-confirm-checkbox");
    if (!checkbox.checked) {
        alert("Debes marcar la casilla de confirmación para autorizar la acción.");
        return;
    }

    if (state.config.read_only) {
        alert("Operación bloqueada: MangoRed está en Modo Solo Lectura. Cambia la opción en Ajustes.");
        return;
    }

    const mac = state.selectedDeviceForBlock.mac;
    const reason = document.getElementById("block-reason").value.trim() || "Bloqueo administrativo autorizado";

    const confirmBtn = document.getElementById("btn-confirm-block");
    confirmBtn.disabled = true;
    confirmBtn.textContent = "Aplicando en Router...";

    try {
        const res = await fetch("/api/router/block", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                mac: mac,
                confirmed: true,
                reason: reason
            })
        });
        const data = await res.json();

        if (data.success) {
            closeAllModals();
            await loadStats();
            await loadDevices(false);
            showToast("Bloqueo Aplicado", data.message, "success");
        } else {
            showToast("Fallo al Bloquear", data.error || "El router rechazó la regla.", "danger");
        }
    } catch (err) {
        showToast("Error", "Error de comunicación con el servicio del router.", "danger");
    } finally {
        confirmBtn.disabled = false;
        confirmBtn.textContent = "Confirmar Bloqueo Autorizado";
    }
}

async function handleUnblockClick(mac) {
    const dev = state.devices.find(d => d.mac === mac);
    const name = dev ? (dev.custom_name || dev.hostname || dev.mac) : mac;

    if (!confirm(`¿Deseas desbloquear el dispositivo '${name}' en el router y restaurar su acceso a la red?`)) {
        return;
    }

    if (state.config.read_only) {
        alert("Operación bloqueada: MangoRed está en Modo Solo Lectura.");
        return;
    }

    try {
        const res = await fetch("/api/router/unblock", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mac: mac })
        });
        const data = await res.json();
        if (data.success) {
            await loadStats();
            await loadDevices(false);
            showToast("Desbloqueado", data.message, "success");
        } else {
            showToast("Error", data.error || "No se pudo desbloquear.", "danger");
        }
    } catch (err) {
        showToast("Error", "Error al contactar con la API del router.", "danger");
    }
}

// ============================================================================
// MODAL DE HISTORIAL DE CONEXIONES Y AUDITORÍA
// ============================================================================

async function openHistoryModal(macFilter = null) {
    const historyList = document.getElementById("history-items-list");
    historyList.innerHTML = `<div style="text-align: center; padding: 1.5rem; color: var(--text-muted);">Cargando registros de historial...</div>`;

    document.getElementById("history-modal-title").textContent = macFilter 
        ? `Historial del Dispositivo (${macFilter})` 
        : "Historial de Conexiones y Eventos de Red";

    openModal("modal-history");

    try {
        let url = "/api/history?limit=150";
        if (macFilter) url += `&mac=${encodeURIComponent(macFilter)}`;

        const res = await fetch(url);
        const data = await res.json();

        if (data.success && data.history.length > 0) {
            historyList.innerHTML = data.history.map(item => {
                let icon = "ℹ️";
                if (item.event_type === "new_device") icon = "🚨";
                else if (item.event_type === "connected") icon = "🟢";
                else if (item.event_type === "disconnected") icon = "⚪";
                else if (item.event_type === "ip_changed") icon = "🔄";
                else if (item.event_type === "blocked") icon = "⛔";
                else if (item.event_type === "unblocked") icon = "🔓";
                else if (item.event_type === "tag_updated") icon = "🏷️";

                return `
                    <div class="history-item ${item.severity}">
                        <div class="history-icon-badge">${icon}</div>
                        <div style="flex: 1;">
                            <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.2rem;">
                                <span>${formatTimestamp(item.timestamp)}</span>
                                <span style="font-family: monospace;">${escapeHtml(item.mac || '')} ${item.ip ? '• ' + escapeHtml(item.ip) : ''}</span>
                            </div>
                            <div style="font-size: 0.85rem; color: var(--text-primary); line-height: 1.4;">
                                ${escapeHtml(item.details)}
                            </div>
                        </div>
                    </div>
                `;
            }).join("");
        } else {
            historyList.innerHTML = `<div style="text-align: center; padding: 2rem; color: var(--text-muted);">No hay eventos registrados en este periodo.</div>`;
        }
    } catch (err) {
        historyList.innerHTML = `<div style="text-align: center; padding: 1.5rem; color: var(--color-danger);">Error al cargar historial.</div>`;
    }
}

// ============================================================================
// MODAL DE AJUSTES Y CONFIGURACIÓN DEL ROUTER
// ============================================================================

function openSettingsModal() {
    document.getElementById("cfg-readonly").checked = state.config.read_only;
    document.getElementById("cfg-scan-interval").value = state.config.scan_interval || 30;
    document.getElementById("cfg-interface").value = state.config.interface || "";
    document.getElementById("cfg-desktop-notifs").checked = state.config.enable_desktop_notifications !== false;

    // Configuración del router
    document.getElementById("cfg-router-type").value = state.config.router_type || "simulator";
    document.getElementById("cfg-router-host").value = state.config.router_host || "192.168.1.1";
    document.getElementById("cfg-router-port").value = state.config.router_port || 80;
    document.getElementById("cfg-router-user").value = state.config.router_user || "admin";
    document.getElementById("cfg-router-pass").value = state.config.router_password || "";
    document.getElementById("cfg-router-token").value = state.config.router_api_token || "";

    openModal("modal-settings");
}

async function handleSaveSettings(e) {
    e.preventDefault();

    const payload = {
        read_only: document.getElementById("cfg-readonly").checked,
        scan_interval: parseInt(document.getElementById("cfg-scan-interval").value, 10),
        interface: document.getElementById("cfg-interface").value.trim(),
        enable_desktop_notifications: document.getElementById("cfg-desktop-notifs").checked,
        router_type: document.getElementById("cfg-router-type").value,
        router_host: document.getElementById("cfg-router-host").value.trim(),
        router_port: parseInt(document.getElementById("cfg-router-port").value, 10),
        router_user: document.getElementById("cfg-router-user").value.trim(),
        router_password: document.getElementById("cfg-router-pass").value,
        router_api_token: document.getElementById("cfg-router-token").value
    };

    try {
        const res = await fetch("/api/config", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
            state.config = data.config;
            closeAllModals();
            updateHeaderModeBadge();
            await loadStats();
            showToast("Ajustes Guardados", "La configuración ha sido persistida de forma segura.", "success");
        } else {
            showToast("Error en Ajustes", data.error || "Validación fallida.", "danger");
        }
    } catch (err) {
        showToast("Error", "No se pudieron guardar los ajustes.", "danger");
    }
}

async function handleTestRouterConnection() {
    const statusDiv = document.getElementById("router-test-result");
    statusDiv.textContent = "Probando conexión con la API del router...";
    statusDiv.style.color = "var(--text-muted)";

    try {
        const res = await fetch("/api/router/test", { method: "POST" });
        const data = await res.json();
        if (data.success) {
            statusDiv.textContent = `✓ Éxito (${data.driver_name}): ${data.message}`;
            statusDiv.style.color = "var(--color-success)";
        } else {
            statusDiv.textContent = `✗ Fallo: ${data.message}`;
            statusDiv.style.color = "var(--color-danger)";
        }
    } catch (err) {
        statusDiv.textContent = "✗ Error de red al probar la API del router.";
        statusDiv.style.color = "var(--color-danger)";
    }
}

// ============================================================================
// MODAL DE GUÍA OFICIAL Y BUENAS PRÁCTICAS
// ============================================================================

let cachedGuide = null;

async function loadGuide() {
    try {
        const res = await fetch("/api/guide");
        const data = await res.json();
        if (data.success) {
            cachedGuide = data.guide;
        }
    } catch (err) {
        console.error("Error al precargar guía:", err);
    }
}

function openGuideModal() {
    if (!cachedGuide) {
        loadGuide().then(() => renderGuideTab("ethics_and_security"));
    } else {
        renderGuideTab("ethics_and_security");
    }
    openModal("modal-guide");
}

function renderGuideTab(tabKey) {
    document.querySelectorAll(".guide-tab-btn").forEach(btn => {
        btn.classList.toggle("active", btn.dataset.tab === tabKey);
    });

    const container = document.getElementById("guide-tab-content");
    if (!cachedGuide || !cachedGuide[tabKey]) {
        container.innerHTML = "<p>Información no disponible.</p>";
        return;
    }

    const section = cachedGuide[tabKey];
    if (tabKey === "ethics_and_security") {
        container.innerHTML = `
            <div style="background-color: var(--color-warning-soft); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: var(--radius-md); padding: 1rem; margin-bottom: 1rem;">
                <h4 style="color: var(--color-warning); margin-bottom: 0.5rem; font-size: 1rem;">🛡️ Principio de Supervisión Autorizada</h4>
                <p style="font-size: 0.875rem; line-height: 1.6; white-space: pre-line;">${escapeHtml(section.content)}</p>
            </div>
            <p style="font-size: 0.85rem; color: var(--text-secondary);">
                MangoRed está diseñado exclusivamente para la administración legítima de redes locales de tu propiedad.
                No contiene funciones de ataque ni recopila el contenido del tráfico de los usuarios.
            </p>
        `;
    } else {
        container.innerHTML = `
            <h4 style="margin-bottom: 1rem; font-size: 1.05rem; color: var(--brand-primary);">${escapeHtml(section.title)}</h4>
            <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                ${section.steps.map(step => `<div class="guide-step">${escapeHtml(step)}</div>`).join("")}
            </div>
        `;
    }
}

// Configuración de clics en las pestañas de la guía
document.addEventListener("click", (e) => {
    if (e.target.classList.contains("guide-tab-btn")) {
        renderGuideTab(e.target.dataset.tab);
    }
});

// ============================================================================
// UTILIDADES DE INTERFAZ Y MODALES
// ============================================================================

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add("active");
    }
}

function closeAllModals() {
    document.querySelectorAll(".modal-overlay").forEach(m => m.classList.remove("active"));
}

function showToast(title, message, type = "info") {
    // Si existe el contenedor de toasts, insertar uno flotante
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `stat-card`;
    toast.style.borderLeft = `4px solid var(--color-${type === 'danger' ? 'danger' : type === 'success' ? 'success' : 'info'})`;
    toast.style.minWidth = "280px";
    toast.style.boxShadow = "var(--shadow-lg)";
    toast.style.pointerEvents = "auto";
    toast.style.marginBottom = "0.5rem";

    toast.innerHTML = `
        <div>
            <strong style="font-size: 0.85rem; color: var(--text-primary); display: block;">${escapeHtml(title)}</strong>
            <span style="font-size: 0.75rem; color: var(--text-secondary);">${escapeHtml(message)}</span>
        </div>
    `;

    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transition = "opacity 0.3s";
        setTimeout(() => toast.remove(), 300);
    }, 4500);
}

function formatTimestamp(isoStr) {
    if (!isoStr) return "Desconocido";
    try {
        const dt = new Date(isoStr);
        return dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + 
               " (" + dt.toLocaleDateString() + ")";
    } catch {
        return isoStr;
    }
}

function escapeHtml(text) {
    if (!text) return "";
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
