/**
 * Mango LAN Map - mapa lógico en vivo de la red local (vista de MangoRed).
 *
 * Pinta el gateway en el centro y los dispositivos en anillos por tipo, con
 * enlaces, animaciones de conexión/desconexión y posiciones arrastrables que se
 * guardan en el servidor. Es un mapa *lógico*: no pretende geolocalizar nada.
 */

const SVG_NS = "http://www.w3.org/2000/svg";
const API_TOKEN = (document.querySelector('meta[name="mangored-api-token"]') || {}).content || "";

const TYPE_ICONS = {
    router: "📡", nas: "💾", server: "🗄️", computer: "💻", desktop: "🖥️", laptop: "💻",
    printer: "🖨️", tv: "📺", console: "🎮", camera: "📷", smartphone: "📱",
    tablet: "📲", wearable: "⌚", iot: "🔌", vm: "🧩", unknown: "❓"
};

const RING_RADIUS_PCT = [0, 21, 33, 42];
const POLL_MS = 2000;

const el = (id) => document.getElementById(id);

const state = {
    nodes: [],
    byMac: new Map(),
    links: new Map(),
    view: { k: 1, x: 0, y: 0 },
    selected: null,
    dragging: null,
    panning: null,
    latest: 0,
    floorplan: false,
    floorplanVersion: 0,
    query: "",
    firstLoad: true,
    saveTimer: null,
    dirty: new Map()
};

// ============================================================================
// Utilidades
// ============================================================================

function escapeHtml(value) {
    return String(value === null || value === undefined ? "" : value)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function showToast(title, message, type = "info") {
    const container = el("map-toasts");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.innerHTML = `<strong>${escapeHtml(title)}</strong><span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.transition = "opacity .3s";
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 320);
    }, 5000);
}

async function apiFetch(url, options = {}) {
    const opts = Object.assign({}, options);
    opts.headers = Object.assign({}, options.headers || {});
    if (API_TOKEN) opts.headers["X-MangoRed-Token"] = API_TOKEN;
    opts.headers["Accept"] = opts.headers["Accept"] || "application/json";

    const response = await window.fetch(url, opts);
    if (!response.ok) {
        let detail = "";
        try {
            const data = await response.clone().json();
            detail = (data && (data.error || data.message)) || "";
        } catch (err) { detail = ""; }
        if (detail) {
            showToast("Error", detail, "danger");
        } else if (response.status >= 500) {
            showToast("Error del servidor", `HTTP ${response.status}`, "danger");
        }
    }
    return response;
}

function eventTitle(event) {
    if (event.type === "new_device") return "Nuevo dispositivo en la red";
    if (event.type === "connected") return "Dispositivo conectado";
    if (event.type === "disconnected") return "Dispositivo desconectado";
    return "Evento de red";
}

function statusClass(node) {
    if (node.is_blocked) return "blocked";
    return node.status === "online" ? "online" : "offline";
}

// ============================================================================
// Carga de datos y tiempo real
// ============================================================================

async function loadMap() {
    if (document.visibilityState === "hidden") return;

    let payload;
    try {
        const response = await apiFetch(`/api/map?since=${state.latest}`);
        payload = await response.json();
    } catch (err) {
        return; // se reintenta en el siguiente ciclo
    }
    if (!payload || !payload.success) return;

    if (typeof payload.latest === "number") state.latest = payload.latest;
    state.floorplan = Boolean(payload.floorplan);

    updateHeader(payload);
    updateStats(payload.stats || {});

    const events = payload.events || [];
    if (!state.firstLoad) {
        events.forEach((event) => showToast(eventTitle(event), event.message, event.severity || "info"));
    }
    state.firstLoad = false;

    state.nodes = payload.nodes || [];
    state.byMac = new Map(state.nodes.map((node) => [node.mac, node]));

    if (!state.dragging) render();

    if (state.selected && state.byMac.has(state.selected)) {
        renderSidePanel(state.byMac.get(state.selected));
    }
    syncFloorplan();
}

function updateHeader(payload) {
    const liveText = el("map-live-text");
    const liveDot = el("map-live-dot");
    const watcher = payload.watcher || {};
    if (liveText && liveDot) {
        if (watcher.running) {
            liveText.textContent = `En vivo · ${watcher.interval}s`;
            liveDot.style.color = "var(--color-success)";
        } else {
            liveText.textContent = "Vigilancia inactiva";
            liveDot.style.color = "var(--text-muted)";
        }
    }

    const network = payload.network || {};
    const chip = el("map-live");
    if (chip) {
        chip.title = `${network.subnet || ""} · ${network.interface || ""} · Gateway ${network.gateway || "-"}`;
    }
}

function updateStats(stats) {
    el("chip-online").textContent = `🟢 ${stats.online_devices ?? 0}`;
    el("chip-total").textContent = `💾 ${stats.total_devices ?? 0}`;
    el("chip-new").textContent = `🚨 ${stats.new_devices_count ?? 0}`;
}

async function triggerScan() {
    const button = el("btn-map-scan");
    button.disabled = true;
    button.textContent = "⏳ Escaneando...";
    try {
        const response = await apiFetch("/api/scan", { method: "POST" });
        const data = await response.json();
        if (data.success) {
            const result = data.result || {};
            showToast("Escaneo completado",
                `${result.devices_found ?? 0} dispositivos en ${result.duration_seconds ?? "?"}s`,
                "success");
        }
        await loadMap();
    } catch (err) {
        showToast("Error", "No se pudo completar el escaneo.", "danger");
    } finally {
        button.disabled = false;
        button.textContent = "🔄 Escanear";
    }
}

// ============================================================================
// Render del mapa (SVG)
// ============================================================================

function toUserUnits(percent) { return percent * 10; }

function svgElement(tag, attributes = {}) {
    const node = document.createElementNS(SVG_NS, tag);
    Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, value));
    return node;
}

function applyView() {
    const scene = el("scene");
    if (!scene) return;
    const { k, x, y } = state.view;
    scene.setAttribute("transform", `translate(${x}, ${y}) scale(${k})`);
}

function render() {
    renderRings();
    renderFloorplanLayer();
    renderNodes();
    applyView();
    renderLegend();
}

function renderRings() {
    const container = el("map-rings");
    if (!container) return;
    container.innerHTML = "";
    [1, 2, 3].forEach((ring) => {
        container.appendChild(svgElement("circle", {
            class: "ring-guide", cx: 500, cy: 500, r: toUserUnits(RING_RADIUS_PCT[ring])
        }));
    });
    if (state.nodes.some((node) => node.center)) {
        container.appendChild(svgElement("circle", {
            class: "gateway-ring", cx: 500, cy: 500, r: 150
        }));
    }
}

function renderFloorplanLayer() {
    const image = el("floorplan-image");
    if (!image) return;
    if (state.floorplan) {
        image.classList.remove("hidden");
        image.setAttribute("href", `/api/map/floorplan?v=${state.floorplanVersion}`);
        image.setAttribute("opacity", "0.35");
    } else {
        image.classList.add("hidden");
        image.setAttribute("href", "");
    }
}

function matchesQuery(node) {
    if (!state.query) return true;
    const haystack = [
        node.display_name, node.custom_name, node.hostname, node.ip, node.mac,
        node.vendor, node.model, node.device_type_label, node.os_guess, node.custom_tags
    ].filter(Boolean).join(" ").toLowerCase();
    return haystack.includes(state.query);
}

function renderNodes() {
    const linkLayer = el("map-links");
    const nodeLayer = el("map-nodes");
    if (!linkLayer || !nodeLayer) return;

    linkLayer.innerHTML = "";
    nodeLayer.innerHTML = "";
    state.links = new Map();

    const gateway = state.nodes.find((node) => node.center);
    const origin = gateway ? { x: gateway.x, y: gateway.y } : { x: 50, y: 50 };

    state.nodes.forEach((node) => {
        const link = svgElement("line", {
            class: `link ${statusClass(node)}`,
            x1: toUserUnits(origin.x), y1: toUserUnits(origin.y),
            x2: toUserUnits(node.x), y2: toUserUnits(node.y)
        });
        linkLayer.appendChild(link);
        state.links.set(node.mac, link);
    });

    state.nodes.forEach((node) => {
        const icon = TYPE_ICONS[node.device_type] || TYPE_ICONS.unknown;
        const classes = ["node", statusClass(node)];
        if (node.is_new) classes.push("is-new");
        if (node.mac === state.selected) classes.push("selected");
        if (state.query) classes.push(matchesQuery(node) ? "match" : "dimmed");

        const group = svgElement("g", {
            class: classes.join(" "),
            transform: `translate(${toUserUnits(node.x)}, ${toUserUnits(node.y)})`
        });
        group.dataset.mac = node.mac;

        const halo = statusClass(node) === "online" ? "online" : "offline";
        group.innerHTML = `
            <circle class="halo" r="34" fill="url(#halo-${halo})"></circle>
            <circle class="disc" r="22"></circle>
            <text class="icon" y="1">${icon}</text>
            <text class="label" y="46">${escapeHtml(node.display_name || node.mac)}</text>
            <text class="sublabel" y="64">${escapeHtml(node.ip || "")}${node.pinned ? " 📌" : ""}</text>
        `;
        nodeLayer.appendChild(group);
    });
}

function renderLegend() {
    const container = el("legend-items");
    if (!container) return;

    const order = ["router", "computer", "laptop", "desktop", "smartphone", "tablet",
        "tv", "console", "printer", "camera", "nas", "iot", "wearable", "vm", "unknown"];
    const present = new Map();
    state.nodes.forEach((node) => {
        const type = node.device_type || "unknown";
        if (!present.has(type)) present.set(type, node.device_type_label || "Desconocido");
    });

    container.innerHTML = order
        .filter((type) => present.has(type))
        .map((type) => `<span class="legend-item">${TYPE_ICONS[type] || "❓"} `
            + `${escapeHtml(present.get(type))}</span>`)
        .join("");
}

function updateLinkPosition(node) {
    const link = state.links.get(node.mac);
    if (!link) return;
    link.setAttribute("x2", toUserUnits(node.x));
    link.setAttribute("y2", toUserUnits(node.y));
}

function syncFloorplan() {
    const image = el("floorplan-image");
    if (!image) return;
    const href = image.getAttribute("href") || "";
    if (state.floorplan && !href) {
        state.floorplanVersion = Date.now();
        renderFloorplanLayer();
    } else if (!state.floorplan && href) {
        renderFloorplanLayer();
    }
    const clearButton = el("btn-map-floorplan-clear");
    if (clearButton) clearButton.classList.toggle("hidden", !state.floorplan);
}

// ============================================================================
// Interacción: arrastrar, desplazar y zoom
// ============================================================================

function canvasMetrics() {
    const rect = el("map-canvas").getBoundingClientRect();
    return { rect, unit: 1000 / Math.max(1, rect.width) };
}

function scenePoint(event) {
    const svg = el("map-canvas");
    const scene = el("scene");
    const point = svg.createSVGPoint();
    point.x = event.clientX;
    point.y = event.clientY;
    try {
        const local = point.matrixTransform(scene.getScreenCTM().inverse());
        return { x: local.x / 10, y: local.y / 10 };
    } catch (err) {
        return { x: 50, y: 50 };
    }
}

function onPointerDown(event) {
    const svg = el("map-canvas");
    const target = event.target;
    const nodeElement = target && target.closest ? target.closest(".node") : null;

    if (nodeElement) {
        const mac = nodeElement.dataset.mac;
        if (!state.byMac.has(mac)) return;
        state.dragging = { mac, moved: false, startX: event.clientX, startY: event.clientY };
        try { svg.setPointerCapture(event.pointerId); } catch (err) { /* opcional */ }
        event.preventDefault();
        return;
    }

    state.panning = { startX: event.clientX, startY: event.clientY, x: state.view.x, y: state.view.y };
    svg.classList.add("panning");
    try { svg.setPointerCapture(event.pointerId); } catch (err) { /* opcional */ }
}

function onPointerMove(event) {
    if (state.dragging) {
        const node = state.byMac.get(state.dragging.mac);
        if (!node) return;
        if (Math.abs(event.clientX - state.dragging.startX) > 3 ||
            Math.abs(event.clientY - state.dragging.startY) > 3) {
            state.dragging.moved = true;
        }
        const point = scenePoint(event);
        node.x = Math.max(2, Math.min(98, point.x));
        node.y = Math.max(2, Math.min(98, point.y));

        const group = el("map-nodes").querySelector(`[data-mac="${state.dragging.mac}"]`);
        if (group) {
            group.setAttribute("transform",
                `translate(${toUserUnits(node.x)}, ${toUserUnits(node.y)})`);
        }
        updateLinkPosition(node);
        return;
    }

    if (state.panning) {
        const { unit } = canvasMetrics();
        const scale = Math.max(0.2, state.view.k);
        state.view.x = state.panning.x + ((event.clientX - state.panning.startX) * unit) / scale;
        state.view.y = state.panning.y + ((event.clientY - state.panning.startY) * unit) / scale;
        applyView();
    }
}

function onPointerUp(event) {
    const svg = el("map-canvas");

    if (state.dragging) {
        const { mac, moved } = state.dragging;
        state.dragging = null;
        const node = state.byMac.get(mac);
        if (moved && node) {
            node.pinned = true;
            state.dirty.set(mac, [Number(node.x.toFixed(2)), Number(node.y.toFixed(2))]);
            scheduleSave();
        } else if (!moved) {
            selectDevice(mac);
        }
    }

    if (state.panning) {
        state.panning = null;
        svg.classList.remove("panning");
    }
    try { svg.releasePointerCapture(event.pointerId); } catch (err) { /* opcional */ }
}

function zoomBy(factor, anchorEvent) {
    const { rect, unit } = canvasMetrics();
    const anchorX = anchorEvent ? anchorEvent.clientX - rect.left : rect.width / 2;
    const anchorY = anchorEvent ? anchorEvent.clientY - rect.top : rect.height / 2;

    const previous = state.view.k;
    const next = Math.max(0.45, Math.min(3.5, previous * factor));
    if (next === previous) return;

    const pointX = (anchorX * unit - state.view.x) / previous;
    const pointY = (anchorY * unit - state.view.y) / previous;

    state.view.k = next;
    state.view.x = anchorX * unit - pointX * next;
    state.view.y = anchorY * unit - pointY * next;
    applyView();
}

function onWheel(event) {
    event.preventDefault();
    zoomBy(event.deltaY < 0 ? 1.15 : 1 / 1.15, event);
}

function resetView() {
    state.view = { k: 1, x: 0, y: 0 };
    applyView();
}

function centerOn(node) {
    const { rect } = canvasMetrics();
    const center = scenePoint({
        clientX: rect.left + rect.width / 2,
        clientY: rect.top + rect.height / 2
    });
    state.view.x += (center.x - node.x) * 10 * state.view.k;
    state.view.y += (center.y - node.y) * 10 * state.view.k;
    applyView();
}

function onDoubleClick(event) {
    const target = event.target;
    const nodeElement = target && target.closest ? target.closest(".node") : null;
    if (nodeElement && nodeElement.dataset.mac) {
        resetPositions(nodeElement.dataset.mac);
    }
}

// ============================================================================
// Guardado de posiciones y acciones
// ============================================================================

function scheduleSave() {
    if (state.saveTimer) clearTimeout(state.saveTimer);
    state.saveTimer = setTimeout(savePositions, 600);
}

async function savePositions() {
    if (!state.dirty.size) return;
    const positions = {};
    state.dirty.forEach((point, mac) => { positions[mac] = point; });
    state.dirty = new Map();

    try {
        const response = await apiFetch("/api/map/positions", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ positions })
        });
        const data = await response.json();
        if (data.success) {
            showToast("Posiciones guardadas",
                `${data.saved} dispositivo(s) colocados a mano.`, "success");
        }
    } catch (err) {
        showToast("Error", "No se pudieron guardar las posiciones.", "danger");
    }
}

async function resetPositions(mac) {
    try {
        const response = await apiFetch("/api/map/positions/reset", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(mac ? { mac } : {})
        });
        const data = await response.json();
        if (data.success) {
            showToast("Layout automático",
                mac ? "El dispositivo vuelve al reparto por anillos."
                    : `${data.reset} dispositivo(s) recolocados por tipo.`,
                "success");
            await loadMap();
        }
    } catch (err) {
        showToast("Error", "No se pudo recolocar.", "danger");
    }
}

async function uploadFloorplan(file) {
    const form = new FormData();
    form.append("file", file);
    try {
        const response = await apiFetch("/api/map/floorplan", { method: "POST", body: form });
        const data = await response.json();
        if (data.success) {
            state.floorplan = true;
            state.floorplanVersion = Date.now();
            showToast("Plano cargado",
                "Arrastra los dispositivos para situarlos sobre tu plano.", "success");
            await loadMap();
        }
    } catch (err) {
        showToast("Error", "No se pudo subir el plano.", "danger");
    }
}

async function clearFloorplan() {
    try {
        const response = await apiFetch("/api/map/floorplan", { method: "DELETE" });
        const data = await response.json();
        if (data.success) {
            state.floorplan = false;
            showToast("Plano quitado", "El mapa vuelve al fondo de rejilla.", "info");
            await loadMap();
        }
    } catch (err) {
        showToast("Error", "No se pudo quitar el plano.", "danger");
    }
}

async function acknowledgeDevice(mac) {
    try {
        await apiFetch(`/api/devices/${encodeURIComponent(mac)}/acknowledge`, { method: "POST" });
        showToast("Marcado como revisado", "El aviso de dispositivo nuevo se ha limpiado.", "success");
        await loadMap();
    } catch (err) {
        showToast("Error", "No se pudo marcar el dispositivo.", "danger");
    }
}

// ============================================================================
// Panel lateral del dispositivo seleccionado
// ============================================================================

function selectDevice(mac) {
    state.selected = mac;
    document.querySelectorAll(".node.selected").forEach((node) => node.classList.remove("selected"));
    const group = el("map-nodes").querySelector(`[data-mac="${mac}"]`);
    if (group) group.classList.add("selected");
    const node = state.byMac.get(mac);
    if (node) renderSidePanel(node);
}

function renderSidePanel(node) {
    const detail = el("side-detail");
    const empty = el("side-empty");
    if (!detail || !empty) return;

    const icon = TYPE_ICONS[node.device_type] || TYPE_ICONS.unknown;
    const status = statusClass(node);
    const statusText = node.is_blocked ? "Bloqueado"
        : (status === "online" ? "En línea" : "Desconectado");

    const badges = [
        `<span class="badge ${status}">${escapeHtml(statusText)}</span>`,
        `<span class="badge type">${icon} ${escapeHtml(node.device_type_label || "Desconocido")}</span>`
    ];
    if (node.os_guess) badges.push(`<span class="badge">${escapeHtml(node.os_guess)}</span>`);
    if (node.model) badges.push(`<span class="badge">${escapeHtml(node.model)}</span>`);
    if (node.is_new) badges.push('<span class="badge new">NUEVO</span>');
    if (node.pinned) badges.push('<span class="badge">📌 Posición manual</span>');

    const rows = [
        ["Nombre", node.custom_name || node.hostname || "—"],
        ["Dirección IP", node.ip || "—"],
        ["Dirección MAC", node.mac],
        ["Fabricante", node.vendor || "Desconocido"],
        ["Puertos", node.services || "—"],
        ["Nombre (origen)", node.name_source || "—"],
        ["Primera vez", node.first_seen || "—"],
        ["Última vez", node.last_seen || "—"]
    ];

    detail.innerHTML = `
        <div class="side-head">
            <div class="side-icon">${icon}</div>
            <div>
                <div class="side-title">${escapeHtml(node.custom_name || node.hostname || node.mac)}</div>
                <div class="side-sub">${escapeHtml(node.ip || "")}</div>
            </div>
        </div>
        <div class="side-badges">${badges.join("")}</div>
        <dl class="kv">
            ${rows.map(([key, value]) =>
                `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>`).join("")}
        </dl>
        <div class="side-actions">
            <button class="btn" data-action="center">🎯 Centrar</button>
            <button class="btn" data-action="reset">✨ Posición automática</button>
            ${node.is_new ? '<button class="btn" data-action="ack">✅ Marcar revisado</button>' : ""}
        </div>
        <div class="side-tip">
            Arrastra el dispositivo en el mapa para colocarlo donde quieras (se guarda solo).
            Haz doble clic sobre él para devolverlo al reparto automático.
        </div>
    `;
    detail.classList.remove("hidden");
    empty.classList.add("hidden");
}

function onSideAction(event) {
    const button = event.target.closest ? event.target.closest("button[data-action]") : null;
    if (!button || !state.selected) return;

    const node = state.byMac.get(state.selected);
    if (!node) return;

    const action = button.dataset.action;
    if (action === "center") centerOn(node);
    else if (action === "reset") resetPositions(node.mac);
    else if (action === "ack") acknowledgeDevice(node.mac);
}

// ============================================================================
// Arranque
// ============================================================================

function init() {
    const svg = el("map-canvas");
    svg.addEventListener("pointerdown", onPointerDown);
    svg.addEventListener("pointermove", onPointerMove);
    svg.addEventListener("pointerup", onPointerUp);
    svg.addEventListener("pointercancel", onPointerUp);
    svg.addEventListener("wheel", onWheel, { passive: false });
    svg.addEventListener("dblclick", onDoubleClick);

    el("btn-zoom-in").addEventListener("click", () => zoomBy(1.2));
    el("btn-zoom-out").addEventListener("click", () => zoomBy(1 / 1.2));
    el("btn-zoom-reset").addEventListener("click", resetView);
    el("btn-map-scan").addEventListener("click", triggerScan);
    el("btn-map-layout").addEventListener("click", () => resetPositions(null));
    el("btn-map-floorplan").addEventListener("click", () => el("floorplan-input").click());
    el("btn-map-floorplan-clear").addEventListener("click", clearFloorplan);

    el("floorplan-input").addEventListener("change", (event) => {
        const file = event.target.files && event.target.files[0];
        if (file) uploadFloorplan(file);
        event.target.value = "";
    });

    el("map-search").addEventListener("input", (event) => {
        state.query = event.target.value.trim().toLowerCase();
        render();
    });

    el("side-detail").addEventListener("click", onSideAction);

    document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") loadMap();
    });

    loadMap();
    setInterval(loadMap, POLL_MS);
}

document.addEventListener("DOMContentLoaded", init);