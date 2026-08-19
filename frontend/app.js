/**
 * Frontend de solo lectura.
 *
 * Vanilla JS a propósito: son cuatro fetch y una tabla, no hace falta traerse
 * un framework para eso.
 *
 * REGLA DE SEGURIDAD DE ESTE ARCHIVO: el contenido de los feeds es hostil. Un
 * nombre de víctima lo escribe un grupo de ransomware, no nosotros. Todo texto
 * que venga de la API se inserta con `textContent` — nunca `innerHTML`. Los
 * enlaces se validan antes de asignar el `href` (ver `safeHref`).
 */

const PAGE_SIZE = 50;
/** Días para considerar reciente un evento. Espeja LEAKS_FRESHNESS_DAYS. */
const FRESH_DAYS = 30;
/** Filas por página en la watchlist. */
const WL_PAGE_SIZE = 50;
/** Vistas válidas del router. La primera es el default. */
const VIEWS = [
  "hallazgos",
  "watchlist",
  "reglas",
  "fuentes",
  "sitios",
  "adyacentes",
  "telegram",
  "consola",
];
/** Filas por página en la lista de canales. */
const TG_PAGE_SIZE = 50;
/** Filas por página en el catálogo de sitios. */
const SITES_PAGE_SIZE = 50;
/** Cada cuánto se pregunta por actividad nueva. */
const CONSOLE_POLL_MS = 2000;

/** Cada cuánto se reverifica la IP de salida mientras está bloqueado. */
const BLOCK_RECHECK_MS = 10000;

const state = {
  blocked: false,
  offset: 0,
  total: 0,
  filters: {},
  editingAllowed: true,
  sourcesAlerted: false,
  view: "hallazgos",
  running: false,
  wlOffset: 0,
  wlTotal: 0,
  stOffset: 0,
  stTotal: 0,
  tgOffset: 0,
  tgTotal: 0,
  // Cursor de la consola: el id del último evento ya pintado.
  lastEventId: 0,
  consoleLines: 0,
  // Ids tildados para exportar. Es un Set y NO se limpia al paginar: la
  // gracia es poder juntar hallazgos de varias páginas en un solo informe.
  selected: new Set(),
  // Si el pipeline estuvo activo en el último poll, se refrescan los paneles.
  lastActivityAt: 0,
};

const $ = (id) => document.getElementById(id);

/**
 * GET a la API. Devuelve `null` si falla, para que un panel roto no rompa la
 * página.
 *
 * Los consumidores además tratan como opcional cada colección que reciben: una
 * respuesta con otra forma no puede rechazar una promesa y cortar la carga del
 * resto del tablero.
 */
async function api(path, params = {}) {
  const url = new URL(path, window.location.origin);
  for (const [k, v] of Object.entries(params)) {
    if (v !== "" && v !== null && v !== undefined) url.searchParams.set(k, v);
  }
  try {
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error(`Falló ${path}:`, err);
    return null;
  }
}

/** Crea un elemento con texto seguro y clases opcionales. */
function el(tag, text = "", className = "") {
  const node = document.createElement(tag);
  if (text !== null && text !== undefined && text !== "") node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

/**
 * Devuelve la URL solo si es http(s), y `null` si no.
 *
 * Los feeds traen enlaces .onion y a veces basura; un `javascript:` en un href
 * sería XSS directo. Se valida el esquema en vez de confiar.
 */
function safeHref(value) {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    // Un .onion llega como http:// y pasaría el filtro de esquema. No se
    // enlaza: es el sitio de extorsión, y llegar ahí no puede ser el resultado
    // de un click distraído (además, el navegador no lo va a resolver).
    if (url.hostname.endsWith(".onion")) return null;
    return url.href;
  } catch {
    return null;
  }
}

/** Hora local con segundos, para la consola. */
function fmtTime(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "--:--:--" : d.toTimeString().slice(0, 8);
}

/** Bytes legibles: 112406 -> "110 KB". */
function fmtBytes(n) {
  if (n === null || n === undefined) return null;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Reciente / histórico según los días transcurridos.
 *
 * El vocabulario coincide con el del filtro a propósito: si el chip dijera "4a"
 * y el filtro "histórico", el usuario no podría relacionarlos. A lo viejo se le
 * agrega la antigüedad, que es la información que de verdad importa.
 */
function freshnessLabel(iso) {
  const dias = (Date.now() - new Date(iso).getTime()) / 86400000;
  if (Number.isNaN(dias)) return { texto: "sin fecha", tono: "skipped" };
  if (dias <= FRESH_DAYS) return { texto: "reciente", tono: "ok" };
  if (dias <= 365) return { texto: "histórico", tono: "skipped" };
  return { texto: `histórico · ${Math.floor(dias / 365)}a`, tono: "skipped" };
}

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toISOString().slice(0, 10);
}

/* ---------------------------------------------------------------- Totales */

async function loadStats() {
  const stats = await api("/api/stats");
  const cont = $("stats");
  cont.replaceChildren();
  if (!stats) {
    cont.append(el("p", "No se pudieron cargar los totales.", "error"));
    return;
  }

  const sev = stats.by_severity || {};
  const tiles = [
    { label: "Hallazgos AR", value: stats.total, tone: "" },
    { label: "Críticos", value: sev.critical || 0, tone: "critical" },
    { label: "Altos", value: sev.high || 0, tone: "high" },
    { label: "Medios", value: sev.medium || 0, tone: "medium" },
    { label: "Último hallazgo", value: fmtDate(stats.latest_discovered_at), tone: "" },
  ];

  for (const t of tiles) {
    const card = el("div", "", `stat ${t.tone}`);
    card.append(el("div", t.value, "stat-value"), el("div", t.label, "stat-label"));
    cont.append(card);
  }
}

/* --------------------------------------------------------- Salud de feeds */

/**
 * Estado de las alertas.
 *
 * El caso que este panel existe para evitar: sin canales configurados el
 * pipeline descarta los avisos en silencio. Antes de esto, la única forma de
 * saber que había hallazgos críticos esperando a nadie era leer la base.
 */
async function loadAlerts() {
  const d = await api("/api/alerts");
  const estado = $("alerts-estado");
  const canales = $("alerts-canales");
  estado.replaceChildren();
  canales.replaceChildren();
  if (!d) return;

  const pendientes = d.pending ?? 0;

  if (!d.enabled) {
    // El estado que importa: apagadas Y con cosas esperando.
    estado.append(
      el("span", "sin canales", `pill pill-${pendientes ? "critical" : "medium"}`),
    );
    $("alerts-resumen").textContent = pendientes
      ? `${pendientes} hallazgos ${d.min_severity}+ están esperando un aviso que no se va a enviar. ` +
        "Configurá al menos un canal o esa señal se pierde."
      : "No hay ningún canal configurado: si aparece un hallazgo grave, nadie se entera.";
  } else {
    estado.append(
      el("span", `${d.sent_total ?? 0} enviadas`, "pill pill-ok"),
      el("span", `${pendientes} pendientes`, `pill pill-${pendientes ? "high" : "low"}`),
    );
    const ultima = d.last_sent_at ? `Última: ${fmtDate(d.last_sent_at)}.` : "Todavía sin enviar ninguna.";
    $("alerts-resumen").textContent =
      `Se avisa de ${d.min_severity} en adelante, de eventos de hasta ${d.max_age_days} días. ${ultima}`;
  }

  for (const c of d.channels || []) {
    const fila = el("div", "", `alert-canal ${c.configured ? "" : "alert-canal-off"}`);
    fila.append(
      el("span", c.configured ? "listo" : "falta", `pill pill-${c.configured ? "ok" : "skipped"}`),
      el("span", c.name, "alert-canal-nombre"),
    );
    if (!c.configured && (c.missing || []).length) {
      // Se nombra la variable, nunca su valor: un token no sale por la API.
      fila.append(el("code", c.missing.join(" · ")));
    }
    canales.append(fila);
  }
}

async function loadSources() {
  const sources = await api("/api/sources");

  const cont = $("sources");
  cont.replaceChildren();
  // `Array.isArray` y no solo `!sources`: una respuesta con otra forma haría
  // explotar el `.filter` de abajo, y un rechazo sin capturar corta la carga
  // del resto del tablero.
  if (!Array.isArray(sources)) {
    cont.append(el("p", "No se pudo consultar el estado de las fuentes.", "error"));
    return;
  }

  renderSourcesSummary(sources);

  for (const s of sources || []) {
    const run = s.last_run;
    const estado = run ? run.status : s.enabled ? "sin correr" : "deshabilitada";
    const card = el("div", "", `source source-${estado}`);

    const head = el("div", "", "source-head");
    head.append(el("strong", s.name), el("span", estado, `pill pill-${estado}`));
    card.append(head);

    if (run) {
      card.append(
        el("div", `${run.items_fetched} traídos · ${run.items_matched} AR · ${run.items_persisted} nuevos`, "hint"),
        el("div", `Última corrida: ${fmtDate(run.started_at)}`, "hint"),
      );
      if (run.error) card.append(el("div", run.error, "error"));
    } else if (s.skip_reason) {
      card.append(el("div", s.skip_reason, "hint"));
    }
    if (s.requires_pii) card.append(el("div", "Requiere STORE_PII=true", "hint"));

    cont.append(card);
  }
}

/* ----------------------------------------------------------- Filtro por actor */

/** Filtra por un actor y muestra el chip de filtro activo. */
function filtrarPorActor(actor) {
  state.filters = { ...state.filters, actor };
  state.offset = 0;
  renderActiveFilters();
  loadFindings();
  document.querySelector(".table-wrap").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

/**
 * Dibuja los filtros que no están en el formulario (hoy, el actor), con su ×
 * para sacarlos. Sin esto, un filtro por actor sería invisible y parecería que
 * faltan hallazgos.
 */
function renderActiveFilters() {
  const cont = $("active-filters");
  cont.replaceChildren();
  if (!state.filters.actor) return;

  const chip = el("span", "", "filter-chip");
  chip.append(el("span", "actor: ", "filter-chip-key"), el("strong", state.filters.actor));

  const quitar = el("button", "×", "filter-chip-x");
  quitar.type = "button";
  quitar.title = "Quitar el filtro de actor";
  quitar.addEventListener("click", () => {
    delete state.filters.actor;
    state.offset = 0;
    renderActiveFilters();
    loadFindings();
  });

  chip.append(quitar);
  cont.append(chip);
}

/**
 * Resumen de una línea para el encabezado colapsado.
 *
 * Estando cerrado igual tiene que verse si algo se cayó: si hay fuentes
 * fallidas, el panel se abre solo y no se vuelve a cerrar hasta que el usuario
 * lo cierre.
 */
function renderSourcesSummary(sources) {
  const ok = sources.filter((s) => s.last_run && s.last_run.status === "ok").length;
  const fallidas = sources.filter((s) => s.last_run && s.last_run.status === "failed").length;
  const apagadas = sources.filter((s) => !s.enabled).length;

  const cont = $("sources-summary");
  cont.replaceChildren();
  if (ok) cont.append(el("span", `${ok} ok`, "pill pill-ok"));
  if (fallidas) cont.append(el("span", `${fallidas} caídas`, "pill pill-failed"));
  if (apagadas) cont.append(el("span", `${apagadas} apagadas`, "pill pill-skipped"));

  // El menú avisa si hay fuentes caídas aunque estés en otra pantalla.
  const navBadge = $("nav-fuentes-badge");
  navBadge.textContent = fallidas ? String(fallidas) : "";
  navBadge.className = fallidas ? "nav-badge" : "";

  const panel = $("sources-panel");
  if (fallidas && !state.sourcesAlerted) {
    // Se abre una sola vez por incidente: si el usuario lo cierra, se respeta.
    state.sourcesAlerted = true;
    panel.open = true;
  }
  if (!fallidas) state.sourcesAlerted = false;
}

/* ------------------------------------------------------------- Filtros UI */

async function loadFilterOptions() {
  const opts = await api("/api/filters");
  if (!opts) return;
  const mapa = {
    "f-source": opts.sources,
    "f-sector": opts.sectors,
    "f-severity": opts.severities,
  };
  for (const [id, valores] of Object.entries(mapa)) {
    const select = $(id);
    const actual = select.value;
    // Se conserva la primera opción ("Todas") y se repuebla el resto.
    while (select.options.length > 1) select.remove(1);
    for (const v of valores || []) select.append(el("option", v));
    select.value = actual;
  }
}

/* ----------------------------------------------------------- Tabla de hallazgos */

function renderRow(f) {
  const tr = document.createElement("tr");

  // Casilla de selección. Refleja el Set global, así que una fila que ya
  // estaba tildada sigue tildada al volver a su página.
  const sel = el("td", "", "col-sel");
  const tilde = document.createElement("input");
  tilde.type = "checkbox";
  tilde.className = "sel-box";
  tilde.checked = state.selected.has(f.id);
  tilde.setAttribute("aria-label", `Seleccionar ${f.victim_name}`);
  tilde.addEventListener("change", () => {
    if (tilde.checked) state.selected.add(f.id);
    else state.selected.delete(f.id);
    renderSelection();
  });
  sel.append(tilde);
  tr.append(sel);

  // La fecha del EVENTO, no la de importación. Sin fecha se dice "sin fecha":
  // fingir una es lo que hacía ver el histórico como novedad del día.
  const cuando = el("td");
  if (f.occurred_at) {
    cuando.append(el("div", fmtDate(f.occurred_at)));
    const etiqueta = freshnessLabel(f.occurred_at);
    cuando.append(el("span", etiqueta.texto, `pill pill-${etiqueta.tono}`));
  } else {
    cuando.append(el("span", "sin fecha", "pill pill-skipped"));
  }
  if (f.backfill) {
    const marca = el("div", "importación inicial", "hint");
    marca.title = "Entró con el histórico de su fuente: no es una novedad.";
    cuando.append(marca);
  }
  cuando.title = [
    f.occurred_at ? `Ocurrió: ${fmtDate(f.occurred_at)} (según ${f.occurred_at_basis})` : "Sin fecha de evento",
    `Lo declaró el feed: ${fmtDate(f.discovered_at)}`,
    `Lo vimos: ${fmtDate(f.first_seen_at)}`,
  ].join("\n");
  tr.append(cuando);

  const victima = el("td");
  victima.append(el("div", f.victim_name, "victim-name"));
  if (f.victim_domain) victima.append(el("div", f.victim_domain, "victim-domain"));
  tr.append(victima);

  tr.append(el("td", f.sector || "—"));

  // Actor clickeable: filtra todos los hallazgos de ese grupo.
  const actor = el("td");
  if (f.actor) {
    const boton = el("button", f.actor, "linkish");
    boton.type = "button";
    boton.title = `Ver todos los hallazgos de ${f.actor}`;
    boton.addEventListener("click", () => filtrarPorActor(f.actor));
    actor.append(boton);
  } else {
    actor.append(el("span", "—"));
  }
  tr.append(actor, el("td", f.source));

  const sev = el("td");
  sev.append(el("span", f.severity, `pill pill-${f.severity}`));
  tr.append(sev);

  // La columna auditable: qué regla disparó el match argentino.
  const razones = el("td", "", "reasons");
  for (const r of f.ar_match_reason || []) {
    const detalle = (f.ar_match_detail || {})[r];
    const chip = el("span", r, "chip");
    if (detalle && detalle.length) chip.title = detalle.join(", ");
    razones.append(chip);
  }
  tr.append(razones);

  const ref = el("td");
  const href = safeHref(f.raw_ref);
  if (href) {
    const a = el("a", "ver");
    a.href = href;
    a.target = "_blank";
    // noopener/noreferrer: el destino puede ser un sitio de extorsión.
    a.rel = "noopener noreferrer nofollow";
    ref.append(a);
  } else if (f.raw_ref) {
    // .onion y demás: la dirección se muestra COMPLETA como texto, nunca como
    // enlace. Que no sea clickeable es deliberado —es el sitio de extorsión, y
    // el navegador tampoco lo resuelve sin Tor— pero ocultarla sería peor:
    // es justo el dato que el investigador necesita copiar.
    const code = document.createElement("code");
    code.className = "onion-ref";
    code.textContent = f.raw_ref;
    code.title =
      `${f.raw_ref}\n\n` +
      "No es un enlace a propósito. Copiá y pegá si necesitás abrirlo (requiere Tor).";
    ref.append(code);
  } else {
    ref.append(el("span", "—"));
  }
  tr.append(ref);

  // Columna de enlaces a los datos: un icono con el conteo, que abre el pop-up.
  const datos = el("td");
  const enlaces = f.download_links || [];
  if (enlaces.length) {
    const boton = el("button", "", "dl-btn");
    boton.type = "button";
    const conData = enlaces.filter((l) => l.kind === "data").length;
    boton.append(el("span", "📎", "dl-icon"), el("span", String(enlaces.length)));
    boton.title = `${enlaces.length} enlaces encontrados${conData ? ` (${conData} al volcado)` : ""}`;
    if (conData) boton.classList.add("dl-btn-data");
    boton.addEventListener("click", () => openDownloads(f));
    datos.append(boton);
  }

  // Exposición por infostealers: qué sistemas se comprometieron.
  const exp = f.exposure_detail;
  if (exp && (exp.urls || []).length) {
    const internos = (exp.urls || []).filter((u) => u.kind === "employee").length;
    const boton = el("button", "", "dl-btn");
    boton.type = "button";
    boton.append(el("span", "🔎", "dl-icon"), el("span", String(exp.urls.length)));
    boton.title = internos
      ? `${exp.urls.length} sistemas comprometidos (${internos} de empleados)`
      : `${exp.urls.length} sistemas comprometidos`;
    // Con credenciales de empleados se destaca: es acceso interno.
    if (internos) boton.classList.add("dl-btn-data");
    boton.addEventListener("click", () => openExposure(f));
    datos.append(boton);
  }

  if (!datos.children.length) datos.append(el("span", "—", "hint"));
  tr.append(datos);

  return tr;
}

/**
 * Pop-up con los enlaces a los datos filtrados.
 *
 * Las URLs se insertan con `textContent` dentro de un <code>, NUNCA como <a>.
 * Son punteros a volcados de datos y a infraestructura de quien los publicó:
 * que abrirlos requiera copiar y pegar es la idea, no una limitación.
 */
function openDownloads(f) {
  $("dl-victim").textContent = `${f.victim_name}${f.victim_domain ? ` · ${f.victim_domain}` : ""}`;

  const lista = $("dl-list");
  lista.replaceChildren();

  const etiquetas = { data: "volcado", sample: "muestra", unknown: "sin clasificar" };

  for (const link of f.download_links || []) {
    const fila = el("div", "", `dl-item dl-${link.kind}`);

    const cabecera = el("div", "", "dl-item-head");
    cabecera.append(
      el("span", etiquetas[link.kind] || link.kind, `pill pill-${link.kind === "data" ? "critical" : "low"}`),
    );

    const copiar = el("button", "Copiar", "btn dl-copy");
    copiar.type = "button";
    copiar.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(link.url);
        copiar.textContent = "Copiado";
      } catch {
        // Sin permiso de portapapeles: se selecciona para copiar a mano.
        const rango = document.createRange();
        rango.selectNodeContents(fila.querySelector("code"));
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(rango);
        copiar.textContent = "Seleccionado";
      }
      setTimeout(() => (copiar.textContent = "Copiar"), 1500);
    });
    cabecera.append(copiar);
    fila.append(cabecera);

    // textContent: la URL viene de un foro, es contenido hostil.
    const code = document.createElement("code");
    code.textContent = link.url;
    fila.append(code);

    lista.append(fila);
  }

  $("dl-modal").hidden = false;
}

function closeDownloads() {
  $("dl-modal").hidden = true;
}

/**
 * Pop-up con el detalle de exposición por infostealers.
 *
 * Las URLs son de sistemas del propio organismo, así que acá sí se pueden
 * enlazar… pero no se hace: son superficies de login comprometidas y el valor
 * está en leerlas, no en visitarlas. Se muestran como texto, igual que el
 * resto.
 */
function openExposure(f) {
  const exp = f.exposure_detail || {};
  $("exp-victim").textContent = `${f.victim_name}${f.victim_domain ? ` · ${f.victim_domain}` : ""}`;

  const resumen = $("exp-summary");
  resumen.replaceChildren();
  const urls = exp.urls || [];
  const internos = urls.filter((u) => u.kind === "employee");
  resumen.append(
    el("span", `${urls.length} sistemas`, "pill pill-low"),
    el(
      "span",
      `${internos.length} de empleados`,
      `pill pill-${internos.length ? "critical" : "low"}`,
    ),
  );
  if (exp.weak_password_pct) {
    resumen.append(el("span", `${exp.weak_password_pct}% contraseñas débiles`, "pill pill-high"));
  }

  const lista = $("exp-urls");
  lista.replaceChildren();
  for (const u of urls) {
    const fila = el("div", "", `dl-item ${u.kind === "employee" ? "dl-data" : "dl-sample"}`);
    const cab = el("div", "", "dl-item-head");
    cab.append(
      el("span", u.kind === "employee" ? "empleado" : "usuario",
         `pill pill-${u.kind === "employee" ? "critical" : "low"}`),
    );
    if (u.occurrences) cab.append(el("span", `${u.occurrences.toLocaleString()} capturas`, "hint"));
    fila.append(cab);
    const code = document.createElement("code");
    code.textContent = u.url;
    fila.append(code);
    lista.append(fila);
  }

  const fam = $("exp-families");
  fam.replaceChildren();
  for (const [nombre, n] of Object.entries(exp.stealer_families || {})) {
    fam.append(el("span", `${nombre} · ${n.toLocaleString()}`, "chip"));
  }
  if (!fam.children.length) fam.append(el("span", "sin datos", "hint"));

  const terceros = $("exp-third");
  terceros.replaceChildren();
  for (const d of exp.third_party_domains || []) terceros.append(el("span", d, "chip"));
  if (!terceros.children.length) terceros.append(el("span", "sin datos", "hint"));

  $("exp-modal").hidden = false;
}

function closeExposure() {
  $("exp-modal").hidden = true;
}

/* ------------------------------------------------- Selección y exportación */

/** Refresca el contador, los botones y la casilla de "toda la página". */
function renderSelection() {
  const n = state.selected.size;
  $("sel-count").textContent =
    n === 0
      ? "Ningún hallazgo seleccionado"
      : n === 1
        ? "1 hallazgo seleccionado"
        : `${n} hallazgos seleccionados`;
  $("sel-clear").disabled = n === 0;
  $("export-txt").disabled = n === 0;

  // La casilla del encabezado describe la página visible, no la selección
  // entera: marcarla con hallazgos tildados en OTRA página sería mentira.
  const cajas = Array.from(document.querySelectorAll("#findings-body .sel-box"));
  const marcadas = cajas.filter((c) => c.checked).length;
  const cabecera = $("sel-page");
  cabecera.checked = cajas.length > 0 && marcadas === cajas.length;
  cabecera.indeterminate = marcadas > 0 && marcadas < cajas.length;
}

/** Tilda o destilda todas las filas visibles, sin tocar el resto de la selección. */
function togglePagina(marcar) {
  for (const caja of document.querySelectorAll("#findings-body .sel-box")) {
    if (caja.checked !== marcar) {
      caja.checked = marcar;
      caja.dispatchEvent(new Event("change"));
    }
  }
}

function limpiarSeleccion() {
  state.selected.clear();
  for (const caja of document.querySelectorAll("#findings-body .sel-box")) caja.checked = false;
  renderSelection();
}

/**
 * Pide el informe TXT y lo baja.
 *
 * El archivo lo arma el backend: el frontend tiene solo la página que está
 * mirando, y la selección puede abarcar varias. Se manda la lista de ids y
 * vuelve el texto ya formateado.
 */
async function exportarSeleccion() {
  const ids = Array.from(state.selected);
  if (!ids.length) return;

  await conBotonOcupado($("export-txt"), "Exportar TXT", async () => {
    const res = await fetch(new URL("/api/findings/export", window.location.origin), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids }),
    });
    const exportados = await bajarInforme(res, "hallazgos.txt", "X-Findings-Exported", ids.length);

    // Un id puede haber desaparecido entre que se tildó y se pidió el archivo:
    // se avisa en vez de entregar un informe corto en silencio.
    setStatus(
      exportados < ids.length
        ? `Exportados ${exportados} de ${ids.length}: el resto ya no está en la base.`
        : `Informe con ${exportados} hallazgos descargado.`,
      exportados < ids.length ? "warn" : "ok",
    );
  });
  renderSelection();
}

/**
 * Exporta la watchlist con los filtros que estén puestos.
 *
 * Sin filtros baja entera, que es el caso normal. El informe declara en su
 * encabezado cuál se aplicó, así un TXT parcial no se confunde con el total.
 */
async function exportarWatchlist() {
  await conBotonOcupado($("wl-export"), "Exportar TXT", async () => {
    const url = new URL("/api/watchlist/export", window.location.origin);
    for (const [k, v] of Object.entries(wlFilters())) {
      if (v !== "" && v !== null && v !== undefined) url.searchParams.set(k, v);
    }
    const res = await fetch(url);
    const n = await bajarInforme(res, "watchlist.txt", "X-Watchlist-Exported", 0);
    setStatus(`Watchlist exportada: ${n} entradas.`, "ok");
  });
}

/** Deshabilita el botón mientras corre, y lo deja usable pase lo que pase. */
async function conBotonOcupado(boton, rotulo, tarea) {
  boton.disabled = true;
  boton.textContent = "Exportando…";
  try {
    await tarea();
  } catch (err) {
    setStatus(`No se pudo exportar: ${err.message || err}`, "error");
  } finally {
    boton.textContent = rotulo;
    boton.disabled = false;
  }
}

/**
 * Convierte la respuesta en una descarga. Devuelve cuántos ítems trajo.
 *
 * Los informes vuelven como texto, no como JSON: hay que mirar el header para
 * saber qué entró, porque el cuerpo es el archivo.
 */
async function bajarInforme(res, porDefecto, headerConteo, esperados) {
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error((data && data.detail) || `HTTP ${res.status}`);
  }
  const cantidad = Number(res.headers.get(headerConteo) || esperados);
  descargarBlob(await res.blob(), nombreDeArchivo(res) || porDefecto);
  return cantidad;
}

/** Nombre que propuso el backend en el Content-Disposition. */
function nombreDeArchivo(res) {
  const cabecera = res.headers.get("Content-Disposition") || "";
  const m = /filename="([^"]+)"/.exec(cabecera);
  // El nombre viene de nuestro backend, pero se sanea igual: es lo que va a
  // terminar escrito en el disco del investigador.
  return m ? m[1].replace(/[^A-Za-z0-9._-]/g, "_") : null;
}

function descargarBlob(blob, nombre) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = nombre;
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function loadFindings() {
  const body = $("findings-body");
  const page = await api("/api/findings", {
    ...state.filters,
    limit: PAGE_SIZE,
    offset: state.offset,
  });

  body.replaceChildren();
  if (!page) {
    const tr = document.createElement("tr");
    const td = el("td", "No se pudieron cargar los hallazgos.", "error");
    td.colSpan = 10;
    tr.append(td);
    body.append(tr);
    renderSelection();
    return;
  }

  state.total = page.total;
  if (!(page.items || []).length) {
    const tr = document.createElement("tr");
    const td = el("td", "Sin hallazgos para este filtro.", "empty");
    td.colSpan = 10;
    tr.append(td);
    body.append(tr);
  } else {
    for (const f of page.items || []) body.append(renderRow(f));
  }

  const desde = page.total === 0 ? 0 : state.offset + 1;
  const hasta = Math.min(state.offset + PAGE_SIZE, page.total);
  $("page-info").textContent = `${desde}–${hasta} de ${page.total}`;
  $("prev").disabled = state.offset === 0;
  $("next").disabled = hasta >= page.total;
  renderSelection();
}

/* -------------------------------------------------- Corridas y actualización */

/**
 * Dispara una corrida del pipeline.
 *
 * Hace falta un botón aparte de "Actualizar" porque son cosas distintas y
 * confundirlas fue justamente el problema: "Actualizar" relee la base, esto
 * sale a consultar las fuentes. Cambiar un toggle o la watchlist no dispara
 * nada por su cuenta — aplica en la próxima corrida, y esta es la forma de
 * pedirla sin esperar al horario.
 */
async function runNow() {
  if (state.running) return;

  const boton = $("run-now");
  boton.disabled = true;
  boton.textContent = "Iniciando…";

  const r = await apiWrite("/api/runs", "POST");
  if (!r.ok) {
    boton.disabled = false;
    boton.textContent = "Correr ahora";
    setStatus(`No se pudo iniciar: ${r.error}`, "error");
    return;
  }

  state.running = true;
  setStatus("Corrida en curso — el detalle se ve en la Consola.", "run");
  watchRun();
}

/** Sigue el estado de la corrida hasta que termina. */
async function watchRun() {
  const boton = $("run-now");
  boton.disabled = true;
  boton.textContent = "Corriendo…";

  const estado = await api("/api/runs/current");

  if (estado && estado.running) {
    setTimeout(watchRun, 2000);
    return;
  }

  state.running = false;
  boton.disabled = false;
  boton.textContent = "Correr ahora";

  if (!estado) {
    setStatus("Se perdió el estado de la corrida.", "error");
  } else if (estado.last_blocked_reason) {
    setStatus(estado.last_blocked_reason, "error");
  } else if (estado.last_error) {
    setStatus(`La corrida falló: ${estado.last_error}`, "error");
  } else {
    const nuevos = estado.last_total_new ?? 0;
    setStatus(
      nuevos ? `Corrida lista: ${nuevos} hallazgos nuevos.` : "Corrida lista: sin novedades.",
      "ok",
    );
  }

  // Se repinta con lo que haya quedado, haya novedades o no.
  await refreshData();
}

/** Mensaje corto al lado de los botones. Sin esto, todo parece no hacer nada. */
function setStatus(texto, tono = "") {
  const nodo = $("last-updated");
  nodo.textContent = texto;
  nodo.className = `last-updated last-updated-${tono}`;
}

/** "Actualizar": relee la base y lo dice, para que no parezca muerto. */
async function refreshNow() {
  const boton = $("refresh");
  boton.disabled = true;
  boton.textContent = "Actualizando…";

  await refreshAll();

  boton.disabled = false;
  boton.textContent = "Actualizar";
  setStatus(`Actualizado ${new Date().toLocaleTimeString()}`, "ok");
}

/* ------------------------------------------------------------------ Router */

/**
 * Navegación por pantallas, con hash (`#/watchlist`).
 *
 * Se eligió hash y no History API porque la app se sirve como archivo estático:
 * con rutas reales, recargar en `/watchlist` daría 404 salvo que el server
 * reescriba todo a index.html.
 *
 * Cada vista carga sus datos al entrar, no todas juntas al arrancar: entrar a
 * "Reglas" no tiene por qué disparar la consulta de hallazgos.
 */
function viewFromHash() {
  const nombre = (window.location.hash || "").replace(/^#\/?/, "");
  return VIEWS.includes(nombre) ? nombre : VIEWS[0];
}

function showView(nombre) {
  state.view = nombre;

  for (const seccion of document.querySelectorAll(".view")) {
    seccion.classList.toggle("is-active", seccion.dataset.view === nombre);
  }
  for (const enlace of document.querySelectorAll(".mainnav a")) {
    const activo = enlace.dataset.view === nombre;
    enlace.classList.toggle("is-active", activo);
    // aria-current: un lector de pantalla anuncia en qué sección está.
    if (activo) enlace.setAttribute("aria-current", "page");
    else enlace.removeAttribute("aria-current");
  }

  // Al cambiar de pantalla se vuelve arriba: si no, se entra a media página.
  window.scrollTo({ top: 0 });
  loadView(nombre);
}

/** Carga los datos de una vista. Barato de repetir: son consultas chicas. */
function loadView(nombre) {
  if (state.blocked) return;
  if (nombre === "hallazgos") return Promise.all([loadStats(), loadFilterOptions(), loadFindings()]);
  if (nombre === "watchlist") return loadWatchlist();
  if (nombre === "reglas") return loadRules();
  if (nombre === "fuentes") return Promise.all([loadSources(), loadAlerts()]);
  if (nombre === "sitios") return loadSites();
  if (nombre === "adyacentes") return loadAdjacency();
  if (nombre === "telegram") return loadTelegram();
  if (nombre === "consola") return pollEvents();
  return Promise.resolve();
}

/* ------------------------------------------------------- Canales de Telegram */

function tgFilters() {
  const estado = $("tg-f-enabled").value;
  return {
    q: $("tg-q").value.trim(),
    origin: $("tg-f-origin").value,
    ...(estado ? { enabled: estado } : {}),
  };
}

async function loadTelegram() {
  const datos = await api("/api/telegram", {
    ...tgFilters(),
    limit: TG_PAGE_SIZE,
    offset: state.tgOffset,
  });
  const body = $("tg-body");
  body.replaceChildren();
  if (!datos) return;

  const c = datos.counts || {};
  $("tg-counts").replaceChildren(
    el("span", `${c.enabled ?? 0} activos`, "pill pill-ok"),
    el("span", `${c.disabled ?? 0} apagados`, "pill pill-skipped"),
    el("span", `${c.user ?? 0} a mano`, "pill pill-low"),
  );

  state.tgTotal = datos.total ?? 0;
  const items = Array.isArray(datos.items) ? datos.items : [];
  if (!items.length) {
    const tr = document.createElement("tr");
    const td = el("td", "Sin canales para este filtro.", "empty");
    td.colSpan = 7;
    tr.append(td);
    body.append(tr);
  } else {
    for (const canal of items) body.append(filaCanal(canal));
  }

  const desde = state.tgTotal === 0 ? 0 : state.tgOffset + 1;
  const hasta = Math.min(state.tgOffset + TG_PAGE_SIZE, state.tgTotal);
  $("tg-page-info").textContent = `${desde}–${hasta} de ${state.tgTotal}`;
  $("tg-prev").disabled = state.tgOffset === 0;
  $("tg-next").disabled = hasta >= state.tgTotal;
}

function filaCanal(canal) {
  const tr = document.createElement("tr");

  const estado = el("td");
  const sw = el("label", "", "switch");
  const input = document.createElement("input");
  input.type = "checkbox";
  input.checked = canal.enabled;
  input.disabled = !state.editingAllowed;
  input.title = canal.enabled
    ? "Habilitado: se consulta en cada corrida."
    : "Deshabilitado: no se consulta.";
  input.addEventListener("change", async () => {
    const r = await apiWrite(`/api/telegram/${canal.id}`, "PATCH", { enabled: input.checked });
    if (!r.ok) {
      input.checked = !input.checked;
      $("tg-error").textContent = r.error;
    } else {
      setStatus("Canal actualizado — aplica en la próxima corrida.", "run");
      loadTelegram();
    }
  });
  sw.append(input);
  estado.append(sw);
  tr.append(estado);

  // La dirección se muestra como texto, nunca enlazada: es infraestructura de
  // quien publica los volcados, igual que los .onion de los hallazgos.
  const handle = el("td");
  const code = document.createElement("code");
  code.className = "onion-ref";
  code.textContent = `t.me/s/${canal.handle}`;
  code.title = "No es un enlace a propósito. Copiá y pegá si necesitás abrirlo.";
  handle.append(code);
  tr.append(handle);

  tr.append(el("td", canal.actor || "—"), el("td", canal.kind || "—"));

  const origen = el("td");
  origen.append(
    el("span", canal.origin === "user" ? "a mano" : "catálogo",
       `pill pill-${canal.origin === "user" ? "low" : "skipped"}`),
  );
  tr.append(origen);

  const cursor = el("td");
  if (canal.last_post_id) {
    cursor.append(el("span", canal.last_post_id, "hint"));
    cursor.title = canal.last_fetch_at ? `Última lectura: ${fmtDate(canal.last_fetch_at)}` : "";
  } else if (canal.last_error) {
    cursor.append(el("span", "error", "pill pill-critical"));
    cursor.title = canal.last_error;
  } else {
    cursor.append(el("span", "sin leer", "hint"));
  }
  tr.append(cursor);

  const acciones = el("td");
  const borrar = el("button", "Quitar", "btn btn-sm");
  borrar.type = "button";
  borrar.disabled = !state.editingAllowed;
  borrar.addEventListener("click", async () => {
    if (!confirm(`¿Quitar el canal ${canal.handle}?`)) return;
    const r = await apiWrite(`/api/telegram/${canal.id}`, "DELETE", null);
    if (!r.ok) $("tg-error").textContent = r.error;
    else loadTelegram();
  });
  acciones.append(borrar);
  tr.append(acciones);

  return tr;
}

async function agregarCanal(evento) {
  evento.preventDefault();
  $("tg-error").textContent = "";
  const cuerpo = {
    handle: $("tg-handle").value.trim(),
    actor: $("tg-actor").value.trim() || null,
    kind: $("tg-kind").value.trim() || null,
    notes: $("tg-notes").value.trim() || null,
    enabled: true,
  };
  if (!cuerpo.handle) return;

  const r = await apiWrite("/api/telegram", "POST", cuerpo);
  if (!r.ok) {
    $("tg-error").textContent = r.error;
    return;
  }
  for (const id of ["tg-handle", "tg-actor", "tg-kind", "tg-notes"]) $(id).value = "";
  setStatus("Canal agregado — se consulta en la próxima corrida.", "ok");
  loadTelegram();
}

async function importarCatalogo() {
  const boton = $("tg-import");
  boton.disabled = true;
  boton.textContent = "Importando…";
  const r = await apiWrite("/api/telegram/import", "POST", {});
  boton.textContent = "Importar catálogo";
  boton.disabled = false;
  if (!r.ok) {
    $("tg-error").textContent = r.error;
    return;
  }
  const d = r.data || {};
  setStatus(
    `${d.imported ?? 0} canales importados de ${d.available ?? 0} disponibles, deshabilitados.`,
    "ok",
  );
  loadTelegram();
}

/* ---------------------------------------------------------- Leaks adyacentes */

/** Nombre corto del componente, para el desglose. */
const ADJ_COMPONENTES = {
  alcance: "Alcance regional",
  recencia: "Actividad reciente",
  volumen: "Volumen de víctimas",
  tendencia: "Tendencia",
  proximidad: "Proximidad a AR",
  afinidad: "Afinidad sectorial",
};

/** Guarda los perfiles de la última carga, para abrir el desglose sin refetch. */
const adjCache = new Map();

async function loadAdjacency() {
  const datos = await api("/api/adjacency", { limit: 100 });
  const cand = $("adj-cand-body");
  const conf = $("adj-conf-body");
  cand.replaceChildren();
  conf.replaceChildren();
  if (!datos) return;

  adjCache.clear();

  $("adj-counts").replaceChildren(
    el("span", `${datos.total_candidatos ?? 0} candidatos`, "pill pill-high"),
    el("span", `${datos.total_confirmados ?? 0} confirmados`, "pill pill-critical"),
    el("span", `${datos.victimas_criticas ?? 0} críticas`, "pill pill-critical"),
    el("span", `${datos.victimas_regionales ?? 0} víctimas regionales`, "pill pill-low"),
  );

  renderCobertura(datos.cobertura || {});

  const candidatos = Array.isArray(datos.candidatos) ? datos.candidatos : [];
  if (!candidatos.length) {
    cand.append(filaVacia(7, "Sin candidatos: ¿corrió la adyacencia?"));
  } else {
    for (const a of candidatos) {
      adjCache.set(a.actor, a);
      cand.append(filaCandidato(a));
    }
  }

  renderCriticas(Array.isArray(datos.criticas) ? datos.criticas : []);

  const confirmados = Array.isArray(datos.confirmados) ? datos.confirmados : [];
  if (!confirmados.length) {
    conf.append(filaVacia(5, "Ningún actor de la región golpeó Argentina todavía."));
  } else {
    for (const a of confirmados) conf.append(filaConfirmado(a));
  }
}

function filaVacia(columnas, texto) {
  const tr = document.createElement("tr");
  const td = el("td", texto, "empty");
  td.colSpan = columnas;
  tr.append(td);
  return tr;
}

/**
 * El cartel de alcance.
 *
 * No es un descargo de responsabilidad de compromiso: son números medidos, y
 * sin ellos la lista afirma más de lo que sabe.
 */
function renderCobertura(c) {
  const cuerpo = $("adj-cobertura-cuerpo");
  cuerpo.replaceChildren();

  const total = (c.con_precursor ?? 0) + (c.sin_precursor ?? 0);
  const ciego = total ? Math.round((100 * (c.sin_precursor ?? 0)) / total) : 0;

  cuerpo.append(
    el(
      "p",
      `De ${total} actores que golpearon Argentina, ${c.sin_precursor ?? 0} la eligieron ` +
        `como su primera víctima latinoamericana: para ellos no hay actividad regional ` +
        `previa que puntuar. El score es ciego al ${ciego}% de los casos, y es ciego por ` +
        `construcción, no por estar mal calibrado.`,
      "hint",
    ),
    el(
      "p",
      `Sobre los ${c.con_precursor ?? 0} que sí dejaron rastro, funciona: el día que ` +
        `cruzaron estaban en el percentil ${c.percentil_mediano ?? 0} mediano del ranking, ` +
        `con ${c.anticipacion_mediana_dias ?? 0} días de anticipación mediana.`,
      "hint",
    ),
    el(
      "p",
      "Y hay un tercer límite que ningún score arregla: un actor que ninguna de " +
        "nuestras fuentes trackea no aparece acá. Eso se arregla sumando una fuente.",
      "hint",
    ),
    el("p", `Medido el ${c.medido_el || "—"}.`, "hint"),
  );
}

/**
 * La lista corta: infraestructura crítica regional.
 *
 * De ~1.350 víctimas regionales la mayoría son empresas privadas que no dicen
 * nada sobre el riesgo argentino. Éstas sí, y las que además vienen de un actor
 * que ya nos golpeó son la señal más fuerte de toda la sección.
 */
function renderCriticas(items) {
  const body = $("adj-crit-body");
  body.replaceChildren();
  if (!items.length) {
    body.append(filaVacia(5, "Ninguna infraestructura crítica regional en el período."));
    return;
  }

  for (const v of items) {
    const tr = document.createElement("tr");
    tr.append(el("td", v.occurred_at ? fmtDate(v.occurred_at) : "sin fecha"));

    const pais = el("td");
    pais.append(el("span", v.country, "pill pill-low"));
    tr.append(pais);

    tr.append(el("td", v.sector || "—"));

    const org = el("td");
    org.append(el("div", v.victim_name, "victim-name"));
    if (v.victim_domain) org.append(el("div", v.victim_domain, "victim-domain"));
    tr.append(org);

    const actor = el("td");
    const boton = el("button", v.actor, "linkish");
    boton.type = "button";
    boton.title = `Ver los hallazgos argentinos de ${v.actor}`;
    boton.addEventListener("click", () => filtrarPorActor(v.actor));
    actor.append(boton);
    if (v.actor_hit_ar) {
      const chip = el("span", "ya nos golpeó", "pill pill-critical");
      chip.title = "Este actor tiene víctimas argentinas registradas.";
      actor.append(chip);
    }
    tr.append(actor);

    if (v.actor_hit_ar) tr.classList.add("adj-fila-critica");
    body.append(tr);
  }
}

function filaCandidato(a) {
  const tr = document.createElement("tr");

  const actor = el("td");
  const boton = el("button", a.actor, "linkish");
  boton.type = "button";
  boton.title = `Ver de dónde sale el score de ${a.actor}`;
  boton.addEventListener("click", () => openAdjacency(a.actor));
  actor.append(boton);
  tr.append(actor);

  // Barra + número: el número solo no da idea de la escala.
  const score = el("td");
  const barra = el("div", "", "adj-bar");
  const relleno = el("div", "", "adj-bar-fill");
  relleno.style.width = `${Math.max(0, Math.min(100, a.score || 0))}%`;
  barra.append(relleno);
  score.append(el("div", (a.score ?? 0).toFixed(1), "adj-score"), barra);
  tr.append(score);

  const variacion = el("td");
  if (a.variacion === null || a.variacion === undefined || a.variacion === 0) {
    variacion.append(el("span", "—", "hint"));
  } else {
    const sube = a.variacion > 0;
    const chip = el("span", `${sube ? "↑" : "↓"}${Math.abs(a.variacion).toFixed(1)}`,
                    `pill pill-${sube ? "critical" : "low"}`);
    chip.title = `Corrida anterior: ${(a.score_prev ?? 0).toFixed(1)}`;
    variacion.append(chip);
  }
  tr.append(variacion);

  tr.append(el("td", a.victims_total ?? 0));

  const paises = el("td");
  const lista = a.countries || [];
  paises.append(el("span", String(lista.length)));
  paises.title = lista.join(", ");
  tr.append(paises);

  tr.append(el("td", a.last_seen ? fmtDate(a.last_seen) : "—"));

  // La confianza se muestra aparte del score: un número alto con poca
  // evidencia tiene que poder verse como tal.
  const conf = el("td");
  const c = (a.score_breakdown || {}).confianza;
  if (typeof c === "number") {
    const chip = el("span", c < 0.6 ? "poca evidencia" : "sostenido", `pill pill-${c < 0.6 ? "medium" : "ok"}`);
    chip.title = `Confianza ${c} — atenúa los componentes que son ratios.`;
    conf.append(chip);
  }
  tr.append(conf);

  return tr;
}

function filaConfirmado(a) {
  const tr = document.createElement("tr");

  const actor = el("td");
  const boton = el("button", a.actor, "linkish");
  boton.type = "button";
  boton.title = `Ver los hallazgos argentinos de ${a.actor}`;
  boton.addEventListener("click", () => filtrarPorActor(a.actor));
  actor.append(boton);
  tr.append(actor);

  const ar = el("td");
  ar.append(el("span", String(a.ar_victims ?? 0), "pill pill-critical"));
  tr.append(ar);

  tr.append(el("td", a.victims_total ?? 0));

  const paises = el("td");
  const lista = a.countries || [];
  paises.append(el("span", String(lista.length)));
  paises.title = lista.join(", ");
  tr.append(paises, el("td", a.last_seen ? fmtDate(a.last_seen) : "—"));

  return tr;
}

/** Pop-up con el desglose: por qué el score es ese y no otro. */
function openAdjacency(nombre) {
  const a = adjCache.get(nombre);
  if (!a) return;

  $("adj-actor").textContent = `${a.actor} · ${a.victims_total} víctimas en ${(a.countries || []).length} países`;

  const resumen = $("adj-summary");
  resumen.replaceChildren(
    el("span", `score ${(a.score ?? 0).toFixed(1)} / 100`, "pill pill-high"),
  );
  const conf = (a.score_breakdown || {}).confianza;
  if (typeof conf === "number") {
    resumen.append(el("span", `confianza ${conf}`, `pill pill-${conf < 0.6 ? "medium" : "ok"}`));
  }

  const cont = $("adj-breakdown");
  cont.replaceChildren();
  for (const [clave, etiqueta] of Object.entries(ADJ_COMPONENTES)) {
    const puntos = (a.score_breakdown || {})[clave];
    if (typeof puntos !== "number") continue;
    const fila = el("div", "", "adj-comp");
    fila.append(el("span", etiqueta, "adj-comp-name"));
    const barra = el("div", "", "adj-bar");
    const relleno = el("div", "", "adj-bar-fill");
    // Relativo al total, para que se vea qué componente domina.
    relleno.style.width = `${Math.max(0, Math.min(100, (puntos / Math.max(1, a.score)) * 100))}%`;
    barra.append(relleno);
    fila.append(barra, el("span", puntos.toFixed(1), "adj-comp-val"));
    cont.append(fila);
  }
  if (typeof conf === "number") {
    const nota = el(
      "p",
      "La confianza no suma puntos: atenúa recencia, tendencia, proximidad y " +
        "afinidad, que son ratios que un solo dato satura.",
      "hint",
    );
    cont.append(nota);
  }

  const paises = $("adj-paises");
  paises.replaceChildren();
  for (const cc of a.countries || []) paises.append(el("span", cc, "chip"));
  if (!paises.children.length) paises.append(el("span", "sin datos", "hint"));

  $("adj-modal").hidden = false;
}

function closeAdjacency() {
  $("adj-modal").hidden = true;
}

/* ------------------------------------------------ Reglas y watchlist (CRUD) */

/** POST/PATCH/DELETE contra la API. Devuelve {ok, data, error}. */
async function apiWrite(path, method, body) {
  try {
    const res = await fetch(new URL(path, window.location.origin), {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 204) return { ok: true, data: null };
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      // FastAPI manda el motivo en `detail`; puede ser string o lista.
      const detalle = data && data.detail;
      const msg = Array.isArray(detalle)
        ? detalle.map((d) => d.msg || "").join("; ")
        : detalle || `HTTP ${res.status}`;
      return { ok: false, error: String(msg) };
    }
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

/** Dibuja las 5 reglas con su interruptor. */
async function loadRules() {
  const datos = await api("/api/rules");
  const cont = $("rules");
  cont.replaceChildren();
  if (!datos) return;

  state.editingAllowed = datos.editing_allowed;

  for (const regla of datos.rules || []) {
    const fila = el("div", "", `rule ${regla.enabled ? "" : "rule-off"}`);

    const label = el("label", "", "switch switch-lg");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = regla.enabled;
    input.disabled = !datos.editing_allowed;
    input.addEventListener("change", async () => {
      const r = await apiWrite(`/api/rules/${regla.name}`, "PATCH", { enabled: input.checked });
      if (!r.ok) {
        input.checked = !input.checked;
        alert(`No se pudo cambiar la regla: ${r.error}`);
      } else {
        setStatus("Regla actualizada — aplica en la próxima corrida.", "run");
      }
      loadRules();
    });
    label.append(input, el("span", regla.name, "rule-name"));
    fila.append(label, el("p", regla.description, "hint"));
    cont.append(fila);
  }

  renderPiiControl(datos);
}

/**
 * Pinta la pastilla y el interruptor de PII con el estado REALMENTE vigente.
 *
 * Son dos cosas distintas y la pastilla tiene que decir cuál está viendo:
 *
 * * `pii_sources_enabled` — si las fuentes con PII corren. Es el toggle, se
 *   guarda en la base y es lo que el usuario cambia acá.
 * * `pii_storage_available` — si además se puede *persistir* PII cifrada. Eso
 *   depende de la clave en el entorno y no se puede cambiar desde la UI.
 *
 * Antes la pastilla mostraba el segundo valor y el interruptor cambiaba el
 * primero, así que quedaba clavada en OFF por más que se prendieran las
 * fuentes.
 */
function renderPiiControl(datos) {
  const badge = $("pii-badge");
  const pii = $("pii-sources");
  const control = $("pii-control");

  pii.checked = Boolean(datos.pii_sources_enabled);
  pii.disabled = !datos.editing_allowed;
  control.classList.toggle("is-on", pii.checked);

  if (!datos.pii_sources_enabled) {
    badge.textContent = "PII: OFF";
    badge.className = "badge badge-ok";
  } else if (datos.pii_storage_available) {
    badge.textContent = "PII: ON · cifrada";
    badge.className = "badge badge-warn";
  } else {
    // Estado intermedio real: las fuentes corren pero la PII se descarta.
    badge.textContent = "PII: fuentes ON · sin guardar";
    badge.className = "badge badge-warn";
  }

  const nota = datos.pii_storage_available
    ? "Con clave de cifrado configurada: los registros con PII se guardan cifrados y con retención."
    : "Sin clave de cifrado en el entorno: estas fuentes corren, pero la PII se descarta y solo se guarda metadata. Para persistirla hacen falta LEAKS_STORE_PII=true y LEAKS_PII_ENCRYPTION_KEY.";
  $("pii-toggle-note").textContent = nota;
  $("pii-switch").title = `${badge.textContent} — ${nota}`;

  pii.onchange = async () => {
    const r = await apiWrite("/api/settings/pii-sources", "PATCH", { enabled: pii.checked });
    if (!r.ok) {
      pii.checked = !pii.checked;
      alert(`No se pudo cambiar: ${r.error}`);
      return;
    }
    // Se repinta con lo que devolvió el servidor, no con lo que asumimos.
    renderPiiControl(r.data);
    loadSources();
    // El cambio no consulta nada por su cuenta: aplica en la próxima corrida.
    setStatus(
      pii.checked
        ? 'Fuentes con PII habilitadas — aplican en la próxima corrida ("Correr ahora").'
        : "Fuentes con PII deshabilitadas — aplica en la próxima corrida.",
      "run",
    );
  };
}

/** Lee los filtros de la tabla de watchlist. */
function wlFilters() {
  const estado = $("wl-f-enabled").value;
  return {
    q: $("wl-q").value.trim(),
    kind: $("wl-f-kind").value,
    ...(estado ? { enabled: estado } : {}),
  };
}

async function loadWatchlist() {
  const datos = await api("/api/watchlist", {
    ...wlFilters(),
    limit: WL_PAGE_SIZE,
    offset: state.wlOffset,
  });
  const body = $("wl-body");
  body.replaceChildren();
  if (!datos) return;

  const c = datos.counts;
  $("wl-counts").replaceChildren(
    el("span", `${c.enabled} activas`, "pill pill-ok"),
    el("span", `${c.disabled} deshabilitadas`, "pill pill-skipped"),
    el("span", `${c.domains} dominios`, "chip"),
    el("span", `${c.keywords} keywords`, "chip"),
  );

  // Autocompletado de sectores en el alta.
  const lista = $("wl-sectors");
  lista.replaceChildren();
  for (const sector of datos.sectors || []) lista.append(el("option", sector));

  state.wlTotal = datos.total;
  renderWlPager();

  if (!(datos.items || []).length) {
    const tr = document.createElement("tr");
    const td = el("td", "Sin entradas para este filtro.", "empty");
    td.colSpan = 7;
    tr.append(td);
    body.append(tr);
    return;
  }

  for (const e of datos.items || []) {
    const tr = document.createElement("tr");
    if (!e.enabled) tr.className = "row-off";

    // Estado: interruptor que habilita/deshabilita y persiste.
    const estado = el("td");
    const sw = document.createElement("input");
    sw.type = "checkbox";
    sw.checked = e.enabled;
    sw.disabled = !state.editingAllowed;
    sw.title = e.enabled ? "Deshabilitar (deja de matchear)" : "Habilitar";
    sw.addEventListener("change", async () => {
      const r = await apiWrite(`/api/watchlist/${e.id}`, "PATCH", { enabled: sw.checked });
      if (!r.ok) {
        sw.checked = !sw.checked;
        alert(`No se pudo cambiar: ${r.error}`);
      }
      loadWatchlist();
    });
    estado.append(sw);
    tr.append(estado);

    tr.append(el("td", e.kind === "domain" ? "dominio" : "keyword"));

    const valor = el("td");
    valor.append(el("span", e.value, "wl-value"));
    if (e.kind === "domain") valor.append(el("div", "cubre subdominios", "hint"));
    tr.append(valor);

    tr.append(el("td", e.sector), el("td", e.critical ? "sí" : "—"), el("td", e.origin));

    const acciones = el("td");
    const borrar = el("button", "eliminar", "btn btn-danger");
    borrar.type = "button";
    borrar.disabled = !state.editingAllowed;
    borrar.addEventListener("click", async () => {
      if (!confirm(`¿Eliminar ${e.value} de la watchlist?\n\nSi es temporal, mejor deshabilitala.`)) return;
      const r = await apiWrite(`/api/watchlist/${e.id}`, "DELETE");
      if (!r.ok) alert(`No se pudo eliminar: ${r.error}`);
      loadWatchlist();
    });
    acciones.append(borrar);
    tr.append(acciones);

    body.append(tr);
  }
}

/** Controles de paginación de la watchlist. */
function renderWlPager() {
  const desde = state.wlTotal === 0 ? 0 : state.wlOffset + 1;
  const hasta = Math.min(state.wlOffset + WL_PAGE_SIZE, state.wlTotal);
  $("wl-page-info").textContent = `${desde}–${hasta} de ${state.wlTotal}`;
  $("wl-prev").disabled = state.wlOffset === 0;
  $("wl-next").disabled = hasta >= state.wlTotal;
}

/* ------------------------------------------------------ Catálogo de sitios */

function stFilters() {
  const estado = $("st-available").value;
  return {
    q: $("st-q").value.trim(),
    kind: $("st-kind").value,
    ...(estado ? { available: estado } : {}),
    ...($("st-ar").checked ? { ar_only: "true" } : {}),
  };
}

/**
 * Catálogo de dónde vive cada sitio de leaks.
 *
 * Las direcciones se muestran como texto, nunca como enlace: son sitios de
 * extorsión, y además la mayoría son `.onion` que el navegador no resuelve.
 * El prototipo tampoco las visita — esto es un catálogo consolidado de lo que
 * publican los registros públicos.
 */
async function loadSites() {
  const datos = await api("/api/sites", {
    ...stFilters(),
    limit: SITES_PAGE_SIZE,
    offset: state.stOffset,
  });

  const body = $("sites-body");
  body.replaceChildren();
  if (!datos) return;

  const c = datos.counts || {};
  $("sites-counts").replaceChildren(
    el("span", `${c.available || 0} en línea`, "pill pill-ok"),
    el("span", `${c.offline || 0} caídos`, "pill pill-skipped"),
    el("span", `${c.groups || 0} grupos`, "chip"),
  );

  // Mudanzas recientes: es la señal por la que existe esta pantalla.
  const moves = $("sites-moves");
  moves.replaceChildren();
  const recientes = datos.recent_moves || [];
  if (recientes.length) {
    const caja = el("div", "", "moves-box");
    caja.append(
      el("strong", `${recientes.length} direcciones nuevas en los últimos 7 días`),
      el(
        "p",
        "Un grupo que estrena dominio suele estar por publicar. Los que ya golpearon " +
          "en Argentina van primero.",
        "hint",
      ),
    );
    const lista = el("div", "", "moves-list");
    for (const m of recientes.slice(0, 8)) {
      const fila = el("div", "", `moves-item ${m.ar_findings ? "moves-ar" : ""}`);
      fila.append(el("span", m.group_name, "moves-group"));
      if (m.ar_findings) fila.append(el("span", `${m.ar_findings} AR`, "pill pill-critical"));
      const dir = document.createElement("code");
      dir.textContent = m.fqdn;
      fila.append(dir);
      lista.append(fila);
    }
    caja.append(lista);
    moves.append(caja);
  }

  state.stTotal = datos.total || 0;
  renderStPager();

  if (!(datos.items || []).length) {
    const tr = document.createElement("tr");
    const td = el("td", "Sin sitios para este filtro. Corré el pipeline para poblarlo.", "empty");
    td.colSpan = 6;
    tr.append(td);
    body.append(tr);
    return;
  }

  for (const sitio of datos.items) {
    const tr = document.createElement("tr");
    if (!sitio.available) tr.className = "row-off";

    const grupo = el("td");
    grupo.append(el("span", sitio.group_name));
    if (sitio.ar_findings) {
      // El cruce que le da sentido operativo: este grupo ya golpeó acá.
      const marca = el("span", `${sitio.ar_findings} AR`, "pill pill-critical");
      marca.title = `${sitio.ar_findings} hallazgos argentinos atribuidos a este grupo`;
      grupo.append(marca);
    }
    tr.append(grupo);

    // Dirección como texto seleccionable, nunca enlazada.
    const dir = el("td");
    const code = document.createElement("code");
    code.textContent = sitio.fqdn;
    code.className = "site-fqdn";
    dir.append(code);
    if (sitio.title) dir.append(el("div", sitio.title, "hint"));
    tr.append(dir);

    tr.append(el("td", sitio.kind));

    const estado = el("td");
    estado.append(
      el("span", sitio.available ? "en línea" : "caído",
         `pill pill-${sitio.available ? "ok" : "skipped"}`),
    );
    tr.append(estado);

    tr.append(el("td", fmtDate(sitio.first_seen_at)));

    const fuentes = el("td");
    fuentes.append(el("div", (sitio.sources || []).join(", ")));
    // Se dice de dónde sale el estado y cuándo lo revisaron. Si el registro no
    // publica la fecha, se dice eso también en vez de inventar frescura.
    fuentes.append(
      el(
        "div",
        sitio.checked_at ? `revisado ${fmtDate(sitio.checked_at)}` : "sin fecha de revisión",
        "hint",
      ),
    );
    tr.append(fuentes);

    body.append(tr);
  }
}

function renderStPager() {
  const desde = state.stTotal === 0 ? 0 : state.stOffset + 1;
  const hasta = Math.min(state.stOffset + SITES_PAGE_SIZE, state.stTotal);
  $("st-page-info").textContent = `${desde}–${hasta} de ${state.stTotal}`;
  $("st-prev").disabled = state.stOffset === 0;
  $("st-next").disabled = hasta >= state.stTotal;
}

/* --------------------------------------------------------- Bloqueo de OPSEC */

/**
 * Muestra u oculta el bloqueo por IP de salida.
 *
 * Mientras está bloqueado se corta TODA la actividad del frontend: no se
 * poletea la consola ni se recargan paneles. El bloqueo real igual está en el
 * pipeline — esto evita además que el tablero siga pidiendo datos.
 *
 * No hay forma de cerrarlo: sale solo cuando la IP de salida deja de estar
 * bloqueada.
 */
function applyBlock(info) {
  const modal = $("egress-block");
  const bloqueado = Boolean(info && info.blocked);

  if (!bloqueado) {
    if (state.blocked) {
      // Se liberó: se recarga todo lo que quedó viejo durante el bloqueo.
      state.blocked = false;
      modal.hidden = true;
      document.body.classList.remove("is-blocked");
      refreshAll();
    }
    return;
  }

  state.blocked = true;
  modal.hidden = false;
  // Bloquea el scroll del fondo: el modal es la única superficie activa.
  document.body.classList.add("is-blocked");

  $("blocker-reason").textContent = info.block_reason || "Salida no permitida.";
  $("blocker-ip").textContent = info.ip || "no resuelta";
  $("blocker-country").textContent = info.country
    ? `${info.country}${info.country_name ? ` — ${info.country_name}` : ""}`
    : "indeterminado";
  $("blocker-org").textContent = info.org || "—";
}

// El modal no se cierra con ESC. Se captura en fase de captura para ganarle a
// cualquier otro handler.
// Botón "Reintentar ahora": fuerza el re-chequeo sin esperar los 10 s.
$("blocker-retry-btn").addEventListener("click", async () => {
  const boton = $("blocker-retry-btn");
  const nota = $("blocker-retry");
  boton.disabled = true;
  boton.textContent = "Verificando…";
  nota.textContent = "Consultando la IP de salida…";

  await loadEgress(true);

  boton.disabled = false;
  boton.textContent = "Reintentar ahora";
  // Si sigue bloqueado, `applyBlock` dejó el motivo actualizado arriba.
  nota.textContent = state.blocked
    ? `Sigue bloqueado — último intento ${new Date().toLocaleTimeString()}`
    : "Desbloqueado.";
});

document.addEventListener(
  "keydown",
  (e) => {
    if (state.blocked && (e.key === "Escape" || e.key === "Enter")) {
      e.preventDefault();
      e.stopPropagation();
    }
  },
  true,
);

/* ------------------------------------------------------- IP de salida (VPN) */

/**
 * Muestra desde qué IP pública sale el tráfico, con país y proveedor.
 *
 * Es un control de operación: antes de consultar feeds de este rubro conviene
 * confirmar que se está saliendo por la VPN que uno cree.
 */
async function loadEgress(force = false) {
  const badge = $("egress-badge");
  const texto = $("egress-text");

  // `force` no es un override: obliga a volver a preguntar la IP. Solo
  // desbloquea si realmente cambió.
  const info = await api("/api/egress", force ? { force: "true" } : {});

  // El veredicto de bloqueo se aplica siempre, incluso si la consulta falló:
  // sin respuesta no se puede afirmar que la salida sea segura.
  applyBlock(info || { blocked: true, block_reason: "No se pudo verificar la IP de salida." });

  if (!info || !info.ip) {
    texto.textContent = "IP de salida: desconocida";
    badge.className = "badge badge-warn";
    badge.title = "No se pudo resolver la IP de salida. ¿Hay conectividad?";
    return;
  }

  const partes = [info.ip];
  if (info.country) partes.push(info.country);
  texto.textContent = partes.join(" · ");

  badge.className = info.blocked ? "badge badge-blocked" : "badge badge-egress";
  badge.title = [
    `IP de salida: ${info.ip}`,
    info.country_name ? `País: ${info.country_name} (${info.country})` : null,
    info.city ? `Ciudad: ${info.city}` : null,
    info.org ? `Proveedor: ${info.org}` : null,
    info.checked_at ? `Consultado: ${new Date(info.checked_at).toLocaleString()}` : null,
    "Verificá que coincida con tu VPN.",
  ]
    .filter(Boolean)
    .join("\n");

  // La bandera del país hace el chequeo visual de un vistazo.
  const flag = badge.querySelector(".egress-flag");
  if (flag && info.country && /^[A-Za-z]{2}$/.test(info.country)) {
    flag.textContent = String.fromCodePoint(
      ...[...info.country.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65),
    );
  }
}

/* --------------------------------------------------- Consola de actividad */

/**
 * Pinta una línea de la consola.
 *
 * Igual que la tabla: todo texto va por `textContent`. La URL de un evento la
 * decide nuestro pipeline, pero no se enlaza igual — es para leer, no para
 * navegar a un sitio de extorsión por accidente.
 */
function renderEvent(ev) {
  const line = el("div", "", `cline cline-${ev.level}`);

  line.append(el("span", fmtTime(ev.occurred_at), "cline-time"));
  line.append(el("span", ev.source || "pipeline", "cline-source"));

  const cuerpo = el("span", "", "cline-msg");
  cuerpo.append(el("span", ev.message));

  // Detalles a la derecha: estado HTTP, duración y tamaño.
  const partes = [];
  if (ev.status_code) partes.push(String(ev.status_code));
  if (ev.duration_ms !== null && ev.duration_ms !== undefined) {
    partes.push(ev.duration_ms >= 1000 ? `${(ev.duration_ms / 1000).toFixed(1)}s` : `${ev.duration_ms}ms`);
  }
  const tam = fmtBytes(ev.bytes_received);
  if (tam) partes.push(tam);
  if (partes.length) cuerpo.append(el("span", ` · ${partes.join(" · ")}`, "cline-meta"));

  line.append(cuerpo);
  return line;
}

function setConsoleStatus(texto, clase) {
  const badge = $("console-status");
  badge.textContent = texto;
  badge.className = `pill pill-${clase}`;
}

/**
 * Trae la actividad nueva y la agrega abajo.
 *
 * Nunca se descarta nada de lo ya pintado: "Limpiar" es la única forma de
 * vaciar la consola, y solo afecta a la vista (la bitácora sigue en la base).
 */
async function pollEvents() {
  // Bloqueado: no se consulta nada más que la IP de salida.
  if (state.blocked) return;

  const page = await api("/api/events", { after_id: state.lastEventId, limit: 500 });
  if (!page) {
    setConsoleStatus("sin conexión", "failed");
    return;
  }

  if ((page.items || []).length) {
    const consola = $("console");
    // La consola crece hacia arriba: lo más reciente queda primero. El ancla
    // pasa a ser el tope, no el final.
    const pegadoArriba = consola.scrollTop < 40;
    const altoAntes = consola.scrollHeight;

    // La API devuelve ascendente por id; se invierte para que dentro del lote
    // el más nuevo quede arriba, y el lote entero se antepone.
    const lote = document.createDocumentFragment();
    for (const ev of [...(page.items || [])].reverse()) lote.append(renderEvent(ev));
    consola.prepend(lote);

    state.lastEventId = page.last_id;
    state.consoleLines += page.items.length;
    state.lastActivityAt = Date.now();
    $("console-count").textContent = `${state.consoleLines} líneas`;

    if ($("console-follow").checked && pegadoArriba) {
      consola.scrollTop = 0;
    } else {
      // Si estaba leyendo más abajo, se compensa el alto agregado para que no
      // se le mueva la línea que estaba mirando.
      consola.scrollTop += consola.scrollHeight - altoAntes;
    }

    // Si el pipeline terminó una corrida, los paneles quedaron viejos.
    if ((page.items || []).some((e) => e.kind === "run_done")) {
      refreshData();
    }
  }

  const activo = Date.now() - state.lastActivityAt < 15000;
  setConsoleStatus(activo ? "activo" : "en espera", activo ? "ok" : "skipped");
}

/* ------------------------------------------------------------------ Eventos */

function readFilters() {
  const since = $("f-since").value;
  const until = $("f-until").value;
  return {
    // El actor no está en el formulario: se conserva el que haya activo.
    ...(state.filters.actor ? { actor: state.filters.actor } : {}),
    q: $("f-q").value.trim(),
    source: $("f-source").value,
    sector: $("f-sector").value,
    severity: $("f-severity").value,
    freshness: $("f-freshness").value,
    // La API espera datetime ISO; el input date da solo la fecha.
    since: since ? `${since}T00:00:00Z` : "",
    until: until ? `${until}T23:59:59Z` : "",
  };
}

/** Refresca los paneles de datos (no la consola, que va por su cuenta). */
async function refreshData() {
  if (state.blocked) return;
  // Siempre: las fuentes alimentan el badge del menú y el control de PII.
  // Lo demás, solo la pantalla en la que estés.
  await Promise.all([loadSources(), loadRules(), loadView(state.view)]);
}

async function refreshAll() {
  await Promise.all([refreshData(), pollEvents(), loadEgress()]);
}

$("filters").addEventListener("submit", (e) => {
  e.preventDefault();
  state.filters = readFilters();
  state.offset = 0;
  loadFindings();
});

$("clear").addEventListener("click", () => {
  // El reset del form corre después del handler: se espera un tick.
  setTimeout(() => {
    state.filters = {};
    state.offset = 0;
    renderActiveFilters();
    loadFindings();
  }, 0);
});

$("prev").addEventListener("click", () => {
  state.offset = Math.max(0, state.offset - PAGE_SIZE);
  loadFindings();
});

$("next").addEventListener("click", () => {
  state.offset += PAGE_SIZE;
  loadFindings();
});

$("exp-close").addEventListener("click", closeExposure);
$("exp-modal").addEventListener("click", (e) => {
  if (e.target === $("exp-modal")) closeExposure();
});

$("dl-close").addEventListener("click", closeDownloads);
$("dl-modal").addEventListener("click", (e) => {
  // Click fuera de la tarjeta cierra. Este modal sí se puede cerrar: no es el
  // bloqueo de OPSEC, es informativo.
  if (e.target === $("dl-modal")) closeDownloads();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !state.blocked) {
    closeDownloads();
    closeExposure();
  }
});

$("refresh").addEventListener("click", refreshNow);
$("sel-page").addEventListener("change", (e) => togglePagina(e.target.checked));
$("sel-clear").addEventListener("click", limpiarSeleccion);
$("export-txt").addEventListener("click", exportarSeleccion);
$("wl-export").addEventListener("click", exportarWatchlist);
$("adj-close").addEventListener("click", closeAdjacency);
$("tg-add").addEventListener("submit", agregarCanal);
$("tg-import").addEventListener("click", importarCatalogo);
$("tg-q").addEventListener("input", () => { state.tgOffset = 0; loadTelegram(); });
$("tg-f-enabled").addEventListener("change", () => { state.tgOffset = 0; loadTelegram(); });
$("tg-f-origin").addEventListener("change", () => { state.tgOffset = 0; loadTelegram(); });
$("tg-prev").addEventListener("click", () => {
  state.tgOffset = Math.max(0, state.tgOffset - TG_PAGE_SIZE);
  loadTelegram();
});
$("tg-next").addEventListener("click", () => {
  state.tgOffset += TG_PAGE_SIZE;
  loadTelegram();
});
$("run-now").addEventListener("click", runNow);

// -- Watchlist: alta y filtros
$("wl-add").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("wl-error").textContent = "";

  const r = await apiWrite("/api/watchlist", "POST", {
    kind: $("wl-kind").value,
    value: $("wl-value").value.trim(),
    sector: $("wl-sector").value.trim() || "sin_sector",
    critical: $("wl-critical").checked,
  });

  if (!r.ok) {
    $("wl-error").textContent = r.error;
    return;
  }
  $("wl-value").value = "";
  state.wlOffset = 0;
  loadWatchlist();
});

for (const id of ["wl-q", "wl-f-kind", "wl-f-enabled"]) {
  $(id).addEventListener("input", () => {
    // Cambiar el filtro vuelve a la primera página: quedarse en la 3 de un
    // resultado que ahora tiene 1 sola muestra una tabla vacía sin motivo.
    state.wlOffset = 0;
    loadWatchlist();
  });
}

for (const id of ["st-q", "st-kind", "st-available", "st-ar"]) {
  $(id).addEventListener("input", () => {
    state.stOffset = 0;
    loadSites();
  });
}

$("st-prev").addEventListener("click", () => {
  state.stOffset = Math.max(0, state.stOffset - SITES_PAGE_SIZE);
  loadSites();
});

$("st-next").addEventListener("click", () => {
  state.stOffset += SITES_PAGE_SIZE;
  loadSites();
});

// Importar las entradas nuevas del YAML semilla.
$("wl-sync").addEventListener("click", async () => {
  const boton = $("wl-sync");
  boton.disabled = true;
  boton.textContent = "Importando…";

  const r = await apiWrite("/api/watchlist/sync", "POST");
  boton.disabled = false;
  boton.textContent = "Importar semilla";

  if (!r.ok) {
    $("wl-error").textContent = r.error;
    return;
  }
  setStatus(`Watchlist sincronizada: ${r.data.counts.total} entradas.`, "ok");
  state.wlOffset = 0;
  loadWatchlist();
});

$("wl-prev").addEventListener("click", () => {
  state.wlOffset = Math.max(0, state.wlOffset - WL_PAGE_SIZE);
  loadWatchlist();
});

$("wl-next").addEventListener("click", () => {
  state.wlOffset += WL_PAGE_SIZE;
  loadWatchlist();
});

$("console-clear").addEventListener("click", () => {
  // Limpia la vista, no la bitácora: `lastEventId` no se toca, así que no
  // vuelven a aparecer las líneas ya vistas.
  $("console").replaceChildren();
  state.consoleLines = 0;
  $("console-count").textContent = "0 líneas";
});

// El panel de fuentes recuerda si lo dejaste abierto o cerrado.
const sourcesPanel = $("sources-panel");
sourcesPanel.open = localStorage.getItem("sources-open") === "1";
sourcesPanel.addEventListener("toggle", () => {
  localStorage.setItem("sources-open", sourcesPanel.open ? "1" : "0");
});

window.addEventListener("hashchange", () => showView(viewFromHash()));

// Arranque: se pinta la vista del hash y se traen los datos comunes.
// La IP de salida se resuelve ANTES de pintar nada: si arranca bloqueado, no
// tiene que salir ni un pedido de datos. (Antes se pintaba la vista primero y
// recién después se sabía que estaba bloqueado.)
loadEgress().then(() => {
  showView(viewFromHash());
  refreshAll();
});

// Si el scheduler o alguien más dejó una corrida en curso, se engancha.
api("/api/runs/current").then((estado) => {
  if (estado && estado.running) {
    state.running = true;
    setStatus("Corrida en curso — el detalle se ve en la Consola.", "run");
    watchRun();
  }
});

// La consola se actualiza sola aunque estés en otra pantalla: así no se pierde
// actividad mientras mirás otra sección.
setInterval(pollEvents, CONSOLE_POLL_MS);
// La IP de salida se revisa siempre: es lo que libera el bloqueo cuando se
// conecta la VPN, y lo que lo activa si la VPN se cae a mitad de sesión.
setInterval(loadEgress, BLOCK_RECHECK_MS);
