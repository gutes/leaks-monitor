/**
 * Tests del frontend, con el runner nativo de Node (`node --test`).
 *
 * Qué se verifica: el cableado y las reglas de seguridad de la UI. Cada test
 * de acá corresponde a algo que ya falló o que no puede fallar:
 *
 *  - que ninguna URL de descarga termine siendo un enlace clickeable;
 *  - que el bloqueo por IP de salida corte la actividad del tablero;
 *  - que cada pantalla pida solo lo suyo;
 *  - que el contenido de los feeds nunca se inserte como HTML.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { buscar, cargarApp, disparar, textoDe, tieneClase } from "./dom.mjs";

const HTML = readFileSync(new URL("../../frontend/index.html", import.meta.url), "utf8");
const APP = readFileSync(new URL("../../frontend/app.js", import.meta.url), "utf8");

const hallazgo = (extra = {}) => ({
  id: 1,
  source: "darkforums",
  leak_type: "forum_post",
  victim_name: "Ministerio de Prueba",
  victim_domain: "prueba.gob.ar",
  sector: "gobierno_nacional",
  actor: "actor_uno",
  severity: "critical",
  discovered_at: "2026-08-15T10:00:00Z",
  first_seen_at: "2026-08-15T10:00:00Z",
  last_seen_at: "2026-08-15T10:00:00Z",
  raw_ref: "https://foro.test/thread-1",
  ar_match_reason: ["watchlist"],
  ar_match_detail: { watchlist: ["prueba.gob.ar"] },
  download_links: [],
  ...extra,
});

const RESPUESTAS_BASE = {
  "/api/egress": { enabled: true, ip: "1.2.3.4", country: "CL", blocked: false },
  "/api/health": { status: "ok", store_pii: false, pii_sources_enabled: false, findings: 1 },
  "/api/events": { items: [], last_id: 0 },
  "/api/stats": { total: 1, by_severity: {}, by_source: {}, by_sector: {}, by_leak_type: {} },
  "/api/sources": [],
  "/api/filters": { sources: [], sectors: [], severities: [], actors: [], leak_types: [] },
  "/api/findings": { items: [hallazgo()], total: 1, limit: 50, offset: 0 },
  "/api/rules": { rules: [], pii_sources_enabled: false, pii_storage_available: false, editing_allowed: true },
  "/api/watchlist": { items: [], counts: {}, sectors: [], total: 0, limit: 50, offset: 0 },
  "/api/runs/current": { running: false },
};

/* ------------------------------------------------------------ Seguridad */

test("las URLs de descarga nunca se insertan como enlaces", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/findings": {
        items: [
          hallazgo({
            download_links: [
              { url: "magnet:?xt=urn:btih:ABC", kind: "data" },
              { url: "https://gofile.io/d/xyz", kind: "data" },
            ],
          }),
        ],
        total: 1,
        limit: 50,
        offset: 0,
      },
    },
  });

  // Se abre el pop-up desde el botón de la fila.
  const boton = buscar(el("findings-body"), (n) => n.className?.includes("dl-btn"))[0];
  assert.ok(boton, "tiene que haber un botón de enlaces");
  await disparar(boton, "click");

  const enlaces = buscar(el("dl-list"), (n) => n.tag === "a");
  assert.equal(enlaces.length, 0, "no puede haber ningún <a> con la URL");

  const codigos = buscar(el("dl-list"), (n) => n.tag === "code");
  assert.ok(
    codigos.some((c) => c.textContent.startsWith("magnet:")),
    "la URL tiene que estar como texto en un <code>",
  );
});

test("el contenido de los feeds se inserta como texto, nunca como HTML", () => {
  // `innerHTML` no puede aparecer en el archivo: el nombre de una víctima lo
  // escribe un grupo de ransomware, no nosotros.
  assert.equal(/\.innerHTML\s*=/.test(APP), false, "app.js no debe asignar innerHTML");
  assert.equal(/insertAdjacentHTML/.test(APP), false);
});

test("un href de feed solo se acepta si es http(s)", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/findings": {
        items: [hallazgo({ raw_ref: "javascript:alert(1)" })],
        total: 1,
        limit: 50,
        offset: 0,
      },
    },
  });

  const enlaces = buscar(el("findings-body"), (n) => n.tag === "a");
  assert.equal(enlaces.length, 0, "un javascript: no puede convertirse en enlace");
});

test("los .onion se muestran enteros pero no se enlazan", async () => {
  // Regresión: al dejar de enlazarlos se los reemplazó por una píldora que
  // decía "onion" y ocultaba la dirección. No enlazar es correcto; esconder el
  // dato que el investigador necesita copiar, no.
  const direccion = "http://abcdef1234567890.onion/post/ministerio";
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/findings": {
        items: [hallazgo({ raw_ref: direccion })],
        total: 1,
        limit: 50,
        offset: 0,
      },
    },
  });

  const celdas = buscar(el("findings-body"), (n) => n.className === "onion-ref");
  assert.equal(celdas.length, 1, "la dirección tiene que estar en la tabla");
  assert.equal(celdas[0].textContent, direccion, "y tiene que estar completa");

  const enlaces = buscar(el("findings-body"), (n) => n.tag === "a");
  assert.equal(enlaces.length, 0, "pero no puede ser un enlace");
});

/* --------------------------------------------------- Bloqueo de OPSEC */

test("con la salida bloqueada se corta la actividad del tablero", async () => {
  const { el, pedidos } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/egress": {
        enabled: true,
        ip: "200.1.2.3",
        country: "AR",
        blocked: true,
        block_reason: "BLOQUEADO: el tráfico sale desde AR",
      },
    },
  });

  assert.equal(el("egress-block").hidden, false, "el modal tiene que estar visible");
  assert.match(el("blocker-reason").textContent, /BLOQUEADO/);
  assert.equal(
    pedidos.some((p) => p.startsWith("/api/findings")),
    false,
    "estando bloqueado no se piden hallazgos",
  );
});

test("el botón de reintentar fuerza la consulta de la IP", async () => {
  const { el, pedidos } = await cargarApp({
    html: HTML,
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/egress": { enabled: true, ip: "200.1.2.3", country: "AR", blocked: true },
    },
  });

  await disparar(el("blocker-retry-btn"), "click");
  assert.ok(
    pedidos.some((p) => p.includes("/api/egress") && p.includes("force=true")),
    "reintentar tiene que pedir force=true",
  );
});

/* ------------------------------------------------------------- Router */

test("cada pantalla pide solo sus datos", async () => {
  const { pedidos } = await cargarApp({
    html: HTML,
    hash: "#/reglas",
    respuestas: RESPUESTAS_BASE,
  });

  assert.ok(pedidos.some((p) => p.startsWith("/api/rules")), "reglas sí");
  assert.equal(
    pedidos.some((p) => p.startsWith("/api/findings")),
    false,
    "entrar a Reglas no puede disparar la consulta de hallazgos",
  );
});

test("un hash desconocido cae en la pantalla por defecto", async () => {
  const { pedidos } = await cargarApp({
    html: HTML,
    hash: "#/no-existe",
    respuestas: RESPUESTAS_BASE,
  });
  assert.ok(pedidos.some((p) => p.startsWith("/api/findings")));
});

/* --------------------------------------------------------- Control PII */

test("la pastilla de PII refleja el estado persistido, no el del entorno", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/reglas",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/rules": {
        rules: [],
        pii_sources_enabled: true,
        pii_storage_available: false,
        editing_allowed: true,
      },
    },
  });

  assert.match(el("pii-badge").textContent, /ON/);
  assert.equal(el("pii-sources").checked, true);
});

test("sin clave de cifrado la pastilla avisa que la PII no se guarda", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/reglas",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/rules": {
        rules: [],
        pii_sources_enabled: true,
        pii_storage_available: false,
        editing_allowed: true,
      },
    },
  });
  assert.match(el("pii-badge").textContent, /sin guardar/);
});

/* ------------------------------------------------------------ Corridas */

test("si hay una corrida en curso la UI se engancha", async () => {
  const { el } = await cargarApp({
    html: HTML,
    respuestas: { ...RESPUESTAS_BASE, "/api/runs/current": { running: true } },
  });
  assert.match(el("last-updated").textContent, /curso/);
});

test("una API caída no rompe la página", async () => {
  // Sin respuestas: todo devuelve 404. No debe lanzar.
  const { el } = await cargarApp({ html: HTML, respuestas: {} });
  assert.ok(el("egress-block"), "la página sigue en pie");
});

/* ------------------------------------------------------ Robustez de la UI */

test("una respuesta con forma inesperada no corta la carga", async () => {
  // Regresión: `for (const r of datos.rules)` sobre algo que no era iterable
  // rechazaba la promesa y se caía la carga entera del tablero.
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/reglas",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/rules": {},
      "/api/sources": {},
      "/api/events": {},
      "/api/watchlist": {},
    },
  });

  // La página sigue en pie y el bloqueo se pudo evaluar.
  assert.equal(el("egress-block").hidden, true);
});

test("la consola no pierde líneas al recibir un lote", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/consola",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/events": {
        items: [
          { id: 1, occurred_at: "2026-08-15T10:00:00Z", level: "info", kind: "run_start", message: "primera" },
          { id: 2, occurred_at: "2026-08-15T10:00:01Z", level: "error", kind: "source_failed", message: "segunda" },
        ],
        last_id: 2,
      },
    },
  });

  const texto = textoDe(el("console"));
  assert.match(texto, /primera/);
  assert.match(texto, /segunda/);
  // La más reciente va arriba.
  assert.ok(texto.indexOf("segunda") < texto.indexOf("primera"), "la más nueva va primero");
});

/* ------------------------------------------------------------- Frescura */

test("muestra la fecha del evento y no la de importación", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/findings": {
        items: [
          hallazgo({
            occurred_at: "2022-03-15T00:00:00Z",
            occurred_at_basis: "feed",
            discovered_at: "2026-08-18T00:00:00Z",
            first_seen_at: "2026-08-18T00:00:00Z",
          }),
        ],
        total: 1,
        limit: 50,
        offset: 0,
      },
    },
  });

  const texto = textoDe(el("findings-body"));
  assert.match(texto, /2022-03-15/, "tiene que verse cuándo ocurrió");
  assert.match(texto, /histórico/, "y clasificarse como histórico, no como nuevo");
});

test("un hallazgo sin fecha lo dice, no la inventa", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/findings": {
        items: [hallazgo({ occurred_at: null, occurred_at_basis: "sin_dato" })],
        total: 1,
        limit: 50,
        offset: 0,
      },
    },
  });

  assert.match(textoDe(el("findings-body")), /sin fecha/);
});

test("la importación inicial se marca como tal", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/findings": {
        items: [hallazgo({ occurred_at: "2021-01-01T00:00:00Z", backfill: true })],
        total: 1,
        limit: 50,
        offset: 0,
      },
    },
  });

  assert.match(textoDe(el("findings-body")), /importación inicial/);
});

/* -------------------------------------------------- Selección y exportación */

/** Las casillas de las filas ya pintadas. */
const casillas = (el) => buscar(el("findings-body"), (n) => n.className === "sel-box");

/** Respuestas con N hallazgos en la página. */
const conHallazgos = (...items) => ({
  ...RESPUESTAS_BASE,
  "/api/findings": { items, total: items.length, limit: 50, offset: 0 },
});

const RESPUESTA_EXPORT = {
  __texto: "INFORME",
  __headers: {
    "Content-Disposition": 'attachment; filename="hallazgos-20260818-1530-2.txt"',
    "X-Findings-Exported": "2",
  },
};

test("no se puede exportar sin seleccionar nada", async () => {
  const { el } = await cargarApp({ html: HTML, hash: "#/hallazgos", respuestas: RESPUESTAS_BASE });

  assert.equal(el("export-txt").disabled, true);
  assert.equal(el("sel-clear").disabled, true);
  assert.match(textoDe(el("sel-count")), /Ningún hallazgo/);
});

test("tildar una fila habilita la exportación y la cuenta", async () => {
  const { el } = await cargarApp({ html: HTML, hash: "#/hallazgos", respuestas: RESPUESTAS_BASE });

  const caja = casillas(el)[0];
  caja.checked = true;
  await disparar(caja, "change");

  assert.equal(el("export-txt").disabled, false);
  assert.match(textoDe(el("sel-count")), /1 hallazgo seleccionado/);
});

test("la casilla del encabezado tilda toda la página", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: conHallazgos(hallazgo({ id: 1 }), hallazgo({ id: 2 }), hallazgo({ id: 3 })),
  });

  await disparar(el("sel-page"), "change", { target: { checked: true } });

  assert.equal(casillas(el).filter((c) => c.checked).length, 3);
  assert.match(textoDe(el("sel-count")), /3 hallazgos seleccionados/);
});

test("la selección sobrevive al cambio de página", async () => {
  // Es la razón de ser del Set: juntar hallazgos de varias páginas en un
  // informe. Si se limpiara al paginar, el feature no serviría para nada.
  const { el, esperar } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: conHallazgos(hallazgo({ id: 7 }), hallazgo({ id: 8 })),
  });

  const caja = casillas(el)[0];
  caja.checked = true;
  await disparar(caja, "change");

  await disparar(el("next"), "click");
  await esperar();

  assert.match(textoDe(el("sel-count")), /1 hallazgo seleccionado/);
  assert.equal(casillas(el)[0].checked, true, "la fila vuelve tildada");
});

test("limpiar deja la selección en cero", async () => {
  const { el } = await cargarApp({ html: HTML, hash: "#/hallazgos", respuestas: RESPUESTAS_BASE });

  const caja = casillas(el)[0];
  caja.checked = true;
  await disparar(caja, "change");
  await disparar(el("sel-clear"), "click");

  assert.equal(el("export-txt").disabled, true);
  assert.equal(casillas(el)[0].checked, false);
  assert.match(textoDe(el("sel-count")), /Ningún hallazgo/);
});

test("exportar manda los ids tildados y baja el archivo", async () => {
  const { el, pedidos, cuerpos, descargas } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...conHallazgos(hallazgo({ id: 11 }), hallazgo({ id: 22 })),
      "/api/findings/export": RESPUESTA_EXPORT,
    },
  });

  await disparar(el("sel-page"), "change", { target: { checked: true } });
  await disparar(el("export-txt"), "click");

  assert.ok(pedidos.includes("/api/findings/export"), "tiene que pegarle al endpoint");
  const cuerpo = cuerpos[pedidos.indexOf("/api/findings/export")];
  assert.deepEqual(cuerpo, { ids: [11, 22] }, "manda solo ids, no contenido");
  assert.equal(descargas.length, 1, "se dispara una descarga");
  assert.match(textoDe(el("last-updated")), /2 hallazgos descargado/);
});

test("si algún hallazgo ya no existe se avisa en vez de entregar un informe corto", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...conHallazgos(hallazgo({ id: 11 }), hallazgo({ id: 22 })),
      "/api/findings/export": {
        __texto: "INFORME",
        __headers: { "X-Findings-Exported": "1" },
      },
    },
  });

  await disparar(el("sel-page"), "change", { target: { checked: true } });
  await disparar(el("export-txt"), "click");

  assert.match(textoDe(el("last-updated")), /Exportados 1 de 2/);
});

test("un error al exportar se informa y el botón vuelve a quedar usable", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/findings/export": { __status: 403, detail: "Salida bloqueada" },
    },
  });

  const caja = casillas(el)[0];
  caja.checked = true;
  await disparar(caja, "change");
  await disparar(el("export-txt"), "click");

  assert.match(textoDe(el("last-updated")), /No se pudo exportar/);
  assert.equal(el("export-txt").disabled, false, "se puede reintentar");
  assert.match(textoDe(el("export-txt")), /Exportar TXT/, "el botón vuelve a su rótulo");
});

test("el nombre del archivo se sanea antes de escribirlo en disco", async () => {
  assert.match(APP, /replace\(\/\[\^A-Za-z0-9\._-\]\/g, "_"\)/);
});

test("la watchlist se exporta con los filtros puestos", async () => {
  const { el, pedidos, descargas } = await cargarApp({
    html: HTML,
    hash: "#/watchlist",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/watchlist/export": {
        __texto: "WATCHLIST",
        __headers: {
          "Content-Disposition": 'attachment; filename="watchlist-20260818-1600-284.txt"',
          "X-Watchlist-Exported": "284",
        },
      },
    },
  });

  el("wl-f-kind").value = "domain";
  await disparar(el("wl-export"), "click");

  const pedido = pedidos.find((p) => p.startsWith("/api/watchlist/export"));
  assert.ok(pedido, "tiene que pegarle al endpoint");
  assert.match(pedido, /kind=domain/, "lleva el filtro que se está viendo");
  assert.equal(descargas.length, 1);
  assert.match(textoDe(el("last-updated")), /284 entradas/);
});

test("un error al exportar la watchlist se informa y el botón vuelve", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/watchlist",
    respuestas: { ...RESPUESTAS_BASE, "/api/watchlist/export": { __status: 500, detail: "roto" } },
  });

  await disparar(el("wl-export"), "click");

  assert.match(textoDe(el("last-updated")), /No se pudo exportar/);
  assert.equal(el("wl-export").disabled, false);
  assert.match(textoDe(el("wl-export")), /Exportar TXT/);
});

test("la pantalla de Telegram lista canales y dice por qué falla cada uno", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/telegram",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/telegram": {
        items: [
          { id: 1, handle: "vivo", actor: "Grupo Vivo", kind: "data_leak",
            origin: "user", enabled: true, last_post_id: "vivo/42", url: "https://t.me/s/vivo" },
          { id: 2, handle: "muerto", actor: null, kind: null, origin: "catalog",
            enabled: false, last_post_id: null, last_error: "el canal no existe",
            url: "https://t.me/s/muerto" },
        ],
        counts: { total: 2, enabled: 1, disabled: 1, user: 1, catalog: 1 },
        total: 2, limit: 50, offset: 0,
      },
    },
  });

  const texto = textoDe(el("tg-body"));
  assert.match(texto, /t\.me\/s\/vivo/);
  assert.match(texto, /vivo\/42/, "muestra el cursor incremental");
  assert.match(texto, /error/, "un canal muerto se ve distinto de uno tranquilo");
});

test("la dirección del canal nunca se inserta como enlace", async () => {
  // Es infraestructura de quien publica los volcados, igual que los .onion.
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/telegram",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/telegram": {
        items: [{ id: 1, handle: "peligroso", origin: "user", enabled: true,
                  url: "https://t.me/s/peligroso" }],
        counts: {}, total: 1, limit: 50, offset: 0,
      },
    },
  });

  const enlaces = buscar(el("tg-body"), (n) => n.tag === "a");
  assert.equal(enlaces.length, 0, "ningún <a> en la lista de canales");
  const codes = buscar(el("tg-body"), (n) => n.tag === "code");
  assert.ok(codes.length, "se muestra como texto seleccionable");
});

test("la sección de adyacentes se anuncia como beta en el menú", async () => {
  // Su score es ciego a casi la mitad de los actores: eso hay que saberlo
  // antes de entrar, no después de leer la lista.
  assert.match(HTML, /data-view="adyacentes">Adyacentes<span class="nav-beta"/);
  assert.match(HTML, /46%/, "el aviso dice cuánto es el punto ciego");
});

test("sin canales de alerta y con hallazgos esperando, el panel lo dice", async () => {
  // El caso que este panel existe para evitar: el pipeline descarta los avisos
  // en silencio y nadie se entera de que hay señal perdiéndose.
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/fuentes",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/alerts": {
        enabled: false,
        channels: [
          { name: "webhook", configured: false, missing: ["LEAKS_ALERT_WEBHOOK_URL"] },
          { name: "telegram", configured: false, missing: ["LEAKS_ALERT_TELEGRAM_TOKEN"] },
        ],
        min_severity: "high", max_age_days: 30, pending: 7, sent_total: 0,
      },
    },
  });

  assert.match(textoDe(el("alerts-resumen")), /7 hallazgos high\+ están esperando/);
  assert.match(textoDe(el("alerts-estado")), /sin canales/);
  assert.match(textoDe(el("alerts-canales")), /LEAKS_ALERT_WEBHOOK_URL/,
    "dice qué variable falta");
});

test("con canales configurados el panel informa el estado real", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/fuentes",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/alerts": {
        enabled: true,
        channels: [{ name: "webhook", configured: true, missing: [] }],
        min_severity: "high", max_age_days: 30, pending: 0, sent_total: 12,
        last_sent_at: "2026-08-18T10:00:00Z",
      },
    },
  });

  assert.match(textoDe(el("alerts-estado")), /12 enviadas/);
  assert.match(textoDe(el("alerts-resumen")), /Última:/);
});

test("los foros ofrecen buscar subforos; el resto de las fuentes no", async () => {
  // El botón vive en la tarjeta del foro porque es donde se mira cuando el
  // foro cambió: si se mudó o reorganizó, los ids viejos dejan de servir.
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/fuentes",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/sources": [
        {
          name: "darkforums", enabled: true, tags: ["foro", "pii"],
          last_run: { source: "darkforums", status: "ok", started_at: "2026-09-01T15:00:00Z",
            finished_at: "2026-09-01T15:01:00Z", items_fetched: 50, items_matched: 0,
            items_persisted: 0, error: null },
        },
        {
          name: "ransomware.live", enabled: true, tags: ["ransomware", "metadata"],
          last_run: { source: "ransomware.live", status: "ok", started_at: "2026-09-01T15:00:00Z",
            finished_at: "2026-09-01T15:01:00Z", items_fetched: 293, items_matched: 0,
            items_persisted: 0, error: null },
        },
      ],
    },
  });

  const botones = buscar(el("sources"), (n) => n.tag === "button");
  const textos = botones.map((b) => b.textContent);
  assert.deepEqual(textos, ["Buscar subforos"], "solo el foro lo ofrece");
});

test("el encabezado dice cuándo corrió el pipeline por última vez", async () => {
  const ahora = Date.now();
  const hace10min = new Date(ahora - 10 * 60000).toISOString();
  const hace3h = new Date(ahora - 3 * 3600000).toISOString();

  const { el } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/sources": [
        // Sondeado hace 10 min: dice que está vivo, pero no que miró todo.
        { name: "darkforums", enabled: true, poll_interval_minutes: 120,
          last_run: { source: "darkforums", status: "ok", finished_at: hace10min } },
        // Solo corre en la corrida completa: es el que fecha "completa".
        { name: "ransomware.live", enabled: true, poll_interval_minutes: null,
          last_run: { source: "ransomware.live", status: "ok", finished_at: hace3h } },
      ],
    },
  });

  const texto = textoDe(el("last-run"));
  assert.match(texto, /Última corrida: hace 10 min/);
  assert.match(texto, /completa hace 3 h/, "distingue el sondeo de la corrida entera");
});

test("una corrida completa vieja se marca, aunque los sondeos sigan", async () => {
  // El síntoma del apagón: la fuente sondeada responde y todo parece bien,
  // pero hace días que no corre el pipeline entero.
  const ahora = Date.now();
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/sources": [
        { name: "darkforums", enabled: true, poll_interval_minutes: 120,
          last_run: { source: "darkforums", status: "ok",
            finished_at: new Date(ahora - 60000).toISOString() } },
        { name: "ransomware.live", enabled: true, poll_interval_minutes: null,
          last_run: { source: "ransomware.live", status: "ok",
            finished_at: new Date(ahora - 72 * 3600000).toISOString() } },
      ],
    },
  });

  assert.ok(
    tieneClase(el("last-run"), "last-run-stale"),
    "la corrida completa de hace 3 días tiene que verse como problema",
  );
});

test("la ventana medida del feed se muestra", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/fuentes",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/sources": [
        {
          name: "darkforums",
          enabled: true,
          last_run: {
            source: "darkforums", status: "ok",
            started_at: "2026-09-01T15:26:53Z", finished_at: "2026-09-01T15:26:57Z",
            items_fetched: 50, items_matched: 0, items_persisted: 0, error: null,
            window_from: "2026-08-31T19:00:00Z", window_to: "2026-09-01T15:00:00Z",
          },
        },
      ],
    },
  });

  assert.match(textoDe(el("sources")), /Ventana del feed: 20\.0 h/);
});

const ALERTA_PENDIENTE = {
  id: 7,
  dedup_hash: "a".repeat(64),
  source: "ransomware.live",
  leak_type: "ransomware",
  victim_name: "Ministerio X",
  victim_domain: "x.gob.ar",
  severity: "critical",
  actor: "LockBit",
  occurred_at: "2026-08-30T10:00:00Z",
  discovered_at: "2026-08-31T10:00:00Z",
  notified: false,
};

test("los avisos pendientes se listan con enlace al hallazgo", async () => {
  // El panel decía "13 esperando" y no dejaba llegar a ninguno: sabías que
  // había señal y no podías verla.
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/fuentes",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/alerts": {
        enabled: false,
        channels: [],
        min_severity: "high", max_age_days: 30, pending: 13, sent_total: 0,
      },
      "/api/alerts/feed": { items: [ALERTA_PENDIENTE], total: 13, limit: 15, offset: 0 },
    },
  });

  const cont = el("alerts-pendientes");
  assert.match(textoDe(cont), /Ministerio X/);
  assert.match(textoDe(cont), /LockBit/, "dice de un vistazo de qué se trata");
  assert.match(textoDe(cont), /y 12 más/, "no esconde que hay más");

  const enlace = buscar(cont, (n) => n.tag === "a")[0];
  assert.ok(enlace, "cada aviso tiene que ser un enlace de verdad");
  assert.equal(enlace.href, `#/hallazgos?hallazgo=${"a".repeat(64)}`);
});

test("el enlace del aviso NO apunta a la fuente de origen", async () => {
  // `raw_ref` es un sitio de extorsión o un foro de volcados: se muestra para
  // leer, nunca para navegar por accidente.
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/fuentes",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/alerts": {
        enabled: false, channels: [], min_severity: "high",
        max_age_days: 30, pending: 1, sent_total: 0,
      },
      "/api/alerts/feed": {
        items: [{ ...ALERTA_PENDIENTE, raw_ref: "http://sitio-de-extorsion.onion/post/1" }],
        total: 1, limit: 15, offset: 0,
      },
    },
  });

  for (const a of buscar(el("alerts-pendientes"), (n) => n.tag === "a")) {
    assert.ok(a.href.startsWith("#/"), `enlace hacia afuera: ${a.href}`);
  }
});

test("sin avisos pendientes el widget no ocupa lugar", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/fuentes",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/alerts": {
        enabled: true, channels: [], min_severity: "high",
        max_age_days: 30, pending: 0, sent_total: 4,
      },
    },
  });

  assert.equal(textoDe(el("alerts-pendientes")).trim(), "");
});

test("entrar por la URL de un hallazgo lo pide a la API y lo muestra fijado", async () => {
  const hash = "b".repeat(64);
  const { el, pedidos } = await cargarApp({
    html: HTML,
    hash: `#/hallazgos?hallazgo=${hash}`,
    respuestas: RESPUESTAS_BASE,
  });

  const pedido = pedidos.find((p) => p.includes("/api/findings"));
  assert.ok(pedido.includes(`dedup_hash=${hash}`), `no pidió el hallazgo: ${pedido}`);
  assert.match(textoDe(el("active-filters")), /hallazgo:/, "tiene que verse que está fijado");
});

test("un hueco de cobertura se muestra aunque la corrida haya andado", async () => {
  // El caso que esto existe para evitar: la fuente responde OK, no trae nada
  // nuevo, y la pérdida se lee igual que "no hubo novedades".
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/fuentes",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/sources": [
        {
          name: "darkforums",
          enabled: true,
          requires_pii: true,
          last_run: {
            source: "darkforums",
            status: "ok",
            started_at: "2026-09-01T15:26:53Z",
            finished_at: "2026-09-01T15:26:57Z",
            items_fetched: 50,
            items_matched: 0,
            items_persisted: 0,
            error: null,
            gap_from: "2026-08-25T18:03:00Z",
            gap_to: "2026-09-01T12:00:00Z",
          },
        },
      ],
    },
  });

  const texto = textoDe(el("sources"));
  assert.match(texto, /Hueco de cobertura/);
  assert.match(texto, /161\.9 h/, "dice cuánto tiempo estuvo sin ver");
});

test("sin hueco no se muestra el aviso", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/fuentes",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/sources": [
        {
          name: "ransomware.live",
          enabled: true,
          last_run: {
            source: "ransomware.live",
            status: "ok",
            started_at: "2026-09-01T15:26:42Z",
            finished_at: "2026-09-01T15:26:47Z",
            items_fetched: 293,
            items_matched: 0,
            items_persisted: 0,
            error: null,
            gap_from: null,
            gap_to: null,
          },
        },
      ],
    },
  });

  assert.doesNotMatch(textoDe(el("sources")), /Hueco de cobertura/);
});

test("ningún resaltado de fila usa un color fijo", async () => {
  // Hubo dos: `#eef4ff` en la fila seleccionada y `#fdf0ef` en la fila crítica.
  // En tema oscuro pintaban la fila casi blanca con el texto claro encima, o
  // sea ilegible. Los colores tienen que salir de las variables del tema.
  const CSS = readFileSync(new URL("../../frontend/style.css", import.meta.url), "utf8");

  const fondosFijos = CSS.split("\n")
    .map((linea, i) => [i + 1, linea])
    .filter(([, l]) => /background:\s*#[0-9a-fA-F]{3,8}\b/.test(l))
    // La perilla del interruptor es blanca a propósito, sobre una vía de color.
    .filter(([, l]) => !l.includes("#fff"));

  assert.deepEqual(fondosFijos, [], `colores fijos en: ${JSON.stringify(fondosFijos)}`);
});

test("el resaltado de la fila crítica se ve aunque falle el tinte", async () => {
  // Dos marcas y no una: el borde izquierdo sobrevive a cualquier tema y a
  // cualquier ajuste de contraste del sistema.
  const CSS = readFileSync(new URL("../../frontend/style.css", import.meta.url), "utf8");
  assert.match(CSS, /adj-fila-critica td:first-child\s*\{[^}]*box-shadow:\s*inset/);
});

test("la última columna dice cuándo se agregó, no cuándo ocurrió", async () => {
  // Son cosas distintas y confundirlas fue el problema original: una fuente
  // que trae su histórico de golpe agrega hoy leaks de 2020.
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/findings": {
        items: [
          hallazgo({
            occurred_at: "2021-05-10T00:00:00Z",
            occurred_at_basis: "feed",
            first_seen_at: "2026-08-15T00:00:00Z",
          }),
        ],
        total: 1, limit: 50, offset: 0,
      },
    },
  });

  const texto = textoDe(el("findings-body"));
  assert.match(texto, /2021-05-10/, "se ve cuándo ocurrió");
  assert.match(texto, /2026-08-15/, "y cuándo se agregó");
});

test("un hallazgo agregado hoy se distingue de un vistazo", async () => {
  const { el } = await cargarApp({
    html: HTML,
    hash: "#/hallazgos",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/findings": {
        items: [hallazgo({ first_seen_at: new Date().toISOString() })],
        total: 1, limit: 50, offset: 0,
      },
    },
  });

  assert.match(textoDe(el("findings-body")), /hoy/);
});

test("el orden de columnas pone Agregado antes de Ref y la auditable al final", async () => {
  // "Por qué es AR" son chips que se estiran: al final no empujan al resto.
  const encabezados = [...HTML.matchAll(/<th[^>]*>([^<]*)</g)].map((m) => m[1].trim());
  const i = (t) => encabezados.indexOf(t);
  assert.ok(i("Severidad") < i("Agregado"), "Agregado va después de Severidad");
  assert.ok(i("Agregado") < i("Ref."), "y antes de Ref.");
  assert.ok(i("Datos") < i("Por qué es AR"), "la auditable queda última");
});

test("la dirección .onion se acota pero no se oculta", async () => {
  // Esconderla detrás de una pastilla ya se probó y fue peor: es el dato que
  // hay que copiar.
  const CSS = readFileSync(new URL("../../frontend/style.css", import.meta.url), "utf8");
  assert.match(CSS, /\.onion-ref\s*\{[^}]*text-overflow:\s*ellipsis/);
  assert.match(APP, /code\.title\s*=/, "la dirección completa va en el title");
});

test("la adyacencia separa los dos carriles de actor", async () => {
  // Dos universos en una tabla se leen como uno solo: el score está calibrado
  // sobre la cadencia de una banda con sitio de extorsión, no sobre la de un
  // broker que vende accesos. La UI tiene que poder mirarlos por separado.
  const actor = (nombre, kind) => ({
    actor: nombre,
    victims_total: 3,
    countries: ["BR"],
    kind,
    hit_ar: false,
    ar_victims: 0,
    score: 50,
    score_breakdown: {},
    score_prev: null,
    variacion: null,
  });

  const { el } = await cargarApp({
    html: HTML,
    hash: "#/adyacentes",
    respuestas: {
      ...RESPUESTAS_BASE,
      "/api/adjacency": {
        confirmados: [],
        candidatos: [actor("lockbit3", "dls"), actor("rabbitt1337", "foro")],
        total_candidatos: 2,
        criticas: [],
        paises: ["BR"],
      },
    },
  });

  const tabla = () => textoDe(el("adj-cand-body"));
  assert.match(tabla(), /lockbit3/);
  assert.match(tabla(), /rabbitt1337/);
  assert.match(tabla(), /Foro \/ Telegram/, "cada fila dice de qué carril es");

  const [boton] = buscar(el("adj-carriles"), (n) => n.dataset?.kind === "foro");
  assert.ok(boton, "hay un filtro por carril");
  await disparar(boton, "click");

  assert.doesNotMatch(tabla(), /lockbit3/, "la banda de ransomware queda fuera del carril de foro");
  assert.match(tabla(), /rabbitt1337/);
});
