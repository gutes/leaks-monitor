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

import { buscar, cargarApp, disparar, textoDe } from "./dom.mjs";

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
