/**
 * DOM mínimo para ejercitar `frontend/app.js` en Node, sin navegador.
 *
 * No es un navegador ni pretende serlo: alcanza para verificar el cableado
 * —qué endpoints pide cada pantalla, qué se pinta, qué NO se pinta— que es
 * justo donde estuvieron los errores reales de este frontend (un id que no
 * existía, un endpoint mal escrito, una URL que terminaba en un <a>).
 *
 * Sin jsdom a propósito: son ~80 líneas y una dependencia menos que auditar en
 * un proyecto que se toma en serio la cadena de suministro.
 */

/** Un nodo de mentira que registra lo que le hacen. */
export function makeEl(tag = "div", id = "") {
  const node = {
    tag,
    id,
    textContent: "",
    className: "",
    title: "",
    value: "",
    type: "",
    href: "",
    rel: "",
    target: "",
    checked: false,
    disabled: false,
    hidden: false,
    open: false,
    colSpan: 0,
    style: {},
    dataset: {},
    options: { length: 1 },
    children: [],
    listeners: {},
    classList: {
      _set: new Set(),
      add(...c) { c.forEach((x) => this._set.add(x)); },
      remove(...c) { c.forEach((x) => this._set.delete(x)); },
      toggle(c, on) { on ? this._set.add(c) : this._set.delete(c); },
      contains(c) { return this._set.has(c); },
    },
    append(...hijos) { node.children.push(...hijos.filter(Boolean)); },
    prepend(...hijos) { node.children.unshift(...hijos.filter(Boolean)); },
    appendChild(h) { node.children.push(h); },
    replaceChildren(...hijos) { node.children = hijos.filter(Boolean); },
    remove() {},
    addEventListener(evento, fn) { (node.listeners[evento] ||= []).push(fn); },
    removeEventListener() {},
    setAttribute(k, v) { node[k] = v; },
    getAttribute(k) { return node[k] ?? null; },
    removeAttribute(k) { delete node[k]; },
    querySelector: () => makeEl(),
    querySelectorAll: () => [],
    scrollIntoView() {},
    focus() {},
    scrollTop: 0,
    scrollHeight: 0,
    clientHeight: 0,
  };
  return node;
}

/** Texto de un nodo y toda su descendencia. */
export function textoDe(node) {
  if (!node) return "";
  return [node.textContent || "", ...(node.children || []).map(textoDe)].join(" ").trim();
}

/** Todos los nodos del árbol que cumplen el predicado. */
export function buscar(node, predicado) {
  if (!node) return [];
  const propios = predicado(node) ? [node] : [];
  return [...propios, ...(node.children || []).flatMap((h) => buscar(h, predicado))];
}

/** Dispara el handler registrado para un evento. */
export async function disparar(node, evento, arg = {}) {
  for (const fn of node.listeners?.[evento] || []) await fn(arg);
}

/**
 * Instala el entorno global y carga app.js.
 *
 * `respuestas` mapea ruta -> objeto. `pedidos` acumula las URLs consultadas,
 * que es lo que permite afirmar "esta pantalla no pide hallazgos".
 */
import { readFileSync } from "node:fs";
import { runInThisContext } from "node:vm";

let contador = 0;

//: Timers reales, guardados antes de que los tests los reemplacen por stubs.
//: Hacen falta para esperar de verdad a que se resuelvan las cadenas de fetch.
const timerReal = globalThis.setTimeout;

/** Deja que se vacíe la cola de promesas del arranque de la app. */
async function esperarQueSeAsienteTodo(vueltas = 8) {
  for (let i = 0; i < vueltas; i++) {
    await new Promise((r) => timerReal(r, 1));
  }
}

export async function cargarApp({ html, respuestas = {}, hash = "" } = {}) {
  const ids = new Set([...html.matchAll(/id="([^"]+)"/g)].map((m) => m[1]));
  // Elementos que arrancan ocultos en el marcado: el nodo tiene que nacer
  // igual que en el navegador, o un test no puede distinguir "se ocultó" de
  // "nunca se mostró".
  const ocultos = new Set(
    [...html.matchAll(/<[^>]*id="([^"]+)"[^>]*\shidden[\s>]/g)].map((m) => m[1]),
  );
  const vistas = [...html.matchAll(/class="view" data-view="([a-z]+)"/g)].map((m) => m[1]);
  const navs = [...html.matchAll(/<a href="#\/([a-z]+)"/g)].map((m) => m[1]);

  const nodos = new Map();
  const pedidos = [];

  globalThis.document = {
    getElementById: (id) => {
      if (!ids.has(id)) return null;
      if (!nodos.has(id)) {
        const nodo = makeEl("div", id);
        nodo.hidden = ocultos.has(id);
        nodos.set(id, nodo);
      }
      return nodos.get(id);
    },
    createElement: (tag) => makeEl(tag),
    createDocumentFragment: () => makeEl("fragment"),
    createRange: () => ({ selectNodeContents() {} }),
    querySelector: () => makeEl(),
    querySelectorAll: (sel) => {
      const nombres = sel.includes("mainnav") ? navs : vistas;
      return nombres.map((n) => {
        const e = makeEl("a", n);
        e.dataset = { view: n };
        return e;
      });
    },
    addEventListener() {},
    body: { classList: makeEl().classList },
  };

  globalThis.window = {
    location: { origin: "http://localhost:8000", hash },
    addEventListener() {},
    scrollTo() {},
    getSelection: () => ({ removeAllRanges() {}, addRange() {} }),
  };
  globalThis.localStorage = { getItem: () => null, setItem() {} };
  // `navigator` es de solo lectura en Node: hay que redefinirlo.
  Object.defineProperty(globalThis, "navigator", {
    value: { clipboard: { writeText: async () => {} } },
    configurable: true,
    writable: true,
  });
  globalThis.setInterval = () => 0;
  // No-op a propósito: `watchRun` se reencola con setTimeout, y ejecutarlo en
  // el acto daría recursión infinita cuando una corrida está en curso.
  globalThis.setTimeout = () => 0;
  globalThis.alert = () => {};
  globalThis.confirm = () => true;

  globalThis.fetch = async (url) => {
    const ruta = new URL(url).pathname;
    pedidos.push(String(url).replace("http://localhost:8000", ""));
    const cuerpo = respuestas[ruta];
    return {
      ok: cuerpo !== undefined,
      status: cuerpo !== undefined ? 200 : 404,
      json: async () => cuerpo ?? {},
    };
  };

  // Se evalúa el archivo en vez de importarlo. Dos razones:
  //
  //  1. En el navegador `app.js` es un script clásico, no un módulo ES: esto
  //     reproduce esa carga tal cual.
  //  2. `import()` cachea por ruta ignorando el query, así que el truco de
  //     `?t=N` no re-ejecuta nada y el segundo test correría sobre el módulo
  //     del primero. (Costó encontrarlo: se veía como "no hace ningún pedido".)
  //
  // El IIFE aísla cada carga: sin él, los `const` de nivel superior chocarían
  // entre corridas.
  const fuente = readFileSync(new URL("../../frontend/app.js", import.meta.url), "utf8");
  runInThisContext(`(function () {\n${fuente}\n})()`, {
    filename: `app.js#${contador++}`,
  });

  // El arranque dispara varios fetch encadenados: hay que esperar a que se
  // asienten antes de mirar el resultado.
  await esperarQueSeAsienteTodo();

  return { nodos, pedidos, el: (id) => nodos.get(id), esperar: esperarQueSeAsienteTodo };
}
