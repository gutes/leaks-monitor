# Pendientes y decisiones abiertas

Estado al **2026-08-15**. El prototipo corre end-to-end: 250 tests, 90,7% de
cobertura, imagen Docker verificada, 216 hallazgos argentinos reales en la base,
3 commits en `main`.

---

## 0. Lo último que se hizo

### Sesión 3 (2026-08-15)

- **El tablero se partió en 5 pantallas** con menú (router por hash), cada una
  con su carga perezosa. La watchlist se pagina de verdad (`limit`/`offset` en
  el endpoint, total del filtro).

**Pendiente inmediato:** el botón **"Actualizar" sigue sin conectar** a
`POST /api/runs`, que ya existe y funciona. Hoy solo relee la base y no da
ninguna señal — que es la queja original. Falta: botón "Correr ahora", estado
"corriendo…", y timestamp de última actualización.

### Sesión 2 (2026-08-14)

**El control de IP de salida se endureció.** Se encontró en vivo que el pipeline
consultaba feeds con la salida en AR: el chequeo era solo al arrancar la
corrida, y la IP puede cambiar en el medio. Agujeros cerrados, cada uno con su
test:

1. **Barrera antes de cada request HTTP** (`FeedHttpClient.before_request`). No
   sale un byte a un feed sin una lectura fresca que lo autorice.
2. **AR no se puede sacar de la lista** (`ALWAYS_BLOCKED` en `egress_guard.py`).
   La configuración solo puede AGREGAR países.
3. **Lectura fresca obligatoria** (60 s). Antes el cache de 5 min podía tapar
   una VPN caída.
4. **La API entera devuelve 403** estando bloqueada, salvo `/api/egress` y
   `/api/health` (si se cerraran, el modal quedaría trabado para siempre).
5. **Corte a mitad de corrida**: si la salida se bloquea, no se sigue con las
   fuentes que faltan.

**Ojo con el ruteo:** se observó que el contenedor sale por la VPN (CL) mientras
el shell del host salía por AR (Red Científica). Hay ruteo dividido: verificar
por dónde sale **cada** proceso, no alcanza con mirar el navegador.

**Otras cosas de esta sesión:** botón "Reintentar ahora" en el modal (fuerza el
re-chequeo, no es override); endpoint `POST /api/runs` + `RunCoordinator` para
disparar corridas a mano; pastilla de PII arreglada (mostraba la variable de
entorno en vez del estado persistido); redacción de `email:password` en títulos
(la contraseña sobrevivía a la redacción).

---

## 1. Decisiones que esperan confirmación del líder técnico

Las tomé yo para no bloquear. Todas son reversibles.

| # | Decisión | Alternativa |
|---|---|---|
| 1 | **El control de IP de salida bloquea también cuando el país es indeterminable** (`LEAKS_EGRESS_BLOCK_ON_UNKNOWN=true`). El pedido fue "bloquear si es AR"; interpreté fail-closed porque el control promete que *no* se sale por AR, y una IP sin resolver no da esa garantía. **Costo:** si los proveedores de geo-IP se caen, el monitoreo se detiene. | Ponerlo en `false`: prioriza disponibilidad sobre garantía. |
| 2 | **La API dejó de ser solo-lectura.** Hay escritura para watchlist y reglas, sin autenticación, detrás de `LEAKS_ALLOW_RULE_EDITING` (default `true`). Aceptable en loopback, no en una red. | `false` para bloquear la edición, o poner auth adelante. |
| 3 | **DarkForums quedó `enabled_by_default=True` + `requires_pii=True`**, para que su único motivo de apagado sea el toggle de PII y el interruptor pueda encenderlo. | — |
| 4 | **El handle del autor de un thread de foro se guarda como `actor`.** Es un seudónimo público, igual que el nombre de un grupo de ransomware. | Hashearlo si se considera PII. |

---

## 2. Deuda contra el bootstrap original

| # | Pendiente | Detalle |
|---|---|---|
| 1 | **Alertas — no existe nada.** | El ejemplo del bootstrap termina en *"Alerta emitida"*. Hoy el hallazgo se persiste y se ve en el tablero, nada más. Sin email, sin webhook, sin Telegram. **Es lo único del spec original que falta entero.** |
| 2 | **Watchlist ampliada, todavía sin validar contra el CNC.** | Pasó de 69 a 284 entradas (11 sectores: + provincias, municipios, universidades, salud, nuclear). Los 8 dominios estatales huérfanos quedaron cubiertos y 18 hallazgos existentes ganaron sector. **No se pudo verificar por DNS**: el nodo VPN no alcanza sitios `.ar`. Falta la validación contra el inventario del CNC. |
| 3 | **Hudson Rock sin verificar.** | Adapter escrito contra la forma documentada, nunca probado: el endpoint no respondía (timeout 60 s). |
| 4 | **Fase 2 sin implementar.** | GitHub secret scanning sobre orgs `.gob.ar`, Telegram (MTProto), paste sites. Los hooks están listos: es un adapter más una entrada en el registro. |

---

## 3. Calidad de los datos

- **`sector` vacío** en el 100% de dls-monitor (31/31) y de los foros: esos feeds no lo traen y no lo derivamos de la watchlist cuando hay match. Se podría.
- **Sin loop de falsos positivos.** No hay forma de marcar un hallazgo como descartado ni una allowlist. El caso *Distribuidora Ejemplo Dominicana* se corrigió tocando código; debería ser dato.
- **Sin deduplicación entre fuentes.** Por diseño `source` entra en el hash, así que una misma víctima aparece dos veces si dos feeds la publican. Falta la vista agrupada por víctima.

---

## 4. Producto / UX

- **Conectar "Actualizar" a `POST /api/runs`** (ver sección 0). Es lo más chico
  y lo más visible.
- Export CSV/JSON.
- Vista de detalle por hallazgo.
- Filtro por `ar_match_reason` en la UI (el dato está, falta el selector).
- Timeline o gráfico de evolución.
- ~~Partir el tablero en pantallas~~ ✅ hecho en la sesión 3.

---

## 5. Operación y seguridad

- **El repositorio ya está inicializado** (`git init` + commit inicial en `main`). Falta remoto: el workflow de CI existe pero **nunca se ejecutó**. (El líder técnico indicó que el CI no es prioridad por ahora.)
- **La API no tiene autenticación y ahora además escribe.** Sube la prioridad de poner un proxy que autentique si sale de loopback.
- Sin rate limiting en la API. Sin backup de la base.
- `dls-monitor` baja 2 MB completos en cada corrida: falta `ETag`/`If-Modified-Since`.
- Del checklist del CLAUDE.md faltan: escaneo de imagen (trivy/grype), DAST, `pip-audit` local, gitleaks local.

---

## 6. Testing

- ~~El frontend no tiene tests~~ ✅ 14 tests sobre un DOM mínimo propio (`tests/frontend/`), integrados al `check` y al CI. Encontraron 3 bugs reales: un `for...of` sobre datos no iterables que cortaba la carga entera, `.filter` sobre una respuesta con otra forma que **crasheaba el proceso**, y los `.onion` que sí se estaban enlazando pese a lo documentado.
- Sin test de `alembic downgrade`.

---

## 7. Hallazgos que conviene no perder

- **BreachForums está incautado.** `.hn`, `.is` y `.cx` muestran el cartel de las fuerzas del orden; el resto no resuelve. Queda registrado y apagado; cuando reaparezca alcanza con setear `LEAKS_BREACHFORUMS_BASE_URLS`.
- **Ningún proveedor CTI de los 8 evaluados tiene free tier con API usable.** Ver [cti-proveedores.md](cti-proveedores.md).
- **VECERT: no integrar sin verificación independiente.** Hay un análisis público que alega credenciales hardcodeadas, API abierta sin key y redistribución de ~633.000 registros robados. Son alegaciones de un tercero, pero de gravedad suficiente para frenar.
- **Dos bugs que solo aparecieron en Docker** (ya corregidos, con tests): las listas por variable de entorno rompían el arranque porque pydantic-settings las parseaba como JSON; y `leaks serve` no creaba el schema, así que todos los endpoints devolvían 500.

---

## Prioridad sugerida

0. **Conectar "Actualizar"** — media hora, y cierra la queja que quedó abierta.
1. **Alertas** — lo único del spec original que falta entero.
2. **Completar la watchlist** — hoy se está perdiendo señal o degradando severidad; ya se puede cargar desde la UI.
3. **Tests del frontend** — es donde vive ahora la lógica sin cobertura.
4. **Loop de falsos positivos** — para que tunear deje de requerir tocar código.
