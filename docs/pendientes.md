# Pendientes y decisiones abiertas

Estado verificado contra el código el **2026-09-01**: 716 tests backend + 43
frontend, imagen Docker corriendo, migración `0015` aplicada.

> Este archivo se desactualizó una vez y decía cosas falsas («Alertas — no
> existe nada» cuando ya existían). Cada ítem de acá se cruzó contra el código,
> no contra la memoria.

---

## 0. Lo último que se hizo (sesión del 2026-09-01)

El disparador: un thread argentino del **28-ago** que el pipeline nunca trajo.
La investigación encontró tres causas encadenadas, y se atacaron las tres.

**Hecho y verificado** (commits `416a67f`, `1c9662f`, `856a393`, `33d8135`,
`92f1c04`, todos pusheados):

1. **darkforums.ru murió** — el DNS resolvía pero el 443 rechazaba la conexión.
   El dominio vivo hoy es `darkforums.as`. El error del adapter ahora dice la
   causa por dominio (`describe_cause`), que antes había que reproducir a mano.
2. **La ventana era de 3,3 h** — `syndication.php` acepta `limit`, y con
   `limit=50` (el tope de MyBB) pasó a 20,6 h medidas.
3. **La corrida era diaria** — `FeedSpec.poll_interval_minutes`; darkforums se
   sondea cada 120 min. El scheduler elige el evento más próximo (`plan_next`).
4. **Las pérdidas eran invisibles** — `source_runs.gap_from/gap_to` declara el
   tramo que la fuente publicó y no vimos, y `window_from/window_to` mide la
   ventana real en cada corrida. Los dos se ven en la pantalla Fuentes.
5. **Nadie avisaba que el pipeline estaba caído** — `pipeline/watchdog.py`, que
   mide contra la última corrida **exitosa**. Umbral
   `LEAKS_WATCHDOG_MAX_SILENCE_HOURS`, 26 h.
6. **Los subforos suman ventana** — `LEAKS_DARKFORUMS_FIDS`, y
   `leaks discover-fids` + botón "Buscar subforos" en la tarjeta del foro para
   encontrarlos por la sindicación abierta.

### El pendiente inmediato

**Elegir qué fids activar.** El barrido encontró 20 subforos en el rango 1..30,
con ventanas de 1,8 a 1.226 días, pero `LEAKS_DARKFORUMS_FIDS` **sigue vacío**.
Recomendación dada al líder técnico y todavía sin respuesta: empezar por **25**
(*All Stealers, Discord breaches*), **13** (*SMTPs / WEBMAILS / OFFICE365*) y
**10** (bases de datos), que son los temáticamente relevantes. Los otros —
crypto-cash, métodos de TikTok— traerían ruido, y cada fid es un GET más por
sondeo.

Al activarlos, la primera corrida va a traer una tanda de threads viejos de
golpe. No inunda de alertas porque `alert_max_age_days` (30) filtra lo viejo,
pero el conteo de hallazgos va a saltar.

### Lo que NO se pudo hacer, y por qué

**El thread del 28-ago no se recuperó.** Ninguna ventana llega hasta ahí. Sí
aparecieron dos hallazgos argentinos que se habían perdido y que los subforos sí
alcanzan (`fid=13`, 26-ago; `fid=25`, 21-ago) — otro argumento para activarlos.

**El HTML del foro está vetado.** `index.php` devuelve un desafío JS de vshield;
`syndication.php` no lo tiene. Pasar ese control con un browser headless sería
evadir un control de acceso: **no se hace**, y por eso el descubrimiento se
apoya solo en la sindicación. Esto ya está escrito en `docs/feeds.md`; si
reaparece la idea de scrapear la búsqueda del foro, la respuesta es esta.

---

## Lo que YA está (para no re-preguntar)

| | |
|---|---|
| Pipeline diario | 6 fuentes, aisladas, incremental por cursor |
| Relevancia AR | 5 reglas auditables, editables desde la UI |
| Frescura | ocurrencia vs. descubrimiento vs. importación inicial |
| Alertas | `AlertDispatcher` + registro de canales (webhook, Telegram) |
| Botón "Actualizar" | conectado a `POST /api/runs`, con estado en vivo |
| Exportación TXT | hallazgos seleccionados y watchlist con historial de compromisos |
| Exposición infostealer | qué sistemas cayeron, con la URL exacta |
| Catálogo de sitios | 979 ubicaciones, señal de mudanza de dominio |
| Adyacencia | 1.353 víctimas, 156 actores, score calibrado por backtest, vista propia |
| Telegram | canales públicos, gestión de canales, cursor incremental |
| Pantallas | 8, con router por hash y paginado |

---

## 1. Lo que falta, por orden de valor

### 1.1 — El handle del canal de Chronus

**Es lo más valioso y lo más barato: no requiere código.** La maquinaria de
Telegram está lista y probada, pero hasta que no se cargue el canal real de
Chronus Team (y de Sherlock, Dictadores, La Pampa Leaks) se están vigilando
canales globales que no tocan Argentina.

No está en ningún catálogo público: de 1.025 filas de deepdarkCTI, 4 son de la
región y ninguna es de estos actores. Ver `docs/hueco-hacktivistas.md`.

### 1.2 — Watchlist regional por país (adyacencia)

Falta `data/watchlist/<cc>.yaml` y su gestión. Hoy la **afinidad sectorial** del
score se calcula contra los sectores que se golpean en Argentina, que funciona,
pero no se puede distinguir "cayó un ministerio chileno" de "cayó una PyME
brasileña". Es el último incremento del plan aprobado.

### 1.3 — Alerta por salto de score

`score_prev` ya se persiste y la variación se muestra en la vista. Falta
disparar el aviso cuando un candidato pega un salto. `dispatch_notice()` ya
existe —lo usan las mudanzas de dominio—, así que es cablear, no construir.

**Ojo:** no alertar por víctima regional (serían 1.353 avisos de cosas que no
son nuestras), solo por salto.

### 1.4 — Sector vacío en dls-monitor y foros

100% de los hallazgos de esas fuentes no tienen sector, porque el feed no lo
trae. **Ya lo sabemos por otra vía**: si el hallazgo matcheó la watchlist,
conocemos su sector. Falta derivarlo en `_to_finding`.

### 1.5 — Loop de falsos positivos

No hay forma de descartar un hallazgo ni una allowlist. El caso *Distribuidora Ejemplo
Dominicana* se corrigió tocando código; debería ser dato.

### 1.6 — Vista agrupada por víctima

Por diseño `source` entra en el `dedup_hash`, así que la misma víctima aparece
una vez por feed que la publique. Falta la vista que las agrupe.

---

## 2. Producto / UX

- **Export CSV/JSON.** El TXT es para leer; un CSV es para cruzar con otra
  herramienta. Otro caso de uso, no un reemplazo.
- **Filtro por `ar_match_reason` en la UI.** El dato está y es la columna
  auditable; falta el selector.
- Vista de detalle por hallazgo.
- Timeline o gráfico de evolución.

---

## 3. Operación y seguridad

| # | Pendiente | Por qué importa |
|---|---|---|
| 1 | **La API no tiene autenticación y escribe.** | Aceptable en loopback. Si sale a una red, hace falta un proxy que autentique — son hallazgos de seguridad de organismos públicos. |
| 2 | Sin rate limiting en la API. | — |
| 3 | Sin backup de la base. | — |
| 4 | **CI nunca corrió**: no hay remoto. | El workflow existe. El líder técnico indicó que no es prioridad. |
| 5 | **Watchlist sin validar contra el CNC.** | 288 entradas en 11 sectores. No se pudo verificar por DNS: el nodo VPN no alcanza sitios `.ar`. |
| 6 | `dls-monitor` sin ETag. | Se baja entero en cada corrida. |

---

## 4. Decisiones tomadas por mí que siguen abiertas

Todas reversibles.

| # | Decisión | Alternativa |
|---|---|---|
| 1 | **Bloquear también cuando el país es indeterminable** (`EGRESS_BLOCK_ON_UNKNOWN=true`). El pedido fue "bloquear si es AR"; interpreté fail-closed porque el control promete que *no* se sale por AR, y una IP sin resolver no da esa garantía. **Costo:** si la geo-IP se cae, el monitoreo se detiene. | `false`: prioriza disponibilidad sobre garantía. |
| 2 | **La API dejó de ser solo-lectura**, detrás de `LEAKS_ALLOW_RULE_EDITING` (default `true`). | `false`, o auth adelante. |
| 3 | **El handle del autor de un thread se guarda como `actor`.** Es un seudónimo público, igual que el nombre de un grupo. | Hashearlo si se considera PII. |
| 4 | **Los canales de Telegram guardan el cuerpo en el vault cifrado** (decisión del líder técnico, sesión 6), solo con `STORE_PII=true`. | Solo metadata. |

---

## 5. Límites conocidos que ningún código arregla

Están acá para que no se prometan de más:

- **El score de adyacencia es ciego al 46%** de los actores que golpean
  Argentina: la eligieron como su primera víctima latinoamericana y no hay
  precursor regional que puntuar. Ver `docs/adyacencia.md`.
- **Solo se ve lo que las fuentes publican.** Un actor que ninguna fuente
  trackea no aparece — es lo que pasó con Chronus. Se arregla sumando fuentes,
  no ajustando pesos. Ver `docs/hueco-hacktivistas.md`.
- **Las credenciales de Hudson Rock no vienen** en el tier gratuito: son su
  producto comercial. Lo que se obtiene son agregados y URLs.
