# Pendientes y decisiones abiertas

Estado verificado contra el código el **2026-10-13**: 900 tests backend + 50
frontend, imagen Docker corriendo, migración `0017` aplicada.

> Este archivo se desactualizó una vez y decía cosas falsas («Alertas — no
> existe nada» cuando ya existían). Cada ítem de acá se cruzó contra el código,
> no contra la memoria.

---

## 0. Lo último que se hizo (sesiones del 2026-09-30 al 10-13)

### Traspaso a otra persona — hecho y confirmado andando

Se entregó una instalación completa: paquete de datos, `.env` operativo sin la
clave del vault, y `docs/traspaso.md` como checklist autocontenida. El acceso al
repo va por **deploy key de solo lectura**, no por cuenta de GitHub.

Tres pasos del manual fallaron en la máquina de destino —**Linux, desde cero**—
y los tres estaban escritos desde macOS con el venv armado. Corregidos en el
manual, no sólo por chat:

1. `python -c "from cryptography.fernet import Fernet…"` → la clave se genera con
   `openssl rand -base64 32 | tr '+/' '-_'`.
2. `import-bundle ../paquete.tar.gz` → el path se resuelve **dentro** del
   contenedor; va en `./data`, que ya está montado en `/app/data`.
3. `/app/data no es escribible` → un bind mount conserva el uid numérico y el
   contenedor corre como uid 10001. El mensaje de error ahora lo explica y trae
   el `chown`; antes mandaba a revisar el `:ro`, que estaba bien.

**La instalación del otro lado quedó funcionando** (confirmado por el líder
técnico el 2026-10-13), con el manual ya corregido. O sea que el tramo completo
—deploy key, clon, `.env`, clave del vault, import del paquete, arranque— está
**validado de punta a punta en Linux desde cero**, que es la única prueba que
vale para este documento.

Queda ofrecida, sin respuesta y ya sin urgencia, una revisión del tramo asumiendo
ese entorno. Después de tres fallas corregidas y una instalación exitosa, el
valor que queda es preventivo.

### Exportación a IntelMQ — hecha

`/api/alerts/feed?formato=intelmq` devuelve NDJSON armonizado. **Pull, no push**:
IntelMQ tira de una URL con su collector HTTP, y así no sale metadata de
organismos argentinos hacia un tercero. Las 9 clasificaciones del CERT.ar mapean
exacto contra RSIT; los 31 tipos tienen su par canónico, con tres casos que se
corren a propósito —`ransomware` → `data-leak` el principal, decisión del líder
técnico—. Ver `docs/taxonomia.md`.

Verificado desde dentro de la red de Compose, incluida la paginación incremental:
sin duplicados por offset, sin huecos, y el borde de `desde` se repite una vez
porque es inclusivo.

### PwnForums — analizado, NO implementado

Re-sondeado el 2026-10-01: sigue devolviendo 403 con `cf-mitigated: challenge` en
**todas** las rutas, `robots.txt` incluido, idéntico al 24-sep. No hay espejo.

El adapter no es el problema: si el endpoint abriera, son ~15 líneas
(`enables_with_setting`, igual que BreachForums). Lo que falta es un endpoint que
responda.

**Recomendación sobre la mesa, esperando decisión:** importar el Atom **a mano**.
El investigador pasa el desafío en su navegador como persona, guarda el XML, y un
`leaks import-forum-atom --feed pwnforums --file x.xml` lo mete por el pipeline
completo. No es evasión —la herramienta no finge nada— y reusa `parse_atom` tal
cual, así que es un adapter con transporte de archivo. Generaliza: cualquier foro
que se meta detrás de un desafío pasa de perdido a importable.

Tampoco se sabe si el foro **vale la pena**: nunca se obtuvo un 200, así que no
está confirmado que sea MyBB ni que publique contenido argentino. La importación
manual lo contesta en una corrida, antes de construir nada continuo.

### Lo que queda abierto

* **Ningún canal de aviso configurado, y ya hay 62 hallazgos esperando.**
  `alerted_at` nulo en 62 de severidad alta o crítica, y **0 avisados en la
  historia de la instalación**. No se pierden —se reintentan— pero nadie los
  recibe. Se evaluaron las opciones (receptor propio, Telegram, Slack; Discord
  **no funciona** porque manda `text` y Discord exige `content`) y quedó sin
  elegir.
* **La VPN estaba caída el 2026-10-13 a las 20:25 UTC**: el control de salida
  bloqueaba la API con salida por AS7303 Telecom Argentina. Es el guard haciendo
  su trabajo, pero mientras dure no se consulta ninguna fuente.
* Los dos falsos positivos viejos (Indonesia, Perú) siguen en la base.

---

## Lo anterior (sesión del 2026-09-18)

### Telegram: canales privados y pagos — evaluado, no implementado

El líder técnico preguntó si un bot de BotFather sirve para entrar a canales de
pago. **No sirve**, por tres límites independientes de la Bot API (no puede
entrar solo, no lee historial, la suscripción es de una cuenta de usuario). El
veredicto y las dos rutas que sí existen —buzón de reenvío y MTProto— quedaron
en `docs/feeds.md`. **Decisión: ninguna por ahora.**

### La adyacencia ya no ve sólo ransomware

La pregunta era si la sección se actualizaba con los actores que van
apareciendo. Se actualiza todos los días, pero **dentro de un solo universo**:
`REGIONAL_SOURCES` tenía una sola entrada, ransomware.live. Medido contra la
base: 32 actores que ya golpearon Argentina no estaban en `adjacent_actors` y no
podían estar, `rabbitt1337` entre ellos.

Hecho, en tres etapas:

1. **`leaks regional-probe`** — mide qué aportarían los foros y Telegram **sin
   escribir una fila**, porque los items no argentinos nunca se guardaron y no
   había forma de backtestear. Resultado: 27 víctimas regionales en 5.877 items
   (0,46%), 17 actores nuevos, precisión 26/27.
2. **Los foros y Telegram alimentan la adyacencia** (`FeedSpec.feeds_adjacency`
   + `runner._a_victima_regional`). El criterio de país vive en
   `adjacency/country_detect.py` y es más estricto que el argentino: el dominio
   manda, el nombre del país sólo corrobora.
3. **Dos carriles** (`adjacent_actors.kind`, migración `0017`): el score está
   calibrado sobre la cadencia de un DLS y no se le aplica a un broker de
   acceso. La UI los filtra aparte.

### Lo que queda abierto de esta sesión

* **`elobservador.com.uy`** entra como víctima uruguaya y es el enlace a una
  nota periodística *sobre* un hackeo. Con un solo caso no alcanza para escribir
  una regla; si aparecen más, hay que distinguir "medio que informa" de
  "víctima".
* **El sondeo de Telegram tarda** ~10 min (228 canales con puesta al día). No
  es un problema del sondeo sino de que los extractores son secuenciales — ver
  la nota sobre paralelizar, que el líder técnico dejó explícitamente en pausa.

---

## Lo anterior (sesión del 2026-09-15)

**El caso SIPA.** Apareció en DarkForums un volcado del sistema previsional
argentino (38M registros) y no lo trajimos. La investigación descartó tres
hipótesis y encontró la causa real:

* **No fue por falta de usuario en el foro.** El thread es público: responde 200
  sin cuenta.
* **No fue el bajón de VPN** del 14 a la noche (ese hueco existe y está bien
  declarado, pero el post es de las 06:57).
* **No fue la relevancia**: matcheaba `keyword: SIPA`.
* **Causa real: vive en el subforo `fid=21`, y el índice global no lo lista.**
  Como `LEAKS_DARKFORUMS_FIDS` estaba vacío, solo leíamos el global. Nunca
  estuvo a nuestro alcance.

Arreglado y verificado:

1. **`LEAKS_DARKFORUMS_FIDS=21,45,25,13,10`**, elegidos por un barrido de los 60
   subforos buscando contenido argentino. El 21 tiene ventana de 9 días; el 45,
   de 28,8.
2. **La regla de país ahora lee el texto**, no solo el campo `country` que los
   foros nunca mandan. `[ARGENTINA] …` y "Argentina: …" cuentan como
   corroboración. Sin esto el SIPA puntuaba `low` y, con el umbral en `high`,
   no habría alertado ni capturado. Ahora da **critical**. `ar` suelto NO
   dispara, y el falso positivo histórico (Distribuidora Ejemplo Dominicana) sigue cubierto.
3. **Dos bugs de aislamiento en el adapter de foros**: un subforo con Atom roto
   tumbaba la fuente entera (el `try` cubría el request pero no el parseo, que
   es un generador y fallaba al iterar), y un índice global ilegible impedía
   llegar a los subforos — justo donde está el contenido argentino.

### Los tres pendientes, resueltos el 2026-09-15

1. **Falsos positivos de `cuit_valid`.** Prefijo válido por mod-11 deja ~0,8%
   de los números de once dígitos pasando por azar, y el cuerpo de un volcado
   trae miles: entraron una universidad de Indonesia (26 "CUIT") y una pasarela
   peruana (8). Ahora se exige **contexto**: formato canónico `NN-NNNNNNNN-N` o
   la palabra CUIT/CUIL a menos de 24 caracteres. Reevaluados contra los datos
   reales, los dos falsos positivos quedan descartados.
2. **La corrida bloqueada avisa.** `_avisar_bloqueo()` manda un aviso al
   **entrar** al estado, no en cada corrida: con el sondeo cada dos horas
   repetirlo sería un aviso por hora, y un canal que repite enseña a ignorarlo.
3. **`leaks rewind-cursor --feed X --to FECHA`.** Reemplaza el `UPDATE` a mano.
   `set_cursor` sigue sin retroceder —eso protege la corrida normal—; esto es
   la operación explícita. **Nunca pone el cursor en NULL**: eso contaría como
   importación inicial y todo entraría como `backfill`, que no alerta.

### Lo que queda abierto

* **Quedaron en la base los dos hallazgos falsos** de la corrida anterior
  (Indonesia y Perú). El arreglo evita que entren nuevos pero no borra los
  viejos; hace falta decidir si se purgan a mano o si se agrega un "descartar
  hallazgo" a la UI — que es el ítem 1.5 de este mismo archivo.
* **Sin canales de alerta configurados**, el aviso de bloqueo tampoco sale.
  `LEAKS_ALERT_WEBHOOK_URL` o el bot de Telegram siguen vacíos.

---

## Lo anterior (sesión del 2026-09-01)

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
