# Monitoreo de leaks — capa de relevancia argentina

Prototipo de threat intelligence OSINT: una vez por día ingiere feeds públicos
y gratuitos de leaks/ransomware, se queda **solo con lo que afecta a
Argentina**, deduplica y lo muestra en un frontend web de solo lectura.

No scrapea Tor ni foros por su cuenta: consume feeds de terceros y les aplica
encima una capa de relevancia argentina auditable.

**Por defecto persiste solo metadata no sensible.** Nada de credenciales,
contraseñas, emails de personas ni contenido de dumps. Ver
[Privacidad](#privacidad-y-pii).

---

## Arrancar

```bash
./scripts/dev.sh setup    # venv + dependencias + .env
./scripts/dev.sh run      # una corrida del pipeline
./scripts/dev.sh serve    # http://127.0.0.1:8000
```

O con Docker, sin instalar nada:

```bash
docker compose up -d      # API en 127.0.0.1:8000 + scheduler
```

El scheduler **corre una vez apenas arranca** (`LEAKS_RUN_ON_START=true`), así
que el tablero tiene datos a los ~20 segundos. Si lo ponés en `false`, espera a
`LEAKS_DAILY_RUN_AT` (03:00) y hasta entonces el tablero está vacío.

### Control de IP de salida (OPSEC)

**Si el tráfico sale desde Argentina, el prototipo no consulta ninguna fuente.**

El motivo es operacional: monitorear filtraciones de organismos argentinos
consultando esos mismos índices desde una IP argentina expone al investigador.
La VPN es parte del procedimiento, no una comodidad.

Cómo funciona:

* Arriba de todo hay un badge con la **IP de salida, el país y el proveedor**
  (el proveedor es lo que delata de un vistazo si estás saliendo por la VPN o
  por la conexión de casa).
* Si la salida es desde un país bloqueado, la UI se tapa con un **modal sin
  cierre**: no tiene botón, no acepta ESC y no se puede saltar.
* El bloqueo real **no está en el navegador**: está en el pipeline. El
  scheduler corre en otro proceso y verifica la salida *antes de tocar una sola
  fuente*. Un modal no detendría al scheduler; esto sí.
* **Fail-closed**: si no se puede determinar el país, también bloquea. El
  control promete que no se sale por AR, y una IP sin resolver no da esa
  garantía.
* Se libera solo: en cuanto la salida deja de estar bloqueada, el tablero
  vuelve sin recargar.

No hay override desde la interfaz, a propósito. Los países bloqueados son
configuración de despliegue (`LEAKS_EGRESS_BLOCKED_COUNTRIES`, default `AR`).

### Watchlist gestionable

En la sección **Watchlist monitoreada** se ve todo lo que se está vigilando y se
puede editar sin tocar archivos:

* **Agregar** dominios o keywords. Los dominios se normalizan solos: pegá
  `https://www.Comision Nuclear Ejemplo.gob.ar/algo` o `*.gba.gob.ar` y queda `nuclear-ejemplo.gob.ar` /
  `gba.gob.ar`. Un dominio cubre siempre sus subdominios, así que el comodín es
  redundante.
* **Deshabilitar** — baja lógica que **persiste**: la entrada deja de matchear
  pero no se pierde, y se rehabilita cuando quieras.
* **Eliminar** — para bajas definitivas.

También se pueden **prender y apagar las cinco reglas de relevancia** (típicamente
`keyword`, que es la más ruidosa). Todo aplica en la corrida siguiente, sin
reiniciar nada.

El YAML `data/watchlist.yaml` pasó a ser la **semilla**: se importa a la base la
primera vez y queda versionado como respaldo. La base es la fuente de verdad
desde entonces (el contenedor corre con filesystem de solo lectura).

### Fuentes con PII

Arriba a la derecha, pegado a la pastilla de estado, hay un interruptor que
habilita las fuentes cuyo contenido son volcados de datos (foros). La pastilla
muestra el estado **realmente vigente**, que persiste entre sesiones:

| Pastilla | Qué significa |
|---|---|
| `PII: OFF` | Las fuentes con PII no corren. Es el default. |
| `PII: fuentes ON · sin guardar` | Corren, pero no hay clave de cifrado: la PII se descarta y solo queda metadata. |
| `PII: ON · cifrada` | Corren y los registros se guardan cifrados, con retención. |

Son **dos cosas distintas** y conviene no confundirlas:

* el **interruptor** decide si esas fuentes *corren*. Se guarda en la base y
  cambia en caliente;
* **persistir** PII exige `LEAKS_STORE_PII=true` **y**
  `LEAKS_PII_ENCRYPTION_KEY` en el entorno. Un interruptor de una UI sin
  autenticación no puede crear esa clave ni suplirla.

### Consola de actividad

Abajo del tablero hay una consola en vivo que muestra **a qué sitio le está
pegando el pipeline**, qué respondió y cuánto tardó:

```
19:36:12  pipeline         Corrida iniciada — 4 fuentes en el registro
19:36:14  ransomware.live  GET https://api.ransomware.live/v2/countryvictims/AR → 429, reintentando
19:36:20  ransomware.live  GET https://api.ransomware.live/v2/countryvictims/AR → 200 · 200 · 3.5s · 109 KB
19:36:23  ransomware.live  283 traídos, 184 relevantes AR, 183 nuevos
19:36:30  hudsonrock       Salteado: requiere STORE_PII=true
19:36:30  pipeline         Corrida terminada en 17.7 s
```

La línea más reciente va **arriba**. Se actualiza sola cada 2 s y **no pierde
nada**: sube por cursor (`after_id`), así que no repite ni saltea líneas. El
botón **Limpiar** vacía la vista, no la bitácora. El checkbox **seguir**
controla el autoscroll — si te vas a leer más abajo, la consola no te arrastra
de vuelta.

El pipeline y la API son procesos distintos (contenedores distintos en Docker),
así que el canal es la base que ya comparten: el pipeline escribe en
`run_events` y la API la sirve por `GET /api/events`. Los eventos llevan URL,
código de estado y conteos — **nunca PII ni contenido de los feeds**.

### Comandos

| Comando | Qué hace |
|---|---|
| `leaks run` | Una corrida y termina. Es lo que va en el cron. |
| `leaks schedule` | Corrida diaria a `LEAKS_DAILY_RUN_AT` (default 03:00). |
| `leaks serve` | API + frontend de solo lectura. |
| `leaks feeds` | Lista los feeds, si corren y con qué licencia. |
| `leaks init-db` | Crea el schema. |
| `leaks purge-pii` | Aplica la retención de la bóveda cifrada y de la bitácora. |

`leaks run` devuelve **1** si ninguna fuente respondió, para que el cron se
entere. Si una sola fuente falla, devuelve 0 y sigue: eso es diseño, no
descuido.

---

## Qué hace, en orden

```
feeds públicos ─▶ adapters ─▶ relevancia AR ─▶ privacidad ─▶ SQLite ─▶ API ─▶ frontend
                (por fuente)  (5 reglas)      (scrubber)   (dedup)
```

1. **Adapters** — un módulo por feed, todos detrás de la misma interfaz.
   Sumar una fuente es implementar `FeedAdapter` + una entrada en el registro;
   el core no se toca.
2. **Relevancia AR** — cinco reglas independientes; cada match guarda **qué
   regla disparó** (`ar_match_reason`) y con qué evidencia. Sin eso no se
   pueden tunear los falsos positivos.
3. **Privacidad** — el texto libre pasa por un scrubber fail-closed: si tiene
   PII, se descarta el campo entero (no se enmascara).
4. **Persistencia** — SQLite, idempotente por `dedup_hash`. Re-correr no
   duplica.

### Las cinco reglas de relevancia

| Regla | Dispara cuando | Ejemplo |
|---|---|---|
| `watchlist` | El dominio (o un subdominio) está en `data/watchlist.yaml` | `datos.prevision-ejemplo.gob.ar` |
| `tld_ar` | Cualquier dominio bajo `.ar` | `obrasocial-ejemplo.com.ar` |
| `country_ar` | El feed declara país AR/Argentina | `"country": "AR"` |
| `cuit_valid` | Hay un CUIT/CUIL **con dígito verificador válido** | `30-71234567-8` |
| `keyword` | Aparece un organismo/empresa de la watchlist | "Ministerio de Economía" |

Un item sin ninguna regla no es un hallazgo argentino: se descarta.

**El CUIT se valida, no se detecta.** Buscar "once dígitos" no sirve: uno de
cada once números al azar pasa el módulo 11 por probabilidad. Se valida dígito
verificador **y** prefijo, y el número se guarda enmascarado (`30-********-8`)
porque el CUIT completo de una persona física es PII.

**La keyword sola no escala a crítica.** Caso real de la primera corrida:
*Distribuidora Ejemplo Dominicana* (distribuidora dominicana) matcheaba la keyword `DISTRIBUIDORA EJEMPLO` y,
como energía está marcado infraestructura crítica, salía como `critical` entre
organismos argentinos reales. Hoy la severidad máxima exige una regla que
corrobore la identidad argentina (dominio `.ar`, país o CUIT). Está cubierto por
un test de regresión.

---

## Feeds

Estado verificado el **2026-08-14**. Los modelos de acceso cambian: reverificar
antes de confiar.

| Feed | Estado | Tipo | Notas |
|---|---|---|---|
| [ransomware.live](https://api.ransomware.live/v2) | ✅ activo | ransomware | **Tier free: uso personal, NO corporativo.** Ver abajo. |
| [RansomLook](https://www.ransomlook.io/) | ✅ activo | ransomware | Open source. Sin país ni dominio estructurado. |
| [dls-monitor](https://github.com/cyberiskvision/dls-monitor) | ✅ activo | ransomware | Histórico completo (~14k posts) vía `posts.json`. |
| [DarkForums](https://darkforums.ru) | ✅ activo | foro | Atom público. **Fuente con PII**: detrás del toggle. |
| BreachForums | ❌ **incautado** | foro | Todos los dominios conocidos muestran el cartel de incautación. |
| [Hudson Rock](https://docs.hudsonrock.com/) | ⚠️ **sin verificar** | infostealer | No respondía (timeout 60 s). Deshabilitado + `STORE_PII`. |
| [ecrime.ch](https://ecrime.ch/) | ❌ no integrable | ransomware | Solo búsqueda web por nombre de archivo; sin API pública. |
| [WhiteIntel](https://whiteintel.io/) | ❌ no integrable | infostealer | El tier free exige cuenta; sin API pública documentada. |

> ### ⚠️ Licencia de ransomware.live
> El tier gratuito es **"personal use only, not for corporate/business use"**.
> Alcanza para este prototipo. **No habilita un despliegue institucional** sobre
> la licencia free: para eso hay que contratar el tier que corresponda.

Detalle por feed, límites y política de User-Agent: [`docs/feeds.md`](docs/feeds.md).

**Proveedores CTI comerciales** (Axur, SOCRadar, VECERT, Group-IB, Breachsense,
SpyCloud, Cybersixgill, Flare): se evaluaron y **ninguno tiene free tier con API
usable** para ingesta automática — el free tier, cuando existe, es una demo del
panel web. Detalle y fuentes en
[`docs/cti-proveedores.md`](docs/cti-proveedores.md).

### Fase 2 (no implementado, hooks listos)

GitHub secret scanning sobre orgs `.gob.ar`, Telegram (MTProto) y paste sites.
La interfaz `FeedAdapter` y el registro ya los contemplan: son un adapter nuevo,
no un rediseño.

---

## Privacidad y PII

Estas reglas son el piso del proyecto, no una recomendación.

**Por defecto se persiste solo:** organización/víctima, dominio, país, sector,
grupo/actor, fecha, URL de la fuente, `ar_match_reason`, severidad y hash de
dedup.

**Nunca se persiste por defecto:** credenciales, contraseñas, emails de
personas físicas, hashes de password, cookies/tokens, contenido de dumps ni PII
de individuos.

- El scrubber es **fail-closed**: un texto libre con cualquier rastro de PII se
  descarta **entero**. Enmascarar deja margen a que se filtre por un patrón no
  previsto; perder contexto es más barato.
- Todo lo record-level va detrás de `LEAKS_STORE_PII` (**default: `false`**),
  en una tabla **separada** (`pii_records`), **cifrada** con Fernet y con
  retención configurable que se aplica en cada corrida.
- `STORE_PII=true` **sin clave de cifrado no arranca el proceso**. No hay
  degradación silenciosa a "lo guardo en claro".
- La API **no expone** la tabla de PII ni con el flag activo.
- La watchlist y los resultados **no se mandan a terceros ni a LLMs**. La única
  excepción posible es Hudson Rock, que por diseño consulta *solo* los dominios
  que se listen a mano en `LEAKS_HUDSONROCK_DOMAINS` — nunca la watchlist.

Verificable desde afuera: `GET /api/health` publica el valor de `store_pii`.

### Secretos

Solo por entorno o secrets manager. Nunca hardcodeados, nunca en logs, nunca
commiteados. `.env.example` no tiene valores reales; `.env` está en `.gitignore`.
Los mensajes de error se truncan y nunca vuelcan el body de una respuesta.

```bash
# Generar la clave de cifrado (solo si vas a activar STORE_PII)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## La watchlist

`data/watchlist.yaml` es **dato, no código**: sumar un organismo es agregar una
línea. Las siglas de menos de 4 caracteres se descartan al cargar (`ARCA`
pegaría dentro de "arcade").

> ⚠️ La lista que viene es un **punto de partida SEED, no autoritativa ni
> exhaustiva**. Antes de cualquier uso real hay que validarla y completarla
> contra el inventario de activos / la designación de infraestructura crítica
> del CNC.

---

## Seguridad del despliegue

**La API no tiene autenticación** y sirve en `127.0.0.1` por defecto. Son
hallazgos de seguridad de organismos públicos: exponerla a una red requiere un
proxy que autentique adelante. El `docker-compose.yml` publica el puerto solo en
loopback a propósito.

El frontend trata el contenido de los feeds como hostil: todo texto se inserta
con `textContent` (nunca `innerHTML`), los `href` se validan por esquema (un
`javascript:` sería XSS) y los enlaces `.onion` se muestran sin enlazar.

---

## Desarrollo

```bash
./scripts/dev.sh check   # lint + formato + tipos + tests + SAST (lo mismo que el CI)
```

Ningún test toca la red: los adapters corren contra fixtures capturadas en
`tests/fixtures/`. El CI corre en cada push y es determinístico y offline.

Estructura:

```
src/leaks/
  domain/      modelos y puertos — el núcleo, sin HTTP ni SQL
  adapters/    un módulo por feed + el registro declarativo
  relevance/   watchlist, CUIT, reglas AR y severidad
  privacy/     scrubber de texto libre
  storage/     SQLAlchemy, dedup, consultas y bóveda cifrada
  pipeline/    runner y scheduler
  api/         FastAPI de solo lectura
  bootstrap.py composition root
frontend/      HTML + JS + CSS, sin frameworks
```

Documentación: [arquitectura](docs/arquitectura.md) · [feeds](docs/feeds.md) ·
[privacidad](docs/privacidad.md) · [proveedores CTI](docs/cti-proveedores.md) ·
**[pendientes y decisiones abiertas](docs/pendientes.md)**.

---

## Alcance

Es un **prototipo**. Antes de un uso institucional hace falta, como mínimo:
validar la watchlist contra el inventario del CNC, resolver la licencia de
ransomware.live, poner autenticación adelante de la API (que además ahora
escribe), y reverificar el modelo de acceso de cada feed.

El estado del trabajo, lo que falta y los supuestos que esperan confirmación
están en **[`docs/pendientes.md`](docs/pendientes.md)**.
