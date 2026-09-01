# Arquitectura

## Forma general

Hexagonal, en una versión chica y sin ceremonia. El núcleo (`domain/`) define
modelos y **puertos**; todo lo que toca el mundo exterior —HTTP, SQLAlchemy,
proveedores— entra como **adaptador** por afuera.

```
                    ┌──────────────────────────────────┐
   feeds HTTP ──▶   │  adapters/   (FeedAdapter)       │
                    ├──────────────────────────────────┤
                    │  pipeline/   runner + scheduler  │
                    │  relevance/  reglas AR + sever.  │  ← núcleo, sin I/O
                    │  privacy/    scrubber            │
                    │  domain/     modelos + puertos   │
                    ├──────────────────────────────────┤
   SQLite   ◀────   │  storage/    (FindingRepository) │
                    └──────────────────────────────────┘
                                   │
                    api/ (solo lectura) ──▶ frontend/
```

Consecuencia práctica: los tests arman el pipeline completo con un doble de
feed y una SQLite temporal. **Ningún test toca la red.**

## Decisiones y por qué

### Catálogos declarativos en vez de cableado

Dos familias crecen sin parar: los **feeds** y los **organismos**. Las dos se
modelan como dato inmutable que leen todos los consumidores.

- `adapters/registry.py` — un `FeedSpec` por feed: cómo se construye, su
  licencia, si toca PII, con qué User-Agent. Sumar un feed = una entrada + su
  clase.
- `data/watchlist.yaml` — sumar un organismo = una línea de YAML.
- `relevance/severity.py` — las reglas de severidad son una tupla de
  `SeverityRule` evaluada en orden, no una escalera de `if`.

### Separación escritura / lectura

`SqlAlchemyFindingRepository` escribe; `FindingQueryService` lee. Son
responsabilidades distintas y mezclarlas termina en un objeto que hace de todo.

**La API no escribe en `findings`.** Sí escribe en las tablas de configuración
—watchlist, reglas, toggle de PII— y dispara corridas, pero los hallazgos los
produce únicamente el pipeline. La exportación a TXT
(`POST /api/findings/export`) es POST por el tamaño del cuerpo, no porque
escriba: manda solo ids y devuelve texto.

### Idempotencia por `dedup_hash`

`sha256(source | víctima | actor | día)`.

- Se usa el **día** y no el timestamp completo: varios feeds reescriben
  `discovered` con jitter de microsegundos al republicar su índice, y un hash
  sobre el timestamp exacto generaría un duplicado nuevo en cada corrida.
- Se prefiere el **dominio** sobre el nombre: los feeds escriben el mismo
  nombre de mil formas ("Ministerio X", "MINISTERIO X S.A."), el dominio es
  limpio.
- `source` entra en el hash **a propósito**: que dos feeds independientes vean
  el mismo hallazgo es señal, no ruido.

### Aislamiento por fuente

Cada feed corre en su propio `try/except`. Uno que se cae queda `failed` en
`source_runs` y el run sigue. Los feeds salteados **también** se registran: un
feed invisible es un feed olvidado, y el frontend los muestra.

### Incremental por cursor

Cada fuente lleva su marca en `source_state`. El cursor **nunca retrocede**: si
una corrida trae datos viejos, la marca queda donde estaba.

Dónde se recorta depende del volumen: para feeds chicos lo hace el runner sobre
el item ya normalizado; `dls-monitor` (14.000 posts históricos) lo hace en su
propio `fetch`, antes de normalizar.

### Severidad derivada, nunca la del feed

La calculamos nosotros a partir del veredicto de relevancia. La que declare el
feed responde a los intereses de quien publica.

`critical` exige **corroboración**: una keyword sola no alcanza aunque el
sector esté marcado crítico (ver el caso Distribuidora Ejemplo Dominicana en el README).

### Cadencia: una diaria, y sondeos para las fuentes efímeras

El scheduler no tiene una sola cadencia. La corrida completa va a la hora
configurada (`LEAKS_DAILY_RUN_AT`), pero una fuente puede declarar
`poll_interval_minutes` en el registro y se la sondea aparte, más seguido.

Es para las fuentes cuya **ventana de publicación es más corta que un día**: la
sindicación de un foro expone los últimos N threads y nada más, así que si el
foro los rota en horas, verla una vez por día no baja la resolución — pierde lo
que pasó en el medio. Hoy la declara solo `darkforums` (120 min).

Dos decisiones que sostienen esto:

* **La cadencia es dato, no cableado.** Vive en el `FeedSpec`, como el resto de
  la política por fuente. Sumar una fuente de ventana corta no toca el
  scheduler ni el CLI.
* **Acotar la corrida no saltea ninguna puerta.** `PipelineRunner.run(only=…)`
  filtra por nombre *después* de resolver el registro, así que el sondeo pasa
  por el control de IP de salida y por el gate de PII igual que la corrida
  diaria. Si `only` armara su propia selección, sondear sería la forma de
  correr una fuente `requires_pii` con la PII deshabilitada.

### Zona horaria

Naive vs aware se decide **en el borde**: `adapters/parsing.py` convierte todo a
aware en UTC y `NormalizedItem` lo valida. De ahí para adentro no hay ambigüedad.
El scheduler es la excepción deliberada: razona en hora local, porque un
investigador piensa en su horario.

## Modelo de datos

| Tabla | Para qué |
|---|---|
| `findings` | Hallazgos argentinos. **Solo metadata no sensible.** Único por `dedup_hash`. |
| `source_runs` | Telemetría por feed y corrida: salud de las fuentes. |
| `source_state` | Cursor incremental por fuente. |
| `pii_records` | Payloads cifrados. Vacía salvo `STORE_PII=true`. |
| `run_events` | Bitácora de actividad: lo que muestra la consola del frontend. |

Migraciones con Alembic (`alembic upgrade head`). `leaks run` crea el schema si
falta, para que arranque de cero con un solo comando.

### La consola de actividad

El pipeline reporta lo que hace a un puerto `EventSink`; el cliente HTTP emite
un evento por request (URL, estado, duración, bytes) y el runner uno por
fuente. La implementación por default persiste en `run_events`.

Por qué la base y no el log del proceso: **el pipeline y la API son procesos
distintos** (contenedores distintos en Docker), y la base es el único canal que
ya comparten. Meter una cola o un websocket sería infraestructura nueva para
mover veinte líneas por corrida.

El frontend poletea `GET /api/events?after_id=N` cada 2 s. El cursor por id es
lo que hace que no repita ni pierda líneas — importa porque la consola es
append-only por diseño.

Dos defensas: el sink se traga sus propios errores, y además el runner envuelve
cada `emit`. Perder una corrida porque falló el panel que la muestra sería el
peor intercambio posible.

Retención: `LEAKS_EVENT_RETENTION_DAYS` (default 14), aplicada por
`leaks purge-pii`. Es un panel de actividad, no un archivo histórico.

### Puesta al día del esquema

`create_all` crea las tablas que faltan pero **nunca agrega una columna a una
tabla que ya existe**. Mientras el esquema no cambió eso alcanzó; al sumar una
columna, los despliegues existentes seguían arrancando y fallaban en el primer
`SELECT` que la tocaba.

Ahora manda Alembic (`storage/schema.py`), con tres caminos:

* **Base nueva** → `create_all` + `stamp head` (más rápido que encadenar todas
  las migraciones).
* **Base con `alembic_version`** → `upgrade head`.
* **Base anterior a Alembic** → se agregan las columnas que falten (solo
  aditivo y solo nullable) y se sella. Arreglo de una sola vez.

Si las migraciones no están en la imagen, se degrada a reconciliar columnas y se
avisa, en vez de reventar el arranque.

## Fase 2

`FeedAdapter` y el registro ya contemplan GitHub secret scanning, Telegram y
paste sites: son un adapter nuevo más una entrada, no un rediseño. Los tipos
`LeakType.PASTE` y `LeakType.REPO_SECRET` ya existen.
