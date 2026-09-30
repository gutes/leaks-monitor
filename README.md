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

> Para repartirlo a un equipo —con los datos ya cargados— está
> **[docs/instalacion.md](docs/instalacion.md)**: qué conviene mandar, cómo
> empaquetar los datos y por qué no se reparte la imagen. Para entregarle una
> instalación a alguien que arranca de cero, la checklist paso a paso es
> **[docs/traspaso.md](docs/traspaso.md)**.


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
  `https://www.Comision Nuclear Ejemplo.gob.ar/algo` o `*.provincia-ejemplo.gob.ar` y queda
  `nuclear-ejemplo.gob.ar` / `provincia-ejemplo.gob.ar`. Un dominio cubre siempre sus subdominios, así que el comodín es
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

### Navegación

El tablero está partido en pantallas, accesibles desde el menú de arriba:

| Pantalla | Qué tiene |
|---|---|
| **Hallazgos** | Totales, filtros y la tabla paginada de hallazgos argentinos |
| **Watchlist** | Alta, baja y habilitado de lo que se monitorea, paginado |
| **Reglas** | Las 5 reglas de relevancia con su interruptor |
| **Fuentes** | Salud de cada feed y su última corrida |
| **Sitios** | Dónde vive cada sitio de leaks y desde cuándo |
| **Consola** | Actividad del pipeline en vivo |

El router va por hash (`#/watchlist`), así que el enlace se puede compartir y el
botón "atrás" funciona. Cada pantalla trae sus datos al entrar: abrir "Reglas"
no dispara la consulta de hallazgos.

El menú muestra un contador rojo sobre **Fuentes** si alguna se cayó, para que
se note desde cualquier pantalla.

### Enlaces a los datos filtrados

La tabla de hallazgos tiene una última columna 📎 con los enlaces encontrados en
la publicación: magnets, `.torrent`, file hosts (`mega.nz`, `gofile.io`, …) y
las capturas de muestra. Se clasifican en **volcado** y **muestra**.

**No son clickeables, a propósito.** El pop-up los muestra como texto para
copiar y pegar, nunca como `<a>`: apuntan a datos de terceros y a
infraestructura de quien los publicó, y un click accidental no puede ser lo que
te lleve ahí.

**El prototipo no descarga nada.** Guarda la referencia para que sepas dónde
mirar; bajar el contenido es una decisión aparte, con sus implicancias legales
y de custodia, y no la toma una herramienta automática.

Los enlaces se extraen del **HTML crudo** del post —viven en atributos `href` y
`src`, así que quitar las etiquetas se los lleva puestos— y se guardan aunque el
cuerpo del post se descarte por contener PII.

### Exposición por infostealers

Los hallazgos de Hudson Rock traen un icono 🔎 que abre el detalle de **qué
sistemas** se comprometieron, no solo cuántos equipos:

```
[empleado]  89 capturas   https://siar.nuclear-ejemplo.gob.ar/sslvpn_logon.shtml
[empleado]  64 capturas   https://webmail.nuclear-ejemplo.gob.ar
[usuario]  515.965        https://portal.prevision-ejemplo.gob.ar/clavelogon/logon.aspx
```

Son las URLs contra las que se estaba autenticando la víctima al infectarse. La
distinción **empleado vs. usuario** es la que importa: una VPN institucional con
credenciales de empleado no es lo mismo que el portal público de trámites.
Además se guardan las familias de malware predominantes y el porcentaje de
contraseñas débiles.

> **Las credenciales no están, ni acá ni en otro lado accesible.** El tier
> gratuito del proveedor devuelve solo agregados; los registros
> (email:contraseña, cookies, tokens) son su producto comercial. Verificado: el
> payload no trae un solo email. Igual las URLs pasan por el redactor, porque
> una query string puede arrastrar un identificador.

### Exportar hallazgos a un informe

Cada fila de Hallazgos tiene una casilla. Se tildan los que interesan —y la
selección **sobrevive al paginado**, así que se pueden juntar de varias
páginas— y "Exportar TXT" baja un informe con todos.

El documento va ordenado **por fecha de ocurrencia del evento**, del más
reciente al más antiguo, con los que no se pudieron fechar al final: un
hallazgo sin fecha no es "viejo", es desconocido, y mezclarlo con los de 2020
diría algo que no sabemos.

Cada ficha lleva la ocurrencia (y de dónde salió esa fecha), cuándo lo declaró
la fuente, cuándo lo vimos, víctima, dominio, sector, actor, fuente, severidad,
la referencia, **las reglas de relevancia AR con su evidencia** y un resumen de
la columna Datos:

```
  DATOS · Exposición por infostealers
    15 sistemas comprometidos · 12 de empleados · 100.0% de contraseñas débiles

      [ acceso ]   capturas  sistema
      [EMPLEADO]       150  https://correo.registro-ejemplo.gob.ar/owa/auth/logon.aspx
      [EMPLEADO]        49  https://intranet.registro-ejemplo.gob.ar
      [usuario ]         5  https://tramites.registro-ejemplo.gob.ar/pasaporte/...
```

Se eligió TXT y no PDF porque el destino es un informe, un mail o un ticket: se
pega en cualquier lado, no arrastra estilos y se puede leer dentro de veinte
años. El archivo lo arma el backend (`src/leaks/export/report.py`, funciones
puras) y el nombre no lleva nombres de víctima, porque el archivo circula.

Como todo lo demás, **el informe solo contiene metadata**: no hay credenciales
que exportar porque no se persisten, y el encabezado lo dice explícitamente.

### Exportar la watchlist

En la pantalla Watchlist, "Exportar TXT" baja el listado completo agrupado por
sector, con estado, origen (semilla o manual) e infraestructura crítica. Si hay
filtros puestos exporta lo que se está viendo, y el encabezado dice cuál se
aplicó — un TXT parcial no se puede confundir con el total.

Lo que lo convierte en informe y no en listado es el cruce contra los
hallazgos: **por cada dominio vigilado se listan los sistemas suyos que
aparecieron comprometidos alguna vez**, agrupados por hallazgo, con la fecha
del evento y la URL donde lo encontramos.

```
    activa   semilla  nuclear-ejemplo.gob.ar     Ciencia, registros y nuclear · CRÍTICO

      Comprometidos alguna vez: 11 sistemas, 14 URLs (9 de empleados)

        2026-08-09 · hudsonrock
          [EMPLEADO]  https://siar.nuclear-ejemplo.gob.ar/sslvpn_logon.shtml
          [EMPLEADO]  https://gitlab.nuclear-ejemplo.gob.ar/users/sign_in
          [EMPLEADO]  https://webmaildos.nuclear-ejemplo.gob.ar/squirrelmail/src/login.php
          [usuario ]  https://www.nuclear-ejemplo.gob.ar/becas/login
          visto en: https://cavalier.hudsonrock.com/...

        2024-12-18 · ransomware.live
          [organismo señalado por la fuente]  nuclear-ejemplo.gob.ar
          visto en: http://blogvl7...onion/news.php?id=1
```

Ahí se ve algo que ninguna pantalla muestra: el mismo organismo cayó por dos
vías distintas con año y medio de diferencia.

Tres precisiones sobre qué es cada línea, porque no son lo mismo:

- **La URL va exacta, con su path.** `/sslvpn_logon.shtml` es lo que identifica
  al sistema como la VPN institucional y `/squirrelmail/src/login.php` como un
  webmail viejo; recortado al hostname queda un dato genérico.
- **Sistemas y URLs se cuentan por separado.** `siar.nuclear-ejemplo.gob.ar/sslvpn_logon`
  y `siar.nuclear-ejemplo.gob.ar/wgcgi.cgi` son dos superficies de **un** sistema.
- **«Organismo señalado por la fuente» no es un sistema comprometido**, y por
  eso va rotulado aparte y no entra en el conteo. Ahí la fuente nombró a la
  organización sin decir qué sistema suyo cayó — y en las fuentes que se
  consultan dominio por dominio (Hudson Rock) ese valor es *el dominio que
  preguntamos nosotros*. Mezclarlo con los sistemas encontrados haría pasar la
  propia consulta por evidencia.

Un host se asigna siempre a la entrada **más específica** que lo cubra.

Este cruce existe **solo en la exportación**. En la pantalla, colgarle el
historial a cada fila convertiría una vista de administración en otra cosa.

> El historial es acumulado: que un sistema figure no significa que siga
> comprometido hoy, y que no figure no prueba que esté limpio — solo que no
> apareció en las fuentes que miramos. El informe lo dice explícitamente.

### Antigüedad de los hallazgos

El tablero distingue **cuándo ocurrió** un leak de **cuándo lo vimos**, que no
es lo mismo: una fuente que recién agregás trae su histórico entero y todo
parecería novedad del día.

La columna *Ocurrió* muestra la fecha del evento, con un chip de `reciente` /
`histórico` / `sin fecha`, y el detalle completo en el tooltip (qué declaró el
feed, cuándo lo vimos nosotros, de dónde salió la fecha).

La fecha se resuelve por cascada, todo en código: lo que declara la fuente → el
año embebido en el título (los foros titulan `[2.1TB][2026] …`) → lo que aportó
otra fuente para el mismo dominio. **Si no se puede fechar, dice "sin fecha".**
Nunca se rellena con la fecha de la consulta: una fecha inventada es creíble y
contamina el orden, las alertas y cualquier cálculo de recencia.

Dos consecuencias prácticas:

- **La importación inicial de una fuente no alerta.** Se detecta porque no
  había cursor previo y se marca como tal. Sin eso, activar una fuente con
  histórico disparaba un aviso por cada hallazgo viejo.
- **No se avisa de eventos viejos** (`LEAKS_ALERT_MAX_AGE_DAYS`, default 30), ni
  de los que no se pudieron fechar: si no se puede afirmar que es reciente, no
  se alerta.

### Catálogo de sitios de leaks

Los grupos rotan de dominio permanentemente. Los feeds que ya consumimos
publican, además de las víctimas, **el catálogo de ubicaciones de cada grupo con
su disponibilidad**, así que el prototipo lo consolida en la pantalla **Sitios**:
~979 ubicaciones de ~530 grupos, cruzando ransomware.live, dls-monitor y
RansomLook.

Lo más útil no es el listado sino el bloque de arriba: **direcciones vistas por
primera vez en los últimos 7 días**. Un grupo que estrena dominio suele estar por
publicar.

**El cruce con Argentina es lo que le da filo.** Cada grupo muestra cuántos
hallazgos argentinos tiene atribuidos, hay un filtro *solo grupos que golpearon
en AR*, y las mudanzas de esos grupos van primero y disparan una **alerta**. Que
un grupo cualquiera se mude es dato; que se mude uno que ya golpeó acá es otra
cosa.

> **El estado lo reportan los registros, no lo verificamos nosotros.** El
> prototipo **no se conecta** a ninguna de esas direcciones —no usa Tor— así que
> "en línea" significa que respondió cuando pasó el registro. Dos matices: a
> veces lo que responde es un cartel de incautación (el propio `title` lo
> delata), y solo dls-monitor publica **cuándo** revisó. ransomware.live no manda
> marca de tiempo, y en esos casos la UI dice *sin fecha de revisión* en lugar de
> aparentar frescura.

Dos cosas importantes:

- **Es un catálogo, no un colector.** Se registra dónde está cada sitio; **no se
  lo visita**. Los `.onion` de esa pantalla nunca se consultan desde acá.
- Las direcciones se muestran **como texto, nunca enlazadas**, por el mismo
  motivo que los enlaces de descarga.

Se puebla solo en cada corrida. Un registro caído se anota y el resto sigue: el
catálogo no puede costar la corrida.

### Alertas

Se avisa de los hallazgos que llegan al umbral (`LEAKS_ALERT_MIN_SEVERITY`,
default `high`) por los canales configurados: webhook genérico y Telegram.

**El estado se ve en la pantalla Fuentes.** Ese panel existe por un problema
concreto: sin canales configurados el pipeline descarta los avisos **en
silencio**, y antes de tenerlo la única forma de darse cuenta de que había
hallazgos críticos esperando a nadie era leer la base a mano. El panel dice
cuántos están pendientes, cuántos se enviaron, cuándo fue el último y —si falta
un canal— **qué variable de entorno hay que setear**.

Nunca devuelve el valor de un secreto: solo si está o no. Un token de Telegram
no sale por la API ni para diagnosticar, y hay un test que lo verifica.

Qué NO dispara aviso, a propósito:

- La **importación inicial** de una fuente. Entra su histórico entero de golpe y
  serían cientos de avisos de cosas que no son novedad.
- Los eventos **más viejos** que `LEAKS_ALERT_MAX_AGE_DAYS` (default 30).
- Los hallazgos **sin fecha**: no se puede afirmar que sean recientes.
- Las **víctimas regionales** de la sección de adyacencia: serían 1.355 avisos
  de cosas que no son nuestras. De ahí solo se avisa por **salto de score**.

El criterio de reintento es `alerted_at IS NULL` y no "recién insertado": si un
envío falla, el hallazgo sigue pendiente y se reintenta en la corrida siguiente
en vez de perderse.

**Para probar sin gastar alertas:** `LEAKS_ALERT_DRY_RUN=true` arma el aviso,
registra en la consola qué se habría mandado y por qué canales, y no envía ni
marca nada. Existe por un incidente real: verificar el cableado contra un
webhook de terceros mandó metadata de 7 hallazgos argentinos afuera y además los
consumió, porque quedaron marcados como avisados sin que nadie los recibiera.

### Consumir las alertas desde otro software

`GET /api/alerts/feed` devuelve las alertas para que las procese otra
herramienta. Una alerta es un hallazgo que llega al umbral de severidad, y se
devuelve **haya salido o no por los canales**: `notified` y `alerted_at` dicen
en qué estado está y el consumidor decide.

| Parámetro | Default | Para qué |
|---|---|---|
| `limit` / `offset` | 50 / 0 | Cuántas como máximo, y paginado |
| `desde` / `hasta` | — | Rango ISO-8601. **Los dos opcionales e independientes** |
| `campo` | `first_seen` | Sobre qué fecha filtrar y ordenar |
| `estado` | `todas` | `pendientes` o `enviadas` para acotar por despacho |
| `min_severity` | el configurado | Bajar o subir el umbral para esta consulta |

```bash
# Las últimas 20, sin importar si se despacharon
curl 'localhost:8000/api/alerts/feed?limit=20'

# Todo lo posterior a una fecha (sin `hasta`)
curl 'localhost:8000/api/alerts/feed?desde=2026-08-01T00:00:00&limit=200'

# Un mes cerrado, por fecha del EVENTO y no de importación
curl 'localhost:8000/api/alerts/feed?desde=2026-07-01T00:00:00&hasta=2026-07-31T23:59:59&campo=occurred'
```

**Para paginar incrementalmente usá `campo=first_seen`** (el default) y guardá
el `first_seen_at` más alto de la última página. Es el único campo monótono:
`occurred` retrocede cuando una importación inicial mete eventos de 2020, y un
consumidor que pagine por ahí se saltea alertas sin enterarse.

Cada ítem trae `dedup_hash` para deduplicar del lado del consumidor, y
`backfill` para distinguir el histórico que recién importamos de una novedad.

> El feed **no** aplica los filtros del despachador: incluye la importación
> inicial y lo que no se pudo fechar. Eso es política de a-quién-interrumpir, y
> un consumidor que pide un rango explícito quiere lo que hay. Por eso el mismo
> umbral puede dar 35 acá y 7 en el panel de estado.

> **No hay autenticación.** Este endpoint está pensado para que lo consuma otro
> software, así que si sale de loopback hace falta un proxy que autentique.

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
| `leaks regional-probe` | Mide qué víctimas regionales aportarían los foros y Telegram. No escribe nada. |

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
| [Hudson Rock](https://docs.hudsonrock.com/) | ✅ activo | infostealer | Verificado 2026-08-18. Detrás del toggle **y** de `LEAKS_HUDSONROCK_DOMAINS`. |
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

**La tuya no está en el repo, a propósito.** Una watchlist dice qué organismos
vigila una investigación: publicarla es publicar el mapa del trabajo. Mismo
patrón que `.env`:

| En el repo | En tu disco (`.gitignore`) |
|---|---|
| `data/examples/watchlist.yaml` | `data/watchlist.yaml` |
| `data/examples/watchlist-regional/` | `data/watchlist-regional/` |

Los ejemplos usan dominios **ficticios** (`*-ejemplo.gob.ar`) que no matchean
nada real. Es deliberado: el prototipo arranca y los tests pasan, y queda claro
que hay que armar la propia. Una watchlist seria se valida contra el inventario
de infraestructura crítica que corresponda; heredar la de otro no sirve.

```bash
cp data/examples/watchlist.yaml data/watchlist.yaml
cp -r data/examples/watchlist-regional data/watchlist-regional
```

Si el archivo real no existe, el código cae al ejemplo **y lo dice por la
bitácora**: correr con datos de ejemplo sin saberlo sería peor que no arrancar.

### Respaldarla

Apenas editás una entrada desde la pantalla Watchlist, la fuente de verdad pasa
a ser la base y el YAML queda viejo. Para respaldar lo que realmente está
vigente:

```bash
leaks export-watchlist --out mi-watchlist.yaml
```

Incluye las deshabilitadas, marcadas: perder "esto lo di de baja a propósito"
haría que la próxima siembra lo reviva.

### Formato


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

El **frontend también tiene tests** (`node --test "tests/frontend/*.test.mjs"`):
corren sobre un DOM mínimo propio, sin navegador y sin dependencias de npm.
Verifican el cableado y las reglas de seguridad de la UI — que ninguna URL de
descarga termine siendo clickeable, que el bloqueo de OPSEC corte la actividad,
que cada pantalla pida solo lo suyo y que una respuesta con forma inesperada no
tumbe la página.

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
