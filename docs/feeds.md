# Feeds: modelo de acceso, límites y política

Estado verificado el **2026-08-14** consultando cada endpoint. Los feeds de
este rubro cambian de modelo de acceso sin avisar: **reverificar antes de
confiar**, y actualizar esta tabla en el mismo commit.

## telegram — canales públicos de actores

- **Endpoint:** `https://t.me/s/<canal>` — la vista previa web pública.
- **Autenticación:** ninguna. Sin cuenta, sin API key y sin Tor.
- **Estado:** verificado el 2026-08-18. HTTP 200, 20 mensajes por página, con
  `datetime` real y `data-post` que sirve de cursor incremental.

### Por qué existe

Las tres fuentes de ransomware indexan **data leak sites de bandas de
ransomware**. Los colectivos hacktivistas que van contra el sector público
argentino publican por **Telegram**. Chronus Team golpeó México el 2026-01-30 y
Argentina el 2026-03-30 —una docena de organismos públicos, entre ellos el
banco central y varios ministerios—
una obra social provincial— y la base no tenía ni una fila. Ver `docs/hueco-hacktivistas.md`.

Además esta clase de actor **anuncia sus objetivos antes de atacar**: Chronus
avisó en su canal con un mes de anticipación.

### Qué se descartó y por qué

- **MTProto / Telethon**: da más, pero exige `api_id` y un número de teléfono.
  Es una identidad que quemar y una cuenta que se puede banear. Para leer
  canales públicos no hace falta.
- **Bot API**: un bot solo lee canales de los que es miembro. No sirve.

### Qué se persiste

- A `findings`, **metadata**: canal, fecha, URL del post y la **primera línea**
  del mensaje, topeada en 300 caracteres y pasada por el redactor. El título es
  la primera línea a propósito: un volcado de cien líneas de credenciales no
  puede terminar en el nombre de la víctima.
- El cuerpo **entero y sin recortar** se le pasa a la capa de relevancia, que lo
  lee en memoria y lo descarta. Es imprescindible: estos canales ponen un
  titular genérico —«MEGA LEAK 2026»— y el organismo afectado cientos de
  caracteres más abajo. Recortarlo antes de evaluar hacía invisible a
  `prevision-ejemplo.gob.ar` en la línea 22, y el hallazgo nunca se creaba.
- El **cuerpo completo** viaja en `RawItem.payload` y va al vault cifrado, y
  **solo con `STORE_PII=true`**. Sin clave se descarta; nunca se guarda en claro.

### Gestión de canales

Nada se consulta por defecto: hacen falta canales **dados de alta y
habilitados**. Se administran desde la pantalla Telegram.

Para cargar muchos de una —el caso real, una lista sacada de un informe— hay
alta masiva. Desde la pantalla, en «Pegar una lista de canales», o por línea de
comandos:

```bash
leaks import-telegram canales.txt            # entran apagados
leaks import-telegram canales.txt --enabled  # y habilitados
```

Un canal por línea, en cualquiera de las formas habituales (`@x`, `t.me/x`, la
URL), con columnas opcionales `canal, actor, tipo, nota` separadas por coma,
punto y coma o tabulación. Las líneas con `#` se ignoran.

**Lo que no se pudo leer se reporta línea por línea, con el motivo.** Saltearlo
en silencio haría creer que se están vigilando canales que nunca entraron, y no
hay forma de notarlo hasta que hace falta.

Se rechazan antes de generar un pedido las direcciones que no se pueden leer en
abierto: `t.me/+…` y `t.me/joinchat/…` son invitaciones a grupos privados.

Un canal que no aporta nada anota **por qué**: `el canal no existe` (Telegram
devuelve su página de "Contact") o `sin vista previa pública` (privado). Sin
eso, un canal muerto se ve igual que uno tranquilo y nadie se entera.

### El catálogo público

Se importa de `fastfire/deepdarkCTI` (`telegram_threat_actors.md`). Medido el
2026-08-18: **1.025 filas, 390 no marcadas como muertas, 344 canales públicos
únicos**. De 25 canales de filtración verificados uno por uno, **16** tenían
vista previa real.

**El catálogo no trae a los actores que importan acá**: Chronus Team, Gov.eth,
Sherlock, Dictadores y La Pampa Leaks no figuran; de 1.025 filas solo 4 son de
la región. Por eso el alta manual es el mecanismo principal y esto una
conveniencia. Los importados entran **deshabilitados**.

## Resumen

| Feed | Auth | Formato | Verificado | Estado |
|---|---|---|---|---|
| ransomware.live | no | JSON | 2026-08-14 | ✅ 200 OK |
| RansomLook | no | JSON | 2026-08-14 | ✅ 200 OK |
| dls-monitor | no | JSON | 2026-08-14 | ✅ 200 OK |
| Hudson Rock | no | JSON | 2026-08-14 | ⚠️ timeout 60 s |
| DarkForums | no | Atom | 2026-08-14 | ✅ 200 OK (fuente con PII) |
| BreachForums | no | Atom | 2026-08-14 | ❌ dominios incautados |
| ecrime.ch | — | HTML | 2026-08-14 | ❌ sin API |
| WhiteIntel | cuenta | — | 2026-08-14 | ❌ sin API pública |

Proveedores CTI comerciales (Axur, SOCRadar, Group-IB, SpyCloud y otros):
ver [cti-proveedores.md](cti-proveedores.md). Resumen: ninguno tiene free tier
con API usable.

---

## ransomware.live

- **Endpoints:** `GET /v2/countryvictims/AR` y `GET /v2/recentvictims`.
- **Por qué los dos:** el índice AR es preciso pero el feed deja `country`
  vacío seguido; una víctima con dominio `.com.ar` puede no estar etiquetada y
  se perdería. El índice global la levanta igual por `tld_ar`.
- **Trampa:** los dos endpoints usan **nombres de campo distintos para lo
  mismo** (`group` vs `group_name`, `victim` vs `post_title`, `domain` vs
  `website`). El adapter contempla ambas formas.
- **PII:** el payload puede traer `infostealer.last_employee_compromised` y
  `last_user_compromised` con emails de personas. **No se copian al modelo**:
  quedan afuera por construcción, con un test que lo verifica.

> **Licencia:** el tier gratuito es *"personal use only, not for
> corporate/business use"*. Apto para prototipo, **no** para producción
> institucional sobre la licencia free.

## RansomLook

- **Endpoint:** `GET /api/recent` (100 posts más recientes).
- **Limitación:** no trae `country` ni dominio estructurado. El título suele
  **ser** el dominio, así que la relevancia se apoya en `tld_ar` y keywords.
- **Nota:** `link` viene relativo; el adapter lo absolutiza.
- Open source (AGPL). Cubre también canales de Telegram.

## dls-monitor

- **Fuente:** `posts.json` crudo del repo en GitHub (~2 MB, ~14.000 posts desde
  2020). La "API" es el archivo versionado.
- **Es un histórico, no un feed incremental.** Por eso el adapter recorta por
  `since` **dentro del `fetch`**: normalizar 14.000 posts en cada corrida
  diaria para descartar el 99,9% sería tirar CPU. La primera corrida procesa
  todo — eso es el backfill, y es correcto.
- Solo trae `post_title`, `group_name` y `discovered`.

## Hudson Rock Cavalier — ✅ verificado el 2026-08-18

- **Estado:** `search-by-domain` responde. (El 2026-08-14 daba timeout a los
  60 s; no era el adapter.) Probado contra `prevision-ejemplo.gob.ar`: devolvió 225.375
  equipos comprometidos, de los que se persistieron **solo los conteos**.
- **No corre solo.** Hacen falta **dos** decisiones explícitas:
  1. habilitar las fuentes con PII (el toggle de la UI o `STORE_PII=true`);
  2. decirle qué dominios consultar. Dos caminos, combinables:
     * `LEAKS_HUDSONROCK_DOMAINS` — a mano, siempre los mismos.
     * `LEAKS_HUDSONROCK_FROM_WATCHLIST=true` — recorre la watchlist por
       **lotes rotativos** de `LEAKS_HUDSONROCK_MAX_PER_RUN` (default 25),
       avanzando un cursor que se guarda en la base.

     Con los dos vacíos/apagados no sale un solo request.

**Por qué lotes y no la watchlist entera.** Cada consulta le revela al proveedor
qué organismo estás vigilando: mandarle los 173 dominios todos los días le
entrega el mapa completo de la investigación. Y son ~2 s por dominio con
timeouts intermitentes, así que la corrida se iría a ~6 minutos martillando un
endpoint gratuito. La rotación cubre todo en unos días sin ninguna de las dos
cosas. Cada dominio va aislado: un timeout no se lleva puesto el lote.
- **Diferencia de fondo con el resto:** todos los demás feeds se bajan enteros
  y se filtran localmente. Este exige **mandarle un dominio al proveedor**, que
  es un tercero comercial extranjero. Como la regla del proyecto es no filtrar
  la watchlist a terceros, el adapter **no la lee**: consulta únicamente los
  dominios listados a mano en `LEAKS_HUDSONROCK_DOMAINS`. Consultar un dominio
  es una decisión explícita, no un efecto secundario de la watchlist.
- **Qué se persiste:** conteos agregados (cuántos equipos, cuántos empleados,
  cuántos usuarios) **y el detalle de exposición**: qué URLs de login se
  capturaron y si eran de empleados o de usuarios, qué familias de malware
  predominan y qué porcentaje de contraseñas es débil. Todo eso es metadata del
  organismo, no de personas.
- **Las credenciales no vienen.** Verificado el 2026-08-18 sobre el payload
  completo: cero emails, cero contraseñas. `employeePasswords`/`userPasswords`
  son distribuciones de fortaleza, no claves. Los registros son el producto
  comercial del proveedor. Identidades y credenciales, jamás en `findings`.

## DarkForums / BreachForums (foros MyBB)

Los dos corren MyBB y publican `/syndication.php`, así que los cubre **un solo
adapter** parametrizado por dominio.

**Estado al 2026-09-01:**

* `darkforums.as` responde 200 y sirve el Atom (15 threads en el índice).
  Responde bien con **User-Agent identificable**: no hace falta falsear un
  navegador, y no se hace.
* `darkforums.ru` **se cayó**: el DNS sigue resolviendo a `104.234.204.18`,
  pero el 443 rechaza la conexión. Queda en la lista de candidatos como
  respaldo — cuestan nada y estos foros vuelven de dominios viejos.
  `darkforums.st` no tiene registro A.
* Recordatorio: incorporar un dominio nuevo es un **acto manual**, después de
  verificarlo por fuera. El adapter detecta la caída pero nunca se muda solo
  (ver `sitios-que-cambian-de-dominio.md`).
* **BreachForums no tiene dominio operativo.** `breachforums.hn`, `.is` y `.cx`
  devuelven el cartel de incautación de las fuerzas del orden; el resto no
  resuelve. Queda registrado y deshabilitado, con la lista de dominios vacía;
  cuando reaparezca alcanza con setear `LEAKS_BREACHFORUMS_BASE_URLS`.

**Qué se consume:** solo el índice público de threads —título, autor, fecha,
URL—. No se entra a los threads, no se descargan adjuntos y no se persiste el
cuerpo del post.

**Subforos: más ventana, sin tocar el HTML.** `syndication.php` acepta `fid`, y
cada subforo devuelve **sus** últimos 50 threads. Medido el 2026-09-01: el
índice global cubría 20,6 h, un subforo activo (`fid=10`) 1,8 días y uno
tranquilo (`fid=2`) 1.130 días con 17 threads. Los ids se cargan a mano en
`LEAKS_DARKFORUMS_FIDS`; el adapter pide el global más uno por id y deduplica
por URL de thread, así que la telemetría cuenta threads distintos y no
repeticiones. Un subforo que falla no tumba la fuente.

**Cómo se consiguen los ids: `leaks discover-fids`.** No hace falta recorrer el
foro. El barrido usa la **misma sindicación abierta**: un GET por id candidato,
leyendo cuántos threads trae, qué período cubre y un título de muestra
—redactado— para reconocer la sección. Se corre a mano, cuando el foro se
reorganiza o cambia de dominio, y también desde el botón **"Buscar subforos"**
de la tarjeta del foro en la pantalla Fuentes.

```
leaks discover-fids --feed darkforums --from 1 --to 60
```

Devuelve la línea `LEAKS_DARKFORUMS_FIDS=…` lista para pegar. **No aplica
nada**: incorporar un subforo sigue siendo un acto explícito del investigador,
igual que incorporar un dominio nuevo.

**Lo que sí sigue estando prohibido es el HTML.** `index.php` está detrás de un
desafío JS (*"Checking your browser…"*, vshield); `syndication.php` no. Sacar
los ids del índice implicaría pasar ese control con un browser headless: eso es
**evadir un control de acceso**, no leer una fuente abierta, y no se hace. El
descubrimiento se apoya solo en el endpoint que ya consumimos.

**Lo que esto NO resuelve.** Un thread que ya se cayó de todas las ventanas no
se recupera: el subforo activo llega a ~2 días, no a la semana pasada. Esto
compra resiliencia hacia adelante, no historia hacia atrás.

**Cadencia: se sondea cada 2 horas, no una vez por día.** La sindicación es una
ventana de los últimos 15 threads, sin historial ni paginación. Medido el
2026-09-01, esos 15 cubrían **3,1 horas**: con una sola corrida diaria no se
monitorea el foro con menos resolución, se pierde la mayor parte de lo
publicado. El caso testigo fue un thread del 28-ago que nunca vimos.

La cadencia se declara en el registro (`FeedSpec.poll_interval_minutes=120`) y
el scheduler la lee de ahí; el sondeo pasa por las mismas puertas que la corrida
diaria —control de IP de salida, gate de PII, watchlist vigente— y cuesta un
solo GET. Las fuentes de ransomware no declaran sondeo: publican por día y
sondearlas sería ruido.

**Por qué van detrás del flag de PII.** El contenido de estos threads son
volcados de datos: muestras con emails, documentos y contraseñas. Los dos van
marcados `requires_pii` (no corren si no se habilitan a propósito) y
`high_pii_surface` (no se persiste texto libre).

**El cuerpo se usa pero no se guarda.** Es donde el foro declara `Location:` y
el dominio afectado, así que la capa de relevancia lo lee **en memoria** y el
runner lo descarta antes de persistir.

**El título se redacta, no se descarta.** Es la única excepción a la regla de
"si tiene PII se cae el campo entero": el título es la identidad del hallazgo, y
tirarlo perdería el hallazgo completo — justo el más grave. Ver
[privacidad.md](privacidad.md).

**Dominios rotativos.** Se configura una lista de candidatos y gana el primero
que responda. Si no responde ninguno, el adapter falla y el runner lo aísla como
a cualquier fuente caída.

**XML de fuente hostil:** se parsea con `defusedxml`, no con la stdlib.

## ecrime.ch — no integrable

Es un buscador web por nombre de archivo filtrado. No expone API pública
(`/api/*` → 404). Integrarlo requeriría scrapear HTML de un servicio que no lo
ofrece como feed: fuera del alcance.

## WhiteIntel — no integrable

El sitio responde, pero el tier gratuito de monitoreo exige cuenta y no publica
API documentada. Sin credenciales por entorno no hay integración posible bajo
las reglas del proyecto.

---

## Política de recolección

- **User-Agent identificable** (`leaks-monitor/0.1`, configurable). No se
  falsean navegadores: si un feed no quiere ser consumido por una herramienta,
  la respuesta correcta es no consumirlo, no disfrazarse.
- **Backoff exponencial** ante 429/5xx, respetando `Retry-After` cuando el
  servidor lo manda (tope 300 s).
- **Autolimitación** entre requests (`LEAKS_HTTP_RATE_LIMIT_DELAY_SECONDS`):
  varios de estos feeds no publican sus límites, así que nos los imponemos.
- **Nada de Tor.** Se consumen feeds públicos; los `.onion` que aparecen en los
  hallazgos se guardan como referencia y el frontend los muestra sin enlazar.

## Sumar un feed

1. Implementar `FeedAdapter` (`fetch` + `normalize`) en `src/leaks/adapters/`.
2. Agregar un `FeedSpec` al registro en `adapters/registry.py`, con su licencia
   y su política de PII.
3. Capturar una fixture en `tests/fixtures/` y testear el mapeo.
4. Documentar el feed acá.

El core, la API y el frontend no se tocan.
