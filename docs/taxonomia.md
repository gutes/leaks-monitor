# Taxonomía de incidentes del CERT.ar

Cada hallazgo lleva un tipo de la **Guía de Notificación y Gestión de Incidentes
de Ciberseguridad** del CERT.ar (IF-2023-69993929-APN-SSTI#JGM), sección 4.

## Por qué dos ejes y no uno

Conviven `severity` y el nivel de criticidad del CERT porque **miden cosas
distintas**:

| | Qué mide | Quién lo define |
|---|---|---|
| `severity` | **relevancia argentina corroborada**: qué tan seguro es que afecte a una entidad argentina y cuánto importa esa entidad | nosotros (`relevance/severity.py`) |
| `taxonomy_criticality` | **tipo de incidente**, sin mirar quién es la víctima | la guía del CERT |

Cruzados sobre los datos reales al 2026-09-15, la independencia se ve sola:

```
severity (AR)   nivel CERT      n
medium          alto          212     ← ransomware sin corroboración AR fuerte
critical        medio          16     ← infostealer de un organismo de la watchlist
low             alto            9
```

Un ransomware contra una PyME sin dominio `.ar` es **Alto** para el CERT y `low`
para nosotros. Pisar un eje con el otro perdería justo la información que hace
falta para reportar.

## Qué se guarda y qué se deriva

En `findings` van **solo dos columnas**:

* `taxonomy_type` — el slug, que es la clave estable.
* `taxonomy_basis` — por qué se asignó ese tipo.

La clasificación, el nombre del tipo y el nivel de criticidad **no se guardan**:
se derivan del catálogo en cada lectura. Si el CERT publica otra versión de la
guía, se reemplaza `taxonomy/cert_ar.py` y todas las filas quedan al día — no
hay datos viejos contradiciendo la tabla vigente.

`taxonomy_basis` existe por la misma razón que `ar_match_reason`: una
clasificación que no explica su motivo es imposible de revisar sin reproducir la
corrida.

## El mapeo

| Nuestro `leak_type` | Clasificación CERT | Tipo | Nivel |
|---|---|---|---|
| `ransomware` | Contenido Dañino | Ransomware | Alto |
| `infostealer` | Intrusión | **Compromiso de cuenta** | Medio |
| `forum_post`, `paste` | Compromiso de la información | Acceso no autorizado a la información | Alto |
| `repo_secret` | Activo vulnerable | Revelación de información | Medio |
| *(sin regla)* | Otros | Sectores no críticos | Bajo |

Dos decisiones que conviene no re-litigar:

* **Infostealer → Compromiso de cuenta, no Malware.** Se clasifica lo que
  observamos: credenciales de la organización en manos de terceros. Que atrás
  haya habido malware es probable pero no lo vemos, y la guía pide clasificar
  "según aquel que mejor se ajuste a la situación acontecida que motiva el
  reporte". Confirmado por el líder técnico el 2026-09-15.
* **Los volcados de foro NO son "Robo".** La guía define Robo como *intrusión
  física*, por más que el título del thread diga "stolen database".

## Cómo se usa

* **Nunca queda un hallazgo sin tipo.** Si ninguna regla aplica cae en *Otros /
  Sectores no críticos*, que es el tipo que la propia guía reserva para lo no
  clasificable. Un hallazgo sin taxonomía desaparecería de cualquier reporte.
* `GET /api/taxonomy` devuelve el catálogo entero, para que un integrador sepa
  qué significa cada slug sin leer el PDF.
* `GET /api/findings?taxonomy_type=<slug>` filtra por tipo, y la tabla de la UI
  lo muestra en su propia columna con la clasificación y el motivo en el tooltip.
* `leaks classify-taxonomy` asigna el tipo a los hallazgos que no lo tengan. Es
  idempotente: recorre solo lo que falta.

## Exportar a IntelMQ

IntelMQ es el pipeline de procesamiento de incidentes de la comunidad de CSIRT.
Emitir en su formato significa que un CERT consume esto con su herramienta, sin
escribir un parser.

**Sale casi gratis porque las dos taxonomías vienen del mismo lugar**: la guía
del CERT.ar deriva de eCSIRT.net / RSIT, que es la que usa
`classification.taxonomy`. Las 9 clasificaciones tienen equivalente exacto:

| CERT.ar | RSIT / IntelMQ |
|---|---|
| Contenido Abusivo | `abusive-content` |
| Contenido Dañino | `malicious-code` |
| Obtención de información | `information-gathering` |
| Intrusión | `intrusions` |
| Disponibilidad | `availability` |
| Compromiso de la información | `information-content-security` |
| Indicio de fraude | `fraud` |
| Activo vulnerable | `vulnerable` |
| Otros | `other` |

### Se emite siempre el par canónico de RSIT

IntelMQ trata taxonomía y tipo como dos campos independientes, pero algunos de
sus bots **derivan la taxonomía del tipo**. Emitir un par que RSIT no aparea así
es pedir que un bot de la cadena lo reescriba sin avisar.

Por eso el mapeo prioriza el par canónico aunque eso mueva el evento a otra
taxonomía que la del CERT. **Nada se pierde**: el slug viaja en
`extra.taxonomy_cert`. Se corren tres casos:

| Slug del CERT | Par emitido | Por qué |
|---|---|---|
| `ransomware` | `information-content-security` / `data-leak` | IntelMQ **no tiene** un tipo `ransomware` |
| `explotacion_de_vulnerabilidades` | `intrusion-attempts` / `exploit` | RSIT pone `exploit` ahí; el CERT lo agrupa en Intrusión |
| `fuerza_bruta` | `intrusion-attempts` / `brute-force` | ídem |
| `ataque_desconocido`, `sectores_no_criticos` | `other` / `undetermined` | no hay tipo equivalente, y `undetermined` dice la verdad |

Sobre ransomware, que es el que más cambia el triage: lo que observamos **no es
una infección que detectamos** sino la publicación de datos robados en un sitio
de extorsión. El grupo queda en `classification.identifier`. Decisión del líder
técnico, 2026-09-30.

Otras dos elecciones que afirman lo menos posible: `compromiso_de_cuenta` va a
`unprivileged-account-compromise` porque no sabemos si la cuenta era
privilegiada, y `denegacion_de_servicio` va a `ddos` porque el CERT agrupa
"DoS/DDoS" en un tipo y RSIT los separa.

### Se consume tirando, no empujando

IntelMQ está hecho para **tirar** de una URL con su collector HTTP, así que el
formato se sirve en el feed de alertas que ya existía para integradores —mismos
filtros, misma paginación incremental, otra representación—:

```bash
curl "http://127.0.0.1:8000/api/alerts/feed?formato=intelmq&limit=100"
```

Devuelve **NDJSON**: un evento por línea. El total y la página van en las
cabeceras `X-Total-Count`, `X-Limit` y `X-Offset`, porque NDJSON no tiene dónde
ponerlos. Para paginar incrementalmente vale lo mismo que para el feed JSON:
`campo=first_seen` y guardar el `time.observation` más alto de la última página.

**`desde` es inclusivo**, así que la pasada siguiente vuelve a traer el evento
del borde. Se deduplica con `extra.dedup_hash`, que es estable. Es a propósito:
un `desde` exclusivo se saltearía cualquier evento que comparta la marca con el
último visto. Verificado desde el contenedor el 2026-10-01 — dos pasadas sobre
55 eventos: 55 únicos sin duplicados por paginación, 1 repetido en el borde, y
pidiendo desde la marca más vieja vuelven los 55 sin huecos.

Que sea *pull* tiene una ventaja de OPSEC sobre un webhook: no hay metadata de
organismos argentinos saliendo hacia un tercero. El CSIRT viene a buscarla.

### Qué NO se emite

**`raw`.** La especificación lo define como base64 de la línea original, y
nuestra línea original es un volcado con PII. No se emite ni cifrado ni
recortado; lo que viaja es el mismo metadata que ya se persiste.

**Fechas inventadas.** Sin `occurred_at` creíble no se manda `time.source`: el
campo ausente dice "no sabemos cuándo pasó", que es la verdad.

**Un `source.fqdn` que no sea un dominio.** IntelMQ valida el campo y un nombre
de víctima ahí haría rechazar el evento entero.

Medido sobre las 55 alertas de la instalación real el 2026-09-30: 22 eventos
`data-leak`, 17 `unauthorised-information-access`, 16
`unprivileged-account-compromise`; 34 con `source.fqdn`, 55 con `time.source`,
ninguno fuera del vocabulario y ninguno con `raw`.

## Sumar o corregir un tipo

Es una entrada en `TAXONOMIA` (si cambia la guía) o una regla en `REGLAS` (si
cambia cómo clasificamos). El clasificador y el catálogo están separados a
propósito: el catálogo es transcripción del documento y no se interpreta; las
reglas sí son criterio nuestro y se discuten.

Si el tipo es nuevo, hay que mapearlo también a RSIT en
`export/intelmq.py`: hay un test que falla si queda uno sin par, y otro que
verifica que el par esté dentro del vocabulario que IntelMQ acepta. Es
deliberado que falle acá y no del lado del CERT que consume el feed.
