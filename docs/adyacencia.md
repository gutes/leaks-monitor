# Leaks adyacentes

Actores que operan en la región y podrían apuntar a Argentina.

## La pregunta

El pipeline argentino descarta todo lo que no es argentino. Pero los actores
que ya nos golpearon siguen operando en la región, y hay otros barriendo
Latinoamérica que todavía no cruzaron. Saber quiénes son **antes** es la señal
que se pierde.

## Qué tan bien funciona (medido, no supuesto)

Todo lo de acá sale de medir el feed el **2026-08-18**: 1.537 víctimas en 19
países, 163 actores.

### El punto ciego es del 46%

De los **65 actores que golpearon Argentina**, solo **35 tenían actividad
regional previa**. Los otros **30 eligieron Argentina como su primera víctima
latinoamericana registrada**: para ellos no existe precursor regional que
puntuar. El score es **estructuralmente ciego**, no está mal calibrado.

### Tres modos de falla, no dos

Los dos actores que se citaron como motivación del feature fallan por razones
**distintas**, y confundirlas lleva a arreglar lo que no es:

| | `thegentlemen` | Chronus/Cronus Team |
|---|---|---|
| ¿Está en las fuentes? | **Sí**, 92 víctimas | **No**, en ninguna |
| Por qué falla | Golpeó AR sin precursor regional | Nadie que consumamos lo trackea |
| Categoría | Punto ciego del score | **Hueco de cobertura** |
| Cómo se arregla | No se arregla: es ciego el enfoque | Sumando una fuente |

Ningún ajuste de la fórmula toca el segundo caso.

La búsqueda de Chronus fue exhaustiva —variantes `chronus|cronus|chronos|
kronos|crono` contra los 156 actores de `adjacent_actors`, los actores de
`findings`, los 531 grupos de `leak_sites`, el texto libre de los hallazgos, y
los catálogos en vivo de ransomware.live (388 grupos) y ransomlook (613)— y no
hay nada. Los dos únicos aciertos son ruido: `lockbit3_cronos` es la Operación
Cronos, el operativo policial contra LockBit, y `empresa-ejemplo.com.ar` es una víctima
argentina.

**La UI tiene que decir las tres cosas**, o la lista se lee como "las amenazas"
cuando es "las que nuestras fuentes registran y además dejaron rastro regional".

### El patrón México → Argentina sí existe

19 de 163 actores golpearon México antes que Argentina, con anticipaciones de 2
a 862 días:

```
funksec       2 días        akira        32 días        ransomhub   138 días
m3rx         15 días        clop         92 días        killsec     162 días
blackbyte    27 días        krybit      130 días        lockbit2    172 días
```

### Sobre los que sí puede ver, anda bien

Backtest: para cada uno de los 35 cruces, se rankea a todos los actores con
datos **estrictamente anteriores** al día del cruce y se mira en qué puesto
quedó el que cruzó.

| Métrica | Resultado |
|---|---|
| Percentil mediano | **93%** |
| En el top 10 | 25/35 (71%) |
| En el cuartil inferior | **0/35** |

### Y avisa con tiempo

Anticipación entre la primera víctima regional y la primera argentina:

| | días |
|---|---|
| mediana | **105** |
| ≥30 días | 30/35 (86%) |
| ≥90 días | 21/35 (60%) |
| mínimo | 4 |

## De dónde salen las víctimas regionales

Hasta el 2026-09-18 la respuesta era **una sola fuente**: ransomware.live. Eso
significaba que la sección prometía *"actores que operan en la región"* y en los
hechos entregaba *"bandas de ransomware que publican en un data leak site"*.

Lo que quedaba afuera se midió contra la base, no se supuso: de los actores que
ya vimos golpear Argentina, **32 no estaban en `adjacent_actors` y no podían
estar** — 15 vendedores de DarkForums, 14 de dls-monitor, 4 canales de Telegram
y 1 de BreachForums, todos con **cero** víctimas regionales, porque ninguna
fuente regional los miraba. Entre ellos `rabbitt1337`, que vendía acceso de
shell a `gde.gob.ar` y `educacion.gob.ar`.

Esto es **distinto del punto ciego del 46%**, y confundirlos lleva a arreglar lo
que no es:

| | Punto ciego del score | Hueco de fuente |
|---|---|---|
| Qué pasa | Eligieron AR como primera víctima LatAm | Ninguna fuente regional los mira |
| Ejemplo | `thegentlemen` | `rabbitt1337` |
| Se arregla | No: es ciego el enfoque | Sí: sumando una fuente |

### Los foros y Telegram también alimentan la sección

Desde el 2026-09-18, lo que el pipeline argentino descarta por no ser argentino
se le ofrece al lado regional antes de tirarlo (`runner._a_victima_regional`).
Sólo lo hacen los feeds que declaran `feeds_adjacency` —foros y Telegram—: los
de ransomware ya entran por su propia vía y dejarlos entrar por las dos puertas
duplicaría las mismas víctimas.

El criterio de atribución de país vive en `adjacency/country_detect.py` y es
**más estricto que el argentino** a propósito: allá un falso positivo cuesta un
hallazgo que se descarta en diez segundos, acá se convierte en un actor con
score. **El dominio manda** — ccTLD del país o watchlist regional—, el nombre
del país en el texto corrobora pero nunca dispara solo, y la ambigüedad se
devuelve como nada.

Medido con `leaks regional-probe` el 2026-09-18, sin persistir nada:

| | items mirados | argentinos | regionales | actores nuevos |
|---|---:|---:|---:|---:|
| foros | 340 | 15 | 4 | 3 |
| telegram | 5.537 | 20 | 23 | 14 |
| **total** | **5.877** | **35** | **27** | **17** |

Rendimiento del **0,46%**, con una precisión de 26/27 revisando las muestras a
mano. El riesgo que justificaba medir antes de persistir —inundar la tabla de
handles de foro— no se materializó: 17 actores nuevos sobre 162.

El único falso positivo fue de una clase que no estaba prevista: el canal
`breachstars` anunciando **su propio dominio nuevo**, `breachstars.hn`. Un
vendedor no se ataca a sí mismo, así que se descartan los dominios cuya etiqueta
coincide con el handle del actor.

Quedó uno sin resolver y se dice: `elobservador.com.uy` es el enlace a una nota
periodística *sobre* un hackeo, no una víctima. Con un solo caso no alcanza para
escribir una regla.

### Se mira la ventana entera, no sólo lo nuevo

El lado regional se evalúa **antes** del filtro incremental del runner, y es a
propósito. La adyacencia es el histórico del actor, no la novedad del día: el
colector de ransomware.live ya rebaja el país completo en cada corrida y
deduplica. Si acá se filtrara por cursor, la sección vería sólo lo publicado
desde el día que se encendió la bandera y nunca lo que el foro ya tiene a la
vista — con un item viejo por corrida, tardaría meses en poblarse.

`upsert_victims` es idempotente por clave natural, así que repasar la ventana en
cada corrida no duplica nada.

### La víctima es el dominio, no el título

En estas fuentes el título del post es genérico —`FREE WEB SHELL`,
`HOST : smtp.office365.com`, o directamente un emoji— y la clave natural de
`regional_victims` es `(actor, país, nombre, fecha)`. Con el título como nombre,
dos víctimas distintas del mismo canal en la misma fecha se guardarían como una.

Se persiste el dominio, que además no tiene PII: el título de un thread puede
traer una muestra de los datos robados, un dominio no.

## Los dos carriles

Las víctimas de foro y Telegram traen actores de otra naturaleza —brokers de
acceso, vendedores, hacktivistas— y el score **no está calibrado sobre ellos**:
`volumen` y `tendencia` suponen el goteo de un DLS, y un post que vende acceso a
cinco sistemas es *un post*, no cinco víctimas.

Por eso `adjacent_actors.kind` los separa en dos carriles (`dls` y `foro`, ver
`adjacency/kinds.py`) y la UI los filtra aparte. Un actor con al menos una
víctima publicada en un DLS cuenta como `dls` aunque también venda en un foro:
ahí el score sí está medido y es la lectura más informativa.

## El score

0–100, sin ML, recalculado en cada corrida. Cada componente se persiste en
`score_breakdown`: un número sin explicación no se puede discutir ni corregir.

| Componente | Peso | Qué mide |
|---|---:|---|
| Alcance | 25 | países distintos / 10 |
| Recencia | 25 | decaimiento exponencial, vida media 180 días |
| Volumen | 15 | víctimas, escala logarítmica |
| Tendencia | 15 | últimos 90 días vs. los 90 previos |
| Proximidad | 10 | limítrofes > resto de Sudamérica > México/Centroamérica |
| Afinidad | 10 | ¿golpea los sectores que más se golpean en AR? |

**Los confirmados no llevan score.** Una probabilidad de que le peguen a
Argentina no significa nada para quien ya lo hizo.

### El factor de confianza, y por qué existe

La primera versión daba **65 puntos a un actor con UNA víctima**: recencia,
tendencia, proximidad y afinidad son ratios que un solo dato satura, y juntos
son 60 de los 100 puntos. Empataba con uno de once víctimas en tres países.

La corrección atenúa esos cuatro componentes por `n / (n + k)`. El valor de `k`
sale de un barrido contra el backtest, no de una intuición — y hay una tensión
real, porque al cruzar la mediana de víctimas regionales previas es 4, así que
castigar la poca evidencia castiga también la señal buena:

| k | percentil | top-10 | top-5 | candidatos flacos en el top 8 |
|---|---|---|---|---|
| 0.0 | 93% | 27/35 | 20/35 | 5 de 8 |
| **1.0** | **93%** | **25/35** | **20/35** | **0 de 8** |
| 3.0 | 91% | 23/35 | 20/35 | 0 de 8 |
| 5.0 | 91% | 23/35 | 18/35 | 0 de 8 |

`k=1` saca todo el ruido de una-sola-víctima sin mover el percentil mediano ni
el top-5. Subirlo más solo empeora la detección.

## Por qué es un subsistema aparte

Tablas propias (`regional_victims`, `adjacent_actors`), colector propio,
repositorio propio. No es prolijidad: hay tres bloqueos concretos.

- `findings.dedup_hash` tiene unique **global**: mezclarlas colisionaría.
- `Finding.ar_match_reason` exige `min_length=1`. Un hallazgo argentino **no
  puede existir** sin razón argentina, y estas no la tienen.
- `queries.stats()` y `list_pending_alerts()` recorren la tabla entera. Con una
  columna `scope` habría que acordarse del filtro en cada consulta, y olvidarse
  una sola vez mezcla los datos en silencio.

Lo único que la adyacencia le pide al lado argentino es `actor_counts()` y
`sector_values()`, declarados como un `Protocol` para que la dirección de la
dependencia quede escrita.

## La watchlist regional: para qué sirvió de verdad

Se cargaron 9 países —los 5 limítrofes más MX, CO, PE, EC— con 177 dominios de
gobierno, banca central, energía, telecomunicaciones y salud, en
`data/watchlist-regional/<cc>.yaml`. Reusa `relevance/watchlist.py` tal cual:
ese módulo nunca tuvo nada de argentino, lo argentino era el archivo.

**No movió el score.** Se re-corrió el backtest con la criticidad conectada y
dio idéntico: percentil mediano 93%, 25/35 en el top 10, 0 en el cuartil
inferior. La razón es simple: solo **67 de 1.355** víctimas regionales son
infraestructura crítica, así que la señal casi nunca gana sobre el rubro que
declara el feed.

**Pero esas 67 son el producto.** De ~1.350 víctimas regionales, la mayoría son
empresas privadas que no dicen nada sobre el riesgo argentino. Éstas sí, y 13
de las 14 más recientes son de actores **que ya nos golpearon**:

```
2026-08-07  BR  gobierno    intranet.gov.br          thegentlemen  ← ya nos golpeó
2026-07-31  PE  gobierno    munisanluis.gob.pe       thegentlemen  ← ya nos golpeó
2026-07-19  CO  energia     www.ecopetrol.com.co     thegentlemen  ← ya nos golpeó
2026-06-20  MX  gobierno    idefeey.yucatan.gob.mx   lockbit5      ← ya nos golpeó
2026-06-20  BR  gobierno    saude.mt.gov.br          lockbit5      ← ya nos golpeó
```

`thegentlemen` —el actor que golpeó Argentina en septiembre de 2025— viene
atacando la intranet del gobierno brasileño, municipios peruanos y la petrolera
estatal colombiana. Eso no lo dice ningún score: lo dice la lista.

La criticidad se **recalcula en cada corrida** sobre todo lo guardado, así que
editar un `<cc>.yaml` reclasifica sin volver a bajar nada.

## Alertas: por salto, no por umbral

Se avisa cuando el score de un candidato **se mueve**, no cuando está alto. Un
actor alto y quieto no es novedad, y alertar por umbral absoluto lo repetiría en
cada corrida hasta que alguien apague las alertas.

Tres condiciones, todas necesarias: no haber golpeado Argentina (a los
confirmados no se les calcula score), haber saltado `LEAKS_ADJACENCY_ALERT_JUMP`
puntos (default 10) y estar sobre `LEAKS_ADJACENCY_ALERT_MIN_SCORE` (default
40). La primera vez que se puntúa a un actor **no se avisa**: no hay salto que
medir y fingirlo sería inventar.

**No se alerta por víctima regional**: serían 1.355 avisos de cosas que no son
nuestras.

## Estado

| Incremento | Estado |
|---|---|
| Recolección regional + tablas | ✅ 1.355 víctimas, 18 países |
| Score + calibración por backtest | ✅ 156 actores: 61 confirmados, 95 candidatos |
| API + vista de actores | ✅ sección propia, con el desglose del score |
| Watchlist regional por país | ✅ 9 países, 177 dominios, 67 víctimas críticas |
| Alerta por salto de score | ✅ por movimiento, no por umbral |
| Foros y Telegram como fuente regional | ✅ 2026-09-18, medido antes con `regional-probe` |
| Carriles separados (`dls` / `foro`) | ✅ el score no se compara entre universos |

La sección está marcada **beta** en el menú: su punto ciego del 46% es
estructural y hay que saberlo antes de entrar, no después de leer la lista.
