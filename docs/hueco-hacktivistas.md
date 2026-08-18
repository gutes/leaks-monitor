# El hueco que Chronus Team dejó al descubierto

**Fecha del análisis: 2026-08-18.** Disparado por el líder técnico, que pidió
revalidar el caso.

## El caso

**Chronus Group** (alias *Chronus Team*, handle `CHRONUSTEAM`, líder autodeclarado
`L0stex`). Colectivo **hacktivista** activo desde al menos 2021, dedicado a
defacement y filtración de datos contra el sector público.

| | |
|---|---|
| **México** | 2026-01-30 — 25+ instituciones de gobierno, ~36 M de ciudadanos expuestos |
| **Argentina** | 2026-03-30 — la jefatura de gabinete, Ministerios de Educación/Salud/Seguridad, **el banco central**, un poder judicial provincial, una obra social provincial, una obra social provincial, salud de Misiones y Neuquén, una policía provincial |
| **Anticipación** | **~59 días** |

El patrón México → Argentina que se sospechaba **está confirmado**.

Fuentes aportadas por el líder técnico: Malpedia (`actor/chronus_group`),
Rescana, ITSitio, Chequeado, DefOnline, CyberMidnight Club.

## Qué falló

**No fue la watchlist.** Contra la watchlist real, 9 de los 12 organismos
golpeados ya estaban cubiertos —incluido `Banco Central Ejemplo.gob.ar`— y los subdominios
provinciales entraban por `gba.gob.ar` y `mendoza.gov.ar`. Los 3 que faltaban
(`cortesuprema-ejemplo.gov.ar`, `educacionprov-ejemplo.edu.ar`, `saludprov-ejemplo.gob.ar`) ya se agregaron.

**No fue el score.** El score nunca llegó a correr sobre este actor.

**Fue la cobertura de fuentes, y es estructural.** Las tres fuentes de
ransomware que consumimos —ransomware.live, ransomlook, dls-monitor— indexan
**data leak sites de bandas de ransomware**. Chronus publica por **Telegram y
foros**. No es que se nos pasó: es que **nunca podría aparecer ahí**.

Verificación exhaustiva: 388 grupos en ransomware.live, 613 en ransomlook, 531
en `leak_sites`, más los actores de `findings` y `adjacent_actors`, con
variantes `chronus|cronus|chronos|kronos|crono`. Cero. Los dos aciertos son
ruido: `lockbit3_cronos` es la Operación Cronos (el operativo policial contra
LockBit) y `empresa-ejemplo.com.ar` es una víctima argentina sin relación.

Y la prueba definitiva: la ventana 2026-03-20 / 2026-04-10 en nuestra base tiene
**5 hallazgos, todos de empresas privadas por ransomware.live**. La filtración
más grande del sector público argentino del año no dejó **ni una fila**.

## Las tres clases de amenaza, y qué las arregla

| Clase | Ejemplo | Estado | Qué la arregla |
|---|---|---|---|
| Ransomware con DLS y rastro regional | `qilin` | ✅ cubierto, score anda | — |
| Ransomware con DLS, sin rastro regional | `thegentlemen` | ⚠️ visible, score ciego | Nada: es ciego el enfoque |
| **Hacktivistas en Telegram/foros** | **`chronus`** | ❌ **invisible** | **Sumar una clase de fuente** |

Las dos primeras salían del análisis del score. La tercera no estaba contada, y
es la que más duele: los objetivos de estos actores son organismos públicos,
que es exactamente lo que esta watchlist vigila.

## Qué haría falta

Ninguna de estas está implementada. Van ordenadas por relación señal/esfuerzo:

1. **Telegram.** Es el canal principal de esta clase de actor. Hay API pública
   y no requiere Tor. Es lo que más movería la aguja.
2. **DarkForums**, que ya está integrado, pero hoy solo se lee el índice Atom de
   threads. Habría que verificar si estos actores postean ahí y con qué nombre.
3. **Catálogos de actores hacktivistas** (Malpedia tiene API pública). No trae
   víctimas, pero sí alias — que es justamente lo que hizo fallar la búsqueda
   inicial por nombre.

Decisión pendiente del líder técnico: la watchlist y los hallazgos **no salen a
terceros**, así que cualquier fuente nueva se consume igual que las demás —se
baja entera y se filtra localmente— nunca consultando por organismo.
