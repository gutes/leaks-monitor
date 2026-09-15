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

## Sumar o corregir un tipo

Es una entrada en `TAXONOMIA` (si cambia la guía) o una regla en `REGLAS` (si
cambia cómo clasificamos). El clasificador y el catálogo están separados a
propósito: el catálogo es transcripción del documento y no se interpreta; las
reglas sí son criterio nuestro y se discuten.
