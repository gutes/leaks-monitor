# Privacidad y manejo de PII

Las reglas de este documento son el **piso mínimo** del proyecto. Si algo del
resto de la documentación las contradice, mandan éstas.

## Principio

Se persiste **metadata de víctimas** (organizaciones), no **datos de personas**.
Un hallazgo dice "este organismo aparece publicado por este grupo en esta
fecha". No dice quién trabaja ahí ni cuál es su contraseña.

## Qué se guarda y qué no

**Se persiste por defecto:** organización/víctima, dominio, país, sector,
grupo/actor, fecha de publicación, URL/ref de la fuente, `ar_match_reason`,
severidad, `dedup_hash`.

**Nunca por defecto:** credenciales, contraseñas, emails de personas físicas,
hashes de password, cookies/tokens, contenido de dumps, PII de individuos.

## Las tres barreras

### 1. Por construcción

El modelo `NormalizedItem` **no tiene campos para PII**. Un adapter no puede
"pasar de más" un email aunque el feed lo mande: no hay dónde ponerlo. Es la
barrera más fuerte porque no depende de que un filtro funcione.

### 2. El scrubber (fail-closed)

El único texto libre que se persiste es `description`. Antes de escribirlo se
buscan emails, credenciales `user:pass`, líneas de combolist, hashes de
password, tarjetas, DNI y CUIT. Si aparece **cualquiera**, el campo se descarta
**entero**.

No se enmascara la parte sensible: enmascarar deja margen a que algo se filtre
por un patrón que no previmos. Perder el contexto de un hallazgo es barato;
persistir el email de una persona no lo es.

Las fuentes marcadas `high_pii_surface` (títulos de threads de foro) no
persisten texto libre en absoluto.

### 2-bis. La redacción de títulos (la excepción)

Hay **una** excepción a "si tiene PII, se cae el campo entero", y aplica solo al
`victim_name` de las fuentes `high_pii_surface` (títulos de threads de foro).
Ahí la PII se reemplaza por `[redactado]` en vez de descartar el campo.

El motivo: en `description` tirar el campo cuesta contexto. En `victim_name`
cuesta **el hallazgo entero** — un thread titulado "Ministerio dump juan@x.gob.ar"
desaparecería del monitoreo justo por ser el más grave. Redactado sigue siendo
identificable, y el thread queda referenciado en `raw_ref` para quien tenga que
ir a verlo.

### 3. La bóveda cifrada

Solo para feeds `requires_pii=True`, y solo si se cumplen las tres condiciones
a la vez:

1. `LEAKS_STORE_PII=true`
2. hay clave de cifrado válida
3. el feed está marcado en el registro

Si falta cualquiera, la PII **se descarta** y queda en el log. Nunca se degrada
a guardarla en claro.

- Tabla **separada** (`pii_records`), payload cifrado con **Fernet**
  (AES-128-CBC + HMAC-SHA256): autenticado, detecta manipulación al descifrar.
- **Retención** configurable (`LEAKS_PII_RETENTION_DAYS`, default 30), aplicada
  en cada corrida y también a mano con `leaks purge-pii`. Una política que
  nadie ejecuta no es una política.
- Borrar el hallazgo borra su PII (`ON DELETE CASCADE`, con
  `PRAGMA foreign_keys=ON` — en SQLite viene apagado y sin eso sería
  decorativo).
- **La API no expone esta tabla**, ni con el flag activo.

## Fail-closed en el arranque

`STORE_PII=true` sin `LEAKS_PII_ENCRYPTION_KEY` **no arranca el proceso**. Es
deliberado: la alternativa —arrancar y guardar en claro— es exactamente el
accidente que hay que evitar.

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

La clave va por entorno o secrets manager. Si se pierde, los registros cifrados
son irrecuperables: eso es la propiedad que se busca, no un problema.

## Datos que no salen del sistema

La watchlist y los resultados **no se mandan a servicios de terceros ni a
LLMs/APIs externas para "enriquecer"**.

La única salida de datos posible es Hudson Rock, que por diseño **no lee la
watchlist**: consulta solo los dominios listados a mano en
`LEAKS_HUDSONROCK_DOMAINS`. Ver [feeds.md](feeds.md).

## Secretos y logs

- Solo por entorno / secrets manager. Nunca hardcodeados ni commiteados.
- Los errores por fuente se truncan a 500 caracteres y guardan **tipo y
  mensaje**, nunca el body de la respuesta: un body podría arrastrar PII o un
  token a la tabla de telemetría y a los logs.
- `.env` está en `.gitignore`; `.env.example` no tiene valores reales.
- El CI corre secret scanning (gitleaks) y SAST (bandit) como gates que
  bloquean.

## La bitácora de actividad

La consola (`run_events`) guarda **URL consultada, código de estado, duración,
bytes y conteos**. No guarda respuestas, ni items de feeds, ni PII. Los
mensajes se truncan a 500 caracteres y los errores llevan tipo y mensaje, nunca
el body.

Las URLs son las de los feeds públicos que consultamos — no revelan la
watchlist. La única excepción posible sería Hudson Rock, que lleva un dominio
en la query string: es otro motivo más para que sea opt-in explícito.

Se purga con `leaks purge-pii` según `LEAKS_EVENT_RETENTION_DAYS` (default 14).

## Auditabilidad

- `GET /api/health` publica el valor efectivo de `store_pii`: la postura de
  privacidad es verificable desde afuera, no una promesa del README.
- Cada hallazgo guarda `ar_match_reason` y `ar_match_detail` con la evidencia
  de cada regla. Los CUIT van **enmascarados** (`30-********-8`) porque el
  número completo de una persona física es PII.
