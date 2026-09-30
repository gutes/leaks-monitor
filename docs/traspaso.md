# Traspaso: entregar esta instalación a otra persona

Checklist para reemplazar la **semilla de ejemplo** de una instalación nueva por
los datos reales de una instalación en uso: watchlist, keywords, canales de
Telegram, catálogo de sitios y configuración de fuentes.

Este archivo es el que se manda **junto al paquete**, así que se puede leer sin
tener el repositorio a mano. El *por qué* de cada decisión —por qué no se
reparte la imagen, cuántas instancias conviene tener, qué lleva y qué no lleva
el paquete— está en [`instalacion.md`](instalacion.md) y no se repite acá.

---

## Lo que se entrega: tres archivos

| Archivo | Qué es | Sensibilidad |
|---|---|---|
| `leaks-traspaso-AAAA-MM-DD.tar.gz` | La base entera y las watchlists | **Alta** — dice qué se vigila |
| `traspaso-AAAA-MM-DD.env` | La configuración operativa, sin secretos | **Media** — dominios de foro y fids |
| `traspaso.md` | Este archivo | ninguna |

**Nunca se entrega `LEAKS_PII_ENCRYPTION_KEY`.** No hace falta: el vault de PII
no viaja en el paquete, así que la clave vieja no abre nada del lado de quien
recibe. Compartirla sería regalar acceso a datos de personas sin ningún
beneficio. Quien recibe genera la suya en el paso 3 de la parte 2.

---

## Parte 1 — Quien entrega (cuatro comandos)

### 1. Sincronizar el YAML de la watchlist con la base

**Este paso es primero y es fácil de saltear.** Apenas se edita la watchlist
desde la UI, el YAML deja de ser la fuente de verdad: lo que vale es la tabla.
El paquete lleva las dos cosas, así que un YAML viejo viaja junto a una base
correcta.

Medido en la instalación real el 2026-09-30, antes de sincronizar: **319
entradas en la base contra 289 en el archivo** — 35 agregadas desde la UI que no
estaban en el YAML, y 5 dadas de baja que seguían ahí. Al importar manda la
base, así que quien recibe ve las 319 bien; pero se queda con un archivo que
miente, y el día que alguien re-siembre desde él pierde 35 y revive 5.

```bash
cp -p data/watchlist.yaml data/watchlist.yaml.bak-$(date +%F)
docker compose run --rm --no-deps api \
    leaks export-watchlist --out /app/data/watchlist.yaml
```

Comprobar que quedaron iguales:

```bash
docker compose exec -T api python -c "
import yaml, sqlite3
d = yaml.safe_load(open('/app/data/watchlist.yaml'))
en_yaml = {str(v).strip().lower() for s in d['sectors']
           for v in s.get('domains', []) + s.get('keywords', [])}
c = sqlite3.connect('/data/leaks.db')
en_db = {r[0].strip().lower() for r in c.execute('select value from watchlist_entries')}
print('solo en la base:', len(en_db - en_yaml), '| solo en el YAML:', len(en_yaml - en_db))"
```

Los dos tienen que dar **0**.

### 2. Generar el paquete

```bash
docker compose run --rm --no-deps api \
    leaks export-bundle --out /app/data/leaks-traspaso-$(date +%F).tar.gz
```

Aparece en `./data/` de tu máquina, porque ese directorio está montado en el
contenedor. Imprime los conteos de lo que metió: **guardalos**, son los que
quien recibe usa para verificar en el paso 5 de la parte 2.

`VACUUM INTO` toma la instantánea, así que incluye lo que todavía está en el WAL
y no hace falta parar nada. Copiar `leaks.db` a mano **no** sirve: ver
`instalacion.md`.

### 3. Sacar la configuración operativa, sin la clave

```bash
grep -v '^LEAKS_PII_ENCRYPTION_KEY=' .env > data/traspaso-$(date +%F).env
grep -E '^LEAKS_\w*(KEY|TOKEN|SECRET|PASSWORD)\w*=.+' data/traspaso-*.env \
    && echo "⚠️  quedó un secreto adentro, revisalo" \
    || echo "✅ sin secretos"
```

El segundo comando no es adorno: es la verificación de que no se está mandando
una credencial por descuido.

### 4. Cifrar antes de mandarlo

El paquete dice qué organismos se vigilan. No viaja en claro por un canal que no
controlás:

```bash
gpg --symmetric --cipher-algo AES256 data/leaks-traspaso-$(date +%F).tar.gz
```

Se manda el `.gpg` y la frase de paso **por otra vía** (no en el mismo mail, no
en el mismo chat). `data/*.tar.gz`, `data/*.gpg` y `data/*.env` están en
`.gitignore`: ninguno de estos archivos va al repositorio.

---

## Parte 2 — Quien recibe (seis pasos)

Hace falta: **Docker** con `compose`, **git**, y acceso al repositorio privado.

### 1. Clonar

```bash
git clone git@github.com:gutes/leaks-monitor.git && cd leaks-monitor
```

### 2. Poner la configuración

```bash
cp /ruta/al/traspaso-AAAA-MM-DD.env .env
```

Ese archivo ya trae los dominios de foro vivos, los fids que se están vigilando,
la hora de la corrida diaria y la política de OPSEC. Es lo que **no** viaja en el
paquete: el paquete lleva datos, el `.env` lleva configuración.

> Si en vez de eso arrancás de `.env.example`, el prototipo levanta igual pero
> con placeholders: sin dominios de foro configurados esas fuentes no traen
> nada.

### 3. Generar tu propia clave del vault

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Pegala en `.env` como `LEAKS_PII_ENCRYPTION_KEY=…`. Sin esto, con
`LEAKS_STORE_PII=true` el proceso **se niega a arrancar** — es a propósito:
fail-closed. Si preferís no persistir PII, poné `LEAKS_STORE_PII=false` y no
hace falta clave.

### 4. Importar el paquete ANTES de levantar nada

```bash
gpg --decrypt leaks-traspaso-AAAA-MM-DD.tar.gz.gpg > leaks-traspaso.tar.gz

docker compose run --rm -v "$PWD:/entrada:ro" api \
    leaks import-bundle /entrada/leaks-traspaso.tar.gz
```

**El orden importa y es el error más fácil de cometer.** Si levantás
`docker compose up` primero, el arranque siembra la watchlist de ejemplo y los
canales del catálogo público, y el import se niega a pisar eso. No es grave: el
mensaje detecta que no hay hallazgos propios, te dice que es una instalación
recién sembrada y que `--force` es seguro ahí. Repetí con `--force` y listo.

El import verifica que **todos** los destinos sean escribibles antes de tocar
ninguno, así que no puede dejar una instalación a medio importar.

### 5. Verificar que llegó completo

```bash
docker compose run --rm --no-deps api python -c "
from leaks.bootstrap import build_application
a = build_application()
print(a.watchlist_repo.counts()['total'], 'entradas de watchlist')
print(a.queries.stats()['total'], 'hallazgos')
print(a.adjacency_repo.count_victims(), 'víctimas regionales')"
```

Los tres números tienen que coincidir con los que imprimió `export-bundle`. Si
no coinciden, **no sigas**: importá de nuevo antes de levantar el servicio.

### 6. Levantar

```bash
docker compose up -d
```

La UI queda en <http://127.0.0.1:8000> — solo loopback, porque la API no tiene
autenticación.

---

## Antes de la primera corrida: la VPN

El control de IP de salida **bloquea la corrida** si el tráfico sale desde
Argentina, y también si no puede determinar el país (fail-closed). Con la VPN
caída no se consulta ninguna fuente y la UI lo dice.

Es intencional y no se puede desactivar desde la interfaz. Se gobierna con
`LEAKS_EGRESS_BLOCKED_COUNTRIES` en el `.env`.

Ojo con una trampa que ya costó una sesión de depuración: **el contenedor y tu
terminal pueden salir por rutas distintas.** Un `curl ifconfig.me` desde el shell
no prueba por dónde sale el pipeline. Verificá desde adentro:

```bash
docker compose run --rm --no-deps api python -c "
from leaks.bootstrap import build_application
d = build_application().egress_guard.evaluate()
print('permitido' if d.allowed else 'BLOQUEADO', '—', d.reason)"
```

---

## Qué reemplaza el paquete, y qué queda de la semilla

Después de importar, **nada de la semilla de ejemplo sobrevive**: el import
reemplaza el archivo de base completo, más `data/watchlist.yaml` y
`data/watchlist-regional/`.

| Qué | Viaja en el paquete | Nota |
|---|---|---|
| Watchlist (dominios + keywords) | ✅ | Con lo editado desde la UI, que el YAML solo no tiene |
| Watchlists regionales por país | ✅ | 9 archivos |
| Canales de Telegram | ✅ | Con su estado habilitado/deshabilitado **y sus cursores** |
| Catálogo de sitios de leaks | ✅ | |
| Hallazgos y víctimas regionales | ✅ | Viaja la investigación, no solo la configuración |
| Actores de adyacencia | ✅ | Con su score y su carril |
| Toggle de fuentes con PII | ✅ | Está en `app_settings`, dentro de la base |
| **Vault de PII** | ❌ | Lo único con datos de personas. Nunca se exporta |
| **Credenciales** | ❌ | Vienen por entorno |
| Dominios de foro y fids | ❌ | Van en el `.env`, no en el paquete |

Dos consecuencias que conviene tener presentes:

**Los canales de Telegram llegan con sus cursores.** La primera corrida trae solo
lo nuevo desde que se generó el paquete, no el historial. Si querés releer un
canal, `leaks telegram-recatchup <canal>`.

**Buena parte de los canales llega deshabilitada**, a propósito: el catálogo
público trae cientos y habilitarlos todos convertiría cada corrida en cientos de
pedidos. Se habilitan desde la pantalla de Telegram.

---

## Trampas conocidas

**No descomentes las rutas en el `.env`.** `LEAKS_DATABASE_URL`,
`LEAKS_ALEMBIC_DIR`, `LEAKS_FRONTEND_DIR` y `LEAKS_API_HOST` están comentadas a
propósito: la imagen ya las fija a las de adentro del contenedor, y definirlas en
el `.env` se las pisa con rutas del host. El síntoma es un contenedor en bucle
con `no such table: watchlist_entries`. Ver la sección final de
`instalacion.md`.

**`TZ` gobierna la hora de la corrida.** Sin ella el contenedor corre en UTC y
`LEAKS_DAILY_RUN_AT=03:00` cae a medianoche argentina. El `docker-compose.yml` ya
la fija en `America/Argentina/Buenos_Aires`.

**Los canales de alerta llegan vacíos.** `LEAKS_ALERT_WEBHOOK_URL` y el bot de
Telegram no viajan. Sin configurarlos el pipeline funciona y acumula avisos
pendientes, pero no manda ninguno — no es un error, es que no hay a dónde.

**`leaks` puede no ser este `leaks`.** En macOS hay un `/usr/bin/leaks` del
sistema que se lleva el nombre. Si el comando responde algo sobre *"cannot find
any existing process"*, estás ejecutando el de Apple: usá `uv run leaks` o
`.venv/bin/leaks`. Dentro del contenedor no pasa.

**Si exportás la watchlist a YAML, revisá las deshabilitadas.**
`leaks export-watchlist` marca las entradas dadas de baja agregándoles
`# deshabilitada` al valor, y al volver a sembrar ese YAML la marca entra como
parte del dominio. No afecta al traspaso por paquete —ahí la watchlist viaja en
la base, con su estado intacto—, solo a la ruta por YAML.

---

## Actualizar después

El repositorio es la fuente única; el paquete es solo el arranque.

```bash
git pull && docker compose build && docker compose up -d
```

Las migraciones corren solas al arrancar. El manifiesto del paquete anota la
revisión de esquema con la que se generó, así que importar en una versión
distinta avisa en vez de fallar raro tres pantallas después.
