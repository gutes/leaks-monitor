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

## Acceso al repositorio: deploy key, no cuenta de GitHub

El repositorio es privado y quien recibe necesita `git pull` para actualizar. No
hace falta que tenga cuenta de GitHub: para eso existen las **deploy keys**, que
son claves SSH atadas a **un solo repositorio** y que por defecto son de **solo
lectura**.

Cuándo *sí* conviene una cuenta en vez de una deploy key:

| | deploy key | cuenta de GitHub |
|---|---|---|
| Un repo, solo `pull` | ✅ lo indicado | innecesario |
| Va a escribir código y abrir PRs | ❌ no sirve (solo lectura) | ✅ |
| Necesita varios repos | ❌ una clave por repo | ✅ |
| Auditoría de quién hizo qué | ❌ es una máquina, no una persona | ✅ |

Para entregar una instalación que solo se corre y se actualiza, la deploy key es
la opción correcta: menos superficie, y se revoca borrando una línea sin tocar
el acceso de nadie más.

### El intercambio, en el orden que importa

**La clave privada se genera en la máquina de quien recibe y no se mueve de
ahí.** Solo viaja la pública. Quien entrega nunca tiene la privada, así que no
puede perderla ni filtrarla.

**1. Quien recibe genera el par y manda solo la pública:**

```bash
ssh-keygen -t ed25519 -C "leaks-monitor deploy $(hostname)" \
    -f ~/.ssh/leaks_monitor_deploy
cat ~/.ssh/leaks_monitor_deploy.pub    # esto es lo que se manda
```

La frase de paso es opcional: con una, cada `git pull` la pide (o hace falta un
agente). Sin una, el archivo alcanza para leer el repo, así que vale lo mismo
que el permiso de lectura.

**2. Quien entrega la registra en GitHub**, en el repositorio —no en la cuenta—:

> *Settings → Deploy keys → Add deploy key*. Un título que diga de qué máquina
> es, el contenido del `.pub`, y **sin** tildar *Allow write access*.

Si GitHub responde *"Key is already in use"*, esa clave ya está registrada en
otro repositorio o como clave de usuario: una deploy key es única en todo
GitHub. Se genera otra.

**3. Quien recibe apunta el repo a esa clave.** En `~/.ssh/config`:

```
Host github-leaks-deploy
  HostName github.com
  User git
  IdentityFile ~/.ssh/leaks_monitor_deploy
  IdentitiesOnly yes
```

`IdentitiesOnly yes` no es decorativo: sin eso, en una máquina que ya tenga otra
clave de GitHub, SSH ofrece todas y el servidor autentica con la primera que le
sirva — que puede no ser esta. Es exactamente el problema por el que la máquina
de origen usa el alias `github-leaks`.

Probar antes de clonar:

```bash
ssh -T git@github-leaks-deploy
```

La respuesta dice con qué identidad autenticó, y son distintas:

```
Hi gutes/leaks-monitor!  ...   ← deploy key: está atada al REPOSITORIO
Hi <usuario>!            ...   ← clave de usuario: es una persona
```

Si aparece un nombre de usuario, la clave que se usó no es la deploy key: casi
siempre es `IdentitiesOnly` faltando y SSH ofreciendo otra clave de la máquina.

**4. Clonar por el alias**, no por `git@github.com`:

```bash
git clone git@github-leaks-deploy:gutes/leaks-monitor.git && cd leaks-monitor
```

El `origin` queda con el alias, así que `git pull` funciona sin más
configuración.

### Dos cosas que no hay que hacer

**No metas la clave en la imagen de Docker.** El repositorio se clona y se
actualiza en el host; el contenedor se construye desde el checkout. Una clave
dentro de una imagen queda en las capas y viaja con cada copia de la imagen.

**No uses un token personal (PAT) para esto.** Un PAT es una credencial *de una
persona*: aunque se limite a un repo, quien lo tiene actúa como el dueño. La
deploy key es de la máquina y no representa a nadie.

### Revocar

*Settings → Deploy keys → borrar la fila.* El acceso de esa máquina se corta en
el momento y no afecta a nadie más. Es el motivo principal para preferir esto a
compartir una cuenta.

---

### Si la copia no llegó por `git clone`

Pasa: se manda el directorio del proyecto en un zip, o se copia por `scp`, y del
otro lado queda una instalación que **no sabe de dónde actualizarse**. Hay dos
casos y se arreglan distinto.

> **Mejor no llegar acá.** Mandar el directorio de trabajo es mandar también el
> `.env` —y ahí vive `LEAKS_PII_ENCRYPTION_KEY`—, la watchlist real y cualquier
> paquete sin cifrar que haya quedado en `data/`. El repositorio se clona; los
> datos van en el paquete. Ver `instalacion.md`.

**Caso A — la copia trae `.git`.** El `origin` apunta al alias SSH de la máquina
de origen, que del otro lado no existe:

```
ssh: Could not resolve hostname github-leaks: nodename nor servname provided
fatal: Could not read from remote repository.
```

No falta la clave: falta el alias. Se reapunta al propio:

```bash
git remote set-url origin git@github-leaks-deploy:gutes/leaks-monitor.git
git remote -v          # confirmar
git pull
```

**Caso B — la copia no trae `.git`.** No es un repositorio, así que no hay nada
que reapuntar. Lo limpio es clonar al lado y mudar los datos:

```bash
git clone git@github-leaks-deploy:gutes/leaks-monitor.git leaks-monitor-nuevo
cp copia-vieja/.env leaks-monitor-nuevo/.env
cd leaks-monitor-nuevo
cp ../leaks-traspaso-AAAA-MM-DD.tar.gz data/
docker compose run --rm --no-deps api \
    leaks import-bundle /app/data/leaks-traspaso-AAAA-MM-DD.tar.gz
```

Si borrar la copia vieja no es una opción —porque ya está corriendo con datos—,
se le puede injertar el repositorio encima. **Verificado en un sandbox el
2026-09-30**: el código del repo entra, y `.env` y `data/` sobreviven intactos
porque no están versionados.

```bash
cd copia-vieja
git init -b main .
git remote add origin git@github-leaks-deploy:gutes/leaks-monitor.git
git fetch origin main
git reset --hard origin/main      # ⚠️ ver abajo
git status                        # tiene que quedar limpio
```

**Lo que `git reset --hard` se lleva:** cualquier archivo **versionado** que esté
modificado en la copia queda pisado por la versión del repositorio. Los que no
están versionados —`.env`, `data/`, la base— no se tocan. Si se editó código en
esa copia, respaldarlo antes:

```bash
cp -a copia-vieja copia-vieja.bak-$(date +%F)
```

Después de cualquiera de los dos casos, `git pull` funciona normalmente con la
deploy key.

---

### Borrar lo anterior y empezar de cero

Cuando la instalación vieja no vale la pena arreglarla. El orden no es negociable:
**el volumen se borra desde el directorio viejo**, porque Compose necesita ese
contexto para saber de qué proyecto es.

**0. Rescatar lo que no se puede volver a bajar.** Sacar de ahí el `.env` y el
paquete antes de borrar nada:

```bash
mkdir -p ~/traspaso
cp proyecto-viejo/.env ~/traspaso/env-viejo.txt   # por si hace falta comparar
ls proyecto-viejo/data                            # ¿queda algo que rescatar?
```

**1. Parar y borrar contenedores y datos, desde el directorio viejo:**

```bash
cd proyecto-viejo
docker compose ps
docker compose down -v
```

El `-v` es lo que borra el volumen con la base. Es lo que se quiere: el paquete
la va a reemplazar, y partir de un volumen vacío evita tener que usar `--force`
al importar.

**2. Comprobar que no quedó nada colgado.**

El nombre del volumen se deriva del **nombre del directorio**
(`<directorio>_leaks-data`). Si el clon nuevo va a un directorio con otro nombre,
el volumen viejo sobrevive huérfano con los datos viejos adentro:

```bash
docker compose ls -a
docker volume ls | grep leaks
docker volume rm <nombre-del-volumen-viejo>   # si quedó alguno
```

**3. Borrar el código viejo.**

```bash
cd ..
rm -rf proyecto-viejo
```

**4. Clon limpio, configuración, importación y arranque** — los pasos de la
parte 2, en ese orden. El único cambio es que el paquete ya no está en el
directorio del proyecto:

```bash
git clone git@github-leaks-deploy:gutes/leaks-monitor.git
cd leaks-monitor
cp ~/traspaso/traspaso-AAAA-MM-DD.env .env
# + pegar la propia LEAKS_PII_ENCRYPTION_KEY (openssl, ver parte 2 paso 3)

cp ~/traspaso/leaks-traspaso-AAAA-MM-DD.tar.gz data/
docker compose run --rm --no-deps api \
    leaks import-bundle /app/data/leaks-traspaso-AAAA-MM-DD.tar.gz

docker compose up -d
```

`import-bundle` no siembra el esquema antes de restaurar, así que sobre un
volumen recién borrado entra sin `--force` y sin preguntar nada.

Verificar los conteos (parte 2, paso 5) **antes** de dar el arranque por bueno.

---

## Parte 2 — Quien recibe (seis pasos)

Hace falta: **Docker** con `compose`, **git**, y acceso al repositorio privado
(ver la sección anterior).

### 1. Clonar

```bash
git clone git@github-leaks-deploy:gutes/leaks-monitor.git && cd leaks-monitor
```

Si tenés cuenta de GitHub con acceso al repo en vez de una deploy key, el clon
es por `git@github.com:gutes/leaks-monitor.git` y no hace falta el alias.

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
openssl rand -base64 32 | tr '+/' '-_'
```

Pegala en `.env` como `LEAKS_PII_ENCRYPTION_KEY=…`.

Una clave de Fernet son 32 bytes al azar en base64 **urlsafe**, que es
exactamente lo que produce ese comando: el `tr` cambia `+/` por `-_`, que es la
única diferencia entre las dos variantes de base64. Verificado el 2026-09-30
haciendo ida y vuelta con una clave generada así.

`openssl` viene en cualquier macOS o Linux, y por eso es el camino recomendado
acá: no necesita el proyecto instalado. **El comando con
`from cryptography.fernet import Fernet` solo funciona con el entorno de Python
del proyecto armado** (`./scripts/dev.sh setup`); en el Python del sistema falla
con `ModuleNotFoundError: No module named 'cryptography'`, porque es una
dependencia del proyecto y no de la máquina.

Si preferís usar la biblioteca, hacelo dentro del contenedor —que ya la trae—,
pero entonces este paso va **después** de que la imagen esté construida:

```bash
docker compose build api
docker compose run --rm --no-deps api python -c \
    "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Sin esto, con
`LEAKS_STORE_PII=true` el proceso **se niega a arrancar** — es a propósito:
fail-closed. Si preferís no persistir PII, poné `LEAKS_STORE_PII=false` y no
hace falta clave.

### 4. Importar el paquete ANTES de levantar nada

```bash
gpg --decrypt leaks-traspaso-AAAA-MM-DD.tar.gz.gpg > data/leaks-traspaso.tar.gz

docker compose run --rm --no-deps api \
    leaks import-bundle /app/data/leaks-traspaso.tar.gz
```

> **El path es el de adentro del contenedor, no el de tu máquina.** Es el error
> más común de este paso: `leaks import-bundle ../paquete.tar.gz` falla con
> `No existe ../paquete.tar.gz` aunque el archivo esté ahí, porque adentro el
> directorio de trabajo es `/app` y tu `..` no existe. Lo más simple es dejar el
> paquete en `./data/`, que el `docker-compose.yml` **ya monta** en `/app/data`
> — la misma ruta que usa `export-bundle --out`.

Si el paquete no se puede mover a `./data/`, se monta su directorio a mano:

```bash
docker compose run --rm --no-deps -v "/donde/esta:/entrada:ro" api \
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

## Puesta en marcha: cadencia y avisos

Las dos cosas que hay que configurar después de importar, y que el paquete no
trae porque van por entorno.

### La corrida periódica: no hay cron

**Nada en el repositorio instala un crontab.** La corrida periódica la hace un
proceso largo, `leaks schedule`, en el contenedor `scheduler` que el
`docker-compose.yml` ya levanta. Con `docker compose up -d` queda andando.

Se gobierna con cuatro variables:

| Variable | Default | Qué hace |
|---|---|---|
| `TZ` | `America/Argentina/Buenos_Aires` | La hora del run es **local**. Sin esto el contenedor corre en UTC y las 03:00 caen a medianoche |
| `LEAKS_DAILY_RUN_AT` | `03:00` | Hora de la corrida completa |
| `LEAKS_RUN_ON_START` | `true` | Corre una vez al arrancar, sin esperar la hora |
| `LEAKS_SCHEDULER_CATCHUP` | `true` | Si la máquina estaba suspendida a la hora del run, lo ejecuta al despertar |

Las fuentes efímeras se sondean además cada tanto —los foros cada 120 minutos—
y eso **no se configura por entorno**: vive en `poll_interval_minutes` del
registro de feeds, porque depende de la ventana de cada fuente y no del gusto
del operador. Ver `docs/arquitectura.md`, *Cadencia*.

Comprobar que está corriendo:

```bash
docker compose logs --tail 20 scheduler
curl -s http://127.0.0.1:8000/api/health   # last_run_at y last_full_run_at
```

`last_run_at` responde "¿está vivo?" y `last_full_run_at` "¿miró todo?": un
sondeo de foros mueve el primero y no el segundo.

### Si se prefiere el cron del sistema

Es una opción válida en un servidor, y tiene un costo que conviene saber antes.

**Primero apagar el scheduler**, o las dos corridas se pisan: el candado que
evita solapamientos es **en proceso**, así que no ve al otro contenedor.

```bash
docker compose stop scheduler
docker compose up -d api
```

Y el crontab, con rutas absolutas —cron no tiene el `PATH` de la sesión—:

```cron
0 3 * * * cd /home/usuario/leaks-monitor && /usr/bin/docker compose run --rm --no-deps api leaks run >> /var/log/leaks.log 2>&1
```

`leaks run` devuelve **1** si ninguna fuente respondió, así que el cron puede
avisar por su cuenta.

**Lo que se pierde:** cron no recupera una ejecución que no ocurrió. Si la
máquina estaba apagada a las 03:00, ese día no hay corrida — es justo lo que
`LEAKS_SCHEDULER_CATCHUP` resuelve en el scheduler. En un servidor que no se
suspende da igual; en una notebook, no. Con systemd, un timer con
`Persistent=true` recupera el disparo perdido y sería el equivalente.

### Los avisos

Dos canales, los dos por entorno y los dos opcionales:

```bash
# Webhook genérico: sirve para Slack, Discord, n8n o uno propio.
LEAKS_ALERT_WEBHOOK_URL=

# Telegram: hacen falta los dos.
LEAKS_ALERT_TELEGRAM_TOKEN=
LEAKS_ALERT_TELEGRAM_CHAT_ID=
```

Y los umbrales:

| Variable | Default | Qué hace |
|---|---|---|
| `LEAKS_ALERT_MIN_SEVERITY` | `high` | Desde qué severidad se avisa |
| `LEAKS_ALERT_MAX_AGE_DAYS` | `30` | No avisar de eventos más viejos que esto |
| `LEAKS_ALERT_MAX_PER_RUN` | `50` | Tope por corrida |
| `LEAKS_ALERT_DRY_RUN` | `false` | Ensaya sin enviar ni marcar |
| `LEAKS_WATCHDOG_MAX_SILENCE_HOURS` | `26` | Avisa si una fuente se quedó muda. `0` lo apaga |

**Sin canales configurados no es un error**: el pipeline corre igual y los avisos
quedan pendientes. El riesgo es no darse cuenta, así que el estado se consulta:

```bash
curl -s http://127.0.0.1:8000/api/alerts
```

Dice cuántos hay pendientes, cuántos se enviaron, y —si falta un canal— **qué
variable de entorno hay que setear**. Nunca devuelve el valor de un secreto,
solo si está o no. Lo mismo se ve en la pantalla **Fuentes** de la UI.

**Antes de enchufar un webhook por primera vez, ensayarlo.** Con
`LEAKS_ALERT_DRY_RUN=true` se arma el aviso, queda en la consola de actividad qué
se habría mandado y por qué canales, y no se envía ni se marca nada. Existe por
un incidente real: verificar el cableado contra un webhook de terceros mandó
metadata de 7 hallazgos afuera **y además los consumió**, porque quedaron
marcados como avisados sin que nadie los hubiera recibido.

Hay un tercer aviso, aparte: el **salto de score** de la adyacencia
(`LEAKS_ADJACENCY_ALERT_JUMP`, `LEAKS_ADJACENCY_ALERT_MIN_SCORE`). Ver
`docs/adyacencia.md`.

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

### `/app/data no es escribible`

Sale al importar, en Linux, y el mensaje viejo mandaba a revisar el montaje —que
está bien—. La causa es de permisos: **un bind mount conserva el uid numérico**.
El contenedor corre como `uid 10001` (`leaks`, definido en el `Dockerfile`),
mientras que `data/` del host pertenece al usuario que clonó el repo (uid 1000
normalmente). Adentro, ese directorio no es escribible.

En macOS no pasa, porque Docker Desktop remapea la pertenencia de los archivos
compartidos. Por eso el problema aparece recién del otro lado del traspaso.

Se arregla dándole al directorio el grupo del contenedor, sin perder la
propiedad del usuario:

```bash
sudo chown -R $USER:10001 data
chmod -R g+rwX data
```

Así el usuario del host sigue pudiendo editar esos archivos y el contenedor
puede escribirlos. Hace falta para `import-bundle`, y también para
`export-bundle --out /app/data/…` y `export-watchlist --out /app/data/…`.

**El atajo de correr como root** (`docker compose run --user root …`) desbloquea
el import pero deja `watchlist.yaml` y las regionales pertenecientes a `root`:
la próxima importación como usuario normal vuelve a fallar, y editarlas a mano
pide `sudo`. Sirve para salir del paso, no como arreglo.

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
