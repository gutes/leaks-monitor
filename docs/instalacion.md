# Instalación y distribución al equipo

## La decisión de fondo: qué se reparte

**No se reparte la imagen de Docker.** Los números lo dicen solo:

| | tamaño |
|---|---|
| Imagen Docker | **314 MB** |
| Todos los datos (base + watchlists) | **0,44 MB** |

La imagen es 700 veces más grande que los datos y se reconstruye con un comando
desde el repositorio. Repartirla significa que queda vieja al día siguiente, que
no se puede parchear y que cada actualización son otros 314 MB por persona.

Se reparten **dos cosas**:

1. **El repositorio** — la fuente única. Cada uno lo clona y construye.
2. **Un paquete de datos de ~450 KB** — la base y las watchlists.

## Antes de repartir: cuántas instancias

Cada instancia que corre el pipeline multiplica tres costos, y ninguno es
técnico:

- **Licencia.** El tier gratuito de ransomware.live es *"personal use only, not
  for corporate/business use"*. Una persona prototipando se defiende; cinco
  instancias de un equipo es uso corporativo.
- **Exposición.** Cada consulta a Hudson Rock le revela a un proveedor comercial
  extranjero qué organismo se está vigilando. Cinco instancias son cinco veces
  esa revelación.
- **OPSEC.** Cada instancia necesita la VPN. Cinco personas con disciplina de
  VPN es una consulta saliendo desde Argentina esperando a pasar.

Por eso conviene el modelo **mixto**: una instancia que corre el pipeline, y el
resto del equipo mirándola o con instancias que **no corren el pipeline** (sin
`schedule`, solo `serve` sobre los datos importados).

---

## A. Instancia compartida (la mayoría del equipo)

Una sola máquina corre el pipeline y el equipo entra por el navegador.

```bash
git clone git@github.com:gutes/leaks-monitor.git && cd leaks-monitor
cp .env.example .env          # editar según haga falta
docker compose up -d          # construye y levanta
```

> El repositorio es **privado**. Antes de que alguien pueda clonarlo hay que
> darle acceso:
>
> ```bash
> gh api repos/gutes/leaks-monitor/collaborators/USUARIO -X PUT -f permission=push
> ```

Por defecto la API escucha **solo en loopback** (`127.0.0.1:8000`), así que
desde otra máquina no se ve. Para exponerla en la red interna, en
`docker-compose.yml`:

```yaml
    ports:
      - "0.0.0.0:8000:8000"   # antes: "127.0.0.1:8000:8000"
```

> **La API no tiene autenticación y además escribe** (watchlist, reglas,
> canales, disparar corridas). Exponerla en una red es dejar todo eso abierto a
> quien llegue. Mitigación barata mientras no haya login: poner
> `LEAKS_ALLOW_RULE_EDITING=false` en el `.env`, que la deja de solo lectura
> salvo por el botón de correr.

## B. Instancia propia con tus datos

Para quien necesite correrlo o desarrollarlo.

**Vos, una vez, generás el paquete:**

```bash
docker compose exec api leaks export-bundle --out /tmp/p.tar.gz
docker compose exec -T api cat /tmp/p.tar.gz > leaks-datos-$(date +%Y%m%d).tar.gz
```

**Cada uno, en su máquina:**

```bash
git clone git@github.com:gutes/leaks-monitor.git && cd leaks-monitor
cp .env.example .env

# 1) Restaurar los datos ANTES de levantar nada
docker compose run --rm -v "$PWD:/entrada:ro" api \
    leaks import-bundle /entrada/leaks-datos-AAAAMMDD.tar.gz

# 2) Levantar
docker compose up -d
```

**El orden importa.** Si levantás el compose primero, la base se siembra con
la watchlist de ejemplo y el import se va a negar a pisarla. No es grave: el
mensaje detecta que no hay hallazgos y te dice que `--force` es seguro ahí.

El import verifica que todos los destinos sean escribibles **antes** de tocar
ninguno, así que no puede dejarte una instalación a medio importar.

### Clonar solo, sin el paquete

Es una opción válida: se obtiene el prototipo funcionando con **watchlists
ficticias y la base vacía** (29 entradas de ejemplo, 0 hallazgos). Sirve para
desarrollar o para armar una watchlist propia desde cero. Lo que no sirve es
para ver los mismos datos que el resto del equipo — para eso hace falta el
paquete.

### Verificar que llegó completo

```bash
docker compose run --rm --no-deps api python -c "
from leaks.bootstrap import build_application
a = build_application()
print(a.watchlist_repo.counts()['total'], 'entradas de watchlist')
print(a.queries.stats()['total'], 'hallazgos')
print(a.adjacency_repo.count_victims(), 'víctimas regionales')"
```

Los números tienen que coincidir con los que imprimió `export-bundle`.

---

## Qué lleva y qué no lleva el paquete

**Lleva:** la base entera (hallazgos, watchlist, víctimas regionales, perfiles
de actor, catálogo de sitios, canales de Telegram) y las watchlists en YAML.

**No lleva:**

- **El vault de PII.** Es lo único con datos de personas físicas y no viaja,
  aunque tenga contenido. Compartirlo tendría que ser una decisión aparte.
- **Ninguna credencial.** La configuración va por entorno: tokens de alerta,
  clave de cifrado y demás quedan en el `.env` de cada uno.

### Por qué existe el comando y no alcanza con copiar el archivo

La base corre en modo **WAL**: lo recién escrito vive en `leaks.db-wal` hasta
que SQLite hace checkpoint. Medido en el despliegue real, la base tenía 1,8 MB
y el WAL 4,3 MB, con el `.db` escrito el día anterior. **Copiar `leaks.db` a
mano habría entregado una base sin nada de la última jornada, y sin ningún
error que lo delatara.** `export-bundle` usa `VACUUM INTO`, que toma una
instantánea consistente y de paso compacta.

### Cómo mandarlo

El paquete dice **qué organismos vigilás y cuáles figuran comprometidos**. Si
va por un canal que no controlás —correo, Drive, mensajería— tiene que ir
cifrado:

```bash
age -p -o leaks-datos.tar.gz.age leaks-datos.tar.gz     # o gpg -c
```

Por copia directa entre máquinas de la organización, alcanza tal cual.

---

## Las watchlists no están en el repositorio

Están en `.gitignore` porque dicen qué organismos se vigilan. El repositorio
lleva `data/examples/` con dominios **ficticios**, y el código cae ahí cuando
los reales no existen, avisando por la bitácora.

`docker-compose.yml` monta `./data` dentro del contenedor, así que las reales
—las tuyas o las que restaure el paquete— se usan sin tocar la imagen.

Para respaldar solo la watchlist, sin la base:

```bash
docker compose exec api leaks export-watchlist --out mi-watchlist.yaml
```

Sale de la **base**, no del YAML: apenas se edita una entrada desde la pantalla
Watchlist, el archivo original queda viejo.

---

## Instalación local, sin Docker

Para desarrollar.

```bash
uv venv && uv pip install -e ".[dev]"
cp .env.example .env
cp data/examples/watchlist.yaml data/watchlist.yaml       # o importá un paquete
cp -r data/examples/watchlist-regional data/watchlist-regional

.venv/bin/leaks init-db
.venv/bin/leaks serve
```

`./scripts/dev.sh check` corre lint, tipos, tests y SAST — lo mismo que el CI.

---

## Actualizar

El código se actualiza con `git pull` + `docker compose up -d --build`. Las
migraciones corren solas al arrancar.

Los datos **no se sincronizan solos**: cada instancia diverge desde el momento
en que se importa el paquete. Si el equipo tiene que ver lo mismo, la instancia
compartida (opción A) es el único camino que no requiere repartir un paquete
nuevo cada vez.
