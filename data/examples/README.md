# Archivos de ejemplo

El proyecto usa estos cuando no encuentra los reales. Mismo patrón que
`.env.example`: lo del repo es genérico y lo tuyo queda en tu disco.

| Ejemplo | Se usa si falta | Qué es |
|---|---|---|
| `watchlist.yaml` | `data/watchlist.yaml` | Qué organismos argentinos vigilar |
| `watchlist-regional/` | `data/watchlist-regional/` | Infraestructura crítica por país, para la sección de adyacencia |

**Los reales están en `.gitignore`.** La watchlist de una investigación dice
qué se está vigilando: publicarla es publicar el mapa de la investigación.

Para empezar, copiá lo que necesites y editalo:

```bash
cp data/examples/watchlist.yaml data/watchlist.yaml
cp -r data/examples/watchlist-regional data/watchlist-regional
```

La watchlist argentina también se edita desde la pantalla **Watchlist**. Al
hacerlo la fuente de verdad pasa a ser la base, no el YAML — usá
`leaks watchlist export` para respaldarla.
