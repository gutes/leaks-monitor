# Seguir a los sitios cuando cambian de dominio

Investigación del 2026-08-15. La pregunta: cómo no perder una fuente cuando el
sitio se muda, y si hay algún proyecto que ya lo rastree.

Respuesta corta: **para sitios de ransomware, sí y ya los estamos consumiendo.
Para foros, no hay nada confiable — y automatizarlo sería peligroso.**

---

## 1. Sitios de ransomware: ya resuelto por los feeds que usamos

Los tres feeds del prototipo publican, además de las víctimas, **el catálogo de
ubicaciones de cada grupo con su disponibilidad**. Verificado el 2026-08-15:

| Proyecto | Endpoint | Qué trae |
|---|---|---|
| **ransomware.live** | `GET /v2/groups` | 387 grupos, **782 ubicaciones** con `fqdn`, `available`, `enabled`, `type` |
| **dls-monitor** | `groups.json` | 182 grupos, **367 ubicaciones** con `fqdn`, `available`, `lastscrape`, `updated` |
| **RansomLook** | `GET /api/group/<nombre>` | detalle por grupo con sus espejos; además `GET /api/markets` (~30 mercados) |

O sea: el trabajo de perseguir dominios que rotan **ya lo hacen ellos**, y
nosotros ya tenemos acceso. No hace falta un proyecto nuevo ni un scraper
propio.

**Implementado el 2026-08-15.** Tabla `leak_sites`, colector dentro de la
corrida diaria, endpoint `GET /api/sites` y pantalla **Sitios**. En la primera
pasada consolidó 979 ubicaciones de 530 grupos. Lo que sigue describe el diseño:

- Tabla `leak_sites`: `name`, `kind`, `fqdn`, `available`, `first_seen`,
  `last_seen`, `source`.
- Un colector que corre dentro del run diario, usando los feeds que ya
  consumimos — sin sumar dependencias ni términos nuevos.
- Pantalla "Sitios" en la UI: qué grupos se mudaron, qué ubicación está viva y
  desde cuándo. Sirve como señal por sí sola: un grupo que cambia de dominio
  suele estar por publicar.
- Como los `.onion` no se visitan desde acá, esto es puro catálogo: se registra
  dónde está cada sitio, no se entra.

---

## 2. Foros: no hay proyecto confiable, y automatizar es riesgoso

El caso testigo es BreachForums, cuyos dominios conocidos están incautados.
Del relevamiento surge que **no hay una "nueva URL oficial"**: tras las
incautaciones y detenciones aparecieron varias reconstrucciones competidoras
usando la misma marca, con dominios distintos.

Lo importante para nosotros no es cuál es el dominio correcto, sino esto:

> Los reportes de seguridad advierten que algunos dominios "resucitados" pueden
> ser **honeypots o infraestructura controlada** (por otros actores o por las
> fuerzas del orden).

Eso convierte al auto-seguimiento en una mala idea. Un adapter que detecte que
el dominio configurado murió y **se conecte solo** al siguiente candidato puede
terminar identificándose contra un servidor hostil, desde la IP del
investigador. El costo de equivocarse es mucho mayor que el de perderse unos
días de un foro.

**Mecanismo propuesto para foros: detectar y proponer, nunca seguir solo.**

1. Health-check de los dominios configurados en cada corrida (ya existe: el
   adapter prueba la lista de candidatos y falla si no responde ninguno).
2. Cuando ninguno responde, marcar la fuente como *sin dominio operativo* — ya
   lo hace, y se ve en la pantalla Fuentes.
3. Agregar una alerta específica: "la fuente X se quedó sin dominio", para que
   el investigador se entere el mismo día.
4. La incorporación del dominio nuevo queda como **acto explícito**: se agrega
   a `LEAKS_*_BASE_URLS` después de verificarlo por fuera. Igual que el control
   de IP de salida: lo que puede exponer al investigador no se automatiza.

---

## Recomendación

Implementar (1) —el catálogo de sitios de ransomware— porque es barato, usa lo
que ya consumimos y agrega señal real. Para (2), agregar solo la alerta del
punto 3 y dejar la rotación de dominios de foros como decisión manual.

## Fuentes

- [BreachForums Successors in 2026: PWN vs Breached — KELA](https://www.kelacyber.com/blog/breachforums-succession-wars-2026/)
- [Is BreachForums Back in 2026? Why No Version Is Verified](https://rottenwifi.com/breachforums-keeps-coming-back-but-there-is-no-longer-one-real-version/)
- Endpoints verificados: `api.ransomware.live/v2/groups`, `raw.githubusercontent.com/cyberiskvision/dls-monitor/main/groups.json`, `www.ransomlook.io/api/markets`
