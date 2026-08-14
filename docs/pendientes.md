# Pendientes y decisiones abiertas

Estado al **2026-08-14**. El prototipo corre end-to-end: 224 tests, 89% de
cobertura, imagen Docker verificada, 214 hallazgos argentinos reales en la base.

---

## 1. Decisiones que esperan confirmación del líder técnico

Las tomé yo para no bloquear. Todas son reversibles.

| # | Decisión | Alternativa |
|---|---|---|
| 1 | **El control de IP de salida bloquea también cuando el país es indeterminable** (`LEAKS_EGRESS_BLOCK_ON_UNKNOWN=true`). El pedido fue "bloquear si es AR"; interpreté fail-closed porque el control promete que *no* se sale por AR, y una IP sin resolver no da esa garantía. **Costo:** si los proveedores de geo-IP se caen, el monitoreo se detiene. | Ponerlo en `false`: prioriza disponibilidad sobre garantía. |
| 2 | **La API dejó de ser solo-lectura.** Hay escritura para watchlist y reglas, sin autenticación, detrás de `LEAKS_ALLOW_RULE_EDITING` (default `true`). Aceptable en loopback, no en una red. | `false` para bloquear la edición, o poner auth adelante. |
| 3 | **DarkForums quedó `enabled_by_default=True` + `requires_pii=True`**, para que su único motivo de apagado sea el toggle de PII y el interruptor pueda encenderlo. | — |
| 4 | **El handle del autor de un thread de foro se guarda como `actor`.** Es un seudónimo público, igual que el nombre de un grupo de ransomware. | Hashearlo si se considera PII. |

---

## 2. Deuda contra el bootstrap original

| # | Pendiente | Detalle |
|---|---|---|
| 1 | **Alertas — no existe nada.** | El ejemplo del bootstrap termina en *"Alerta emitida"*. Hoy el hallazgo se persiste y se ve en el tablero, nada más. Sin email, sin webhook, sin Telegram. **Es lo único del spec original que falta entero.** |
| 2 | **Watchlist SEED sin validar contra el inventario del CNC.** | Ya aparecieron 8 dominios estatales reales que matchean solo por `tld_ar`: `nuclear-ejemplo.gob.ar`, `cnv.gob.ar`, `provinciados-ejemplo.gob.ar`, `tigre.gob.ar`, `santarosa.gob.ar`, `iscamen.gov.ar`, `provincia-ejemplo.gob.ar`, `fm.gob.ar`. Falta todo el nivel provincial y municipal. Ahora se puede cargar desde la UI. |
| 3 | **Hudson Rock sin verificar.** | Adapter escrito contra la forma documentada, nunca probado: el endpoint no respondía (timeout 60 s). |
| 4 | **Fase 2 sin implementar.** | GitHub secret scanning sobre orgs `.gob.ar`, Telegram (MTProto), paste sites. Los hooks están listos: es un adapter más una entrada en el registro. |

---

## 3. Calidad de los datos

- **`sector` vacío** en el 100% de dls-monitor (31/31) y de los foros: esos feeds no lo traen y no lo derivamos de la watchlist cuando hay match. Se podría.
- **Sin loop de falsos positivos.** No hay forma de marcar un hallazgo como descartado ni una allowlist. El caso *Distribuidora Ejemplo Dominicana* se corrigió tocando código; debería ser dato.
- **Sin deduplicación entre fuentes.** Por diseño `source` entra en el hash, así que una misma víctima aparece dos veces si dos feeds la publican. Falta la vista agrupada por víctima.

---

## 4. Producto / UX

- Export CSV/JSON.
- Vista de detalle por hallazgo.
- Filtro por `ar_match_reason` en la UI (el dato está, falta el selector).
- Timeline o gráfico de evolución.

---

## 5. Operación y seguridad

- **El repositorio ya está inicializado** (`git init` + commit inicial en `main`). Falta remoto: el workflow de CI existe pero **nunca se ejecutó**. (El líder técnico indicó que el CI no es prioridad por ahora.)
- **La API no tiene autenticación y ahora además escribe.** Sube la prioridad de poner un proxy que autentique si sale de loopback.
- Sin rate limiting en la API. Sin backup de la base.
- `dls-monitor` baja 2 MB completos en cada corrida: falta `ETag`/`If-Modified-Since`.
- Del checklist del CLAUDE.md faltan: escaneo de imagen (trivy/grype), DAST, `pip-audit` local, gitleaks local.

---

## 6. Testing

- **El frontend no tiene tests.** Subió de prioridad: ya no es una tabla, tiene el bloqueo de OPSEC, la consola, el CRUD de watchlist y el control de PII. Toda esa lógica está sin cobertura automatizada.
- Sin test de `alembic downgrade`.

---

## 7. Hallazgos que conviene no perder

- **BreachForums está incautado.** `.hn`, `.is` y `.cx` muestran el cartel de las fuerzas del orden; el resto no resuelve. Queda registrado y apagado; cuando reaparezca alcanza con setear `LEAKS_BREACHFORUMS_BASE_URLS`.
- **Ningún proveedor CTI de los 8 evaluados tiene free tier con API usable.** Ver [cti-proveedores.md](cti-proveedores.md).
- **VECERT: no integrar sin verificación independiente.** Hay un análisis público que alega credenciales hardcodeadas, API abierta sin key y redistribución de ~633.000 registros robados. Son alegaciones de un tercero, pero de gravedad suficiente para frenar.
- **Dos bugs que solo aparecieron en Docker** (ya corregidos, con tests): las listas por variable de entorno rompían el arranque porque pydantic-settings las parseaba como JSON; y `leaks serve` no creaba el schema, así que todos los endpoints devolvían 500.

---

## Prioridad sugerida

1. **Alertas** — lo único del spec original que falta entero.
2. **Completar la watchlist** — hoy se está perdiendo señal o degradando severidad; ya se puede cargar desde la UI.
3. **Tests del frontend** — es donde vive ahora la lógica sin cobertura.
4. **Loop de falsos positivos** — para que tunear deje de requerir tocar código.
