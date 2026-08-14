# Proveedores CTI: ¿hay free tier usable?

Consulta hecha el **2026-08-14**. La pregunta concreta era si alguno permite
**ingesta automática por API sin contratar**, que es lo que necesitaría este
prototipo. Respuesta corta: **ninguno de los ocho**.

No se implementó ningún conector, por decisión del líder técnico.

## Cuadro

| Proveedor | ¿Free tier? | ¿API en el free tier? | Veredicto |
|---|---|---|---|
| **SOCRadar** | Sí — *Free Edition*, 2 usuarios por empresa | **No.** Las integraciones por API están excluidas; además el free apaga el monitoreo de deep/dark web y el descubrimiento continuo | No sirve para ingesta automática |
| **Flare** | Parcial — prueba de 2 semanas y después queda monitoreando **1 identificador** por el resto del año | Tiene API REST, pero no está confirmado que entre en el tramo gratuito | El más cercano, igual insuficiente |
| **Breachsense** | No hay plan gratuito. Escaneo puntual web + 7 días de prueba después de una demo | La cuota de API es una característica de los planes pagos | No |
| **Group-IB** | Solo prueba. Desde ~USD 10.000/año | La API viene incluida, pero con licencia paga | No |
| **SpyCloud** | No. Precio por cotización | Las consultas de API vienen atadas a asientos pagos | No |
| **Cybersixgill** | No documentado | — | No |
| **Axur** | No documentado. Enterprise, por demo | API y STIX/TAXII, con contrato | No |
| **VECERT** | No. Plan de API anual pago | — | No — y ver la advertencia de abajo |

## Conclusión

Los ocho son plataformas comerciales cuyo free tier —cuando existe— es una
**demo del panel web**, no un canal de datos. El patrón es consistente: la API
es justamente lo que se vende.

Esto refuerza la elección de fuentes del prototipo: ransomware.live, RansomLook
y dls-monitor son abiertas, sin contrato y sin depender de la buena voluntad de
un proveedor comercial.

Si en algún momento se contrata alguno, el registro de feeds ya está preparado:
sumar el proveedor es un `FeedSpec` más un adapter, con la API key por variable
de entorno (nunca hardcodeada, nunca commiteada).

## ⚠️ Advertencia sobre VECERT

Antes de considerar a este proveedor conviene revisar el análisis público
publicado en
[github.com/Ringmast4r/vecert-exposed](https://github.com/Ringmast4r/vecert-exposed/blob/master/VECERT-Analysis.md).
Son **alegaciones de un investigador independiente**, no hechos verificados por
nosotros, pero son de una gravedad que amerita diligencia previa. Entre ellas:

- que la empresa es un unipersonal registrado en Florida en octubre de 2025, sin
  reportes anuales presentados;
- credenciales hardcodeadas en repositorios públicos (tokens de sesión);
- que su API de análisis estaría **abierta, sin API key**;
- que sus repositorios públicos redistribuirían ~633.000 registros provenientes
  de mercados de dark web, incluyendo logs de infostealers.

Si algo de eso es cierto, integrarlo sería incompatible con las reglas de este
proyecto: mandaríamos consultas a un tercero cuya postura de seguridad está
cuestionada, y consumiríamos datos de origen dudoso. Recomendación: **no
avanzar sin verificación independiente.**

## Fuentes

- SOCRadar Free Edition — <https://socradar.io/resources/introducing-socradar-free-edition/>
- SOCRadar prueba gratuita — <https://socradar.io/use-for-free/>
- Flare prueba verificada — <https://flare.io/verified-free-trial>
- Breachsense precios — <https://www.breachsense.com/pricing/>
- SpyCloud precios — <https://spycloud.com/pricing/>
- Group-IB (reseñas y precios) — <https://www.peerspot.com/products/group-ib-threat-intelligence-reviews>
- Cybersixgill (reseñas y precios) — <https://www.peerspot.com/products/cybersixgill-reviews>
- Axur API e integraciones — <https://www.axur.com/en-us/api-integrations/>
- VECERT plan de API — <https://analyzer.vecert.io/api_plan>
