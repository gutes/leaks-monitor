"""Exportación de hallazgos al formato de datos de IntelMQ.

## Por qué

IntelMQ es el pipeline de procesamiento de incidentes de la comunidad de CSIRT.
Emitir en su formato significa que un CERT puede consumir esto con su
herramienta, sin escribir un parser a medida.

## Por qué sale casi gratis

Las dos taxonomías vienen del mismo lugar. La guía del CERT.ar deriva de
**eCSIRT.net / RSIT** (Reference Security Incident Taxonomy), que es exactamente
la que usa `classification.taxonomy` en IntelMQ. Las 9 clasificaciones del CERT
tienen su equivalente exacto, así que lo que hay que escribir es el mapeo de los
31 **tipos**, no una traducción conceptual.

## La regla que gobierna el mapeo: pares canónicos

IntelMQ trata `classification.taxonomy` y `classification.type` como dos campos
independientes, pero algunos de sus bots **derivan la taxonomía a partir del
tipo**. Emitir un par que RSIT no aparea así es pedir que un bot de la cadena lo
reescriba sin avisar.

Por eso acá se emite **siempre el par canónico de RSIT**, aunque eso mueva el
evento a otra taxonomía que la del CERT. Nada se pierde: el slug del CERT viaja
en `extra.taxonomy_cert`. Tres casos se corren a propósito:

* `ransomware` → `information-content-security` / `data-leak`. IntelMQ **no tiene
  un tipo `ransomware`**. Lo que observamos no es una infección que detectamos
  sino la **publicación de datos robados** en un sitio de extorsión, y el grupo
  queda en `classification.identifier`. Decisión del líder técnico (2026-09-30).
* `explotacion_de_vulnerabilidades` y `fuerza_bruta` → `intrusion-attempts`, que
  es donde RSIT pone `exploit` y `brute-force`; el CERT los agrupa en Intrusión.
* `ataque_desconocido` y `sectores_no_criticos` → `other` / `undetermined`.

## Qué NO se emite

`raw` se define como base64 de la línea original, y nuestra línea original es un
volcado con PII. No se emite: ni cifrada ni recortada. Lo que viaja es el mismo
metadata que ya se persiste, ni un campo más.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Alertable(Protocol):
    """Lo que hace falta para armar un evento de IntelMQ.

    Se declara como protocolo de **propiedades de solo lectura** y no se importa
    el modelo de la API, por dos razones:

    * `time.observation` es "cuándo lo observó esta instancia", o sea
      `first_seen_at`, que es una columna de la base y **no existe** en el
      `Finding` del dominio. El que puede contestarlo es la proyección del feed
      de alertas.
    * Este módulo está del lado del dominio; importar `api.schemas` invertiría
      la dirección de la dependencia. El protocolo lo satisface cualquiera que
      tenga estos campos, y `AlertItemOut` lo cumple estructuralmente.
    """

    @property
    def dedup_hash(self) -> str: ...
    @property
    def source(self) -> str: ...
    @property
    def leak_type(self) -> Any: ...
    @property
    def victim_name(self) -> str: ...
    @property
    def victim_domain(self) -> str | None: ...
    @property
    def sector(self) -> str | None: ...
    @property
    def actor(self) -> str | None: ...
    @property
    def severity(self) -> Any: ...
    @property
    def ar_match_reason(self) -> Sequence[Any]: ...
    @property
    def occurred_at(self) -> datetime | None: ...
    @property
    def occurred_at_basis(self) -> Any: ...
    @property
    def first_seen_at(self) -> datetime: ...
    @property
    def backfill(self) -> bool: ...
    @property
    def raw_ref(self) -> str | None: ...
    @property
    def taxonomy_type(self) -> str | None: ...


#: Formato de fecha que exige IntelMQ. UTC es la única zona que acepta.
FORMATO_FECHA = "%Y-%m-%dT%H:%M:%S+00:00"

#: Nombre por defecto del feed, en `feed.name`.
FEED_NAME = "leaks-monitor"

#: Todo hallazgo de este pipeline es argentino por definición: es lo que la capa
#: de relevancia decide. Para un CSIRT es un campo útil y no una suposición.
PAIS = "AR"

#: Las 11 taxonomías de RSIT que acepta IntelMQ. Está acá para que los tests
#: puedan verificar que el mapeo no se sale del vocabulario.
RSIT_TAXONOMIAS: frozenset[str] = frozenset(
    {
        "abusive-content",
        "availability",
        "fraud",
        "information-content-security",
        "information-gathering",
        "intrusion-attempts",
        "intrusions",
        "malicious-code",
        "other",
        "test",
        "vulnerable",
    }
)

#: Los tipos que acepta IntelMQ. Nótese que **no hay `ransomware`**: ver el
#: encabezado del módulo.
RSIT_TIPOS: frozenset[str] = frozenset(
    {
        "application-compromise",
        "blacklist",
        "brute-force",
        "burglary",
        "c2-server",
        "copyright",
        "data-leak",
        "data-loss",
        "ddos",
        "ddos-amplifier",
        "dga-domain",
        "dos",
        "exploit",
        "harmful-speech",
        "ids-alert",
        "infected-system",
        "information-disclosure",
        "malware",
        "malware-configuration",
        "malware-distribution",
        "masquerade",
        "misconfiguration",
        "other",
        "outage",
        "phishing",
        "potentially-unwanted-accessible",
        "privileged-account-compromise",
        "proxy",
        "sabotage",
        "scanner",
        "sniffing",
        "social-engineering",
        "spam",
        "system-compromise",
        "test",
        "tor",
        "unauthorised-information-access",
        "unauthorised-information-modification",
        "unauthorized-use-of-resources",
        "undetermined",
        "unprivileged-account-compromise",
        "violence",
        "vulnerable-system",
        "weak-crypto",
    }
)


@dataclass(frozen=True)
class Rsit:
    """Un par canónico de RSIT."""

    taxonomy: str
    type: str


#: Par por defecto cuando el hallazgo no tiene taxonomía asignada todavía.
#: `undetermined` dice "no se pudo determinar", que es la verdad; inventar un
#: tipo concreto sería peor que no decir nada.
SIN_CLASIFICAR = Rsit("other", "undetermined")

#: Los 31 tipos del CERT.ar a su par canónico de RSIT. Catálogo declarativo:
#: sumar un tipo a `taxonomy/cert_ar.py` es sumar una entrada acá, y hay un test
#: que falla si alguno queda sin mapeo.
CERT_A_RSIT: dict[str, Rsit] = {
    # -- Activo vulnerable ---------------------------------------------------
    "revelacion_de_informacion": Rsit("vulnerable", "information-disclosure"),
    "servicios_vulnerables_expuestos": Rsit("vulnerable", "potentially-unwanted-accessible"),
    "sistema_vulnerable": Rsit("vulnerable", "vulnerable-system"),
    # -- Compromiso de la información ---------------------------------------
    "acceso_no_autorizado": Rsit("information-content-security", "unauthorised-information-access"),
    "modificacion_no_autorizada": Rsit(
        "information-content-security", "unauthorised-information-modification"
    ),
    "perdida_de_datos": Rsit("information-content-security", "data-loss"),
    # -- Contenido Abusivo ---------------------------------------------------
    # RSIT mete bajo `violence` el contenido sexual infantil, sexual y violento.
    "abuso_sexual_infantil": Rsit("abusive-content", "violence"),
    "manifestacion_de_odio": Rsit("abusive-content", "harmful-speech"),
    "spam": Rsit("abusive-content", "spam"),
    # -- Contenido Dañino ----------------------------------------------------
    # Participar de una botnet es, del lado de la víctima, un equipo infectado.
    "botnet": Rsit("malicious-code", "infected-system"),
    "command_and_control": Rsit("malicious-code", "c2-server"),
    "malware": Rsit("malicious-code", "malware"),
    # El caso que cruza de clasificación. Ver el encabezado del módulo.
    "ransomware": Rsit("information-content-security", "data-leak"),
    # -- Disponibilidad ------------------------------------------------------
    "configuracion_erronea": Rsit("availability", "misconfiguration"),
    # El CERT agrupa "DoS/DDoS" en un tipo y RSIT los separa. Se elige `ddos`
    # porque es la forma en que llegan estos reportes; si alguna vez importa
    # distinguirlos, hay que partir el tipo del lado del CERT, no adivinar acá.
    "denegacion_de_servicio": Rsit("availability", "ddos"),
    "interrupciones": Rsit("availability", "outage"),
    "sabotaje": Rsit("availability", "sabotage"),
    # -- Indicio de fraude ---------------------------------------------------
    "derechos_de_autor": Rsit("fraud", "copyright"),
    "phishing": Rsit("fraud", "phishing"),
    "suplantacion": Rsit("fraud", "masquerade"),
    "uso_no_autorizado_de_recursos": Rsit("fraud", "unauthorized-use-of-resources"),
    # -- Intrusión -----------------------------------------------------------
    "ataque_desconocido": SIN_CLASIFICAR,
    # Sin saber si la cuenta era privilegiada, la conservadora es la no
    # privilegiada: afirma menos.
    "compromiso_de_cuenta": Rsit("intrusions", "unprivileged-account-compromise"),
    "compromiso_de_sistema": Rsit("intrusions", "system-compromise"),
    "explotacion_de_vulnerabilidades": Rsit("intrusion-attempts", "exploit"),
    "fuerza_bruta": Rsit("intrusion-attempts", "brute-force"),
    "robo": Rsit("intrusions", "burglary"),
    # -- Obtención de información -------------------------------------------
    "escaneo_de_redes": Rsit("information-gathering", "scanner"),
    "ingenieria_social": Rsit("information-gathering", "social-engineering"),
    # -- Otros ---------------------------------------------------------------
    # APT no es un tipo de RSIT. El dato no se pierde: va en el `extra`.
    "apt": Rsit("other", "other"),
    "sectores_no_criticos": SIN_CLASIFICAR,
}


def clasificar(slug: str | None) -> Rsit:
    """Par canónico de RSIT para un slug del CERT.ar.

    Un slug desconocido cae en `other`/`undetermined` en vez de fallar: un tipo
    nuevo sin mapear no puede cortar la exportación entera.
    """
    if not slug:
        return SIN_CLASIFICAR
    return CERT_A_RSIT.get(slug, SIN_CLASIFICAR)


def _fecha(momento: datetime | None) -> str | None:
    if momento is None:
        return None
    return momento.astimezone(UTC).strftime(FORMATO_FECHA)


def _es_fqdn(valor: str | None) -> bool:
    """¿Sirve como `source.fqdn`?

    IntelMQ valida el campo, y un nombre de víctima que no es un dominio lo
    haría rechazar el evento entero. El modelo ya normaliza `victim_domain`
    (sin esquema, sin puerto, sin `www.`), así que alcanza con exigir un punto y
    que no haya espacios.
    """
    if not valor:
        return False
    return "." in valor and " " not in valor and "/" not in valor


def to_intelmq(finding: Alertable, *, feed_name: str = FEED_NAME) -> dict[str, Any]:
    """Un hallazgo como evento de IntelMQ.

    Los campos ausentes **se omiten** en vez de ir en `null`: un `time.source`
    nulo haría fallar la validación del tipo, y además "no sabemos cuándo pasó"
    se dice no mandando el campo, que es lo que el formato espera.
    """
    rsit = clasificar(finding.taxonomy_type)

    evento: dict[str, Any] = {
        "feed.name": feed_name,
        # Cuándo lo vimos nosotros, que es lo que este campo significa.
        "time.observation": _fecha(finding.first_seen_at),
        "classification.taxonomy": rsit.taxonomy,
        "classification.type": rsit.type,
        # El país lo define la capa de relevancia: si está acá, es argentino.
        "source.geolocation.cc": PAIS,
        # El organismo afectado. IntelMQ lo define como "the target
        # (organization) of an attack", que es exactamente nuestra víctima.
        "event_description.target": finding.victim_name,
        # Metadata nuestra que RSIT no tiene campo para representar.
        "extra.severity": str(finding.severity),
        "extra.source": finding.source,
        "extra.dedup_hash": finding.dedup_hash,
        "extra.leak_type": str(finding.leak_type),
        "extra.backfill": finding.backfill,
        "extra.ar_match_reason": [str(r) for r in finding.ar_match_reason],
    }

    # Cuándo ocurrió según la fuente. Sin fecha creíble no se manda: la postura
    # del pipeline es no inventar fechas, y acá no cambia.
    ocurrido = _fecha(finding.occurred_at)
    if ocurrido is not None:
        evento["time.source"] = ocurrido
        evento["extra.occurred_at_basis"] = str(finding.occurred_at_basis)

    if _es_fqdn(finding.victim_domain):
        evento["source.fqdn"] = finding.victim_domain

    if finding.actor:
        # La especificación pide el identificador en minúsculas.
        evento["classification.identifier"] = finding.actor.strip().lower()

    if finding.raw_ref and finding.raw_ref.startswith(("http://", "https://")):
        evento["event_description.url"] = finding.raw_ref

    if finding.sector:
        evento["extra.sector"] = finding.sector

    if finding.taxonomy_type:
        # El slug del CERT no se pierde aunque el par de RSIT mueva el evento a
        # otra taxonomía. Ver el encabezado del módulo.
        evento["extra.taxonomy_cert"] = finding.taxonomy_type

    return evento


def to_ndjson(findings: Iterable[Alertable], *, feed_name: str = FEED_NAME) -> str:
    """Un evento por línea, que es como IntelMQ consume un lote.

    NDJSON y no un array: un consumidor puede procesar línea por línea sin
    cargar el lote entero, y una línea malformada no invalida las demás.
    """
    lineas: Sequence[str] = [
        json.dumps(to_intelmq(f, feed_name=feed_name), ensure_ascii=False, sort_keys=True)
        for f in findings
    ]
    return "\n".join(lineas) + ("\n" if lineas else "")
