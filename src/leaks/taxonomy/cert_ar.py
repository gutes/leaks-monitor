"""Taxonomía de incidentes de ciberseguridad del CERT.ar.

Transcripción de la *Guía de Notificación y Gestión de Incidentes de
Ciberseguridad* (IF-2023-69993929-APN-SSTI#JGM), sección 4 y tabla 5.1.1.

**Es dato, no criterio nuestro.** La clasificación, el tipo, la descripción y el
nivel de criticidad salen del documento tal cual; acá no se interpretan ni se
ajustan. Si mañana el CERT publica otra versión, se reemplaza esta tabla y nada
más se toca — los consumidores leen el catálogo, no constantes sueltas.

**El nivel del CERT no es nuestra severidad.** Son dos ejes distintos y por eso
conviven:

* `Severity` (nuestra) mide **relevancia argentina corroborada**: qué tan seguro
  es que esto afecte a una entidad argentina y cuánto importa esa entidad.
* `CriticidadCert` mide **tipo de incidente** según la guía, sin mirar quién es
  la víctima.

Un ransomware contra una PyME sin dominio `.ar` es `Alto` para el CERT y `low`
para nosotros. Pisar un eje con el otro perdería información que después hace
falta para reportar.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CriticidadCert(StrEnum):
    """Niveles de criticidad de la guía (tabla 5.1.1)."""

    BAJO = "bajo"
    MEDIO = "medio"
    ALTO = "alto"
    CRITICO = "critico"


#: Orden de los niveles, para comparar y ordenar.
CRITICIDAD_RANK: dict[str, int] = {
    CriticidadCert.BAJO: 1,
    CriticidadCert.MEDIO: 2,
    CriticidadCert.ALTO: 3,
    CriticidadCert.CRITICO: 4,
}


@dataclass(frozen=True)
class TipoIncidente:
    """Una fila de la taxonomía: clasificación, tipo, descripción y nivel."""

    #: Clave estable, la que se persiste. No cambia aunque cambie la redacción.
    slug: str
    clasificacion: str
    tipo: str
    criticidad: CriticidadCert
    descripcion: str


#: La taxonomía completa, en el orden del documento.
TAXONOMIA: tuple[TipoIncidente, ...] = (
    # --- Contenido Abusivo -------------------------------------------------
    TipoIncidente(
        slug="spam",
        clasificacion="Contenido Abusivo",
        tipo="SPAM",
        criticidad=CriticidadCert.BAJO,
        descripcion="Correo electrónico masivo no solicitado.",
    ),
    TipoIncidente(
        slug="manifestacion_de_odio",
        clasificacion="Contenido Abusivo",
        tipo="Manifestación de odio",
        criticidad=CriticidadCert.MEDIO,
        descripcion=(
            "Contenido discriminatorio, acoso, amenazas, incitación a la violencia o similar."
        ),
    ),
    TipoIncidente(
        slug="abuso_sexual_infantil",
        clasificacion="Contenido Abusivo",
        tipo="Abuso sexual infantil, contenido sexual",
        criticidad=CriticidadCert.ALTO,
        descripcion=(
            "Material que represente contenido relacionado con el abuso sexual infantil, etc."
        ),
    ),
    # --- Contenido Dañino --------------------------------------------------
    TipoIncidente(
        slug="malware",
        clasificacion="Contenido Dañino",
        tipo="Malware",
        criticidad=CriticidadCert.ALTO,
        descripcion=(
            "Código malicioso que puede ser distribuido con fines ilegítimos y se instala sin "
            "autorización o conocimiento del usuario en equipos que resultan infectados."
        ),
    ),
    TipoIncidente(
        slug="ransomware",
        clasificacion="Contenido Dañino",
        tipo="Ransomware",
        criticidad=CriticidadCert.ALTO,
        descripcion=(
            "Tipo de software malicioso que bloquea el acceso a los datos de la víctima. Quien lo "
            "usa puede inclusive publicar y/o difundir la información bloqueada si no se paga el "
            "rescate pedido para liberar la información."
        ),
    ),
    TipoIncidente(
        slug="botnet",
        clasificacion="Contenido Dañino",
        tipo="Botnet",
        criticidad=CriticidadCert.MEDIO,
        descripcion=(
            "Conjunto de hosts conectados a Internet que interactúan con el fin de cumplir una "
            "tarea distribuida, que generalmente es maliciosa."
        ),
    ),
    TipoIncidente(
        slug="command_and_control",
        clasificacion="Contenido Dañino",
        tipo="Command & Control",
        criticidad=CriticidadCert.ALTO,
        descripcion=(
            "También llamados C&C o C2, son servidores operados por el/los atacante/s para "
            "controlar una botnet."
        ),
    ),
    # --- Obtención de información ------------------------------------------
    TipoIncidente(
        slug="escaneo_de_redes",
        clasificacion="Obtención de información",
        tipo="Escaneo de redes / análisis de tráfico",
        criticidad=CriticidadCert.BAJO,
        descripcion=(
            "Envío de peticiones a un sistema para descubrir vulnerabilidades, obtención del "
            "tráfico de red o similar."
        ),
    ),
    TipoIncidente(
        slug="ingenieria_social",
        clasificacion="Obtención de información",
        tipo="Ingeniería social",
        criticidad=CriticidadCert.MEDIO,
        descripcion=(
            "Recopilación de información, con el uso o no de la tecnología, en la que el atacante "
            "utiliza técnicas de manipulación psicológica o engaños para lograr que la víctima le "
            "entregue voluntariamente su información."
        ),
    ),
    # --- Intrusión ---------------------------------------------------------
    TipoIncidente(
        slug="explotacion_de_vulnerabilidades",
        clasificacion="Intrusión",
        tipo="Explotación de vulnerabilidades",
        criticidad=CriticidadCert.ALTO,
        descripcion=(
            "Intento o compromiso de un sistema a través de fallas o ausencia de controles o "
            "medidas de seguridad apropiadas."
        ),
    ),
    TipoIncidente(
        slug="fuerza_bruta",
        clasificacion="Intrusión",
        tipo="Ataque de fuerza bruta",
        criticidad=CriticidadCert.ALTO,
        descripcion="Múltiples intentos de vulnerar credenciales.",
    ),
    TipoIncidente(
        slug="ataque_desconocido",
        clasificacion="Intrusión",
        tipo="Ataque desconocido",
        criticidad=CriticidadCert.ALTO,
        descripcion="Son aquellos ataques cuya naturaleza no se conoce.",
    ),
    TipoIncidente(
        slug="compromiso_de_sistema",
        clasificacion="Intrusión",
        tipo="Compromiso de equipo/sistema",
        criticidad=CriticidadCert.ALTO,
        descripcion=(
            "Afectación de la confidencialidad, integridad o disponibilidad de un "
            "sistema/aplicación mediante técnicas tales como SQLi, keyloggers, web shell, etc."
        ),
    ),
    TipoIncidente(
        slug="robo",
        clasificacion="Intrusión",
        tipo="Robo",
        criticidad=CriticidadCert.ALTO,
        descripcion=(
            "Intrusión física que concluye con el robo de activos, como pueden ser equipos o "
            "información."
        ),
    ),
    TipoIncidente(
        slug="compromiso_de_cuenta",
        clasificacion="Intrusión",
        tipo="Compromiso de cuenta",
        criticidad=CriticidadCert.MEDIO,
        descripcion="Compromiso de un sistema empleando una cuenta con o sin privilegios.",
    ),
    # --- Disponibilidad ----------------------------------------------------
    TipoIncidente(
        slug="denegacion_de_servicio",
        clasificacion="Disponibilidad",
        tipo="Denegación de servicio (DoS/DDoS)",
        criticidad=CriticidadCert.ALTO,
        descripcion=(
            "Ciberataque que tiene como objetivo que uno o varios ordenadores, servicios u otros "
            "dispositivos no estén disponibles para los usuarios a los que va dirigido, "
            "interrumpiendo su funcionamiento normal."
        ),
    ),
    TipoIncidente(
        slug="configuracion_erronea",
        clasificacion="Disponibilidad",
        tipo="Configuración errónea",
        criticidad=CriticidadCert.MEDIO,
        descripcion=(
            "Configuración débil o errónea de un sistema que permita afectar su disponibilidad."
        ),
    ),
    TipoIncidente(
        slug="sabotaje",
        clasificacion="Disponibilidad",
        tipo="Sabotaje",
        criticidad=CriticidadCert.ALTO,
        descripcion=(
            "Sabotaje físico que puede afectar la disponibilidad de los servicios o de la "
            "información. Ej: cortes de cableados de equipos o incendios provocados."
        ),
    ),
    TipoIncidente(
        slug="interrupciones",
        clasificacion="Disponibilidad",
        tipo="Interrupciones",
        criticidad=CriticidadCert.ALTO,
        descripcion=(
            "Afectaciones a la disponibilidad por causas ajenas como desastre natural, condiciones "
            "climáticas desfavorables, etc."
        ),
    ),
    # --- Compromiso de la información --------------------------------------
    TipoIncidente(
        slug="acceso_no_autorizado",
        clasificacion="Compromiso de la información",
        tipo="Acceso no autorizado a la información",
        criticidad=CriticidadCert.ALTO,
        descripcion="Acceso sin permiso a los activos, como documentos, sistemas, servicios, etc.",
    ),
    TipoIncidente(
        slug="modificacion_no_autorizada",
        clasificacion="Compromiso de la información",
        tipo="Modificación no autorizada de la información",
        criticidad=CriticidadCert.ALTO,
        descripcion=(
            "Alteración no autorizada de la información (creación, modificación o borrado). Esto "
            "puede ser causado por ataques de ransomware, queries SQL, etc."
        ),
    ),
    TipoIncidente(
        slug="perdida_de_datos",
        clasificacion="Compromiso de la información",
        tipo="Pérdida de datos",
        criticidad=CriticidadCert.ALTO,
        descripcion="Pérdida de información sucedida por fallo de hardware.",
    ),
    # --- Indicio de fraude -------------------------------------------------
    TipoIncidente(
        slug="uso_no_autorizado_de_recursos",
        clasificacion="Indicio de fraude",
        tipo="Uso no autorizado de los recursos",
        criticidad=CriticidadCert.MEDIO,
        descripcion="Utilización de los recursos para propósitos inadecuados.",
    ),
    TipoIncidente(
        slug="derechos_de_autor",
        clasificacion="Indicio de fraude",
        tipo="Derechos de autor",
        criticidad=CriticidadCert.MEDIO,
        descripcion=(
            "Ofrecimiento o instalación de software, y utilización o difusión de manera ilegítima "
            "de material protegido por derechos de autor."
        ),
    ),
    TipoIncidente(
        slug="suplantacion",
        clasificacion="Indicio de fraude",
        tipo="Suplantación",
        criticidad=CriticidadCert.MEDIO,
        descripcion=(
            "Ataque mediante el cual una entidad se hace pasar por otra para obtener "
            "beneficios ilegítimos."
        ),
    ),
    TipoIncidente(
        slug="phishing",
        clasificacion="Indicio de fraude",
        tipo="Phishing",
        criticidad=CriticidadCert.ALTO,
        descripcion="Suplantación de identidad para la sustracción de datos.",
    ),
    # --- Activo vulnerable -------------------------------------------------
    TipoIncidente(
        slug="sistema_vulnerable",
        clasificacion="Activo vulnerable",
        tipo="Sistema vulnerable",
        criticidad=CriticidadCert.MEDIO,
        descripcion=(
            "Sistema con servicios vulnerables, ya sea por errores de diseño o por no poseer "
            "medidas de seguridad o controles apropiados."
        ),
    ),
    TipoIncidente(
        slug="servicios_vulnerables_expuestos",
        clasificacion="Activo vulnerable",
        tipo="Publicación de servicios vulnerables",
        criticidad=CriticidadCert.MEDIO,
        descripcion=(
            "Servicios activos expuestos en Internet que pueden ser utilizados para el acceso no "
            "autorizado en los sistemas. Ej: RDP, Telnet, etc."
        ),
    ),
    TipoIncidente(
        slug="revelacion_de_informacion",
        clasificacion="Activo vulnerable",
        tipo="Revelación de información",
        criticidad=CriticidadCert.MEDIO,
        descripcion="Servicios que permiten la obtención de información sensible.",
    ),
    # --- Otros -------------------------------------------------------------
    TipoIncidente(
        slug="apt",
        clasificacion="Otros",
        tipo="Amenaza persistente avanzada (APT)",
        criticidad=CriticidadCert.CRITICO,
        descripcion="Ataques dirigidos a organizaciones.",
    ),
    TipoIncidente(
        slug="sectores_no_criticos",
        clasificacion="Otros",
        tipo="Sectores no críticos",
        criticidad=CriticidadCert.BAJO,
        descripcion=(
            "Aquellos incidentes que no puedan ser clasificados dentro de los actuales parámetros."
        ),
    ),
)

#: Índice por slug, que es lo que se persiste.
POR_SLUG: dict[str, TipoIncidente] = {t.slug: t for t in TAXONOMIA}


def get_tipo(slug: str | None) -> TipoIncidente | None:
    """Busca un tipo por su clave estable."""
    return POR_SLUG.get(slug) if slug else None
