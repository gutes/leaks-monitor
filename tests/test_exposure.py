"""Tests del detalle de exposición por infostealers.

Lo que se protege: que se guarde lo accionable (qué sistema, de quién, qué
malware) y **nada de PII**. Las credenciales no vienen en el tier gratuito del
proveedor, pero eso no puede quedar librado a la buena fe del feed.
"""

from __future__ import annotations

from leaks.extraction.exposure import MAX_URLS, build_exposure

PAYLOAD = {
    "total": 225375,
    "employees": 2,
    "users": 225350,
    "data": {
        "employees_urls": [
            {"occurrence": 1, "type": "Employee", "url": "https://ftp.prevision-ejemplo.gob.ar"},
        ],
        "clients_urls": [
            {"occurrence": 515965, "type": "User", "url": "https://x.gob.ar/logon.aspx"},
            {"occurrence": 26, "type": "User", "url": "https://x.gob.ar/acceso.aspx"},
        ],
    },
    "stealerFamilies": {"total": 50000, "RedLine": 23590, "Lumma": 7950, "Vacia": 0},
    "userPasswords": {
        "too_weak": {"qty": 94, "perc": 0.94},
        "weak": {"qty": 9869, "perc": 98.69},
        "strong": {"qty": 28, "perc": 0.28},
    },
    "thirdPartyDomains": [{"occurrence": 28, "domain": "unsoloclic.info"}],
}


class TestExtraccion:
    def test_las_de_empleados_van_primero(self) -> None:
        """Es la señal fuerte: implica acceso interno, no un ciudadano."""
        exp = build_exposure(PAYLOAD)
        assert exp is not None
        assert exp.urls[0].kind == "employee"
        assert "ftp" in exp.urls[0].url

    def test_dentro_de_cada_grupo_ordena_por_capturas(self) -> None:
        exp = build_exposure(PAYLOAD)
        assert exp is not None
        usuarios = [u for u in exp.urls if u.kind == "user"]
        assert usuarios[0].occurrences > usuarios[1].occurrences

    def test_expone_las_urls_de_empleados_aparte(self) -> None:
        exp = build_exposure(PAYLOAD)
        assert exp is not None
        assert len(exp.employee_urls) == 1

    def test_familias_ordenadas_y_sin_el_total(self) -> None:
        """`total` es la suma, no una familia de malware."""
        exp = build_exposure(PAYLOAD)
        assert exp is not None
        assert "total" not in exp.stealer_families
        assert "Vacia" not in exp.stealer_families, "las de cero no aportan"
        assert next(iter(exp.stealer_families)) == "RedLine"

    def test_suma_las_contraseñas_debiles(self) -> None:
        exp = build_exposure(PAYLOAD)
        assert exp is not None
        assert exp.weak_password_pct == 99.63

    def test_dominios_de_terceros(self) -> None:
        exp = build_exposure(PAYLOAD)
        assert exp is not None
        assert exp.third_party_domains == ("unsoloclic.info",)


class TestTolerancia:
    def test_payload_vacio_no_genera_estructura(self) -> None:
        """No se llena la base de objetos vacíos."""
        assert build_exposure({}) is None
        assert build_exposure({"data": {}}) is None

    def test_tolera_urls_como_strings_pelados(self) -> None:
        """El proveedor manda dos formas según el campo."""
        exp = build_exposure({"data": {"employees_urls": ["https://a.gob.ar"]}})
        assert exp is not None
        assert exp.urls[0].url == "https://a.gob.ar"

    def test_descarta_lo_que_no_es_una_url(self) -> None:
        exp = build_exposure({"data": {"clients_urls": ["no-es-url", {"url": 42}, {"sin": "url"}]}})
        assert exp is None

    def test_tiene_tope(self) -> None:
        muchas = [{"url": f"https://x{i}.gob.ar", "occurrence": i} for i in range(40)]
        exp = build_exposure({"data": {"clients_urls": muchas}})
        assert exp is not None
        assert len(exp.urls) == MAX_URLS


class TestPrivacidad:
    def test_una_url_con_pii_se_redacta(self) -> None:
        """Una query string puede arrastrar un identificador."""
        exp = build_exposure(
            {"data": {"clients_urls": [{"url": "https://x.gob.ar/l?u=juan@x.gob.ar"}]}}
        )
        assert exp is not None
        assert "juan@x.gob.ar" not in exp.urls[0].url
        assert "[redactado]" in exp.urls[0].url

    def test_no_se_copia_nada_que_parezca_credencial(self) -> None:
        """Solo se leen campos conocidos: lo demás del payload no entra."""
        exp = build_exposure({**PAYLOAD, "employeePasswords_plain": ["hunter2"]})
        assert exp is not None
        assert "hunter2" not in str(exp.as_dict())
