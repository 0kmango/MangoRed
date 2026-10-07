"""
Pruebas para el módulo de resolución de fabricantes (OUI) y detección de MAC aleatoria.
"""

from oui_lookup import lookup_vendor


def test_known_oui_lookup():
    """Verifica la resolución correcta de fabricantes conocidos y el flag de estimación."""
    res = lookup_vendor("F8:9A:25:B8:55:14")
    assert res["vendor"] == "Huawei Technologies"
    assert res["is_confirmed"] is False, "El fabricante debe estar catalogado como dato estimado."

    res_tplink = lookup_vendor("B0:2E:BA:BA:DF:F8")
    assert "TP-Link" in res_tplink["vendor"]
    assert res_tplink["is_confirmed"] is False


def test_randomized_mac_detection():
    """Verifica que las MAC privadas/aleatorias (bit 1 activo en el 2º hex) sean detectadas."""
    # DA:17:25... -> segundo dígito es 'A' (1010 en binario, bit 1 activo)
    res_rand = lookup_vendor("da:17:25:b6:a6:42")
    assert "MAC Aleatoria" in res_rand["vendor"] or "Privado" in res_rand["vendor"]
    assert res_rand["is_confirmed"] is False
