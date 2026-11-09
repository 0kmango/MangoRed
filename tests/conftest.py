import os
import sys
import tempfile
from pathlib import Path

import pytest

# Agregar directorio raíz del proyecto a sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

# Redirigir el archivo de configuración ANTES de importar el módulo config,
# para que la suite nunca cree ni modifique el archivo real del usuario.
os.environ["MANGORED_CONFIG_FILE"] = str(
    Path(tempfile.mkdtemp(prefix="mangored-tests-")) / "mangored_config.json"
)


@pytest.fixture(autouse=True)
def isolated_config_file(tmp_path, monkeypatch):
    """
    Aísla el archivo de configuración en cada prueba.

    Sin este aislamiento, cualquier prueba que guarde ajustes escribiría en el
    ``mangored_config.json`` real del desarrollador (que contiene credenciales).
    """
    import config as config_module

    target = tmp_path / "mangored_config.json"
    monkeypatch.setattr(config_module, "CONFIG_FILE", target)
    yield target
