# Política de seguridad

## Versiones con soporte

MangoRed se distribuye desde `main`. Solo la última versión recibe
correcciones de seguridad.

| Versión | Soporte |
| :--- | :--- |
| `main` (última) | ✅ |
| Cualquier versión anterior | ❌ |

## Cómo reportar una vulnerabilidad

**No abras un issue público** con detalles de una vulnerabilidad: cualquiera
podría aprovecharla antes de que exista un arreglo.

Usa la pestaña **[Security → Report a vulnerability](https://github.com/0kmango/MangoRed/security/advisories/new)**
del repositorio (GitHub Security Advisories). Es privado y llega solo al
mantenedor.

Si prefieres el correo, escribe a la dirección pública del perfil
(<https://github.com/0kmango>) indicando en el asunto `[MangoRed][seguridad]`.

### Qué incluir

- Versión o commit afectado y sistema operativo.
- Pasos mínimos para reproducirlo (comandos, peticiones HTTP, configuración).
- Impacto que crees que tiene (por ejemplo: *bypass del token de la API local*,
  *lectura de credenciales del router*, *SSRF*, *inyección en la base SQLite*).
- Si lo deseas, una propuesta de arreglo.

### Qué esperar

- Confirmación de recepción en un plazo de **7 días**.
- Evaluación y, si se acepta, un parche y un aviso en la sección *Security*
  del repositorio dando crédito a quien reportó (salvo que prefiera el anonimato).
- Este proyecto lo mantiene una persona en su tiempo libre: no hay SLA de
  empresa, pero **ningún reporte se ignora**.

## Alcance

Están en alcance, entre otras cosas:

- El **endpoint local** (`http://127.0.0.1:5000`): autenticación por token,
  comprobación de `Host`/`Origin`, cabeceras y *rate limit*.
- El **almacenamiento de credenciales** del router (permisos de archivo y
  cifrado).
- El **controlador SSH** y la integración con la API del router.
- La **base de datos SQLite** (consultas, migraciones, inyección).
- Los **analizadores** de `ip neigh` / `arp` / `ipconfig` / `route print`.

Fuera de alcance:

- Vulnerabilidades de terceros (Flask, Paramiko, psutil…): repórtalas a su
  proyecto.
- Problemas que requieran acceso físico al equipo o privilegios de
  administrador ya concedidos.
- **Pruebas contra redes que no son tuyas.** MangoRed es una herramienta
  defensiva: escanear redes ajenas es ilegal y no es un fallo del software.

## Uso responsable

MangoRed está pensada **exclusivamente** para redes de tu propiedad o en las
que tengas autorización explícita de administración. Consulta la sección
«Uso responsable: salvaguardas incorporadas» del `README.md`.