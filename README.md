# 🥭 MangoRed — Monitor Doméstico de Red Local para Kali Linux

**MangoRed** es una herramienta defensiva y de administración doméstica diseñada para supervisar redes locales en **Kali Linux**, destinada **exclusivamente a redes de tu propiedad o en las que cuentas con autorización explícita para administrar**.

Proporciona un panel interactivo moderno y ligero accesible vía navegador local (`http://127.0.0.1:5000`), con descubrimiento periódico no invasivo, inventario detallado de dispositivos, historial de conexiones, detección de dispositivos nuevos y gestión de bloqueo administrativo oficial mediante la API del router.

---

## 📑 Índice de Contenidos

1. [Principios de Seguridad y Ética](#principios-de-seguridad-y-ética)
2. [Características Principales](#características-principales)
3. [Distinción entre Datos Confirmados y Estimados](#distinción-entre-datos-confirmados-y-estimados)
4. [Arquitectura del Sistema](#arquitectura-del-sistema)
5. [Instalación y Requisitos en Kali Linux](#instalación-y-requisitos-en-kali-linux)
6. [Instrucciones de Uso](#instrucciones-de-uso)
7. [Integración con Routers y Bloqueo Autorizado](#integración-con-routers-y-bloqueo-autorizado)
8. [Configuración Manual en Routers sin API (Huawei, etc.)](#configuración-manual-en-routers-sin-api-huawei-etc)
9. [Límites Conocidos](#límites-conocidos)
10. [Ejecución de Pruebas Automatizadas](#ejecución-de-pruebas-automatizadas)

---

## 🛡️ Principios de Seguridad y Ética

MangoRed se rige por estrictas directrices de seguridad defensiva:

* **Modo Solo Lectura por Defecto (`READ_ONLY = True`):** Por seguridad, MangoRed inicia en modo de solo lectura. Cualquier acción que intente modificar reglas en el router es rechazada a nivel de API hasta que el usuario desmarque explícitamente la casilla en la pestaña de Ajustes.
* **Sin Técnicas de Ataque Ofensivo:** **No se emplean paquetes de desautenticación Wi-Fi (802.11 deauth frames), ni envenenamiento de caché ARP (ARP spoofing), ni puntos de acceso falsos.** Dichas técnicas son inestables, degradan el rendimiento de la radiofrecuencia, son bloqueadas por WPA3 / 802.11w (PMF) y no constituyen una solución de administración legítima.
* **Bloqueo Exclusivamente Oficial:** La restricción de acceso solo se aplica si se cuenta con una función oficial autorizada en el router (API REST, ubus, lista negra administrativa). Si el router no dispone de API, MangoRed ofrece una guía paso a paso para aplicar la regla en su interfaz web oficial.
* **Privacidad Absoluta:** No se captura el contenido del tráfico de los usuarios ni contraseñas. Únicamente se inspecciona la información de presencia en capa de enlace e IP.
* **Protección de Credenciales:** El archivo de configuración y credenciales (`mangored_config.json`) se almacena localmente con permisos de archivo restrictivos **`chmod 600`** (legible y escribible únicamente por el usuario propietario).

---

## ✨ Características Principales

* **Detección Automática de Dispositivos:** Identifica dinámicamente Dirección IP, Dirección MAC, Nombre de host (si está disponible), Fabricante (mediante base de datos OUI de Kali), Estado (En línea, Inactivo, Desconectado, Bloqueado) y marca de tiempo de última detección.
* **Panel Web Local Intuitivo:** Interfaz moderna, accesible y con tema oscuro diseñada para Kali Linux.
* **Actualización Periódica:** Escaneo automático en segundo plano a intervalos configurables (por defecto cada 30 segundos) y botón para forzar escaneo manual bajo demanda.
* **Búsqueda y Filtros en Tiempo Real:** Filtra por estado (*En línea, Nuevos, Desconectados, Bloqueados*), etiquetas personalizadas o búsqueda libre de texto (IP, MAC, nombre, notas).
* **Gestión de Identidad y Alias:** Asigna nombres personalizados (p. ej., *"Portátil Trabajo"*, *"Bombilla Salón"*), etiquetas y notas para cada dispositivo.
* **Avisos de Nuevos Dispositivos:** Panel de alertas visuales en la interfaz y notificaciones nativas de escritorio en Kali Linux (`notify-send`) cuando un dispositivo no reconocido se conecta por primera vez.
* **Historial de Conexiones y Auditoría:** Registro continuo de eventos de conexión, desconexión, cambios de dirección IP asignada y auditoría de bloqueos/desbloqueos.

---

## 🔍 Distinción entre Datos Confirmados y Estimados

MangoRed distingue claramente en su interfaz la certeza de cada dato mostrado para evitar conclusiones erróneas:

| Tipo de Dato | Clasificación | Justificación Técnica |
| :--- | :--- | :--- |
| **Dirección IP** | **`CONFIRMADO`** | Verificado mediante respuesta activa ICMP o enlace directo en la tabla de vecinos del kernel de Linux. |
| **Dirección MAC** | **`CONFIRMADO`** | Obtenido directamente de las tramas ARP en la capa de enlace de datos (capa 2) confirmadas en estado `REACHABLE`. |
| **Nombre de Host (Hostname)** | **`ESTIMADO`** | Obtenido mediante consulta de DNS inverso (PTR) o mDNS. Un dispositivo puede reportar un nombre arbitrario o no tener registro inverso configurado. |
| **Fabricante (Vendor)** | **`ESTIMADO`** | Inferencia basada en el registro IEEE OUI de los primeros 24 bits. Dispositivos modernos con iOS, Android o Windows pueden usar direcciones MAC privadas/aleatorias. |

---

## 🏗️ Arquitectura del Sistema

El proyecto está estructurado modularmente en la carpeta `MangoRed`:

```text
/home/mango/MangoRed/
├── app.py                      # Servidor Flask, API REST y control de acceso
├── config.py                   # Gestión segura de configuración y permisos 0600
├── scanner.py                  # Motor de descubrimiento pasivo/activo en subred
├── database.py                 # Base de datos SQLite (dispositivos, auditoría, historial)
├── oui_lookup.py               # Resolución de fabricantes con base de datos de Kali y MAC aleatoria
├── router/                     # Capa de controladores para routers autorizados
│   ├── __init__.py             # Factoría de controladores
│   ├── base.py                 # Interfaz abstracta BaseRouterDriver
│   ├── simulator.py            # Controlador simulado para pruebas seguras
│   ├── openwrt.py              # Controlador oficial OpenWrt (ubus / LuCI)
│   ├── mikrotik.py             # Controlador oficial MikroTik (RouterOS v7 REST)
│   ├── generic_webhook.py      # Controlador de Webhook HTTPS con token Bearer
│   └── guide.py                # Guía integrada para routers comerciales (Huawei, TP-Link, etc.)
├── static/
│   ├── css/style.css           # Estilos CSS tema oscuro para Kali
│   └── js/app.js               # Cliente reactivo, modales de confirmación y eventos
├── templates/
│   └── index.html              # Plantilla HTML5 del panel de supervisión
├── tests/                      # Suite de pruebas automatizadas con pytest
│   ├── conftest.py
│   ├── test_config.py
│   ├── test_database.py
│   ├── test_oui.py
│   ├── test_router.py
│   └── test_api.py
├── requirements.txt            # Dependencias Python
├── mangored.sh                 # Lanzador bash optimizado para Kali
└── README.md                   # Esta documentación
```

---

## 🚀 Instalación y Requisitos en Kali Linux

### Requisitos del Sistema

* **Sistema Operativo:** Kali Linux (o cualquier distribución Debian/Ubuntu compatible).
* **Python:** Versión 3.10 o superior (verificado en Python 3.14).
* **Paquetes opcionales recomendados:**
  ```bash
  sudo apt update
  sudo apt install -y python3-pip libnotify-bin iproute2
  ```

### Instalación de Dependencias

Desde el directorio `MangoRed`:

```bash
cd /home/mango/MangoRed
pip install -r requirements.txt --break-system-packages
```

*(Nota: En versiones recientes de Kali / Debian con PEP 668, los paquetes `flask`, `requests`, `scapy` y `pytest` suelen estar preinstalados o pueden instalarse mediante `apt install python3-flask python3-requests python3-scapy python3-pytest`).*

---

## 💻 Instrucciones de Uso

### 1. Iniciar MangoRed

Puedes iniciar la herramienta mediante el script lanzador:

```bash
cd /home/mango/MangoRed
./mangored.sh
```

O directamente con Python:

```bash
python3 app.py
```

### 2. Acceder al Panel

Abre tu navegador web en Kali Linux y dirígete a:

👉 **`http://127.0.0.1:5000`**

### 3. Operaciones Comunes

1. **Escanear:** Pulsa el botón **"Escanear Ahora"** en el encabezado para actualizar el inventario inmediatamente.
2. **Identificar:** Haz clic en **"✏️ Editar"** en cualquier dispositivo para asignarle un alias (ej. *"Móvil Personal"*), etiquetas y notas.
3. **Reconocer Dispositivos Nuevos:** Si aparece un aviso de dispositivo nuevo, pulsa **"Marcar Todos como Conocidos"** o edita el equipo para aceptar su presencia.
4. **Ver Historial:** Pulsa en **"🕒 Historial"** en la barra superior o en un dispositivo particular para auditar los cambios de IP y momentos de conexión.

---

## 🔌 Integración con Routers y Bloqueo Autorizado

MangoRed incluye una arquitectura modular de controladores de router:

1. **Simulador de Laboratorio (`simulator`):** Controlador activo por defecto. Permite probar el flujo completo de doble confirmación, bloqueo y registro de auditoría de forma 100% segura sin enviar tráfico destructivo a la red física.
2. **OpenWrt (`openwrt`):** Envía llamadas autenticadas a la API `ubus` de OpenWrt para crear una regla oficial de cortafuegos de descarte (`target: DROP`) sobre la MAC.
3. **MikroTik (`mikrotik`):** Conecta a la API REST de RouterOS v7 para insertar una regla en `/ip/firewall/filter` con acción `drop` sobre la dirección MAC de origen.
4. **Webhook Genérico (`generic_webhook`):** Envía solicitudes HTTPS autenticadas mediante token Bearer a una pasarela local personalizada (ej. Home Assistant o script de control).

### Flujo de Seguridad al Bloquear:

1. **Modo Solo Lectura:** Si está activo (por defecto), la acción se bloquea inmediatamente y se notifica al usuario.
2. **Doble Confirmación:** Se despliega un diálogo modal que muestra exactamente:
   * Nombre del dispositivo
   * Dirección IP
   * Dirección MAC
   * Fabricante
   * Controlador de router activo
3. **Casilla de Aprobación:** El usuario debe marcar obligatoriamente la casilla de confirmación de autorización administrativa antes de ejecutar el bloqueo.

---

## 📖 Configuración Manual en Routers sin API (Huawei, etc.)

Si tu router residencial (por ejemplo, el router/ONT de operadora **Huawei EchoLife / OptiXstar** presente en la red) no dispone de una API abierta para terceros, aplica el bloqueo oficial mediante su interfaz web:

1. Abre tu navegador y accede a la puerta de enlace predeterminada: **`http://192.168.1.1`** (o la IP mostrada en el encabezado de MangoRed).
2. Inicia sesión con tus credenciales de administración autorizadas.
3. Navega al menú **Seguridad (Security)** o **Avanzado (Advanced)**.
4. Entra en **Filtro MAC Wi-Fi (WLAN MAC Filter)** o **Control de Acceso (Access Control)**.
5. Selecciona el modo **Lista Negra (Blacklist)**.
6. Añade una nueva regla y pega la **Dirección MAC** exacta proporcionada por MangoRed.
7. Guarda y aplica los cambios. El router denegará la conexión a nivel de radiofrecuencia de forma limpia, permanente y sin causar cortes ni perturbaciones al resto de equipos.

---

## ⚠️ Límites Conocidos

* **Direcciones MAC Aleatorias / Privadas:** Los teléfonos inteligentes y portátiles modernos (iOS con "Dirección Wi-Fi privada", Android con "MAC aleatoria", Windows 11) suelen generar una dirección MAC aleatoria para cada red Wi-Fi. MangoRed detecta este patrón mediante el bit de administración local e informa de ello, pero el dispositivo podría cambiar de MAC si se reconecta con otra configuración.
* **Aislamiento de Clientes AP (Client Isolation):** Si el router tiene activado el aislamiento de clientes en la red Wi-Fi o en la red de invitados, los dispositivos no pueden responderse entre sí en capa 2, limitando la visibilidad del escaneo unicamente a los clientes que pasen por el router.
* **Modos de Ahorro de Energía en Móviles:** Dispositivos en suspensión profunda (deep sleep) pueden dejar de responder a ráfagas ICMP momentáneas; MangoRed mantiene un periodo de gracia antes de marcarlos como *Desconectados*.

---

## 🧪 Ejecución de Pruebas Automatizadas

El proyecto incluye 17 pruebas unitarias e integrales que cubren validación de red, seguridad de credenciales, certeza de datos, controladores de router y endpoints de la API.

Para ejecutar la suite completa en Kali Linux:

```bash
cd /home/mango/MangoRed
pytest -v
```

Resultado esperado:
```text
============================== 17 passed in 0.59s ==============================
```

---

*Desarrollado para Kali Linux con fines de supervisión defensiva, inventario autorizado y administración doméstica legítima.*
