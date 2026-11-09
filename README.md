# 🥭 MangoRed — Monitor Doméstico de Red Local (Linux, Windows y macOS)

**MangoRed** es una herramienta defensiva y de administración doméstica para
supervisar redes locales, destinada **exclusivamente a redes de tu propiedad o
en las que cuentas con autorización explícita para administrar**.

Proporciona un panel interactivo y ligero accesible vía navegador local
(`http://127.0.0.1:5000`), con descubrimiento periódico no invasivo, inventario
detallado de dispositivos (tipo, sistema operativo y nombre visible), historial de
conexiones, avisos en tiempo real y **desconexión real** de un equipo mediante el
canal administrativo del router (SSH, API oficial o su lista negra MAC).

Originalmente escrito para Kali Linux, ahora funciona **en cualquier
distribución de Linux, en Windows 10/11 y en macOS** mediante una capa de
compatibilidad multiplataforma (`platform_compat.py` + `network_discovery.py`).

---

## 📑 Índice de Contenidos

1. [Compatibilidad de Plataformas](#-compatibilidad-de-plataformas)
2. [Principios de Seguridad y Ética](#-principios-de-seguridad-y-ética)
3. [Endurecimiento de la API Local](#-endurecimiento-de-la-api-local)
4. [Características Principales](#-características-principales)
5. [Distinción entre Datos Confirmados y Estimados](#-distinción-entre-datos-confirmados-y-estimados)
6. [Reconocimiento de Dispositivos (tipo y nombre)](#-reconocimiento-de-dispositivos-tipo-y-nombre)
7. [Tiempo Real: conexión y desconexión](#-tiempo-real-conexión-y-desconexión-en-el-momento)
8. [Mango LAN Map: mapa lógico en vivo](#-mango-lan-map-mapa-lógico-en-vivo)
9. [Desconectar un dispositivo de la red (SSH)](#-desconectar-un-dispositivo-de-la-red-controlador-ssh)
10. [Uso responsable: salvaguardas](#-uso-responsable-salvaguardas-incorporadas)
11. [Arquitectura del Sistema](#-arquitectura-del-sistema)
12. [Instalación y Requisitos](#-instalación-y-requisitos)
13. [Instrucciones de Uso](#-instrucciones-de-uso)
14. [Referencia de CLI y Variables de Entorno](#-referencia-de-cli-y-variables-de-entorno)
15. [Integración con Routers](#-integración-con-routers-y-bloqueo-autorizado)
16. [Configuración Manual en Routers sin API (Huawei, etc.)](#-configuración-manual-en-routers-sin-api-huawei-etc)
17. [Límites Conocidos y Diagnóstico](#-límites-conocidos)
18. [Ejecución de Pruebas Automatizadas](#-ejecución-de-pruebas-automatizadas)

---

## 🖥 Compatibilidad de Plataformas

| Función | Linux (Kali, Debian, Ubuntu, Arch, Fedora…) | Windows 10 / 11 | macOS |
| :--- | :--- | :--- | :--- |
| Interfaz y puerta de enlace | `ip route`, `/proc/net/route`, `psutil` | `route print -4`, `ipconfig`, `psutil` | `route -n get default`, `ifconfig` |
| IP / máscara / MAC local | `ip addr`, `ip link`, `/sys/class/net` | `psutil`, `ipconfig` | `ifconfig`, `psutil` |
| Tabla de vecinos (ARP) | `ip neigh`, `/proc/net/arp`, `arp -an` | `arp -a` | `arp -an -i <iface>` |
| Barrido ICMP de refresco | `ping -c 1 -W 1` | `ping -n 1 -w 1000` | `ping -c 1 -t 1` |
| Notificaciones nativas | `notify-send` (libnotify) | Toast de Windows (PowerShell) | `osascript` |
| Permisos de credenciales | `chmod 0600` | `icacls` (ACL sólo del usuario) | `chmod 0600` |
| Lanzador incluido | `mangored.sh` | `mangored.bat`, `mangored.ps1` | `mangored.sh` |

La detección intenta primero `psutil` (si está instalado) y cae automáticamente
a las herramientas nativas del sistema; si todo falla, usa un socket UDP que no
envía tráfico y, como último recurso, valores por defecto seguros. **La
detección nunca lanza excepciones.**

---

## 🛡 Principios de Seguridad y Ética

* **Modo Solo Lectura por Defecto (`READ_ONLY = True`):** Cualquier acción que
  modifique reglas en el router se rechaza a nivel de API hasta que el usuario
  desmarque explícitamente la casilla en la pestaña de Ajustes.
* **Sin Técnicas de Ataque Ofensivo:** **No se emplean paquetes de
  desautenticación Wi-Fi (802.11 deauth frames), ni envenenamiento de caché ARP
  (ARP spoofing), ni puntos de acceso falsos.** Dichas técnicas son inestables,
  degradan el rendimiento de la radiofrecuencia, son bloqueadas por WPA3 /
  802.11w (PMF) y no constituyen una solución de administración legítima.
* **Barrido Activo Limitado a Redes Locales:** El refresco ICMP sólo se ejecuta
  si la subred detectada es privada (RFC 1918), de enlace local o CGNAT. En
  rangos públicos el barrido se desactiva y sólo se lee la tabla ARP del sistema
  (`is_local_network()` en `network_discovery.py`).
* **Bloqueo Exclusivamente Oficial:** La restricción de acceso sólo se aplica a
  través de una función administrativa autorizada del router (API REST,
  ubus/uci, lista negra administrativa). Si el router no dispone de API,
  MangoRed ofrece una guía paso a paso para aplicar la regla en su interfaz web
  oficial.
* **Nada de "éxitos" ficticios:** los controladores reales devuelven error
  explícito si el router rechaza la operación o si la regla no se pudo aplicar.
* **Privacidad Absoluta:** No se captura el contenido del tráfico de los usuarios
  ni contraseñas. Únicamente se inspecciona información de presencia en capa de
  enlace e IP.
* **Protección de Credenciales:** `mangored_config.json` (credenciales del router)
  se guarda con permisos restrictivos **`0600`** en Linux/macOS y con ACL
  equivalente (`icacls`) en Windows. La base de datos del inventario
  (`mangored.db`) recibe el mismo tratamiento.
* **Aislamiento SSRF:** la IP del router debe pertenecer a un rango local
  (privado, link-local o CGNAT). Así MangoRed no puede convertirse en un proxy
  hacia servicios de Internet.

---

## 🔒 Endurecimiento de la API Local

El panel escucha en `127.0.0.1`, pero un servicio local sigue siendo alcanzable
por cualquier proceso del equipo y por páginas web maliciosas que intenten hablar
con `localhost`. MangoRed incorpora defensas activas (`security.py`):

| Defensa | Descripción |
| :--- | :--- |
| **Token local anti-CSRF** | Se genera un token aleatorio por arranque y se inyecta en el propio HTML. Toda petición `POST/PUT/PATCH/DELETE` debe enviarlo en la cabecera `X-MangoRed-Token`. Se compara en tiempo constante (`hmac.compare_digest`). |
| **Validación de `Host`** | Sólo se aceptan `127.0.0.1`, `localhost`, `::1` (o los hosts añadidos con `MANGORED_ALLOWED_HOSTS`). Bloquea ataques de **DNS rebinding** con HTTP 403. |
| **Rate limiting** | Ventana deslizante por cliente y categoría: 12 escaneos/min, 30 acciones de router/min, 20 cambios de configuración/min. Devuelve `429` con cabecera `Retry-After`. |
| **Límite de cuerpo** | `MAX_CONTENT_LENGTH` = 64 KB por petición (`413` si se supera). |
| **Cabeceras de seguridad** | `Content-Security-Policy` sin `unsafe-inline` para scripts, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy`, `Permissions-Policy` y `Cache-Control: no-store`. |
| **Exposición remota bloqueada** | Escuchar fuera de loopback exige `MANGORED_ALLOW_REMOTE=1` y declarar el host en `MANGORED_ALLOWED_HOSTS`. |
| **Escape y saneamiento** | Todos los datos provenientes de la red (hostnames, fabricantes, notas) se escapan en el cliente (`escapeHtml`) y se sanean en el servidor antes de persistirse. La tabla usa delegación de eventos (`data-action`) en lugar de `onclick` inline. |
| **Validación estricta** | MAC/IP/CIDR, rangos numéricos, nombres de interfaz (Linux y Windows), rutas de base de datos y límites de longitud. |

Todas estas defensas están cubiertas por pruebas automatizadas
(`tests/test_security.py`, `tests/test_api.py`).

---

## ✨ Características Principales

* **Detección Automática de Dispositivos:** Identifica dinámicamente Dirección IP,
  Dirección MAC, Nombre de host (si está disponible), Fabricante (base de datos
  OUI local multiplataforma) y Estado (En línea, Inactivo, Desconectado, Bloqueado).
* **Reconocimiento del Tipo de Dispositivo:** clasifica cada equipo como
  **móvil, tablet, portátil/ordenador, router, impresora, TV/streaming, consola,
  cámara IP, NAS o IoT**, con el sistema operativo estimado (iOS, Android,
  Windows, macOS, Linux, tvOS/Google TV…) y su grado de confianza.
* **Nombres Visibles Reales:** obtiene el nombre del equipo por **DNS inverso,
  NetBIOS (equipos Windows) y mDNS** (Apple/IoT/impresoras), indicando siempre de
  qué fuente proviene cada nombre.
* **Panel Web Local Intuitivo:** Interfaz moderna con tema oscuro, sin dependencias
  externas (sin CDN, sin fuentes remotas), compatible con la CSP estricta.
* **Actualización Periódica:** Escaneo automático en segundo plano a intervalos
  configurables (por defecto cada 30 s) y botón para forzar escaneo manual.
* **Escaneo Serializado:** un único escaneo a la vez (cerrojo no bloqueante), sin
  duplicar trabajo ni corromper el inventario.
* **Búsqueda y Filtros en Tiempo Real:** por estado (*En línea, Nuevos,
  Desconectados, Bloqueados*), por **tipo de dispositivo**, etiquetas
  personalizadas o búsqueda libre (IP, MAC, nombre, notas).
* **Gestión de Identidad y Alias:** nombres personalizados, etiquetas y notas por
  dispositivo (p. ej. *"Portátil Trabajo"*, *"Bombilla Salón"*).
* **Avisos de Nuevos Dispositivos:** alertas visuales en el panel y notificaciones
  nativas del escritorio según el sistema operativo.
* **Vigilancia en Tiempo Real:** un hilo ligero lee la tabla ARP cada 5 s y avisa
  **en el momento** en que un equipo se conecta o se desconecta (toast en el panel,
  notificación de escritorio y, opcionalmente, notificación del navegador). Antes
  de declarar una desconexión se confirma con un ICMP puntual.
* **Mango LAN Map (mapa lógico en vivo):** vista `/map` que dibuja la red como un
  mapa —gateway en el centro, equipos en anillos por tipo, enlaces y animaciones—,
  con posiciones **arrastrables y guardadas**, **plano de tu casa** como fondo,
  zoom, búsqueda y panel de detalle. Ver *Mango LAN Map*.
* **Desconexión Real de la Red:** el controlador **SSH** (OpenWrt/`uci` o cualquier
  router Linux/`iptables`) expulsa al equipo del Wi-Fi (lista negra MAC del AP +
  `hostapd_cli`) y le corta Internet, **verificando** que la regla quedó aplicada.
  Los controladores por API cortan el acceso a Internet. Nada de simulaciones.
* **Historial de Conexiones y Auditoría:** registro continuo de conexión,
  desconexión, cambios de IP y auditoría de bloqueos/desbloqueos.
* **Selector de Interfaces:** `/api/interfaces` lista las interfaces detectadas y
  las ofrece como sugerencias en Ajustes.
* **Endpoint de Salud:** `/api/health` informa del estado, la versión, la
  plataforma y las herramientas del sistema disponibles.

---

## 🔍 Distinción entre Datos Confirmados y Estimados

MangoRed distingue claramente en su interfaz la certeza de cada dato mostrado
para evitar conclusiones erróneas:

| Tipo de Dato | Clasificación | Justificación Técnica |
| :--- | :--- | :--- |
| **Dirección IP** | **`CONFIRMADO`** | Verificada mediante respuesta ICMP activa o entrada directa en la tabla de vecinos del sistema. |
| **Dirección MAC** | **`CONFIRMADO`** | Obtenida de las tramas ARP en la capa de enlace de datos (capa 2). |
| **Nombre de Host (Hostname)** | **`ESTIMADO`** | Obtenido mediante DNS inverso (PTR), NetBIOS o mDNS. Un dispositivo puede reportar un nombre arbitrario o no anunciar ninguno. |
| **Fabricante (Vendor)** | **`ESTIMADO`** | Inferencia por el prefijo OUI de 24 bits. Dispositivos modernos con iOS, Android o Windows pueden usar MAC privadas/aleatorias (se detectan por el bit de administración local). |
| **Tipo de dispositivo** | **`ESTIMADO`** | Se deduce del nombre visible, de los puertos TCP abiertos y del fabricante. El nivel de confianza (alto/medio/bajo) y las evidencias se muestran en el panel. |

---

## 🔎 Reconocimiento de Dispositivos (tipo y nombre)

Cada dispositivo aparece en el inventario con un **icono y una etiqueta de tipo**
(`📱 Móvil · Android`, `💻 Ordenador · Windows`, `📡 Router`, `🖨️ Impresora`…), el
nombre visible y la **fuente** del nombre (`DNS`, `NetBIOS` o `mDNS`).

### Cómo se identifica el tipo

Se combinan tres evidencias, de mayor a menor fiabilidad:

| Evidencia | Ejemplos | Confianza |
| :--- | :--- | :--- |
| **0. Modelo publicado por mDNS** | `model=iPhone14,2` → Móvil/iOS · `iPad13,4` → Tablet/iPadOS · `MacBookPro18,3` → Portátil/macOS · `Chromecast`/`FUSE 4K` → TV | **Máxima** |
| **1. Nombre visible** | `iPhone-de-Luis` → Móvil/iOS · `DESKTOP-4F2K9L` → Ordenador/Windows · `MacBook-Pro` → Portátil/macOS · `raspberrypi` → Ordenador/Linux · `HP-LaserJet` → Impresora · `Chromecast` → TV | Alta |
| **2. Puertos TCP abiertos** (connect scan acotado) | `62078` → iPhone/iPad · `445`/`3389` → Windows · `9100`/`631` → Impresora · `554` → Cámara IP · `8008`/`8009` → Chromecast · `1883` → IoT · `53`+`80` → Router | Alta / Media |
| **3. Servicios mDNS** | `_apple-mobdev2` (sincronización Wi-Fi de iPhone/iPad) · `_airplay` (ecosistema Apple) · `_googlecast` + modelo → Android TV/Chromecast | Media |
| **4. Fabricante (OUI)** | `Espressif` → IoT · `Raspberry Pi` → Linux · `VMware` → Máquina virtual · `Hikvision` → Cámara · `Canon` → Impresora | Media / Baja |

La puerta de enlace se marca siempre como **Router** y el propio equipo como
**Ordenador** con su sistema operativo real. Apple, sin más datos, se muestra como
«Desconocido · iOS/iPadOS/macOS» para no afirmar algo incorrecto.

### 📱 Dispositivos iOS (iPhone / iPad): sí, se reconocen

MangoRed identifica un iPhone o un iPad por **cuatro vías independientes**, de
modo que basta con que una funcione:

1. **Modelo por mDNS (la más fiable):** los dispositivos Apple publican
   `_device-info._tcp` con un registro TXT `model=iPhone14,2`. MangoRed lo lee y
   clasifica como **Móvil · iOS** (o **Tablet · iPadOS**), mostrando el modelo.
   **Funciona aunque la MAC sea aleatoria, no haya DNS y el equipo no tenga nombre.**
2. **Servicio `_apple-mobdev2._tcp`:** indica un iPhone/iPad con sincronización
   Wi-Fi activa; sin modelo se informa como «Desconocido · iOS/iPadOS».
3. **Puerto 62078 (lockdownd):** si el equipo lo expone, se marca **Móvil · iOS**.
4. **Nombre visible:** `iPhone…`, `iPad…`, `iPod…` (por DNS, NetBIOS o mDNS).

Además, `AirPlay` y `HomePod`/`Apple TV`/`Apple Watch`/`AirPods` tienen sus propias
reglas (`watchOS`, `tvOS`, `HomePod`, `AirPods`).

> En la prueba real de esta red no había dispositivos Apple, pero la ruta de
> detección es exactamente la misma que sí funcionó con los Android TV
> (`model=FUSE 4K` → TV). El parseo de `model=iPhone14,2` está cubierto por
> pruebas con paquetes mDNS reales (`tests/test_name_resolver.py`).

### Cómo se obtiene el nombre

1. **DNS inverso (PTR)** — rápido y universal.
2. **NetBIOS NBSTAT (UDP 137)** — nombre real de equipos Windows sin DNS.
3. **mDNS (UDP 5353, PTR inversa)** — `.local` de Apple, impresoras e IoT.

Cada protocolo se puede desactivar en **Ajustes → Reconocimiento de Dispositivos**.
Los nombres genéricos (`_gateway`, `localhost`, IPs, MACs) se descartan para no
ensuciar el inventario.

### Coste y privacidad

* El análisis de puertos usa una **lista fija y corta** (19 puertos) y sólo sobre
  equipos ya descubiertos en la tabla ARP, nunca sobre toda la subred.
* Sólo se analizan equipos **nuevos o aún sin clasificar**, con un presupuesto
  máximo por ronda (`fingerprint_max_devices`, 32 por defecto).
* El descubrimiento mDNS consulta **5 tipos de servicio** (`_device-info`,
  `_apple-mobdev2`, `_airplay`, `_raop`, `_googlecast`) y sólo lee los metadatos
  que el propio equipo publica (nombre amigable y modelo); no accede a su
  contenido ni a sus ficheros.
* Si el nombre o el modelo ya identifican el equipo (p. ej. `iPhone`), **no se
  escanean puertos** para ahorrar tráfico y tiempo.
* No se abren sockets raw ni se necesita `root`; es un `connect()` TCP normal.
* Todo el resultado es **estimado** y se guarda con sus evidencias para que puedas
  auditarlo con el ratón sobre la etiqueta del tipo.

---

## ⚡ Tiempo Real: conexión y desconexión en el momento

`event_watcher.py` ejecuta un hilo propio que cada `watch_interval` segundos
(5 por defecto, mínimo 2) lee la **tabla de vecinos ARP** —sin barridos ni ping
masivo— y detecta cambios de estado:

| Evento | Cuándo se emite | Notificación |
| :--- | :--- | :--- |
| `new_device` | Aparece una MAC que no estaba en el inventario | Toast + escritorio + navegador (opcional) |
| `connected` | Un equipo que estaba desconectado vuelve a la red | Toast + escritorio + navegador |
| `disconnected` | Un equipo lleva ausente la **gracia** y tampoco responde a un ICMP puntual | Toast + escritorio + navegador |

Detalles de diseño (para que sea real y no ruidoso):

* **Línea base:** la primera pasada sólo inventaría; no notifica. Además, el
  vigilante espera al primer escaneo completo, así que al arrancar **no** te avisa
  de toda tu red.
* **Anti falsos positivos:** el kernel caduca entradas ARP de equipos inactivos.
  Por eso una ausencia en ARP **no** basta: se envía **un ping** al equipo; si
  responde, sigue en línea. También se espera `max(disconnect_grace, 2×intervalo
  de escaneo)` segundos.
* **Sin ruido:** sólo se escribe en la base de datos y se notifica en cambios de
  estado, no en cada sondeo.
* **Entrega al panel:** `GET /api/events?since=<id>` devuelve los eventos nuevos;
  el panel lo consulta cada 2 s y muestra un toast + (opcional) notificación del
  navegador. El indicador **● En vivo · 5s** del encabezado muestra el estado.
* **Sin privilegios:** sólo lee tablas del sistema y ejecuta `ping`.

Ajustes relacionados: *Sondeo de conexiones (s)*, *Gracia antes de "desconectado"*
y la casilla de **notificaciones del navegador**.

---

## 🗺 Mango LAN Map: mapa lógico en vivo

**Mango LAN Map** es la vista de mapa incluida en MangoRed (botón **🗺 Mapa** o
`http://127.0.0.1:5000/map`). Dibuja la red como un mapa: la **puerta de enlace en
el centro** y los equipos repartidos en **anillos por tipo** (infraestructura,
móviles/IoT, sin identificar), con enlaces al gateway y animaciones de
conexión/desconexión.

> ⚠️ Es un **mapa lógico** (topología y presencia en la red), **no** una
> geolocalización: un equipo no puede conocer la posición GPS de otros
> dispositivos de la red. Las posiciones son orientativas y **tú las colocas**.

| Función | Cómo funciona |
| :--- | :--- |
| **Anillos por tipo** | Router/AP en el centro; impresoras, NAS, TV y ordenadores en el anillo 1; móviles, cámaras e IoT en el 2; desconocidos en el 3. Reparto determinista (ángulo áureo) para que cada equipo mantenga su sitio. |
| **Arrastrar y guardar** | Arrastra cualquier dispositivo para colocarlo donde quieras; la posición se guarda en la base de datos (`map_x`, `map_y`, `map_pinned`) y se conserva entre reinicios. |
| **Plano de tu casa** | Sube una imagen **PNG/JPEG** (máx. 2 MB) y colócala como fondo translúcido para situar cada equipo en su habitación. Validación por extensión y por firma del archivo. |
| **Zoom y desplazamiento** | Rueda del ratón para acercar/alejar, arrastrar el fondo para moverse, botones ＋ － ⤢. |
| **Búsqueda y leyenda** | Filtra por nombre, IP, MAC, fabricante o tipo (los que no coinciden se atenúan) y leyenda dinámica con los tipos presentes. |
| **Detalle al clic** | Panel lateral con nombre, IP, MAC, fabricante, tipo, SO, modelo, puertos y marcas de tiempo, más acciones: centrar, devolver a posición automática y marcar como revisado. |
| **Tiempo real** | Cada 2 s consulta el estado; las conexiones y desconexiones aparecen como aviso y el nodo se anima. |

Endpoints de la vista:

| Método | Ruta | Uso |
| :--- | :--- | :--- |
| GET | `/map` | Página del mapa (incluye el token de sesión) |
| GET | `/api/map?since=<id>` | Nodos con posición, eventos nuevos, métricas y estado |
| POST | `/api/map/positions` | Guarda posiciones arrastradas (`{ "positions": { "mac": [x, y] } }`) |
| POST | `/api/map/positions/reset` | Vuelve al layout automático (uno o todos) |
| POST/GET/DELETE | `/api/map/floorplan` | Sube, sirve o elimina el plano de planta |

Todas las escrituras exigen el token local (`X-MangoRed-Token`); el plano se
guarda con permisos restringidos en `map_assets/`.

---

## 🔌 Desconectar un dispositivo de la red (controlador SSH)

El controlador **SSH** (`router_type: ssh`, por defecto) aplica un bloqueo **real**.
En modo `full` hace dos cosas y **verifica ambas**:

1. **Expulsión del Wi-Fi:** añade la MAC a la lista negra del punto de acceso
   (`uci set wireless.<iface>.macfilter=deny` + `uci add_list … maclist=<MAC>`,
   `uci commit wireless`, `wifi reload`) y ordena a hostapd que lo expulse en el
   acto (`hostapd_cli -i <iface> deauthenticate <MAC>`). Es la función
   administrativa oficial del AP, no un ataque de deauth.
2. **Cortafuegos:** `uci set firewall.mangored_<mac>=rule` con `src_mac` y
   `target=DROP` (más `commit` y recarga) o, en el perfil `iptables`, las cadenas
   `MANGORED` (FORWARD) y `MANGORED_IN` (INPUT). Así pierde Internet y el acceso a
   los servicios del router.

| Perfil | Comandos principales | Verificación |
| :--- | :--- | :--- |
| `openwrt` | `uci` (firewall + `wireless.macfilter/maclist`) y `hostapd_cli deauthenticate` | `uci get firewall.<rule>.target` = `DROP` y `uci show wireless` contiene la MAC |
| `iptables` | Cadenas `MANGORED` (FORWARD) y `MANGORED_IN` (INPUT) con `-m mac --mac-source <MAC> -j DROP`, más `hostapd_cli` si el propio equipo es el AP | `iptables -S MANGORED` contiene la MAC |

* Transporte: **paramiko** (contraseña o clave) o el cliente **OpenSSH** del sistema
  (sólo clave). La **clave de host** se verifica contra `known_hosts`; si no existe,
  hay que autorizarla explícitamente en Ajustes (menos seguro, sólo redes de confianza).
* La MAC se valida y normaliza antes de construir el comando, y los comandos son
  **plantillas fijas**: no hay forma de inyectar comandos.
* Si el cortafuegos no confirma la regla, MangoRed **no** marca el equipo como
  bloqueado. Si el Wi-Fi no se pudo tocar (equipo por cable o router sin `hostapd`),
  el resultado lo indica: «sin acceso a Internet; no se pudo añadir la lista MAC».
* Al desbloquear se elimina la regla, se quita la MAC de `maclist` y se recargan
  Wi-Fi y cortafuegos, verificando que no queda ninguna entrada.

> **Alcance:** el equipo deja de tener Internet y, si es Wi-Fi, deja de poder
> asociarse al AP. No se envían tramas falsificadas: el propio AP aplica su lista
> negra. Un equipo por cable no se puede «expulsar» del switch sin 802.1X; se aísla
> con el cortafuegos.

---

## ⚖ Uso responsable: salvaguardas incorporadas

MangoRed es una herramienta de **administración defensiva**. Para que no pueda
convertirse en un arma contra redes ajenas, incorpora varias barreras:

1. **Modo Solo Lectura por defecto:** cualquier cambio en el router se rechaza
   hasta que lo desactives a mano.
2. **Declaración de autorización:** antes de bloquear o desbloquear debes marcar en
   Ajustes que eres el propietario o administrador autorizado de la red. Sin esa
   casilla, la API responde `403`. No existe modo simulador: no hay forma de
   "probar" el bloqueo sin aplicarlo.
3. **Doble confirmación:** el modal muestra el equipo, la IP, la MAC, el fabricante,
   el controlador y el **efecto real** de la acción; exige marcar otra casilla.
4. **Auditoría completa:** cada bloqueo/desbloqueo queda en el historial con motivo,
   controlador y resultado (`blocked`/`unblocked`).
5. **Sin técnicas ofensivas:** ni deauth 802.11, ni ARP spoofing, ni MITM.
6. **Token local + rate limit + Host permitido** en todas las operaciones (ver
   *Endurecimiento de la API Local*).

---

## 🏗 Arquitectura del Sistema

```text
MangoRed/
├── app.py                      # Servidor Flask/waitress, API REST, CLI y control de acceso
├── security.py                 # Token anti-CSRF, validación de Host, rate limiting y CSP
├── platform_compat.py          # Capa multiplataforma: permisos, notificaciones y ejecución segura
├── network_discovery.py        # Detección de interfaz/gateway/subred y tabla ARP por SO
├── name_resolver.py            # Nombres visibles: DNS inverso + NetBIOS NBSTAT + mDNS
├── device_fingerprint.py       # Tipo de dispositivo: nombre + puertos TCP + fabricante OUI
├── event_watcher.py            # Vigilancia en tiempo real (conexión/desconexión + búfer de eventos)
├── map_layout.py               # Mango LAN Map: anillos por tipo y posiciones (deterministas)
├── config.py                   # Configuración validada y credenciales con permisos 0600
├── scanner.py                  # Motor de descubrimiento (vecinos + barrido ICMP acotado)
├── database.py                 # SQLite: dispositivos, tipo, historial y auditoría
├── oui_lookup.py               # Fabricantes por OUI (rutas Linux/Windows/macOS + reserva)
├── router/                     # Controladores de router autorizados
│   ├── __init__.py             # Factoría de controladores reales (sin simulador)
│   ├── base.py                 # Interfaz abstracta BaseRouterDriver
│   ├── openwrt.py              # OpenWrt real: ubus JSON-RPC + uci (add/set/delete/commit/reload)
│   ├── mikrotik.py             # MikroTik RouterOS v7 REST API
│   ├── ssh_router.py           # SSH real: expulsa del Wi-Fi + uci/iptables — desconecta de la red
│   ├── generic_webhook.py      # Webhook HTTPS con token Bearer
│   └── guide.py                # Guía de routers comerciales (Huawei, TP-Link, ASUS…)
├── static/
│   ├── css/style.css           # Tema oscuro autocontenido
│   ├── css/map.css             # Estilos de la vista Mango LAN Map
│   ├── js/app.js               # Cliente REST con token, modales y delegación de eventos
│   └── js/map.js               # Mapa SVG: anillos, drag&drop, zoom, plano y tiempo real
├── templates/
│   ├── index.html              # Panel HTML5 (inyecta el token de sesión)
│   └── map.html                # Vista Mango LAN Map
├── map_assets/                 # Plano de planta subido por el usuario (ignorado en git)
├── tests/                      # 260 pruebas con pytest
│   ├── conftest.py             # Aísla la configuración real del desarrollador
│   ├── test_api.py             # Endpoints + cabeceras + token + Host + filtro por tipo + eventos
│   ├── test_security.py        # Token, rate limiter, Host, CSP
│   ├── test_platform_compat.py # Permisos, saneamiento, notificaciones
│   ├── test_network_discovery.py # Analizadores ip neigh/arp/ipconfig/route
│   ├── test_device_fingerprint.py # Tipo de dispositivo (hostname/puertos/fabricante)
│   ├── test_name_resolver.py   # Nombres por DNS/NetBIOS/mDNS y parseo de paquetes
│   ├── test_event_watcher.py   # Tiempo real: línea base, conexión/desconexión y gracia
│   ├── test_map_layout.py      # Mango LAN Map: anillos, límites y posiciones fijadas
│   ├── test_map_api.py         # Mapa: /api/map, posiciones, plano y validaciones
│   ├── test_ssh_router.py      # Comandos SSH reales y verificación posterior
│   ├── test_config.py          # Validaciones y permisos de credenciales
│   ├── test_database.py        # Certeza de datos, migración, huella y permisos
│   ├── test_oui.py             # Fabricantes y MAC aleatoria
│   └── test_router.py          # Controladores, confirmación y modo solo lectura
├── mangored.sh                 # Lanzador Linux/macOS
├── mangored.bat                # Lanzador Windows (CMD)
├── mangored.ps1                # Lanzador Windows (PowerShell)
├── requirements.txt
└── README.md
```

### Flujo de un escaneo

```text
detect_network_context()        → interfaz, IP, máscara, gateway y MAC local
        ↓
ping_sweep(subred)              → sólo en redes locales, hasta `scan_max_hosts` hosts
        ↓
read_neighbor_table()           → ip neigh / /proc/net/arp / arp -a (más fiable)
        ↓
resolve_names()                 → DNS inverso → NetBIOS → mDNS (nombre + fuente)
        ↓
oui_lookup.lookup_vendor()      → fabricante estimado por OUI
        ↓
fingerprint_device()            → tipo + SO (nombre, puertos TCP y fabricante)
        ↓
database.upsert_device()        → inventario + historial + notificación de nuevos
```

En paralelo, **`event_watcher.py`** lee la tabla de vecinos cada 5 s y emite los
eventos de conexión/desconexión que consume `GET /api/events`.

---

## 🚀 Instalación y Requisitos

### Requisitos

* **Python 3.9 o superior** (probado con 3.14).
* Dependencias Python: `flask`, `requests`, `waitress`, `psutil` y `paramiko`
  (+ `pytest` para las pruebas). `waitress` mejora el servidor, `psutil` la
  detección de interfaces y `paramiko` permite SSH con contraseña; el código
  funciona sin ellos con degradación controlada (SSH usaría OpenSSH + clave).

### Linux (Kali, Debian, Ubuntu, Arch, Fedora…)

```bash
cd MangoRed
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Opcionales recomendados (Debian/Kali/Ubuntu)
sudo apt install -y python3-venv libnotify-bin iproute2 iputils-ping
```

### Windows 10 / 11

```powershell
cd MangoRed
py -m venv .venv
.venv\Scripts\activate
py -m pip install -r requirements.txt
```

Windows ya incluye `ping`, `arp`, `route` e `ipconfig`, así que no hace falta
nada adicional. `psutil` (incluido en `requirements.txt`) mejora la precisión de
la detección de adaptadores.

### macOS

```bash
cd MangoRed
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Opcional: brew install nmap   (base de datos OUI ampliada)
```

### Base de datos OUI (opcional, amplía la detección de fabricantes)

MangoRed busca automáticamente, en este orden:

1. `MANGORED_OUI_PATH` (variable de entorno).
2. `oui.txt` / `nmap-mac-prefixes` dentro del propio proyecto.
3. Linux: `/usr/share/nmap/nmap-mac-prefixes`, `/usr/share/arp-scan/ieee-oui.txt`,
   `/var/lib/ieee-data/oui.txt`, `/usr/share/ieee-data/oui.txt`,
   `/usr/share/wireshark/manuf`.
4. macOS: `/usr/local/share/...`, `/opt/homebrew/share/...`, `/opt/local/share/...`.
5. Windows: `%ProgramFiles%\Nmap\nmap-mac-prefixes`, `%ProgramFiles%\Wireshark\manuf`.

Si no hay ninguna base de datos, se usa el diccionario interno con los
fabricantes más habituales.

---

## 💻 Instrucciones de Uso

### 1. Iniciar MangoRed

**Linux / macOS:**

```bash
cd MangoRed
./mangored.sh          # o directamente: python3 app.py
```

**Windows:**

```bat
cd MangoRed
mangored.bat           REM doble clic también funciona
:: alternativa en PowerShell
powershell -ExecutionPolicy Bypass -File .\mangored.ps1
```

El servidor abre el navegador automáticamente (omítelo con `--no-browser`).

### 2. Acceder al Panel

👉 **`http://127.0.0.1:5000`**

### 3. Operaciones Comunes

1. **Escanear:** pulsa **"Escanear Ahora"** para refrescar el inventario al momento.
2. **Ver el mapa:** pulsa **"🗺️ Mapa"** para abrir **Mango LAN Map**: gateway en el
   centro, equipos en anillos por tipo, arrástralos donde quieras y sube un plano
   de tu casa como fondo (se guarda solo).
3. **Identificar:** usa **"✏️ Editar"** para asignar alias, etiquetas y notas.
4. **Reconocer dispositivos nuevos:** pulsa **"Marcar Todos como Conocidos"**.
5. **Ver historial:** abre **"🕒 Historial"** para consultar eventos y auditoría.
6. **Recibir avisos en vivo:** el indicador **● En vivo · 5s** confirma que la
   vigilancia está activa; cada conexión/desconexión aparece como toast (y como
   notificación del navegador si la activas en Ajustes).
7. **Bloquear / desconectar:** abre **"⛔ Bloquear"**, revisa el **efecto real**
   que muestra el modal, escribe el motivo y marca la casilla de confirmación.
   Requiere desactivar el Modo Solo Lectura y aceptar la declaración de
   autorización en Ajustes.
8. **Ajustes:** intervalo de escaneo, límite de hosts, interfaz, notificaciones,
   reconocimiento de dispositivos, tiempo real y credenciales/SSH del router.

---

## ⌨ Referencia de CLI y Variables de Entorno

### Argumentos de línea de comandos

| Argumento | Descripción |
| :--- | :--- |
| `--host <ip>` | Dirección de escucha (por defecto `127.0.0.1`). Fuera de loopback exige `MANGORED_ALLOW_REMOTE=1`. |
| `--port <puerto>` | Puerto de escucha (por defecto `5000`). |
| `--no-browser` | No abrir el navegador automáticamente. |
| `--no-scan` | No iniciar el escáner periódico de fondo. |
| `--no-watch` | No iniciar la vigilancia en tiempo real (conexión/desconexión). |
| `--version` | Muestra la versión y sale. |

### Variables de entorno

| Variable | Función |
| :--- | :--- |
| `MANGORED_API_TOKEN` | Fija el token de escritura (mínimo 16 caracteres). Si no se define, se genera uno aleatorio por arranque. |
| `MANGORED_ALLOWED_HOSTS` | Hosts adicionales aceptados en la cabecera `Host` (separados por comas), para acceder con otro nombre/IP. |
| `MANGORED_ALLOW_REMOTE` | Debe valer `1` para permitir escuchar fuera de loopback. |
| `MANGORED_CONFIG_FILE` | Ruta alternativa del archivo de configuración. |
| `MANGORED_OUI_PATH` | Ruta a una base de datos OUI propia. |
| `MANGORED_LOG_LEVEL` | Nivel de logging (`INFO` por defecto, admite `DEBUG`). |

### Ejemplos con `curl`

```bash
TOKEN=$(curl -s http://127.0.0.1:5000/ | grep -o 'mangored-api-token" content="[^"]*' | cut -d'"' -f3)

curl -s http://127.0.0.1:5000/api/health
curl -s -X POST -H "X-MangoRed-Token: $TOKEN" http://127.0.0.1:5000/api/scan
curl -s -X POST -H "X-MangoRed-Token: $TOKEN" -H 'Content-Type: application/json' \
     -d '{"mac":"aa:bb:cc:dd:ee:ff","confirmed":true}' http://127.0.0.1:5000/api/router/block
```

---

## 🔌 Integración con Routers y Bloqueo Autorizado

MangoRed ofrece cuatro controladores reales (`router/`). **No hay modo simulador:**
todas las acciones modifican la red de verdad (o fallan con un error explícito).

1. **OpenWrt (`openwrt`):** autenticación real por `session.login` de ubus y
   creación/eliminación de reglas en `/etc/config/firewall` mediante `uci`
   (`add`/`set`/`delete` + `commit` + recarga del cortafuegos). Si algo falla, la
   operación se reporta como fallida. **Corta Internet** al equipo.
2. **MikroTik (`mikrotik`):** API REST de RouterOS v7; inserta una regla en
   `/ip/firewall/filter` (`action=drop`, `src-mac-address`) y la elimina buscando
   por comentario. **Corta Internet** al equipo.
3. **SSH del Router (`ssh`, recomendado):** expulsa al equipo del Wi-Fi (lista MAC
   del AP + `hostapd_cli deauthenticate`) y corta Internet con `uci` (OpenWrt) o
   `iptables` (cadena `MANGORED`), verificando que todo quedó aplicado. Es el
   único controlador que aplica el **modo de bloqueo**; ver
   [Desconectar un dispositivo de la red](#-desconectar-un-dispositivo-de-la-red-controlador-ssh).
4. **Webhook genérico (`generic_webhook`):** envía POST a una pasarela local
   (Home Assistant, script propio...) con token Bearer. Avisa si el canal es HTTP
   sin cifrar.

### Modo de bloqueo (controlador SSH)

| Modo | Qué hace | Cuándo usarlo |
| :--- | :--- | :--- |
| `full` (por defecto) | **Desconecta al equipo de la red**: lo expulsa del Wi-Fi (lista negra MAC del AP + expulsión inmediata) y le corta el acceso a Internet y al router. | Quieres que el dispositivo deje de estar en tu red. |
| `internet` | Sólo corta el acceso a Internet a través del router; el equipo sigue conectado al Wi-Fi. | Quieres quitarle Internet sin echarlo de la red. |

En equipos **conectados por cable** no existe expulsión de radio: el modo `full`
los aísla con el cortafuegos (FORWARD + INPUT) y el resultado lo indica
explícitamente. Los controladores `openwrt`, `mikrotik` y `generic_webhook` cortan
**Internet** a través de su API; para expulsar del Wi-Fi sin SSH usa el filtro MAC
del AP (pestaña **📖 Guía**).

### Flujo de seguridad al bloquear

1. **Token local:** la petición debe llevar `X-MangoRed-Token`.
2. **Modo Solo Lectura:** si está activo (por defecto) se rechaza con `403`.
3. **Confirmación explícita:** el cuerpo debe incluir `"confirmed": true` y la UI
   muestra un modal con nombre, IP, MAC, fabricante y controlador activo, además
   de una casilla obligatoria de autorización administrativa.
4. **Validación:** MAC normalizada, dispositivo existente en el inventario, IP del
   router dentro de la red local.
5. **Ejecución y auditoría:** se aplica en el router y se registra el resultado en
   el historial (`blocked` / `unblocked`).

Los bloqueos manuales en routers sin API se explican en la sección siguiente y
también están integrados en la pestaña **"📖 Guía"** del panel.

---

## 📖 Configuración Manual en Routers sin API (Huawei, etc.)

Si tu router residencial (por ejemplo, un router/ONT de operadora **Huawei
EchoLife / OptiXstar**) no dispone de API abierta para terceros, aplica el
bloqueo mediante su interfaz web oficial:

1. Accede a la puerta de enlace: **`http://192.168.1.1`** (o la IP que muestra la
   cabecera de MangoRed).
2. Inicia sesión con tus credenciales de administración autorizadas.
3. Ve a **Seguridad (Security)** o **Avanzado (Advanced)**.
4. Entra en **Filtro MAC Wi-Fi (WLAN MAC Filter)** o **Control de Acceso**.
5. Selecciona el modo **Lista Negra (Blacklist)**.
6. Añade la **Dirección MAC** exacta que muestra MangoRed.
7. Guarda y aplica. El router denegará la conexión a nivel de enlace de radio de
   forma limpia y permanente para ese equipo.

---

## ⚠ Límites Conocidos

### Solución de problemas: «no se puede conectar por SSH»

MangoRed comprueba el puerto SSH **antes** de intentar el handshake, así que falla en
menos de un segundo con el motivo y un diagnóstico de servicios:

```
No se puede conectar por SSH a 192.168.1.1:22 (puerto cerrado o filtrado).
Servicios detectados en el router: Interfaz web HTTP (80), Interfaz web HTTPS (443).
El router sólo responde en su interfaz web (sin SSH/API). Usa el bloqueo manual
desde la pestaña Guía (filtro MAC del AP) o un webhook local.
```

| Servicios detectados | Qué usar |
| :--- | :--- |
| SSH (22) abierto | Controlador **SSH** (revisa usuario/clave y `known_hosts`) |
| API MikroTik (8728) | Controlador **MikroTik** (REST) |
| Sólo HTTP/HTTPS (80/443) | Router de operadora sin API: **filtro MAC manual** (pestaña **📖 Guía**) o un **webhook** local |
| Ninguno | Revisa la IP del router, que estés en su red y que no haya aislamiento de clientes |

El botón **Probar Conexión** muestra este mismo diagnóstico. Los routers/ONT de
operadora (Huawei EchoLife/OptiXstar, etc.) **no suelen tener SSH ni API**: en ese
caso el bloqueo automático no es posible y hay que aplicar la lista negra MAC desde
su interfaz web (la Guía explica los pasos).

### Límites técnicos

* **Direcciones MAC Aleatorias / Privadas:** iOS ("Dirección Wi-Fi privada"),
  Android ("MAC aleatoria") y Windows 11 generan MAC por red. MangoRed lo detecta
  por el bit de administración local y lo indica, pero el dispositivo puede
  cambiar de MAC al reconectarse con otra configuración.
* **Aislamiento de Clientes AP:** si el router aísla clientes (red de invitados),
  los equipos no se responden en capa 2 y el escaneo sólo verá lo que pase por el
  router.
* **Ahorro de Energía en Móviles:** los dispositivos en suspensión profunda pueden
  no responder a un ICMP puntual; MangoRed aplica un periodo de gracia antes de
  marcarlos como *Desconectados*.
* **ICMP filtrado:** algunos equipos (o el firewall del sistema) bloquean `ping`.
  En ese caso el descubrimiento depende sólo de la tabla ARP/vecinos, que sigue
  siendo fiable para equipos que hayan hablado recientemente en la red.
* **Permisos elevados:** MangoRed **no** necesita `root` ni modo promiscuo; nunca
  abre sockets raw. Sólo ejecuta `ping`, un `connect()` TCP a una lista corta de
  puertos y consultas UDP de NetBIOS/mDNS.
* **Un solo escaneo simultáneo:** las peticiones concurrentes reciben `409` en
  lugar de duplicar el trabajo.
* **Dispositivos que se ocultan:** un equipo con MAC aleatoria, sin puertos
  abiertos y sin nombre anunciado aparecerá como **Desconocido**. Es el
  comportamiento esperado (privacidad del propio dispositivo), no un fallo.
* **Nombres dependientes del equipo:** Windows puede no responder a NetBIOS si lo
  desactiva el firewall, y macOS/iOS sólo responden a mDNS mientras están
  despiertos y en la misma red. En esos casos quedará el nombre DNS (si existe) o
  «No disponible».
* **iOS con la pantalla bloqueada o con mDNS filtrado:** el modelo (`model=iPhone…`)
  se publica cuando el equipo está despierto y la red no bloquea el multicast
  (algunos routers con "aislamiento de clientes" o IGMP snooping agresivo lo
  filtran). Si no se recibe, se intentan las otras tres vías (servicio
  `_apple-mobdev2`, puerto 62078 y nombre visible).
* **El tipo es orientativo:** un mismo fabricante puede producir equipos muy
  distintos (p. ej. Apple: iPhone, iPad o Mac). Por eso se muestra la confianza y
  las evidencias, en lugar de afirmar una categoría sin pruebas.
* **Corte de Internet ≠ expulsión del Wi-Fi:** los controladores por API
  descartan el tráfico que **atraviesa el router**. El controlador SSH en modo
  `full` sí expulsa al cliente Wi-Fi (lista MAC + hostapd). Dos equipos del
  mismo AP/switch pueden seguir hablándose en capa 2.
* **Detección de desconexión:** se apoya en la tabla ARP + un ICMP de confirmación.
  Un equipo que bloquee ICMP y permanezca inactivo podría tardar en marcarse como
  desconectado (nunca se marca por una simple ausencia en ARP).

---

## 🧪 Ejecución de Pruebas Automatizadas

La suite incluye **260 pruebas** que cubren validación de red, seguridad de
credenciales, controles de la API (token, Host, cabeceras, rate limit),
compatibilidad multiplataforma, analizadores de `ip neigh`/`arp`/`ipconfig`/
`route print`, reconocimiento de nombres (DNS/NetBIOS/mDNS), descubrimiento de
servicios y modelos Apple/Google Cast, clasificación de tipos de dispositivo,
vigilancia en tiempo real (línea base, gracia y confirmación ICMP), comandos SSH
con verificación posterior, migración del esquema SQLite, certeza de datos,
controladores de router y endpoints.

```bash
cd MangoRed
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pytest -v
```

Resultado esperado:

```text
260 passed in 2.3s
```

Las pruebas **no** tocan tu `mangored_config.json` real: `tests/conftest.py`
redirige el archivo de configuración a un directorio temporal y aísla cada test.

---

*Desarrollado originalmente para Kali Linux y ampliado a Linux, Windows y macOS
con fines de supervisión defensiva, inventario autorizado y administración
doméstica legítima.*
