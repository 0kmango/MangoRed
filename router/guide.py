"""
Guía de Configuración Oficial para Routers Residenciales y Empresariales.
Explica cómo aplicar bloqueos autorizados cuando el router no dispone
de una API REST abierta, y la justificación ética y técnica del enfoque.
"""

ROUTER_SETUP_GUIDE = {
    "ethics_and_security": {
        "title": "Por qué NO usar desautenticación Wi-Fi ni suplantación ARP",
        "content": (
            "En herramientas domésticas y de auditoría defensiva, las técnicas ofensivas como los paquetes "
            "de desautenticación Wi-Fi (deauth frames 802.11) o el envenenamiento de caché ARP (ARP spoofing) "
            "son inestables, degradan el rendimiento de toda la red local, generan ruido de radiofrecuencia "
            "y vulneran la integridad de las comunicaciones. Además, en redes modernas con WPA3 o 802.11w (PMF - "
            "Protected Management Frames), los paquetes de desautenticación son rechazados por hardware.\n\n"
            "El único método legítimo, estable y seguro para revocar el acceso a un dispositivo en una red de tu propiedad "
            "es mediante la función administrativa oficial del router (su Firewall, lista de control de acceso ACL o "
            "filtro MAC por hardware)."
        )
    },
    "huawei": {
        "title": "Routers / ONT Huawei (EchoLife, OptiXstar, HG8245, etc.)",
        "steps": [
            "1. Abre el navegador y accede a http://192.168.1.1 (o http://192.168.100.1 según operadora).",
            "2. Inicia sesión con las credenciales de administración del router (impresas en la etiqueta inferior o facilitadas por tu proveedor).",
            "3. Navega a la pestaña 'Security' (Seguridad) o 'Advanced' (Avanzado).",
            "4. Localiza el apartado 'WLAN MAC Filter' (Filtro MAC Wi-Fi) o 'MAC Filtering'.",
            "5. Selecciona el modo 'Blacklist' (Lista Negra / Bloqueo).",
            "6. Haz clic en 'New' (Nuevo) o 'Add' (Añadir) e introduce la dirección MAC exacta copiada desde MangoRed.",
            "7. Pulsa 'Apply' (Aplicar). El router cortará inmediatamente la negociación a nivel de enlace de radio sin perturbar al resto de clientes."
        ]
    },
    "tplink": {
        "title": "Routers TP-Link (Archer, Deco, etc.)",
        "steps": [
            "1. Accede a http://192.168.0.1 o http://tplinkwifi.net e inicia sesión.",
            "2. Ve a 'Avanzado' (Advanced) → 'Seguridad' (Security) → 'Control de Acceso' (Access Control) o 'Control Parental'.",
            "3. En 'Control de Acceso', activa la función y selecciona el modo 'Lista Negra' (Blacklist).",
            "4. Añade un nuevo dispositivo pegando su dirección MAC proporcionada por MangoRed.",
            "5. Guarda los cambios. Opcionalmente, puedes usar la app oficial 'TP-Link Tether' para pulsar 'Bloquear' en el cliente deseado con un solo toque."
        ]
    },
    "asus": {
        "title": "Routers ASUS (ASUSWRT / Merlin)",
        "steps": [
            "1. Accede a http://router.asus.com o http://192.168.1.1.",
            "2. Ve a 'Inalámbrico' (Wireless) → pestaña 'Filtro MAC Inalámbrico' (Wireless MAC Filter).",
            "3. Selecciona la banda (2.4 GHz o 5 GHz) y marca 'Modo de aceptación de filtro MAC: Rechazar' (Lista negra).",
            "4. Añade la dirección MAC del dispositivo y pulsa 'Aplicar'.",
            "5. Si dispones de ASUSWRT-Merlin, puedes habilitar el acceso SSH para automatizar esta tarea mediante MangoRed."
        ]
    },
    "openwrt": {
        "title": "Routers OpenWrt (API ubus habilitada)",
        "steps": [
            "1. En el terminal de OpenWrt, asegúrate de tener instalado uhttpd y rpcd: 'opkg update && opkg install rpcd rpcd-mod-uci uhttpd'.",
            "2. Configura un usuario con permisos ubus o utiliza las credenciales de LuCI.",
            "3. En los Ajustes de MangoRed, selecciona el controlador 'OpenWrt (ubus / LuCI RPC)'.",
            "4. Introduce la IP de tu OpenWrt (por ejemplo 192.168.1.1), el puerto (80 o 443) y las credenciales.",
            "5. Pulsa 'Probar Conexión'. Una vez validado, podrás aplicar bloqueos administrativos con un clic tras confirmación."
        ]
    },
    "mikrotik": {
        "title": "Routers MikroTik (RouterOS v7 REST API)",
        "steps": [
            "1. En Winbox o terminal de MikroTik, activa la API REST: '/ip service enable rest' (utiliza el puerto 80 o 443 con certificado SSL).",
            "2. Crea un usuario con permisos de lectura y escritura sobre el firewall: '/user add name=mangored group=write password=...'.",
            "3. En MangoRed, selecciona el controlador 'MikroTik (RouterOS v7 REST API)' e introduce las credenciales.",
            "4. Realiza la prueba de conexión y gestiona las reglas desde la interfaz."
        ]
    }
}
