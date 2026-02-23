---
title: Firewalld Instalación
description: Instalación de FirewallD
date: 2023-02-02 17:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Admin
   - Network
weight: 1
---

## FirewallD  

**Instalación y configuración del firewallD**

Si queremos tener el applet en la barra de tareas de gnome añadimos lo siguiente:
``` bash
sudo dnf install firewall-config firewall-applet -y
```

FirewalID debería estar ya habilitado por defecto, lo comprobamos:
La mejor práctica es habilitar automáticamente el software de firewall al iniciar el sistema e iniciarlo de inmediato. 
Esto se puede lograr con un comando todo en uno de la siguiente manera.
``` bash
sudo systemctl enable firewalld --now
```
A continuación, verificamos el estado de FirewallD para asegurarse de que todo funcione y no haya errores.
``` bash
systemctl status firewalld
```

Después añadimos a los programas de inicio el firewall-applet de la siguiente forma:
``` bash
cd ~/.config/autostart
touch firewall-applet.desktop
nano firewall-applet.desktop
```
 Añadimos el siguiente texto:
```
[Desktop Entry]
Name=Firewall Applet
Comment=Firewall Applet
Icon=firewall-config
Categories=System;Settings;Security;
#Translators: These are searchable keywords for the firewall configuration tool
Keywords=firewall;network;security;iptables;netfilter;
Exec=/usr/bin/firewall-applet
Type=Application
StartupNotify=true
Terminal=false
X-Desktop-File-Install-Version=0.26
```

Las reglas del firewall para aplicaciones y demás ya es configurar a gusto del usuario.

***
Fuentes:  
[https://fedoraproject.org/wiki/FirewallD/es](https://fedoraproject.org/wiki/FirewallD/es)

