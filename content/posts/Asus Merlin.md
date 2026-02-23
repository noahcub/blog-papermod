---
title: Entware
description: Instalación de Entware en firmware Merlin router Asus
date: 2023-02-02 19:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Asus
weight: 1
---

## Instalación de Entware en firmware Merlin

[Entware](https://github.com/RMerl/asuswrt-merlin/wiki/Entware) es un repositorio de software que nos va a permitir la instalación de diferentes programas en nuestro router. [Software disponible en Entware](http://bin.entware.net/armv7sf-k3.2/Packages.html)

Requisitos

- Es necesario tener conectado un disco USB en el router formateado con ext2 o ext3
- Si está instalado Download Manager, se debe desinstalar y reiniciar el router

**Instalación**

Descargar el script y añadirlo al usb.
Nos conectamos por ssh al router.
Ejecutar el script:
``` bash
usuario@RT-AC86U-3EB8:/tmp/home/root# entware-setup.sh
Info:  This script will guide you through the Entware installation.
Info:  Script modifies "entware" folder only on the chosen drive,
Info:  no other data will be changed. Existing installation will be
Info:  replaced with this one. Also some start scripts will be installed,
Info:  the old ones will be saved on Entware partition with name
Info:  like /tmp/mnt/sda1/jffs_scripts_backup.tgz
```
Entware se instalará en el USB. Si tenemos varios nos preguntará donde instalarlo.

**Uso**

``` bash
    opkg list - lista todos los paquetes disponibles para instalar
    opkg install nombre_software - instala el paquete nombre_software
    opkg remove software_name - borra el paquete nombre_software
```

A partir de aquí podemos instalar software como Tailscale.  

***  
Fuentes:  
[https://elblogdelazaro.org/posts/2019-01-02-instalacion-de-entware-en-firmware-merlin/](https://elblogdelazaro.org/posts/2019-01-02-instalacion-de-entware-en-firmware-merlin/)  
[https://github.com/RMerl/asuswrt-merlin/wiki/Entware](https://github.com/RMerl/asuswrt-merlin/wiki/Entware)  


