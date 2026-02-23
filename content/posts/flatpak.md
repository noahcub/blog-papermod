---
title: Flatpak
description: Instalación y uso básico de flatpak
date: 2023-02-01 14:00:00+02:00
#image: borg-1.png
categories:
   - Fedora
   - Debian
tags:
   - Admin
weight: 1
---


## Soporte Flatpak en Debian 11 Bullseye  

Información en la [web oficial de Flatpak](https://flatpak.org/setup/Debian/).  

Aunque, a mi modo de ver, es importante instalar el software con la paquetería .deb, en ocasiones es necesario usar flatpak porque el software no está disponible en otro formato.  

**Instalamos el paquete flatpak**  
Dependiendo nuestro sistema operativo, el comando será el siguiente:
``` bash
# Debian
apt install flatpak
# Fedora
dnf install flatpak
```

**Instalamos el plugin para la tienda de software. En este caso la tienda de Gnome.**

``` bash
apt install gnome-software-plugin-flatpak
```

**Agregamos el repositorio de Flathub** 

``` bash
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
```

Para buscar una aplicación en Flathub:

``` bash
flatpak search firefox
```
Listado de aplicaciones flatpak instaladas
``` bash
flatpak list
```
Listado limpio que solo enumera las aplicaciones
``` bash
flatpak list --app
```
Para eliminar un flatpak, primero debemos obtener el ID de la aplicación y ejecutar el siguiente comando
``` bash
flatpak uninstall --delete-data org.mozilla.firefox
```
Para eliminar un flatpak, primero debemos obtener el ID de la aplicación y ejecutar el siguiente comando
``` bash
flatpak uninstall --delete-data org.mozilla.firefox
```
Elimina todas la librerías que no están en uso por ninguna app instalada, o las versiones antiguas residuales que ya han sido actualizadas
``` bash
flatpak uninstall --unused
```
Para eliminar completamente Flatpak del sistema ejecutamos:
``` bash
sudo flatpak repair
```
Después podemos seguir con los comandos:
``` bash
sudo apt autoremove flatpak
sudo apt purge flatpak
```

