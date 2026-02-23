---
title: Gsconnect (kdeconnect para Gnome)
description: Instalación y configuración de GSconnect
date: 2023-12-21 11:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Admin
weight: 1
---

## GSconnect  

**Instalación y configuración de GSconnect**

GSConnect es una implementación completa de KDE Connect especialmente para GNOME Shell con integración de Nautilus, Chrome y Firefox.  No depende de la aplicación de escritorio KDE Connect y no funcionará si está instalada.

KDE Connect permite que los dispositivos compartan contenido de forma segura, como notificaciones o archivos, y otras funciones como mensajería SMS y control remoto.  El equipo de KDE Connect cuenta con aplicaciones para Linux, BSD, Android, Sailfish, iOS, macOS y Windows.

Esp preciso seguir estos pasos en Debian para que nos conecte correctamente, ya que por experiencia propia de otra forma no funciona en algunas ocasiones:

Si ha estado instalado y nos ha dado problemas, eliminar todo rastro de la aplicación en el ordenador y en el móvil.

``` bash
sudo apt autoremove --purge gnome-shell-extension-gsconnect
```
Revisamos las carpetas ~/.config y ~/.cache y borramos cualquier resto de gsconnect.

Instalar el paquete .deb con apt

``` bash
sudo apt install gnome-shell-extension-gsconnect
```

Instalamos la extensión desde el gestor de extensiones de gnome:

![gsconnect-1](gsconnect-1.png)

Verificar que ha sido todo correcto.  

Reiniciar el ordenador.  

Instalar en el móvil kde connect  

En el móvil refrescar para ver dispositivos y debería aparecer el ordenador para enlazar.  

Aceptar y dar permisos en el móvil a la aplicación.  

Por último, tenemos que dar permisos en firewalld al servicio de GSconnect, no olvidando crear la regla de forma permanente.

``` bash
firewall-cmd --permanent --zone=public --add-service=gsconnect
```

***
Fuentes:  
[https://userbase.kde.org/KDEConnect#Troubleshooting](https://userbase.kde.org/KDEConnect#Troubleshooting)

