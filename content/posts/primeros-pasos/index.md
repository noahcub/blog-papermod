---
title: Primeros pasos con Fedora Gnome
description: Instalación y configuración de Fedora Workstation Gnome
date: 2023-02-02 18:00:00+02:00
#image: borg-1.png
categories:
   - Fedora
tags:
   - Admin
weight: 1
---

## Primeros pasos después de instalar Fedora o Debian

NOTA: Aunque la mayor parte de este post se centra en Fedora, debo decir que Debian para mí siempre será la mejor, por ese motivo he añadido unas notas sobre instalación en Debian.
Configurar DNF para descargas más rápidas:
``` bash
sudo nano /etc/dnf/dnf.conf
```

y añadimos la siguiente línea:
``` bash
max_parallel_downloads=10
```

Realizamos una acutalización completa del sistema:
``` bash
sudo dnf upgrade -y
```

Habilitamos los respostorios de RPM Fusion:
``` bash
sudo dnf install https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm
sudo dnf install https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
```

Compatibilidad con ciertos formatos comprimidos, así como OpenSSL para usar la extensión GSConnect:  
``` bash
sudo dnf install openssl unrar p7zip p7zip-plugins
``` 

Principales codecs multimedia:
``` bash
sudo dnf install gstreamer1-plugins-bad-free-extras gstreamer1-plugin-openh264 gstreamer1-plugins-good-extras mozilla-openh264 gstreamer1-plugins-bad-free-fluidsynth gstreamer1-plugins-bad-free-wildmidi gstreamer1-svt-av1
sudo dnf install vlc
``` 
***ACTUALIZACIÓN 28/07/2025***
He tenido problemas de reproducción de videos H.265 del sistema CCTV. Para solucionarlo he tenido que instalar los siguientes paquetes según [este hilo de los foros de Fedora](https://discussion.fedoraproject.org/t/cleanest-way-to-install-all-video-codecs-on-fedora-kde-40/134005/23):  
Esto creo que no es necesario porque los repositorios rpmfusion ya deberían estar instalados de los pasos anteriores:  
```bash
sudo dnf install https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm
sudo dnf install https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
```
```bash
sudo dnf install libavcodec-freeworld --allowerasing
sudo dnf install intel-media-driver --allowerasing
```

Por defecto Fedora ofrece la versión libre para el códec de vídeo H264, que resulta insuficiente. Con la anterior orden ampliamos el soporte, pero si usamos Firefox debemos efectuar un pequeño cambio: Menú > Complementos y temas > Plugins, y allí activaremos el códec Open H264 de Cisco. Esta información ha sido obtenida de la web [thecheis.com](https://thecheis.com/2023/08/09/puesta-a-punto-intel-nuc-fedora/).  

Añadimos el repositorio de Flathub:
``` bash
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
```
***Solo para Debian*** Si queremos tener disponible el software de faltpak en el administrador de software de gnome debemos instalar el siguiente paquete:
``` bash
sudo apt install gnome-software-plugin-flatpak
```


En la instalación Fedora no pregunta por el nombre del host. Ahora podemos modificarlo:
``` bash
sudo hostnamectl set-hostname "New_Custom_Name"
```

Instalamos las aplicaciones esenciales para personalizar Gnome:
``` bash
sudo dnf install gnome-tweaks gnome-extensions-app
```
Instalamos también Extension Manager desde el administrador de Software de Gnome (es una aplicación Flatpak).  

Instalamos Flatseal y Warehouse, que son aplicaciones de Flatpak para gestionar permisos y almacenamientos de estas aplicaciones. 
![flatpak-admin.png](flatpak-admin.png)

Extensiones instaladas:
![Foto.png](extensiones-instaladas.png)

Habilitamos Maximizar y Minimizar en las ventanas:

![Foto.png](add-minimize-button-to-windows.png)

Habilitar/deshabilitar los informes de errores:
![Foto.png](automatic-problem-reporting-feature.png)

Configuraciones de energía:
![Foto.png](power-settings.png)

Habilitamos luz nocturna para reducir la fatiga visual:
![Foto.png](night-light-settings.png)

Ordenación de directorios antes de los ficheros:
![Foto.png](sort-folder-before-files.png)

Configuraciones de papelera de reciclaje:
![Foto.png](automatically-delete-trash-content.png)

***Nota: Lista de flatpak que he instalado a mayores de lo que había:***
``` bash
Warp                                    app.drey.Warp                                         0.6.1      stable        flathub   system
teams-for-linux                         com.github.IsmaelMartinez.teams_for_linux             1.3.19     stable        flathub   system
Flatseal                                com.github.tchx84.Flatseal                            2.1.0      stable        flathub   system
IntelliJ IDEA Community                 com.jetbrains.IntelliJ-IDEA-Community                 2023.2.5   stable        flathub   system
Extension Manager                       com.mattjakeman.ExtensionManager                      0.4.3      stable        flathub   system
Warehouse                               io.github.flattool.Warehouse                          1.3.0      stable        flathub   system
Kooha                                   io.github.seadve.Kooha                                2.2.4      stable        flathub   system
SaveDesktop                             io.github.vikdevelop.SaveDesktop                      2.9        stable        flathub   system
Photoflare                              io.photoflare.photoflare                              1.6.13     stable        flathub   system
Joplin                                  net.cozic.joplin_desktop                              2.12.19    stable        flathub   system
Geary                                   org.gnome.Geary                                       44.1       stable        fedora    system
Kasts                                   org.kde.kasts                                         23.08.1    stable        fedora    system
``` 

***Nota: Lista de paquetes instalados por dnf:***
``` bash
    8  sudo dnf install vlc conky zsh
   14  sudo dnf install teams
   17  sudo dnf install gnome-tweaks gnome-extensions-app
   19  sudo dnf install timeshift
   20  sudo dnf install firewall-config firewall-applet
   28  sudo dnf install translate-shell
   31  sudo dnf install nvme-cli
   38  sudo dnf install etherwake
   39  sudo dnf install ether-wake
   40  sudo dnf install net-tools
   43  sudo dnf install thunderbird # Ya no lo uso, ahora uso Geary
   55  sudo dnf install wireguard-tools
   72  sudo dnf install code
  149  sudo dnf install util-linux-user
  456  sudo dnf install codium
  794  sudo dnf install nextcloud-client-nautilus nextcloud-client
 1013  sudo dnf install brave-browser
 1016  sudo dnf install photoflare
 1295  sudo dnf install telegram-desktop
 1965  sudo dnf install steam
 2291  sudo dnf install dconf-editor
 2348  sudo dnf install htop
 2351  sudo dnf install gstreamer1-plugins-bad-free-extras gstreamer1-plugin-openh264 gstreamer1-plugins-good-extras mozilla-openh264 gstreamer1-plugins-bad-free-fluidsynth gstreamer1-plugins-bad-free-wildmidi gstreamer1-svt-av1
 2352  sudo dnf install openssl unrar p7zip p7zip-plugins
```
***Nota: Lista de paquetes instalados por apt:***
``` bash
sudo apt install zram-tools
sudo apt install flatpak
sudo apt install gnome-software-plugin-flatpak
sudo apt autoremove gnome-games
sudo apt install nextcloud-desktop nautilus-nextcloud

```

***
Fuentes:  
[https://itsfoss.com/things-to-do-after-installing-fedora/](https://itsfoss.com/things-to-do-after-installing-fedora/)  
[https://thecheis.com/2023/08/09/puesta-a-punto-intel-nuc-fedora/](https://thecheis.com/2023/08/09/puesta-a-punto-intel-nuc-fedora/)



