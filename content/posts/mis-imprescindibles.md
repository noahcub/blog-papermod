---
title: Software imprescindible
description: Mi software imprescindible
date: 2023-02-02 14:00:00 +0100
categories:
   - Debian
   - Fedora
tags:
   - Admin
weight: 1
---

## System  
- [ ] quitar entradas antiguas de UEFI
- [ ] [Instalarción Zsh](/posts/zsh/index.html) 
    - [ ] Alias .zshrc [(fichero .zshrc)](/assets/files/zshrc)
- [ ] firewall-config y firewall-applet (ojo añadir firewall-applet al arranque del sistema)
- [ ] Instalación conky [(fichero .conkyrc)](/assets/files/conkyrc)
- [ ] Traductor de consola (sudo apt install translate-shell)


## Apps 
- [ ] [Configuración Flatpak](/posts/Flatpak/index.html)
- [ ] Timeshift
- [ ] Deja-dup
- [ ] Insync
- [ ] Nextcloud
- [ ] Joplin (Flatpak)
- [ ] Thunderbird o Geary (Actualmente estoy con Geary)
    - [ ] Idioma thunderbird
- [ ] Libreoffice
    - [ ] Idioma en Libreoffice - OK
- [ ] Kooha (Flatpak)
- [ ] Teams
- [ ] Telegram
- [ ] Boxes de Gnome
- [ ] Virtual box 

## Network
- [ ] Configurar claves ssh con NAS principal
- [ ] Configurar claves ssh con NAS secundario
- [ ] Configurar accesos smb al NAS principal
- [ ] Configurar accesos smb al NAS secundario a través de Zerotier o Tailscale
	- [ ] Con tailscale el recurso compartido en smb es:
		smb://xxx.xxx.xxx.xxx/Recurso_compartido
- [ ] Configurar claves ssh con ROUTERS
- [ ] Configurar el cliente Wireguard de nuestra VPN al NAS (para debian):
    - [ ] sudo apt install wireguard
    - [ ] Copiamos el fichero wg0.conf generado por el servidor a la carpeta /etc/wireguard
    - [ ] sudo wg-quick up wg0 - Conexión a la VPN
    - [ ] sudo wg-quick down wg0 - Desconexión a la VPN
- [ ] Configurar VPN de pago en Gnome
    - [ ] Instalar antes el paquete network-manager-openvpn-gnome
- [ ] Configuración ZeroTier (ultima versión da fallo en Debian testing)
- [ ] Configuración Tailscale
- [ ] Configuración NextDNS
  - [ ] curl -fsSL https://tailscale.com/install.sh | sh (en la web de Tailscale se detalla)
	- [ ] Instalar extensión Gnome: Tailscale Status

## Desktop
- [ ] Primeros pasos con Gnome (https://itsfoss.com/things-to-do-after-installing-fedora/)
	- [ ] Tweeks
	- [ ] Gnome extensions
	- [ ] Extension manager (está como paquete en Flathub)
	- [ ] Minimizar y Maximizar
	- [ ] Night-light settings
- [ ] Cambiar primer dia calendario ([Generar locales Debian](/posts/locales/index.html))
- [ ] Añadir accesos directos Office Online
- [ ] Nuevo documento en plantillas de nautilus
- [ ] SaveDesktop - Backup de la configuración de escritorio

## Programming
- [ ] visual studio code
- [ ] Python entornos virtuales


