---
title: Drivers Nvidia
description: Configuración gráfica Nvidia en Fedora
date: 2023-02-02 18:00:00+02:00
#image: borg-1.png
categories:
   - Fedora
tags:
   - Admin
weight: 1
---

## Instalación de drivers NVIDIA en Fedora

Verificamos si en el administrador de software de Gnome aparecen los drivers Nvidia:

![Foto.png](gnome-software-driver-nvidia-1024x666.png)
En caso afirmativo podemos saltarnos el siguiente paso.
Si no aparecen los drivers de Nvidia quiere decir que tenemos que actualizar el repositorio RPMFusion

**Instalación de forma gráfica desde administrador de software**

Instalamos el software necesario a través de DNF:
Instalamos primeramente el repositorio free:
``` bash
sudo dnf install https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm
```
Y después instalamos el non-free que es donde se alojan los drivers de Nvidia:
``` bash
sudo dnf install https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
sudo dnf upgrade -y
```
Si hacemos la instalación de forma gráfica instalamos “Nvidia Linux Graphics Driver” y “Nvidia X Server Settings”.  
Los demás no. Como se ve en la captura anterior.  
  
**Instalación desde la terminal**
``` bash
sudo dnf -y install kmod-nvidia
sudo dnf install xorg-x11-drv-nvidia-cuda
```
Puedes ejecutarlos juntos o uno y después el otro. El primero instala los drivers generales y el segundo comando el oporte para CUDA(cuda son los núcleos de Nvidia, una gráfica tiene miles normalmente a día de hoy, sería el equivalente a los núcleos de las CPU).

De hecho, puedes instalar solo los drivers y prescindir del segundo programa, pero es mejor ambos.  

**Problemas al ejecutar algunos programas**  
Algunos programas dan problemas al ejecutarse con el renderizado de la GPU activada. Pasos para desactivarlo:

***VISUAL STUDIO CODE***
- Primera opción  
Dentro de Visual Studio abrimos la paleta (Ctrl+Shift+P).
Ejecutamos:
`Preferences: Configure Runtime Arguments`
Este comando abre el fichero de configuración "argv.json" y añadimos el siguiente texto
```bash 
"disable-hardware-acceleration": true 
```
y reiniciamos Visual Studio Code  

- Segunda Opción  
Modificar el fichero "argv.json" de Visual Studio desde la terminal:
```bash 
nano ~/.vscode/argv.json
```
Añadimos el mismo texto que decíamos antes
```bash 
"disable-hardware-acceleration": true
```
  
- Tercera Opción  
Modificar el lanzador de la aplicación de escritorio en Gnome:
Editamos el fichero
`/usr/share/applications/code.desktop`.

Cambiamos
```bash 
`Exec=/usr/share/code/code --unity-launch %F`

por
 
`Exec=/usr/share/code/code --disable-gpu --unity-launch %F`
```
  
***TEAMS***  
Modificar el fichero

~/.config/Microsoft/Microsoft Teams/desktop-config.json  
Cambiamos  
```bash 
"disableGpu":false
por 
"disableGpu":false
```
  
***THUNDERBIRD***  
En la configuración hay que deshabilitar la aceleración por hardware:  
![foto](thunderbird.png)  


***   
Fuentes:  
[https://yourgeekweb.com/es/2022/06/18/como-instalar-los-drivers-de-nvidia-en-linux-fedora/](https://yourgeekweb.com/es/2022/06/18/como-instalar-los-drivers-de-nvidia-en-linux-fedora/)  

