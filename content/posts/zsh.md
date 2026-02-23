---
title: Zsh
description: Instalación y configuración de zsh
date: 2023-02-01 16:00:00+02:00
categories:
   - Fedora
   - Debian
tags:
   - Admin
---

## Instalación y configuración de zsh con oh-my-zsh

**Instalación zsh**
Dependiendo nuestro sistema operativo, el comando será el siguiente:
``` bash
# Debian
sudo apt install git zsh util-linux-user
# Fedora
sudo dnf install zsh git
```
Clonamos el repositorio de oh-my-zsh
``` bash
git clone https://github.com/ohmyzsh/ohmyzsh.git ~/.oh-my-zsh
```
Usamos la primera plantilla para el fichero .zshrc
``` bash
cp ~/.oh-my-zsh/templates/zshrc.zsh-template ~/.zshrc
```
Cambiamos la terminal por defecto de nuestro usuario
``` bash
sudo chsh -s /bin/zsh user_____
```
**Instalación del tema** [Powerlevel10k](https://github.com/romkatv/powerlevel10k)
``` bash
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ~/.oh-my-zsh/custom/themes/powerlevel10k
echo 'source ~/.oh-my-zsh/custom/themes/powerlevel10k/powerlevel10k.zsh-theme' >>~/.zshrc
```
Modificamos el fichero .zshrc
``` bash
ZSH_THEME="robbyrussell" 
reemplazarlo por 
ZSH_THEME="powerlevel10k/powerlevel10k"
```
[Fuentes recomendadas para el tema ](https://github.com/romkatv/powerlevel10k#fonts)MesloLGS NF
[Enlace en mi github](/assets/files/fonts_zsh/MesloLGS_NF.zip) 
Copiamos las fuentes a su ubicación y configuramos Gnome terminal con la fuente recomendada
``` bash
/usr/share/fonts/truetype
```
Reiniciar la termninal, si no arranca la configuración inicial, siguiente comando
``` bash
p10k configure
```
**Instalación de los plugins**
``` bash
plugins=(
	git
	sudo
	web-search
	history
	zsh-autosuggestions
	zsh-syntax-highlighting
	zsh-completions
	zsh-dircolors-solarized
)
```
Los únicos plugin que requiere instalación manual es zsh-autosuggestions:  
[zsh-autosuggestions](https://github.com/zsh-users/zsh-autosuggestions/blob/master/INSTALL.md)  
[zsh-completions](https://github.com/zsh-users/zsh-completions)  
[sh-syntax-highlighting](https://github.com/zsh-users/zsh-syntax-highlighting/blob/master/INSTALL.md)  
[zsh-dircolors-solarized](https://github.com/joel-porquet/zsh-dircolors-solarized)  
Clonamos los repositorios y añadimos los nombres al apartado plugins del fichero .zshrc:
```
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
git clone https://github.com/zsh-users/zsh-completions ${ZSH_CUSTOM:=~/.oh-my-zsh/custom}/plugins/zsh-completions  
git clone --recursive https://github.com/joel-porquet/zsh-dircolors-solarized $ZSH_CUSTOM/plugins/zsh-dircolors-solarized  
```
Este último plugin el zsh-dircolors-solarized, despues de añadirlo a la sección plugins, es necesario ejecutar el siguiente comando para establecer los valores por defecto: **setupsolarized**.   
El resto de plugins simplemente hay que añadirlo a la sección plugins de .zshrc:
[sudo](https://github.com/ohmyzsh/ohmyzsh/tree/master/plugins/sudo)
[web-search](https://github.com/ohmyzsh/ohmyzsh/tree/master/plugins/web-search)
[history](https://github.com/ohmyzsh/ohmyzsh/tree/master/plugins/history)

***
Fuentes:  
[https://terminaldelinux.com/terminal/introduccion/instalacion-zsh/](https://terminaldelinux.com/terminal/introduccion/instalacion-zsh/)   
[https://blog.linuxitos.com/post/instalar-zsh-y-tema-powerlevel10k-fedora-33](https://blog.linuxitos.com/post/instalar-zsh-y-tema-powerlevel10k-fedora-33)  
[https://travis.media/top-10-oh-my-zsh-plugins-for-productive-developers/#20210719-sudo](https://travis.media/top-10-oh-my-zsh-plugins-for-productive-developers/#20210719-sudo)

