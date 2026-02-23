---
title: IntelliJ IDE
description: Instalación de IDE IntelliJ
date: 2023-06-16 22:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Programming
weight: 1
---


---
title: Instalación de IDE IntelliJ
date: 2023-06-16 22:00:00 +0100
categories: [Programming]
tags: [software, programming]     # TAG names should always be lowercase
img_path: /pictures/
author: <noah>
---
## Instalación del IDE de programación IntelliJ

**Instalación mediante Flatpak**  
Es una buena opción a través del centro de software de Gnome pero a mi me dio problemas de bloqueos por lo que he decidido realizar la instalación desde la web de jetbrains.


**Descargamos la versión Comunity de la web**

[https://www.jetbrains.com/idea/download/#section=linux](https://www.jetbrains.com/idea/download/#section=linux)

Descomprimimos el paquete en /opt:

```bash
sudo tar -xzf ideaIU-*.tar.gz -C /opt 
```

Accedemos al directorio descomprimido:

``` bash
cd /opt/idea-IC-231.9011.34/bin
ejecutamos ./idea.sh
```

Por último podemos crear un enlace simbolico al path del sistema:

 ``` bash
 sudo ln -s /opt/idea-IC-231.9011.34/bin/idea.sh /usr/bin/ideaC
```

Para crear un enlace en el escritorio tenemos dos opciones:

***Primera opción y más complicada***  
Copiamos el icono al directorio de iconos:

 ``` bash
sudo cp IntelliJ.svg /usr/share/icons/
 ```
y generamos el fichero IntelliJ.desktop en /usr/share/applications con el siguiente contenido:

 ``` bash
 [Desktop Entry]
Version=1.0
Type=Application
Name=IntelliJ Comunity
GenericName=IntelliJ
Comment=Launch IntelliJ
Icon=IntelliJ
Categories=Development;
Exec=ideaC
TryExec=ideaC
Terminal=false
```

***Segunda opción y más sencilla***  
Abrimos la aplicación idea.sh y en el menú principal:

``` bash
Tools | Create Desktop Entry
```


***
Fuentes:  
[https://www.jetbrains.com/help/idea/installation-guide.html#standalone](https://www.jetbrains.com/help/idea/installation-guide.html#standalone)

