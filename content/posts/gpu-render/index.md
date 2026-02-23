---
title: Problemas con Nvidia
description: Problemas renderizado GPU Nvidia
date: 2023-02-19 08:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Admin
weight: 1
---

## Problemas al ejecutar algunos programas con renderizado gpu

Algunos programas generan errores de visualización debido al renderizado de GPU con drivers Nvidia. En la mayoría lo podemos deshabilitar:

**VISUAL STUDIO CODE**
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
  
**TEAMS**  
Modificar el fichero

~/.config/Microsoft/Microsoft Teams/desktop-config.json  
Cambiamos  
```bash 
"disableGpu":false (por defecto la opción es FALSE)
por 
"disableGpu":true
```
  
**THUNDERBIRD**  
En la configuración hay que deshabilitar la aceleración por hardware:  
![foto](thunderbird.png)  


***   
Fuentes:  


