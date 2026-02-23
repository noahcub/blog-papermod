---
title: Backups a USB automático
description: Backup carpetas USB automaticamente al conectar al equipo
date: 2024-01-13 08:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Admin
weight: 1
---

### Script de backup con rsync

Con este pequeño script  hacemos el backup del USB del trabajo a nuestro disco duro:  
	Origen:  /ruta origen  
	Destino: /ruta destino  
	OJO - cuando tenemos espacios en los nombres hay que usar '\' para que el script sepa que es un espacio  

``` bash
#!/bin/bash
<< 'Comment'
	Opciones rsync: 
	--delete: borrar los archivos que fueron borrados de la carpeta origen en la carpeta destino
	-a: mantiene el usuario, grupo, permisos, fecha y hora, así como los enlaces simbólicos
	-v: la información imprimida durante la ejecución del programa será mucho más detallada,
	-h: nos da las tasas de transferencia y el tamaño de los archivos en unidades razonables
	-u: evitar copiar archivos que ya tenemos en la carpeta de destino que no has sido modificados en la carpeta de origen
Comment

rsync --progress --stats --delete  -avhiu /media/user/Nuevo\ vol/Origen /home/user/Destino
```

### Configuración con reglas UDEV  

Primero debemos obtener el idProduct y el idVendor del nuestro usb
``` bash
lsusb
Bus 002 Device 003: ID 0781:5581 SanDisk Corp. Ultra
Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
```
idVendor = 0781  
idProduct = 5581  

Con estos datos creamos un fichero .rules:
``` bash
sudo nano /etc/udev/rules.d/10.backup_usb.rules
```
``` bash
SUBSYSTEM=="block", ACTION=="add", ATTRS{idVendor}=="0781", ATTRS{idProduct}=="5581", SYMLINK+="external", RUN+="/home/user/backup_usb.sh"
```

Por último, recargamos las reglas udev para que el sistema ejecute el script al enchufar nuestro pendrive:  
``` bash
udevadm control --reload
```
Este método funcionaria de maravilla para usb normales. El problema es que mi usb del trabajo está encritado con bitlocker y cuando se ejecuta la regla udev todavía no está montada la partción del usb porque antes tenemos que introducir la contraseña de bitlocker, por lo que no funciona mi backup automático.

### Configuración con systemd

La solución al problema anterior es crear un servicio systemd que ejecute mi script de backup cuando se monta la partición que nos interesa.  

Creamos nuestro backup_usb.service en /home/user/.config/systemd/user:
``` bash
cat backup_usb.service
[Unit]
Description=Backup pendrive trabajo
Requires=media-label-user.mount
After=media-label-user.mount

[Service]
ExecStart=/home/user/Apps/backup_usb.sh

[Install]
WantedBy=media-label-user.mount
```

Para buscar las media label:
``` bash
sudo systemctl list-units -t mount
``` 
Aqui aparecerá una etiqueta similar a esta entre otras muchas: 

``` bash
media-user-Work.mount  
```
Por último habilitamos nuestro servicio:  
``` bash
systemctl --user enable backup_usb.service
```
Al crear el enlace simbólico nos dirá el sistema que estamos creando un servicio con una dependencia que no existe:
``` bash
Unit /home/user/.config/systemd/user/backup_usb.service is added as a dependency to a non-existent unit media-user-Work.mount.
```
No importa porque cuando se ejecute el servicio al insertar el pendrive debería funcionar correctamente ya que la unidad se crea en ese momento.  



***  
Fuentes:  
***Systemd***  
[https://askubuntu.com/questions/25071/how-to-run-a-script-when-a-specific-flash-drive-is-mounted](https://askubuntu.com/questions/25071/how-to-run-a-script-when-a-specific-flash-drive-is-mounted)


