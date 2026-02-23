---
title: Reinstalar Debian con LVM
description: Reinstalar Debian en particiones LVM ya existentes sin perder datos
date: 2024-02-08 08:00:00 +0100
categories:
   - Debian
tags:
   - Admin
weight: 1
---

## Instalar Debian en particiones LVM encriptadas ya existentes conservando datos

Arrancamos con el médio de instalación de Debian y seleccionamos Opciones avanzadas - Instalación experta

![debian.png](debian.png)  
![debian2.png](debian2.png)  

Avanzamos en el proceso de instalación normalmente y en Load Installer components from CD cargamos los siguientes:  
**crypto-dm-modules and rescue-mode**

![debian3.png](debian3.png)  

Continuamos con la instalación y nos detenemos antes de Detect disks:

![debian4.png](debian4.png)  

Accedemos a una consola con **ctrl+alt+f2** y realizamos la carga de nuestro LVM:  

Cargamos los módulos necesarios (**por motivo que desconozco este comando no funciona pero no es relevante para la instalación**)

``` bash
depmod -a
```
Listamos las particiones del sistema:  
``` bash
blkid
```

Desbloqueamos nuestro volumen LVM con **cryptsetup**:  

``` bash
cryptsetup luksOpen /dev/vda3 debian-encriptado
Enter passphrase for /dev/vda3:
```
![debian5.png](debian5.png)  

Abrimos nuestro VG volume group y verificamos que esté disponible en dev/mapper/debian-encriptado:  

``` bash
vgchange -ay
ls /dev/mapper
```
![debian6.png](debian6.png)  

Presionamos **ctrl+alt+f1** y continuamos con la instalación normalmente:  

Ahora ya tenemos disponibles nuestros volúmenes para instalar nuevamente el sistema:  
![debian7.png](debian7.png)  

En mi caso, formateo todas las particiones excepto el volumen /home que es donde estan mis datos de usuario y efi que está compartido con Windows:  
Como se ve tengo el siguiente particionado:  
vda1 - uefi - 100MB   				/boot/efi  
vda2 - boot - 1GB  					/boot  
vda3 - luks - 20GB  
	VG debian - LV home - 5GB 		/home  
	VG debian - LV root - 15GB		/root  

![debian8.png](debian8.png)  

Continuamos con la instalación del sistema normal y nos detenemos antes de **Install the GRUB bootloader to a hard disk.**  
Accedemos nuevamente a la consola con **ctrl+alt+f2** para configurar **initramfs**:  

Nos interesa la partición **TYPE="crypto_LUKS"**, que en mi caso es /dev/vda3:  
Listamos las particiones del sistema:  
``` bash
blkid
cryptsetup luksDump /dev/vda3 |grep -F UUID
```
Tenemos que modificar el fichero /target/etc/crypttab.  
``` bash
cryptsetup luksDump /dev/vda3 |grep -F UUID >> /target/etc/crypttab
```
![debian9.png](debian9.png)  

Modificamos **crypttab** dejandolo así: 
``` bash
# <target name> <source device>		<key file>	<options>
debian-encriptado UUID=3dfb977c-8368-4146-b7b9-5a2426aa4347 none luks,discard
```

Volvemos a la instalación con **ctrl+alt+f1** y procedemos a instalar Grub bootloader.  

Si algo ha ido mal en la generación de initramfs podemos iniciar nuevamente desde nuestro usb de debian y ejecutar un Rescue mode, seguimos los pasos de carga de nuestros volúmnes LUKS, etc y a la hora de generamos initramfs manualmente con el siguiente comando:

``` bash
 update-initramfs -u -k all
```
Si hay algún error nos lo dirá el comando y podemos corregir lo que sea neceario.  

## Instalar Debian en particiones LVM NO encriptadas ya existentes conservando datos  

En este caso es todo muy sencillo. Seleccionamos particionado manual y el instalador de Debian nos detectará la estructura de particiones que tiene el disco y simplemente tenemos que indicar que volumenes queremos que se formateen y cuales no.  
Debemos dejar el sistema configurado como se muestra en la imangen y en ningún momento es preciso salir del instalador a una consola. (NOTA: esta imagen está aprovechada del apartado donde se hacía con encriptado, pero es exactamente lo mismo).

![debian8.png](debian8.png)  


***
Fuentes:  
[https://www.blakecarpenter.dev/installing-debian-on-existing-encrypted-lvm/](https://www.blakecarpenter.dev/installing-debian-on-existing-encrypted-lvm/)  
[https://consolematt.wordpress.com/2013/06/19/reinstalling-debian-on-existing-lukslvm-partition/](https://consolematt.wordpress.com/2013/06/19/reinstalling-debian-on-existing-lukslvm-partition/)  
[https://www.reddit.com/r/debian/comments/1599rkt/how_to_reinstall_debian_12_with_existing/](https://www.reddit.com/r/debian/comments/1599rkt/how_to_reinstall_debian_12_with_existing/)  


