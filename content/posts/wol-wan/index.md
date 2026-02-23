---
title: Wake On Lan WAN
description: Configurar WOL desde Internet
date: 2023-02-02 19:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Asus
---

## Configuración WOL desde Internet en router Asus

**Instalación y configuración del firewallD**

El primer paso es hacer una redirección de puertos en el router:
Elegimos un puerto aleatorio externo (que sea alto) y redireccionamos al puerto 9 a la IP 192.168.1.254:

![Foto 1 puertos](redirect-puertos.png)

Accedemos al router por ssh y creamos una nueva entrada en la tabla arp del router para reenviar el paquete WOL al broadcast de la red FF:FF:FF:FF:FF:FF (a todas las direcciones MAC):  

``` bash
arp -s 192.168.1.254 ff:ff:ff:ff:ff:ff
```
Verificamos que se ha creado la nueva entrada:
``` bash
 admin@(none):/jffs/scripts# arp
? (192.168.1.155) at <incomplete>  on br0
? (XXX.XXX.178.1) at XX:XX:XX:XX:fc:81 [ether]  on eth0
? (192.168.1.254) at ff:ff:ff:ff:ff:ff [ether] PERM on br0  <----
? (192.168.1.58) at XX:XX:XX:XX:4c:c4 [ether]  on br0
? (192.168.1.251) at XX:XX:XX:XX:5d:0a [ether]  on br0
? (192.168.1.170) at XX:XX:XX:XX:0e:f3 [ether]  on br0
? (192.168.1.40) at XX:XX:XX:XX:8a:58 [ether]  on br0
```

Ahora simplemente es necesario configurar nuestra aplicación WOL para enviar el magic packet:
- DIRECCION MAC: La de nuestro dispositivo que deseamos levantar
- HOSTNAME/IP: myDDNS.asuscomm.com
- PUERTO: Según el ejemplo 4231

Esta configuración del router desaparecerá con el siguiente reinicio. Para dejarla permanente creamos un pequeño script que haga este trabajo en cada reinicio:
Los router Asus tienen un almacenamiento permanente en /jffs
Creamos un directorio dentro de /jffs llamado scrits y creamos el siguiente fichero:

``` bash
cat <<EOF > wan-wol.sh
#!/bin/sh

scriptName="/jffs/scripts/\$(basename $0)"
myIp="192.168.1.254"

/usr/bin/logger -t "\${scriptName}" \$$ "arp -s \${myIp} ff:ff:ff:ff:ff:ff"
arp -s \$myIp ff:ff:ff:ff:ff:ff
/usr/bin/logger -t "\${scriptName}" \$$ "Check: \$(arp | grep $myIp)"
EOF
```
Verificamos que esté bien:
``` bash
cat /jffs/scripts/wan-wol.sh
```
Resultado correcto:
``` bash
#!/bin/sh
scriptName="/jffs/scripts/$(basename $0)"
myIp="192.168.1.254"

/usr/bin/logger -t "${scriptName}" $$ "arp -s $myIp ff:ff:ff:ff:ff:ff"
arp -s $myIp ff:ff:ff:ff:ff:ff
/usr/bin/logger -t "${scriptName}" $$ "Check: $(arp | grep $myIp)"
```
Los hacemos ejecutable:
``` bash
admin@(none):/jffs/scripts# chmod a+x wan-wol.sh
```

``` bash
master@(none):/tmp/home/root# nvram show 2>&1 | grep script_usbmount
script_usbmount=
```

``` bash
master@(none):/jffs/scripts# nvram set script_usbmount="/jffs/scripts/wan-wol.sh"
master@(none):/jffs/scripts# nvram commit
```

``` bash
master@(none):/jffs/scripts# nvram show 2>&1 | grep script_usbmount
script_usbmount=/jffs/scripts/wan-wol.sh
```
Después de reiniciar el router debería haberse ejecutado el script para crear la entrada en la tabla arp:
![Foto 1 puertos](/redirect-puertos-2.png)


***
Fuentes:  
[https://andblu.blogspot.com/2016/08/configure-wol-from-internet-wan-asus.html](https://andblu.blogspot.com/2016/08/configure-wol-from-internet-wan-asus.html)  

