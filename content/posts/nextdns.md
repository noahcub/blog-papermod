---
title: Nextdns
description: Configuración NextDNS en router Asus con firmware Merlin y en equipos Debian con NetworkManager
date: 2023-10-20 09:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Admin
   - Network
   - Asus
weight: 1
---

---
title: Configuración NextDNS en router Asus con firmware Merlin y en equipos Debian con NetworkManager
date: 2023-10-20 09:00:00 +0100
categories: [Network]
tags: [config, network]     # TAG names should always be lowercase
img_path: /assets/pictures/
author: <noah>
---
## Instalación de Nextdns firmware Merlin router ASUS

En el [github de Nextdns](https://github.com/nextdns/nextdns) tenemos toda la información para la instalación del NextDNS CLI Client en nuestro router. Este cliente emplea DNS-over-HTTPS.

**Instalación**

Nos conectamos por ssh al router y ejecutamos el script de instalación:

``` bash
sh -c 'sh -c "$(curl -sL https://nextdns.io/install)"'
```

Tenemos otra opción para realizar la configuración de NextDNS en nuestro router, esta vez empleando DNS-over-TLS:  
EN el [reddit de nextdns](https://www.reddit.com/r/nextdns/comments/x2k8f3/asus_merlin_noncli_configuration_guide/) se explica perfectamente.  

Si queremos saber la diferencia entre DNS-over-HTTPS y DNS-over-TLS en el siguiente [enlace se explica muy bien](https://www.cloudflare.com/es-es/learning/dns/dns-over-tls/).


## Instalación de Nextdns en Debian

Según la web de NextDNS se recomienda la siguiente instalación:  
Editar el fichero /etc/systemd/resolved.conf:

``` bash
[Resolve]
DNS=45.90.28.0#user_id.dns.nextdns.io
DNS=2a07:a8c0::#user_id.dns.nextdns.io
DNS=45.90.30.0#user_id.dns.nextdns.io
DNS=2a07:a8c1::#user_id.dns.nextdns.io
DNSOverTLS=yes
```
En Debian no venía preinstalado el servicio systemd-resolved y tuve que instalarlo. Pero surgió un problema: NextDNS no se lleva bien con NetworkManager cuando activamos alguna de las VPN de pago que tengo configuradas a través del protocolo OpenVPN. En esta [entrada del blog NextDNS](https://help.nextdns.io/t/h7yhxk1/setting-up-nextdns-on-ubuntu-in-resolved-conf-doesnt-work-with-vpns-dns) explican el mismo problema que yo tengo y con la solución que aportan a mi no me ha funcionado.  
En mi caso he optado por instalar NextDNS a través del cliente en línea de comando y ***cuando activo la VPN tengo que tener la precaución de parar NextDNS***. 

Revisamos que esté correctamente configurado el fichero  /etc/resolv.conf:  
Debería tener líneas similares a esta:

``` bash
nameserver 9.9.9.9
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 192.168.1.1
```
Es importante revisar esto si hemos tenido instalado systemd-resolved o si viene instalado por defecto. En ese caso es importante desinstalarlo si vamos a trabajar con VPN hasta que se resuelva el [bug](https://help.nextdns.io/t/h7yhxk1/setting-up-nextdns-on-ubuntu-in-resolved-conf-doesnt-work-with-vpns-dns).  
[Guía de desintalación de systemd-resolved](https://gist.github.com/zoilomora/f7d264cefbb589f3f1b1fc2cea2c844c).  

**Instalación de cliente NextDNS**
``` bash
sh -c 'sh -c "$(curl -sL https://nextdns.io/install)"'
```
Seguimos las instrucciones y ya debería funcionar.  

Comandos básicos:

``` bash
nextdns start
nextdns stop
nextdns restart
nextdns status
nextdns log
nextdns help
```

**Desinstalar**  
Ejecutamos el mismo comando y elegimos la opción Uninstall en el menú.
``` bash
sh -c 'sh -c "$(curl -sL https://nextdns.io/install)"'
```

**Uso de la VPN a través de NetworkManager**  
Mi operativa ahora es sencilla, NextDNS se inicia al arrancar el sistema.  

Si tengo que hacer uso de la VPN los pasos son los siguientes:

``` bash
sudo nextdns stop
```
2.- Activo la VPN a través del NetworkManager de Gnome  

3.- Hago el trabajo que sea.  

4.- Activo la VPN a través del NetworkManager de Gnome  

``` bash
sudo nextdns start
```

***  
Fuentes:  
***Asus***  
[https://github.com/nextdns/nextdns/wiki/AsusWRT-Merlin](https://github.com/nextdns/nextdns/wiki/AsusWRT-Merlin)  
[https://www.reddit.com/r/nextdns/comments/x2k8f3/asus_merlin_noncli_configuration_guide/](https://www.reddit.com/r/nextdns/comments/x2k8f3/asus_merlin_noncli_configuration_guide/)  
[https://www.cloudflare.com/es-es/learning/dns/dns-over-tls/](https://www.cloudflare.com/es-es/learning/dns/dns-over-tls/).  
***Debian***  
[https://help.nextdns.io/t/h7yhxk1/setting-up-nextdns-on-ubuntu-in-resolved-conf-doesnt-work-with-vpns-dns](https://help.nextdns.io/t/h7yhxk1/setting-up-nextdns-on-ubuntu-in-resolved-conf-doesnt-work-with-vpns-dns)  
[https://github.com/nextdns/nextdns/wiki](https://github.com/nextdns/nextdns/wiki)  
[https://gist.github.com/zoilomora/f7d264cefbb589f3f1b1fc2cea2c844c](https://gist.github.com/zoilomora/f7d264cefbb589f3f1b1fc2cea2c844c)
