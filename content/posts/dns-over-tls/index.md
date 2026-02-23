---
title: DNS Over TLS
description: DNS Over TLS con systemd-resolved y NextDNS. Nuestro firewall online
date: 2024-10-18 16:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Admin
   - Network
ShowToc: false
TocOpen: true
---

Según su [web](https://nextdns.io/), NextDNS ofrece un firewall para la Internet moderna. NextDNS protege de todo tipo de amenazas a la seguridad, bloquea anuncios y rastreadores en sitios web y aplicaciones, y brinda una Internet segura y supervisada para niños, en todos los dispositivos y en todas las redes.  
Me parece un servicio genial por 20€ al año que ofrece mucha seguridad a la hora de navegar por internet.   


## Configuración de DNS privado en Fedora
En nuestro sistema Fedora, estarán conviviendo NetworkMananger con systemd-resolved, por tanto, el primer paso que debemos hacer es indicarle a NetworkManager que la resolución de DNS se va a realizar con systemd-resolved.  
Editamos el fichero **/etc/NetworkManager/conf.d/dns.conf** y añadimos el siguiente contenido:

``` bash
[main]
dns=systemd-resolved
```

En versiones actuales del servicio systemd-resolved el fichero de configuración resolved.conf se encuentra en /etc/systemd/resolved.conf.d/, anteriormente se encontraba en /etc/systemd/

Creamos el fichero **resolved.conf** en la ruta **/etc/systemd/resolved.conf.d**:

Tenemos como ejemplo los DNS de quad9, que funcionan muy bien:
``` bash
[Resolve]
DNS=9.9.9.9#dns.quad9.net
DNSOverTLS=yes
```

En nuestro caso vamos a usar los DNS de NetxDNS, para ello accedemos a nuestro panel de usuario de NextDNS y copiamos la configuración:
``` bash
[Resolve]
DNS=xx.xx.xx.xx#AAAAAAAA.dns.nextdns.io
DNS=xx.xx.xx.xx#AAAAAAAA.dns.nextdns.io
DNS=xx.xx.xx.xx#AAAAAAAA.dns.nextdns.io
DNS=xx.xx.xx.xx#AAAAAAAA.dns.nextdns.io
DNSOverTLS=yes
```

En Fedora ya debería estar el enlace simbólico de /etc/resolv.conf. Lo comprobamos y sino procedemos a crearlo:
``` bash
sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```

El servicio systemd-resolved debería estar habilitado, sino lo habilitamos:

``` bash
sudo systemctl status systemd-resolved.service
sudo systemctl enable systemd-resolved.service
```

Podemos habilitar el registro de logs para detectar errores en la resolución de DNS:

``` bash
sudo resolvectl log-level debug
```

``` bash
journalctl -u systemd-resolved -f
```
Como en nuestro sistema tenemos conviviendo systemd-resolved con NetworkManager, debemos reiniciar ambos para que todo funcione correctamente:

``` bash
sudo systemctl restart systemd-resolved.service && sudo service NetworkManager restart
```

Verificamos si está bien configurada la resolución de nombres:

``` bash
resolvectl status
```

Por último, si accedemos a nuestro panel de NextDNS veremos que ya estamos trabajando con sus servidores.

![dns-systemd.png](dns-systemd.png)

**Nota importante**: En mi caso tuve problemas con la resolución de nombres porque tengo configuradas varias redes en mi equipo. La red que me generó problemas era la que crea TailScale, la red **tailscale0**.   
En el panel de control de Tailscale tenía configurada la resolución de nombres a través de un perfil diferente de NextDNS, entonces al acceder al panel de control de NextDNS, por motivos que desconozco mi portátil Fedora hacía la resolución de nombres a través del perfil configurado en Tailscale en lugar del perfil configurado en el equipo.  
No he descubierto porque lo hace así, la solución fue sencilla, a través de la extensión de Tailscale Status de Gnome habilito la red de Tailscale cuando es necesario para conectarme a mis NAS de forma remota.

***ACTUALIZACIÓN 26/07/2025***
En mi última configuración de Fedora 42 con KDE he tenido que seguir al pie de la letra la siguiente [guia](https://www.adityathebe.com/systemd-resolved-dns-over-tls/) para que funcione.  
Por el motivo que sea el fichero /etc/systemd/resolved.conf.d/resolved.conf no se lee por systemd-resolved y no se aplica la configuración.  
Si configuramos los datos de NEXTDNS en el fichero **/etc/systemd/resolved.conf**, todo comenzó a funcionar a la primera.
***
Fuentes:  
[https://nextdns.io/](https://nextdns.io/pricing)  
[https://www.adityathebe.com/systemd-resolved-dns-over-tls/](https://www.adityathebe.com/systemd-resolved-dns-over-tls/) 
 
[https://dev.to/archerallstars/using-dns-over-tls-on-opensuse-linux-in-4-easy-steps-enable-cloud-firewall-for-free-today-2job](https://dev.to/archerallstars/using-dns-over-tls-on-opensuse-linux-in-4-easy-steps-enable-cloud-firewall-for-free-today-2job)  

[https://docs.quad9.net/Setup_Guides/Linux_and_BSD/Ubuntu_22.04_%28Encrypted%29/#instructions](https://docs.quad9.net/Setup_Guides/Linux_and_BSD/Ubuntu_22.04_%28Encrypted%29/#instructions)
