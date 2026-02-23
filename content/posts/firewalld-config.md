---
title: Firewalld configuración
description: Configuración de FirewallD
date: 2023-12-18 16:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Admin
   - Network
weight: 1
---

## Uso de FirewallD  

**NOTA: En Joplin tengo un manual más completo**

Manual de ayuda:  
``` bash
firewall-cmd --help
```

FirewallD funciona con systemd, por lo que se emplean todos los comandos de systemd:
``` bash
systemctl enable firewalld

systemctl start firewalld

systemctl restart firewalld

systemctl status firewalld

```

***Zonas de firewall***
Zonas de Firewalld.

De modo predeterminado Firewalld tiene diferentes tipos de zonas. Cada una tiene un distinto nivel de seguridad.

***drop***
    Descripción: Para redes públicas. Se descartan los paquetes de red entrantes no solicitados. Los paquetes entrantes que están relacionados con las conexiones de red salientes son aceptados. Se permite el tráfico de salida. Ésta sería la zona más segura. Ideal para paranoicos.
    Servicios habilitados: ninguno.
    Política predeterminada: DROP.

***block***
    Descripción: Para redes públicas. Se rechazan los paquetes de red entrantes no solicitados. Los paquetes entrantes que están relacionados con las conexiones de red salientes son aceptados. Se permite el tráfico de salida.
    Servicios habilitados: ninguno.
    Política predeterminada: REJECT.

***public***
    Descripción: Es la zona predeterminada. Para redes públicas. Sólo se aceptan algunas conexiones entrantes selectas y el resto son rechazadas. Es ideal para áreas públicas.
    Servicios habilitados: ssh y dhcpv6-client.
    Política predeterminada: REJECT.

***external***
    Descripción: Para redes externas.Sólo se aceptan algunas conexiones entrantes selectas y el resto son rechazadas. Es ideal para redes externas con enmascaramiento habilitado especialmente para ruteadores.
    Servicios habilitados: ssh.
    Política predeterminada: REJECT.

***dmz***
    Descripción: Para en sistemas zona desmilitarizada con acceso limitado a la red interna. Sólo se aceptan algunas conexiones entrantes selectas y el resto son rechazadas.
    Servicios habilitados: ssh.
    Política predeterminada: REJECT.

***work***
    Descripción: Para trabajo u oficina. Se confía en los sistemas que coexisten en la misma red pero sólo se aceptan algunas conexiones entrantes selectas y el resto son rechazadas.
    Servicios habilitados: ssh, ipp-client y dhcpv6-client.
    Política predeterminada: REJECT.

***home***
    Descripción: Para el hogar. Se confía en los sistemas que coexisten en la misma red pero sólo se aceptan algunas conexiones entrantes selectas y el resto son rechazadas. Básicamente igual que work.
    Servicios habilitados: ssh, ipp-client, mdns, samba-client y dhcpv6-client.
    Política predeterminada: REJECT.

***internal***
    Descripción: Para redes internas. Se confía en los sistemas que coexisten en la misma red pero sólo se aceptan algunas conexiones entrantes selectas y el resto son rechazadas.
    Servicios habilitados: ssh, ipp-client, mdns, samba-client y dhcpv6-client.
    Política predeterminada: REJECT.

***trusted***
    Descripción: Todas las conexiones son aceptadas.
    Servicios habilitados: todos.
    Política predeterminada: ACCEPT.  

***Primeros comandos***  
Si solo queremos recargar la configuración:
``` bash
firewall-cmd --reload
```

El firewall dispone de diferentes zonas, cada una con sus particularidades, para verlas:
``` bash
firewall-cmd --get-zones
```
Para ver la que tenemos por defecto:
``` bash
firewall-cmd --get-default-zone
```

Servicios habilitados en la zona activa:
``` bash
firewall-cmd --list-services
```

***Cambios temporales y permanentes***  
Los cambios realizados con firewall-cmd sin la opción --permanent se aplicarán de inmediato sin guardarse en la configuración.  
Los cambios realizados con firewall-cmd con la opción --permanent se guardan de inmediato en la configuración pero sólo aplicarán después de ejecutar firewall-cmd con la opción --reload o systemctl restart firewalld.  

***Cambios de zona por defecto***
``` bash
firewall-cmd --set-default-zone=public
```

Añadir un servicio a una zona:
``` bash
firewall-cmd --permanent --zone=public --add-service=gsconnect
```
Si nos surge un problema tipo ransomware o similar que esté sincronizando nuestros ficheros con el NAS o la nube podemos tomar medidas extremas:  
Activar el módo pánico:
``` bash
firewall-cmd --panic-on
```
Desactivar:
``` bash
firewall-cmd --panic-off
```
Verificar estado:
``` bash
firewall-cmd --query-panic
```

Y un largo etc. de opciones....




***
Fuentes:  
[https://blog.alcancelibre.org/staticpages/index.php/como-firewalld](https://blog.alcancelibre.org/staticpages/index.php/como-firewalld)  
[https://www.redhat.com/sysadmin/how-to-configure-firewalld](https://www.redhat.com/sysadmin/how-to-configure-firewalld)

