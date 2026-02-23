---
title: Systemd
description: Crear un servicio con systemd
date: 2023-02-21 22:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Admin
weight: 1
---

## Crear un servicio con systemd

### Crear un script

Antes que nada necesitamos crear un script que no es más que un simple archivo, que debe contener algo muy importante para arrancar y es #!/bin/bash, así que usamos un editor, en mi caso nano para crearlo:
```bash
nano /usr/local/sbin/servicios
```

Dentro vamos a colocar lo que necesitamos quedando con la siguiente estructura:

```bash
#!/bin/bash
contenido del script
```

Una vez que lo guardamos con F2, le damos permisos de ejecución.

```bash
chmod +x /usr/local/sbin/servicios
```

### Crear el servicio con systemd

Es importante que el nombre al final termine con .service, dado que así lo entenderá systemd. Recordá que también debe tener permisos (otra forma es # chmod 777 servicio.service)  

```bash
nano /etc/systemd/system/servicios.service
```

El contenido será el siguiente, teniendo en cuenta que la primera de las instrucciones especifica que se debe iniciar tras sección syslog.target.


ExecStart=/usr/local/sbin/servicio.service se da la ruta en dónde realmente está el script a ejecutar.

Después viene el tipo de servicio que hay varios, pero para este caso será:

[Service]
Type=forking

Por último, la sección [Install] nos dice en qué runlevel se ejecutará. En el modo multiusuario o en el clásico sysv, que sería el runlevel 3.

El contenido entonces deberá ser algo como:

```bash
[Unit]
Description=Lanza servicios varios
After=syslog.target

[Service]
Type=forking
ExecStart=/usr/local/sbin/servicios

[Install]
WantedBy=multi-user.target
```

Una vez este todo configurado debemos recargar.

```bash
sudo systemctl daemon-reload
```

Para lanzar el servicio simplemente hacemos:

```bash
sudo systemctl start servicios.service
```

Para habilitarlo al inicio y que se lance automáticamente:

```bash
sudo systemctl enable servicios.service
```

Y finalmente para ver el estado podemos hacer:

```bash
sudo systemctl status servicios.service
```
