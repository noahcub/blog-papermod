---
title: Locales Debian
description: Instalación y configuración idiomas Debian
date: 2023-02-02 14:00:00+02:00
#image: borg-1.png
categories:
   - Debian
tags:
   - Admin
weight: 1
---

## Instalación nuevos locales en Debian
Revisamos los locales que tenemos generados en el sistema:
``` bash
locale -a
```
Podemos generar más editando /etc/locale.gen y descomentando la línea que nos interesa:
``` bash
es_ES.UTF-8 UTF-8
```

Generamos nuevamente los locales con:
``` bash
locale-gen
```
Hacemos el cambio en "Region & Language"

![Region](1.png)

![vista](2.png)
