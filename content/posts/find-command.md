---
title: Comando "find"
description: Buscar y eliminar archivos con find
date: 2023-02-06 08:00:00 +02:00
categories:
   - Fedora
   - Debian
tags:
   - Admin
weight: 1
---

## Qué es y cómo funciona el comando find en Linux

La sintáxis básica del comando “find” es:

find directorio criterio acción

1.  **Directorio**.\- define la ubicación desde la que se quiere empezar la búsqueda. Por ejemplo: /home/
2.  **Criterio**.\- se usa para seleccionar los archivos. Se pueden usar comodines. Por ejemplo: *.tmp
3.  **Acción**.\- se especifica aquí qué debe hacer el comando con los archivos que cumplan con el criterio indicado.

Para eliminar múltiples archivos del tipo que queramos:

```bash
 find . -name "archivo" -exec rm -rf {} \\;
```
o  
```bash
 find . -type f -name "archivo" -exec rm -rf {} \\;
```
La diferencia entre ambos comandos indicados arriba es que el primero localiza y borra archivos y directorios, y el segundo sólo archivos.

1.  **-name “archivo”**.\- se indica aquí qué estamos buscando. Se pueden usar comodines.
2.  **-exec rm -rf**.\- Ejecuta el comando indicado a continuación, es decir, tras el “-exec” insertamos el comando que se ejecutará con cada archivo encontrado. En este caso es “rm” con el modificador “-rf”, que significa borrar de forma recursiva sin preguntar.
3.  **-type f**: Permite filtrar para incluir sólo **f**(icheros) o **d**(irectorios).

### Ejemplos:

**Mucho mucho ojo al usar estos comandos como root**:

Buscar y borrar todos los archivos con extensión *.bak en el directorio en el que estás:
```bash
find . -type f -name "*.bak" -exec rm -f {} \\; 
```
Buscar todos los nombres de archivo que contengan la palabra “core” desde la raíz y eliminarlos:
```bash
find / -name core -exec  rm -f {} \\;
```
Buscar y eliminar los archivos *.bak desde el directorio actual pero pidiendo confirmación por cada archivo encontrado:
```bash
find . -type f -name "*.bak" -exec rm -i {} \\; 
```
Buscar y eliminar archivos ocultos en el directorio que estamos:
```bash
find -type f -name ".*" -exec rm -f {} \;
```
  
***
Fuentes:  

