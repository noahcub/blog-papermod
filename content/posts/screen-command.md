---
title: Comando "screen"
description: Uso del comando screen para ejecutar procesos en segundo plano
date: 2023-02-06 08:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Admin
weight: 1
---

## Qué es y cómo funciona el comando Screen en Linux


Hablamos del programa **Screen**, que permite en los sistemas **GNU**/**Linux**, abrir múltiples instancias de terminal dentro de una sola sesión. De esta manera, si salimos de una de las instancias de terminal, el proceso que se ejecute en dicha terminal no se interrumpirá y continuará en segundo plano.

### ¿En qué consiste el comando Screen?

**Screen**, según indica su página de [**man**](https://linux.die.net/man/1/screen), es un administrador de ventanas en pantalla completa, que multiplexa un terminal en varios procesos, cada proceso asociado a una nueva terminal.

Cuando se utiliza el comando **Screen**, este crea una única ventana con una terminal en ella (o un comando especificado) de forma independiente. Por lo que, en cualquier momento, podemos crear nuevas ventanas con otros programas.

Permite también obtener una lista de las ventanas activas, activar o desactivar el registro de salida, copiar y pegar texto en las ventanas, mostrar el historial, cambiar entre ventanas, etcétera.

Para usuarlo sólo hemos de escribir “screen”

```bash
screen
```

Existe la posibilidad de asignar un nombre a una nueva sesión, como se muestra en el ejemplo, utilizando el parámetro “-S”

```bash
screen -S nombre-de-sesión
```

Si nos queremos desvincular de una sesión hemos de utilizar la siguiente combinación de teclas:

```bash
Ctrl+a d
```

Para volver a una sesión ya existente debemos utilizar el parámetro “-r”
```bash
screen -r
```
***
Fuentes:  

