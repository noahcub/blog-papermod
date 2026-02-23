---
title: Python
description: Notas sobre Python
date: 2023-12-20 18:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Programming
weight: 1
---

## Notas sobre configuraciones para uso de Python

**Instalación de Pip**  

Pip es un sistema de gestión de paquetes utilizado para instalar y administrar paquetes de software escritos en Python.  
Además de instalar pip aprovechamos para instalar software de desarrollo de python muy util.  

```bash
sudo apt install python3-pip python-dev build-essential python3-venv
```

El módulo venv proporciona soporte para crear «entornos virtuales» ligeros con sus propios directorios de ubicación, aislados opcionalmente de los directorios de ubicación del sistema.  
Cada entorno virtual tiene su propio binario Python (que coincide con la versión del binario que se utilizó para crear este entorno) y puede tener su propio conjunto independiente de paquetes Python instalados en sus directorios de ubicación.  
En resumen, los entornos virtuales nos permiten tener un entorno de desarrollo en cada proyecto sin llenar el sistema de dependencias y paquetes instalados.  
Para crear un entorno virtual dentro del proyecto que estemos:   

```bash
python3 -m venv entorno_virtual
```

De esta forma creamos una carpeta llamada entorno_virtual dentro del proyecto donde se almacenaran todos los archivos de python para ese entorno.  
Al abrir un proyecto con un entorno virtual, VSCode nos lo detecta automáticamente lo activa directamente.  
Si no se activa directamente, o vamos a trabajar fuera de VSCode lo activamos nosotros:

```bash
source ruta/al/entorno/virtual/bin/activate
```
Para desactivarlo:
```bash
deactivate
```

Si queremos eliminar un entorno virtual:
```bash
rm -rf ruta/al/entorno/virtual
```

**Nota SUPERIMPORTANTE**  
Si vamos a usar el entorno virtual dentro de un proyecto en github tenemos que excluir esa carpeta de git. Para ello creamos un fichero .gitignore dentro de la carpeta entorno_virtual y excluimos todo con '*':
```bash
nano .gitignore
*
```
![python.png](python.png)


Una vez tengamos pip instalado podemos instalar los paquetes que necesitemos para nuestros proyectos:
```bash
pip install jupyter pandas request numpy etc.....
```

Para actulizar pip: 
```bash
pip install --upgrade pip
```

***
Fuentes:  
[]https://code.tutsplus.com/es/tutorials/understanding-virtual-environments-in-python--cms-28272](https://code.tutsplus.com/es/tutorials/understanding-virtual-environments-in-python--cms-28272)  
[https://gee.es/2023/05/17/como-creo-un-entorno-de-desarrollo-con-env-en-vscode/](https://gee.es/2023/05/17/como-creo-un-entorno-de-desarrollo-con-env-en-vscode/)


