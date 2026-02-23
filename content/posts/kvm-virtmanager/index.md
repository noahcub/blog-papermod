---
title: KVM y VirtManager
description: Instalación de KVM y Virt Manager en Fedora
date: 2023-07-19 18:00:00 +0100
categories:
   - Fedora
   - Debian
tags:
   - Admin
weight: 1
---

## Instalación de Entware en firmware Merlin

Fedora con Gnome trae instalado por defecto Gnome-Boxes. La verdad es que está genial pero tiene algunas carencias, como por ejemplo la conectividad de red.  
Con Gnome Boxes solo podemos acceder a nuestra máquina virtual desde el host pero no podemos acceder desde la red local o contactar con la red local desde la máquina virtual. Para eso vamos a instalar y configurar KVM Y Virt Manger.

Requisitos

- Verificamos si tenemos la virtualización activa. Si no lo estuviera debemos acceder a la UEFI (BIOS) y activarla.

 ``` bash
grep -E --color '(vmx|svm)' /proc/cpuinfo
 ```
![kvm-1](kvm-1.png)

Verificamos que el módulo KVM del kernel esté cargado:

``` bash
lsmod | grep -i kvm
```
![kvm-2](kvm-2.png)

Instalación de los paquetes:
``` bash
sudo dnf install -y qemu-kvm libvirt virt-install bridge-utils
```

Instalamos Virt-manager que es un gestor gráfico que facilita mucho el trabajo:
``` bash
sudo dnf install -y virt-manager
```

Módulos de virtualización adicionales:
``` bash
sudo dnf install -y libvirt-devel virt-top libguestfs-tools guestfs-tools
```

Iniciamos y habilitamos el daemon de virtualización:
``` bash
sudo systemctl start libvirtd
sudo systemctl enable libvirtd
sudo systemctl status libvirtd
```
![kvm-3](kvm-3.png)

Ahora crearemos una red puente a nuestro sistema para poder acceder a la red local:

Accedemos a la configuración de redes de QEMU/KVM:

![kvm-7](kvm-7.png)

Y configuramos el nombre.
Forward to: Physical device... 
Device: En mi caso he puesto la interfaz wifi: wlo1

El resto se configura según gustos del usuario:

![kvm-8](kvm-8.png)


Si tenemos máquinas virtuales creadas con Gnome Boxes podemos usarlas a través de Virt Manager y adaptar las conexiones de red a nuestras necesidades. 
Gnome Boxes guarda sus máquinas en: ~/.local/share/gnome-boxes/images

Podemos importar el disco de almacenamiento de estas máquinas a Virt Manager
![kvm-4](kvm-4.png)
![kvm-5](kvm-5.png)
![kvm-6](kvm-6.png)

Y configuramos la red eligiendo el bridge network que hemos creado:

![kvm-9](kvm-9.png)

y ya deberíamos poder acceder con nuestra máquina virtual a los equipos de la red local o viceversa.


***  
Fuentes:  
[https://www.linuxtechi.com/how-to-install-kvm-on-fedora-step-by-step/](https://www.linuxtechi.com/how-to-install-kvm-on-fedora-step-by-step/)  
[https://computingforgeeks.com/how-to-create-and-configure-bridge-networking-for-kvm-in-linux/?expand_article=1](https://computingforgeeks.com/how-to-create-and-configure-bridge-networking-for-kvm-in-linux/?expand_article=1)  


