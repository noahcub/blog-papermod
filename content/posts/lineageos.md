---
title: LineageOS y SafetyNet
description: Configurar SafetyNet en LineageOS para activar el pago por NFC
date: 2023-09-25 16:00:00 +0100
categories:
   - Android
tags:
   - Smartphone
weight: 1
---

## Habilitar el safetynet en el móvil con ROM personalizada

**ROM personalizada LINEAGEOS**  
Cuando nuestro teléfono ha llegado al fin de su vida útil en lo que se refiere a actualizaciones de seguridad, he decidido emplear una ROM personalizada que nos permite tener nuestro sistema actualizado y operativo. 
Entre las que he probado están [Pixel Experience](https://get.pixelexperience.org/) y [LineageOS](https://lineageos.org/) entre otras.

Al final me he decido por LineageOS ya que me da mucha confianza.

Al usar estas ROM se genera un problema secundario, mi aplicación de pagos a través de NFC dice que el sistema tiene una ROM personalizada y por seguridad no permite realizar el pago.

Tenemos varias soluciones:

1.- Instalar MAGISK con un módulo de safetynet. Tal vez, si probara hoy me funcione, pero la segunda opción han sido 5 minutos y me ha funcionado a la primera.

2.- Modificar el fichero  **/system/build.prop** del teléfono móvil.

He optado por esta segunda opción porque en su día lo intenté con MAGISK y no lo hice funcionar, desconociendo el por qué.

La esencia consiste en modificar las siguientes líneas del fichero **/system/build.prop** y cambiar el valor:

```bash
ro.secure=0 sustituirlos por ro.secure=1
ro.debuggable=1 sustituirlos por ro.debuggable=0
```

Para hacer este cambio tenemos que acceder al móvil por adb, que debe estar correctamente instalado en nuestro ordenador.  

Habilitamos las opciones de desarrollador en el móvil:  
Accedemos a Información del teléfono ---> Número de compilación (pulsamos 5 veces)

Después:  
Sistema ---> **Opciones de desarrollador**

Activamos **Depuración por USB** y **Depuración como Superusuario**.  

Conectamos el teléfono al ordenador y activamos **Transferencia de Archivos** en lugar de **Solo carga**.

Ahora nos vamos a la terminal de nuestro ordenador y testeamos que detecta el teléfono:

```bash
[noah@envy ~]$ 
╰─ adb devices
* daemon not running; starting now at tcp:5037
* daemon started successfully
List of devices attached
967fd02	device
```
Vemos que detectamos el teléfono, procedemos con el cambio: 
```bash
[noah@envy ~]$ 
╰─ adb root   
restarting adbd as root
[noah@envy ~]$ 
╰─ adb remount 
remount succeeded
[noah@envy ~]$ 
╰─ adb pull /system/build.prop .         
/system/build.prop: 1 file pulled, 0 skipped. 0.9 MB/s (7671 bytes in 0.008s)
[noah@envy ~]$ 
╰─ 
```
Ya tenemos el fichero build.prop y ahora vamos a modificar las dos líneas que nos interesan. El comando **sed** nos permite sustituir una cadena de texto por otra:

```bash
sed -i "s/ro.secure=0/ro.secure=1/" build.prop
sed -i "s/ro.debuggable=1/ro.debuggable=0/" build.prop
```
Volvemos a subir el fichero al teléfono móvil:
```bash
 adb push build.prop /system/build.prop
```

Y listo, reiniciamos el teléfono móvil y ya podemos instalar nuestra aplicación de pagos a través del NFC y debería funcionar.  

Para simplificar el trabajo podemos hacer un pequeño script que lo haga todo a la primera:

```bash
#!/bin/bash
adb root
adb remount
adb pull /system/build.prop .
sed -i "s/ro.secure=0/ro.secure=1/" build.prop
sed -i "s/ro.debuggable=1/ro.debuggable=0/" build.prop
adb push build.prop /system/build.prop
rm build.prop
```
LineageOS hace actualizaciones semanales de la ROM. Cada vez que actualicemos tenemos que ejecutar nuestro pequeño script, activando las opciones de desarrollador, etc. por eso he decidido hacer actualizaciones mensuales mas o menos para no tener que estar pendiente de esto.


***
Fuentes:  

Modificar fichero build.prop  
[https://github.com/OmarAhmed-A/MakeLineageOSSecure](https://github.com/OmarAhmed-A/MakeLineageOSSecure)  
[https://forum.xda-developers.com/t/safetynet-on-lineageos-20-microg.4558065/](https://forum.xda-developers.com/t/safetynet-on-lineageos-20-microg.4558065/)

Magisk  
[https://topjohnwu.github.io/Magisk/install.html](https://topjohnwu.github.io/Magisk/install.html)  
[https://community.fxtec.com/topic/2537-magisk-install-step-by-step-root/](https://community.fxtec.com/topic/2537-magisk-install-step-by-step-root/)  
[https://telegra.ph/Instalar-Magisk-v24-en-nuestra-ROM--Install-Magisk-on-our-ROM-03-11](https://telegra.ph/Instalar-Magisk-v24-en-nuestra-ROM--Install-Magisk-on-our-ROM-03-11)
