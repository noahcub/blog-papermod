---
title: Borg Backups
description: Backups con borg en server y PC
date: 2025-08-21 13:40:36+02:00
#image: borg-1.png
categories:
   - Unraid
#   - Server
tags:
   - Backups
weight: 1
---

## Configuración de Backups con Borg  
  
Nuestro servidor de Unraid va a servir para guardar los backups de nuestras máquinas. En concreto vamos a guardar los backups de los equipos (portátiles y móviles) a través de Vorta, del VPS y del servidor Debian sanMi.  
Esta necesidad ha surgido por dos temas distintos:  
El primero es la necesidad de hacer backup de nuestros servidores secundarios. Podría instalar Duplicacy, que es el sistema que uso para hacer backup de unRaid en la cuenta de GoogleDrive pero visto lo bien que habla todo el mundo de borg vamos a probarlo una temporada.  
Segundo, los equipos de oficina estaban configurados con Gnome y usando la herramienta Deja-dup hacía los backups. El problema es que Deja-dup no funciona con KDE y me he visto obligado a emplear otra aplicación. Kbackup es una buena opción, pero no acaba de convencerme. Vorta me parece que es una opción excelente así que vamos a ello.  

### Instalación de borgserver  
  
Buscamos en aplicaciones Unraid el servidor borg:

![borg-1.png](borg-1.png)

``` bash
Repository: nold360/borgserver:latest
Network Type: Bridge
SSH: 2222
# Ubicación de las claves ssh
sshkeys:/mnt/user/appdata/borg/sshkeys/
# Ubicación de los backups
backup: /mnt/user/Backups/borg
```

Pulsamos en aplicar y no arranca el contenedor. El motivo es que si no hemos añadido alguna clave ssh antes no arrancará.  
En la [web del proyecto](https://hub.docker.com/r/nold360/borgserver) de hub.docker.com lo explica:
**!IMPORTANT!: The container wouldn't start the SSH-Deamon until there is at least one ssh-keyfile in this directory!**  

``` bash
Copiamos nuestra clave pública a la siguiente ruta:
/mnt/user/appdata/borg/sshkeys/clients
```
En el momento de hacer este manual tengo dos claves públicas, la del pc portátil y la del servidor sanmi:
```bash
➜  clients pwd
/mnt/user/appdata/borg/sshkeys/clients
➜  clients ls   
envy_kde.pub  sanmi.pub
```

Ahora si reiniciamos el contenedor debería arrancar sin problemas

![borg-2.png](borg-2.png)

### Instalación de Vorta Backup en Fedora  
  
En mi caso he instalado Vorta a través de Discover en formato flatpak.  
Iniciamos Vorta y comenzamos el procedimiento:  

Primero creamos nuestra clave ssh:

![borg-3.png](borg-3.png)

Una vez creada la clave ssh tenemos que copiarla a nuestro servidor borg a la siguiente ruta:
```bash
/mnt/user/appdata/borg/sshkeys/clients
```

Añadimos nuestro repositorio de Borg:

![borg-4.png](borg-4.png)

Es importante verificar correctamente los datos del repositorio. En mi caso:

```bash
PESTAÑA GENERAL:
Repository URL: ssh://borg@DIRECCION_IP_TAILSCALE:2222/./envy
Repository name: envy
Enter passphrase: XXXXXXXXX
PESTAÑA ADVANCED:
SSH Key: seleccionamos la clave ssh que hemos creado anteriormente
Encryption: Repokey-Blake2
```
El resto de opciones las dejamos por defecto.  
Planificamos la programación tanto de backups como de prune:

![borg-5.png](borg-5.png)

IMPORTANTE: En los Settings de Vorta debemos marcar **"Automatically start Vorta at login"** para que arranque al inicio.  

Con esto debería funcionar ya nuestro primer backup. Para restaurar es muy sencillo a través de Vorta. Procedemos a montar el backup que nos interese y realizamos la copia a nuestro sistema.  

### Configuración del cliente borgmatic en los servidores (modo consola)  
  
Esta parte es un poco más compleja porque se hace todo en modo consola, pero una vez configurada resulta todo muy sencillo.  
La configuración consiste en varios pasos (**Nota: las claves empleadas en este manual son ficticias**):  
- Instalación de **borgmatic**. Borgmatic nos permite realizar backups con borg a través de un sencillo fichero de configuración.
- Instalación de **gpg** y **pass** que nos harán falta para encriptar los  backups en destino.
- Creamos nuestra contraseña gpg para almacenar el password de encriptado de la copia de seguridad.
- Creamos nueva clave ssh para logearse en nuestro servidor destino de los backups.
- Configuramos nuestro fichero config.yaml para borgmatic.
- Creamos nuestra pass para encriptar la copia de seguridad
- Añadimos una entrada a crontab para programar los backups y las limpiezas.

### Instalación de borgmatic  
  
```bash
sudo apt install borgmatic
```

### Instalación de gpg y pass  
  
```bash
sudo apt install pass gpg

```

### Creación clave gpg  
  
Configuramos nuestra clave gpg:
```bash
sudo gpg --full-generate-key
```
Tipo de clave: predeterminada
![borg-client-1.png](borg-client-1.png)  
![borg-client-2.png](borg-client-2.png)  

Validez: sin caducidad
![borg-client-3.png](borg-client-3.png)  

Rellenamos nuestros datos personales y de correo:
![borg-client-4.png](borg-client-4.png)  

Nuestra contraseña para proteger la clave:
![borg-client-5.png](borg-client-5.png)  

Por último nos muestra un resumen de la clave creada:
![borg-client-6.png](borg-client-6.png)  

Si queremos ver nuevamente la clave ejecutamos el siguiente comando:
```bash
sudo gpg --list-secret-keys --keyid-format LONG
```
Nos genera la siguiente salida:
```bash
[sudo] password for XXXXXXXXXXXXX: 
/root/.gnupg/pubring.kbx
------------------------
sec   XXXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXXXX 2025-07-30 [SC]
      XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
uid                 [ultimate] xxxxxx XXXXXXXXXXXXXXX <XXXXXXXXXXXXXXX@XXXXXXXXXXXXXXX.com>
ssb   XXXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXXXX 2025-07-30 [E]
```

### Creación de claves ssh  
  
```bash
sudo ssh-keygen -o -a 100 -t ed25519
```
Ponemos el nombre de fichero que vamos a usar para almacenar la clave y el resto lo dejamos sin contraseña.
![borg-client-7.png](borg-client-7.png)  

Una vez tenemos nuestra clave ssh la pasamos al servidor borgserver de Unraid (tenemos varias opciones con scp, ssh-cp-id, o creando el fichero a mano y añadiendo el contenido):

```bash
# Servidor Unraid
cd /mnt/user/appdata/borg/sshkeys/clients
nano my_server.pub

# y pegamos el contenido de la clave ssh.pub
```
Posteriormente reiniciamos el servidor borg:


```bash
docker restart borgserver
###
docker logs borgserver
####
########################################################
 * Testing Volume BORG_DATA_DIR: /backup
 * Testing Volume SSH_KEY_DIR: /sshkeys
 * Checking / Preparing SSH Host-Keys...
########################################################
 * Starting SSH-Key import...
  ** Adding client envy_kde.pub with repo path /backup/envy_kde.pub
  ** Adding client my_server.pub with repo path /backup/my_server.pub
```
En la salida vemos que ya se ha añadido la nueva clave ssh a nuestro servidor borg.  

### Configuramos nuestro fichero config.yaml para borgmatic  
  
Generamos el fichero por defecto para borgmatic

```bash
sudo generate-borgmatic-config
# Hacemos una copia por seguridad
sudo cp /etc/borgmatic/config.yaml /etc/borgmatic/config.yaml.bak
# Editamos el fichero
```
Editamos el fichero: 
```bash
sudo nano /etc/borgmatic/config.yaml
```

Contenido definitivo del fichero de configuración de borgmatic:

```bash
# /etc/borgmatic/config.yaml
location:
  source_directories:
    - /home/mi_usuario
  repositories:
    - ssh://borg@MY_SERVER_IP_TAILSCALE:2222/./mi_nombre_del_repositorio
  exclude_caches: true
  exclude_patterns:
    - '*.pyc'
    - /home/*/.cache
storage:
  compression: auto,zstd
  encryption_passphrase: pass /super_admin@mi_compañía.com/borg-repokey
  archive_name_format: "{hostname}-{now}"

  ssh_command: ssh -i /root/.ssh/my_server_ssh_key
  # Number of times to retry a failing backup
  # Needs recent Borgmatic version
  retries: 5
  retry_wait: 5
retention:
  keep_daily: 3
  keep_weekly: 4
  keep_monthly: 12
consistency:
  checks:
    - disabled
    # Uncomment to regularly read all repo data
    # Needs recent Borgmatic version
    # - name: repository
    #   frequency: 4 weeks
    # - name: archives
    #   frequency: 8 weeks

  check_last: 3
```
Llegado a este punto ya está casi todo hecho, pero debemos prestar atención a esta parte del fichero:
  
**encryption_passphrase: pass /super_admin@mi_compañía.com/borg-repokey**
  
  
Tenemos que generar nuestra pass para encritar la copia de seguridad. Vamos a ello.  

### Creamos nuestra pass para encriptar la copia de seguridad  
  
```bash
sudo pass generate /super_admin@mi_compañía.com/borg-repokey 16
```
Nos pedirá la contraseña de nuestro gpg para encriptarla y nos la crea.  
Para ver lista de contraseñas:
```bash
sudo pass list
```

Si queremos ver la contraseña:
```bash
sudo pass list /super_admin@mi_compañía.com/borg-repokey 16
```

Si queremos editar la contraseña:
```bash
sudo pass edit /super_admin@mi_compañía.com/borg-repokey 16
```
Y con esto ya está creada y lista para se usada en nuestro fichero config.yaml de borgmatic.  

Verificamos que nuestro fichero config.yaml no contenga errores:
```bash
sudo validate-borgmatic-config -c /etc/borgmatic/config.yaml
```

### Primer backup  
  
El manejo de borgmatic en modo consola está muy bien explicado en la [web docs.borgbase.com](https://docs.borgbase.com/setup/borg/).  
```bash
sudo env "PATH=$PATH" validate-borgmatic-config
sudo env "PATH=$PATH" borgmatic init --encryption repokey-blake2
sudo borgmatic create --list --stats
```

Verificamos que lo ha creado:
```bash
sudo borgmatic list

ssh://borg@IP_My_server:2222/./my_repo: Listing archives
my_server-2025-07-30T04:22:14       Wed, 2025-07-30 04:22:17 [f920bbec8c5f1ff80cfb794b801f1a3d55b3a90a52047f37bf8035e57902fb51]
```

### Añadimos una entrada a crontab para programar los backups y las limpiezas.  
  
Vamos a programar nuestros backups y limpiezas a las 08.00 horas todos los días:
```bash
sudo crontab -e 

# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command
0 8 * * * /usr/bin/borgmatic --stats -v 0 2>&1
```
**INFORMACIÓN IMPORTANTE SOBRE EL COMANDO BORGMATIC**  
En el [repositorio de github borgmatic-collective](https://github.com/borgmatic-collective/borgmatic/blob/main/docs/how-to/set-up-backups.md) nos dice lo siguiente:  
If you omit create and other actions, borgmatic runs through a set of default actions: prune any old backups as per the configured retention policy, compact segments to free up space (with Borg 1.2+, borgmatic 1.5.23+), create a backup, and check backups for consistency problems due to things like file damage. For instance:

```bash
sudo borgmatic --verbosity 1 --list --stats
```
En resumen, cuando no añadimos otras opciones a borgmatica, éste ejecuta de forma automática por defecto las siguientes operaciones: **Prune, Compact, Backups y Check de backup**, lo que me parece ideal para añadir el comando en cron.
  
  
### Restaurar el backup  
  
Esta la segunda parte más importante. He realizado varias pruebas y todo ha funcionado correctamente. Para restaurar el backup primero hacemos un listado de los que tenemos y después montamos el backup en la ubicación deseada para restaurar los ficheros:

Primero listamos los ficheros creados con borgmatic:
```bash
sudo borgmatic list
```

Una vez sabemos el fichero que nos interesa podemos ver el contenido:
```bash
sudo borgmatic list --archive server-2020-04-01
```

Extracción completa de ficheros:
```bash
sudo borgmatic extract --archive my_server-2025-07-30T04:24:04 --destination /mnt/new-directory
```

Extracción de una parte solamente:
```bash
sudo borgmatic extract --archive my_server-2020-04-01 --path mnt/catpics --destination /mnt/new-directory
```

### Notificaciones del Backup usando apprise  
  
Instalamos el software necesario. Según su [github](https://github.com/caronc/apprise) Apprise permite enviar una notificación a casi todos los servicios de notificación más populares disponibles en la actualidad, como: Telegram, Discord, Slack, Amazon SNS, Gotify, etc.   

Instalación es sencilla:
```bash
sudo apt install apprise
```

Configuración de nuestro fichero borgmatic conf:
```bash
sudo nano /etc/borgmatic/config.yaml

#### AÑADIMOS ESTO AL FINAL de nuestro fichero de configuración
hooks:
  before_backup:
    - echo "Starting a backup job."

  after_backup:
    - echo "Backup created."
    - apprise -vv -t "✅ SUCCESS Backup My_Server" -b "$(cat /tmp/backup_run.log)" "mailtos://smtp.gmail.com:587?user=super_admin@gmail.com&pass=superpasssecreta&from=superadmin@gmail.com&to=superadmin@hotmail.com,tgram://bot_token:de_telegram/chat_id_telegram/"

  on_error:
    - echo "Error while creating a backup."
    - apprise -vv -t "❌ FAILED Backup My_Server" -b "$(cat /tmp/backup_run.log)" "mailtos://smtp.gmail.com:587?user=super_admin@gmail.com&pass=superpasssecreta&from=superadmin@gmail.com&to=superadmin@hotmail.com,tgram://bot_token:de_telegram/chat_id_telegram/"
```

En mi caso he configurado para que nos envíe dos notificaciones. La primera por correo electrónico y la segunda a Telegram.  
   
En la versión de borgmatic 1.8.4+ Apprise se integra de forma nativa con borgmatic, lo que permite una configuración mucho más limpia, tal y como se muestra en la siguiente ejemplo. Esta configuración yo no puedo usarla porque mi sistema tiene la versión borgmatic 1.7.7:
```bash
apprise:
    states:
        - start
        - finish
        - fail

    services:
        - url: mailtos://smtp.example.com:587?user=server@example.com&pass=YourSecurePassword&from=server@example.com&to=receiver@example.com
          label: mail
        - url: slack://token@Txxxx/Bxxxx/Cxxxx
          label: slack

    start:
        title: ⚙️ Started
        body: Starting backup process.

    finish:
        title: ✅ SUCCESS
        body: Backups successfully made.

    fail:
        title: ❌ FAILED
        body: Your backups have failed.
```
En la versión 1.8.9+, los logs de borgmatic son añadidos automaticamenta al cuerpo de las notificaciones de apprise. Me parece una colaboración impresionante. **Que ganas tengo de que actualice Debian a la nueva versión de borgmatic**.   
  
Por último, modificamos nuestro crontab para que al ejecutarse guarde la salida de las estadísticas en el fichero **/tmp/backup_run.log**. 
```bash
sudo crontab -e

#
#
#
30 8 * * * /usr/bin/borgmatic --stats -v 0 > /tmp/backup_run.log
```
Con esto, nuestro borgmatica ya debería notificarnos:

Correo:  
![borg-client-8.png](borg-client-8.png)
  
Telegram:  
![borg-client-9.png](borg-client-9.png)

### Notas finales a tener en cuenta  

En mi servidor sanmi tengo instalado [Fedora Server](https://fedoraproject.org/es/server/download). En este caso, la versión de borgmatic que nos acompaña es la versión 2.0.6 por lo que ya disponemos de las nuevas características para notificaciones y de un nuevo formato en el fichero config.yaml.  
  
Respecto a la configuración de **encryption_passcommand** en borgmatic, se me presenta un problema.  
Si programamos el backup con cron, no se ejecuta. El motivo es que cada vez que se va a ejecutar, el comando **pass** nos solicita nuestra contraseña de la clave gpg y si no la introducimos el resto no continúa. Entonces, para que los backups se realicen de forma automática sin intervención del usuario, la única forma que he conseguido hacerlo es poniendo la contraseña directamente en el fichero config.yaml.  

Configuración de mi fichero **config.yaml** en Fedora Server:

```bash
source_directories:
  - /home/AppData
  - /home/super_admin

repositories:
  - path: ssh://borg@100.100.100.100:2222/./sanMi
    label: sanMi

exclude_caches: true
exclude_patterns:
  - '*.pyc'
  - /home/*/.cache

compression: auto,zstd
encryption_passphrase: My_super_password
#encryption_passcommand: pass /super_admin@gmail.com/borg-repokey
archive_name_format: "{hostname}-{now}"

ssh_command: ssh -i /root/.ssh/sanmi
retries: 5
retry_wait: 5

keep_daily: 3
keep_weekly: 4
keep_monthly: 12

checks:
  - name: repository
    frequency: 4 weeks
  - name: archives
    frequency: 8 weeks

check_last: 3

apprise:
  states:
    - start
    - finish
    - fail

  services:
    - url: mailtos://smtp.gmail.com:587?user=super_admin_@gmail.com&pass=super_password&from=super_admin@gmail.com&to=destino@hotmail.com
      label: mail
    - url: tgram://123456789:AAE39Q5XXXXXXXXXXXXXXX_XXXXXXXXXXXXXXXXXXXxPGrI/XXXXXXXXXXXX/
      label: telegram

  start:
    title: ⚙️ Starrted Backup
    body: Starting backup process

  finish:
    title: ✅ SUCCESS Backup SanMi
    body: Backup SanMi success

  fail:
    title: ❌ FAILED Backup SanMi
    body: Backups SanMi failed

```


***   
Fuentes y enlaces de interés que ayudaran a complementar esta guía:  

[Borgserver en hub.docker.com](https://hub.docker.com/r/nold360/borgserver)    
[Guía muy completa, base de casi todo el manual](https://willbrowning.me/automated-offsite-encrypted-backups-with-borg-backup/)  
[Guía en español con detalle de uso contraseña cifrado](https://es.linux-console.net/?p=9687)  
[Tutorial bilito para configurar borg en Unraid](https://tutoriales.bilito.eu/automatizar-backups-de-nuestro-unraid-con-borg/)  
[Guía en español configuración pass y claves gpg para almacenar esas pass](https://es.unixlinux.online/ix/1002011444.html)  
[Configuración de pass como password-manager en consola](https://linuxconfig.org/how-to-organize-your-passwords-using-pass-password-manager)  
[Documentación Borgbase.com](https://docs.borgbase.com/)  
[Github de borgmatic-collective con ejemplos varios](https://github.com/borgmatic-collective/borgmatic/blob/main/docs/how-to/set-up-backups.md)  
[Notificaciones con apprise](https://github.com/caronc/apprise)  
[Github de borgmatic-collective notificaciones apprise](https://github.com/borgmatic-collective/docker-borgmatic)  
[Doc notificaciones apprise Telegram](https://github.com/caronc/apprise/wiki/Notify_telegram)  

