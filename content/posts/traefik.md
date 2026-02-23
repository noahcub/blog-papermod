---
title: Traefik v3 y Crowdsec
description: Configuración de traefik v3 con crowdsec
date: 2026-01-23 07:00:00 +01:00
categories: 
    - Nas
tags: 
    - Unraid
    - Software
    - Config
weight: 1
---

## Traefik y crowdsec
  
Hasta hace poco tenía en funcionamiento traefik con crowdsec usando las plantillas de unraid. Hice varios manuales sobre la instalación pero por motivos que desconozco crowdsec no parseaba las líneas de logs de traefik y por tanto no hacía absolutamente nada.  
He decicido hacer una instalación limpia desde 0 y aquí va.  
Gran parte de este manual se ha hecho usando [Perplexity](https://www.perplexity.ai/). Debo decir que tiene mucho que mejorar, pero nos marca unas bases buenas para empezar.

### Preparación del entorno
Lo primero que vamos a hacer es preparar nuestro entorno de directorios:  

Directorios de traefik y crowdsec:
``` bash
mkdir -p /mnt/user/appdata/traefik/{letsencrypt,log}
mkdir -p /mnt/user/appdata/crowdsec/data
```

Ficheros de configuración y logs de traefik:
``` bash
touch /mnt/user/appdata/traefik/letsencrypt/acme.json
chmod 600 /mnt/user/appdata/traefik/letsencrypt/acme.json

touch /mnt/user/appdata/traefik/traefik.yml
touch /mnt/user/appdata/traefik/dynamic_conf.yml

touch /mnt/user/appdata/traefik/log/access.log
chmod 644 /mnt/user/appdata/traefik/log/access.log
```

Fichero de configuración de crowdsec. Dentro de la carpeta de configuración de crowdsec creamos el fichero acquis.yaml:
``` bash
touch /mnt/user/appdata/crowdsec/config/acquis.yaml
```

### Docker-compose
Sigo usando Unraid. Nos vamos a la pestaña compose y creamos nuestro stack de docker:

**docker-compose.yml**
``` bash
services:
  traefik:
    image: traefik:v3.0
    container_name: traefik
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    ports:
      - "1880:80"
      - "18443:443"
    environment:
      - CF_DNS_API_TOKEN=${CF_DNS_API_TOKEN} # API TOKEN DE CLOUDFLARE
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /mnt/user/appdata/traefik/letsencrypt/acme.json:/letsencrypt/acme.json
      - /mnt/user/appdata/traefik/traefik.yml:/etc/traefik/traefik.yml:ro
      - /mnt/user/appdata/traefik/dynamic_conf.yml:/etc/traefik/dynamic_conf.yml:ro
      - /mnt/user/appdata/traefik/log:/var/log/traefik # Volumen para persistencia de logs
    networks:
      - cloud
      
  crowdsec:
    image: crowdsecurity/crowdsec
    container_name: crowdsec
    restart: unless-stopped
    environment:
      - COLLECTIONS=crowdsecurity/traefik crowdsecurity/http-cve
    volumes:
      - /mnt/user/appdata/traefik/log:/var/log/traefik:ro   # comparte los logs
      - /mnt/user/appdata/crowdsec/data:/var/lib/crowdsec/data
      - /mnt/user/appdata/crowdsec/config:/etc/crowdsec
    networks:
      - cloud

networks:
  cloud:
    external: true
```

**Fichero .env**
``` bash
CF_DNS_API_TOKEN=MI_API_KEY_CLOUDFLARE. # Se obtiene en el panel de cloudflare
CROWDSEC_BOUNCER_API_KEY= xxxxxxxx # Con la última versión del docker-compose se puede borrar
DOMAIN_NAME=mi_dominio.com  # Con la última versión del docker-compose se puede borrar
EMAIL=mi_correo@hotmail.com # Con la última versión del docker-compose se puede borrar
```

**Nota Importante: ES IMPRESCINDIBLE QUE LOS SERVICIOS QUE USEMOS CON TRAEFIK ESTÉN EN LA MISMA RED DOCKER. En mi caso se llama cloud**  

### Ficheros de configuración

**Traefik - traefik.yml**
``` bash
api:
  dashboard: false # Cuando necesito revisar el dashboard lo cambio a true y reinicio el contenedor. Mientras no sea necesario lo dejo en false.

providers:
  docker:
    exposedByDefault: false
    network: cloud # Debe coincidir con el nombre de tu red externa en docker-compose
  file:
    fileName: /etc/traefik/dynamic_conf.yml
    watch: true

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"
    transport:
      respondingTimeouts:
        idleTimeout: 3600

# 1. HABILITAR LOGS (Vital para que CrowdSec detecte ataques)
accessLog:
  filePath: "/var/log/traefik/access.log"
  format: json
  bufferingSize: 100
  fields:
    headers:
      defaultMode: keep # Mantiene headers para que CrowdSec vea IPs reales

# 2. PLUGINS (CrowdSec Bouncer para Traefik v3)
#
# AQUI AÑADIREMOS EL PLUGIN DE CROWDSEC
#

# 3. CONFIGURACIÓN DE CERTIFICADOS (Cloudflare DNS Challenge)
certificatesResolvers:
  cloudflare:
    acme:
      email: mi_correo@hotmail.com
      storage: /letsencrypt/acme.json
      dnsChallenge:
        provider: cloudflare
        resolvers:
          - "1.1.1.1:53"
          - "8.8.8.8:53"
``` 

**Traefik - dynamic_conf.yml**
``` bash
http:
  routers:
    dashboard:
      rule: "Host(`traefik.mi_dominio.com`)"
      service: api@internal
      entryPoints:
        - websecure
      tls:
        certResolver: cloudflare
      middlewares:
        - auth
        - security-headers

  middlewares:
    auth:
      basicAuth:
        # Generar con: echo $(htpasswd -nB usuario) | sed -e s/\\$/\\$\\$/g
        users:
          - "noah:$mi_pass_hasheada"

    security-headers:
      headers:
        stsSeconds: 15552000
        stsIncludeSubdomains: true
        stsPreload: true
        forceSTSHeader: true
        frameDeny: true # Previene Clickjacking
        contentTypeNosniff: true # Previene sniffing de MIME
        browserXssFilter: true
        referrerPolicy: "same-origin"
        # Ajuste para Nextcloud:
        customFrameOptionsValue: "SAMEORIGIN"
    #
    # AQUI AÑADIREMOS EL MIDDLEWARE DE CROWDSEC
    #
```

**Crowdsec - acquis.yaml**
``` bash
---
filenames:
  - /var/log/traefik/access.log
poll_without_inotify: true
labels:
  type: traefik
```

### Integración del bouncer en traefik   

Iniciamos nuestro compose y no debería lanzar errores.  
Es momento de crear nuestra API key del bouncer crowdsec:  

``` bash
---
docker exec -it crowdsec cscli bouncers add traefik-bouncer
# te devolverá una API key, guárdala
```

Verificamos que nuestras colecciones estén actualizadas:

``` bash
docker exec -it crowdsec cscli hub update
docker exec -it crowdsec cscli hub upgrade
docker restart crowdsec
```

Modificamos nuestros ficheros traefik.yml y dynamic_conf.yml para añadir lo siguente:  

**Traefik - traefik.yml**
``` bash
experimental:
  plugins:
    crowdsec-bouncer:
      moduleName: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin
      version: v1.3.5
``` 

**Traefik - dynamic_conf.yml**
``` bash
  middlewares:
    [...AQUI TENEMOS NUESTROS OTROS MIDDLEWARES......]
    crowdsec-bouncer:
      plugin:
        crowdsec-bouncer:
          Enabled: true
          CrowdsecMode: live          # o streaming si prefieres
          CrowdsecLapiUrl: "http://crowdsec:8080"
          CrowdsecLapiKey: "ESTA KEY SE GENERA MAS ADELANTE"
          ForwardedHeadersCustomName: "X-Forwarded-For"
          # Obtenemos la lista oficial de IPs con el siguiente comando:
          # curl https://www.cloudflare.com/ips-v4 -o cloudflare-ips-v4.txt
          ForwardedHeadersTrustedIps:
            - "103.21.244.0/22"
            - "103.22.200.0/22"
            - "103.31.4.0/22"
            - "104.16.0.0/13"
            - "104.24.0.0/14"
            - "108.162.192.0/18"
            - "131.0.72.0/22"
            - "141.101.64.0/18"
            - "162.158.0.0/15"
            - "172.64.0.0/13"
            - "173.245.48.0/20"
            - "188.114.96.0/20"
            - "190.93.240.0/20"
            - "197.234.240.0/22"
            - "198.41.128.0/17"
```

**Ficheros completos:**  

**Traefik - traefik.yml**  
``` bash
api:
  dashboard: false # Cuando necesito revisar el dashboard lo cambio a true y reinicio el contenedor. Mientras no sea necesario lo dejo en false.

providers:
  docker:
    exposedByDefault: false
    network: cloud # Debe coincidir con el nombre de tu red externa en docker-compose
  file:
    fileName: /etc/traefik/dynamic_conf.yml
    watch: true

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"
    transport:
      respondingTimeouts:
        idleTimeout: 3600

# 1. HABILITAR LOGS (Vital para que CrowdSec detecte ataques)
accessLog:
  filePath: "/var/log/traefik/access.log"
  format: json
  bufferingSize: 100
  fields:
    headers:
      defaultMode: keep # Mantiene headers para que CrowdSec vea IPs reales

# 2. PLUGINS (CrowdSec Bouncer para Traefik v3)
experimental:
  plugins:
    crowdsec-bouncer:
      moduleName: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin
      version: v1.3.5

# 3. CONFIGURACIÓN DE CERTIFICADOS (Cloudflare DNS Challenge)
certificatesResolvers:
  cloudflare:
    acme:
      email: mi_correo@hotmail.com
      storage: /letsencrypt/acme.json
      dnsChallenge:
        provider: cloudflare
        resolvers:
          - "1.1.1.1:53"
          - "8.8.8.8:53"
``` 

**Traefik - dynamic_conf.yml**
``` bash
http:
  routers:
    dashboard:
      rule: "Host(`traefik.mi_dominio.com`)"
      service: api@internal
      entryPoints:
        - websecure
      tls:
        certResolver: cloudflare
      middlewares:
        - auth
        - security-headers
        - crowdsec-bouncer # Protegemos el dashboard con crowdsec


  middlewares:
    auth:
      basicAuth:
        # Generar con: echo $(htpasswd -nB usuario) | sed -e s/\\$/\\$\\$/g
        users:
          - "noah:$mi_pass_hasheada"

    security-headers:
      headers:
        stsSeconds: 15552000
        stsIncludeSubdomains: true
        stsPreload: true
        forceSTSHeader: true
        frameDeny: true # Previene Clickjacking
        contentTypeNosniff: true # Previene sniffing de MIME
        browserXssFilter: true
        referrerPolicy: "same-origin"
        # Ajuste para Nextcloud:
        customFrameOptionsValue: "SAMEORIGIN"
    
    crowdsec-bouncer:
      plugin:
        crowdsec-bouncer:
          Enabled: true
          CrowdsecMode: live          # o streaming si prefieres
          CrowdsecLapiUrl: "http://crowdsec:8080"
          CrowdsecLapiKey: "zEtyY2gJsQgQca03vEvWWwcowSG8f9yJz84nF95qZq4"
          ForwardedHeadersCustomName: "X-Forwarded-For"
          ForwardedHeadersTrustedIps:
            - "103.21.244.0/22"
            - "103.22.200.0/22"
            - "103.31.4.0/22"
            - "104.16.0.0/13"
            - "104.24.0.0/14"
            - "108.162.192.0/18"
            - "131.0.72.0/22"
            - "141.101.64.0/18"
            - "162.158.0.0/15"
            - "172.64.0.0/13"
            - "173.245.48.0/20"
            - "188.114.96.0/20"
            - "190.93.240.0/20"
            - "197.234.240.0/22"
            - "198.41.128.0/17"
```

### Obtener las IPs confiables de cloudflare  

Para configurar ForwardedHeadersTrustedIps con precisión en el middleware de CrowdSec, se usan las IPs de Cloudflare. Esto evita que IPs falsas se usen para evadir bloqueos.  
​
Lista oficial de IPs de Cloudflare.  

Cloudflare publica sus rangos IPv4/IPv6 en dos archivos JSON. Los podemos obetner así
```bash
# Desde la terminal de Unraid (donde corre Docker)
curl https://www.cloudflare.com/ips-v4 -o cloudflare-ips-v4.txt
curl https://www.cloudflare.com/ips-v6 -o cloudflare-ips-v6.txt
```
Las IPs que obtenemos las añadimos al fichero dynamic_conf.yml, apartado **ForwardedHeadersTrustedIps** del middleware crowdsec-bouncer.  


### Puesta en marcha y comprobación  

Con todo esto reiniciamos el stack de docker y debería arrancar funcionando sin errores. Revisaremos los logs para verificar fallos.
```bash
docker compose down
docker compose up -d
# En Unraid lo hacemos de forma gráfica
```

```bash
docker logs traefik | grep -i crowdsec
docker logs crowdsec
docker exec crowdsec cscli decisions list
``` 
Comandos intersantes de crowdsec:

```bash
# Listado de decisiones tomadas
docker exec -it crowdsec cscli decisions list
# Métricas completas de crowdsec
docker exec -it crowdsec cscli metrics
# Unban IP
docker exec -it crowdsec cscli decisions delete -i x.x.x.x
# Banear una IP
docker exec -it crowdsec cscli decisions add --ip xx.xx.xx.xx --duration 1h
```
  
### Enrutar servicios a través de traefik  

Las etiquetas básicas que debe llevar cualquier servicio para que traefik lo enrute son las siguientes:

```bash
# Ejemplo para nuestro karakeep  
traefik.enable=true
traefik.http.routers.karakeep.rule=Host(`karakeep.mi_dominio.com`)
traefik.http.routers.karakeep.entrypoints=websecure
traefik.http.routers.karakeep.tls.certresolver=cloudflare
traefik.http.services.karakeep.loadbalancer.server.port=3000
# middelware que vamos a aplicar a este servcio
traefik.http.routers.karakeep.middlewares=crowdsec-bouncer@file,security-headers@file
```

IMPORTANTE: La etiqueta **traefik.http.services.karakeep.loadbalancer.server.port** debe indicar el puerto interno del contenedor, ya que tenemos que recordar que nuestros **servicios siempre deben estar en la misma red que traefik** para que funcionen.  
En mi caso, el docker-compose de karakeep lleva la siguiente configuración de puertos porque el puerto 3000 lo estoy usando para otro servicio:
```bash
    [....]
    ports:
      - 3333:3000
    [....]
```
Entonces, el acceso a karakeep a través de la red local es:  
http://192.168.10.55:3333  

Pero traefik sólo entiende de la red docker, por lo que el **puerto para traefik es 3000**.


### Protección de servicios con crowdsec  
Hemos configurado crowdsec como un middleware, por tanto, la solicitud de conexión al servicio debe pasar antes por crowdsec que dirá si permite esa conexión o no.  

Para proteger servicios tenemos dos opciones:  
1.- Configuración estática en dynamic_conf.yml  
2.- Etiquetas traefik en el servicio en cuestión.  
Por facilidad vamos a hacer la segunda opción, a través de etiquetas, así mantenemos más limpio el dynamic_conf.yml y traefik hace una carga en vivo sin reiniciar el proxy.  

Etiqueta:
```bash
# Ejemplo para Nextcloud. El resto de servicios sería exactamente igual
traefik.http.routers.nextcloud.middlewares=rowdsec-bouncer@file,security-headers@file
```

### Protección de Nextcloud  
Crowdsec tiene una colección específica para Nextcloud. Vamos a proteger nuestra instancia.  
Modificamos el docker-compose añadiendo la colección de crowdsecurity/nextcloud y montando la carpeta donde almacenamos los logs de Nextcloud.

```bash
  crowdsec:
    image: crowdsecurity/crowdsec
    container_name: crowdsec
    restart: unless-stopped
    environment:
      - COLLECTIONS=crowdsecurity/traefik crowdsecurity/http-cve crowdsecurity/nextcloud
    volumes:
      - /mnt/user/appdata/traefik/log:/var/log/traefik:ro   # comparte los logs
      - /mnt/user/appdata/nextcloud/config/nextcloud-logs:/var/log/nextcloud:ro   # comparte los logs
```  
Reiniciamos crowdsec y podemos actualizar las colletions:
```bash
docker exec -it crowdsec cscli hub update
```

Revisamos nuestro config.php de Nextcloud para verificar que los logs se guardan en el lugar correcto:
```bash
  'mail_smtpport' => '465',
  'bulkupload.enabled' => false,
  'loglevel' => 2,
  'logfile' => '/var/www/html/config/nextcloud-logs/nextcloud.log',
  'log_rotate_size = 0',
```
Modificamos nuestro fichero acquis.yaml de crowdsec, quedano así:
```bash
# Logs de Traefik (para todo lo que pasa por el proxy)
---
filenames:
  - /var/log/traefik/access.log
poll_without_inotify: true
labels:
  type: traefik

# Logs de Nextcloud (brute-force y eventos específicos NC)
---
filenames:
  - /var/log/nextcloud/nextcloud.log
labels:
  type: nextcloud
```
Reiniciamos y verificamos si se están parseando los dos ficheros de logs que tenemos:
```bash
docker restart crowdsec
docker exec crowdsec cscli metrics  # Verifica parsing
```
![crowdsec-nextcloud.png](crowdsec-nextcloud.png)

Con esta configuración Nextcloud registraba la dirección IP de Cloudflare, no la IP real del usuario que accede a Nextcloud. Vamos a arreglarlo.  
Problema clásico Cloudflare + Traefik + Nextcloud: Nextcloud ve IP de Cloudflare porque no confía en Traefik como proxy ni lee el header CF-Connecting-IP (IP real que pasa Cloudflare).  

Editamos nuestro fichero config.php de Nextcloud:

```bash
  [.......]
  'dbtype' => 'mysql',
  'version' => '32.0.5.0',
  'trusted_proxies' => 
  array (
    0 => '192.168.10.55',
// añadida rango IP de nuestra red "cloud" de docker:
    1 => '172.21.0.0/16',
// añadidas IPs de clouflare para que Nextcloud confíe en ellas:
    2 => '103.21.244.0/22',
    3 => '103.22.200.0/22',
    4 => '103.31.4.0/22',
    5 => '104.16.0.0/13',
    6 => '104.24.0.0/14',
    7 => '108.162.192.0/18',
    8 => '131.0.72.0/22',
    9 => '141.101.64.0/18',
    10 => '162.158.0.0/15',
    11 => '172.64.0.0/13',
    12 => '173.245.48.0/20',
    13 => '188.114.96.0/20',
    14 => '190.93.240.0/20',
    15 => '197.234.240.0/22',
    16 => '198.41.128.0/17',
  ),
// añadida según info de perplexity para que crowdsec funcione bien.
  'forwarded_for_headers' => 
  array (
    'HTTP_CF_CONNECTING_IP',    // ← IP real de Cloudflare
    'HTTP_X_FORWARDED_FOR',
    'HTTP_X_FORWARDED',
    'HTTP_X_CLUSTER_CLIENT_IP',
    'HTTP_FORWARDED_FOR',
    'HTTP_FORWARDED',
    'REMOTE_ADDR',
  ),
  'overwrite.cli.url' => 'https://nextcloud.mi_dominio.com',
  'overwritehost' => 'nextcloud.mi_dominio.com',
  [......]
```
Y añadimos las siguientes etiquetas al docker-compose de Nextcloud:  
```bash 
# Esta primera la editamos como sigue:
traefik.http.routers.nextcloud.middlewares=crowdsec-bouncer@file,security-headers@file,nextcloud-headers@docker
# Estas se añaden nuevas:
traefik.http.middlewares.nextcloud-headers.headers.customrequestheaders.X-Forwarded-Proto=https
traefik.http.middlewares.nextcloud-headers.headers.customrequestheaders.X-Forwarded-For=true
traefik.http.middlewares.nextcloud-headers.headers.customrequestheaders.X-Forwarded-Port=443
traefik.http.middlewares.nextcloud-headers.headers.customrequestheaders.X-Real-IP={{.ClientIP }}
```

Y con esto nuestro Nextcloud ya detecta la IP verdadera para, si procede, banearla.

### Conexión de nuestro contenedor a Crowdsec.net  
Accedemos a nuestra cuenta en [https://app.crowdsec.net/](https://app.crowdsec.net/).  

En el dashboard → Security Engines → Add Instance (o "Engines")  

Copia el Enrollment Token que genera (algo como cscli console enroll abc123...def456)  

```bash
# Registrar con el token
docker exec -it crowdsec cscli console enroll TU_ENROLLMENT_TOKEN_AQUI
```
Esto creará /etc/crowdsec/online_api_credentials.yaml con login y password válidos.  
Reiniciamos nuestro contenedor:
```bash
docker restart crowdsec
docker logs crowdsec | grep -i capi
```
Volvemos al dashboard de crowdsec.net y aceptamos el enrolado del equipo. Podemos cambiar el nombre para ser más visual al acceder. En mi caso le puse Unraid.  
Ventajas de conectar a Console:  
1.- Dashboard web con alertas en tiempo real  
2.- Blocklist comunitaria (millones de IPs malas)  
3.- Métricas globales y threat intel  
  
**En mi caso, al final no hice el enrolado del equipo por los siguientes motivos:  


### Notificaciones en Telegram de Crowdsec  

Para añadir notificaciones realizamos la siguiente configuración:   

**IMPORTANTE: DETENEMOS EL COMPOSE**  

Fichero **/mnt/user/appdata/crowdsec/config/notifications/http.yaml**
```bash                           
type: http                # No cambiar
name: telegram      # Nombre que usaremos en el perfil
log_level: info

# URL de la API de Telegram con tu TOKEN
# Mucho OJO en la url - Está bien escrita

url: https://api.telegram.org/botXXXXXXXXXXXX:XXXXXXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXXXXX/sendMessage

method: POST
headers:
  Content-Type: application/json

# Formato del mensaje (JSON)
# Formato del mensaje (JSON)
format: |
  {
    "chat_id": "-5002897396",
    "text": "{{range .}}{{$alert := .}}{{range .Decisions}}IP {{.Value}} baneada {{.Duration}} por {{.Scenario}}{{end}}{{end}}",
    "parse_mode": "HTML"
  }
```
Fichero **/mnt/user/appdata/crowdsec/config/profiles.yaml**
```bash
name: default_ip_remediation
#debug: true
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
 - type: ban
   duration: 4h
notifications:
 - telegram
```

Probamos a enviar una notificación de prueba:
```bash
docker exec -it crowdsec cscli notifications test telegram
```
Versión tuneada de notificaciones en Telegram. Tomando como ejemplo el modelo de [la documentación de crowdsec.net](https://docs.crowdsec.net/docs/local_api/notification_plugins/telegram):

```console
type: http          # Don't change
name: telegram      # Must match the registered plugin in the profile

# One of "trace", "debug", "info", "warn", "error", "off"
log_level: info

format: |
  {
   "chat_id": "-5002897396", 
   "text": "
     {{range . -}}  
     {{$alert := . -}}  
     {{range .Decisions -}}
     🚨 CrowdSec Alert on MyServer! 🚨
  🆔 IP: {{.Value}}
  ⚠️  Scenario: {{ .Scenario }}
  🚧 Decision:  {{.Type}} for next {{.Duration}}
     {{end -}}
     {{end -}}
   ",
   "reply_markup": {
      "inline_keyboard": [
          {{ $arrLength := len . -}}
          {{ range $i, $value := . -}}
          {{ $V := $value.Source.Value -}}
          [
              {
                  "text": "See {{ $V }} on shodan.io",
                  "url": "https://www.shodan.io/host/{{ $V -}}"
              },
              {
                  "text": "See {{ $V }} on crowdsec.net",
                  "url": "https://app.crowdsec.net/cti/{{ $V -}}"
              }
          ]{{if lt $i ( sub $arrLength 1) }},{{end }}
      {{end -}}
      ]
  }

url: https://api.telegram.org/botXXXXXXXXXXX:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/sendMessage

method: POST
headers:
  Content-Type: "application/json"
```

***   
Fuentes y enlaces de interés que ayudaran a complementar esta guía:  

[Traefik](https://doc.traefik.io/traefik/getting-started/quick-start/)    
[Crowdsec](https://docs.crowdsec.net/docs/appsec/quickstart/traefik/)  


