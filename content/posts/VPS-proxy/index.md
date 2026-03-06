---
title: Proxy Inverso en VPS
description: VPS como proxy inverso
date: 2026-02-23 14:00:00+02:00
draft: false
categories:
   - Debian
tags:
   - Admin
weight: 1
---

## Traefik y crowdsec
  
Estoy hasta el gorro de la liga y sus puñeteros bloqueos.  Este blog y mis servicios estaban configurados en el NAS con un traefik como proxy inverso. Para proteger mi IP pública uso el Proxied de cloudflare, que además aporta un WAF muy potente, geolocalización, etc. **PROBLEMA**: cada vez que hay futbol pierdo la conexión a homeassistant y otros servicios que para mi son muy importantes.  

Hoy vamos a configurar traefik en un VPS y desde allí enrutamos todo el tráfico a nuestro NAS local a través de Tailscale.  Desactivaremos el proxied de cloudflare y de esta forma no está expuesta mi IP pública, sólo está expuesta la IP del VPS.  
He contratado el VPS más económico que tiene [Piensasolutions](https://www.piensasolutions.com/). En mi caso pago 0,75€ al mes durante 12 meses y después el coste pasa a ser 1€ al mes.  
El VPS tiene 1 GB de RAM, 1 vCPU, 10GB SSD NVMe y conexión de 1Gbps.  
Al principio intenté instalar Pangolín, que ya lo tuve operativo en un VPS de prueba más potente. Pero creo que en este servidor es muy exigente y no puede para nada con él. Solo Pangolín consume 300 Mb de RAM más el sistema, crowdsec, etc. IMPOSIBLE !!!!!

### Preparación del entorno
Como sistema operativo tengo Debian 13. Una maravilla que consume pocos recursos. Instalamos y actualizamos:
``` bash
sudo apt update && sudo apt upgrade -y
```  
Instalamos Tailscale:
```bash
curl -fsSL https://tailscale.com/install.sh | sh

sudo tailscale up -d
```

Configuración del Firewall. Instalamos ufw:
```bash
sudo apt install ufw

# Reglas iniciales
sudo ufw default deny incoming # Ojo con esta regla estamos bloqueando hasta el ssh, que luego permitimos a través de tailscale.
sudo ufw default allow outgoing

#Permitimos todo el tráfico a través de tailscale0
sudo ufw allow in on tailscale0

# Puertos 80 y 443 para traefik
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Activamos el firewall
sudo ufw enable

# Verificamos reglas
sudo ufw status numbered
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] Anywhere on tailscale0     ALLOW IN    Anywhere                  
[ 2] 80/tcp                     ALLOW IN    Anywhere                  
[ 3] 443/tcp                    ALLOW IN    Anywhere                            
[ 5] Anywhere (v6) on tailscale0 ALLOW IN    Anywhere (v6)             
[ 6] 80/tcp (v6)                ALLOW IN    Anywhere (v6)             
[ 7] 443/tcp (v6)               ALLOW IN    Anywhere (v6)  

# Nota para borrar alguna regla:
sudo ufw delete 8

# Antes de cerrar esta sesión abrimos otra terminal y probamos a conectar por ssh. Si hubiera algún fallo siempre tenemos la opción de acceder a través de la web de nuestro VPS.
```


En nuestro panel de control del VPS verificamos que los puertos que vamos a usar estén abiertos. En este caso necesitamos los puertos 80 y 443:
![vps.png](/vps.png)

Mi dominio está registrado en cloudflare. Tenemos que apuntar los registros DNS a la IP pública de nuestro VPS. Desactivamos el Proxied y nos quedamos sin protección para evitar que la dichosa liga y sus esbirros nos jodan a los pobres de a pie. Dejamos la nube de color gris para que cloudflare dirija el tráfico de forma transparente al VPS.
![vps-2.png](/vps-2.png)

CLoudflare nos muestra el siguiente aviso, pero da igual, nos jodemos porques estamos compartiendo la misma IP que alguna web ilegal. Cortamos medio internet y encima no se dan cuenta que no están consiguiendo nada, casi están animando a todo lo contrario. **En fin que me caliento**.
```bash
Es necesario redirigir mediante proxy para la mayoría de las funciones de seguridad y rendimiento
Para configurar sus registros DNS estableciendo la opción redirigido mediante proxy haga clic en "Editar" en la tabla siguiente y se beneficiará de la protección DDoS, las reglas de seguridad, el almacenamiento en caché y mucho más.
```

Por último necesitamos una API Key de cloudflare para los certificados. 

Instalamos docker:
``` bash
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
docker version
docker compose version
# Damos permisos a nuestro usuario para ejecutar docker sin sudo
sudo usermod -aG docker $USER
```

### Docker compose de traefik y crowdsec
Creamos directorios:
``` bash
mkdir -p /home/noah/traefik-crowdsec
mkdir -p /home/noah/traefik-crowdsec/traefik/{conf.d,logs,ssl}
mkdir -p /home/noah/traefik-crowdsec/crowdsec/{config,data}
```

Dentro de /home/noah/traefik-crowdsec creamos nuestro docker-compose.yml:
```bash
services:
  traefik:
    image: traefik:v3.5.0
    container_name: traefik
    hostname: traefik
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true

    environment:
      TZ: ${TZ:-Europe/Madrid}
      CF_DNS_API_TOKEN: ${CF_DNS_API_TOKEN}

    networks:
      - traefik
    ports:
      - "80:80"
      - "443:443"

    volumes:
      - /usr/share/zoneinfo/${TZ:-Europe/Madrid}:/etc/localtime:ro
      - ./traefik/traefik.yml:/traefik.yml:ro
      - ./traefik/conf.d:/conf.d:ro
      - ./traefik/ssl:/ssl
      - ./traefik/logs:/var/log/traefik

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    restart: unless-stopped
    environment:
      - COLLECTIONS=crowdsecurity/traefik crowdsecurity/http-cve 
      # ESTAS COLECCIONES LAS AÑADIREMOS LUEGO crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules
      - DISABLE_CAPI=true  # Ignora CAPI completamente
    volumes:
      - ./traefik/logs:/var/log/traefik:ro   # comparte los logs
      - ./crowdsec/data:/var/lib/crowdsec/data
      - ./crowdsec/config:/etc/crowdsec
    networks:
      - traefik

networks:
  traefik:
    name: traefik
```

***IMPORTANTE***: Las colecciones de crowdsec que he incluido son las siguientes:
```bash
- COLLECTIONS=crowdsecurity/traefik crowdsecurity/http-cve crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules
# La coleccion appsec es para usar el WAF integrado que tiene crowdsec
```

Creamos nuestro fichero .env:
```bash
TZ=Europe/Madrid
CF_DNS_API_TOKEN=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Ficheros de configuración de traefik
Fichero traefik.yml:
```bash
# Global configuration
global:
  checknewversion: false
  sendanonymoususage: false

# API and dashboard configuration
api:
  insecure: false
  dashboard: true
  debug: false

# Load dynamic configuration from .yaml files in a directory - Routers 
providers:
  file:
    directory: /conf.d
    watch: true

# Certificate Resolvers
certificatesResolvers:
  letsencrypt:
    acme:
      email: micorreo@gmail.com
      storage: /ssl/acme.json
      caServer: https://acme-v02.api.letsencrypt.org/directory
      dnsChallenge:
        provider: cloudflare
#        resolvers:
#          - "1.1.1.1:53"
#          - "1.0.0.1:53"

  letsencrypt_staging:
    acme:
      email: micorreo@gmail.com
      storage: /ssl/acme.json
      caServer: https://acme-staging-v02.api.letsencrypt.org/directory
      dnsChallenge:
        provider: cloudflare
#        resolvers:
#          - "1.1.1.1:53"
#          - "1.0.0.1:53"

# EntryPoints configuration
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
    http:
      tls:
        certResolver: letsencrypt
#        certResolver: letsencrypt_staging
      middlewares:
        - geoblock-es
        - crowdsec-bouncer
        - security-headers

accessLog:
  filePath: "/var/log/traefik/access.log"
  format: json
  bufferingSize: 100
  fields:
    headers:
      defaultMode: keep # Mantiene headers para que CrowdSec vea IPs reales

# PLUGINS (CrowdSec Bouncer para Traefik v3)
experimental:
  plugins:
    crowdsec-bouncer:
      moduleName: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin
      version: v1.5.1 # Ultima versión en el momento de la configuración. IMPORTANTE VERIFICAR

    geoblock:
      moduleName: github.com/PascalMinder/geoblock
      version: v0.3.6
```

***IMPORTANTE***: Para hacer pruebas usaremos el **certResolver: letsencrypt_staging**. Una vez esté todo configurado cambiamos a certResolver: letsencrypt. En el [blog de manelrodero](https://www.manelrodero.com/blog/instalacion-y-uso-de-traefik-en-docker-sin-etiquetas) explica muy bien el motivo.  

Dentro de ssl creamos nuestro fichero acme.json para los certificados:
```bash
  touch acme.json
  chmod 600 acme.json
```

Dentro de conf.d crearemos nuestros ficheros para dashboard, middlewares y distintos servicios.
Fichero dashboard.yml:
```bash
http:
  routers:
    dashboard:
      rule: "Host(`traefik.midominio.com`)"
      service: api@internal
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt
      middlewares:
        - auth
```
Fichero middelwares.yml:
```bash
http:
  middlewares:
    auth:
      basicAuth:
        # Generar con: echo $(htpasswd -nB usuario) | sed -e s/\\$/\\$\\$/g
        users:
          - "noah:$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

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
          # Identidad fija para evitar los "bouncers fantasmas"
          bouncerName: "traefik-bouncer"

          # Conexión a la LAPI (Local API)
          CrowdsecLapiUrl: "http://crowdsec:8080"
          CrowdsecLapiKey: "07F+XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

          # Configuración del WAF se añade luego junto con las colecciones (AppSec)
          crowdsecAppsecEnabled: true
          crowdsecAppsecHost: "crowdsec:7422" # Puerto por defecto del WAF en el contenedor crowdsec
          crowdsecAppsecFailureBlock: true
          crowdsecAppsecUnreachableBlock: true
          #appsecFailureAction: "passthrough" # Si el WAF falla, deja pasar (o "block" para máxima seguridad)

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

    geoblock-es:
      plugin:
        geoblock:
          httpStatusCodeDeniedRequest: 404
          api: "https://get.geojs.io/v1/ip/country/{ip}"  # ← OBLIGATORIO
          ipGeolocationHttpHeaderField: "CF-IPCountry"  # ← Prioriza este header!
          ipHeaders: ["X-Forwarded-For", "CF-Connecting-IP"]  # Backup
          ipHeaderStrategy: "CheckFirst"
          countries:  # Permitir SOLO estos (ISO 3166-1 alpha-2)
            - ES
          allowLocalRequests: true  # VPS/local/Tailscale
          allowUnknownCountries: false  # Bloquea IPs sin país
          apiTimeoutMs: 200  # Rápido
          cacheSize: 100  # Para tu tráfico
          forwardedHeadersTrustedIps:  # Cloudflare + Tailscale
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
Cuando arranquemos por primera vez el stack crowdsec no funcionará porque no hemos creado el bouncer de traefik:
```bash
docker exec -it crowdsec cscli bouncers add traefik-bouncer
```
Este comando nos genera una API Key que tenemos que copiar en el fichero middlewares.yml:
```bash
    crowdsec-bouncer:
      plugin:
        crowdsec-bouncer:
          Enabled: true
          CrowdsecMode: live          # o streaming si prefieres
          # Identidad fija para evitar los "bouncers fantasmas"
          bouncerName: "traefik-bouncer"

          # Conexión a la LAPI (Local API)
          CrowdsecLapiUrl: "http://crowdsec:8080"
          CrowdsecLapiKey: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" <<--COPIAR AQUI EL API KEY

          # Configuración del WAF (AppSec)
          appsecEnabled: true
```
Reiniciamos nuestro compose:
```bash
docker compose restart
```

Fichero de ejemplo de un servicio:
karakeep.yml:
```bash
http:
  routers:
    karakeep:
      rule: "Host(`karakeep.midominio.com`)"
      service: karakeep
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt

  services:
    karakeep:
      loadBalancer:
        servers:
          - url: "http://100.105.100.10:3333"
```

Script para creación de servicios:
```bash
service="my_servicio"
url="http://100.105.100.10:3333"

cat << EOF > "./data/conf.d/${service}.yml"
http:
  routers:
    ${service}:
      rule: "Host(\`${service}.midominio.com\`)"
      service: ${service}
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt
#      middlewares:
#        - crowdsec-bouncer
#        - security-headers
#        - geoblock-es

  services:
    ${service}:
      loadBalancer:
        servers:
          - url: "${url}"
EOF
```

**NOTA**: En el fichero traefik.yml ya le indicamos a traefik que todo el tráfico que entre por 443 pase por los siguientes middlewares:
```bash
  websecure:
    address: ":443"
    http:
      tls:
        certResolver: letsencrypt
#        certResolver: letsencrypt_staging
      middlewares:
        - geoblock-es
        - crowdsec-bouncer
        - security-headers
```
En nuestro script de creación de servicios no es necesario añadir los middlewares porque traefik se lo añade a todos de forma general, por eso está comentado en el script.


### Ficheros de configuración de crowdsec

Fichero obtención datos /traefik-crowdsec/crowdsec/config/acquis.yaml:
```bash
---
filenames:
  - /var/log/traefik/access.log
poll_without_inotify: true
labels:
  type: traefik
```

Fichero definir baneos y tipo de notificaciones /traefik-crowdsec/crowdsec/config/profiles.yaml:
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
#duration_expr: Sprintf('%dh', (GetDecisionsCount(Alert.GetValue()) + 1) * 4)
# notifications:
#   - slack_default  # Set the webhook in /etc/crowdsec/notifications/slack.y>
#   - splunk_default # Set the splunk url and token in /etc/crowdsec/notifica>
#   - http_default   # Set the required http parameters in /etc/crowdsec/noti>
#   - email_default  # Set the required email parameters in /etc/crowdsec/not>
on_success: break
---
name: default_range_remediation
#debug: true
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Range"
decisions:
 - type: ban
   duration: 4h
#duration_expr: Sprintf('%dh', (GetDecisionsCount(Alert.GetValue()) + 1) * 4)
# notifications:
#   - slack_default  # Set the webhook in /etc/crowdsec/notifications/slack.y>
#   - splunk_default # Set the splunk url and token in /etc/crowdsec/notifica>
#   - http_default   # Set the required http parameters in /etc/crowdsec/noti>
#   - email_default  # Set the required email parameters in /etc/crowdsec/not>
on_success: break
```

Fichero notificaciones traefik-crowdsec/crowdsec/config/notifications/http.yaml:
```bash
type: http          # Don't change
name: telegram      # Must match the registered plugin in the profile

# One of "trace", "debug", "info", "warn", "error", "off"
log_level: info

format: |
  {
   "chat_id": "-XXXXXXXXXXXXXXXX", 
   "text": "
     {{range . -}}  
     {{$alert := . -}}  
     {{range .Decisions -}}
     🚨 CrowdSec Alert on Piensa! 🚨
  🆔 IP: {{.Value}}
  ⚠️  Scenario: {{ .Scenario }}
  🚧 Decision: {{.Type}} for next {{.Duration}}
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

url: https://api.telegram.org/bot111111111111:XXXXXXXXXx-XXXXXXXXXXXXXXXXXXXXXXXXX/sendMessage

method: POST
headers:
  Content-Type: "application/json"
```
En este momento podemos arrancar nuestro compose y debería funcionar todo correctamente.

### APPSEC para Crowdsec
Según la web de [Crowdsec](https://docs.crowdsec.net/docs/appsec/intro/), Appsec es un WAF que ofrece las siguientes características:  
1.- Aplicación de parches virtuales con bajo esfuerzo.
2.- Compatibilidad con reglas heredadas de ModSecurity.
3.- Protección WAF clásica más funciones de CrowdSec para detección avanzada de comportamiento.
4.- Integración completa con la pila CrowdSec, incluidos la consola y los componentes de remediación.  

Para integrarlo realizamos los siguientes pasos:

```bash
# Detenemos nuestro stack
docker compose down
```

Añadimos a nuestro docker-compose las colecciones:
```bash
- COLLECTIONS=crowdsecurity/traefik crowdsecurity/http-cve crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules

```
```bash
# Arrancamos nuevamente la pila
docker compose up -d
```

Tenemos que crear un fichero de adquisiciones para Appsec. Antes de eso debemos descargar las reglas de appsec porque sino el contenedor de crowdsec no arrancará (me dió este problema y estuvo volviendome loco hasta encontrar una solución por la red).   

Descargamos las reglas:
```bash
docker exec crowdsec cscli collections install crowdsecurity/appsec-virtual-patching
docker exec crowdsec cscli collections install crowdsecurity/appsec-generic-rules
```

Reiniciamos crowdsec:
```bash
docker compose restart crowdsec
```

Ahora podemos verificar que ha arrancado correctamente sin reinicios con 
```bash
docker stats
```

Creamos el fichero de adquisiciones:
```bash
sudo nano /crowdsec/config/acquis.d/appsec.yaml

#Añadimos esto al fichero:
appsec_config: crowdsecurity/appsec-default
labels:
  type: appsec
listen_addr: 0.0.0.0:7422
source: appsec
```

Añadimos la nueva configuración a nuestro middleware de crowdsec:
```bash
   crowdsec-bouncer:
      plugin:
        crowdsec-bouncer:
          Enabled: true
#          CrowdsecMode: live          # o streaming si prefieres
          crowdsecMode: live          # o streaming si prefieres
          # Identidad fija para evitar los "bouncers fantasmas"
          bouncerName: "traefik-bouncer"

          # Conexión a la LAPI (Local API)
          CrowdsecLapiUrl: "http://crowdsec:8080"
#          crowdsecLapiHost: "crowdsec:8080"
          CrowdsecLapiKey: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

          # Configuración del WAF (AppSec)
          crowdsecAppsecEnabled: true
          crowdsecAppsecHost: "crowdsec:7422" # Puerto por defecto del WAF en>
          crowdsecAppsecFailureBlock: true
          crowdsecAppsecUnreachableBlock: true
          #appsecFailureAction: "passthrough" # Si el WAF falla, deja pasar (>
          ForwardedHeadersCustomName: "X-Forwarded-For"
          [.................]
```
Y reiniciamos nuevamente crowdsec:
```bash
docker compose restart crowdsec
```

Verificaciones a realizar para comprobar que funciona correctamente:
```bash
docker exec crowdsec cscli appsec-rules list

# Genera un listado de las reglas que están activas:
------------------------------------------------------------------------------------------------------------------------------------------
 APPSEC-RULES                                                                                                                             
------------------------------------------------------------------------------------------------------------------------------------------
 Name                                             📦 Status    Version  Local Path                                                        
------------------------------------------------------------------------------------------------------------------------------------------
 crowdsecurity/appsec-generic-test                ✔️  enabled  0.3      /etc/crowdsec/appsec-rules/appsec-generic-test.yaml               
 crowdsecurity/base-config                        ✔️  enabled  0.1      /etc/crowdsec/appsec-rules/base-config.yaml                       
 crowdsecurity/experimental-no-user-agent         ✔️  enabled  0.1      /etc/crowdsec/appsec-rules/experimental-no-user-agent.yaml        
 crowdsecurity/generic-freemarker-ssti            ✔️  enabled  0.3      /etc/crowdsec/appsec-rules/generic-freemarker-ssti.yaml    
```
  
```bash
docker exec crowdsec cscli metrics show appsec
#Metricas de Appsec
+-------------------------------------+
| Appsec Metrics                      |
+---------------+-----------+---------+
| Appsec Engine | Processed | Blocked |
+---------------+-----------+---------+
| 0.0.0.0:7422/ | 361       | -       |
+---------------+-----------+---------+
```
   
```bash
╰─ docker exec crowdsec cscli appsec-configs list
----------------------------------------------------------------------------------------------------------
 APPSEC-CONFIGS                                                                                           
----------------------------------------------------------------------------------------------------------
 Name                            📦 Status    Version  Local Path                                         
----------------------------------------------------------------------------------------------------------
 crowdsecurity/appsec-default    ✔️  enabled  0.4      /etc/crowdsec/appsec-configs/appsec-default.yaml   
 crowdsecurity/generic-rules     ✔️  enabled  0.4      /etc/crowdsec/appsec-configs/generic-rules.yaml    
 crowdsecurity/virtual-patching  ✔️  enabled  0.4      /etc/crowdsec/appsec-configs/virtual-patching.yaml 
----------------------------------------------------------------------------------------------------------
```

En teoría, siguiendo las ]instrucciones de crowdsec](https://docs.crowdsec.net/docs/appsec/quickstart/traefik) deberíamos mapear el fichero en el contenedor de docker, **pero yo no lo he hecho y funciona igual**:

```bash
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    restart: unless-stopped

    environment:
      - COLLECTIONS=crowdsecurity/traefik crowdsecurity/http-cve crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules
      - DISABLE_CAPI=true  # Ignora CAPI completamente

    volumes:
#      - ./crowdsec/config/acquis.d/appsec.yaml:/etc/crowdsec/acquis.d/appsec.yaml
      [......]
```

**NOTA IMPORTANTE:** Por último, me he dado cuenta que si ya teníamos funcionando el stack con configuraciones anteriores, cuando añadimos Appsec por lo que sea el Appsec engine se queda en blanco:

```bash
╰─ docker exec crowdsec cscli metrics show appsec 
+-------------------------------------+
| Appsec Metrics                      |
+---------------+-----------+---------+
| Appsec Engine | Processed | Blocked |
+---------------+-----------+---------+
|               |           | -       |
+---------------+-----------+---------+
```
y tengo que borrar toda la configuración de crowdsec y volver a empezar. Con eso ya funciona correctamente. Supongo que algo se queda en caché.
```bash
╰─ docker exec crowdsec cscli metrics show appsec 
+-------------------------------------+
| Appsec Metrics                      |
+---------------+-----------+---------+
| Appsec Engine | Processed | Blocked |
+---------------+-----------+---------+
| 0.0.0.0:7422/ | 4         | -       |
+---------------+-----------+---------+
```

### Actualización de escenarios Crowdsec

Mantener los escenarios y parsers actualizados es vital, ya que los atacantes cambian sus tácticas constantemente. En Docker, esto es sencillo de verificar.  
```bash
docker exec -it crowdsec cscli hub update

# Este comando te mostrará una tabla con todo tu software de seguridad (escenarios, parsers, colecciones). Fíjate en la columna que indica si hay versiones nuevas:
docker exec -it crowdsec cscli hub list

# Si tenemos actualizaciones disponibles:
docker exec -it crowdsec cscli hub upgrade
```

Para que los cambios surtan efecto, reiniciamos el motor de Crowdsec:
```bash
docker exec -it crowdsec kill -SIGHUP 1

# o simplemente reiniciamos el contenedor con:
docker restart crowdsec
```


### Limpieza de logs de traefik

Hay que tener cuidado con los logs de traefik. Revisando un par de dias después de la configuración vi que tenía casi 100MB de logs. Vamos a configurar la limpieza.  
**El trabajo de limpieza lo hacemos en el host ya que tenemos un volumen donde montamos los logs según nuestro docker compose.**   

Instalación de logrotate:
```bash
# En caso de no estar instalado:
sudo apt install logrotate
```

Archivo de configuración:
```bash
sudo nano /etc/logrotate.d/traefik

#Pegamos lo siguiente:
/home/MI_USUARIO/traefik-crowdsec/traefik/logs/*.log {
    daily
    rotate 7
    size 50M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```
```bash
#Explicación:
daily: rota los logs cada día.
rotate 7: conserva 7 días de logs antes de eliminarlos.
size 50M: si superamos los 50M se hace la rotación
compress / delaycompress: comprime los logs antiguos (en .gz) al siguiente ciclo.
missingok: ignora si el archivo no existe.
notifempty: no rota si está vacío.
copytruncate: copia el log y limpia el original sin interrumpir Traefik (importante para contenedores).
```

Prueba de funcionamiento:
```bash
sudo logrotate -f /etc/logrotate.d/traefik

error: skipping "/home/noe/traefik-crowdsec/traefik/logs/access.log" because parent directory has insecure permissions (It's world writable or writable by group which is not "root") Set "su" directive in config file to tell logrotate which user/group should be used for rotation.
```

Este error se produce porque logrotate es muy tiquismikis con los permisos. Yo lo he solucionado de la siguiente forma:
```bash
# Dentro del directorio traefik ejecutamos

sudo chown root:root logs
```

Y ya funciona correctamente.


### EXTRA 1: Instalación y configuración de Wireguard

Vamos a instalar un servidor Wireguard en nuestro VPS.  
```bash
# Instalamos wireguard y generador de qr para escanear desde app movil
sudo apt install wireguard qrencode -y

# Cambiamos a nuestro directorio de wireguard
sudo su
cd /etc/wireguard/
umask 077

# Generamos claves de servidor
wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
```

Creamos nuestro fichero wg0.conf:
```bash
nano wg0.conf

[Interface]
# IP que tendrá el VPS dentro de la VPN
Address = 10.8.0.1/24
# Puerto de escucha (OJO - abrir el puerto en ufw y panel de nuestro vps si es necesario)
ListenPort = 51820
# Clave privada del servidor
PrivateKey = # GENERADA EN EL APARTADO ANTERIOR - FICHERO server.key

# Reglas para permitir que el tráfico fluya y salga a internet
#PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ens6 -j MASQUERADE
#PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ens6 -j MASQUERADE

# Reglas combinadas: Acceso a Internet (ens6) + Acceso a Tailscale (tailscale0)
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ens6 -j MASQUERADE; iptables -A FORWARD -i %i -o tailscale0 -j ACCEPT; iptables -A FORWARD -i tailscale0 -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -o tailscale0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ens6 -j MASQUERADE; iptables -D FORWARD -i %i -o tailscale0 -j ACCEPT; iptables -D FORWARD -i tailscale0 -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -o tailscale0 -j MASQUERADE


# CLIENTES

# s24
[Peer]
PublicKey = # CLAVE PUBLICA DE NUESTRO CLIENTE S24
AllowedIPs = 10.8.0.2/32

# envy
[Peer]
PublicKey = # CLAVE PUBLICA DE NUESTRO CLIENTE ENVY
AllowedIPs = 10.8.0.3/32
```

Generamos las claves de nuestro primer cliente:
```bash
wg genkey | tee /etc/wireguard/s24.key | wg pubkey > /etc/wireguard/s24.pub
```

Fichero de configuracion del cliente:
```bash
nano s24.conf

[Interface]
# Clave privada del cliente s24
PrivateKey = # CLAVE PRIVADA DE s24 GENERADA EN EL PASO ANTERIOR FICHERO s24.key
Address = 10.8.0.2/24
DNS = 1.1.1.1

[Peer]
# Public key del servidor
PublicKey = # CLAVE PUBLICA DEL SERVIDOR FICHERO server.pub
Endpoint = IP_PUBLICA_VPS:51820
AllowedIPs = 0.0.0.0/0
```

Generamos el codigo qr para escanear con el movil:
```bash
qrencode -t ansiutf8 < s24.conf
```

![vps-5.png](vps-5.png)

Y listo. Con esto ya está configurado nuestro servidor y nuestro.  

Arrancamos el servicio y lo habilitamos:
```bash
systemctl start wg-quick@wg0
systemctl enable wg-quick@wg0

#Vemos el estado del servidor
wg show
```

![vps-4.png](vps-4.png)

Cuando actualicemos algún peer reiniciamos el servidor wireguard:
```bash
systemctl restart wg-quick@wg0
```

**IMPORTANTE: Fichero wg0.conf no se puede borrar**. Los ficheros .conf de los clientes no es necesarios conservarlos.Simplemente los creamos para generar luego el qr o para importarlos desde nuestro gestor de red de Gnome. RECORDAR actualizar nuestro fichero wg0.conf con cada cliente que añadimos.


### EXTRA 2: Ampliar la capacidad de RAM de nuestro VPS con swap

Nuestro VPS está muy escaso de RAM. Vamos a darle algo de margen aprovechando nuestro nvme y creando una swap de 1GB de tamaño.  

Creación de nuestro fichero swap:
```bash

sudo fallocate -l 1G /swapfile
ls -la /

sudo chmod 600 /swapfile

sudo mkswap /swapfile

sudo swapon /swapfile

echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
cat /etc/fstab

free -h

sudo sysctl vm.swappiness=20
htop
```

![vps-3.png](/vps-3.png)


### EXTRA 3: Backups remotos con Borgmatic

En este mismo blog, tengo [una entrada](https://blog.lasnotasdenoah.com/posts/borg-backups/) con la configuración de borgmatic en mi NAS secundario de backups.  
Vamos a hacer una mejora en la programación de los backups.  
Debian 13 ya no usa cron para las tareas. Ahora usa systemd.

Instalación de borgmatic
```bash
# Instalación
sudo apt install borgmatic

# Generamos fichero de configuración
sudo generate-borgmatic-config
```

Editamos nuestro fichero de borgmatic:
```bash 
sudo nano /etc/borgmatic/config.yaml

# Añadimos lo siguiente:
source_directories:
  - /home/usuario

repositories:
  # USAMOS NUESTRA IP DE TAILSCALE
  - path: ssh://borg@100.105.100.10:2222/./piensa
    label: piensa

exclude_caches: true
exclude_patterns:
  - '*.pyc'
  - /home/*/.cache


compression: auto,zstd
encryption_passphrase: PASS_SUPER_SECRETA
archive_name_format: "{hostname}-{now}"

# Usamos root porque hay directorios que solo tienen permisos de root (pe. en crowdsec)
ssh_command: ssh -i /root/.ssh/piensa
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
    - url: mailtos://smtp.gmail.com:587?user=SUPERUSUARIO@gmail.com&pass=SUPERSECRETA_PASS&from=SUPERUSUARIO@gmail.com&to=DESTINATARIO@gmail.com
      label: mail
    - url: tgram://BOT_TOKEN:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/-ID_GRUPO_TELEGRAM/
      label: telegram

  start:
    title: ⚙️ Starrted Backup Piensa
    body: Starting backup process

  finish:
    title: ✅ SUCCESS Backup Piensa
    body: Backup Piensa success

  fail:
    title: ❌ FAILED Backup Piensa
    body: Backups Piensa failed
```

Con esto ya está configurado el backup de nuestros datos.  

Vamos a programar los backups. En [la web de borgmatic](https://torsion.org/borgmatic/how-to/set-up-backups/) nos explica como hacerlo con tareas de systemd.

```bash

wget https://projects.torsion.org/borgmatic-collective/borgmatic/raw/branch/main/sample/systemd/borgmatic.service
wget https://projects.torsion.org/borgmatic-collective/borgmatic/raw/branch/main/sample/systemd/borgmatic.timer
sudo mv borgmatic.service borgmatic.timer /etc/systemd/system/
```

```bash
# Connfiguración de horario:
cd /etc/systemd/system
sudo nano borgmatic.timer

# Añadimos lo siguiente:
[Unit]
Description=Run borgmatic backup every day at 23:25:00

[Timer]
#OnCalendar=daily
OnCalendar=*-*-* 23:25:00
Persistent=true
RandomizedDelaySec=10m

[Install]
WantedBy=timers.target
```

Retocamos un par de cosas en nuestro fichero borgmatic.service
```bash
# Connfiguración de horario:
cd /etc/systemd/system
sudo nano borgmatic.service

[Unit]
Description=borgmatic backup
Wants=network-online.target
After=network-online.target
# Prevent borgmatic from running unless the machine is plugged into power. Remove this line if you
# want to allow borgmatic to run anytime.
#ConditionACPower=true
Documentation=https://torsion.org/borgmatic/

[Service]
Type=oneshot
RuntimeDirectory=borgmatic
StateDirectory=borgmatic

# Comentamos para que borgmatic no vaya al fichero borgmatic.pw a buscar las contraseñas
# Load single encrypted credential.
# LoadCredentialEncrypted=borgmatic.pw

LockPersonality=true
MemoryDenyWriteExecute=no
NoNewPrivileges=yes
PrivateDevices=yes
PrivateTmp=yes
ProtectClock=yes
ProtectControlGroups=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service @mount
SystemCallErrorNumber=EPERM
ProtectSystem=full

CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_RAW

# Lower CPU and I/O priority.
Nice=19
CPUSchedulingPolicy=batch
IOSchedulingClass=best-effort
IOSchedulingPriority=7
IOWeight=100

Restart=no
LogRateLimitIntervalSec=0

# Delay start to prevent backups running during boot. Note that systemd-inhibit requires dbus and
# dbus-user-session to be installed.
ExecStartPre=sleep 1m

# En esta linea es importante indicar la ruta de nuestro borgmatic
# which borgmatic
ExecStart=systemd-inhibit --who="borgmatic" --what="sleep:shutdown" --why="Prevent interrupting scheduled backup" /usr/bin/borgmatic --verbosity -2 --syslog-verbosity 1
```

Por último, solo queda habilitar el nuevo servicio:
```bash
sudo systemctl enable --now borgmatic.timer
```

Verificamos la proxima ejecución:
```bash
systemctl list-timers borgmatic.timer

NEXT                        LEFT LAST                        PASSED UNIT            ACTIVATES        
Fri 2026-03-06 23:30:33 UTC   7h Fri 2026-03-06 07:18:33 UTC 8h ago borgmatic.timer borgmatic.service

1 timers listed.
Pass --all to see loaded but inactive timers, too.
```

Con esto debería estar correctamente configurados los backus a nuestro servidor borg a través del cliente borgmatic.  

Para verificar nuestros backups:
```bash
sudo borgmatic list                   
piensa: Listing archives
my-vps-2026-02-23T12:23:46           Mon, 2026-02-23 12:23:46 [f6508163e6c277ea7cbaf33db275ba2052d430d4538e4ca12161a9fec5ee5a06]
my-vps-2026-02-28T08:10:03           Sat, 2026-02-28 08:10:04 [c0fe77d566cc1db569e05c5ff9d7fc5d845e93b667373de24d86445891645945]
my-vps-2026-03-01T08:10:04           Sun, 2026-03-01 08:10:05 [87a15d7677e28c62fe143e28117652dc8ca9f08b230083a01047147eb0cea948]
my-vps-2026-03-02T23:25:04           Mon, 2026-03-02 23:25:05 [e4209a633f6a2f67cba38e3f4d6c481e6212cbcf76d0d2f79d22cc2c52d754e6]
my-vps-2026-03-03T00:51:39           Tue, 2026-03-03 00:51:40 [f1c31249f7c8ded0e7d289a593c78e146606934cd5a913fec9959e7268e88cea]
```

### EXTRA 4: Restaurar el backup  
  
Esta la parte más importante de los backups. He realizado varias pruebas y todo ha funcionado correctamente. Para restaurar el backup primero hacemos un listado de los que tenemos y después montamos el backup en la ubicación deseada para restaurar los ficheros:

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


***   

Fuentes y enlaces de interés que ayudaran a complementar esta guía:  

[Instalación de traefik sin etiquetas](https://www.manelrodero.com/blog/instalacion-y-uso-de-traefik-en-docker-sin-etiquetas)    
[Crowdsec WAF - Appsec](https://docs.crowdsec.net/docs/appsec/quickstart/traefik)  
[Web oficial de borgmatic](https://torsion.org/borgmatic/how-to/set-up-backups/)