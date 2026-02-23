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
    image: crowdsecurity/crowdsec
    container_name: crowdsec
    restart: unless-stopped
    environment:
      - COLLECTIONS=crowdsecurity/traefik crowdsecurity/http-cve crowdsecurity/appsec-generic-rules
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
- COLLECTIONS=crowdsecurity/traefik crowdsecurity/http-cve crowdsecurity/appsec-generic-rules
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
      version: v1.3.5

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

          # Configuración del WAF (AppSec)
          appsecEnabled: true
          appsecHost: "crowdsec:7422" # Puerto por defecto del WAF en el contenedor crowdsec
          appsecFailureAction: "passthrough" # Si el WAF falla, deja pasar (o "block" para máxima seguridad)
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

### EXTRA: Ampliar la capacidad de RAM de nuestro VPS con swap

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

***   

Fuentes y enlaces de interés que ayudaran a complementar esta guía:  

[Instalación de traefik sin etiquetas](https://www.manelrodero.com/blog/instalacion-y-uso-de-traefik-en-docker-sin-etiquetas)    