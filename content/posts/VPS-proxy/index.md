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
mkdir -p /home/noah/traefik-crowdsec/redis-data
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
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /usr/share/zoneinfo/${TZ:-Europe/Madrid}:/etc/localtime:ro
      - ./traefik/traefik.yml:/traefik.yml:ro
      - ./traefik/conf.d:/conf.d:ro
      - ./traefik/ssl:/ssl
      - ./traefik/logs:/var/log/traefik
    networks:
      - infra_network

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    restart: unless-stopped
    environment:
      - COLLECTIONS=crowdsecurity/traefik crowdsecurity/http-cve 
      # ESTAS COLECCIONES LAS AÑADIREMOS LUEGO crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules
      - DISABLE_CAPI=true  # Ignora CAPI completamente. Esto es para iniciar el contenedor sin avisos de error. Posteriormente habilitamos CAPI.
    volumes:
      - ./traefik/logs:/var/log/traefik:ro   # comparte los logs
      - ./crowdsec/data:/var/lib/crowdsec/data
      - ./crowdsec/config:/etc/crowdsec
    networks:
      - infra_network
  
  # Usaremos redis como caché para quitar trabajo a nuestro crowdsec  
  redis:
    image: redis:alpine
    container_name: crowdsec-redis
    restart: unless-stopped
    volumes:
      - ./redis-data:/data
    networks:
      - infra_network

networks:
  infra_network:
    name: infra_network
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
**NOTA: Esta configuración es para emitir certificados individuales por cada servicio. Unas líneas más abajo modificamos nuestro traefik.yml para usar certificados Wildcard.**   
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
      # Aquí podemos añadir los middleware que queramos de forma general. En mi caso no tengo ninguno porque prefiero añadirlos de forma manual a cada fichero en conf.d:
#      middlewares:
#        - crowdsec-bouncer
#        - security-headers

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
**NOTA: Con esta configuración de traefik.yml se genera un certificado para cada servicio**.  
Vamos a modificarla para generar un solo certificado por dominio, lo que se llama **Certificados Wildcard** y de esta forma me facilitará un poco otra parte de la configuración que será hacer una servidor DNS privado con [Adguard Home](https://adguard.com/es/adguard-home/overview.html).

```bash
# Modificaciones en fichero traefik.yml
[.......]
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
        domains:
          - main: "midominio1.com"
            sans:
              - "*.midominio1.com"
          - main: "midominio2.com"
            sans:
              - "*.midominio2.com"
accessLog:
  filePath: "/var/log/traefik/access.log"
[.......]
```

Ahora tenemos que hacer una pequeña modificación en cada fichero de traefik/conf.d. Ahora vemos un ejemplo con certificado individual y otro con certificado Wildcard.  


Dentro de conf.d crearemos nuestros ficheros para dashboard, middlewares y distintos servicios.  
**Fichero dashboard.yml con certificado individual:**
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

**Fichero dashboard.yml con certificado Wildcard:**
```bash
http:
  routers:
    dashboard:
      rule: "Host(`traefik.midominio.com`)"
      service: api@internal
      entryPoints:
        - websecure
      tls: {}   # o simplemente ‘tls: true’ en v3
      middlewares:
        - geoblock-es
        - crowdsec-bouncer
        - security-headers
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
          CrowdsecMode: stream          # live o stream
          # Identidad fija para evitar los "bouncers fantasmas"
          # No funciona bien. De vez en cuando tengo un bouncer traefik-bouncer@172.18.0.X
          bouncerName: "traefik-bouncer"

          # Conexión a la LAPI (Local API)
          #CrowdsecLapiUrl: "http://crowdsec:8080" Nomenclatura antigua
          CrowdsecLapiScheme: "http"
          CrowdsecLapiHost: "crowdsec:8080"
          CrowdsecLapiKey: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

          # Cache Redis
          RedisCacheEnabled: true
          RedisCacheHost: "crowdsec-redis:6379"
          # LogLevel: "DEBUG"

          # Configuración del WAF se añade luego junto con las colecciones (AppSec)
          CrowdsecAppsecEnabled: true
          CrowdsecAppsecHost: "crowdsec:7422" # Puerto por defecto del WAF en el contenedor crowdsec
          CrowdsecAppsecFailureBlock: true
          CrowdsecAppsecUnreachableBlock: true

          # Trusted IPs
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
          CrowdsecMode: strem          # live o stream
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

Fichero de ejemplo de un servicio con certificado individual:
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

Fichero de ejemplo de un servicio con certificado Wildcard:
karakeep.yml:
```bash
http:
  routers:
    karakeep:
      rule: "Host(`karakeep.midominio.com`)"
      service: karakeep
      entryPoints:
        - websecure
      tls: {}   # o simplemente ‘tls: true’ en v3
      middlewares:
        - geoblock-es
        - crowdsec-bouncer
        - security-headers

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
      # Opción para certificado individual
      #tls:
      #  certResolver: letsencrypt
      # Opción para certificado Wildcard
      tls: {}
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

**NOTA**: En el fichero traefik.yml le podemos indicar a traefik que todo el tráfico que entre por 443 pase por los siguientes middlewares:
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
En nuestro script de creación de servicios hemos comentado los middleware para añadir cado uno según nuestras necesidades.  


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
# 1. PERFIL PARA REINCIDENTES (Primero en la lista)
name: reincident_remediation
filters:
# Usamos la función correcta para contar decisiones previas de esa IP
 - Alert.Remediation == true && Alert.GetScope() == "Ip" && GetDecisionsCount(Alert.GetValue()) > 0
decisions:
 - type: ban
   duration: 168h # 1 semana de "nevera" VAMOS A SER MUY EXTRICTOS CON LOS REINCIDENTES
notifications:
 - telegram
on_success: break # Si entra aquí, no sigue leyendo hacia abajo

---

# 2. PERFIL POR DEFECTO PARA IPs
name: default_ip_remediation
#debug: true
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
 - type: ban
   duration: 48h
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

# 3. PERFIL PARA RANGOS
name: default_range_remediation
#debug: true
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Range"
decisions:
 - type: ban
   duration: 48h
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
#          CrowdsecMode: stream          # live o stream
          crowdsecMode: stream          # live o stream
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

En teoría, siguiendo las [instrucciones de crowdsec](https://docs.crowdsec.net/docs/appsec/quickstart/traefik) deberíamos mapear el fichero en el contenedor de docker, **pero yo no lo he hecho y funciona igual**:

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
Llegados a este punto, parece que Appsec funciona correctamente, pero no es cierto. Con el tiempo veremos que procesa muchas peticiones pero no bloquea ninguna. Vamos a ponerle remedio.

### Mejoras en la configuración de Appsec

Verificamos las colecciones de Appsec:
```bash
docker exec crowdsec cscli collections list -a | grep appsec
```

Salida:
```bash
 crowdsecurity/appsec-crs                              ✔️  enabled                    0.8      /etc/crowdsec/collections/appsec-crs.yaml              
 crowdsecurity/appsec-crs-exclusion-plugin-cpanel      🚫  disabled,update-available                                                                  
 crowdsecurity/appsec-crs-exclusion-plugin-dokuwiki    🚫  disabled,update-available                                                                  
 crowdsecurity/appsec-crs-exclusion-plugin-drupal      🚫  disabled,update-available                                                                  
 crowdsecurity/appsec-crs-exclusion-plugin-nextcloud   🚫  disabled,update-available                                                                  
 crowdsecurity/appsec-crs-exclusion-plugin-phpbb       🚫  disabled,update-available                                                                  
 crowdsecurity/appsec-crs-exclusion-plugin-phpmyadmin  🚫  disabled,update-available                                                                  
 crowdsecurity/appsec-crs-exclusion-plugin-wordpress   🚫  disabled,update-available                                                                  
 crowdsecurity/appsec-crs-exclusion-plugin-xenforo     🚫  disabled,update-available                                                                  
 crowdsecurity/appsec-crs-inband                       🚫  disabled,update-available                                                                  
 crowdsecurity/appsec-generic-rules                    ✔️  enabled                    1.1      /etc/crowdsec/collections/appsec-generic-rules.yaml    
 crowdsecurity/appsec-virtual-patching                 ✔️  enabled                    14.7     /etc/crowdsec/collections/appsec-virtual-patching.yaml 
 crowdsecurity/appsec-wordpress                        🚫  disabled,update-available                                                                  
 openappsec/openappsec                                 🚫  disabled,update-available  
```

Modificamos nuestro fichero **appsec-default.yaml**
```bash
sudo nano ~/traefik-crowdsec/crowdsec/config/hub/appsec-configs/crowdsecurity/appsec-default.yaml

# Contenido:
name: crowdsecurity/appsec-default
default_remediation: ban

inband_rules:
 - crowdsecurity/base-config
 - crowdsecurity/vpatch-*
 - crowdsecurity/generic-*
 - crowdsecurity/crs            <---- AÑADIMOS ESTO

outofband_rules:
 - crowdsecurity/experimental-*
 - crowdsecurity/appsec-generic-test
```

Reiniciamos crowdsec. Es posible que en el reinicio nos cree un nuevo bouncer. Ya sabemos lo que hay que hacer.
```bash
docker restart crowdsec
```

Prueba de funcionamiento:
```bash
prueba:
# Terminal 1 en VPS Dejamos los logs visualizando
docker logs crowdsec -f 2>&1

# Terminal 2 en mi pc - SIMULAMOS UNA PETICIÓN QUE APPSEC DEBERÍA BLOQUEAR
curl -v "https://lasnotasdenoah.com/?id=1+UNION+SELECT+1,2,3--"
```

Esta vez deberías recibir un 403.  
⚠️ Aviso importante: este archivo es del hub y cscli hub update podría sobreescribirlo en el futuro. Para hacerlo permanente sin que se pierda, lo ideal sería crear un appsec-config personalizado en /etc/crowdsec/appsec-configs/ con otro nombre que no gestione el hub.   

Vamos a hacer permanente el cambio:
```bash
sudo cp ~/traefik-crowdsec/crowdsec/config/hub/appsec-configs/crowdsecurity/appsec-default.yaml \
        ~/traefik-crowdsec/crowdsec/config/appsec-configs/myconfig-appsec-default.yaml
```

Editamos nuestro fichero **acquis.d/appsec.yaml**:
```bash
appsec_config: myconfig-appsec-default
labels:
  type: appsec
listen_addr: 0.0.0.0:7422
source: appsec
```

Reiniciamos crowdsec
```bash
docker compose restart crowdsec                             
```

**Y vemos que no arranca**.  
El motivo es el siguiente: El problema es que cuando usas appsec_config: myconfig-appsec-default CrowdSec busca ese nombre dentro del hub, no por nombre de archivo. El nombre que registra CrowdSec es el campo name: dentro del yaml, no el nombre del fichero.   

Vamos a editar nuevamente nuestro fichero **myconfig-appsec-default.yaml**:
```bash
sudo nano ~/traefik-crowdsec/crowdsec/config/appsec-configs/myconfig-appsec-default.yaml

# Contenido: 
name: custom/appsec-default  # <--- MODIFICAMOS EL NOMBRE
default_remediation: ban

inband_rules:
 - crowdsecurity/base-config
 - crowdsecurity/vpatch-*
 - crowdsecurity/generic-*
 - crowdsecurity/crs

outofband_rules:
 - crowdsecurity/experimental-*
 - crowdsecurity/appsec-generic-test


```bash
sudo nano ~/traefik-crowdsec/crowdsec/config/acquis.d/appsec.yaml

# Contenido:
appsec_configs:
  - custom/appsec-default
labels:
  type: appsec
listen_addr: 0.0.0.0:7422
source: appsec
```

Verificamos que funciona:
```bash
docker restart crowdsec
docker logs crowdsec 2>&1 | grep -E "fatal|error|inband" | head -10
```

Llegados a este punto, todos mis servicios deberían funcionar correctamente excepto Nextcloud. Nos vamos al siguiente punto del tutorial.

### Correcciones de Nextcloud para funcionar con Appsec
Las reglas crowdsecurity/crs (Core Rule Set de OWASP) son muy agresivas y bloquean muchas peticiones legítimas de Nextcloud, especialmente las subidas de archivos, WebDAV, y las llamadas a la API.   
Tenemos varias opciones:  

**OPCION 1.- Configuración reglas acceso de Appsec para Nextcloud**
```bash
sudo nano ~/traefik-crowdsec/crowdsec/config/appsec-configs/myconfig-appsec-default.yaml

# Contenido:
name: custom/appsec-default
default_remediation: ban

inband_rules:
  - crowdsecurity/base-config
  - crowdsecurity/vpatch-*
  - crowdsecurity/generic-*
  - crowdsecurity/crs

# OPCION 1
inband_options:
  request_exclusions:
    - rules_ids:
        - crowdsecurity/crs
      zone: URI
      zone_filter: "^/(remote\\.php|ocs|index\\.php|apps|core|status\\.php|login|logout|cron\\.php|public\\.php|dav|caldav|carddav|webdav)"

outofband_rules:
  - crowdsecurity/experimental-*
  - crowdsecurity/appsec-generic-test


# OPCION 2
inband_options:
  request_exclusions:
    - rules_ids:
        - crowdsecurity/crs
      zone: URI
      zone_filter: "^/(remote\\.php|ocs|index\\.php|apps|core|status\\.php|login|logout|cron\\.php|public\\.php|dav)"

# Buscando información: Request_exclusions no existe en esta versión de CrowdSec. La estructura inband_options solo acepta disable_rules. La solución correcta para esta versión es usar on_match con un filtro de URI:

# OPCION 3
on_match:
  - filter: "match(req.URI, '^/(remote\\.php|ocs|index\\.php|apps|core|status\\.php|login|logout|cron\\.php|public\\.php|dav)') && evt.Rules_matched contains 'crowdsecurity/crs'"
    apply:
      - SetRemediation("allow")

# OPCION 4
on_match:
  - filter: "evt.Rules_matched contains 'crowdsecurity/crs' && (contains(req.URI, '/remote.php') || contains(req.URI, '/ocs/') || contains(req.URI, '/index.php') || contains(req.URI, '/apps/') || contains(req.URI, '/dav') || contains(req.URI, '/status.php') || contains(req.URI, '/cron.php') || contains(req.URI, '/public.php'))"
    apply:
      - SetRemediation("allow")

# OPCION 5
on_match:
  - filter: "'crowdsecurity/crs' in evt.Rules_matched && (req.URI startsWith '/remote.php' || req.URI startsWith '/ocs/' || req.URI startsWith '/index.php' || req.URI startsWith '/apps/' || req.URI startsWith '/dav' || req.URI startsWith '/status.php' || req.URI startsWith '/cron.php' || req.URI startsWith '/public.php')"
    apply:
      - SetRemediation("allow")
```
**FALLAN TODAS LAS OPCIONES DE MODIFICAR NUESTRO FICHERO myconfig-appsec-default.yaml. No conseguí hacerlo funcionar**  

**OPCION 2.- Configurar un middleware de crowdsec sin Appsec para Nextcloud**  
Vamos a actuar sobre traefik. El plan es sencillo y a la vez potente. Añadiremos un nuevo middleware llamado crowdsec-bouncer-noappsec en middlewares.yml y lo usaremos en el router de Nextcloud.  
Nuestro Nextcloud no tendrá la protección del WAF Appsec pero nos protege igualmente Crowdsec.  

```bash
nano ~/traefik-crowdsec/traefik/conf.d/middlewares.yml

# Añadimos el siguiente middleware después del middleware crowdsec-bouncer:
crowdsec-bouncer-noappsec:
      plugin:
        crowdsec-bouncer:
          Enabled: true
          CrowdsecMode: stream
          bouncerName: "traefik-bouncer"
          CrowdsecLapiScheme: "http"
          CrowdsecLapiHost: "crowdsec:8080"
          CrowdsecLapiKey: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
          RedisCacheEnabled: true
          RedisCacheHost: "crowdsec-redis:6379"
          CrowdsecAppsecEnabled: false
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
**NOTAS IMPORTANTES: Podemos usar el mismo CrowdsecLapiKey para los dos middleware**   

Modificamos nuestro fichero estático de Nextcloud:
```bash
nano ~/traefik-crowdsec/traefik/conf.d/nextcloud.yml  

# Contenido:
http:
  routers:
    nextcloud:
      rule: "Host(`nextcloud.lafinquina.com`)"
      service: nextcloud
      entryPoints:
        - websecure
      tls: {}   # o simplemente ‘tls: true’ en v3
      middlewares:
        - geoblock-es
        - crowdsec-bouncer-noappsec        # <----- Este es el nuevo middleware
        - security-headers

  services:
    nextcloud:
      loadBalancer:
        servers:
          - url: "http://100.105.100.10:8666"
```

En este caso no es necesario reiniciar, ya que traefik cargará la nueva configuración de forma automática. Esperamos unos segundos y ya debería estar cargada la nueva configuración:
![vps-6.png](vps-6.png)


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
   
**Vamos a automatizarlo con timers de systemd.**  

Script de actualización:
```bash
sudo nano /usr/local/bin/crowdsec-update.sh
# Contenido:

#!/bin/bash
set -e

COMPOSE_DIR="/home/noe/traefik-crowdsec"

echo "Actualizando CrowdSec hub..."
docker exec crowdsec cscli hub update
docker exec crowdsec cscli hub upgrade --force

echo "Reiniciando CrowdSec..."
cd "$COMPOSE_DIR" && docker compose restart crowdsec

echo "Actualización completada."
```

Lo hacemos ejecutable:
```bash
sudo chmod +x /usr/local/bin/crowdsec-update.sh
```

Creamos el servicio systemd:
```bash
sudo nano /etc/systemd/system/crowdsec-update.service

# Contenido:
[Unit]
Description=CrowdSec hub update
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/crowdsec-update.sh
StandardOutput=journal
StandardError=journal
```

Timer Unit:
```bash
sudo nano /etc/systemd/system/crowdsec-update.timer

# Contenido:
[Unit]
Description=CrowdSec hub update semanal

[Timer]
OnCalendar=Sun *-*-* 03:00:00
Persistent=true
# El Persistent=true garantiza que si el servidor estaba apagado el domingo a las 3:00, ejecuta la actualización en el próximo arranque.
RandomizedDelaySec=10min

[Install]
WantedBy=timers.target
```

Y activamos
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now crowdsec-update.timer
```

Verificaciones:
```bash
# Estado del timer
systemctl status crowdsec-update.timer

# Cuándo ejecutará la próxima vez
systemctl list-timers crowdsec-update.timer

# Probar manualmente
sudo systemctl start crowdsec-update.service
journalctl -u crowdsec-update.service -f
```


### Configuración de CAPI en Crowdsec

CAPI significa Central API. Es la red de inteligencia colectiva de CrowdSec.  

Con CAPI activado: El servidor recibe una lista de miles de IPs que ya han sido reportadas como maliciosas por otros usuarios de CrowdSec en el mundo. Las bloqueas antes de que  toquen nuestro servidor.  

Con CAPI desactivado: El servidor está en modo "isla". Solo bloquea lo que él mismo detecta. Es mucho menos eficiente.   

Modificamos el docker-compose:
```bash
services:
  crowdsec:
    # ...
    environment:
      - DISABLE_CAPI=false  # Permitir inteligencia colectiva y Consola
```
A veces se desactiva por privacidad extrema (para no enviar señales de ataque a los servidores de CrowdSec) o para ahorrar un mínimo de ancho de banda. Pero para un VPS estándar con Traefik, tenerlo en false es lo recomendado para estar protegido por la "inmunidad de grupo".  

Reiniciamos docker compose:
```bash
docker compose restart
```

Accedemos a nuestra consola de crowdsec [app.crowdsec.net](https://app.crowdsec.net/) y vamos a **Engines** y **Enroll** y nos dará la key para hacer el enrolado:
```bash
docker exec crowdsec cscli console enroll XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Verificamos:
```bash
docker exec crowdsec cscli console status
+--------------------+-----------+------------------------------------------------------+
| Option Name        | Activated | Description                                          |
+--------------------+-----------+------------------------------------------------------+
| custom             | ✅        | Forward alerts from custom scenarios to the console  |
| manual             | ✅        | Forward manual decisions to the console              |
| tainted            | ✅        | Forward alerts from tainted scenarios to the console |
| context            | ✅        | Forward context with alerts to the console           |
| console_management | ❌        | Receive decisions from console                       |
+--------------------+-----------+------------------------------------------------------+
```
Ahora mismo la comunicación es unidireccional: el VPS le cuenta cosas a la consola. Si activamos la última opción, la comunicación será bidireccional:  
1.- Bloqueo remoto: Si ves una IP atacándote desde el móvil en la web de la consola, podrás darle a "Ban" y la consola le dirá a tu VPS que la bloquee inmediatamente.  
2.- Suscripción a listas: Podrás suscribirte a listas de bloqueo de terceros (por ejemplo, "IPs de nodos de salida Tor" o "Bad Bots") desde la web y se aplicarán solas en tu Traefik.

Vamos a activarla:
```bash
docker exec crowdsec cscli console enable console_management
docker compose restart crowdsec

docker exec crowdsec cscli console status  

# Salida:                 
+--------------------+-----------+------------------------------------------------------+
| Option Name        | Activated | Description                                          |
+--------------------+-----------+------------------------------------------------------+
| custom             | ✅        | Forward alerts from custom scenarios to the console  |
| manual             | ✅        | Forward manual decisions to the console              |
| tainted            | ✅        | Forward alerts from tainted scenarios to the console |
| context            | ✅        | Forward context with alerts to the console           |
| console_management | ✅        | Receive decisions from console                       |
+--------------------+-----------+------------------------------------------------------+
```

Verificamos el estado:
```bash
docker exec crowdsec cscli capi status

# Salida:
Loaded credentials from /etc/crowdsec//online_api_credentials.yaml
You can successfully interact with Central API (CAPI)
Your instance is enrolled in the console
Subscription type: COMMUNITY
Sharing signals is enabled
Pulling community blocklist is enabled
Pulling blocklists from the console is enabled
```

Con esto, obtenemos una protección muy superior a la que ya teníamos.  

Para ver los ataques accedemos a [app.crowdsec.net](https://app.crowdsec.net/) y en la sección **Alerts** tenemos los datos por IP, paises, tipo ataque, motivo baneo, etc.


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

### Mejoras en sistema de actualizaciones de crowdsec

Vamos a mejorar nuestro sistema, poniendo las actualizaciones de Telegram más chulas y añadiendo un pulsador de unban para IPs que se baneen por error.  

Modificamos nuestro docker compose:  
**Este servicio es el encargado de interaccionar con crowdsec para desbanear IPs**
```bash
# Añadimos un nuevo servicio:
  crowdsec-decisions-bot:
    image: lluisd/crowdsec-decisions-bot:latest
    container_name: crowdsec-decisions-bot
    restart: unless-stopped
    ports:
      - "3005:3000"
    environment:
      - TELEGRAM_TOKEN=${TELEGRAM_TOKEN} # Token de BotFather
      - LAPI_URL=http://crowdsec:8080  # URL de tu contenedor CrowdSec
      - LAPI_LOGIN=${LAPI_LOGIN}
      - LAPI_PASSWORD=${LAPI_PASSWORD}
    networks:
      - infra_network
```

Nuestro fichero .env:
```bash
TZ=Europe/Madrid

# Cloudflare API_TOKEN
CF_DNS_API_TOKEN=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# Telegram_TOKEN
TELEGRAM_TOKEN=555555555555:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# LAPI Credentials
LAPI_LOGIN=bot-watcher
LAPI_PASSWORD=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```
TELEGRAM_TOKEN es el token de nuestro bot telegram.  
Para obtener los datos LAPI tenemos que crear una nueva machine en crowdsec:
```bash
docker exec crowdsec cscli machines add bot-watcher --force -a
# Si no usamos la opción --force nos dirá crowdsec que ya existe un fichero crowdsec/config/local_api_credentials.yaml y no hará nada.
# La opción -a es para que cree el password de forma automática
```
```bash
sudo cat crowdsec/config/local_api_credentials.yaml

# Aquí ya tenemos los datos que necesitamos, los copiamos a nuestro fichero .env:
url: http://0.0.0.0:8080
login: bot-watcher
password: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Verificamos las machines que tenemos:
```bash
docker exec crowdsec cscli machines list
----------------------------------------------------------------------------------------------------------------------------------
 Name         IP Address  Last Update           Status  Version                 OS                      Auth Type  Last Heartbeat 
----------------------------------------------------------------------------------------------------------------------------------
 localhost    127.0.0.1   2026-04-07T21:55:13Z  ✔️      v1.7.6-eacc8192-docker  alpine (docker)/3.21.5  password   27s            
 bot-watcher  127.0.0.1   2026-04-07T21:42:11Z  ✔️      v1.7.6-eacc8192-docker  ?                       password   ⚠️ -           
----------------------------------------------------------------------------------------------------------------------------------
```

Arrancamos el servicio y verificamos que esté operativo:
```bash
# Levantamos el servicio:
docker compose up -d crowdsec-decisions-bot

# Verificamos los logs:
docker logs -f crowdsec-decisions-bot

> crowdsec-decisions-bot@1.0.0 start
> node ./app.js

Listening on port  3000
Telegram bot on Polling mode
[....]
```

**Ahora vamos a crear un nuevo modelo de notificaciones en crowdsec.**   

Creamos nuestro fichero **crowdsec/config/notifications/telegram_default.yaml**
```bash
# CUMPLIMENTAR LOS SIGUIENTES DATOS:
# chat_id
# apiKey de geoapify.com
# url de Telegram con datos de nuestro bot
type: http
name: telegram
log_level: info

format: |
    {
      "chat_id": "XXXXXXXXX",
      "photo": "https://maps.geoapify.com/v1/staticmap?style=osm-bright-grey&width=600&height=400&center=lonlat:{{(index . 0).Source.Longitude}},{{(index . 0).Source.Latitude}}&zoom=8&marker=lonlat:{{(index . 0).Source.Longitude}},{{(index . 0).Source.Latitude}};type:material;color:%23ff3421;size:large&scaleFactor=2&apiKey=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      "caption": "{{range . -}}{{$alert := . -}}{{range .Decisions -}}{{- $cti := $alert.Source.Value | CrowdsecCTI -}}{{- $flags := dict "US" "🇺🇸" "FR" "🇫🇷" "DE" "🇩🇪" "MX" "🇲🇽" "GB" "🇬🇧" "HK" "🇭🇰" "ES" "🇪🇸" "NL" "🇳🇱" "JP" "🇯🇵" "AR" "🇦🇷" "BR" "🇧🇷" "CA" "🇨🇦" "AU" "🇦🇺" "IN" "🇮🇳" "IT" "🇮🇹" "RU" "🇷🇺" "CN" "🇨🇳" "SA" "🇸🇦" "ZA" "🇿🇦" "KR" "🇰🇷" "ID" "🇮🇩" "NG" "🇳🇬" "EG" "🇪🇬" "TR" "🇹🇷" "SE" "🇸🇪" "NO" "🇳🇴" "DK" "🇩🇰" "FI" "🇫🇮" "PL" "🇵🇱" "PT" "🇵🇹" "CH" "🇨🇭" "BE" "🇧🇪" "AT" "🇦🇹" "SG" "🇸🇬" "MY" "🇲🇾" "TH" "🇹🇭" "PH" "🇵🇭" "VN" "🇻🇳" "PK" "🇵🇰" "BD" "🇧🇩" "UA" "🇺🇦" "RO" "🇷🇴" "HU" "🇭🇺" "BG" "🇧🇬" "SK" "🇸🇰" "HR" "🇭🇷" "SI" "🇸🇮" "EE" "🇪🇪" "LV" "🇱🇻" "LT" "🇱🇹" "CZ" "🇨🇿" "IS" "🇮🇸" "GR" "🇬🇷" "AE" "🇦🇪" "KW" "🇰🇼" "OM" "🇴🇲" "QA" "🇶🇦" "BH" "🇧🇭" "MA" "🇲🇦" "TN" "🇹🇳" "DZ" "🇩🇿" "LY" "🇱🇾" "JO" "🇯🇴" "LB" "🇱🇧" "SY" "🇸🇾" "IQ" "🇮🇶" "YE" "🇾🇪" "IR" "🇮🇷" "MN" "🇲🇳" "KP" "🇰🇵" "TW" "🇹🇼" "MO" "🇲🇴" "LC" "🇱🇨" "TT" "🇹🇹" "VC" "🇻🇨" "BB" "🇧🇧" "JM" "JJAM" "BS" "🇧🇸" "GD" "🇬🇩" "HT" "🇭🇹" "DO" "🇩🇴" "CR" "🇨🇷" "PY" "🇵🇾" "PE" "🇵🇪" "EC" "🇪🇨" "CO" "🇨🇴" "VE" "🇻🇪" "CL" "🇨🇱" "BO" "🇧🇴" "GT" "🇬🇹" "HN" "🇭🇳" "SV" "🇸🇻" "NI" "🇳🇮" "PA" "🇵🇦" "CU" "🇨🇺" -}}{{- $countryCode := upper $alert.Source.Cn -}}{{- $flag := index $flags $countryCode | default $countryCode -}}🚨 *Alerta CrowdSec* \n\n🔴 *IP:* [{{.Value}}](https://www.whois.com/whois/{{.Value}}) \n⚠️ *Escenario:* `{{.Scenario}}` \n⏱️ *Ban:* `{{.Duration}}` \n🌍 *Ubicación:* {{ $flag }} {{ $alert.Source.Cn }} {{if $cti.Location.City}}- {{ $cti.Location.City | replace "\"" "" }}{{end}} \n💀 *Malicia:* {{mulf $cti.GetMaliciousnessScore 100 | floor}}% \n🔊 *Ruido:* {{ $cti.GetBackgroundNoiseScore }}/10 \n\n{{range $alert.Meta -}}{{if not (or (eq .Key "source_ip") (eq .Key "remediation") (eq .Key "scenario")) -}}🔹 *{{.Key}}*: `{{ (splitList "," (.Value | replace "\"" "" | replace "[" "" | replace "]" "")) | join " " }}` \n{{end}}{{end}}{{- end -}}{{- end -}}",
      "parse_mode": "Markdown",
      "reply_markup": {
        "inline_keyboard": [
          {{- $arrLength := len . -}}
          {{- range $i, $value := . -}}
          {{- $V := (index $value.Decisions 0).Value -}}
          [
            {
              "text": "🛡️ Ver en CrowdSec CTI",
              "url": "https://app.crowdsec.net/cti/{{ $V }}"
            }
          ],
          [
            {
              "text": "🔎 Shodan",
              "url": "https://www.shodan.io/host/{{ $V }}"
            }
          ],
          [
            {
              "text": "🔓 UNBAN IP",
              "callback_data": "deleteDecisions~{{ $V }}"
            }
          ]{{if lt $i (sub $arrLength 1)}},{{end}}
          {{- end -}}
        ]
      }
    }

url: https://api.telegram.org/bot111111111:XXXXXXXXXXXXXXXXXXXXXXXXXXXXX/sendPhoto
method: POST
headers:
  Content-Type: "application/json"
```
Para configurar correctamente nuestro fichero tenemos que abrir una cuenta en [Geoapify](https://www.geoapify.com/). Una vez lo tenemos creamos un nuevo proyecto:
![vps-3.png](vps-3.png)

Y creamos una nueva API Key de tipo Map Tiles:
![vps-4.png](vps-4.png)

Y copiamos la APIKey al fichero de notificaciones:
```bash
  "photo": "https://maps.geoapify.com/v1/staticmap?style=osm-bright-grey&width=600&height=400&center=lonlat:{{(index . 0).Source.Longitude}},{{(index . 0).Source.Latitude}}&zoom=8&marker=lonlat:{{(index . 0).Source.Longitude}},{{(index . 0).Source.Latitude}};type:material;color:%23ff3421;size:large&scaleFactor=2&apiKey=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
```

Por último, solo nos queda modificar nuestro fichero **crowdsec/config/profiles.yaml**:
```bash
# 0. PERFIL PARA MEGA-REINCIDENTES (Primero en la lista)
name: mega_reincident_remediation
filters:
# Usamos la función correcta para contar decisiones previas de esa IP
 - Alert.Remediation == true && Alert.GetScope() == "Ip" && GetDecisionsCount(Alert.GetValue()) > 1
decisions:
 - type: ban
   duration: 720h # 1 mes de "nevera"
#notifications:
# - telegram_default
on_success: break # Si entra aquí, no sigue leyendo hacia abajo

---

# 1. PERFIL PARA REINCIDENTES (Primero en la lista)
name: reincident_remediation
filters:
# Usamos la función correcta para contar decisiones previas de esa IP
 - Alert.Remediation == true && Alert.GetScope() == "Ip" && GetDecisionsCount(Alert.GetValue()) == 1
decisions:
 - type: ban
   duration: 168h # 1 semana de "nevera"
notifications:
 - telegram_default
on_success: break # Si entra aquí, no sigue leyendo hacia abajo

---

# 2. PERFIL POR DEFECTO PARA IPs
name: default_ip_remediation
#debug: true
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
 - type: ban
   duration: 48h
notifications:
 - telegram_default
#duration_expr: Sprintf('%dh', (GetDecisionsCount(Alert.GetValue()) + 1) * 4)
# notifications:
#   - slack_default  # Set the webhook in /etc/crowdsec/notifications/slack.y>
#   - splunk_default # Set the splunk url and token in /etc/crowdsec/notifica>
#   - http_default   # Set the required http parameters in /etc/crowdsec/noti>
#   - email_default  # Set the required email parameters in /etc/crowdsec/not>
on_success: break

---

# 3. PERFIL PARA RANGOS
name: default_range_remediation
#debug: true
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Range"
decisions:
 - type: ban
   duration: 48h
#duration_expr: Sprintf('%dh', (GetDecisionsCount(Alert.GetValue()) + 1) * 4)
# notifications:
#   - slack_default  # Set the webhook in /etc/crowdsec/notifications/slack.y>
#   - splunk_default # Set the splunk url and token in /etc/crowdsec/notifica>
#   - http_default   # Set the required http parameters in /etc/crowdsec/noti>
#   - email_default  # Set the required email parameters in /etc/crowdsec/not>
on_success: break
```

Esta nueva versión hace lo siguiente:
```bash
# 2. PERFIL POR DEFECTO PARA IPs
  - Alert.Remediation == true && Alert.GetScope() == "Ip"
# Si detecta una IP la banea 48 horas y envía notificación

# 1. PERFIL PARA REINCIDENTES (Primero en la lista)
 - Alert.Remediation == true && Alert.GetScope() == "Ip" && GetDecisionsCount(Alert.GetValue()) == 1
# Si detecta un reincidente lo banea 1 semana y envía notificación

# 0. PERFIL PARA MEGA-REINCIDENTES (Primero en la lista)
 - Alert.Remediation == true && Alert.GetScope() == "Ip" && GetDecisionsCount(Alert.GetValue()) > 1
# Si detecta un super-reincidente lo banea 1 mes y NO envía notificación
# NO QUIERO EL GRUPO DE TELEGRAM LLENO DE MENSAJES

# El perfil para rangos no lo he tocado.
```



**Prueba**. Baneamos una IP
```bash
docker exec crowdsec cscli decisions add --ip 1.2.3.4 --reason "Prueba de Bot"

# Verificamos en la lista
docker exec crowdsec cscli decisions list

# Arrancamos los logs de nuestro crowdsec-decisions-bot:
docker logs -f crowdsec-decisions-bot
```
Ejemplo notificación:
![vps-5.png](vps-5.png)

```bash
# Pulsamos en unban de Telegram y deberíamos ver lo siguiente:
docker logs -f crowdsec-decisions-bot

> crowdsec-decisions-bot@1.0.0 start
> node ./app.js

Listening on port  3000
Telegram bot on Polling mode
Calling /v1/decisions?ip=1.2.3.4
Calling /v1/watchers/login
1 decision deleted for IP: 1.2.3.4

# Verificamos en la lista nuevamente que ya no esté la IP
docker exec crowdsec cscli decisions list
```

***   
Fuentes y enlaces de interés que ayudaran a complementar esta guía:  

**Debo decir que en esta guía he tirado mucho de IA.**  

[Instalación de traefik sin etiquetas](https://www.manelrodero.com/blog/instalacion-y-uso-de-traefik-en-docker-sin-etiquetas)    
[Crowdsec WAF - Appsec](https://docs.crowdsec.net/docs/appsec/quickstart/traefik)  
[Web oficial de borgmatic](https://torsion.org/borgmatic/how-to/set-up-backups/)  
Agradecimientos en Telegram para @joled y @lluis2k del Grupo [Detras del mostraddor](https://t.me/detrasdelmostrador) que me ayudaron en las mejoras del sistema de actualizaciones de Crowdsec.