---
title: Instalación de Owncloud oCIS en Unraid
description: Nube privada para mi servidor
date: 2026-05-09 07:00:00 +0100
categories:
   - Unraid
tags:
   - Admin
weight: 1
---

### Owncloud oCIS

oCIS está escrito en Go, lo que lo hace extremadamente rápido y ligero, funcionando como un binario único. Nextcloud utiliza PHP, lo que facilita su personalización pero requiere más recursos y optimización del servidor para grandes volúmenes.  

Mientras que oCIS se centra en ser un especialista en almacenamiento y sincronización a gran escala, Nextcloud se posiciona como una "Content Collaboration Platform" completa, incluyendo chat, videollamadas y oficina en línea de forma nativa.  

Llevo varios años usando Nextcloud y nunca he usado ninguna de sus aplicaciones. Tengo la sensación que es lento y por eso vamos a probar Owncloud.  

### Esquema inicial

***Petición a cloud.midominio.com ---> VPS con traefik + lldap + authelia ---> NAS con Owncloud***

### Docker-compose
Si dejamos que docker cree las carpetas nos dará errores de permisos, por tanto las creamos de forma manual:
```bash
# Ficheros de configuración en appdata como siempre
mkdir -p /mnt/user/appdata/ocis/config


# Almacenamiento de datos
# Creamos el recurso compartido en Unraid y después los directorios necesarios
mkdir -p /mnt/user/Ocis-Files/ocis-data                          
mkdir -p /mnt/user/Ocis-Files/thumbnails

# Cambiamos el usuario de los directorios porque sino Ocis nos dará problemas de permisos.
chown -Rfv 1000:1000 /mnt/user/appdata/ocis
chown -Rfv 1000:1000 /mnt/user/Ocis-Files

# Como unraid deja permisos 777 vamos a cambiarlos tambien
chmod -R 755 /mnt/user/Ocis-Files
chmod -R 755 /mnt/user/appdata/ocis
```

Docker-compose:
```bash
services:
  ocis:
    image: owncloud/ocis:latest
    container_name: ocis
    restart: unless-stopped
    user: "1000:1000"
    entrypoint:
      - /bin/sh
    command: ["-c", "ocis init || true; ocis server"]
    environment:
      # --- Dominio público (el que Traefik expone en el VPS) ---
      OCIS_URL: https://cloud.midominio.com
      OCIS_LOG_LEVEL: info  # Cambiar a debug si hay problemas
      OCIS_LOG_COLOR: true
      OCIS_LOG_PRETTY: true

      # --- Deshabilita TLS interno (Traefik termina TLS) ---
      PROXY_TLS: "false"
      OCIS_INSECURE: "true"

      # Configuración para que no se cierre sesión tan a menudo
      OCIS_ACCESS_TOKEN_LIFETIME: 1h
      OCIS_REFRESH_TOKEN_LIFETIME: 2160h
       
    volumes:
      - /mnt/user/appdata/ocis/config:/etc/ocis
      - /mnt/user/Ocis-Files/ocis-data:/var/lib/ocis
      - /mnt/user/Ocis-Files/thumbnails:/var/lib/ocis-thumbnails

    ports:
      # Solo escucha en la IP de Tailscale, no expone al exterior
      - "100.105.100.10:9200:9200"

    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9200/health"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  default:
    name: cloud
    external: true
```

Después de configurar Authelia añadiremos las siguientes variables al compose:

```bash
    environment:
      # --- OIDC / Authelia ---
      OCIS_EXCLUDE_RUN_SERVICES: "idp"
      WEB_OIDC_CLIENT_ID: 'ocis'
      PROXY_OIDC_ISSUER: 'https://auth.midominio.com'
      PROXY_OIDC_REWRITE_WELLKNOWN: 'true'
      PROXY_OIDC_ACCESS_TOKEN_VERIFY_METHOD: 'none'
      PROXY_AUTOPROVISION_ACCOUNTS: 'true'
      PROXY_AUTOPROVISION_CLAIM_USERNAME: 'preferred_username'
      PROXY_AUTOPROVISION_CLAIM_EMAIL: 'email'
      PROXY_AUTOPROVISION_CLAIM_DISPLAYNAME: 'name'
      PROXY_AUTOPROVISION_CLAIM_GROUPS: 'groups'
```

Si queremos usar notificaciones por mail:
```bash
      # Email SMTP    
      NOTIFICATIONS_SMTP_HOST: "${SMTP_HOST}"
      NOTIFICATIONS_SMTP_PORT: "${SMTP_PORT}"
      NOTIFICATIONS_SMTP_SENDER: "${SMTP_SENDER}"
      NOTIFICATIONS_SMTP_USERNAME: "${SMTP_USERNAME}"
      NOTIFICATIONS_SMTP_PASSWORD: "${SMTP_PASSWORD}"
      NOTIFICATIONS_SMTP_AUTHENTICATION: "${SMTP_AUTHENTICATION}"
      NOTIFICATIONS_SMTP_ENCRYPTION: "${SMTP_ENCRYPTION}"
      NOTIFICATIONS_SMTP_INSECURE: "${SMTP_INSECURE}"
```

Después de añadir nuestras variables, modificamos el fichero .env:
```bash
# Datos SMTP de Gmail
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
#SMTP_SENDER=oCIS notifications <mi_correo@gmail.com>
SMTP_SENDER=mi_correo@gmail.com
SMTP_USERNAME=mi_correo@gmail.com
SMTP_PASSWORD=xxxx xxxx xxxx xxxx
SMTP_AUTHENTICATION=login
SMTP_ENCRYPTION=starttls
SMTP_INSECURE=false
```

### Traefik
Por último, creamos nuestro fichero estático de traefik para nuestro dominio:

```bash
# cat ocis.yml                     
http:
  routers:
    cloud:
      rule: "Host(`cloud.midominio.com`)"
      service: cloud
      entryPoints:
        - websecure
      tls: {}   # o simplemente ‘tls: true’ en v3
      middlewares:
        - geoblock-es
        - crowdsec-bouncer-noappsec # IMPORTANTE USAR EL MIDDLEWARE NOAPPSEC PORQUE SINO ME DA PROBLEMAS EN LAS REDIRECCIONES DEL 2FA
        - ocis-headers

  services:
    cloud:
      loadBalancer:
        servers:
          - url: "http://100.105.100.10:9200"
        passHostHeader: true

  middlewares:
    ocis-headers:
      headers:
        customRequestHeaders:
          X-Forwarded-Proto: "https"
          X-Real-IP: ""
        customResponseHeaders:
          X-Frame-Options: "SAMEORIGIN"
          Content-Security-Policy: "default-src 'self' https://auth.midominio.com; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' https://auth.midominio.com; frame-ancestors 'self'"
          Content-Security-Policy: ""
```

### Primer arranque
Arrancamos nuestro compose desde Unraid y verificamos los logs para ver nuestra pass de administrador:
```bash
docker logs owncloud
```

```bash
=========================================
 generated OCIS Config
=========================================
 configpath : /etc/ocis/ocis.yaml
 user       : admin
 password   : #XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXxx

2026-05-09T07:07:41Z WRN starting service nats line=github.com/owncloud/ocis/v2/services/nats/pkg/command/server.go:97 service=nats
2026-05-09T07:07:41Z INF Starting nats-server line=github.com/owncloud/ocis/v2/services/nats/pkg/logging/nats.go:21 service=nats
```

### Usuarios
Tenemos dos opciones. Accedemos como administrador y vamos creando los usuarios:
![owncloud-1.png](owncloud-1.png)

O bien, usamos un sistema centralizado de usuarios Ldap y nos logueamos a través de Authelia. Si el usuario está en Ldap y no está en Owncloud oCIS se genera automáticamente. Optaremos por la opción 2.


### Configuración de LLDAP

Docker compose:
```bash
services:
  lldap:
    container_name: lldap
    hostname: lldap
    image: lldap/lldap:stable
    restart: unless-stopped
    expose:
      - 3890   # LDAP
      - 17170  # Web UI
    environment:
      LLDAP_LDAP_BASE_DN: "${LLDAP_LDAP_BASE_DN}"
      LLDAP_JWT_SECRET: "${JWT_SECRET}"
      LLDAP_LDAP_USER_PASS: "${LDAP_USER_PASS}"
    volumes:
      - ./data:/data
    networks:
      - infra_network

networks:
  infra_network:
    external: true
```

Generamos las llaves aleatorias:
```bash
# JWT_SECRET
tr -cd '[:alnum:]' < /dev/urandom | fold -w "64" | head -n 1
#mIyud6Bz6TKGPDxV3b1SlixrRdIdemNu3LmgvdZ3f9bKyNCyMvyyQ7hlXCfyoYq6

# LDAP_USER_PASS
tr -cd '[:alnum:]' < /dev/urandom | fold -w "20" | head -n 1
#TE7z8T3Ii1rm4u5NUkRC
```

Y las pasamos a nuestro fichero .env:
```bash
LLDAP_LDAP_BASE_DN=dc=midominio,dc=com
JWT_SECRET=mIyud6Bz6TKGPDxV3b1SlixrRdIdemNu3LmgvdZ3f9bKyNCyMvyyQ7hlXCfyoYq6
LDAP_USER_PASS=TE7z8T3Ii1rm4u5NUkRC
```
Arrancamos nuestro contenedor:
```bash
docker compose up -d

# verificamos logs
docker logs lldap
```

Ahora podremos acceder a nuestro ldap desde https://lldap.midominio.com.   

En mi caso he creado los usuarios necesarios y un grupo llamado ocis.


### Configuración de Authelia-redis

Vamos a configurar un contenedor Redis.  
Redis es un sistema de almacenamiento de datos en memoria que Authelia puede utilizar como proveedor de almacenamiento de sesiones. Al usar un servicio externo para los datos de sesión, Authelia se puede reiniciar sin que los usuarios tengan que volver a autenticarse y lo que más importante, no se cerrarán nuestras sesiones al poco tiempo o pocos días de iniciar (por ejemplo en aplicación de escritorio o de Android).  

Docker compose:
```bash
services:
  redis:
    container_name: authelia-redis
    hostname: authelia-redis
    image: redis:latest
    restart: unless-stopped
    command: redis-server --save 60 1 --appendonly yes  # ← persiste en disco
    expose:
      - 6379
    volumes:
      - ./data:/data
    networks:
      - infra_network

networks:
  infra_network:
    external: true
```

Arrancamos el contenedor y debe funcionar sin problemas.
```bash
docker compose up -d
```

### Configuración de Authelia
Este es el más complejo de configurar y el corazón de nuestro sistema de login.  
Ocis redirige la autenticación hacia Authelia, que a su vez se conecta con ldap y verifica que el usuario esté activo tenga los permisos necesarios.   

Docker-compose:
```bash
services:
  authelia:
    image: authelia/authelia:latest
    container_name: authelia
    restart: unless-stopped
    volumes:
      - ./config:/config
    environment:
      - TZ=Europe/Madrid
      - AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET=${AUTHELIA_JWT_SECRET}
      - AUTHELIA_SESSION_SECRET=${AUTHELIA_SESSION_SECRET}
      - AUTHELIA_STORAGE_ENCRYPTION_KEY=${AUTHELIA_STORAGE_ENCRYPTION_KEY}
      - AUTHELIA_AUTHENTICATION_BACKEND_LDAP_PASSWORD=${LLDAP_ADMIN_PASSWORD}

    networks:
      - infra_network

networks:
  infra_network:
    external: true
```

Vamos a generar los secretos.  
Ejecutamos cada línea y copiamos el resultado al fichero .env:
```bash
# Ejecuta cada línea y copia el resultado:
echo "AUTHELIA_JWT_SECRET=$(openssl rand -hex 32)"
echo "AUTHELIA_SESSION_SECRET=$(openssl rand -hex 32)"
echo "AUTHELIA_STORAGE_ENCRYPTION_KEY=$(openssl rand -hex 32)"
echo "AUTHELIA_OIDC_HMAC_SECRET=$(openssl rand -base64 48)"

# LLDAP_ADMIN_PASSWORD
echo "LLDAP_ADMIN_PASSWORD=Pass_generada_en_la_conf_de_lldap"
```

Y los añadimos a nuestro fichero .env:  
```bash
# cat .env:
AUTHELIA_JWT_SECRET=c8207bb043e77a53ba096497877cc13a9af82d7e229454cd2a4dd04c956653b0
AUTHELIA_SESSION_SECRET=904c93860b0e66e43124d0ad62c52ec990c099177dfbfd3c29d681b7888c0709
AUTHELIA_STORAGE_ENCRYPTION_KEY=05990b793ee23f896d151121645c2f57cf0f594e881f96c5cc1936fbec7e4546
LLDAP_ADMIN_PASSWORD=6LbWYgj9sn3EZyIP6KTC
AUTHELIA_OIDC_HMAC_SECRET=zjGQ1ZGejeRJghaEqcQA2iykIE9et6INn6ZNLrWTigl3ORNBYczgXZomETXTFXrY
```

Docker-compose de oCIS. Añadimos las siguientes variables de entorno:
```bash
    environment:
      # --- OIDC / Authelia ---
      OCIS_EXCLUDE_RUN_SERVICES: "idp"
      WEB_OIDC_CLIENT_ID: 'ocis'
      PROXY_OIDC_ISSUER: 'https://auth.midominio.com'
      PROXY_OIDC_REWRITE_WELLKNOWN: 'true'
      PROXY_OIDC_ACCESS_TOKEN_VERIFY_METHOD: 'none'
      PROXY_AUTOPROVISION_ACCOUNTS: 'true'
      PROXY_AUTOPROVISION_CLAIM_USERNAME: 'preferred_username'
      PROXY_AUTOPROVISION_CLAIM_EMAIL: 'email'
      PROXY_AUTOPROVISION_CLAIM_DISPLAYNAME: 'name'
      PROXY_AUTOPROVISION_CLAIM_GROUPS: 'groups'
```

### Fichero de configuración de Authelia

Aquí añadimos la configuración base y los clientes necesarios:

```bash
╰─ cat config/configuration.yml              
---
###############################################################################
# AUTHELIA - CONFIGURACIÓN PRINCIPAL (compatible 4.38+)
# LLDAP + SQLite + TOTP + Traefik (ficheros)
###############################################################################

theme: dark

server:
  address: tcp://0.0.0.0:9091/

log:
  level: debug
  # level: debug  # Descomenta para depurar

totp:
  issuer: midominio.com
  period: 30
  skew: 1

###############################################################################
# AUTENTICACIÓN - LLDAP
###############################################################################
authentication_backend:
  password_reset:
    disable: false
  refresh_interval: 1m
  ldap:
    implementation: custom
    address: ldap://lldap:3890
    timeout: 5s
    start_tls: false
    base_dn: dc=midominio,dc=com
    additional_users_dn: ou=people
    users_filter: (&({username_attribute}={input})(objectClass=person))
    additional_groups_dn: ou=groups
    groups_filter: (member={dn})
    user: uid=admin,ou=people,dc=midominio,dc=com
    password: ${LLDAP_ADMIN_PASSWORD}
    attributes:
      username: uid
      group_name: cn
      mail: mail
      display_name: displayName

###############################################################################
# CONTROL DE ACCESO
###############################################################################
access_control:
  default_policy: deny

  rules:
    - domain: auth.midominio.com
      policy: bypass

    - domain: cloud.midominio.com
      policy: two_factor

    # - domain: blog.midominio.com
    #   policy: one_factor

    # - domain: outline.midominio.com
    #   policy: two_factor
    #   subject:
    #     - "group:admins"

###############################################################################
# SESIONES
###############################################################################
session:
  secret: ${AUTHELIA_SESSION_SECRET}
  cookies:
    - name: authelia_session
      domain: midominio.com
      authelia_url: https://auth.midominio.com
      expiration: 1y     # sesión dura 1 año
      inactivity: 6M     # se cierra solo si no usas nada en 6 meses
      remember_me: 1y    # cookie remember_me dura 1 año
  redis:
    host: authelia-redis
    port: 6379

###############################################################################
# ALMACENAMIENTO - SQLite
###############################################################################
storage:
  encryption_key: ${AUTHELIA_STORAGE_ENCRYPTION_KEY}
  local:
    path: /config/db.sqlite3

###############################################################################
# NOTIFICADOR - Solo uno activo a la vez
# Opción A: filesystem (para pruebas, sin SMTP) <- ACTIVO AHORA
# Opción B: SMTP (descomenta cuando tengas SMTP listo)
###############################################################################
notifier:
  disable_startup_check: false
  filesystem:
    filename: /config/notifications.txt

# --- Opción B: SMTP (comenta el filesystem de arriba si activas esto) ---
# notifier:
#   smtp:
#     username: tu@email.com
#     password: ${AUTHELIA_SMTP_PASSWORD}
#     host: smtp.gmail.com
#     port: 587
#     sender: "Authelia <authelia@midominio.com>"
#     subject: "[Authelia] {title}"
#     startup_check_address: tu@email.com

###############################################################################
# JWT
###############################################################################
identity_validation:
  reset_password:
    jwt_secret: ${AUTHELIA_JWT_SECRET}


###############################################################################
# OIDC - Provider para oCIS
###############################################################################
identity_providers:
  oidc:
    access_token_lifespan: 1h
    authorize_code_lifespan: 1m
    id_token_lifespan: 1h
    refresh_token_lifespan: 90d
    hmac_secret: ${AUTHELIA_OIDC_HMAC_SECRET}
    cors:
      endpoints:
        - authorization
        - token
        - revocation
        - introspection
        - userinfo
    jwks:
      - key: |
          -----BEGIN PRIVATE KEY-----
          MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDOI9Y/nQssjJSD
          /sYc3/agPGpyPWKoFAJw3iGQc8+cxpGS6QELAGASYBPbq11xQOMbMe5YEe2U3zJy
          n/b8heXqRqik79FC3YiO4YaUDz1OWzUnpEcBWeDmEqKSTGPoR0EEiu9u7orM0kX8
          j3uLGz4uHPWSrrTZtoipGADm4yrHk3/GSH9ubC2s8zQVJ47l/0VX7pzNDakCBMDJ
          RlNTGb9Y5b1/aMej6LGkZXAzchdnj3ZnzcVgC2kKQg21fG5xx3SPIZ56BMXW8On0
          FeHi/OPPSYhhbaMVav6uWckcCgab469tjcitk3eLFfyWSRxV29KlH5gKu2yvI6Ia
          4R0ynbb/AgMBAAECggEAFDxlYFpIygdE3w5IIXaE7ebwZiWLhUdtk+nibp1H0LKX
          gM35ybwwMi2XVXWllyQRB07oAGJGKdqdR65XXyO/1bc4//QA3WkE6k3OWcODN6lx
          duJEDChoEP3cUrNIDXnNMqZ26bNmEcRElY36SUYT3Q//tXYMD+FA2iSelgvP28Z8
          PzxxJJ0KJ2Ay9muenR+6rJjT7eaE2Y4oiASTrHjG1A04WHHKQ4ip3VznRaqRMzO6
          HsjdeCwu2WCsuQjwSkbUd3YfjSm4Fyky8abUNUbGyyVJXMJ9hp8A9u7dR6l5YsJ1
          AG1Kd/SNgp9H7lf+cyGplMFHZBnRruMfWygHx9j2DQKBgQD5km3p8wFu9kUk7h8/
          ATchPvWAnv10YZDiXtKdSl7FVdDx+yW0c+adc8Ujomfu+C0H/os8lFGCwDvdN33D
          ngZTlcnGZUJeXNbCT/aXqzA/TIt+8PnHjmRwSmNPxaUbf6+otEqM6Fspgz4kAn1s
          WFPMQGCwnEoJFLP2z938aKYB5QKBgQDTcwka8PltbCfoaRVcxsj8EvHOqBYvLB8H
          iJcEwpRd4E0k5vXAWSLAfK1ns6UcucIT54ocCyXpzu10crUZcIdrz4S6hjwOqqgM
          RTVHyVaT67CWQqNlsyIwKozWoMtrgjxFzFTEES51LcDI2sl8u8+U+HVIlnH0asDq
          A3iisaAXEwKBgQDPquWk5x0JPQkaCr6bSaKbGm1kYmeaYNkTVD3CvjCP2bGsuQON
          3WdHGx8uYKRFN+MYpNktRmlw+A6YK+WNUcAH6zrjyDxqkqvtMmaJm9vgwAvPTCs7
          vyOaQHvU1Cxn7l63bZYfG/VHXLrncd71uaW47tTGALamScDaHeukbVu9dQKBgDFR
          pZAJIMRq86v7xqXLH9nbuVbQUcxS6DHjpAXSNLToulWfITbqE3b+HZwQhLR8h04J
          NWdxGji8sRn2H1N9sbhtwLGY2a06FNQ32EOULIN398o0ZNQ1wgWmBw+QlaHP0Ksf
          C65nq4RdVZgDn/dd/v7qLMDvhkjSFYj/okWgVIzNAoGBAPh+DsV/Lo9JDsFhUiHq
          KEEhOS5GaljhqTLhRt8QA56vIXsWc74t+leP9/pZHWa3p06kbeqzKCV2Xa+3wLUH
          AyCavZboq2NLQZVvE3D6TlST3gSY6bRp9pzRe/GC89VgTjQWU2/PcICgtKxbD8wS
          AnlBZr6T5/VrSs8oOOBtSGE6
          -----END PRIVATE KEY-----
    clients:
      - client_id: ocis
        client_name: ownCloud Infinite Scale
        public: true
        authorization_policy: two_factor
        redirect_uris:
          - https://cloud.midominio.com/oidc-callback.html
          - https://cloud.midominio.com/
        scopes:
          - openid
          - profile
          - email
          - groups
        userinfo_signed_response_alg: none
```

**Clave JWKS**   
```bash
openssl genrsa -out /tmp/oidc_private.pem 2048
cat /tmp/oidc_private.pem
```

Y la añadimos a nuestro fichero configuration.yml:
```bash
jwks:
      - key: |
          -----BEGIN PRIVATE KEY-----
          MIIEvgIBADA... (clave generada)
          -----END PRIVATE KEY-----
```

**Es muy importante pegar la clave JWKS con exactamente 10 espacios de indentación en cada línea del PEM**.  

### Configuración de usuario de Authelia

Accedemos a nuestro authelia desde https://auth.midominio.com con nuestro usuario de ldap. Según nuestro fichero de configuración de authelia, la política de acceso a cloud.midominio.com es de doble factor, por lo que debemos configurar uno.

```bash
    - domain: cloud.midominio.com
      policy: two_factor
```

En mi caso, he elegido passkey como doble factor, porque me resulta mucho más sencillo a la hora de acceder desde mi app móvil. En **Credenciales WebAuthn** se crean las passkeys, aunque podemos usar OTP si queremos una aplicación tipo Google Authenticator o Aegis.

![owncloud-3.png](owncloud-3.png)

### Clientes de escritorio y Android para oCIS

Clientes para aplicación de escritorio y Android. Estas aplicaciones llevan el client_id fijo, por lo que debemos añadirlo con los datos necesarios, siguiendo las instrucciones de la [web de Authelia](https://www.authelia.com/integration/openid-connect/clients/ocis/):
```bash
      - client_id: 'xdXOt13JKxym1B1QcEncf2XDkLAexMBFwiT9j6EfhhHFJhs2KM9jbjTmf8JBXE69'
        client_name: 'ownCloud Infinite Scale (Desktop Client)'
        client_secret: 'UBntmLjC2yYCeHwsyj73Uwo9TAaecAetRwMw0xYcvNL9yRdLSUi0hUAHfvCHFeFh'
        public: false
        authorization_policy: 'two_factor'
        require_pkce: true
        pkce_challenge_method: 'S256'
        scopes:
          - 'openid'
          - 'offline_access'
          - 'groups'
          - 'profile'
          - 'email'
        redirect_uris:
          - 'http://127.0.0.1'
          - 'http://localhost'
        response_types:
          - 'code'
        grant_types:
          - 'authorization_code'
          - 'refresh_token'
        access_token_signed_response_alg: 'none'
        userinfo_signed_response_alg: 'none'
        token_endpoint_auth_method: 'client_secret_basic'

      - client_id: 'e4rAsNUSIUs0lF4nbv9FmCeUkTlV9GdgTLDH1b5uie7syb90SzEVrbN7HIpmWJeD'
        client_name: 'ownCloud Infinite Scale (Android)'
        client_secret: 'dInFYGV33xKzhbRmpqQltYNdfLdJIfJ9L5ISoKhNoT9qZftpdWSP71VrpGR9pmoD'
        public: false
        authorization_policy: 'two_factor'
        require_pkce: true
        pkce_challenge_method: 'S256'
        redirect_uris:
          - 'oc://android.owncloud.com'
        scopes:
          - 'openid'
          - 'offline_access'
          - 'groups'
          - 'profile'
          - 'email'
        response_types:
          - 'code'
        grant_types:
          - 'authorization_code'
          - 'refresh_token'
        access_token_signed_response_alg: 'none'
        userinfo_signed_response_alg: 'none'
        token_endpoint_auth_method: 'client_secret_post'
```

### Inicio de oCIS

Volvemos a Unraid y verificamos que las nuevas variables de entorno de Authelia de oCIS estén correctamente:

```bash
    environment:
      # --- OIDC / Authelia ---
      OCIS_EXCLUDE_RUN_SERVICES: "idp"
      WEB_OIDC_CLIENT_ID: 'ocis'
      PROXY_OIDC_ISSUER: 'https://auth.midominio.com'
      PROXY_OIDC_REWRITE_WELLKNOWN: 'true'
      PROXY_OIDC_ACCESS_TOKEN_VERIFY_METHOD: 'none'
      PROXY_AUTOPROVISION_ACCOUNTS: 'true'
      PROXY_AUTOPROVISION_CLAIM_USERNAME: 'preferred_username'
      PROXY_AUTOPROVISION_CLAIM_EMAIL: 'email'
      PROXY_AUTOPROVISION_CLAIM_DISPLAYNAME: 'name'
      PROXY_AUTOPROVISION_CLAIM_GROUPS: 'groups'
```

Arrancamos nuestro contenedor oCIS y hacemos el primer inicio de sesión con mi usuario.

![owncloud-2.png](owncloud-2.png)

Después de aceptar vemos que nos crea nuestro primer usuario y ya podemos trabajar con nuestro nuevo Owncloud oCIS.




### Comandos útliles para verificar funcionamiento

Para que estos comandos funcionen, es importante que en el docker-compose modifiquemos el loglevel:
```bash
# Logs
OCIS_LOG_LEVEL: error / debug / info

DEBUG:	Detalle granular. Muestra cada paso interno, variables y eventos técnicos.	Se usa en Desarrollo y diagnóstico de errores complejos.	Impacto en rendimiento Alto: Genera archivos muy grandes rápidamente.

INFO	Confirmación de que las cosas funcionan. Reporta eventos normales (inicio de servicios, conexiones).	Se usa en Producción (por defecto en la mayoría de sistemas).	Impacto en rendimiento Moderado: Es el equilibrio estándar.

ERROR	Notificación de fallos críticos. Solo registra eventos que impiden una operación.	Sistemas estables donde solo te interesa saber si algo se rompió.	Impacto en rendimiento Bajo: Solo escribe cuando algo sale mal.
```

Revisar notificaciones:
```bash
docker inspect owncloud | grep NOTIFICATIONS_SMTP
```

Revisar logs docker:
```bash
docker logs ocis --tail=50
```

Verificar si oCIS está escuchando en el puerto:
```bash
docker exec ocis netstat -tlnp 2>/dev/null || docker exec ocis ss -tlnp
```

Prueba de conexión directa:
```bash
curl -k https://100.105.100.10:9200
```

Listado de servicios oCIS en ejecución:
```bash
docker exec owncloud ocis list
```

Verificaciones de notificaciones:
```bash
docker logs -f owncloud 2>&1 | grep -i -E "notification|smtp|email|mail|send"
```

Variables de entorno que carga oCIS:
```bash
docker exec owncloud env
```

### Vitaminar nuestro Owncloud

Instalación de tika.  
Por defecto oCIS solo indexa nombres de archivo y contenido de texto plano. Con Apache Tika puedes activar búsqueda en PDFs usando OCR.   

Añadimos esto a nuestro compose:
```bash
# Añadir estas variables a ocis > environment:
  # SEARCH_EXTRACTOR_TYPE: tika
  # SEARCH_EXTRACTOR_TIKA_TIKA_URL: http://tika:9998
  # FRONTEND_FULL_TEXT_SEARCH_ENABLED: "true"

  tika:
    image: apache/tika:latest-full
    container_name: tika
    restart: always
    logging:
      driver: local
```

Antivirus con ClamAV.  

Añadimos al compose:
```bash
# Añadir a ocis > environment:
  # ANTIVIRUS_SCANNER_TYPE: clamav
  # ANTIVIRUS_INFECTED_FILE_HANDLING: delete
  # ANTIVIRUS_CLAMAV_SOCKET: "/var/run/clamav/clamd.sock"
  # OCIS_ADD_RUN_SERVICES: "antivirus"
  # POSTPROCESSING_STEPS: "virusscan"
  # Y añadir volumen: clamav-socket:/var/run/clamav

  clamav:
    image: clamav/clamav:latest
    container_name: clamav
    volumes:
      - /mnt/user/appdata/ocis/clamav:/var/lib/clamav
      - clamav-socket:/tmp

volumes:
  clamav-socket:
```


***  
Fuentes:  
[Documentación Owncloud](https://doc.owncloud.com/ocis/next/depl-examples/ubuntu-compose/ubuntu-compose-prod.html#download-and-transfer-the-example)  
[Owncloud oCIS en docker](https://owncloud.dev/ocis/guides/ocis-local-docker/)  
[Authelia y oCIS](https://www.authelia.com/integration/openid-connect/clients/ocis/)  
[Authelia y ldap](https://helgeklein.com/blog/authelia-lldap-authentication-sso-user-management-password-reset-for-home-networks/#what-is-lldap)  
[Owncloud con OpenID](https://helgeklein.com/blog/owncloud-infinite-scale-with-openid-connect-authentication-for-home-networks/)  





