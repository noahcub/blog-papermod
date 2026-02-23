---
title: Home Assistant y Telegram
description: Integrar Telegram en Home Assistant
date: 2024-02-02 09:00:00 +0100
categories:
   - Unraid
tags:
   - Programming
weight: 1
---

### Integrar Telegram en Home Assistant

Resulta muy sencillo la integración de Telegram.
Modificamos el fichero configuration.yaml y añadimos lo siguiente:

Tenemos que crear nuestro bot a través de [@BotFather](https://t.me/BotFather). Una vez finalizado nos dará el api_key que necesitamos.

Para obtener el id del chat usamos [@GetIDs bot](https://t.me/getidsbot)

``` yaml
telegram_bot:
  - platform: polling
    api_key: xxxxxxxxx:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    allowed_chat_ids:
      - 123456789
      - 123456789-dos

notify:
  - platform: telegram
    name: "telegram"
    chat_id: 123456789

  - platform: telegram
    name: "telegram_dos"
    chat_id: 123456789-dos
```
En name: "telegram" podemos poner el nombre que queramos, teniendo en cuenta que cuando llamemos a nuestro servicio debemos usar: notify.telegram, notify.my_home, etc...  

Como vemos en el ejemplo, se puede hacer varias notificaciones distintas a distintos grupos o chats.  

Reiniciamos Home Assistant y ya lo tenemos disponible. Nos vamos a Herramientas de desarrolladores -> Servicios para probarlo:  

Mensaje sencillo:  
``` yaml
service: notify.telegram
data:
  message: "Yay! A message from Home Assistant."
``` 

Mensaje enviando una foto:  
``` yaml
service: notify.telegram
data:
  title: Send an images
  message: That's an example that sends an image.
  data:
    photo:
      - file: /media/CCTV/2024/02/02/Tapia XXXXXX_00_20240202184131.jpg
```


***   
Fuentes y enlaces de interés que ayudaran a complementar esta guía:  

[https://www.home-assistant.io/integrations/telegram/](https://www.home-assistant.io/integrations/telegram/)  
