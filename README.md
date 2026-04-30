# npvpn node

**npvpn node** — узел (node) для работы с [npvpn panel](https://github.com/npvpn/panel).  
Предназначен для развёртывания VPN-конфигураций на базе XRay-Core и оптимизирован под высокие нагрузки, многопоточность и масштабирование в продакшене.

---

## Возможности

- Работает как управляемый узел для **npvpn panel**

---

## Обновление с оригинальной ноды

Если нода была установлена из оригинального репозитория Marzban, переключить ее на `npvpn node` можно без переустановки:

1. Подключитесь к серверу, где установлена нода.

2. Откройте `docker-compose`:

```bash
marzban-node edit
```

3. В сервисе `marzban-node` укажите образ `npvpn/node:latest`:

```
services:
  marzban-node:
    image: npvpn/node:latest
    restart: always
    network_mode: host
    environment:
      SSL_CLIENT_CERT_FILE: "/var/lib/marzban-node/cert.pem"
      SERVICE_PORT: "62050"
      XRAY_API_PORT: "62051"
    volumes:
      - /var/lib/marzban:/var/lib/marzban
      - /var/lib/marzban-node:/var/lib/marzban-node
```

4. Загрузите новый образ:

```bash
docker pull npvpn/node:latest
```

5. Перезапустите ноду:

```bash
marzban-node restart
```
---
