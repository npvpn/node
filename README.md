# npvpn node

**npvpn node** — узел (node) для работы с [npvpn panel](https://github.com/npvpn/vpn-panel).  
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

## Пилот одного TCP-маршрута через HAProxy

На REST-ноде оператор может выделить один TCP-вход и разрешённые VPN-инбаунды выходных нод. Панель управляет отдельным master/worker HAProxy через существующую mTLS-сессию. По умолчанию пилот выключен.

Сохраните локальную политику, например в `/var/lib/marzban-node/pilot-policy.json`:

```json
{
  "listen_address": "192.0.2.10",
  "listen_port": 18443,
  "targets": {
    "exit-a": {"address": "198.51.100.10", "port": 443, "exit_node_id": 12, "inbound_tag": "VLESS TCP A"},
    "exit-b": {"address": "198.51.100.11", "port": 443, "exit_node_id": 15, "inbound_tag": "VLESS TCP B"}
  }
}
```

Укажите локальный IPv4 входа, IPv4-адреса и порты выходов, их ID и теги инбаундов. Для адресов используйте IP-литералы. Политику загружает REST-сервис при старте. Передайте контейнеру `HAPROXY_PILOT_POLICY=/var/lib/marzban-node/pilot-policy.json`. Том `/var/lib/marzban-node` сохраняет журнал SQLite и подтверждённую конфигурацию. Для другого расположения задайте `HAPROXY_PILOT_STATE_DIR` на постоянном томе. Нода создаёт этот каталог с правами `0700`, владельцем должен быть пользователь процесса. HAProxy входит в Docker-образ. При установке без контейнера требуется HAProxy с master CLI и командой reload (проверено на 3.x) в PATH.

Если адрес занят внешним сервисом, панель показывает внешний слушатель. Для передачи управления прежний владелец должен освободить порт и исключить его повторный захват при рестарте. Изменение назначения и отключение дренируют уже открытые соединения. После рестарта нода сверяет журнал с текущим worker и восстанавливает подтверждённый маршрут, если его назначение по-прежнему разрешено политикой. Отображаемое состояние backend проверяет TCP-подключение к выходу. Работу VPN по выданной ссылке проверяет отдельная клиентская проба.
