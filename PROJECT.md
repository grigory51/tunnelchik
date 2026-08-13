# tunnelchik

Проект небольшого SSH gateway для личной инфраструктуры. Этот документ — исходная спецификация для отдельной сессии разработки. Реализовывать по фазам, не расширяя scope следующей фазы заранее.

## Задача

Пользователь подключается обычным OpenSSH-клиентом к `gate.net.ozhegov.name:8022`. Gateway:

1. завершает входящее SSH-соединение на себе;
2. авторизует человека через ZITADEL;
3. проверяет, разрешены ли ему выбранные target и Linux user;
4. получает доступ к локальному `ssh-agent` через agent forwarding;
5. открывает второе SSH-соединение к target и аутентифицируется подписью из пользовательского agent;
6. проксирует SSH channels и записывает сессию.

Приватный ключ не копируется на gateway и не хранится там. Gateway получает только интерфейс подписи, пока живёт входящее соединение.

Это не `ProxyJump`: между клиентом и target нет сквозного SSH transport. Gateway видит открытый поток обоих SSH-соединений, поэтому может применять policy и записывать сессию.

## Пользовательский интерфейс MVP

Формат login name:

```text
<route>+<target-user>
```

Пример:

```bash
ssh -A -p 8022 bots+ozhegov@gate.net.ozhegov.name
```

Удобный alias:

```sshconfig
Host bots.via-gate
    HostName gate.net.ozhegov.name
    Port 8022
    User bots+ozhegov
    ForwardAgent yes
```

После установления входящего SSH transport gateway печатает `verification_uri_complete` из OAuth Device Authorization Flow. Пользователь открывает URL в браузере, входит в ZITADEL и подтверждает запрос. До успешной авторизации gateway не соединяется с target.

Каждое новое SSH-соединение требует новой ZITADEL-авторизации. Кеширование login и привязка ключа к identity не входят в MVP.

## Архитектура

```text
OpenSSH client             tunnelchik                    target sshd
----------------          ----------------              ----------------
local ssh-agent  <------  forwarded-agent client
       |                  inbound SSH server
       |                  ZITADEL device flow
       +--- signatures <- outbound SSH client  -------> authorized_keys
                          session recorder      <-----> shell / exec
```

Gateway устанавливает два независимых SSH transport:

- inbound: OpenSSH client → tunnelchik;
- outbound: tunnelchik → target sshd.

Сетевой доступ gateway к target обеспечивает существующая инфраструктура, включая NetBird между удалёнными площадками. `tunnelchik` не строит overlay и не управляет маршрутами.

На target сохраняется реальная идентичность:

- Linux user выбирается из разрешённой конфигурации;
- `sshd` проверяет публичный ключ пользователя из `authorized_keys`;
- локальный audit target видит Linux user и key fingerprint;
- журнал gateway связывает ZITADEL `sub`, target, Linux user и запись сессии.

## Технологии

- Go;
- `golang.org/x/crypto/ssh` для SSH server/client;
- `golang.org/x/crypto/ssh/agent` для протокола forwarded agent;
- стандартный `log/slog` для JSON-логов;
- YAML-конфиг допустим через одну небольшую библиотеку; до появления конфига использовать структуры Go;
- ZITADEL OAuth 2.0 Device Authorization Grant (RFC 8628).

Не писать собственную криптографию, SSH wire protocol, OAuth protocol или policy language.

## Конфигурация MVP

Один файл `/etc/tunnelchik/config.yaml`:

```yaml
listen: ":8022"
host_key: /var/lib/tunnelchik/ssh_host_ed25519_key
known_hosts: /etc/tunnelchik/known_hosts
recordings_dir: /var/lib/tunnelchik/recordings

oidc:
  issuer: https://id.ozhegov.name
  client_id: "replace-with-zitadel-device-client-id"
  scopes:
    - openid
    - profile
    - email
    - urn:zitadel:iam:org:project:roles

routes:
  bots:
    address: 10.129.0.10:22
    users:
      ozhegov:
        required_roles:
          - tunnelchik:user
```

`address` выше — пример, перед использованием взять актуальный адрес из inventory. Общего policy DSL не делать: route содержит разрешённых Linux users и требуемые ZITADEL roles.

Секрет клиента для Device Flow не нужен: в ZITADEL создаётся приложение типа `Native` с grant type `Device Code`. `client_id` не является секретом.

## Обязательные security invariants

1. До успешной проверки ZITADEL token и policy не открывать outbound SSH connection.
2. Не разрешать `none`, password и keyboard-interactive authentication на inbound SSH transport.
3. Inbound public-key authentication подтверждает владение ключом, но не заменяет ZITADEL identity. Принимать ключ можно без локального allowlist только при условии, что до ZITADEL authorization нет shell, exec, forwarding или доступа к target.
4. Проверять у ID token как минимум signature, `iss`, `aud`, `exp`, `nonce`/flow state и требуемые role claims через проверенную OIDC-библиотеку.
5. Outbound host key проверять по `known_hosts`. `ssh.InsecureIgnoreHostKey()` запрещён.
6. Не пересылать agent дальше на target. Использовать forwarded agent только как signer для outbound authentication.
7. Не поддерживать в MVP `direct-tcpip`, remote/local forwarding, X11, SFTP/SCP и дополнительные channels.
8. Никогда не писать в логи OAuth tokens, agent protocol payload, секреты и полные environment variables.
9. Конфиг и `known_hosts` читать при старте; при ошибке завершать процесс. Hot reload не нужен.
10. Host key gateway должен быть постоянным и храниться с mode `0600`.

Agent forwarding предоставляет gateway возможность запрашивать подписи у agent во время сессии. Это осознанная часть trust model. Рекомендуются актуальный OpenSSH, ключи с подтверждением (`ssh-add -c`) или hardware-backed keys.

## SSH flow

### Inbound authentication

1. Разобрать login name строго как `<route>+<target-user>`.
2. Проверить синтаксис обоих компонентов и наличие пары в конфиге.
3. Принять только подписанную public-key authentication; библиотека SSH проверяет proof of possession.
4. Сохранить fingerprint входящего public key в metadata.
5. После открытия `session` channel разрешить только минимальные requests, нужные для авторизации и дальнейшей сессии.

### ZITADEL authorization

1. Запросить device code у `issuer` со scopes из конфига.
2. Напечатать пользователю `verification_uri_complete` и срок действия.
3. Poll token endpoint с interval, который вернул ZITADEL; корректно обработать pending, slowdown, deny и expiry.
4. Проверить ID token и получить `sub`, отображаемое имя/email и roles.
5. Проверить `required_roles` выбранного route/user.
6. При отказе показать короткую причину, записать audit event и закрыть SSH session.

ZITADEL официально поддерживает RFC 8628 и Native/Device Code application. Не строить отдельный HTTP callback для MVP.

### Forwarded agent и outbound authentication

1. Дождаться `auth-agent-req@openssh.com` от клиента.
2. Открыть предусмотренный SSH protocol канал к forwarded agent клиента.
3. Обернуть канал через `golang.org/x/crypto/ssh/agent`.
4. Получить доступные signers и использовать их в `ssh.ClientConfig.Auth` для target.
5. Не экспортировать этот agent в outbound session.
6. Если agent не forwarded или target отверг все ключи, закрыть сессию с понятной ошибкой.

Точный channel flow проверить интеграционным тестом. Не ориентироваться только на сигнатуры helper-функций: часть API `agent` предназначена для клиентской стороны SSH.

### Session proxy

Для MVP поддержать:

- `pty-req`;
- `window-change`;
- `shell`;
- `exec`;
- `signal`;
- exit status/signal от target.

`env` либо запретить полностью, либо пропускать только явный allowlist после появления реальной необходимости.

Копирование потоков должно корректно обрабатывать half-close и завершать обе стороны при disconnect. Ошибка одного направления не должна оставлять goroutine или outbound connection висеть.

## Запись сессий

На каждое соединение создавать:

```text
/var/lib/tunnelchik/recordings/YYYY/MM/DD/<session-id>/
├── metadata.json
├── terminal.cast
└── input.jsonl
```

- `terminal.cast`: asciicast v2 с terminal output и временными метками;
- `input.jsonl`: введённые байты/exec requests и временные метки;
- `metadata.json`: identity, route, target, Linux user, source IP, key fingerprints, время, exit status, результат авторизации и ошибки.

Записывать поток по мере прохождения, а не держать сессию в памяти. Файлы и каталоги — mode `0700`/`0600`. Запись не должна содержать ID/access tokens и agent messages.

MVP хранит записи локально без UI, поиска, object storage, retention и tamper-proof подписи. Добавлять это только после работающего end-to-end gateway.

## Порядок реализации

### Фаза 1 — SSH relay с agent

Цель: доказать самый рискованный технический участок без ZITADEL и recorder.

- один route и user задаются флагами;
- inbound public-key authentication;
- forwarded agent используется для outbound authentication;
- работает интерактивный shell и `exec`;
- outbound host key проверяется через `known_hosts`;
- один интеграционный тест поднимает fake target sshd, fake agent и gateway, затем проверяет `exec` и output.

Готово, когда:

```bash
ssh -A -p 8022 bots+ozhegov@127.0.0.1 -- id
```

выполняется на test target только ключом из test agent.

### Фаза 2 — конфиг и recording

- добавить YAML-конфиг из этой спецификации;
- разрешать только объявленные route/user;
- добавить PTY resize, signal и корректное завершение;
- писать metadata, output и input;
- проверить replay `terminal.cast` через `asciinema play`.

### Фаза 3 — ZITADEL

- создать в ZITADEL Native application с Device Code;
- добавить device flow и token validation;
- проверить role claim;
- запретить outbound connection до успешной authorization;
- проверить allow и deny сценарии вручную и тестом на локальном fake OIDC server либо на уровне token verifier.

### Фаза 4 — deployment

Только после завершения первых трёх фаз:

- собрать один статический binary и минимальный container;
- bind-mount config, host key, `known_hosts` и recordings;
- запускать non-root, read-only root filesystem;
- открыть `8022/tcp` на `gate.net.ozhegov.name`;
- отдельной задачей добавить Ansible role в репозиторий `noc`;
- доступ к удалённым target давать существующим NetBird peer/route, не встраивать NetBird в приложение.

## Не входит в MVP

- web UI и session player;
- inventory/database;
- управление Linux users и `authorized_keys`;
- SSH CA и выпуск сертификатов;
- SFTP/SCP;
- port forwarding;
- reconnect/resume;
- HA и несколько replicas;
- storage backend кроме локального диска;
- кеширование ZITADEL login;
- собственный SSH client/CLI;
- command parsing и попытка восстановить shell-команды из terminal bytes.

Существующий Ansible продолжает создавать Linux users и раскладывать публичные ключи. Источником истины для target routes на первом этапе остаётся статический конфиг.

## Definition of Done MVP

- подключение выполняется стандартным `ssh -A`;
- ZITADEL authentication и role policy обязательны;
- target принимает личный ключ из client agent;
- приватных ключей на gateway нет;
- target видит реального Linux user;
- shell и exec работают, resize и exit status не теряются;
- unknown route/user, отсутствующая role, отсутствующий agent и неверный host key закрывают соединение;
- сессия и metadata записываются на диск;
- есть один end-to-end интеграционный тест основного happy path и проверки fail-closed;
- `go test ./...` проходит;
- README содержит локальный запуск и пример `~/.ssh/config`.

## Полезные источники

- [ZITADEL Device Authorization Flow](https://zitadel.com/docs/guides/integrate/login/oidc/device-authorization)
- [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)
- [`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh)
- [`golang.org/x/crypto/ssh/agent`](https://pkg.go.dev/golang.org/x/crypto/ssh/agent)
- [SSH-MITM: agent forwarding authentication](https://docs.ssh-mitm.at/develop/auth-testing.html)

## Инструкция для следующей сессии

Начать с чтения этого файла. Реализовать только фазу 1, сначала зафиксировав короткий план и структуру не более чем из нескольких Go-файлов. Не добавлять ZITADEL, Docker, Ansible и storage до работающего интеграционного теста agent relay.
