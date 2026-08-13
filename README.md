# tunnelchik

SSH gateway с обязательной ZITADEL-авторизацией, проверкой route/user policy, аутентификацией на target через forwarded `ssh-agent` и локальной записью сессий.

## Конфигурация

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

`address` нужно взять из актуального inventory. Конфиг строгий: неизвестные поля, второй YAML document, относительные пути и `offline_access` приводят к отказу запуска.

В ZITADEL нужно создать приложение типа `Native` с grant type `Device Code`, включить `User Roles Inside ID Token` и назначить пользователю требуемую роль. Gateway требует, чтобы ID token содержал nonce текущей Device Flow и claim `urn:zitadel:iam:org:project:roles`.

## Ключи и каталоги

```bash
install -d -m 0700 /var/lib/tunnelchik /var/lib/tunnelchik/recordings
ssh-keygen -t ed25519 -N '' -f /var/lib/tunnelchik/ssh_host_ed25519_key
chmod 0600 /var/lib/tunnelchik/ssh_host_ed25519_key
install -d -m 0755 /etc/tunnelchik
```

В `/etc/tunnelchik/known_hosts` должен находиться заранее проверенный host key target. Не доверяйте результату `ssh-keyscan` без независимой проверки fingerprint.

## Запуск

```bash
go run . -config /etc/tunnelchik/config.yaml
```

```sshconfig
Host bots.via-gate
    HostName gate.net.ozhegov.name
    Port 8022
    User bots+ozhegov
    ForwardAgent yes
```

```bash
ssh bots.via-gate -- id
```

Gateway принимает только public-key authentication, один `session` channel и requests `auth-agent-req@openssh.com`, `pty-req`, `window-change`, `shell`, `exec`, `signal`. Port forwarding, X11, environment, SFTP и SCP запрещены.

## Записи

Каждое входящее соединение создаёт каталог `YYYY/MM/DD/<session-id>/` с файлами `metadata.json`, `terminal.cast` и `input.jsonl`. Каталоги имеют mode `0700`, файлы — `0600`.

```bash
asciinema play /var/lib/tunnelchik/recordings/YYYY/MM/DD/session-id/terminal.cast
```

## Container

```bash
docker build -t tunnelchik:local .
docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  -p 8022:8022 \
  -v /etc/tunnelchik/config.yaml:/etc/tunnelchik/config.yaml:ro \
  -v /etc/tunnelchik/known_hosts:/etc/tunnelchik/known_hosts:ro \
  -v /var/lib/tunnelchik/ssh_host_ed25519_key:/var/lib/tunnelchik/ssh_host_ed25519_key:ro \
  -v /var/lib/tunnelchik/recordings:/var/lib/tunnelchik/recordings \
  tunnelchik:local
```

Файлы и writable recordings volume на host должны быть доступны UID/GID `65532:65532`. Процесс обрабатывает `SIGTERM`: listener и активные transports закрываются, proxy goroutine завершаются, metadata записи финализируется.

## Проверка

```bash
go test ./...
go test -race ./...
```

Live deployment, firewall, DNS, NetBird и Ansible role в репозитории `noc` выполняются отдельной задачей после проверки реальных ZITADEL `client_id`, target address и host fingerprint.

## License

[MIT](LICENSE)
