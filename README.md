# check-smtp

A Nagios-compatible SMTP check written in Rust. It is a port of
[nabeken/go-check-smtp](https://github.com/nabeken/go-check-smtp) (a drop-in
replacement for `check_smtp` from nagios-plugins) with the same flags, plus
**implicit TLS (SMTPS)** next to STARTTLS.

Unlike the stock `check_smtp`, any 4xx/5xx reply to `STARTTLS`, `MAIL FROM` or
`RCPT TO` is reported as CRITICAL.

## Build

```sh
cargo build --release   # -> target/release/check-smtp
cargo test
```

## Usage

```sh
# STARTTLS on the submission port
check-smtp -H mail.example.com -p 587 -S -F monitor.example.com \
  -w 2 -c 5 --minimum-tls-version 1.2 --cert-warn 30 --cert-crit 7

# SMTP over TLS (implicit TLS, port defaults to 465)
check-smtp -H mail.example.com --smtps --verify

# Behind HAProxy's PROXY protocol, with an envelope check
check-smtp -P -S -H 127.0.0.1 -p 10025 -f sender@example.com -r rcpt@example.com
```

Output follows the Nagios plugin format, e.g.
`SMTP OK: 123ms response time, TLS 1.3 >= 1.2 (TLS13_AES_256_GCM_SHA384), certificate 'mail.example.com' expires in 56 day(s) (2026-12-21T18:40:01Z)`.
Exit codes: `0` OK, `1` WARNING, `2` CRITICAL, `3` UNKNOWN (usage errors).

| Option | Description |
| --- | --- |
| `-H, --hostname` | Host to check (required) |
| `-p, --port` | Port (default `25`, or `465` with `--smtps`) |
| `-F, --fqdn` | Name sent in `EHLO`/`HELO` (default `localhost`) |
| `-f, --from` / `-r, --recipient` | Issue `MAIL FROM` / `RCPT TO` |
| `-w, --warning` / `-c, --critical` | Response-time thresholds; plain seconds (`2`, `1.5`) or `500ms`, `2s` |
| `-t, --timeout` | Overall timeout for connect + session (default `10s`) |
| `-P, --proxyproto` | Send a PROXY protocol v1 header first |
| `-S, --starttls` | Upgrade with STARTTLS |
| `--smtps` (alias `--ssl`) | Implicit TLS from the first byte |
| `--minimum-tls-version` | `1.0`–`1.3`; WARNING if the negotiated version is lower |
| `--cert-warn` / `--cert-crit` | WARNING / CRITICAL when any presented certificate expires within N days |
| `--verify` | Validate the chain and name against the system trust store |
| `--tls-server-name` | SNI / verification name (default: `--hostname`) |
| `-v, --verbose` | SMTP transcript and TLS details on stderr |

`-S` and `--smtps` are mutually exclusive. TLS-only options (`--verify`,
`--cert-*`, `--minimum-tls-version`, `--tls-server-name`) without one of them
are a usage error rather than being silently ignored.

## Differences from go-check-smtp

- **New:** `--smtps`/`--ssl`, `--verify`, `--tls-server-name`.
- Like upstream, certificates are **not validated** unless `--verify` is given.
- Uses [rustls](https://github.com/rustls/rustls), so only **TLS 1.2 and 1.3**
  can be negotiated. A server limited to TLS 1.0/1.1 is reported CRITICAL
  (handshake failure); `--minimum-tls-version 1.0|1.1` is accepted for
  compatibility but can never trigger.
- `--timeout` is one deadline for the whole check (upstream applies it to the
  dial and, separately, to the session). DNS resolution is not covered by it.
- SNI is sent (upstream omits it); `-w/-c/-t` also accept plain seconds.
- Verbose output goes to stderr so stdout stays a valid plugin line.
- When the minimum TLS version is not met, the message reads `TLS 1.2 < 1.3 (...)`.
- No perfdata is emitted (same as upstream).

## License

[MIT](LICENSE)
