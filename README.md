# MapGate

A tiny Paper/Bukkit plugin that puts a single shared-password login page in front of a web service that has no login of its own — using a signed session cookie, no reverse proxy/VPS/database required.

It was originally built to protect [BlueMap](https://bluemap.bluecolored.de/)'s web map, and that's still the primary use case the docs below walk through. But there's nothing BlueMap-specific about it: **it works with any plugin or app that runs its own embedded webserver and doesn't offer authentication** — [Dynmap](https://github.com/webbukkit/dynmap) is another obvious candidate, or really anything reachable over plain HTTP that you'd rather not leave wide open.

## Why

BlueMap has [no built-in authentication](https://github.com/BlueMap-Minecraft/BlueMap/issues/105) (and neither do most plugins in this category). The usual advice is to put a separate reverse proxy (Nginx/Apache) in front, which assumes you have a server you control to run that on. MapGate exists for the common case where you don't — it runs **inside your existing Minecraft server process** and does the gating itself, in front of whatever backend service you point it at.

## How it works

```
                 ┌─────────────────────────────────────────┐
 visitor ──────► │  MapGate (public port, e.g. 8100)        │
                 │   - no session cookie → show login form  │
                 │   - valid session cookie → proxy through │
                 └───────────────────┬───────────────────────┘
                                      │ (localhost only)
                                      ▼
                 ┌─────────────────────────────────────────┐
                 │  target service (127.0.0.1, e.g. 8101)   │
                 │  (BlueMap, Dynmap, or anything similar)  │
                 └─────────────────────────────────────────┘
```

The backend service (BlueMap, Dynmap, etc.) is reconfigured to bind only to `127.0.0.1` — it's not reachable from outside the machine at all, even if a firewall rule is misconfigured. MapGate is the only thing actually exposed publicly, and it only forwards requests that carry a valid session cookie.

## Features
- Fails closed while the password is still the packaged default (`changeme`) by default — shows an interstitial explaining how an admin (`mapgate.admin`/op) can fix it via `/mapgate setpassword`. Installs that want the default password to actually work (local demos/dev only) can opt into that explicitly with `default-password-mode: warn`, which shows a persistent warning on the login page instead of blocking it
- Single shared password, changeable in-game with no restart (`/mapgate setpassword <pass>`)
- Session cookie (`HttpOnly`, random 256-bit token) with configurable expiry
- Logout endpoint (`/mapgate/logout`)
- Warns visitors on the login page if their connection doesn't look like it's coming through a secure (HTTPS-terminating) proxy — see [SECURITY.md](SECURITY.md)
- IP allow-list (bypass the password entirely, e.g. for your own home/office IP) and block-list (always deny, HTTP 403) — block always wins if an address matches both
- Optional self-signed HTTPS (`tls-enabled: true`) — MapGate generates and reuses its own certificate via the JDK's bundled `keytool`, no external tools needed. Encrypts against passive eavesdropping; still shows a browser trust warning since it's not CA-issued — see [SECURITY.md](SECURITY.md)
- No external dependencies at runtime — uses only the JDK's built-in `com.sun.net.httpserver`
- No database, no reverse proxy, no separate process to keep running

## Installation
1. **Move your backend service to a loopback-only port.** In BlueMap's `plugins/BlueMap/webserver.conf`, that means:
   ```
   ip: "127.0.0.1"
   port: 8101
   ```
   (8101 is just an example — pick any free port, as long as it matches `target-port` in MapGate's config below.) For Dynmap or something else, find the equivalent "webserver port" setting in *that* plugin's own config and do the same thing — bind it to `127.0.0.1` and pick an internal port.
2. Drop `mapgate-1.0.0.jar` into your server's `plugins/` folder.
3. Start the server once to generate `plugins/MapGate/config.yml`, then set `target-host`/`target-port` to match what you set in step 1 (see the config reference below).
4. Set a real password — either edit `password` in `config.yml` and restart, or just run `/mapgate setpassword <password>` in console/in-game after the first start (takes effect immediately, no restart needed).
5. Make sure `public-port` (default `8100`) is the port actually open/allocated in your host's firewall — this can be the same port number your service used to expose directly, so nothing changes for visitors except now seeing a login page first.
6. *(Optional)* Set `tls-enabled: true` if you want visitors to reach MapGate over `https://` with a self-signed certificate instead of plain `http://` (encrypts against passive eavesdropping — see [SECURITY.md](SECURITY.md) for what it does and doesn't protect against). No certificate files to prepare yourself; MapGate generates one on first start.
7. Restart. Browse to `http://<your-server-ip>:<public-port>` (or `https://` if you enabled TLS) — you should see a password prompt before reaching the actual service.

## Configuration (`plugins/MapGate/config.yml`)
| Key | Default | Meaning |
|---|---|---|
| `password` | `changeme` | The shared password. Prefer changing it via `/mapgate setpassword` in-game/console instead of editing this file. What happens while it's still the literal default is controlled by `default-password-mode` below. |
| `default-password-mode` | `block` | `block` (fail closed — no one can log in while the password is still the default; visitors see a setup-required page) or `warn` (allow the default password to work, for local demos/dev, with a persistent warning shown on the login page). |
| `target-host` | `127.0.0.1` | Where the backend service you're protecting (BlueMap, Dynmap, etc.) is actually listening. |
| `target-port` | `8101` | The backend service's internal (localhost-only) port. Must match whatever you set in *that* service's own config. |
| `public-port` | `8100` | The port MapGate itself listens on — the one you expose/open in your firewall, and the one visitors actually browse to. |
| `session-duration-hours` | `12` | How long a login lasts before the password is required again. |
| `cookie-name` | `mapgate_session` | Name of the session cookie. |
| `insecure-connection-warning-url` | this repo's `SECURITY.md` | Link shown in the login page's plain-HTTP warning banner (see [SECURITY.md](SECURITY.md)). |
| `ip-block-list` | `[]` | IPs/CIDR ranges (e.g. `203.0.113.0/24`) always denied with a 403, checked before anything else. Wins over `ip-allow-list` if an address is on both. |
| `ip-allow-list` | `[]` | IPs/CIDR ranges that bypass the password **entirely** — a real access-control bypass, use deliberately. |
| `trust-proxy-headers` | `false` | Whether to trust `X-Forwarded-For` (for IP allow/block matching) and `X-Forwarded-Proto`/`CF-Visitor`/`Front-End-Https` (for the plain-HTTP warning) instead of ignoring them. Only safe if MapGate's public port is firewalled to reject direct connections from anyone but your trusted reverse proxy — see [SECURITY.md](SECURITY.md). |
| `tls-enabled` | `false` | Serve HTTPS (self-signed) instead of HTTP on `public-port`. See [SECURITY.md](SECURITY.md) for what this does and doesn't protect against. |
| `tls-common-name` | `localhost` | CN/SAN for the generated certificate — set to whatever hostname/IP visitors actually browse to, to avoid an extra hostname-mismatch warning. |
| `tls-keystore-path` | `selfsigned-keystore.p12` | Where the generated keystore is stored, relative to `plugins/MapGate/`. |
| `tls-keystore-password` | *(auto-generated)* | Filled in automatically the first time `tls-enabled` is turned on. Use `/mapgate regenerate-cert` to force a new certificate rather than clearing this by hand. |

## Using your own certificate instead of self-signed (⚠ unconfirmed)

> **Status: unconfirmed / untested.** This follows directly from how `tls-keystore-path` and `tls-keystore-password` are implemented (MapGate only auto-generates a certificate when the keystore file is missing *or* the password is blank — otherwise it just loads what's there), but nobody has actually run this end-to-end yet with a real certificate. Treat it as a starting point to try, not a verified guide. If you do try it, consider [opening an issue](https://github.com/randallmorse/MapGate/issues) with how it went either way.

If you have (or can obtain) a real, CA-issued certificate, you should be able to use it instead of letting MapGate self-sign one:

1. Obtain a certificate as a PEM `fullchain.pem` + `privkey.pem` pair (e.g. via Let's Encrypt/certbot, or one you purchased).
2. Convert it to a PKCS12 keystore, since that's the format MapGate expects:
   ```sh
   openssl pkcs12 -export -in fullchain.pem -inkey privkey.pem \
     -out real-cert.p12 -name mapgate -passout pass:<choose-a-password>
   ```
3. Place `real-cert.p12` inside `plugins/MapGate/`, then set in `config.yml`:
   ```yaml
   tls-enabled: true
   tls-keystore-path: "real-cert.p12"
   tls-keystore-password: "<the password you chose above>"
   ```
4. Restart (or `/mapgate reload`).

**Known gap even if this works:** Let's Encrypt-style certificates expire roughly every 90 days and need automated renewal. Nothing in MapGate currently detects a renewed certificate file and reloads on its own — you'd need to trigger `/mapgate reload` yourself after each renewal (e.g. a certbot renewal hook script that runs the command over RCON). A longer-lived purchased certificate sidesteps that, at the cost of not being free.

## Commands
| Command | Permission | Effect |
|---|---|---|
| `/mapgate setpassword <pass>` | `mapgate.admin` (default: op) | Changes the password immediately, no restart needed. |
| `/mapgate reload` | `mapgate.admin` | Reloads config and restarts MapGate's internal HTTP server. |
| `/mapgate sessions` | `mapgate.admin` | Shows the number of currently active (unexpired) sessions. |
| `/mapgate regenerate-cert` | `mapgate.admin` | Deletes and regenerates the self-signed TLS certificate (only relevant if `tls-enabled: true`). Visitors' browsers will need to re-accept the new certificate. |

## Security notes — read before relying on this
- **This runs over plain HTTP by default**, unless you turn on `tls-enabled` for self-signed HTTPS, or put something like Cloudflare in front of it *and* also enable `trust-proxy-headers` (off by default - see below). Plain HTTP means the password and session cookie are sent unencrypted — fine for casually keeping randoms out of a hobby server's map, not a substitute for real TLS if that matters to you. The login page shows a warning when it can't confirm the connection is secure — see [SECURITY.md](SECURITY.md) for exactly how that detection works and its limits.
- **Self-signed TLS (`tls-enabled: true`) encrypts the connection but doesn't authenticate the server.** It stops passive eavesdropping (packet sniffing), but browsers will show a "not trusted" warning, and a determined active man-in-the-middle could still present their own self-signed certificate unless a visitor manually checks the certificate fingerprint. A CA-issued certificate (e.g. via Cloudflare or Let's Encrypt) doesn't have that gap.
- **One shared password for everyone**, not per-user accounts. If you need access tied to individual Minecraft accounts/permissions, look at [Chicken/Auth](https://github.com/Chicken/Auth) instead (heavier: needs its own reverse proxy + database).
- Sessions are **in-memory only** — they don't survive a server restart, and there's no persistent session store to worry about securing.
- The reverse-proxy step buffers each response fully in memory before forwarding it — fine for typical BlueMap tile/asset sizes, not designed for heavy concurrent public traffic.

## Building from source
No Gradle/Maven wrapper yet — built directly with `javac` against the Paper API. You'll need:
- JDK 25+ (matching whatever your target Paper version requires)
- `paper-api` jar for your target Paper version, from https://repo.papermc.io/repository/maven-public/io/papermc/paper/paper-api/
- Its transitive deps for compiling: `adventure-api`, `adventure-key` (both `net.kyori`, matching the version in paper-api's declared `adventure-bom`), `bungeecord-chat` (`net.md-5`), and `org.jetbrains:annotations`

```sh
javac -encoding UTF-8 -cp "paper-api.jar;adventure-api.jar;adventure-key.jar;bungeecord-chat.jar;jetbrains-annotations.jar" \
  -d build/classes src/main/java/com/cinaptic/mapgate/*.java

cp src/main/resources/plugin.yml src/main/resources/config.yml build/classes/
jar --create --file build/mapgate-1.0.0.jar --main-class com.cinaptic.mapgate.MapGatePlugin -C build/classes .
```

## Author
Randall Morse (cinaptic) ([randymorse@gmail.com](mailto:randymorse@gmail.com))

## License
[MIT](LICENSE)
