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
- Refuses to work while the password is still the packaged default (`changeme`) — shows an interstitial explaining how an admin (`mapgate.admin`/op) can fix it via `/mapgate setpassword`, instead of ever letting the public default password actually grant access
- Single shared password, changeable in-game with no restart (`/mapgate setpassword <pass>`)
- Session cookie (`HttpOnly`, random 256-bit token) with configurable expiry
- Logout endpoint (`/mapgate/logout`)
- Warns visitors on the login page if their connection doesn't look like it's coming through a secure (HTTPS-terminating) proxy — see [SECURITY.md](SECURITY.md)
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
6. Restart. Browse to `http://<your-server-ip>:<public-port>` — you should see a password prompt before reaching the actual service.

## Configuration (`plugins/MapGate/config.yml`)
| Key | Default | Meaning |
|---|---|---|
| `password` | `changeme` | The shared password. Prefer changing it via `/mapgate setpassword` in-game/console instead of editing this file. While it's still the literal default, MapGate blocks all access and shows a setup-required page instead (see Features). |
| `target-host` | `127.0.0.1` | Where the backend service you're protecting (BlueMap, Dynmap, etc.) is actually listening. |
| `target-port` | `8101` | The backend service's internal (localhost-only) port. Must match whatever you set in *that* service's own config. |
| `public-port` | `8100` | The port MapGate itself listens on — the one you expose/open in your firewall, and the one visitors actually browse to. |
| `session-duration-hours` | `12` | How long a login lasts before the password is required again. |
| `cookie-name` | `mapgate_session` | Name of the session cookie. |
| `insecure-connection-warning-url` | this repo's `SECURITY.md` | Link shown in the login page's plain-HTTP warning banner (see [SECURITY.md](SECURITY.md)). |

## Commands
| Command | Permission | Effect |
|---|---|---|
| `/mapgate setpassword <pass>` | `mapgate.admin` (default: op) | Changes the password immediately, no restart needed. |
| `/mapgate reload` | `mapgate.admin` | Reloads config and restarts MapGate's internal HTTP server. |
| `/mapgate sessions` | `mapgate.admin` | Shows the number of currently active (unexpired) sessions. |

## Security notes — read before relying on this
- **This runs over plain HTTP unless you put something like Cloudflare in front of it.** The password and session cookie are sent unencrypted. Fine for casually keeping randoms out of a hobby server's map; not a substitute for real TLS if that matters to you. The login page shows a warning when it looks like there's no secure proxy in front — see [SECURITY.md](SECURITY.md) for exactly how that detection works and its limits.
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
