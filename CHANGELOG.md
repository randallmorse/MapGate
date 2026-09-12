# Changelog

## 1.0.0 — 2026-09-12

Initial release.

### Added
- Core password gate: a single shared password protects any backend web service with no auth of its own (built for [BlueMap](https://bluemap.bluecolored.de/), works with anything similar such as Dynmap), using a random server-side session token stored in an `HttpOnly` cookie.
- `default-password-mode` (`block`/`warn`) — fails closed while the password is still the packaged default, unless explicitly opted out of for local demos/dev.
- IP `ip-allow-list` (bypasses the password entirely) and `ip-block-list` (always denied), matched against the real TCP source address by default.
- `trust-proxy-headers` — explicit opt-in to trust `X-Forwarded-For`/`X-Forwarded-Proto`/`CF-Visitor`/`Front-End-Https` when a reverse proxy sits in front, off by default.
- Optional self-signed HTTPS (`tls-enabled`) — certificate generated and reused automatically via the JDK's bundled `keytool`, no external tools required.
- Support for loading a real CA-issued certificate instead of self-signing one (⚠ unconfirmed/untested — see README).
- In-game/console commands: `/mapgate setpassword`, `/mapgate reload`, `/mapgate sessions`, `/mapgate regenerate-cert`.

### Fixed — automated security/code review pass
A GitHub Copilot review of the initial implementation surfaced 13 issues, all addressed before this release:
- **Security:** rejected negative/out-of-range CIDR prefixes that could bypass the allow-list entirely; switched `X-Forwarded-For` parsing to the rightmost (proxy-appended) entry instead of the spoofable leftmost one; the session cookie is now marked `Secure` whenever the connection is confirmed encrypted; added per-IP login rate limiting (5 failed attempts/minute); `/mapgate setpassword` now invalidates all existing sessions immediately; `/mapgate regenerate-cert` and first-run certificate generation now refuse to touch a keystore at a non-default path, so a user-supplied CA certificate can't be silently destroyed; the generated certificate's SHA-256 fingerprint is now actually logged (SECURITY.md already documented comparing it).
- **Resource exhaustion / lifecycle:** replaced an unbounded cached thread pool with a bounded, properly-shut-down one; capped the login endpoint's request body at 8KB; added finite connect/read timeouts on the backend proxy connection; the TLS keystore is now loaded/validated before the public HTTPS socket is bound, so a bad certificate can't orphan a listener on the port.
- **Correctness:** fixed a bug where a genuine backend connection failure could skip the intended `502` response; session cleanup now also runs on every new login rather than only when triggered elsewhere.
- **Docs:** corrected the session cookie's description (random token, not cryptographically signed) and the Building From Source classpath separator (was Windows-style `;` under a `sh`-labeled command).

### Known limitations
- The proxy only forwards a request body for `POST`/`PUT` — a `DELETE` with a body reaches the backend empty, and `PATCH` isn't supported at all (a `HttpURLConnection` limitation). Not an issue for BlueMap/Dynmap-style read-mostly services; fixing it generically would mean moving off `HttpURLConnection`.
- Loading a real CA-issued certificate (as opposed to self-signing) is implemented but not yet verified end-to-end.
- No automated tests yet — planned alongside a move to Gradle in the next release.
