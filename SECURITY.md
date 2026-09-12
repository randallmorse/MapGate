# Security Notes

## The plain-text password warning

By default, MapGate's built-in HTTP server does not perform TLS/SSL itself — it only speaks plain HTTP, unless you turn on `tls-enabled` (see below) or put a TLS-terminating proxy in front. Over plain HTTP, if you browse to MapGate directly (`http://your-server-ip:8100`), the password you type is sent over the network **unencrypted**, readable by anything positioned between your browser and the server (your ISP, a shared/public Wi-Fi network, etc.).

If you instead reach it through a proxy that terminates TLS for you — for example [Cloudflare](https://www.cloudflare.com/) sitting in front with your own domain — the visitor-to-Cloudflare hop is encrypted, even though the Cloudflare-to-MapGate hop behind it is still plain HTTP (which is fine, since that hop typically stays on the open internet only briefly between two known endpoints, or can be tunneled privately).

To help you avoid accidentally typing your password into an unencrypted connection, the login page shows a warning banner when it can't detect signs of a secure proxy in front of it.

## How the detection works — and its limits

If `tls-enabled: true`, MapGate knows for certain the connection is encrypted (it terminated the TLS itself) and never shows the warning - no heuristic needed there. Otherwise, the warning triggers based on the *absence* of headers a TLS-terminating proxy normally adds:
- `X-Forwarded-Proto: https`
- Cloudflare's `CF-Visitor` header with `"scheme":"https"`
- `Front-End-Https: on`

**This is a best-effort heuristic, not a security boundary.** These are ordinary HTTP headers — anyone (including a malicious client) can send them directly to MapGate to suppress the warning, since MapGate has no way to cryptographically verify that a real TLS-terminating proxy actually sat in front of the request. The warning exists purely to catch the *honest* mistake of a visitor browsing straight to the raw port without realizing it's unencrypted. It does nothing to stop someone who already intends to intercept traffic.

## What actually protects the password

Genuine HTTPS does - though "genuine" comes in two flavors with different guarantees. Options, roughly in order of effort:
1. **Cloudflare** (free tier is enough) in front of a domain you own, proxying to your server — real, CA-trusted TLS between visitors and Cloudflare, and no warning in visitors' browsers.
2. Your own reverse proxy (Nginx/Apache/Caddy) terminating TLS with a CA-issued certificate (e.g. via Let's Encrypt), forwarding to MapGate over `127.0.0.1` or a private network. Same CA-trusted guarantee as Cloudflare.
3. **MapGate's own `tls-enabled: true`** (self-signed, no extra infrastructure needed) — see below. Weaker than options 1-2, but much stronger than plain HTTP.
4. If none of those are available to you, treat this password the same as you'd treat anything sent over plain HTTP: fine for keeping casual/curious visitors out, not suitable for anything you actually consider sensitive.

## Self-signed TLS (`tls-enabled`)

When you set `tls-enabled: true`, MapGate generates its own self-signed certificate (via the JDK's bundled `keytool`) and serves HTTPS directly - no reverse proxy or separate server needed. This is a genuinely different security level than plain HTTP, but it is **not equivalent to a CA-issued certificate**, and the difference matters:

- **What it protects against:** passive eavesdropping. Anyone merely *observing* network traffic (a shared Wi-Fi network, an ISP, anyone with packet-capture access on the path) sees only encrypted bytes, not your password.
- **What it does NOT protect against:** an *active* man-in-the-middle. Because the certificate isn't vouched for by a certificate authority, a browser can't distinguish your self-signed certificate from an attacker's own self-signed certificate presented in a MITM attack - both just say "trust me." Browsers reflect this honestly by showing a "not trusted"/"not private" warning that visitors must click through, every time they use a browser or device that hasn't seen this specific certificate before.
- **How to actually verify it's really your server**, if that matters to you: compare the certificate's SHA-256 fingerprint (shown in your browser's certificate details) against the one printed in your server's console/log when MapGate generated it, communicated to visitors through some channel other than the connection itself (e.g. tell them in Discord). If those match, you've confirmed there's no MITM. Nothing does this comparison for you automatically.
- The certificate and its password are generated once and reused across restarts (so visitors aren't asked to re-accept a new certificate every time the server restarts) unless you run `/mapgate regenerate-cert`, which forces a fresh one - after which, everyone will need to click through the warning again.
- `tls-common-name` should match whatever hostname or IP visitors actually type into their browser. A mismatch adds a *second*, separate browser warning (hostname mismatch) on top of the untrusted-certificate one.

If you'd rather avoid the untrusted-certificate warning entirely, MapGate can also load a real CA-issued certificate instead of self-signing one — see [Using your own certificate](README.md#using-your-own-certificate-instead-of-self-signed--unconfirmed) in the README (currently unconfirmed/untested).

## IP allow/block lists and `trust-x-forwarded-for`

`ip-allow-list` is a real access-control bypass — anyone matching it skips the password entirely. By default, matching is done against the actual TCP connection's source address, which **cannot be spoofed**: a client cannot make their own socket appear to originate from a different IP.

If you enable `trust-x-forwarded-for: true` (for example, because MapGate sits behind Cloudflare or another reverse proxy that connects to it locally, and you want allow/block-listing to see the *original* visitor's IP instead of the proxy's), be aware that `X-Forwarded-For` is just an ordinary HTTP header. **Anyone who can connect directly to MapGate's public port can set this header to whatever they want** — including an IP from your allow-list — and walk straight past the password.

This setting is only safe to enable if you have separately ensured MapGate's public port cannot be reached directly by anyone except your trusted proxy — for example, a firewall rule that only permits inbound connections to that port from your proxy's known IP ranges (Cloudflare publishes theirs). If you can't guarantee that, leave this `false` and accept that allow/block-listing will match your proxy's IP rather than visitors' real IPs.

See the main [README](README.md#security-notes--read-before-relying-on-this) for the broader security model (single shared password vs. per-user auth, in-memory sessions, etc.).
