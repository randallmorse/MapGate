# Security Notes

## The plain-text password warning

MapGate's built-in HTTP server does not perform TLS/SSL itself — it only speaks plain HTTP. If you browse to it directly (`http://your-server-ip:8100`), the password you type is sent over the network **unencrypted**, readable by anything positioned between your browser and the server (your ISP, a shared/public Wi-Fi network, etc.).

If you instead reach it through a proxy that terminates TLS for you — for example [Cloudflare](https://www.cloudflare.com/) sitting in front with your own domain — the visitor-to-Cloudflare hop is encrypted, even though the Cloudflare-to-MapGate hop behind it is still plain HTTP (which is fine, since that hop typically stays on the open internet only briefly between two known endpoints, or can be tunneled privately).

To help you avoid accidentally typing your password into an unencrypted connection, the login page shows a warning banner when it can't detect signs of a secure proxy in front of it.

## How the detection works — and its limits

The warning triggers based on the *absence* of headers a TLS-terminating proxy normally adds:
- `X-Forwarded-Proto: https`
- Cloudflare's `CF-Visitor` header with `"scheme":"https"`
- `Front-End-Https: on`

**This is a best-effort heuristic, not a security boundary.** These are ordinary HTTP headers — anyone (including a malicious client) can send them directly to MapGate to suppress the warning, since MapGate has no way to cryptographically verify that a real TLS-terminating proxy actually sat in front of the request. The warning exists purely to catch the *honest* mistake of a visitor browsing straight to the raw port without realizing it's unencrypted. It does nothing to stop someone who already intends to intercept traffic.

## What actually protects the password

Only genuine end-to-end HTTPS does. Options, roughly in order of effort:
1. **Cloudflare** (free tier is enough) in front of a domain you own, proxying to your server — real TLS between visitors and Cloudflare.
2. Your own reverse proxy (Nginx/Apache/Caddy) terminating TLS with a certificate (e.g. via Let's Encrypt), forwarding to MapGate over `127.0.0.1` or a private network.
3. If neither is available to you, treat this password the same as you'd treat anything sent over plain HTTP: fine for keeping casual/curious visitors out, not suitable for anything you actually consider sensitive.

See the main [README](README.md#security-notes--read-before-relying-on-this) for the broader security model (single shared password vs. per-user auth, in-memory sessions, etc.).
