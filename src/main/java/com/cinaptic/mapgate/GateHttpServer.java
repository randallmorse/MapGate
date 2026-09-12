package com.cinaptic.mapgate;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/**
 * A tiny standalone HTTP server that sits in front of some other unauthenticated
 * backend web service (e.g. BlueMap, Dynmap, or anything else with its own
 * embedded webserver and no login of its own) - which should be bound to
 * 127.0.0.1 only. Visitors must submit the configured password once; a
 * session cookie then lets their browser through directly to a
 * reverse-proxied copy of the backend's own responses.
 */
final class GateHttpServer {

    private static final Pattern COOKIE_SPLIT = Pattern.compile(";\\s*");
    private static final String DEFAULT_PASSWORD = "changeme";
    private static final int MAX_LOGIN_BODY_BYTES = 8 * 1024;
    private static final int BACKEND_CONNECT_TIMEOUT_MS = 5_000;
    private static final int BACKEND_READ_TIMEOUT_MS = 15_000;
    private static final int GATE_THREAD_POOL_SIZE = 32;

    private final MapGatePlugin plugin;
    private final SessionManager sessions;
    private final LoginRateLimiter loginRateLimiter = new LoginRateLimiter();
    private final HttpServer server;
    private final ExecutorService executorService;
    private final String cookieName;
    private final String targetHost;
    private final int targetPort;
    private final String insecureWarningUrl;
    private final String defaultPasswordMode;
    private final List<String> ipAllowList;
    private final List<String> ipBlockList;
    private final boolean trustProxyHeaders;

    GateHttpServer(MapGatePlugin plugin) throws IOException {
        this.plugin = plugin;
        this.cookieName = plugin.getConfig().getString("cookie-name", "mapgate_session");
        this.targetHost = plugin.getConfig().getString("target-host", "127.0.0.1");
        this.targetPort = plugin.getConfig().getInt("target-port", 8101);
        this.insecureWarningUrl = plugin.getConfig().getString("insecure-connection-warning-url",
                "https://github.com/randallmorse/MapGate/blob/main/SECURITY.md");
        this.defaultPasswordMode = plugin.getConfig().getString("default-password-mode", "block");
        this.ipAllowList = plugin.getConfig().getStringList("ip-allow-list");
        this.ipBlockList = plugin.getConfig().getStringList("ip-block-list");
        this.trustProxyHeaders = plugin.getConfig().getBoolean("trust-proxy-headers", false);
        long durationHours = plugin.getConfig().getLong("session-duration-hours", 12);
        this.sessions = new SessionManager(durationHours * 3600);

        int publicPort = plugin.getConfig().getInt("public-port", 8100);
        boolean tlsEnabled = plugin.getConfig().getBoolean("tls-enabled", false);
        if (tlsEnabled) {
            // Load/validate the certificate BEFORE binding the socket: if this throws,
            // nothing has been bound yet, so there's no orphaned listener left occupying
            // the port for a subsequent retry (e.g. /mapgate reload) to trip over.
            SSLContext sslContext = SelfSignedTls.ensureAndLoad(plugin);
            HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress(publicPort), 0);
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));
            this.server = httpsServer;
        } else {
            this.server = HttpServer.create(new InetSocketAddress(publicPort), 0);
        }
        // Bounded (not cached/unbounded) so a burst of slow/concurrent requests can't spawn
        // unlimited threads; shut down in stop() so reloads don't leak pools.
        this.executorService = Executors.newFixedThreadPool(GATE_THREAD_POOL_SIZE);
        this.server.setExecutor(executorService);
        this.server.createContext("/mapgate/login", this::handleLogin);
        this.server.createContext("/mapgate/logout", this::handleLogout);
        this.server.createContext("/", this::handleRoot);
    }

    void start() {
        server.start();
    }

    void stop() {
        server.stop(0);
        executorService.shutdownNow();
    }

    int activeSessionCount() {
        return sessions.activeCount();
    }

    /** Invalidates every current session - called when the password changes, so a token issued
     *  under the old password can't keep granting access after the change. */
    void invalidateAllSessions() {
        sessions.invalidateAll();
    }

    private void handleRoot(HttpExchange exchange) throws IOException {
        InetAddress client = resolveClientAddress(exchange);
        if (isBlocked(client)) {
            sendForbidden(exchange);
            return;
        }
        if (isAllowed(client)) {
            proxy(exchange);
            return;
        }
        if (isUsingDefaultPassword() && !isDefaultPasswordAllowed()) {
            serveSetupRequiredPage(exchange);
            return;
        }
        String token = readCookie(exchange, cookieName);
        if (sessions.isValid(token)) {
            proxy(exchange);
        } else {
            serveLoginPage(exchange, false);
        }
    }

    private void handleLogin(HttpExchange exchange) throws IOException {
        InetAddress client = resolveClientAddress(exchange);
        if (isBlocked(client)) {
            sendForbidden(exchange);
            return;
        }
        if (isAllowed(client)) {
            exchange.getResponseHeaders().add("Location", "/");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
            return;
        }
        if (isUsingDefaultPassword() && !isDefaultPasswordAllowed()) {
            serveSetupRequiredPage(exchange);
            return;
        }
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            serveLoginPage(exchange, false);
            return;
        }
        if (loginRateLimiter.isLocked(client)) {
            sendTooManyRequests(exchange);
            return;
        }

        String body;
        try {
            body = readBody(exchange, MAX_LOGIN_BODY_BYTES);
        } catch (BodyTooLargeException e) {
            exchange.sendResponseHeaders(413, -1);
            exchange.close();
            return;
        }
        String submitted = parseFormValue(body, "password");
        String configured = plugin.getConfig().getString("password", "");

        if (submitted != null && !configured.isEmpty() && constantTimeEquals(submitted, configured)) {
            loginRateLimiter.recordSuccess(client);
            String token = sessions.createSession();
            String cookieAttributes = "; Path=/; HttpOnly; Max-Age=" + sessions.sessionDurationSeconds()
                    + "; SameSite=Lax" + (looksLikeSecureProxy(exchange) ? "; Secure" : "");
            exchange.getResponseHeaders().add("Set-Cookie", cookieName + "=" + token + cookieAttributes);
            exchange.getResponseHeaders().add("Location", "/");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        } else {
            loginRateLimiter.recordFailure(client);
            serveLoginPage(exchange, true);
        }
    }

    private void handleLogout(HttpExchange exchange) throws IOException {
        if (isBlocked(resolveClientAddress(exchange))) {
            sendForbidden(exchange);
            return;
        }
        String token = readCookie(exchange, cookieName);
        sessions.invalidate(token);
        exchange.getResponseHeaders().add("Set-Cookie", cookieName + "=deleted; Path=/; Max-Age=0");
        exchange.getResponseHeaders().add("Location", "/");
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    /**
     * The actual TCP peer address by default - not spoofable. Only trusts
     * X-Forwarded-For when trust-proxy-headers is explicitly enabled, which
     * is only safe if MapGate's public port is firewalled to reject direct
     * connections from anyone but the trusted reverse proxy setting that
     * header - see SECURITY.md.
     *
     * Uses the RIGHTMOST entry, not the leftmost: well-behaved proxies APPEND
     * the address they received the connection from, rather than overwrite
     * the header, so the rightmost entry is the one your own trusted proxy
     * added - i.e. whoever actually connected to it. The leftmost entries can
     * be arbitrary values a client supplied itself before ever reaching the
     * proxy. This assumes a single trusted proxy hop; a chain of multiple
     * trusted proxies isn't accounted for.
     */
    private InetAddress resolveClientAddress(HttpExchange exchange) {
        if (trustProxyHeaders) {
            String forwardedFor = firstHeader(exchange, "X-Forwarded-For");
            if (forwardedFor != null && !forwardedFor.isBlank()) {
                String[] hops = forwardedFor.split(",");
                try {
                    return InetAddress.getByName(hops[hops.length - 1].trim());
                } catch (UnknownHostException ignored) {
                    // fall through to the raw socket address
                }
            }
        }
        InetSocketAddress remote = exchange.getRemoteAddress();
        return remote == null ? null : remote.getAddress();
    }

    private boolean isBlocked(InetAddress client) {
        return client != null && matchesAny(client, ipBlockList);
    }

    private boolean isAllowed(InetAddress client) {
        return client != null && matchesAny(client, ipAllowList);
    }

    private boolean matchesAny(InetAddress client, List<String> entries) {
        for (String entry : entries) {
            if (matchesCidr(client, entry)) {
                return true;
            }
        }
        return false;
    }

    /** Accepts a plain IP ("203.0.113.5") or CIDR range ("203.0.113.0/24"). Malformed entries never match. */
    private boolean matchesCidr(InetAddress client, String entry) {
        if (entry == null || entry.isBlank()) {
            return false;
        }
        try {
            String[] parts = entry.trim().split("/", 2);
            InetAddress network = InetAddress.getByName(parts[0]);
            byte[] clientBytes = client.getAddress();
            byte[] networkBytes = network.getAddress();
            if (clientBytes.length != networkBytes.length) {
                return false; // one's IPv4, the other IPv6 - never matches
            }
            int addressBits = clientBytes.length * 8;
            int prefixLength = parts.length == 2 ? Integer.parseInt(parts[1]) : addressBits;
            if (prefixLength < 0 || prefixLength > addressBits) {
                return false; // malformed prefix (e.g. negative) - never matches, never "matches everything"
            }
            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;
            for (int i = 0; i < fullBytes; i++) {
                if (clientBytes[i] != networkBytes[i]) {
                    return false;
                }
            }
            if (remainingBits > 0) {
                int mask = (0xFF << (8 - remainingBits)) & 0xFF;
                if ((clientBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask)) {
                    return false;
                }
            }
            return true;
        } catch (Exception malformedEntry) {
            return false;
        }
    }

    private void sendForbidden(HttpExchange exchange) throws IOException {
        byte[] bytes = "Forbidden".getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(403, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendTooManyRequests(HttpExchange exchange) throws IOException {
        byte[] bytes = "Too many failed login attempts from this address - try again in a minute."
                .getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(429, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private boolean isUsingDefaultPassword() {
        return DEFAULT_PASSWORD.equals(plugin.getConfig().getString("password", ""));
    }

    /**
     * "block" (default): the setup-required page is shown and no session can
     * ever be created while the password is still the default - fails closed.
     * "warn": the default password is allowed to work (useful for local
     * demos/dev), but the login page carries a persistent warning about it.
     * This is an explicit opt-in the installer makes in config.yml.
     */
    private boolean isDefaultPasswordAllowed() {
        return "warn".equalsIgnoreCase(defaultPasswordMode);
    }

    private void serveSetupRequiredPage(HttpExchange exchange) throws IOException {
        String html = "<!doctype html><html><head><title>Map Not Yet Secured</title>"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                + "<style>body{background:#111;color:#eee;font-family:sans-serif;display:flex;"
                + "align-items:center;justify-content:center;min-height:100vh;margin:0;padding:1em;box-sizing:border-box}"
                + "div{background:#1c1c1c;padding:2em;border-radius:8px;max-width:28em;line-height:1.6}"
                + "code{background:#0c0c0c;padding:0.15em 0.4em;border-radius:4px}</style></head><body>"
                + "<div><h2>⚠ Map Not Yet Secured</h2>"
                + "<p>This map is still using MapGate's <strong>default password</strong> and cannot be accessed until it's changed.</p>"
                + "<p><strong>If you are the server admin:</strong> run</p>"
                + "<p><code>/mapgate setpassword &lt;your password&gt;</code></p>"
                + "<p>in the server console, or in-game if you have op permission. It takes effect immediately - no restart needed.</p>"
                + "<p>Alternatively, for local demos/development only, set <code>default-password-mode: warn</code> "
                + "in <code>config.yml</code> to allow the default password to work with a visible warning instead of blocking it.</p>"
                + "<p><strong>If you are not the admin:</strong> please contact them and ask them to secure this map before it can be used.</p>"
                + "</div></body></html>";
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(503, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void serveLoginPage(HttpExchange exchange, boolean failed) throws IOException {
        String errorHtml = failed ? "<p style=\"color:#f66\">Incorrect password.</p>" : "";
        // Only reachable here at all when default-password-mode is "warn" (handleRoot/handleLogin
        // otherwise redirect to the blocking setup-required page) - so no need to re-check the mode.
        String defaultPasswordHtml = isUsingDefaultPassword() ? (
                "<div style=\"background:#403820;border:1px solid #a85;border-radius:6px;"
                + "padding:0.75em 1em;margin-bottom:1em;text-align:left;font-size:0.85em;line-height:1.4\">"
                + "⚠ Still using MapGate's <strong>default password</strong> (allowed because "
                + "<code>default-password-mode</code> is set to <code>warn</code>). Fine for a demo/dev "
                + "instance - set a real password with <code>/mapgate setpassword</code> before this is exposed for real."
                + "</div>") : "";
        String warningHtml = looksLikeSecureProxy(exchange) ? "" : (
                "<div style=\"background:#402020;border:1px solid #a55;border-radius:6px;"
                + "padding:0.75em 1em;margin-bottom:1em;text-align:left;font-size:0.85em;line-height:1.4\">"
                + "⚠ You appear to be connecting directly, without a secure (HTTPS) proxy in front of this page. "
                + "Your password would be sent in <strong>plain text</strong>. Do not enter it unless you understand "
                + "the risk. <a href=\"" + escapeHtmlAttribute(insecureWarningUrl) + "\" target=\"_blank\" "
                + "rel=\"noopener\" style=\"color:#9cf\">Learn more</a>."
                + "</div>");
        String html = "<!doctype html><html><head><title>Map Login</title>"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                + "<style>body{background:#111;color:#eee;font-family:sans-serif;display:flex;"
                + "align-items:center;justify-content:center;height:100vh;margin:0}"
                + "form{background:#1c1c1c;padding:2em;border-radius:8px;text-align:center;max-width:22em}"
                + "input{padding:0.5em;margin-top:1em;border-radius:4px;border:1px solid #444;"
                + "background:#0c0c0c;color:#eee;width:100%;box-sizing:border-box}"
                + "button{margin-top:1em;padding:0.5em 1.5em;border-radius:4px;border:none;"
                + "background:#3a7;color:#fff;cursor:pointer}</style></head><body>"
                + "<form method=\"POST\" action=\"/mapgate/login\">"
                + "<h2>Enter Map Password</h2>" + defaultPasswordHtml + warningHtml + errorHtml
                + "<input type=\"password\" name=\"password\" autofocus>"
                + "<br><button type=\"submit\">Enter</button></form></body></html>";
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(failed ? 401 : 200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /**
     * True if this request is genuinely TLS-encrypted because MapGate
     * terminated it itself (tls-enabled: true) - always trusted, since
     * MapGate can be certain about its own listener. Otherwise, only trusts
     * the well-known proxy-set headers (X-Forwarded-Proto, CF-Visitor,
     * Front-End-Https) when trust-proxy-headers is explicitly enabled: these
     * are ordinary HTTP headers a client could forge directly to suppress the
     * plain-HTTP warning, so - same as the IP allow/block-list matching in
     * resolveClientAddress - they're only trusted at all once the admin has
     * opted in, ideally after firewalling the public port to reject direct
     * connections from anyone but the trusted proxy. See SECURITY.md. With
     * trust-proxy-headers left false (the default), a visitor behind an
     * unconfigured reverse proxy will still see the plain-HTTP warning even
     * though the visitor-to-proxy hop is actually encrypted - a false
     * positive that's the deliberately safe side to fail on.
     */
    private boolean looksLikeSecureProxy(HttpExchange exchange) {
        if (exchange instanceof HttpsExchange) {
            return true;
        }
        if (!trustProxyHeaders) {
            return false;
        }
        String forwardedProto = firstHeader(exchange, "X-Forwarded-Proto");
        if (forwardedProto != null && forwardedProto.toLowerCase().contains("https")) {
            return true;
        }
        String frontEndHttps = firstHeader(exchange, "Front-End-Https");
        if (frontEndHttps != null && frontEndHttps.equalsIgnoreCase("on")) {
            return true;
        }
        String cfVisitor = firstHeader(exchange, "CF-Visitor");
        return cfVisitor != null && cfVisitor.toLowerCase().contains("\"scheme\":\"https\"");
    }

    private String firstHeader(HttpExchange exchange, String name) {
        List<String> values = exchange.getRequestHeaders().get(name);
        return (values == null || values.isEmpty()) ? null : values.get(0);
    }

    private String escapeHtmlAttribute(String value) {
        return value.replace("&", "&amp;").replace("\"", "&quot;");
    }

    private void proxy(HttpExchange exchange) throws IOException {
        String target = "http://" + targetHost + ":" + targetPort + exchange.getRequestURI().toString();
        HttpURLConnection conn = (HttpURLConnection) URI.create(target).toURL().openConnection();
        conn.setConnectTimeout(BACKEND_CONNECT_TIMEOUT_MS);
        conn.setReadTimeout(BACKEND_READ_TIMEOUT_MS);
        conn.setRequestMethod(exchange.getRequestMethod());
        conn.setInstanceFollowRedirects(false);
        for (var header : exchange.getRequestHeaders().entrySet()) {
            String key = header.getKey();
            if (key.equalsIgnoreCase("Host") || key.equalsIgnoreCase("Cookie")) {
                continue;
            }
            for (String value : header.getValue()) {
                conn.addRequestProperty(key, value);
            }
        }
        conn.setDoInput(true);
        String method = exchange.getRequestMethod();
        if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method)) {
            conn.setDoOutput(true);
            try (InputStream is = exchange.getRequestBody(); OutputStream os = conn.getOutputStream()) {
                is.transferTo(os);
            }
        }

        int status;
        try {
            status = conn.getResponseCode();
        } catch (IOException e) {
            // A true connection failure (backend down/unreachable) - nothing to salvage, 502 and stop.
            exchange.sendResponseHeaders(502, -1);
            exchange.close();
            return;
        }

        InputStream responseStream;
        try {
            responseStream = conn.getInputStream();
        } catch (IOException e) {
            // getResponseCode() above already succeeded, so this is a non-2xx HTTP response from the
            // backend (e.g. its own 404/500) - relay its real status/body via the error stream instead
            // of masking it as a generic 502.
            responseStream = conn.getErrorStream();
            if (responseStream == null) {
                exchange.sendResponseHeaders(502, -1);
                exchange.close();
                return;
            }
        }

        conn.getHeaderFields().forEach((key, values) -> {
            if (key == null || key.equalsIgnoreCase("Transfer-Encoding") || key.equalsIgnoreCase("Content-Length")) {
                return;
            }
            for (String value : values) {
                exchange.getResponseHeaders().add(key, value);
            }
        });

        byte[] responseBody = responseStream.readAllBytes();
        exchange.sendResponseHeaders(status, responseBody.length == 0 ? -1 : responseBody.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBody);
        }
        responseStream.close();
    }

    private String readCookie(HttpExchange exchange, String name) {
        List<String> cookieHeaders = exchange.getRequestHeaders().get("Cookie");
        if (cookieHeaders == null) {
            return null;
        }
        for (String header : cookieHeaders) {
            for (String part : COOKIE_SPLIT.split(header)) {
                int idx = part.indexOf('=');
                if (idx > 0 && part.substring(0, idx).equals(name)) {
                    return part.substring(idx + 1);
                }
            }
        }
        return null;
    }

    private static final class BodyTooLargeException extends IOException {
        BodyTooLargeException(String message) {
            super(message);
        }
    }

    /** Reads the request body, rejecting anything over maxBytes rather than buffering it unbounded
     *  in memory - important here since this is called from the unauthenticated login endpoint. */
    private String readBody(HttpExchange exchange, int maxBytes) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int total = 0;
            int read;
            while ((read = is.read(buffer)) != -1) {
                total += read;
                if (total > maxBytes) {
                    throw new BodyTooLargeException("Request body exceeded " + maxBytes + " bytes");
                }
                out.write(buffer, 0, read);
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    private String parseFormValue(String body, String key) {
        for (String pair : body.split("&")) {
            int idx = pair.indexOf('=');
            if (idx < 0) {
                continue;
            }
            String k = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
            if (k.equals(key)) {
                return URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
