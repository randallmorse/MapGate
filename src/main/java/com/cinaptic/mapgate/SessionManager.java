package com.cinaptic.mapgate;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory session store. Sessions do not survive a server restart -
 * visitors just log in again, which is an acceptable tradeoff for a
 * simple shared-password gate.
 */
final class SessionManager {

    private final SecureRandom random = new SecureRandom();
    private final Map<String, Instant> sessions = new ConcurrentHashMap<>();
    private final long sessionDurationSeconds;

    SessionManager(long sessionDurationSeconds) {
        this.sessionDurationSeconds = sessionDurationSeconds;
    }

    String createSession() {
        // Piggyback expired-entry cleanup on every new login, rather than only when a
        // caller happens to touch an already-expired token or run /mapgate sessions -
        // otherwise a steady trickle of logins could accumulate entries unboundedly.
        purgeExpired();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        sessions.put(token, Instant.now().plusSeconds(sessionDurationSeconds));
        return token;
    }

    boolean isValid(String token) {
        if (token == null) {
            return false;
        }
        Instant expiry = sessions.get(token);
        if (expiry == null) {
            return false;
        }
        if (Instant.now().isAfter(expiry)) {
            sessions.remove(token);
            return false;
        }
        return true;
    }

    void invalidate(String token) {
        if (token != null) {
            sessions.remove(token);
        }
    }

    /** Invalidates every current session - used when the password changes, so a compromised
     *  or shared old password can't keep granting access via a token issued before the change. */
    void invalidateAll() {
        sessions.clear();
    }

    private void purgeExpired() {
        Instant now = Instant.now();
        sessions.entrySet().removeIf(e -> now.isAfter(e.getValue()));
    }

    int activeCount() {
        purgeExpired();
        return sessions.size();
    }

    long sessionDurationSeconds() {
        return sessionDurationSeconds;
    }
}
