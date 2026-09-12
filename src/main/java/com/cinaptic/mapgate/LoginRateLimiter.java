package com.cinaptic.mapgate;

import java.net.InetAddress;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A simple fixed-window per-IP login attempt limiter, to slow down automated
 * brute-force guessing against the single shared password. This is not a
 * substitute for a strong password - it just raises the cost of guessing one,
 * the same way the rest of MapGate's IP-based checks are best-effort rather
 * than absolute (see SECURITY.md).
 */
final class LoginRateLimiter {

    private static final int MAX_ATTEMPTS_PER_WINDOW = 5;
    private static final long WINDOW_SECONDS = 60;

    private static final class Window {
        final AtomicInteger attempts = new AtomicInteger(0);
        final Instant windowStart = Instant.now();
    }

    private final ConcurrentHashMap<InetAddress, Window> windows = new ConcurrentHashMap<>();

    /** True if this address has exceeded the allowed failed attempts within the current window. */
    boolean isLocked(InetAddress address) {
        if (address == null) {
            return false;
        }
        Window window = windows.get(address);
        if (window == null) {
            return false;
        }
        if (Instant.now().isAfter(window.windowStart.plusSeconds(WINDOW_SECONDS))) {
            windows.remove(address);
            return false;
        }
        return window.attempts.get() >= MAX_ATTEMPTS_PER_WINDOW;
    }

    void recordFailure(InetAddress address) {
        if (address == null) {
            return;
        }
        Window window = windows.computeIfAbsent(address, addr -> new Window());
        if (Instant.now().isAfter(window.windowStart.plusSeconds(WINDOW_SECONDS))) {
            windows.remove(address);
            window = windows.computeIfAbsent(address, addr -> new Window());
        }
        window.attempts.incrementAndGet();
    }

    void recordSuccess(InetAddress address) {
        if (address != null) {
            windows.remove(address);
        }
    }
}
