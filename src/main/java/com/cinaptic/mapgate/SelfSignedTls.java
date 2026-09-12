package com.cinaptic.mapgate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates (once) and loads a self-signed TLS keystore for MapGate's optional
 * HTTPS mode, using the JDK's own bundled `keytool` - no external dependency
 * or manual OpenSSL steps required. The keystore and its password are
 * persisted so visitors don't have to re-accept a new untrusted-certificate
 * warning on every server restart.
 */
final class SelfSignedTls {

    private SelfSignedTls() {
    }

    static SSLContext ensureAndLoad(MapGatePlugin plugin) throws IOException {
        File keystoreFile = new File(plugin.getDataFolder(),
                plugin.getConfig().getString("tls-keystore-path", "selfsigned-keystore.p12"));
        String commonName = plugin.getConfig().getString("tls-common-name", "localhost");
        String storePassword = plugin.getConfig().getString("tls-keystore-password", "");

        if (!keystoreFile.exists() || storePassword.isEmpty()) {
            storePassword = generateRandomPassword();
            generateSelfSignedKeystore(keystoreFile, storePassword, commonName, plugin);
            plugin.getConfig().set("tls-keystore-password", storePassword);
            plugin.saveConfig();
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream in = new FileInputStream(keystoreFile)) {
                keyStore.load(in, storePassword.toCharArray());
            }
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, storePassword.toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            return sslContext;
        } catch (GeneralSecurityException e) {
            throw new IOException("Failed to load MapGate's self-signed TLS keystore at " + keystoreFile, e);
        }
    }

    /** Deletes the keystore (and forgets its saved password) so the next enable regenerates a fresh certificate. */
    static void deleteKeystore(MapGatePlugin plugin) {
        File keystoreFile = new File(plugin.getDataFolder(),
                plugin.getConfig().getString("tls-keystore-path", "selfsigned-keystore.p12"));
        if (keystoreFile.exists() && !keystoreFile.delete()) {
            plugin.getLogger().warning("Could not delete old TLS keystore at " + keystoreFile);
        }
        plugin.getConfig().set("tls-keystore-password", "");
        plugin.saveConfig();
    }

    private static void generateSelfSignedKeystore(File keystoreFile, String password, String commonName,
                                                     MapGatePlugin plugin) throws IOException {
        File parent = keystoreFile.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        if (keystoreFile.exists() && !keystoreFile.delete()) {
            throw new IOException("Could not remove existing keystore file at " + keystoreFile + " before regenerating it");
        }

        String keytoolExecutable = System.getProperty("java.home") + File.separator + "bin" + File.separator
                + (isWindows() ? "keytool.exe" : "keytool");
        String sanType = looksLikeIpAddress(commonName) ? "ip" : "dns";

        ProcessBuilder processBuilder = new ProcessBuilder(
                keytoolExecutable, "-genkeypair",
                "-alias", "mapgate",
                "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "3650",
                "-storetype", "PKCS12",
                "-keystore", keystoreFile.getAbsolutePath(),
                "-storepass", password,
                "-keypass", password,
                "-dname", "CN=" + commonName + ", OU=MapGate, O=MapGate",
                "-ext", "SAN=" + sanType + ":" + commonName
        );
        processBuilder.redirectErrorStream(true);

        String output;
        int exitCode;
        try {
            Process process = processBuilder.start();
            try (InputStream in = process.getInputStream()) {
                output = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            exitCode = process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while generating MapGate's self-signed TLS certificate", e);
        }

        if (exitCode != 0) {
            throw new IOException("keytool exited with code " + exitCode + " while generating MapGate's "
                    + "self-signed TLS certificate:\n" + output);
        }
        plugin.getLogger().info("Generated a new self-signed TLS certificate for MapGate (CN=" + commonName + ")");
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private static boolean looksLikeIpAddress(String value) {
        return value.matches("^[0-9.]+$") || value.contains(":");
    }

    private static String generateRandomPassword() {
        byte[] bytes = new byte[24];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
