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
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;

/**
 * Generates (once) and loads a self-signed TLS keystore for MapGate's optional
 * HTTPS mode, using the JDK's own bundled `keytool` - no external dependency
 * or manual OpenSSL steps required. The keystore and its password are
 * persisted so visitors don't have to re-accept a new untrusted-certificate
 * warning on every server restart.
 *
 * Auto-generation (and the destructive regeneration behind /mapgate
 * regenerate-cert) only ever applies to the DEFAULT keystore path. If an
 * admin has pointed tls-keystore-path at a custom, user-supplied keystore
 * (e.g. a real CA-issued certificate, per the README), this class will only
 * ever try to load it - never silently delete or replace it.
 */
final class SelfSignedTls {

    private static final String DEFAULT_KEYSTORE_FILENAME = "selfsigned-keystore.p12";
    private static final String KEY_ALIAS = "mapgate";

    private SelfSignedTls() {
    }

    static SSLContext ensureAndLoad(MapGatePlugin plugin) throws IOException {
        String keystorePathSetting = plugin.getConfig().getString("tls-keystore-path", DEFAULT_KEYSTORE_FILENAME);
        boolean isDefaultPath = DEFAULT_KEYSTORE_FILENAME.equals(keystorePathSetting);
        File keystoreFile = new File(plugin.getDataFolder(), keystorePathSetting);
        String commonName = plugin.getConfig().getString("tls-common-name", "localhost");
        String storePassword = plugin.getConfig().getString("tls-keystore-password", "");

        boolean needsGeneration = !keystoreFile.exists() || storePassword.isEmpty();
        if (needsGeneration) {
            if (!isDefaultPath) {
                throw new IOException("tls-keystore-path is set to a custom file (\"" + keystorePathSetting + "\") but "
                        + (keystoreFile.exists() ? "no matching tls-keystore-password is configured" : "that file does not exist")
                        + ". MapGate only ever auto-generates a self-signed certificate at the default path (\""
                        + DEFAULT_KEYSTORE_FILENAME + "\") so it never overwrites a custom keystore - for a custom "
                        + "certificate, make sure both the file and its password are correctly set.");
            }
            storePassword = generateRandomPassword();
            generateSelfSignedKeystore(keystoreFile, storePassword, commonName);
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream in = new FileInputStream(keystoreFile)) {
                keyStore.load(in, storePassword.toCharArray());
            }
            if (needsGeneration) {
                // Only save the password (and log the fingerprint) after a successful load,
                // so a keystore that fails to load doesn't get a password persisted for it.
                plugin.getConfig().set("tls-keystore-password", storePassword);
                plugin.saveConfig();
                logFingerprint(keyStore, plugin);
            }
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, storePassword.toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            return sslContext;
        } catch (GeneralSecurityException e) {
            throw new IOException("Failed to load MapGate's TLS keystore at " + keystoreFile, e);
        }
    }

    /**
     * Deletes the keystore (and forgets its saved password) so the next enable regenerates a fresh
     * certificate. Refuses to do anything (returns false) if tls-keystore-path has been pointed at a
     * custom, non-default file, since that's a strong signal it's a user-supplied keystore this class
     * should never delete.
     */
    static boolean deleteKeystore(MapGatePlugin plugin) {
        String keystorePathSetting = plugin.getConfig().getString("tls-keystore-path", DEFAULT_KEYSTORE_FILENAME);
        if (!DEFAULT_KEYSTORE_FILENAME.equals(keystorePathSetting)) {
            return false;
        }
        File keystoreFile = new File(plugin.getDataFolder(), keystorePathSetting);
        if (keystoreFile.exists() && !keystoreFile.delete()) {
            plugin.getLogger().warning("Could not delete old TLS keystore at " + keystoreFile);
        }
        plugin.getConfig().set("tls-keystore-password", "");
        plugin.saveConfig();
        return true;
    }

    private static void generateSelfSignedKeystore(File keystoreFile, String password, String commonName)
            throws IOException {
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
                "-alias", KEY_ALIAS,
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
    }

    /** Logs the SHA-256 fingerprint of the freshly generated certificate - see SECURITY.md's MITM-verification guidance. */
    private static void logFingerprint(KeyStore keyStore, MapGatePlugin plugin) {
        try {
            Certificate certificate = keyStore.getCertificate(KEY_ALIAS);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] fingerprint = digest.digest(certificate.getEncoded());
            StringBuilder hex = new StringBuilder();
            for (byte b : fingerprint) {
                if (hex.length() > 0) {
                    hex.append(':');
                }
                hex.append(String.format("%02X", b));
            }
            plugin.getLogger().info("Generated a new self-signed TLS certificate for MapGate. "
                    + "SHA-256 fingerprint: " + hex);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateEncodingException e) {
            plugin.getLogger().warning("Generated a new self-signed TLS certificate for MapGate, "
                    + "but could not compute its fingerprint for logging: " + e.getMessage());
        }
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
