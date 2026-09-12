package com.cinaptic.mapgate;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Level;

public final class MapGatePlugin extends JavaPlugin {

    private GateHttpServer gateServer;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        startGateServer();
    }

    @Override
    public void onDisable() {
        stopGateServer();
    }

    /** Returns true if the gate server started successfully - callers (commands) must check this
     *  rather than assuming success, since a failure here (e.g. a bad TLS keystore, port already
     *  in use) otherwise gets silently swallowed and reported as a successful reload/regenerate. */
    private boolean startGateServer() {
        try {
            gateServer = new GateHttpServer(this);
            gateServer.start();
            getLogger().info("MapGate listening on port " + getConfig().getInt("public-port")
                    + ", proxying to " + getConfig().getString("target-host") + ":"
                    + getConfig().getInt("target-port"));
            return true;
        } catch (IOException e) {
            getLogger().log(Level.SEVERE, "Failed to start MapGate HTTP server", e);
            gateServer = null;
            return false;
        }
    }

    private void stopGateServer() {
        if (gateServer != null) {
            gateServer.stop();
            gateServer = null;
        }
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (args.length == 0) {
            sender.sendMessage("Usage: /mapgate <setpassword <pass>|reload|sessions|regenerate-cert>");
            return true;
        }

        switch (args[0].toLowerCase()) {
            case "setpassword" -> {
                if (args.length < 2) {
                    sender.sendMessage("Usage: /mapgate setpassword <new password>");
                    return true;
                }
                String newPassword = String.join(" ", Arrays.copyOfRange(args, 1, args.length));
                getConfig().set("password", newPassword);
                saveConfig();
                // A token issued under the old password (or one that leaked) should not keep
                // working after the password changes - force everyone to log in again.
                if (gateServer != null) {
                    gateServer.invalidateAllSessions();
                }
                sender.sendMessage("MapGate password updated. Existing sessions were invalidated.");
            }
            case "reload" -> {
                stopGateServer();
                reloadConfig();
                boolean started = startGateServer();
                sender.sendMessage(started
                        ? "MapGate reloaded."
                        : "MapGate reload FAILED - the gate is currently stopped. See console for details.");
            }
            case "sessions" -> {
                int count = gateServer == null ? 0 : gateServer.activeSessionCount();
                sender.sendMessage("Active MapGate sessions: " + count);
            }
            case "regenerate-cert" -> {
                if (!getConfig().getBoolean("tls-enabled", false)) {
                    sender.sendMessage("tls-enabled is false - there's no certificate to regenerate.");
                    return true;
                }
                stopGateServer();
                boolean deleted = SelfSignedTls.deleteKeystore(this);
                if (!deleted) {
                    sender.sendMessage("tls-keystore-path is set to a custom (non-default) file - refusing to "
                            + "delete it, since that's likely your own certificate, not one MapGate generated. "
                            + "Replace that file yourself if you want a new certificate.");
                    startGateServer();
                    return true;
                }
                reloadConfig();
                boolean started = startGateServer();
                sender.sendMessage(started
                        ? "MapGate's self-signed TLS certificate was regenerated. "
                                + "Visitors' browsers will need to re-accept the new certificate."
                        : "Certificate deleted, but MapGate FAILED to restart - the gate is currently stopped. "
                                + "See console for details.");
            }
            default -> sender.sendMessage("Usage: /mapgate <setpassword <pass>|reload|sessions|regenerate-cert>");
        }
        return true;
    }
}
