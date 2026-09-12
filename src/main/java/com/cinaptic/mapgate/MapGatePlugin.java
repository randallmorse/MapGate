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

    private void startGateServer() {
        try {
            gateServer = new GateHttpServer(this);
            gateServer.start();
            getLogger().info("MapGate listening on port " + getConfig().getInt("public-port")
                    + ", proxying to " + getConfig().getString("target-host") + ":"
                    + getConfig().getInt("target-port"));
        } catch (IOException e) {
            getLogger().log(Level.SEVERE, "Failed to start MapGate HTTP server", e);
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
                sender.sendMessage("MapGate password updated.");
            }
            case "reload" -> {
                stopGateServer();
                reloadConfig();
                startGateServer();
                sender.sendMessage("MapGate reloaded.");
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
                SelfSignedTls.deleteKeystore(this);
                reloadConfig();
                startGateServer();
                sender.sendMessage("MapGate's self-signed TLS certificate was regenerated. "
                        + "Visitors' browsers will need to re-accept the new certificate.");
            }
            default -> sender.sendMessage("Usage: /mapgate <setpassword <pass>|reload|sessions|regenerate-cert>");
        }
        return true;
    }
}
