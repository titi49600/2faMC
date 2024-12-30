package com.security.minecraft2fa.commands;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.security.minecraft2fa.Minecraft2FAPlugin;
import lombok.RequiredArgsConstructor;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.entity.Player;

import java.io.File;
import java.nio.file.Path;

@RequiredArgsConstructor
public class TwoFactorAuthCommand implements CommandExecutor {

    private final Minecraft2FAPlugin plugin;

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (args.length == 0) {
            sendHelp(sender);
            return true;
        }

        switch (args[0].toLowerCase()) {
            case "setup":
                if (!(sender instanceof ConsoleCommandSender)) {
                    sender.sendMessage("§cCette commande ne peut être exécutée que depuis la console!");
                    return true;
                }
                if (args.length != 2) {
                    sender.sendMessage("§cUtilisation: /2fa setup <joueur>");
                    return true;
                }
                handleSetup(sender, args[1]);
                break;
            case "verify":
                if (!(sender instanceof Player)) {
                    sender.sendMessage("§cCette commande ne peut être utilisée que par un joueur!");
                    return true;
                }
                if (args.length != 2) {
                    sender.sendMessage("§cUtilisation: /2fa verify <code>");
                    return true;
                }
                handleVerify((Player) sender, args[1]);
                break;
            case "disable":
                if (!(sender instanceof ConsoleCommandSender)) {
                    sender.sendMessage("§cCette commande ne peut être exécutée que depuis la console!");
                    return true;
                }
                if (args.length != 2) {
                    sender.sendMessage("§cUtilisation: /2fa disable <joueur>");
                    return true;
                }
                handleDisable(sender, args[1]);
                break;
            case "status":
                if (!(sender instanceof Player)) {
                    sender.sendMessage("§cCette commande ne peut être utilisée que par un joueur!");
                    return true;
                }
                handleStatus((Player) sender);
                break;
            default:
                sendHelp(sender);
                break;
        }

        return true;
    }

    private void handleSetup(CommandSender sender, String playerName) {
        Player target = Bukkit.getPlayer(playerName);
        if (target == null) {
            sender.sendMessage("§cJoueur non trouvé!");
            return;
        }

        if (plugin.getAuthManager().has2FAEnabled(target)) {
            sender.sendMessage("§cCe joueur a déjà configuré l'authentification à deux facteurs!");
            return;
        }

        String secret = plugin.getAuthManager().generateSecret(target);
        
        // Création du dossier pour les QR codes s'il n'existe pas
        File qrFolder = new File(plugin.getDataFolder(), "qrcodes");
        if (!qrFolder.exists()) {
            qrFolder.mkdirs();
        }

        try {
            // Génération du QR code
            String otpAuthURL = String.format("otpauth://totp/%s?secret=%s&issuer=MinecraftServer",
                    target.getName(), secret);
            BitMatrix matrix = new MultiFormatWriter().encode(
                    otpAuthURL,
                    BarcodeFormat.QR_CODE,
                    400,
                    400
            );

            // Sauvegarde du QR code
            Path qrPath = new File(qrFolder, target.getName() + "_qr.png").toPath();
            MatrixToImageWriter.writeToPath(matrix, "PNG", qrPath);

            // Envoi des informations au joueur
            target.sendMessage("§e=== Configuration de l'authentification à deux facteurs ===");
            target.sendMessage("§71. Installez Google Authenticator sur votre téléphone");
            target.sendMessage("§72. Scannez le QR code qui vous a été envoyé ou entrez la clé manuellement:");
            target.sendMessage("§7Clé secrète: §e" + secret);
            target.sendMessage("§73. Entrez le code généré avec la commande: §e/2fa verify <code>");

            // Message de confirmation à la console
            sender.sendMessage("§aConfiguration 2FA initiée pour " + target.getName());
            sender.sendMessage("§7Le QR code a été généré dans: plugins/Minecraft2FA/qrcodes/" + target.getName() + "_qr.png");

        } catch (Exception e) {
            sender.sendMessage("§cErreur lors de la génération du QR code: " + e.getMessage());
            plugin.getLogger().severe("Erreur lors de la génération du QR code pour " + target.getName() + ": " + e.getMessage());
        }
    }

    private void handleVerify(Player player, String codeStr) {
        try {
            int code = Integer.parseInt(codeStr);
            
            if (plugin.getAuthManager().has2FAEnabled(player)) {
                if (plugin.getAuthManager().verifyCode(player, code)) {
                    player.sendMessage("§aAuthentification réussie!");
                } else {
                    player.sendMessage("§cCode invalide!");
                }
            } else {
                if (plugin.getAuthManager().finalizeSetup(player, code)) {
                    player.sendMessage("§aConfiguration 2FA terminée avec succès!");
                    // Suppression du QR code après configuration réussie
                    File qrFile = new File(plugin.getDataFolder(), "qrcodes/" + player.getName() + "_qr.png");
                    if (qrFile.exists()) {
                        qrFile.delete();
                    }
                } else {
                    player.sendMessage("§cCode invalide ou configuration non initiée!");
                }
            }
        } catch (NumberFormatException e) {
            player.sendMessage("§cLe code doit être un nombre!");
        }
    }

    private void handleDisable(CommandSender sender, String playerName) {
        Player target = Bukkit.getPlayer(playerName);
        if (target == null) {
            sender.sendMessage("§cJoueur non trouvé!");
            return;
        }

        if (!plugin.getAuthManager().has2FAEnabled(target)) {
            sender.sendMessage("§cCe joueur n'a pas activé l'authentification à deux facteurs!");
            return;
        }

        plugin.getAuthManager().disable2FA(target);
        sender.sendMessage("§aL'authentification à deux facteurs a été désactivée pour " + target.getName());
        target.sendMessage("§aVotre authentification à deux facteurs a été désactivée par un administrateur!");
    }

    private void handleStatus(Player player) {
        boolean enabled = plugin.getAuthManager().has2FAEnabled(player);
        boolean authenticated = plugin.getAuthManager().isAuthenticated(player);

        player.sendMessage("§e=== Statut 2FA ===");
        player.sendMessage("§7État: " + (enabled ? "§aActivé" : "§cDésactivé"));
        if (enabled) {
            player.sendMessage("§7Session: " + (authenticated ? "§aAuthentifié" : "§cNon authentifié"));
        }
    }

    private void sendHelp(CommandSender sender) {
        if (sender instanceof ConsoleCommandSender) {
            sender.sendMessage("§e=== Commandes Admin 2FA ===");
            sender.sendMessage("§7/2fa setup <joueur> §f- Configure le 2FA pour un joueur");
            sender.sendMessage("§7/2fa disable <joueur> §f- Désactive le 2FA pour un joueur");
        } else if (sender instanceof Player) {
            sender.sendMessage("§e=== Commandes 2FA ===");
            sender.sendMessage("§7/2fa verify <code> §f- Vérifie un code 2FA");
            sender.sendMessage("§7/2fa status §f- Affiche votre statut 2FA");
        }
    }
}