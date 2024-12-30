package com.security.minecraft2fa.commands;

import com.security.minecraft2fa.Minecraft2FAPlugin;
import lombok.RequiredArgsConstructor;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

@RequiredArgsConstructor
public class TwoFactorAuthAdminCommand implements CommandExecutor {

    private final Minecraft2FAPlugin plugin;

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!sender.hasPermission("minecraft2fa.admin")) {
            sender.sendMessage("§cVous n'avez pas la permission d'utiliser cette commande!");
            return true;
        }

        if (args.length == 0) {
            sendHelp(sender);
            return true;
        }

        switch (args[0].toLowerCase()) {
            case "force-reset":
                if (args.length != 2) {
                    sender.sendMessage("§cUtilisation: /2fa-admin force-reset <joueur>");
                    return true;
                }
                handleForceReset(sender, args[1]);
                break;
            case "check":
                if (args.length != 2) {
                    sender.sendMessage("§cUtilisation: /2fa-admin check <joueur>");
                    return true;
                }
                handleCheck(sender, args[1]);
                break;
            case "list":
                handleList(sender);
                break;
            default:
                sendHelp(sender);
                break;
        }

        return true;
    }

    private void handleForceReset(CommandSender sender, String targetName) {
        Player target = Bukkit.getPlayer(targetName);
        if (target == null) {
            sender.sendMessage("§cJoueur non trouvé!");
            return;
        }

        plugin.getAuthManager().disable2FA(target);
        sender.sendMessage("§aL'authentification à deux facteurs a été réinitialisée pour " + target.getName());
        target.sendMessage("§cVotre authentification à deux facteurs a été réinitialisée par un administrateur!");
    }

    private void handleCheck(CommandSender sender, String targetName) {
        Player target = Bukkit.getPlayer(targetName);
        if (target == null) {
            sender.sendMessage("§cJoueur non trouvé!");
            return;
        }

        boolean enabled = plugin.getAuthManager().has2FAEnabled(target);
        boolean authenticated = plugin.getAuthManager().isAuthenticated(target);

        sender.sendMessage("§e=== Statut 2FA de " + target.getName() + " ===");
        sender.sendMessage("§7État: " + (enabled ? "§aActivé" : "§cDésactivé"));
        if (enabled) {
            sender.sendMessage("§7Session: " + (authenticated ? "§aAuthentifié" : "§cNon authentifié"));
        }
    }

    private void handleList(CommandSender sender) {
        sender.sendMessage("§e=== Joueurs avec 2FA ===");
        int count = 0;

        for (Player player : Bukkit.getOnlinePlayers()) {
            if (plugin.getAuthManager().has2FAEnabled(player)) {
                boolean authenticated = plugin.getAuthManager().isAuthenticated(player);
                sender.sendMessage("§7- " + player.getName() + ": " + 
                    (authenticated ? "§aAuthentifié" : "§cNon authentifié"));
                count++;
            }
        }

        if (count == 0) {
            sender.sendMessage("§7Aucun joueur en ligne n'a le 2FA activé");
        }
    }

    private void sendHelp(CommandSender sender) {
        sender.sendMessage("§e=== Commandes Admin 2FA ===");
        sender.sendMessage("§7/2fa-admin force-reset <joueur> §f- Réinitialise le 2FA d'un joueur");
        sender.sendMessage("§7/2fa-admin check <joueur> §f- Vérifie le statut 2FA d'un joueur");
        sender.sendMessage("§7/2fa-admin list §f- Liste les joueurs avec 2FA activé");
    }
}