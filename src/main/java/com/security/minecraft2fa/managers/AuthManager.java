package com.security.minecraft2fa.managers;

import com.security.minecraft2fa.Minecraft2FAPlugin;
import com.security.minecraft2fa.utils.DiscordWebhook;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import lombok.RequiredArgsConstructor;
import org.bukkit.BanList;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Date;

@RequiredArgsConstructor
public class AuthManager {
    
    private final Minecraft2FAPlugin plugin;
    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();
    private final Map<UUID, String> pendingSetup = new ConcurrentHashMap<>();
    private final Map<UUID, Long> authenticatedSessions = new ConcurrentHashMap<>();
    private final Map<UUID, Integer> failedAttempts = new ConcurrentHashMap<>();
    private final Map<UUID, Long> lastAttemptTime = new ConcurrentHashMap<>();
    private DiscordWebhook webhook;
    
    /**
     * Initialise le webhook Discord si activé
     */
    public void initializeWebhook() {
        if (plugin.getConfig().getBoolean("discord.enabled", false)) {
            String webhookUrl = plugin.getConfig().getString("discord.webhook-url", "");
            if (!webhookUrl.isEmpty()) {
                webhook = new DiscordWebhook(webhookUrl);
            }
        }
    }
    
    /**
     * Génère une nouvelle clé secrète pour un joueur
     */
    public String generateSecret(Player player) {
        // Vérifie si le joueur n'a pas déjà une configuration en cours
        if (pendingSetup.containsKey(player.getUniqueId())) {
            return pendingSetup.get(player.getUniqueId());
        }
        
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        String secretKey = key.getKey();
        pendingSetup.put(player.getUniqueId(), secretKey);
        
        // Log la génération de la clé
        plugin.getLogger().info("Nouvelle clé 2FA générée pour " + player.getName());
        
        return secretKey;
    }
    
    /**
     * Vérifie si le code 2FA est valide
     */
    public boolean verifyCode(Player player, int code) {
        plugin.getLogger().info("Vérification du code 2FA pour " + player.getName() + " (code: " + code + ")");
        
        // Vérifie le délai entre les tentatives (anti-bruteforce)
        long currentTime = System.currentTimeMillis();
        long lastAttempt = lastAttemptTime.getOrDefault(player.getUniqueId(), 0L);
        long cooldown = plugin.getConfig().getLong("security.attempt-cooldown", 2000); // 2 secondes par défaut
        
        if (currentTime - lastAttempt < cooldown) {
            player.sendMessage(plugin.getConfig().getString("messages.cooldown", "§cVeuillez attendre avant de réessayer."));
            return false;
        }
        lastAttemptTime.put(player.getUniqueId(), currentTime);
        
        String secretKey = plugin.getDatabaseManager().getSecretKey(player.getUniqueId());
        if (secretKey == null) {
            plugin.getLogger().warning("Aucune clé secrète trouvée pour " + player.getName());
            return false;
        }
        
        // Vérifie si le code n'est pas un code évident
        if (isObviousCode(code)) {
            plugin.getLogger().warning(player.getName() + " a tenté d'utiliser un code évident: " + code);
            handleFailedAttempt(player, code);
            return false;
        }
        
        boolean isValid = gAuth.authorize(secretKey, code);
        
        if (!isValid) {
            plugin.getLogger().warning("Code 2FA invalide pour " + player.getName() + " (code: " + code + ")");
            handleFailedAttempt(player, code);
        } else {
            // Reset le compteur en cas de succès et sauvegarde l'IP
            plugin.getLogger().info("Code 2FA valide pour " + player.getName());
            failedAttempts.remove(player.getUniqueId());
            String ip = player.getAddress().getAddress().getHostAddress();
            plugin.getSessionManager().setSession(player.getUniqueId(), ip);
            player.sendMessage(plugin.getConfig().getString("messages.auth-success", "§aAuthentification réussie!"));
            plugin.getLogger().info(player.getName() + " s'est authentifié avec succès via 2FA (IP: " + ip + ")");
        }
        
        return isValid;
    }
    
    /**
     * Gère une tentative d'authentification échouée
     */
    private void handleFailedAttempt(Player player, int code) {
        // Incrémente le compteur d'échecs
        int attempts = failedAttempts.getOrDefault(player.getUniqueId(), 0) + 1;
        failedAttempts.put(player.getUniqueId(), attempts);
        
        // Envoie l'alerte Discord
        if (webhook != null) {
            webhook.sendAlert(player.getName(), player.getAddress().getAddress().getHostAddress(), code);
        }

        // Vérifie si le joueur doit être banni
        int maxAttempts = plugin.getConfig().getInt("security.max-attempts", 3);
        if (attempts >= maxAttempts) {
            // Calcule la durée du ban
            int banMinutes = plugin.getConfig().getInt("security.lockout-duration", 5);
            Date expiration = new Date(System.currentTimeMillis() + (banMinutes * 60 * 1000));
            
            // Ban le joueur
            Bukkit.getBanList(BanList.Type.NAME).addBan(
                player.getName(),
                "§cTrop de tentatives d'authentification échouées. Réessayez dans " + banMinutes + " minutes.",
                expiration,
                "2FA Security"
            );
            
            // Kick le joueur
            Bukkit.getScheduler().runTask(plugin, () -> 
                player.kickPlayer("§cTrop de tentatives d'authentification échouées.\n§7Réessayez dans " + banMinutes + " minutes.")
            );
            
            // Reset le compteur
            failedAttempts.remove(player.getUniqueId());
            
            plugin.getLogger().warning(player.getName() + " a été banni temporairement après " + attempts + " tentatives échouées");
        } else {
            player.sendMessage("§cCode invalide! Tentative " + attempts + "/" + maxAttempts);
            plugin.getLogger().warning(player.getName() + " a échoué la tentative d'authentification " + attempts + "/" + maxAttempts);
        }
    }
    
    /**
     * Vérifie si un code est trop évident (anti-bruteforce simple)
     */
    private boolean isObviousCode(int code) {
        String codeStr = String.format("%06d", code);
        // Vérifie les codes évidents comme 000000, 123456, etc.
        return codeStr.matches("0{6}|1{6}|2{6}|3{6}|4{6}|5{6}|6{6}|7{6}|8{6}|9{6}|12345.|123123|111111|222222|333333|444444|555555|666666|777777|888888|999999");
    }
    
    /**
     * Vérifie si un joueur est authentifié
     */
    public boolean isAuthenticated(Player player) {
        String currentIp = player.getAddress().getAddress().getHostAddress();
        String savedIp = plugin.getSessionManager().getSession(player.getUniqueId());
        
        if (savedIp == null) {
            return false;
        }
        
        return savedIp.equals(currentIp);
    }
    
    /**
     * Finalise la configuration 2FA pour un joueur
     */
    public boolean finalizeSetup(Player player, int code) {
        plugin.getLogger().info("Finalisation de la configuration 2FA pour " + player.getName());
        
        String pendingSecret = pendingSetup.get(player.getUniqueId());
        if (pendingSecret == null) {
            plugin.getLogger().warning("Tentative de finalisation 2FA pour " + player.getName() + " sans configuration préalable");
            return false;
        }
        
        if (gAuth.authorize(pendingSecret, code)) {
            plugin.getLogger().info("Code valide, enregistrement de la configuration pour " + player.getName());
            plugin.getDatabaseManager().setSecretKey(player.getUniqueId(), pendingSecret);
            pendingSetup.remove(player.getUniqueId());
            
            // Enregistre la session après une configuration réussie
            String ip = player.getAddress().getAddress().getHostAddress();
            plugin.getSessionManager().setSession(player.getUniqueId(), ip);
            
            player.sendMessage(plugin.getConfig().getString("messages.setup-success", "§aConfiguration 2FA terminée avec succès!"));
            plugin.getLogger().info("Configuration 2FA terminée avec succès pour " + player.getName());
            
            return true;
        } else {
            plugin.getLogger().warning("Échec de la configuration 2FA pour " + player.getName() + " (code invalide: " + code + ")");
            // Envoie une alerte Discord pour l'échec de configuration
            if (webhook != null) {
                webhook.sendAlert(player.getName(), player.getAddress().getAddress().getHostAddress(), code);
            }
        }
        return false;
    }
    
    /**
     * Désactive le 2FA pour un joueur
     */
    public void disable2FA(Player player) {
        // Supprime la clé secrète de la base de données
        plugin.getDatabaseManager().removeSecretKey(player.getUniqueId());
        
        // Nettoie toutes les sessions
        plugin.getSessionManager().removeSession(player.getUniqueId());
        authenticatedSessions.remove(player.getUniqueId());
        pendingSetup.remove(player.getUniqueId());
        failedAttempts.remove(player.getUniqueId());
        lastAttemptTime.remove(player.getUniqueId());
        
        // Force la vérification des permissions
        if (player.isOnline()) {
            Player onlinePlayer = player.getPlayer();
            if (onlinePlayer != null) {
                // Si le joueur a des permissions sensibles, on le bloque
                List<String> sensitivePermissions = plugin.getConfig().getStringList("sensitive-permissions");
                for (String permission : sensitivePermissions) {
                    if (onlinePlayer.hasPermission(permission)) {
                        onlinePlayer.teleport(onlinePlayer.getLocation()); // Empêche le mouvement
                        onlinePlayer.sendMessage(plugin.getConfig().getString("messages.setup-required", 
                            "§cVous devez configurer l'authentification à deux facteurs!"));
                        break;
                    }
                }
            }
        }
        
        plugin.getLogger().info("2FA désactivé pour " + player.getName() + " - Sessions nettoyées");
    }
    
    /**
     * Vérifie si un joueur a le 2FA activé
     */
    public boolean has2FAEnabled(Player player) {
        return plugin.getDatabaseManager().getSecretKey(player.getUniqueId()) != null;
    }
    
    /**
     * Déconnecte un joueur de sa session 2FA
     */
    public void logout(Player player) {
        authenticatedSessions.remove(player.getUniqueId());
        plugin.getLogger().info(player.getName() + " a été déconnecté de sa session 2FA");
    }
} 