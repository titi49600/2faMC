package com.security.minecraft2fa;

import com.security.minecraft2fa.commands.TwoFactorAuthCommand;
import com.security.minecraft2fa.commands.TwoFactorAuthAdminCommand;
import com.security.minecraft2fa.listeners.PlayerListener;
import com.security.minecraft2fa.managers.AuthManager;
import com.security.minecraft2fa.storage.DatabaseManager;
import com.security.minecraft2fa.storage.SessionManager;
import lombok.Getter;
import org.bukkit.plugin.java.JavaPlugin;

public class Minecraft2FAPlugin extends JavaPlugin {
    
    @Getter
    private static Minecraft2FAPlugin instance;
    
    @Getter
    private DatabaseManager databaseManager;
    
    @Getter
    private AuthManager authManager;
    
    @Getter
    private SessionManager sessionManager;

    @Override
    public void onEnable() {
        instance = this;
        
        getLogger().info("Démarrage du plugin 2FA...");
        
        // Sauvegarde de la configuration par défaut
        saveDefaultConfig();
        reloadConfig();
        
        // Création du dossier du plugin s'il n'existe pas
        if (!getDataFolder().exists()) {
            getLogger().info("Création du dossier du plugin...");
            getDataFolder().mkdirs();
        }
        
        try {
            // Initialisation des managers
            getLogger().info("Initialisation du gestionnaire de base de données...");
            this.databaseManager = new DatabaseManager(this);
            this.databaseManager.initialize();
            getLogger().info("Base de données initialisée avec succès!");
            
            getLogger().info("Initialisation du gestionnaire de sessions...");
            this.sessionManager = new SessionManager(this);
            this.sessionManager.initialize();
            getLogger().info("Gestionnaire de sessions initialisé!");
            
            getLogger().info("Initialisation du gestionnaire d'authentification...");
            this.authManager = new AuthManager(this);
            this.authManager.initializeWebhook();
            getLogger().info("Gestionnaire d'authentification initialisé!");
            
            // Enregistrement des commandes
            getLogger().info("Enregistrement des commandes...");
            getCommand("2fa").setExecutor(new TwoFactorAuthCommand(this));
            getCommand("2fa-admin").setExecutor(new TwoFactorAuthAdminCommand(this));
            
            // Enregistrement des listeners
            getLogger().info("Enregistrement des événements...");
            PlayerListener playerListener = new PlayerListener(this);
            getServer().getPluginManager().registerEvents(playerListener, this);
            
            // Initialisation des écouteurs LuckPerms
            getLogger().info("Initialisation des écouteurs LuckPerms...");
            playerListener.registerLuckPermsEvents();
            getLogger().info("Écouteurs LuckPerms initialisés!");
            
            // Vérification du mode multi-serveur
            if (getConfig().getBoolean("redis.enabled", false)) {
                getLogger().info("Mode multi-serveur activé!");
                getLogger().info("Redis host: " + getConfig().getString("redis.host"));
                getLogger().info("Redis port: " + getConfig().getInt("redis.port"));
                if (sessionManager.isUsingRedis()) {
                    getLogger().info("Connexion Redis établie avec succès!");
                } else {
                    getLogger().warning("Redis est activé dans la configuration mais la connexion a échoué!");
                    getLogger().warning("Le plugin fonctionnera en mode standalone jusqu'à ce que Redis soit disponible.");
                }
            } else {
                getLogger().info("Mode standalone activé - Les sessions ne seront pas partagées entre les serveurs");
            }
            
            getLogger().info("Plugin 2FA activé avec succès!");
            
        } catch (Exception e) {
            getLogger().severe("Erreur lors de l'initialisation du plugin: " + e.getMessage());
            getLogger().severe("Stack trace: " + e.toString());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
    }

    @Override
    public void onDisable() {
        getLogger().info("Arrêt du plugin 2FA...");
        
        if (sessionManager != null) {
            getLogger().info("Fermeture du gestionnaire de sessions...");
            sessionManager.close();
        }
        
        if (databaseManager != null) {
            getLogger().info("Fermeture de la base de données...");
            databaseManager.close();
        }
        
        getLogger().info("Plugin 2FA désactivé!");
    }
} 