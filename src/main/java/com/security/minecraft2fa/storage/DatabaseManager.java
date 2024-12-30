package com.security.minecraft2fa.storage;

import com.security.minecraft2fa.Minecraft2FAPlugin;
import lombok.RequiredArgsConstructor;

import java.sql.*;
import java.util.UUID;

@RequiredArgsConstructor
public class DatabaseManager {

    private final Minecraft2FAPlugin plugin;
    private Connection connection;

    public void initialize() {
        plugin.getLogger().info("Initialisation du DatabaseManager...");
        
        // Force MySQL si Redis est activé (mode multi-serveur)
        boolean useRedis = plugin.getConfig().getBoolean("redis.enabled", false);
        String dbType = useRedis ? "mysql" : plugin.getConfig().getString("database.type", "sqlite");

        if (useRedis && !dbType.equals("mysql")) {
            plugin.getLogger().warning("Mode multi-serveur détecté - Forçage de l'utilisation de MySQL pour la synchronisation des données");
            dbType = "mysql";
        }

        try {
            if (dbType.equals("mysql")) {
                plugin.getLogger().info("Configuration de la connexion MySQL...");
                String host = plugin.getConfig().getString("database.mysql.host", "localhost");
                int port = plugin.getConfig().getInt("database.mysql.port", 3306);
                String database = plugin.getConfig().getString("database.mysql.database", "minecraft2fa");
                String username = plugin.getConfig().getString("database.mysql.username", "root");
                String password = plugin.getConfig().getString("database.mysql.password", "");
                boolean ssl = plugin.getConfig().getBoolean("database.mysql.ssl", false);

                plugin.getLogger().info("Paramètres MySQL: host=" + host + ", port=" + port + 
                    ", database=" + database + ", username=" + username + ", ssl=" + ssl);

                String url = String.format("jdbc:mysql://%s:%d/%s?useSSL=%b&allowPublicKeyRetrieval=true" +
                    "&useUnicode=true&characterEncoding=utf8" +
                    "&connectTimeout=5000" +
                    "&socketTimeout=30000" +
                    "&autoReconnect=true" +
                    "&serverTimezone=UTC" +
                    "&useLocalSessionState=true" +
                    "&tcpKeepAlive=true" +
                    "&useHostsInPrivileges=false", 
                    host, port, database, ssl);

                plugin.getLogger().info("URL de connexion MySQL: " + url);
                plugin.getLogger().info("Tentative de connexion MySQL...");
                
                connection = DriverManager.getConnection(url, username, password);
                plugin.getLogger().info("Connexion MySQL établie avec succès!");
                
            } else {
                plugin.getLogger().info("Utilisation de SQLite en mode standalone");
                Class.forName("org.sqlite.JDBC");
                String dbPath = plugin.getDataFolder().getAbsolutePath() + "/database.db";
                plugin.getLogger().info("Chemin de la base SQLite: " + dbPath);
                connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
                plugin.getLogger().info("Connexion SQLite établie avec succès!");
            }
            
            // Création de la table pour stocker les secrets 2FA
            plugin.getLogger().info("Création/vérification de la table two_factor_auth...");
            try (Statement stmt = connection.createStatement()) {
                stmt.execute("""
                    CREATE TABLE IF NOT EXISTS two_factor_auth (
                        uuid VARCHAR(36) PRIMARY KEY,
                        secret_key VARCHAR(32) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """);
                plugin.getLogger().info("Table two_factor_auth prête!");
            }
        } catch (Exception e) {
            plugin.getLogger().severe("Erreur lors de l'initialisation de la base de données: " + e.getMessage());
            plugin.getLogger().severe("Stack trace: " + e.toString());
            // En cas d'erreur avec MySQL en mode multi-serveur, on désactive le plugin
            if (useRedis) {
                plugin.getLogger().severe("ERREUR CRITIQUE: Impossible de se connecter à MySQL en mode multi-serveur!");
                plugin.getLogger().severe("Le plugin sera désactivé pour éviter les problèmes de sécurité.");
                plugin.getServer().getPluginManager().disablePlugin(plugin);
            }
        }
    }

    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                plugin.getLogger().info("Fermeture de la connexion à la base de données...");
                connection.close();
                plugin.getLogger().info("Connexion fermée avec succès!");
            }
        } catch (SQLException e) {
            plugin.getLogger().severe("Erreur lors de la fermeture de la base de données: " + e.getMessage());
            plugin.getLogger().severe("Stack trace: " + e.toString());
        }
    }

    public String getSecretKey(UUID uuid) {
        try (PreparedStatement stmt = connection.prepareStatement(
                "SELECT secret_key FROM two_factor_auth WHERE uuid = ?")) {
            stmt.setString(1, uuid.toString());
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                String key = rs.getString("secret_key");
                plugin.getLogger().info("Clé secrète récupérée pour " + uuid);
                return key;
            } else {
                plugin.getLogger().info("Aucune clé secrète trouvée pour " + uuid);
            }
        } catch (SQLException e) {
            plugin.getLogger().severe("Erreur lors de la récupération de la clé secrète: " + e.getMessage());
            plugin.getLogger().severe("Stack trace: " + e.toString());
        }
        return null;
    }

    public void setSecretKey(UUID uuid, String secretKey) {
        try (PreparedStatement stmt = connection.prepareStatement(
                "INSERT INTO two_factor_auth (uuid, secret_key) VALUES (?, ?) " +
                "ON DUPLICATE KEY UPDATE secret_key = ?")) {
            stmt.setString(1, uuid.toString());
            stmt.setString(2, secretKey);
            stmt.setString(3, secretKey);
            stmt.executeUpdate();
            plugin.getLogger().info("Clé secrète enregistrée pour " + uuid);
        } catch (SQLException e) {
            plugin.getLogger().severe("Erreur lors de l'enregistrement de la clé secrète: " + e.getMessage());
            plugin.getLogger().severe("Stack trace: " + e.toString());
        }
    }

    public void removeSecretKey(UUID uuid) {
        try (PreparedStatement stmt = connection.prepareStatement(
                "DELETE FROM two_factor_auth WHERE uuid = ?")) {
            stmt.setString(1, uuid.toString());
            stmt.executeUpdate();
            plugin.getLogger().info("Clé secrète supprimée pour " + uuid);
        } catch (SQLException e) {
            plugin.getLogger().severe("Erreur lors de la suppression de la clé secrète: " + e.getMessage());
            plugin.getLogger().severe("Stack trace: " + e.toString());
        }
    }
} 