package com.security.minecraft2fa.storage;

import com.security.minecraft2fa.Minecraft2FAPlugin;
import lombok.RequiredArgsConstructor;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.exceptions.JedisConnectionException;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@RequiredArgsConstructor
public class SessionManager {
    private final Minecraft2FAPlugin plugin;
    private JedisPool jedisPool;
    private boolean useRedis;
    private boolean redisAvailable = false;
    
    // Cache local des sessions avec timestamp de dernière vérification
    private final Map<UUID, CachedSession> sessionCache = new ConcurrentHashMap<>();
    private static final long CACHE_DURATION = 3600000; // 1 heure en millisecondes
    
    private static class CachedSession {
        String ip;
        long lastCheck;
        
        CachedSession(String ip) {
            this.ip = ip;
            this.lastCheck = System.currentTimeMillis();
        }
    }

    public void initialize() {
        plugin.getLogger().info("Initialisation du SessionManager...");
        useRedis = plugin.getConfig().getBoolean("redis.enabled", false);
        
        if (!useRedis) {
            plugin.getLogger().info("Redis est désactivé dans la configuration - Mode standalone activé");
            return;
        }

        plugin.getLogger().info("Redis est activé dans la configuration - Tentative de connexion...");
        String host = plugin.getConfig().getString("redis.host", "localhost");
        int port = plugin.getConfig().getInt("redis.port", 6379);
        String password = plugin.getConfig().getString("redis.password", "");
        
        plugin.getLogger().info("Configuration Redis: host=" + host + ", port=" + port + ", password=" + (password.isEmpty() ? "non" : "oui"));
        
        JedisPoolConfig poolConfig = new JedisPoolConfig();
        poolConfig.setMaxTotal(8);
        poolConfig.setMaxIdle(8);
        poolConfig.setMinIdle(0);
        poolConfig.setTestOnBorrow(true);
        poolConfig.setTestOnReturn(true);
        poolConfig.setTestWhileIdle(true);
        poolConfig.setMinEvictableIdleTimeMillis(60000);
        poolConfig.setTimeBetweenEvictionRunsMillis(30000);
        poolConfig.setNumTestsPerEvictionRun(3);
        poolConfig.setBlockWhenExhausted(true);

        try {
            plugin.getLogger().info("Création du pool de connexions Redis...");
            if (password.isEmpty()) {
                jedisPool = new JedisPool(poolConfig, host, port, 2000);
            } else {
                jedisPool = new JedisPool(poolConfig, host, port, 2000, password);
            }
            
            // Test de la connexion
            plugin.getLogger().info("Test de la connexion Redis...");
            try (Jedis jedis = jedisPool.getResource()) {
                String response = jedis.ping();
                redisAvailable = true;
                plugin.getLogger().info("Connexion Redis établie avec succès! (réponse: " + response + ")");
                plugin.getLogger().info("Les sessions seront partagées entre les serveurs");
                
                // Test d'écriture/lecture
                String testKey = "2fa:test:connection";
                jedis.set(testKey, "test");
                String testValue = jedis.get(testKey);
                jedis.del(testKey);
                plugin.getLogger().info("Test d'écriture/lecture Redis réussi!");
            }
        } catch (Exception e) {
            plugin.getLogger().severe("Erreur lors de la connexion à Redis: " + e.getMessage());
            plugin.getLogger().severe("Stack trace: " + e.toString());
            plugin.getLogger().warning("Le plugin fonctionnera en mode standalone jusqu'à ce que Redis soit disponible");
            if (jedisPool != null) {
                plugin.getLogger().info("Fermeture du pool Redis...");
                jedisPool.close();
                jedisPool = null;
            }
        }
    }

    public void close() {
        if (jedisPool != null) {
            jedisPool.close();
        }
        sessionCache.clear();
    }

    public void setSession(UUID uuid, String ip) {
        // Met à jour le cache local
        sessionCache.put(uuid, new CachedSession(ip));
        
        // Si Redis n'est pas utilisé ou pas disponible, on s'arrête là
        if (!useRedis || !redisAvailable) {
            return;
        }

        try (Jedis jedis = jedisPool.getResource()) {
            String key = "2fa:session:" + uuid.toString();
            jedis.set(key, ip);
            int expiry = plugin.getConfig().getInt("redis.session-expiry", 43200);
            jedis.expire(key, expiry);
        } catch (JedisConnectionException e) {
            redisAvailable = false;
            plugin.getLogger().severe("Erreur de connexion Redis - Passage en mode local: " + e.getMessage());
            tryReconnect();
        } catch (Exception e) {
            plugin.getLogger().severe("Erreur lors de l'enregistrement de la session Redis: " + e.getMessage());
        }
    }

    public String getSession(UUID uuid) {
        // Vérifie d'abord le cache local
        CachedSession cached = sessionCache.get(uuid);
        if (cached != null) {
            long now = System.currentTimeMillis();
            // Si le cache est encore valide, retourne l'IP directement
            if (now - cached.lastCheck < CACHE_DURATION) {
                return cached.ip;
            }
        }
        
        // Si pas dans le cache ou cache expiré, vérifie Redis
        if (useRedis && redisAvailable) {
            try (Jedis jedis = jedisPool.getResource()) {
                String key = "2fa:session:" + uuid.toString();
                String ip = jedis.get(key);
                if (ip != null) {
                    // Rafraîchit l'expiration Redis et met à jour le cache local
                    int expiry = plugin.getConfig().getInt("redis.session-expiry", 43200);
                    jedis.expire(key, expiry);
                    sessionCache.put(uuid, new CachedSession(ip));
                    return ip;
                } else {
                    // Si pas de session dans Redis, supprime du cache local
                    sessionCache.remove(uuid);
                    return null;
                }
            } catch (JedisConnectionException e) {
                redisAvailable = false;
                plugin.getLogger().severe("Erreur de connexion Redis - Utilisation du cache local: " + e.getMessage());
                tryReconnect();
            } catch (Exception e) {
                plugin.getLogger().severe("Erreur lors de la récupération de la session Redis: " + e.getMessage());
            }
        }
        
        // En cas d'erreur ou si Redis est désactivé, utilise le cache local
        return cached != null ? cached.ip : null;
    }

    public void removeSession(UUID uuid) {
        // Supprime du cache local
        sessionCache.remove(uuid);
        
        // Si Redis n'est pas utilisé ou pas disponible, on s'arrête là
        if (!useRedis || !redisAvailable) {
            return;
        }

        try (Jedis jedis = jedisPool.getResource()) {
            // Supprime directement la clé de session (plus rapide que keys + del)
            String sessionKey = "2fa:session:" + uuid.toString();
            long result = jedis.del(sessionKey);
            if (result > 0) {
                plugin.getLogger().info("Session Redis supprimée pour " + uuid);
            }
        } catch (JedisConnectionException e) {
            redisAvailable = false;
            plugin.getLogger().severe("Erreur de connexion Redis lors de la suppression de session: " + e.getMessage());
            tryReconnect();
        } catch (Exception e) {
            plugin.getLogger().severe("Erreur lors de la suppression de la session Redis: " + e.getMessage());
        }
    }

    public boolean isUsingRedis() {
        return useRedis && redisAvailable;
    }
    
    public void tryReconnect() {
        if (useRedis && !redisAvailable && jedisPool != null) {
            try (Jedis jedis = jedisPool.getResource()) {
                String response = jedis.ping();
                redisAvailable = true;
            } catch (Exception e) {
                plugin.getLogger().warning("Échec de la tentative de reconnexion à Redis: " + e.getMessage());
            }
        }
    }
} 