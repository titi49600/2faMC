package com.security.minecraft2fa.listeners;

import com.security.minecraft2fa.Minecraft2FAPlugin;
import lombok.RequiredArgsConstructor;
import net.luckperms.api.LuckPerms;
import net.luckperms.api.event.EventBus;
import net.luckperms.api.event.node.NodeAddEvent;
import net.luckperms.api.event.node.NodeRemoveEvent;
import net.luckperms.api.model.user.User;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.*;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.entity.EntityDropItemEvent;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@RequiredArgsConstructor
public class PlayerListener implements Listener {
    
    private final Minecraft2FAPlugin plugin;
    private final Set<String> allowedCommands = new HashSet<>(Arrays.asList(
        "/2fa", "/2fa verify", "/2fa status", "/login", "/register"
    ));
    
    public void registerLuckPermsEvents() {
        try {
            LuckPerms luckPerms = Bukkit.getServicesManager().getRegistration(LuckPerms.class).getProvider();
            EventBus eventBus = luckPerms.getEventBus();
            
            // Écoute l'ajout de permissions
            eventBus.subscribe(plugin, NodeAddEvent.class, event -> {
                if (event.getTarget() instanceof User) {
                    UUID uuid = ((User) event.getTarget()).getUniqueId();
                    Player player = Bukkit.getPlayer(uuid);
                    if (player != null) {
                        Bukkit.getScheduler().runTask(plugin, () -> checkPermissionsAndAuthenticate(player));
                    }
                }
            });
            
            // Écoute la suppression de permissions
            eventBus.subscribe(plugin, NodeRemoveEvent.class, event -> {
                if (event.getTarget() instanceof User) {
                    UUID uuid = ((User) event.getTarget()).getUniqueId();
                    Player player = Bukkit.getPlayer(uuid);
                    if (player != null) {
                        Bukkit.getScheduler().runTask(plugin, () -> checkPermissionsAndAuthenticate(player));
                    }
                }
            });
            
            plugin.getLogger().info("Écouteurs LuckPerms enregistrés avec succès!");
        } catch (Exception e) {
            plugin.getLogger().severe("Erreur lors de l'enregistrement des écouteurs LuckPerms: " + e.getMessage());
        }
    }
    
    private void checkPermissionsAndAuthenticate(Player player) {
        if (requiresAuth(player) && !plugin.getAuthManager().isAuthenticated(player)) {
            // Force le joueur à s'authentifier
            player.teleport(player.getLocation()); // Empêche le mouvement
            sendAuthMessage(player);
        }
    }
    
    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        checkPermissionsAndAuthenticate(player);
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerQuit(PlayerQuitEvent event) {
        // Nettoie la session si le joueur se déconnecte
        plugin.getAuthManager().logout(event.getPlayer());
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerMove(PlayerMoveEvent event) {
        // Annule uniquement les changements de bloc (permet la rotation)
        if (event.getTo() != null && (
            event.getFrom().getBlockX() == event.getTo().getBlockX() 
            && event.getFrom().getBlockY() == event.getTo().getBlockY()
            && event.getFrom().getBlockZ() == event.getTo().getBlockZ())) {
            return;
        }
        
        if (needsAuth(event.getPlayer())) {
            event.setTo(event.getFrom());
            sendAuthMessage(event.getPlayer());
        }
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onBlockBreak(BlockBreakEvent event) {
        if (needsAuth(event.getPlayer())) {
            event.setCancelled(true);
            sendAuthMessage(event.getPlayer());
        }
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onBlockPlace(BlockPlaceEvent event) {
        if (needsAuth(event.getPlayer())) {
            event.setCancelled(true);
            sendAuthMessage(event.getPlayer());
        }
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onInventoryClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player player && needsAuth(player)) {
            event.setCancelled(true);
            sendAuthMessage(player);
        }
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onInventoryOpen(InventoryOpenEvent event) {
        if (event.getPlayer() instanceof Player player && needsAuth(player)) {
            event.setCancelled(true);
            sendAuthMessage(player);
        }
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onItemDrop(EntityDropItemEvent event) {
        if (event.getEntity() instanceof Player player && needsAuth(player)) {
            event.setCancelled(true);
            sendAuthMessage(player);
        }
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onItemPickup(EntityPickupItemEvent event) {
        if (event.getEntity() instanceof Player player && needsAuth(player)) {
            event.setCancelled(true);
            sendAuthMessage(player);
        }
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerInteract(PlayerInteractEvent event) {
        if (needsAuth(event.getPlayer())) {
            event.setCancelled(true);
            sendAuthMessage(event.getPlayer());
        }
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        if (!needsAuth(event.getPlayer())) {
            return;
        }
        
        String command = event.getMessage().toLowerCase().split(" ")[0];
        if (!allowedCommands.contains(command)) {
            event.setCancelled(true);
            sendAuthMessage(event.getPlayer());
        }
    }
    
    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerChat(AsyncPlayerChatEvent event) {
        if (needsAuth(event.getPlayer())) {
            event.setCancelled(true);
            sendAuthMessage(event.getPlayer());
        }
    }
    
    /**
     * Envoie le message d'authentification approprié au joueur
     */
    private void sendAuthMessage(Player player) {
        if (!plugin.getAuthManager().has2FAEnabled(player)) {
            player.sendMessage(plugin.getConfig().getString("messages.setup-required", 
                "§cVous devez configurer l'authentification à deux facteurs!"));
        } else {
            player.sendMessage(plugin.getConfig().getString("messages.auth-required", 
                "§cVeuillez vous authentifier avec /2fa verify <code>"));
        }
    }
    
    /**
     * Vérifie si le joueur a besoin de s'authentifier
     */
    private boolean needsAuth(Player player) {
        return requiresAuth(player) 
            && !plugin.getAuthManager().isAuthenticated(player);
    }
    
    /**
     * Vérifie si le joueur a des permissions nécessitant le 2FA
     */
    private boolean requiresAuth(Player player) {
        List<String> sensitivePermissions = plugin.getConfig().getStringList("sensitive-permissions");
        for (String permission : sensitivePermissions) {
            if (player.hasPermission(permission)) {
                plugin.getLogger().info("Le joueur " + player.getName() + " a la permission sensible: " + permission);
                return true;
            }
        }
        return false;
    }
}