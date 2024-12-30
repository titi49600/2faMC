package com.security.minecraft2fa.utils;

import com.google.gson.JsonObject;
import lombok.RequiredArgsConstructor;

import javax.net.ssl.HttpsURLConnection;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

@RequiredArgsConstructor
public class DiscordWebhook {
    private final String url;

    public void sendAlert(String username, String ip, int failedCode) {
        try {
            JsonObject json = new JsonObject();
            json.addProperty("username", "Minecraft 2FA Security");
            json.addProperty("avatar_url", "https://www.minecraft.net/etc.clientlibs/minecraft/clientlibs/main/resources/img/GrassBlock_HighRes.png");

            JsonObject embed = new JsonObject();
            embed.addProperty("title", "⚠️ Échec d'authentification 2FA");
            embed.addProperty("color", 15158332); // Rouge
            embed.addProperty("timestamp", Instant.now().toString());

            StringBuilder description = new StringBuilder();
            description.append("**Joueur:** ").append(username).append("\n");
            description.append("**IP:** ||").append(ip).append("||\n");
            description.append("**Code invalide:** ||").append(failedCode).append("||\n");
            embed.addProperty("description", description.toString());

            JsonObject footer = new JsonObject();
            footer.addProperty("text", "Minecraft 2FA Security System");
            embed.add("footer", footer);

            json.add("embeds", new com.google.gson.JsonArray());
            json.getAsJsonArray("embeds").add(embed);

            // Envoi de la requête
            URL webhookUrl = new URL(url);
            HttpsURLConnection connection = (HttpsURLConnection) webhookUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            try (OutputStream os = connection.getOutputStream()) {
                os.write(json.toString().getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Vérification de la réponse
            int responseCode = connection.getResponseCode();
            if (responseCode != 204) {
                throw new RuntimeException("Échec de l'envoi du webhook Discord (Code " + responseCode + ")");
            }

            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}