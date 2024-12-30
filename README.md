# Plugin Minecraft 2FA

Un plugin de sécurité Minecraft ajoutant une authentification à deux facteurs (2FA) pour les utilisateurs avec des permissions sensibles.

## Fonctionnalités

- Intégration avec Google Authenticator
- Configuration flexible des permissions nécessitant le 2FA
- Gestion des sessions d'authentification
- Interface administrative complète
- Support SQLite et MySQL
- Protection contre les tentatives de force brute
- Codes de secours pour la récupération

## Prérequis

- Serveur Minecraft 1.17 - 1.21
- Java 17 ou supérieur
- Vault
- LuckPerms

## Installation

1. Téléchargez la dernière version du plugin
2. Placez le fichier .jar dans le dossier `plugins` de votre serveur
3. Redémarrez votre serveur
4. Le plugin créera automatiquement sa configuration dans `plugins/Minecraft2FA/`

## Configuration

Le fichier `config.yml` permet de personnaliser :
- Les permissions nécessitant le 2FA
- La durée des sessions
- Les messages
- La configuration de la base de données
- Les paramètres de sécurité

## Commandes

### Commandes Utilisateur
- `/2fa setup` - Configure l'authentification à deux facteurs
- `/2fa verify <code>` - Vérifie un code 2FA
- `/2fa disable` - Désactive l'authentification à deux facteurs
- `/2fa status` - Affiche le statut de votre 2FA

### Commandes Admin
- `/2fa-admin force-reset <joueur>` - Réinitialise le 2FA d'un joueur
- `/2fa-admin check <joueur>` - Vérifie le statut 2FA d'un joueur
- `/2fa-admin list` - Liste les joueurs avec 2FA activé

## Permissions

- `minecraft2fa.use` - Permet d'utiliser les commandes de base
- `minecraft2fa.admin` - Permet d'utiliser les commandes administratives

## Support

Pour toute question ou problème :
1. Vérifiez la configuration
2. Consultez les logs du serveur
3. Contactez le support

## Développement

Pour compiler le plugin :
```bash
mvn clean package
```

Le fichier JAR sera généré dans le dossier `target/`.