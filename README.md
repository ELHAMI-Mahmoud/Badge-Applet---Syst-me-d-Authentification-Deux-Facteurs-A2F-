# Badge Applet - Système d'Authentification à Deux Facteurs (A2F)

Système d'authentification sécurisé basé sur JavaCard utilisant un badge intelligent avec authentification à deux facteurs (PIN + clé cryptographique).

##  Fonctionnalités

- **Authentification à deux facteurs (A2F)**
  - Facteur 1 : Code PIN (4-8 chiffres)
  - Facteur 2 : Clé cryptographique AES-128
- **Chiffrement AES-128-CBC** pour le stockage sécurisé des clés
- **Protection contre les attaques**
  - Limitation des tentatives de PIN (3 essais)
  - Blocage automatique après échecs
- **Gestion de sessions** avec timeout
- **Journalisation** de tous les événements d'accès

##  Architecture

### Applet JavaCard
- Stockage sécurisé du PIN et de l'ID utilisateur
- Chiffrement/déchiffrement AES des clés privées
- Gestion des tentatives et blocage

### Client Java
- Interface utilisateur en ligne de commande
- Génération de clés cryptographiques
- Gestion des sessions utilisateur
- Journalisation des accès

##  Prérequis

- Java JDK 11+
- JavaCard Development Kit 3.0.5+
- Simulateur de carte à puce (jCardSim ou autre)
- `socketprovider.jar` pour la communication avec le simulateur

## 🚀 Installation

### 1. Cloner le dépôt
```bash
git clone https://github.com/ELHAMI-Mahmoud/Badge-Applet---Syst-me-d-Authentification-Deux-Facteurs-A2F-.git
cd badge-applet-2fa
```

### 2. Compiler l'applet
```bash
cd applet
# Utiliser votre outil de build JavaCard
# Exemple avec ant :
ant build
```

### 3. Compiler le client
```bash
cd ../client
javac -cp "lib/*" src/com/ensias/badge/a2f/client/BadgeAppletClient.java -d build/
```

##  Utilisation

### 1. Démarrer le simulateur
Lancez votre simulateur de carte à puce sur le port 9025.

### 2. Charger l'applet
Chargez `BadgeApplet.cap` dans le simulateur avec l'AID : `20 20 20 20 20`

### 3. Exécuter le client
```bash
cd client
java -cp "build:lib/*" com.ensias.badge.a2f.client.BadgeAppletClient
```

##  Guide d'utilisation

### Initialisation du badge
1. Sélectionner "Initialiser badge"
2. Entrer un ID utilisateur (max 16 caractères)
3. Définir un PIN (4-8 chiffres)
4. Le système génère automatiquement une clé cryptographique

### Authentification
1. Sélectionner "S'authentifier"
2. Entrer le PIN
3. Le système vérifie automatiquement la clé cryptographique
4. Si succès : accès accordé avec création de session

### Déblocage
En cas de blocage après 3 tentatives incorrectes, utiliser l'option "Débloquer PIN".

##  Sécurité

- **Dérivation de clé** : Le PIN est utilisé pour dériver une clé AES via un algorithme personnalisé
- **Chiffrement** : Toutes les clés sont stockées chiffrées avec AES-128-CBC
- **IV aléatoire** : Génération d'un vecteur d'initialisation unique pour chaque chiffrement
- **Limitation des tentatives** : Blocage après 3 échecs de PIN
- **Journalisation** : Tous les événements sont enregistrés avec horodatage

##  Instructions APDU

| Instruction | INS  | Description |
|-------------|------|-------------|
| SET_PIN     | 0x10 | Définir le PIN et l'ID utilisateur |
| VERIFY_PIN  | 0x20 | Vérifier le PIN |
| STORE_KEY   | 0x30 | Stocker la clé chiffrée |
| GET_KEY     | 0x40 | Récupérer la clé déchiffrée |
| RESET_TRIES | 0x50 | Réinitialiser les tentatives PIN |
| GET_USER_ID | 0x60 | Obtenir l'ID utilisateur |

## ️ Technologies utilisées

- **JavaCard 3.0.5** - Plateforme pour cartes à puce
- **Java SE 11+** - Client application
- **AES-128-CBC** - Chiffrement symétrique
- **SmartCardIO** - Communication avec la carte

##  Fichiers générés

- `badge_logs.txt` : Historique complet des événements d'accès

##  Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer des améliorations
- Soumettre des pull requests



##  Auteurs

- Mahmoud EL HAMI - ENSIAS
- Adam MRANI - ENSIAS

##  Remerciements

- ENSIAS pour le cadre académique
- La communauté JavaCard
