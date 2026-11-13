<html>
<body>
<!--StartFragment--><!-- obsidian --><h1 data-heading="Undercover v0.1-dev — Messagerie P2P Chiffrée (Windows Desktop)">Undercover v0.01-dev — Messagerie P2P Chiffrée (Windows Desktop)</h1>
<p>Application desktop Windows autonome (Tauri v2 + Rust natif + React 18) axée sur la confidentialité absolue : aucun compte, aucun identifiant personnel (pas d'e-mail, pas de numéro de téléphone), chiffrement de bout en bout (E2EE) et transport TCP direct.</p>

### Cryptographie & Sécurité Windows (Rust)
* **Identité locale & Signatures Ed25519** : Basé sur `ed25519-dalek 2.x` avec empreinte SHA-256 tronquée.
* **Échange Diffie-Hellman X25519 birationnel** : Conversion automatique des clés de vérification Edwards vers Montgomery (`to_montgomery()`) garantissant la dérivation d'un secret partagé identique pour Alice et Bob sans nécessiter d'échange de clés tiers.
* **Chiffrement Authentifié Symétrique AES-256-GCM** : Nonce aléatoire unique 96-bit par paquet et intégrité vérifiée.
* **Coffre-fort Windows DPAPI (`keyring`)** : La graine secrète est scellée dans le **Windows Credential Manager** natif, protégée par le trousseau de clés matériel de la session utilisateur.
* **Transport P2P Asynchrone Tokio** : Serveur d'écoute TCP local avec framing binaire, acquittement TCP et émission d'événements Tauri temps réel (`p2p-message-received`).

---

## 🛠️ Commandes Tauri IPC Exposées

| Commande IPC | Paramètres | Description |
| :--- | :--- | :--- |
| `get_or_create_identity` | - | Charge ou génère l'identité cryptographique scellée dans le coffre Windows DPAPI |
| `start_p2p_listener` | `port: Option<u16>` | Démarre le serveur TCP P2P local et retourne le statut réseau |
| `get_p2p_status` | - | Renvoie l'adresse locale, le port et l'état d'écoute du nœud |
| `send_p2p_message` | `peer_public_key_hex`, `plaintext`, `ip_address`, `port` | Chiffre en AES-256-GCM, signe en Ed25519 et expédie le paquet au pair |
| `encrypt_message` | `peer_pubkey`, `text` | Dérive le secret Diffie-Hellman et chiffre un message texte |
| `decrypt_message` | `cipher_text`, `peer_pubkey` | Déchiffre un message AES-256-GCM |
| `add_contact` | `public_key_hex`, `alias`, `ip_address`, `port` | Valide la clé Ed25519 et persiste le contact dans `%APPDATA%/Undercover_v01/contacts.json` |
| `delete_contact` | `key_or_id` | Supprime définitivement un contact localement |
| `get_contacts` | - | Retourne la liste complète des contacts enregistrés |
| `update_contact_addr` | `public_key_hex`, `ip_address`, `port` | Met à jour l'IP ou le port d'un pair existant |

---

## 💻 Démarrage & Compilation

Dans un terminal PowerShell :

```powershell
# 1. Se positionner dans le dossier
cd "C:\Users\[name]\Desktop\Undercover.app\undercover.v0.1-dev"

# 2. Lancer en mode bureau Windows (Développement)
npm.cmd run dev

# 3. Compiler l'exécutable Windows autonome (.exe)
npm.cmd run build
```

Ou exécutez dans :
`undercover.v0.1-dev/src-tauri/target/release/undercover-desktop.exe`