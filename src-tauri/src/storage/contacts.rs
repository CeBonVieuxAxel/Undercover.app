use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::crypto::parse_public_key_hex;
use crate::error::{AppError, Result};

/// DTO envoyé au frontend React via Tauri IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactDto {
    /// Identifiant court (8 premiers chars hex)
    pub id: String,
    /// Alias lisible (fourni par l'utilisateur ou dérivé de la clé)
    pub alias: String,
    /// Nom (alias pour alias)
    pub name: String,
    /// Clé publique Ed25519 complète (hex)
    pub public_key_hex: String,
    /// Clé complète avec préfixe pour compatibilité
    pub full_key: String,
    /// Clé tronquée pour compatibilité
    pub key: String,
    /// Affichage tronqué pour l'UI
    pub key_display: String,
    /// Adresse IP pour la connexion directe P2P
    pub ip_address: Option<String>,
    /// Port TCP P2P
    pub port: Option<u16>,
    /// Statut réseau
    pub status: String,
    /// En ligne
    pub online: bool,
    /// Dernier message aperçu
    pub last_msg: String,
    /// Heure du dernier message
    pub time: String,
    /// Timestamp d'ajout (ms unix)
    pub added_at: u64,
}

impl ContactDto {
    /// Construit l'adresse `IP:port` si disponible, sinon None.
    pub fn peer_addr(&self) -> Option<String> {
        match (&self.ip_address, self.port) {
            (Some(ip), Some(port)) => Some(format!("{}:{}", ip, port)),
            _ => None,
        }
    }
}

/// Clé du fichier JSON sur disque : adresse hex complète de la clé publique.
type HexKey = String;

pub struct ContactStore {
    contacts: RwLock<HashMap<HexKey, ContactDto>>,
    storage_path: Option<PathBuf>,
}

impl Default for ContactStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ContactStore {
    pub fn new() -> Self {
        let app_data = std::env::var("APPDATA").ok().map(PathBuf::from);
        let storage_path = app_data.map(|p| p.join("Undercover_v01").join("contacts.json"));

        let store = Self {
            contacts: RwLock::new(HashMap::new()),
            storage_path,
        };

        // Chargement silencieux — pas d'erreur fatale si le fichier n'existe pas
        let _ = store.load_from_disk();
        store
    }

    /// Ajoute ou met à jour un contact.
    pub fn add_contact(
        &self,
        raw_pubkey: &str,
        alias: Option<String>,
        ip_address: Option<String>,
        port: Option<u16>,
    ) -> Result<ContactDto> {
        // Valide la clé publique Ed25519
        let raw_bytes = parse_public_key_hex(raw_pubkey)?;
        let full_key_hex = hex::encode(raw_bytes);

        // Affichage tronqué style "A9F2...8C1D"
        let key_display = format!(
            "{}…{}",
            full_key_hex[..6].to_uppercase(),
            full_key_hex[full_key_hex.len() - 6..].to_uppercase()
        );

        let id = format!("c_{}", &full_key_hex[..8]);
        let alias = alias.unwrap_or_else(|| format!("Nœud {}", &key_display));

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Nettoyage de l'IP (retire espaces et guillemets accidentels)
        let ip_clean = ip_address
            .map(|s| s.trim().trim_matches('"').to_string())
            .filter(|s| !s.is_empty());

        let contact = ContactDto {
            id,
            alias: alias.clone(),
            name: alias,
            public_key_hex: full_key_hex.clone(),
            full_key: format!("ed25519:{}", full_key_hex),
            key: key_display.clone(),
            key_display,
            ip_address: ip_clean,
            port,
            status: "P2P direct".to_string(),
            online: true,
            last_msg: "Canal chiffré établi.".to_string(),
            time: "À l'instant".to_string(),
            added_at: now_ms,
        };

        {
            let mut lock = self
                .contacts
                .write()
                .map_err(|_| AppError::Storage("Verrou ContactStore corrompu".to_string()))?;
            lock.insert(full_key_hex, contact.clone());
        }

        self.save_to_disk()?;
        Ok(contact)
    }

    /// Retourne tous les contacts.
    pub fn list_contacts(&self) -> Result<Vec<ContactDto>> {
        let lock = self
            .contacts
            .read()
            .map_err(|_| AppError::Storage("Verrou lecture contacts corrompu".to_string()))?;
        Ok(lock.values().cloned().collect())
    }

    /// Retourne un contact par sa clé publique hex (complète).
    pub fn get_by_pubkey(&self, pubkey_hex: &str) -> Result<Option<ContactDto>> {
        let lock = self
            .contacts
            .read()
            .map_err(|_| AppError::Storage("Verrou lecture contact corrompu".to_string()))?;
        Ok(lock.get(pubkey_hex).cloned())
    }

    /// Supprime un contact par sa clé publique ou son identifiant.
    pub fn remove_contact(&self, key_or_id: &str) -> Result<bool> {
        let mut lock = self
            .contacts
            .write()
            .map_err(|_| AppError::Storage("Verrou écriture contacts corrompu".to_string()))?;

        let key_to_remove = if lock.contains_key(key_or_id) {
            Some(key_or_id.to_string())
        } else {
            lock.iter()
                .find(|(_, c)| c.id == key_or_id || c.public_key_hex == key_or_id || c.full_key == key_or_id)
                .map(|(k, _)| k.clone())
        };

        if let Some(k) = key_to_remove {
            lock.remove(&k);
            drop(lock);
            self.save_to_disk()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Mise à jour de l'adresse réseau d'un contact existant.
    pub fn update_peer_addr(
        &self,
        pubkey_hex: &str,
        ip_address: Option<String>,
        port: Option<u16>,
    ) -> Result<()> {
        let mut lock = self
            .contacts
            .write()
            .map_err(|_| AppError::Storage("Verrou écriture contact corrompu".to_string()))?;
        if let Some(contact) = lock.get_mut(pubkey_hex) {
            contact.ip_address = ip_address;
            contact.port = port;
        }
        drop(lock);
        self.save_to_disk()
    }

    // ─── Persistance ────────────────────────────────────────────

    fn save_to_disk(&self) -> Result<()> {
        if let Some(ref path) = self.storage_path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let lock = self
                .contacts
                .read()
                .map_err(|_| AppError::Storage("Verrou écriture contacts corrompu".to_string()))?;
            let data = serde_json::to_vec_pretty(&*lock)?;
            let mut file = File::create(path)?;
            file.write_all(&data)?;
        }
        Ok(())
    }

    fn load_from_disk(&self) -> Result<()> {
        if let Some(ref path) = self.storage_path {
            if !path.exists() {
                return Ok(());
            }
            let content = fs::read_to_string(path)?;
            if let Ok(loaded) = serde_json::from_str::<HashMap<HexKey, ContactDto>>(&content) {
                let mut lock = self
                    .contacts
                    .write()
                    .map_err(|_| AppError::Storage("Verrou chargement contacts corrompu".to_string()))?;
                *lock = loaded;
            }
        }
        Ok(())
    }
}
