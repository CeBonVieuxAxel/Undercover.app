use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, State};

use crate::crypto::{
    decrypt_text, encrypt_text, parse_public_key_hex, IdentityDto, UserIdentity,
};
use crate::error::AppError;
use crate::network::{DecryptedMessageDto, EncryptedPacket, NetworkStatusDto, NetworkTransport};
use crate::storage::{ContactDto, ContactStore, WindowsVault};

// ─── État partagé de l'application ───────────────────────────────────────────

pub struct AppState {
    pub identity: Arc<tokio::sync::RwLock<Option<UserIdentity>>>,
    pub vault: WindowsVault,
    pub contacts: ContactStore,
    pub transport: NetworkTransport,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            identity: Arc::new(tokio::sync::RwLock::new(None)),
            vault: WindowsVault::new(),
            contacts: ContactStore::new(),
            transport: NetworkTransport::new(),
        }
    }
}

// ─── Helpers internes ─────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn ms_to_time_str(ts_ms: u64) -> String {
    let seconds_today = (ts_ms / 1000) % 86400;
    let h = seconds_today / 3600;
    let m = (seconds_today % 3600) / 60;
    format!("{:02}:{:02}", h, m)
}

// ─── Commandes IPC ────────────────────────────────────────────────────────────

/// Charge (ou génère) l'identité cryptographique locale.
/// Clé privée stockée dans le Windows Credential Manager (DPAPI).
#[tauri::command]
pub async fn get_or_create_identity(
    state: State<'_, Arc<AppState>>,
) -> Result<IdentityDto, AppError> {
    let mut lock = state.identity.write().await;

    if let Some(ref ident) = *lock {
        return Ok(ident.to_dto("Nœud P2P Undercover (Windows)"));
    }

    let maybe_seed = state.vault.load_identity_seed()?;

    let identity = match maybe_seed {
        Some(seed_hex) => {
            let bytes = hex::decode(&seed_hex)
                .map_err(|e| AppError::Vault(format!("Graine corrompue dans le coffre : {}", e)))?;
            if bytes.len() != 32 {
                return Err(AppError::Vault("Graine invalide (≠ 32 octets)".to_string()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            UserIdentity::from_secret_bytes(&arr)
        }
        None => {
            let ident = UserIdentity::generate_new();
            state.vault.store_identity_seed(&ident.export_secret_hex())?;
            ident
        }
    };

    let dto = identity.to_dto("Nœud P2P Undercover (Windows)");
    *lock = Some(identity);
    Ok(dto)
}

/// Démarre le serveur TCP P2P et retourne le statut effectif.
#[tauri::command(rename_all = "snake_case")]
pub async fn start_p2p_listener(
    port: Option<u16>,
    state: State<'_, Arc<AppState>>,
    app_handle: AppHandle,
) -> Result<NetworkStatusDto, AppError> {
    let req_port = port.unwrap_or(0);
    let _ = state
        .transport
        .start_listener(req_port, state.identity.clone(), app_handle)
        .await?;
    Ok(state.transport.get_status())
}

/// Retourne le statut du listener P2P (port, is_listening, pairs).
#[tauri::command(rename_all = "snake_case")]
pub async fn get_p2p_status(
    state: State<'_, Arc<AppState>>,
) -> Result<NetworkStatusDto, AppError> {
    Ok(state.transport.get_status())
}

/// Envoie un message chiffré (AES-256-GCM + signature Ed25519) à un pair.
#[tauri::command(rename_all = "snake_case")]
pub async fn send_p2p_message(
    peer_public_key_hex: String,
    plaintext: String,
    ip_address: Option<String>,
    port: Option<u16>,
    state: State<'_, Arc<AppState>>,
) -> Result<DecryptedMessageDto, AppError> {
    // 1. Résolution de l'adresse cible
    let target_addr = resolve_target_addr(
        &peer_public_key_hex,
        ip_address,
        port,
        &state.contacts,
    )?;

    // 2. Parse la clé publique du destinataire
    let recipient_ed_bytes = parse_public_key_hex(&peer_public_key_hex)?;

    // 3. Lecture de l'identité locale
    let lock = state.identity.read().await;
    let identity = lock.as_ref().ok_or_else(|| {
        AppError::Crypto("Identité locale non initialisée — appelez get_or_create_identity d'abord".to_string())
    })?;

    // 4. ECDH X25519 → secret partagé → AES-256-GCM
    let shared_secret = identity.compute_shared_secret(&recipient_ed_bytes);
    let payload_base64 = encrypt_text(&shared_secret, &plaintext)?;

    // 5. Signature Ed25519
    let ts = now_ms();
    let recipient_hex = hex::encode(recipient_ed_bytes);
    let signed_content = format!("{}:{}:{}", recipient_hex, payload_base64, ts);
    let signature_hex = identity.sign_message(signed_content.as_bytes());

    let packet = EncryptedPacket {
        sender_ed_pubkey: hex::encode(identity.verifying_key.to_bytes()),
        sender_x_pubkey: hex::encode(identity.x25519_public.to_bytes()),
        recipient_ed_pubkey: recipient_hex,
        payload_base64,
        timestamp_ms: ts,
        signature_hex,
    };

    // 6. Envoi TCP
    NetworkTransport::send_packet_to_peer(&target_addr, &packet).await?;

    let sender_hex = hex::encode(identity.verifying_key.to_bytes());
    Ok(DecryptedMessageDto {
        id: format!("sent_{}", ts),
        sender_id: sender_hex.clone(),
        sender_pubkey: format!("ed25519:{}", sender_hex),
        text: plaintext.clone(),
        plaintext,
        timestamp_ms: ts,
        timestamp: ts,
        time: ms_to_time_str(ts),
        verified: true,
    })
}

/// Chiffre un texte avec la clé partagée dérivée via ECDH (X25519).
#[tauri::command(rename_all = "snake_case")]
pub async fn encrypt_message(
    peer_pubkey: Option<String>,
    peer_public_key_hex: Option<String>,
    text: Option<String>,
    plaintext: Option<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<String, AppError> {
    let pk = peer_pubkey.or(peer_public_key_hex).ok_or_else(|| {
        AppError::InvalidKey("Clé publique requise".to_string())
    })?;
    let content = text.or(plaintext).unwrap_or_default();
    let peer_bytes = parse_public_key_hex(&pk)?;
    let lock = state.identity.read().await;
    let identity = lock.as_ref().ok_or_else(|| {
        AppError::Crypto("Identité locale non initialisée".to_string())
    })?;
    let shared_secret = identity.compute_shared_secret(&peer_bytes);
    encrypt_text(&shared_secret, &content)
}

/// Déchiffre un texte chiffré avec AES-256-GCM.
#[tauri::command(rename_all = "snake_case")]
pub async fn decrypt_message(
    cipher_text: String,
    peer_pubkey: Option<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<String, AppError> {
    let lock = state.identity.read().await;
    let identity = lock.as_ref().ok_or_else(|| {
        AppError::Crypto("Identité locale non initialisée".to_string())
    })?;

    let key = match peer_pubkey {
        Some(ref pk) => {
            let bytes = parse_public_key_hex(pk)?;
            identity.compute_shared_secret(&bytes)
        }
        None => identity.signing_key.to_bytes(),
    };

    decrypt_text(&key, &cipher_text)
}

/// Ajoute un contact avec sa clé publique, alias, IP et port P2P.
#[tauri::command(rename_all = "snake_case")]
pub async fn add_contact(
    public_key_hex: Option<String>,
    pubkey: Option<String>,
    alias: Option<String>,
    ip_address: Option<String>,
    port: Option<u16>,
    state: State<'_, Arc<AppState>>,
) -> Result<ContactDto, AppError> {
    let key = public_key_hex.or(pubkey).ok_or_else(|| {
        AppError::InvalidKey("Clé publique Ed25519 requise".to_string())
    })?;
    state.contacts.add_contact(&key, alias, ip_address, port)
}

/// Supprime un contact existant.
#[tauri::command(rename_all = "snake_case")]
pub async fn delete_contact(
    key_or_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<bool, AppError> {
    state.contacts.remove_contact(&key_or_id)
}

/// Retourne la liste complète des contacts.
#[tauri::command(rename_all = "snake_case")]
pub async fn get_contacts(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<ContactDto>, AppError> {
    state.contacts.list_contacts()
}

/// Met à jour l'adresse réseau d'un contact existant.
#[tauri::command(rename_all = "snake_case")]
pub async fn update_contact_addr(
    public_key_hex: String,
    ip_address: Option<String>,
    port: Option<u16>,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    state.contacts.update_peer_addr(&public_key_hex, ip_address, port)
}

// ─── Helper de résolution d'adresse ──────────────────────────────────────────

fn resolve_target_addr(
    pubkey_hex: &str,
    ip_address: Option<String>,
    port: Option<u16>,
    contacts: &ContactStore,
) -> Result<String, AppError> {
    // Priorité 1 : paramètres fournis directement
    if let (Some(ip), Some(p)) = (&ip_address, port) {
        let ip_clean = ip.trim().trim_matches('"');
        if !ip_clean.is_empty() {
            return Ok(format!("{}:{}", ip_clean, p));
        }
    }

    // Priorité 2 : lookup dans le ContactStore
    if let Some(contact) = contacts.get_by_pubkey(pubkey_hex)? {
        if let Some(addr) = contact.peer_addr() {
            return Ok(addr);
        }
        return Err(AppError::Network(format!(
            "Contact '{}' trouvé mais sans adresse IP/port configurée. Modifiez le contact.",
            contact.alias
        )));
    }

    Err(AppError::Network(format!(
        "Impossible de résoudre l'adresse pour la clé '{}' — contact introuvable et pas d'IP fournie.",
        &pubkey_hex[..8.min(pubkey_hex.len())]
    )))
}
