use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use crate::crypto::{
    decrypt_text, parse_public_key_hex, verify_ed25519_signature, UserIdentity,
};
use crate::error::{AppError, Result};

const MAX_PACKET_SIZE: usize = 100 * 1024 * 1024; // 100 Mo max (support fichiers/images chiffrés)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPacket {
    pub sender_ed_pubkey: String,
    pub sender_x_pubkey: String,
    pub recipient_ed_pubkey: String,
    pub payload_base64: String,
    pub timestamp_ms: u64,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedMessageDto {
    pub id: String,
    pub sender_id: String,
    pub sender_pubkey: String,
    pub text: String,
    pub plaintext: String,
    pub timestamp_ms: u64,
    pub timestamp: u64,
    pub time: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatusDto {
    pub is_listening: bool,
    pub local_port: u16,
    pub local_addr: String,
    pub address: String,
    pub lan_ip: String,
    pub connected_peers: usize,
}

pub struct NetworkTransport {
    local_port: Arc<AtomicU16>,
    is_listening: Arc<AtomicBool>,
}

impl Default for NetworkTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTransport {
    pub fn new() -> Self {
        Self {
            local_port: Arc::new(AtomicU16::new(0)),
            is_listening: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn start_listener(
        &self,
        requested_port: u16,
        identity_lock: Arc<RwLock<Option<UserIdentity>>>,
        app_handle: AppHandle,
    ) -> Result<u16> {
        // Liaison sur 0.0.0.0 pour écouter sur toutes les interfaces réseau (LAN, VPN, WAN)
        let bind_addr = format!("0.0.0.0:{}", requested_port);
        let listener = TcpListener::bind(&bind_addr)
            .await
            .map_err(|e| AppError::Network(format!("Liaison du port {} impossible : {}", requested_port, e)))?;

        let actual_port = listener
            .local_addr()
            .map_err(|e| AppError::Network(format!("Obtention de l'adresse locale impossible : {}", e)))?
            .port();

        self.local_port.store(actual_port, Ordering::SeqCst);
        self.is_listening.store(true, Ordering::SeqCst);

        let is_listening_flag = self.is_listening.clone();

        tokio::spawn(async move {
            while is_listening_flag.load(Ordering::SeqCst) {
                match listener.accept().await {
                    Ok((mut socket, _)) => {
                        let ident_clone = identity_lock.clone();
                        let app_clone = app_handle.clone();

                        tokio::spawn(async move {
                            if let Err(err) = Self::handle_incoming_connection(&mut socket, ident_clone, app_clone).await {
                                eprintln!("[Undercover v0.1 P2P] Erreur traitement paquet entrant : {}", err);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[Undercover v0.1 P2P] Erreur acceptation connexion TCP : {}", e);
                    }
                }
            }
        });

        Ok(actual_port)
    }

    async fn handle_incoming_connection(
        socket: &mut TcpStream,
        identity_lock: Arc<RwLock<Option<UserIdentity>>>,
        app_handle: AppHandle,
    ) -> Result<()> {
        let packet = Self::read_packet(socket).await?;

        // 1. Vérification stricte de la signature Ed25519 de l'expéditeur
        let sender_ed_bytes = parse_public_key_hex(&packet.sender_ed_pubkey)?;
        let signed_content = format!(
            "{}:{}:{}",
            packet.recipient_ed_pubkey, packet.payload_base64, packet.timestamp_ms
        );

        verify_ed25519_signature(&sender_ed_bytes, signed_content.as_bytes(), &packet.signature_hex)?;

        // 2. Déchiffrement Diffie-Hellman (X25519 + AES-256-GCM)
        let sender_x_bytes = parse_public_key_hex(&packet.sender_x_pubkey)?;

        let decrypted_text = {
            let lock = identity_lock.read().await;
            let identity = lock.as_ref().ok_or_else(|| {
                AppError::Crypto("Identité locale non configurée.".to_string())
            })?;

            let shared_secret = identity.compute_shared_secret(&sender_x_bytes);
            decrypt_text(&shared_secret, &packet.payload_base64)?
        };

        // 3. Formatage horodatage
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(packet.timestamp_ms);

        let seconds_today = (now_ms / 1000) % 86400;
        let hours = (seconds_today / 3600 + 1) % 24;
        let minutes = (seconds_today % 3600) / 60;
        let time_str = format!("{:02}:{:02}", hours, minutes);

        let msg_id = format!("p2p_{}", now_ms);
        let sender_hex = hex::encode(sender_ed_bytes);
        let message_dto = DecryptedMessageDto {
            id: msg_id,
            sender_id: sender_hex.clone(),
            sender_pubkey: format!("ed25519:{}", sender_hex),
            text: decrypted_text.clone(),
            plaintext: decrypted_text,
            timestamp_ms: packet.timestamp_ms,
            timestamp: packet.timestamp_ms,
            time: time_str,
            verified: true,
        };

        // 4. Émission de l'événement Tauri en direct vers React
        let _ = app_handle.emit("p2p-message-received", &message_dto);

        // Acquittement
        let _ = socket.write_all(b"OK\n").await;
        Ok(())
    }

    pub async fn send_packet_to_peer(
        target_addr: &str,
        packet: &EncryptedPacket,
    ) -> Result<()> {
        let mut stream = TcpStream::connect(target_addr)
            .await
            .map_err(|e| AppError::Network(format!("Connexion au pair '{}' impossible : {}", target_addr, e)))?;

        Self::write_packet(&mut stream, packet).await?;

        let mut ack = [0u8; 3];
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(4), stream.read(&mut ack)).await;

        Ok(())
    }

    async fn write_packet(socket: &mut TcpStream, packet: &EncryptedPacket) -> Result<()> {
        let json_bytes = serde_json::to_vec(packet)?;
        let len = json_bytes.len() as u32;

        socket
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| AppError::Network(format!("Erreur écriture longueur : {}", e)))?;

        socket
            .write_all(&json_bytes)
            .await
            .map_err(|e| AppError::Network(format!("Erreur écriture corps paquet : {}", e)))?;

        socket
            .flush()
            .await
            .map_err(|e| AppError::Network(format!("Erreur flush socket : {}", e)))?;

        Ok(())
    }

    async fn read_packet(socket: &mut TcpStream) -> Result<EncryptedPacket> {
        let mut len_bytes = [0u8; 4];
        socket
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| AppError::Network(format!("Erreur lecture en-tête longueur : {}", e)))?;

        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > MAX_PACKET_SIZE {
            return Err(AppError::Network(format!(
                "Taille paquet excessive ({} octets)",
                len
            )));
        }

        let mut buffer = vec![0u8; len];
        socket
            .read_exact(&mut buffer)
            .await
            .map_err(|e| AppError::Network(format!("Erreur lecture corps paquet : {}", e)))?;

        let packet: EncryptedPacket = serde_json::from_slice(&buffer)?;
        Ok(packet)
    }

    pub fn get_status(&self) -> NetworkStatusDto {
        let port = self.local_port.load(Ordering::SeqCst);
        let is_listening = self.is_listening.load(Ordering::SeqCst);
        let lan_ip = Self::detect_lan_ip();
        let addr = format!("{}:{}", lan_ip, port);
        NetworkStatusDto {
            is_listening,
            local_port: port,
            local_addr: addr.clone(),
            address: addr,
            lan_ip,
            connected_peers: if is_listening { 1 } else { 0 },
        }
    }

    /// Détecte l'adresse IP de l'interface réseau locale utilisée pour la sortie.
    fn detect_lan_ip() -> String {
        std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|socket| {
                socket.connect("8.8.8.8:80")?;
                socket.local_addr()
            })
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|_| "127.0.0.1".to_string())
    }
}
