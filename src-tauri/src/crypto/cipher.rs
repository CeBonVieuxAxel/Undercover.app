use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::RngCore;

use crate::error::{AppError, Result};

const NONCE_SIZE: usize = 12; // 96 bits pour AES-256-GCM

pub fn encrypt_aes_gcm(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AppError::Crypto(format!("Échec du chiffrement AES-256-GCM : {:?}", e)))?;

    let mut payload = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(payload))
}

pub fn decrypt_aes_gcm(key_bytes: &[u8; 32], encoded_payload: &str) -> Result<Vec<u8>> {
    let payload = BASE64
        .decode(encoded_payload.trim())
        .map_err(|e| AppError::Crypto(format!("Décodage Base64 échoué : {}", e)))?;

    if payload.len() < NONCE_SIZE + 16 {
        return Err(AppError::Crypto(
            "Taille de paquet chiffré invalide (inférieure à 28 octets)".to_string(),
        ));
    }

    let (nonce_slice, ciphertext_slice) = payload.split_at(NONCE_SIZE);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_slice);

    let decrypted = cipher
        .decrypt(nonce, ciphertext_slice)
        .map_err(|e| AppError::Crypto(format!("Échec du déchiffrement AES-GCM (clé incorrecte ou paquet altéré) : {:?}", e)))?;

    Ok(decrypted)
}

pub fn encrypt_text(key_bytes: &[u8; 32], text: &str) -> Result<String> {
    encrypt_aes_gcm(key_bytes, text.as_bytes())
}

pub fn decrypt_text(key_bytes: &[u8; 32], encoded_payload: &str) -> Result<String> {
    let bytes = decrypt_aes_gcm(key_bytes, encoded_payload)?;
    String::from_utf8(bytes)
        .map_err(|e| AppError::Crypto(format!("Message déchiffré non UTF-8 : {}", e)))
}
