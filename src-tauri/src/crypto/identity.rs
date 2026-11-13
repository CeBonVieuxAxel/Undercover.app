use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::error::{AppError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityDto {
    pub device_name: String,
    #[serde(default)]
    pub user_id: String,
    pub ed25519_pubkey_hex: String,
    #[serde(default)]
    pub public_key_hex: String,
    pub ed25519_pubkey_b58: String,
    pub x25519_pubkey_hex: String,
    #[serde(default)]
    pub x25519_public_key_hex: String,
    pub fingerprint: String,
}

#[derive(Clone)]
pub struct UserIdentity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub x25519_secret: StaticSecret,
    pub x25519_public: X25519PublicKey,
}

impl UserIdentity {
    fn derive_x25519_from_seed(seed: &[u8; 32]) -> (StaticSecret, X25519PublicKey) {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        let hash = hasher.finalize();

        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&hash[0..32]);
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;

        let x25519_secret = StaticSecret::from(scalar_bytes);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        (x25519_secret, x25519_public)
    }

    pub fn generate_new() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let (x25519_secret, x25519_public) = Self::derive_x25519_from_seed(&signing_key.to_bytes());

        Self {
            signing_key,
            verifying_key,
            x25519_secret,
            x25519_public,
        }
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();

        let (x25519_secret, x25519_public) = Self::derive_x25519_from_seed(bytes);

        Self {
            signing_key,
            verifying_key,
            x25519_secret,
            x25519_public,
        }
    }

    pub fn export_secret_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    pub fn sign_message(&self, message: &[u8]) -> String {
        let signature = self.signing_key.sign(message);
        hex::encode(signature.to_bytes())
    }

    pub fn to_dto(&self, device_name: &str) -> IdentityDto {
        let ed_pub_bytes = self.verifying_key.to_bytes();
        let x_pub_bytes = self.x25519_public.to_bytes();

        let ed25519_pubkey_hex = hex::encode(ed_pub_bytes);
        let ed25519_pubkey_b58 = bs58::encode(ed_pub_bytes).into_string();
        let x25519_pubkey_hex = hex::encode(x_pub_bytes);

        let mut hasher = Sha256::new();
        hasher.update(ed_pub_bytes);
        let digest = hasher.finalize();
        let hex_hash = hex::encode(digest);
        let fingerprint = format!(
            "SHA256:{}:{}:{}:{}:{}",
            &hex_hash[0..4],
            &hex_hash[4..8],
            &hex_hash[8..12],
            &hex_hash[12..16],
            &hex_hash[16..20]
        );

        let user_id = format!("UC-{}", &hex_hash[0..8].to_uppercase());

        IdentityDto {
            device_name: device_name.to_string(),
            user_id,
            ed25519_pubkey_hex: ed25519_pubkey_hex.clone(),
            public_key_hex: ed25519_pubkey_hex,
            ed25519_pubkey_b58,
            x25519_pubkey_hex: x25519_pubkey_hex.clone(),
            x25519_public_key_hex: x25519_pubkey_hex,
            fingerprint,
        }
    }

    /// Calcule le secret partagé Diffie-Hellman à partir de la clé publique Ed25519 ou X25519 du pair.
    /// Si une clé Ed25519 est fournie, elle est convertie en Montgomery X25519 de manière birationnelle.
    pub fn compute_shared_secret(&self, peer_pubkey: &[u8; 32]) -> [u8; 32] {
        let montgomery_bytes = match VerifyingKey::from_bytes(peer_pubkey) {
            Ok(vk) => vk.to_montgomery().to_bytes(),
            Err(_) => *peer_pubkey,
        };
        let peer_pub = X25519PublicKey::from(montgomery_bytes);
        let shared = self.x25519_secret.diffie_hellman(&peer_pub);
        *shared.as_bytes()
    }
}

pub fn verify_ed25519_signature(
    ed_pubkey_bytes: &[u8; 32],
    message: &[u8],
    signature_hex: &str,
) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(ed_pubkey_bytes)
        .map_err(|e| AppError::InvalidKey(format!("Clé publique Ed25519 invalide : {}", e)))?;

    let sig_bytes = hex::decode(signature_hex.trim())
        .map_err(|e| AppError::InvalidKey(format!("Format hexadécimal de signature invalide : {}", e)))?;

    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| AppError::Crypto(format!("Signature altérée ou malformée : {}", e)))?;

    verifying_key
        .verify(message, &signature)
        .map_err(|e| AppError::Crypto(format!("Signature Ed25519 invalide : {}", e)))?;

    Ok(())
}

pub fn parse_public_key_hex(hex_str: &str) -> Result<[u8; 32]> {
    let clean = hex_str.trim().trim_start_matches("0x").trim_start_matches("ed25519:").trim_start_matches("x25519:");
    let bytes = hex::decode(clean)
        .map_err(|e| AppError::InvalidKey(format!("Encodage hexadécimal invalide : {}", e)))?;

    if bytes.len() != 32 {
        return Err(AppError::InvalidKey(format!(
            "Longueur de clé invalide (attendu 32 octets, reçu {})",
            bytes.len()
        )));
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diffie_hellman_with_ed25519_keys() {
        let alice = UserIdentity::generate_new();
        let bob = UserIdentity::generate_new();

        let alice_ed_bytes = alice.verifying_key.to_bytes();
        let bob_ed_bytes = bob.verifying_key.to_bytes();

        let secret_alice = alice.compute_shared_secret(&bob_ed_bytes);
        let secret_bob = bob.compute_shared_secret(&alice_ed_bytes);

        assert_eq!(secret_alice, secret_bob, "Diffie-Hellman secrets must match!");
    }
}
