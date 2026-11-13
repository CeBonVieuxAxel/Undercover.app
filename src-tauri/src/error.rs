use serde::Serialize;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Erreur cryptographique : {0}")]
    Crypto(String),

    #[error("Erreur clé publique/privée invalide : {0}")]
    InvalidKey(String),

    #[error("Erreur Windows Credential Manager DPAPI : {0}")]
    Vault(String),

    #[error("Erreur stockage local contacts : {0}")]
    Storage(String),

    #[error("Erreur transport réseau P2P : {0}")]
    Network(String),

    #[error("Erreur E/S système : {0}")]
    Io(#[from] std::io::Error),

    #[error("Erreur format JSON : {0}")]
    Serialization(#[from] serde_json::Error),
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
