use keyring::Entry;

use crate::error::{AppError, Result};

const VAULT_SERVICE_NAME: &str = "Undercover_Secure_Messenger_v01";
const VAULT_ACCOUNT_KEY: &str = "DeviceIdentitySeed";

pub struct WindowsVault {
    service: String,
    account: String,
}

impl Default for WindowsVault {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsVault {
    pub fn new() -> Self {
        Self {
            service: VAULT_SERVICE_NAME.to_string(),
            account: VAULT_ACCOUNT_KEY.to_string(),
        }
    }

    pub fn store_identity_seed(&self, secret_hex: &str) -> Result<()> {
        let entry = Entry::new(&self.service, &self.account)
            .map_err(|e| AppError::Vault(format!("Accès Windows Credential Manager impossible : {}", e)))?;

        entry
            .set_password(secret_hex)
            .map_err(|e| AppError::Vault(format!("Écriture sécurisée DPAPI échouée : {}", e)))?;

        Ok(())
    }

    pub fn load_identity_seed(&self) -> Result<Option<String>> {
        let entry = Entry::new(&self.service, &self.account)
            .map_err(|e| AppError::Vault(format!("Accès Windows Credential Manager impossible : {}", e)))?;

        match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(AppError::Vault(format!("Lecture du Credential Manager Windows échouée : {}", e))),
        }
    }

    pub fn clear_identity_seed(&self) -> Result<()> {
        let entry = Entry::new(&self.service, &self.account)
            .map_err(|e| AppError::Vault(format!("Accès Windows Credential Manager impossible : {}", e)))?;

        match entry.delete_credential() {
            Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(AppError::Vault(format!("Suppression de la clé dans le coffre échouée : {}", e))),
        }
    }
}
