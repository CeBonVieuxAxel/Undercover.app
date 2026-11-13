pub mod commands;
pub mod crypto;
pub mod error;
pub mod network;
pub mod storage;

use std::sync::Arc;
use commands::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_state = Arc::new(AppState::new());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::get_or_create_identity,
            commands::encrypt_message,
            commands::decrypt_message,
            commands::add_contact,
            commands::delete_contact,
            commands::get_contacts,
            commands::start_p2p_listener,
            commands::get_p2p_status,
            commands::send_p2p_message,
            commands::update_contact_addr,
        ])
        .run(tauri::generate_context!())
        .expect("Erreur lors du démarrage d'Undercover v0.1");
}
