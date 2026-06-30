//! Hot Cheese menu-bar app — a thin Tauri front-end over the `hot_cheese` core (`ui_api`).
//!
//! Commands that can block (Touch ID / Secure Enclave / rsync) run on a blocking thread so
//! the WebView UI never freezes. Errors are stringified at this boundary for the frontend.
use hot_cheese::ui_api::{self, Status};
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager};

/// Run a blocking core operation off the UI thread, mapping its error to a string.
async fn run_blocking<T, F>(f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ui_api::UiErr> + Send + 'static,
{
    match tauri::async_runtime::spawn_blocking(f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("{e:?}")),
        Err(e) => Err(format!("background task failed: {e}")),
    }
}

#[tauri::command]
fn status() -> Status {
    ui_api::status()
}

#[tauri::command]
async fn generate_key(
    chain: String,
    name: String,
    passphrase: Option<String>,
) -> Result<(), String> {
    run_blocking(move || ui_api::generate(&chain, &name, passphrase)).await
}

#[tauri::command]
async fn key_address(
    chain: String,
    name: String,
    passphrase: Option<String>,
) -> Result<String, String> {
    run_blocking(move || ui_api::address(&chain, &name, passphrase)).await
}

#[tauri::command]
async fn enroll_passphrase(
    new_passphrase: String,
    existing_passphrase: Option<String>,
) -> Result<(), String> {
    run_blocking(move || ui_api::enroll_passphrase(new_passphrase, existing_passphrase)).await
}

#[tauri::command]
async fn enroll_secure_enclave(existing_passphrase: Option<String>) -> Result<(), String> {
    run_blocking(move || ui_api::enroll_secure_enclave(existing_passphrase)).await
}

#[tauri::command]
async fn backup_push() -> Result<(), String> {
    run_blocking(ui_api::backup_push).await
}

#[tauri::command]
async fn backup_pull() -> Result<(), String> {
    run_blocking(ui_api::backup_pull).await
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            // Menu-bar tray: left-click opens the menu; "Open" shows the dashboard window.
            let show = MenuItemBuilder::with_id("show", "Open Hot Cheese").build(app)?;
            let quit = MenuItemBuilder::with_id("quit", "Quit Hot Cheese").build(app)?;
            let menu = MenuBuilder::new(app).items(&[&show, &quit]).build()?;
            let _tray = TrayIconBuilder::new()
                .icon(
                    app.default_window_icon()
                        .cloned()
                        .ok_or("no default window icon configured")?,
                )
                .tooltip("Hot Cheese")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => show_main(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            generate_key,
            key_address,
            enroll_passphrase,
            enroll_secure_enclave,
            backup_push,
            backup_pull
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
