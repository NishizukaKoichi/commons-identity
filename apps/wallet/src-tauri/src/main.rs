use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeInfo {
    mode: &'static str,
    protocol: &'static str,
    app_version: &'static str,
    seeded_data: bool,
    secret_persistence: &'static str,
    core_connected: bool,
}

#[tauri::command]
fn runtime_info() -> RuntimeInfo {
    RuntimeInfo {
        mode: "desktop-prototype",
        protocol: "commons-identity/1",
        app_version: env!("CARGO_PKG_VERSION"),
        seeded_data: true,
        secret_persistence: "none",
        core_connected: false,
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![runtime_info])
        .run(tauri::generate_context!())
        .expect("failed to run Commons Wallet");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_discloses_prototype_safety_state() {
        let info = runtime_info();
        assert_eq!(info.protocol, "commons-identity/1");
        assert_eq!(info.secret_persistence, "none");
        assert!(!info.core_connected);
    }
}
