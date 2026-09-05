//! Tauri adapter for the shared certificate probe.

pub use sitecmd_runtime::ssl_probe::SslProbeResult;

#[tauri::command]
pub async fn check_ssl(url: String) -> Result<SslProbeResult, String> {
    sitecmd_runtime::ssl_probe::check_ssl(url).await
}
