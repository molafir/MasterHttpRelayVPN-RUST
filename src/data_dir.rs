use std::path::{Path, PathBuf};

const APP_NAME: &str = "mhrv-rs";

/// Returns the platform-appropriate user-data directory for this app, creating
/// it if necessary. Falls back to the current directory if the dir can't be
/// determined (rare).
///
/// - macOS:   `~/Library/Application Support/mhrv-rs`
/// - Linux:   `~/.config/mhrv-rs` (or `$XDG_CONFIG_HOME/mhrv-rs`)
/// - Windows: `%APPDATA%\mhrv-rs`
pub fn data_dir() -> PathBuf {
    let dir = directories::ProjectDirs::from("", "", APP_NAME)
        .map(|d| d.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Path to the config.json for this platform's data dir.
pub fn config_path() -> PathBuf {
    data_dir().join("config.json")
}

/// Path to the CA cert inside the data dir (the MITM CA).
pub fn ca_cert_path() -> PathBuf {
    data_dir().join("ca").join("ca.crt")
}

/// Path to the CA private key inside the data dir.
pub fn ca_key_path() -> PathBuf {
    data_dir().join("ca").join("ca.key")
}

/// Resolve a config path: if the user supplied an explicit path, use it.
/// Otherwise look in the user-data dir first, fall back to `./config.json`
/// in the current working directory (for backward compatibility with the
/// original CLI behavior).
pub fn resolve_config_path(cli_arg: Option<&Path>) -> PathBuf {
    if let Some(p) = cli_arg {
        return p.to_path_buf();
    }
    let user = config_path();
    if user.exists() {
        return user;
    }
    let cwd = PathBuf::from("config.json");
    if cwd.exists() {
        return cwd;
    }
    // Neither exists: return the user-data path so errors point to the
    // blessed location and commands like "Save config" write there.
    user
}
