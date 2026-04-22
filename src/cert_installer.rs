use std::path::Path;
use std::process::Command;

use crate::mitm::CERT_NAME;

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("certificate file not found: {0}")]
    NotFound(String),
    #[error("install failed on this platform")]
    Failed,
    #[error("unsupported platform: {0}")]
    Unsupported(String),
}

/// Install the CA certificate at `path` into the system trust store.
/// Platform-specific — requires admin/sudo on most systems.
pub fn install_ca(path: &Path) -> Result<(), InstallError> {
    if !path.exists() {
        return Err(InstallError::NotFound(path.display().to_string()));
    }

    let path_s = path.to_string_lossy().to_string();

    let os = std::env::consts::OS;
    tracing::info!("Installing CA certificate on {}...", os);

    let ok = match os {
        "macos" => install_macos(&path_s),
        "linux" => install_linux(&path_s),
        "windows" => install_windows(&path_s),
        other => return Err(InstallError::Unsupported(other.to_string())),
    };

    // Best-effort: also install into NSS stores if `certutil` is available.
    // Both Firefox AND Chrome/Chromium on Linux maintain NSS databases that
    // are independent of the OS trust store — which is why running
    // update-ca-certificates alone wasn't enough for a lot of users
    // (issue #11 on Linux was this).
    install_nss_stores(&path_s);

    if ok {
        Ok(())
    } else {
        Err(InstallError::Failed)
    }
}

/// Heuristic check: is the CA already in the trust store?
/// Best-effort — on unknown state we return false to always attempt install.
pub fn is_ca_trusted(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    match std::env::consts::OS {
        "macos" => is_trusted_macos(),
        "linux" => is_trusted_linux(),
        "windows" => is_trusted_windows(),
        _ => false,
    }
}

// ---------- macOS ----------

fn install_macos(cert_path: &str) -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let login_kc_db = format!("{}/Library/Keychains/login.keychain-db", home);
    let login_kc = format!("{}/Library/Keychains/login.keychain", home);
    let login_keychain = if Path::new(&login_kc_db).exists() {
        login_kc_db
    } else {
        login_kc
    };

    // Try login keychain first (no sudo).
    let res = Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            &login_keychain,
            cert_path,
        ])
        .status();
    if let Ok(s) = res {
        if s.success() {
            tracing::info!("CA installed into login keychain.");
            return true;
        }
    }

    // Fall back to system keychain (needs sudo).
    tracing::warn!("login keychain install failed — trying system keychain (needs sudo).");
    let res = Command::new("sudo")
        .args([
            "security",
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
            cert_path,
        ])
        .status();
    if let Ok(s) = res {
        if s.success() {
            tracing::info!("CA installed into System keychain.");
            return true;
        }
    }
    tracing::error!("macOS install failed — run with sudo or install manually.");
    false
}

fn is_trusted_macos() -> bool {
    let out = Command::new("security")
        .args(["find-certificate", "-a", "-c", CERT_NAME])
        .output();
    match out {
        Ok(o) => !o.stdout.is_empty() && o.status.success(),
        Err(_) => false,
    }
}

// ---------- Linux ----------

fn install_linux(cert_path: &str) -> bool {
    let distro = detect_linux_distro();
    tracing::info!("Detected Linux distro family: {}", distro);
    let safe_name = CERT_NAME.replace(' ', "_");

    match distro.as_str() {
        "debian" => {
            let dest = format!("/usr/local/share/ca-certificates/{}.crt", safe_name);
            try_copy_and_run(cert_path, &dest, &[&["update-ca-certificates"]])
        }
        "rhel" => {
            let dest = format!("/etc/pki/ca-trust/source/anchors/{}.crt", safe_name);
            try_copy_and_run(cert_path, &dest, &[&["update-ca-trust", "extract"]])
        }
        "arch" => {
            let dest = format!("/etc/ca-certificates/trust-source/anchors/{}.crt", safe_name);
            try_copy_and_run(cert_path, &dest, &[&["trust", "extract-compat"]])
        }
        "openwrt" => {
            // OpenWRT itself doesn't open HTTPS connections through the proxy —
            // LAN clients do. The CA needs to be trusted on the CLIENTS, not on
            // the router. So this is a no-op success with guidance rather than
            // an error.
            tracing::info!(
                "OpenWRT detected: the router doesn't need to trust the MITM CA. \
                 Copy {} to each LAN client (browser / OS trust store) instead. \
                 Example: scp root@<router>:{} ./ and import from there.",
                cert_path, cert_path
            );
            true
        }
        _ => {
            tracing::warn!(
                "Unknown Linux distro — CA file is at {}. Copy it into your system's \
                 trust anchors dir (e.g. /usr/local/share/ca-certificates/ for \
                 Debian-like, /etc/pki/ca-trust/source/anchors/ for RHEL-like) and \
                 run the corresponding refresh command.",
                cert_path
            );
            false
        }
    }
}

fn try_copy_and_run(src: &str, dest: &str, cmds: &[&[&str]]) -> bool {
    // First try without sudo.
    let mut ok = true;
    if let Some(parent) = Path::new(dest).parent() {
        if std::fs::create_dir_all(parent).is_err() {
            ok = false;
        }
    }
    if ok && std::fs::copy(src, dest).is_err() {
        ok = false;
    }
    if ok {
        for cmd in cmds {
            if !run_cmd(cmd) {
                ok = false;
                break;
            }
        }
    }
    if ok {
        tracing::info!("CA installed via {}.", cmds[0].join(" "));
        return true;
    }

    // Retry with sudo.
    tracing::warn!("direct install failed — retrying with sudo.");
    if !run_cmd(&["sudo", "cp", src, dest]) {
        return false;
    }
    for cmd in cmds {
        let mut full: Vec<&str> = vec!["sudo"];
        full.extend_from_slice(cmd);
        if !run_cmd(&full) {
            return false;
        }
    }
    tracing::info!("CA installed via sudo.");
    true
}

fn run_cmd(args: &[&str]) -> bool {
    if args.is_empty() {
        return false;
    }
    let out = Command::new(args[0]).args(&args[1..]).status();
    matches!(out, Ok(s) if s.success())
}

fn detect_linux_distro() -> String {
    // Marker-file shortcuts (most reliable).
    if Path::new("/etc/openwrt_release").exists() {
        return "openwrt".into();
    }
    if Path::new("/etc/debian_version").exists() {
        return "debian".into();
    }
    if Path::new("/etc/redhat-release").exists() || Path::new("/etc/fedora-release").exists() {
        return "rhel".into();
    }
    if Path::new("/etc/arch-release").exists() {
        return "arch".into();
    }
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        return classify_os_release(&content);
    }
    "unknown".into()
}

/// Parse /etc/os-release content and return a distro family.
///
/// We specifically look at the `ID` and `ID_LIKE` fields (not a substring
/// search over the whole file) because random other fields like
/// `OPENWRT_DEVICE_ARCH=x86_64` contain substrings that false-positive on
/// "arch". Exposed for unit testing.
fn classify_os_release(content: &str) -> String {
    let mut id = String::new();
    let mut id_like = String::new();
    for line in content.lines() {
        let (k, v) = match line.split_once('=') {
            Some(x) => x,
            None => continue,
        };
        let v = v.trim().trim_matches('"').trim_matches('\'').to_ascii_lowercase();
        match k.trim() {
            "ID" => id = v,
            "ID_LIKE" => id_like = v,
            _ => {}
        }
    }
    let tokens: Vec<&str> = id
        .split(|c: char| c.is_whitespace() || c == ',')
        .chain(id_like.split(|c: char| c.is_whitespace() || c == ','))
        .filter(|t| !t.is_empty())
        .collect();
    let has = |needle: &str| tokens.iter().any(|t| *t == needle);
    if has("openwrt") {
        return "openwrt".into();
    }
    if has("debian") || has("ubuntu") || has("mint") || has("raspbian") {
        return "debian".into();
    }
    if has("fedora") || has("rhel") || has("centos") || has("rocky") || has("almalinux") {
        return "rhel".into();
    }
    if has("arch") || has("manjaro") || has("endeavouros") {
        return "arch".into();
    }
    "unknown".into()
}

fn is_trusted_linux() -> bool {
    let anchor_dirs = [
        "/usr/local/share/ca-certificates",
        "/etc/pki/ca-trust/source/anchors",
        "/etc/ca-certificates/trust-source/anchors",
    ];
    for d in anchor_dirs {
        if let Ok(entries) = std::fs::read_dir(d) {
            for e in entries.flatten() {
                let name = e.file_name();
                let s = name.to_string_lossy().to_lowercase();
                if s.contains("masterhttprelayvpn") || s.contains("mhrv") {
                    return true;
                }
            }
        }
    }
    false
}

// ---------- Windows ----------

/// Check whether our CA is present in the Windows Trusted Root store.
/// Looks in both the user store (no admin required to install) and the
/// machine store. Returns true if `certutil -store ... MasterHttpRelayVPN`
/// finds a match. Issue #13 follow-up: previously this always returned
/// false on Windows, so the Check-CA button was misleading users into
/// reinstalling a cert that was already trusted.
fn is_trusted_windows() -> bool {
    // `certutil -user -store Root <name>` prints the matching cert entries
    // on success (stdout), and exits with a non-zero code plus a "Not
    // found" message if nothing matches. We also check stdout for the
    // cert name because certutil in some locales returns 0 even on no-
    // match, just with empty output.
    for args in [
        vec!["-user", "-store", "Root", CERT_NAME],
        vec!["-store", "Root", CERT_NAME],
    ] {
        let out = Command::new("certutil").args(&args).output();
        if let Ok(o) = out {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if o.status.success() && stdout.to_ascii_lowercase().contains(&CERT_NAME.to_ascii_lowercase()) {
                return true;
            }
        }
    }
    false
}

fn install_windows(cert_path: &str) -> bool {
    // Per-user Root store (no admin required).
    let res = Command::new("certutil")
        .args(["-addstore", "-user", "Root", cert_path])
        .status();
    if let Ok(s) = res {
        if s.success() {
            tracing::info!("CA installed in Windows user Trusted Root store.");
            return true;
        }
    }
    // System store (admin).
    let res = Command::new("certutil")
        .args(["-addstore", "Root", cert_path])
        .status();
    if let Ok(s) = res {
        if s.success() {
            tracing::info!("CA installed in Windows system Trusted Root store.");
            return true;
        }
    }
    tracing::error!("Windows install failed — run as administrator or install manually.");
    false
}

// ---------- NSS (Firefox + Chrome/Chromium on Linux) ----------

/// Best-effort install of the CA into all discovered NSS stores:
///   1. Every Firefox profile (each has its own cert9.db).
///   2. On Linux, the shared Chrome/Chromium NSS DB at ~/.pki/nssdb —
///      this is the one update-ca-certificates does NOT populate, and
///      missing it was the real blocker for Chrome users who'd installed
///      the OS-level CA and still got cert errors (part of issue #11).
/// Silently no-ops if `certutil` (from libnss3-tools) isn't on PATH.
/// Browsers must be closed during install for changes to take effect.
fn install_nss_stores(cert_path: &str) {
    // First, try to make Firefox pick up the OS-level CA automatically by
    // flipping the `security.enterprise_roots.enabled` pref in user.js of
    // every Firefox profile we find. This is the cleanest cross-platform
    // fix because it doesn't depend on whether NSS certutil is installed
    // — Firefox just starts trusting whatever the OS trusts. Especially
    // important on Windows where NSS certutil isn't on PATH.
    enable_firefox_enterprise_roots();

    if !has_nss_certutil() {
        tracing::debug!(
            "NSS certutil not found — Firefox will still trust the CA via the \
             `security.enterprise_roots.enabled` user.js pref (flipped above). \
             For Chrome/Chromium on Linux, install `libnss3-tools` (Debian/Ubuntu) \
             or `nss-tools` (Fedora/RHEL), or import ca.crt manually via \
             chrome://settings/certificates → Authorities."
        );
        return;
    }

    let mut ok = 0;
    let mut tried = 0;

    // 1. Firefox profiles.
    for p in firefox_profile_dirs() {
        tried += 1;
        if install_nss_in_profile(&p, cert_path) {
            ok += 1;
        }
    }

    // 2. Chrome/Chromium shared NSS DB (Linux only).
    #[cfg(target_os = "linux")]
    {
        if let Some(nssdb) = chrome_nssdb_path() {
            // Ensure the DB exists. certutil -N creates an empty cert9.db in
            // the directory if none is there. An empty passphrase is fine
            // for a user-local DB.
            let dir_arg = format!("sql:{}", nssdb.display());
            if !nssdb.join("cert9.db").exists() && !nssdb.join("cert8.db").exists() {
                let _ = std::fs::create_dir_all(&nssdb);
                let _ = Command::new("certutil")
                    .args(["-N", "-d", &dir_arg, "--empty-password"])
                    .output();
            }
            tried += 1;
            if install_nss_in_dir(&dir_arg, cert_path) {
                ok += 1;
                tracing::info!(
                    "CA installed in Chrome/Chromium NSS DB: {}",
                    nssdb.display()
                );
            }
        }
    }

    if ok > 0 {
        tracing::info!("CA installed in {}/{} NSS store(s).", ok, tried);
    } else if tried > 0 {
        tracing::warn!(
            "NSS install: 0/{} stores updated. If Firefox/Chrome was running, close \
             them and retry. Otherwise, import ca.crt manually via browser settings.",
            tried
        );
    }
}

/// Write `user_pref("security.enterprise_roots.enabled", true);` to every
/// discovered Firefox profile's user.js. This makes Firefox trust the OS
/// trust store on next startup — so our already-successful system-level
/// CA install automatically propagates. Critical on Windows where Firefox
/// keeps its own NSS DB independent of Windows cert store, and NSS
/// certutil isn't typically installed so the certutil-based path doesn't
/// fire there.
///
/// Existing user.js entries for other prefs are preserved by appending
/// rather than truncating. Idempotent.
fn enable_firefox_enterprise_roots() {
    const PREF: &str = r#"user_pref("security.enterprise_roots.enabled", true);"#;
    let mut touched = 0;
    for profile in firefox_profile_dirs() {
        let user_js = profile.join("user.js");
        let existing = std::fs::read_to_string(&user_js).unwrap_or_default();
        if existing.contains("security.enterprise_roots.enabled") {
            // Already set by us or the user. Replace-or-keep: if they set it
            // to false we leave their choice alone. If it's already our line
            // verbatim, nothing to do.
            if existing.contains(PREF) {
                continue;
            }
            // Different value present — don't overwrite.
            tracing::debug!(
                "firefox profile {} already has a different enterprise_roots pref; leaving alone",
                profile.display()
            );
            continue;
        }
        let mut out = existing;
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(PREF);
        out.push('\n');
        if let Err(e) = std::fs::write(&user_js, out) {
            tracing::debug!(
                "firefox profile {}: user.js write failed: {}",
                profile.display(),
                e
            );
            continue;
        }
        touched += 1;
    }
    if touched > 0 {
        tracing::info!(
            "enabled Firefox enterprise_roots in {} profile(s) — restart Firefox for it to take effect",
            touched
        );
    }
}

fn has_nss_certutil() -> bool {
    Command::new("certutil")
        .arg("--help")
        .output()
        .ok()
        .map(|o| {
            // macOS has a different certutil built-in that doesn't support -d.
            // NSS-specific help output mentions the -d / -n flags.
            String::from_utf8_lossy(&o.stderr).contains("-d")
                || String::from_utf8_lossy(&o.stdout).contains("-d")
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn chrome_nssdb_path() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(std::path::PathBuf::from(format!("{}/.pki/nssdb", home)))
}

/// Install into a given sql: or legacy NSS DB path. Factored out so both
/// Firefox-per-profile and Chrome-shared paths share one code path.
fn install_nss_in_dir(dir_arg: &str, cert_path: &str) -> bool {
    // Delete any stale entry first (ignore errors).
    let _ = Command::new("certutil")
        .args(["-D", "-n", CERT_NAME, "-d", dir_arg])
        .output();

    let res = Command::new("certutil")
        .args([
            "-A",
            "-n",
            CERT_NAME,
            "-t",
            "C,,",
            "-d",
            dir_arg,
            "-i",
            cert_path,
        ])
        .output();
    match res {
        Ok(o) if o.status.success() => {
            tracing::debug!("NSS install ok: {}", dir_arg);
            true
        }
        Ok(o) => {
            tracing::debug!(
                "NSS install failed for {}: {}",
                dir_arg,
                String::from_utf8_lossy(&o.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::debug!("NSS certutil exec failed for {}: {}", dir_arg, e);
            false
        }
    }
}

fn install_nss_in_profile(profile: &Path, cert_path: &str) -> bool {
    let prefix = if profile.join("cert9.db").exists() {
        "sql:"
    } else if profile.join("cert8.db").exists() {
        ""
    } else {
        return false;
    };
    let dir_arg = format!("{}{}", prefix, profile.display());
    install_nss_in_dir(&dir_arg, cert_path)
}

fn firefox_profile_dirs() -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut roots: Vec<PathBuf> = Vec::new();
    let home = std::env::var("HOME").unwrap_or_default();
    match std::env::consts::OS {
        "macos" => {
            roots.push(PathBuf::from(format!(
                "{}/Library/Application Support/Firefox/Profiles",
                home
            )));
        }
        "linux" => {
            roots.push(PathBuf::from(format!("{}/.mozilla/firefox", home)));
            roots.push(PathBuf::from(format!(
                "{}/snap/firefox/common/.mozilla/firefox",
                home
            )));
        }
        "windows" => {
            if let Ok(appdata) = std::env::var("APPDATA") {
                roots.push(PathBuf::from(format!("{}\\Mozilla\\Firefox\\Profiles", appdata)));
            }
        }
        _ => {}
    }

    let mut out: Vec<PathBuf> = Vec::new();
    for root in &roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for ent in entries.flatten() {
            let p = ent.path();
            if !p.is_dir() {
                continue;
            }
            // A profile has cert9.db or cert8.db.
            if p.join("cert9.db").exists() || p.join("cert8.db").exists() {
                out.push(p);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openwrt_os_release_is_not_arch() {
        // Real OpenWRT 23.05 /etc/os-release. Contains OPENWRT_DEVICE_ARCH
        // which substring-matches "arch" — the old detector would mis-classify
        // this as Arch Linux. Regression guard for issue #2.
        let content = r#"
NAME="OpenWrt"
VERSION="23.05.3"
ID="openwrt"
ID_LIKE="lede openwrt"
PRETTY_NAME="OpenWrt 23.05.3"
VERSION_ID="23.05.3"
HOME_URL="https://openwrt.org/"
BUG_URL="https://bugs.openwrt.org/"
SUPPORT_URL="https://forum.openwrt.org/"
BUILD_ID="r23809-234f1a2efa"
OPENWRT_BOARD="x86/64"
OPENWRT_ARCH="x86_64"
OPENWRT_TAINTS=""
OPENWRT_DEVICE_MANUFACTURER="OpenWrt"
OPENWRT_DEVICE_MANUFACTURER_URL="https://openwrt.org/"
OPENWRT_DEVICE_PRODUCT="Generic"
OPENWRT_DEVICE_REVISION="v0"
OPENWRT_RELEASE="OpenWrt 23.05.3 r23809-234f1a2efa"
"#;
        assert_eq!(classify_os_release(content), "openwrt");
    }

    #[test]
    fn debian_bullseye_classified_as_debian() {
        let content = r#"
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian
"#;
        assert_eq!(classify_os_release(content), "debian");
    }

    #[test]
    fn ubuntu_classified_as_debian_via_id_like() {
        let content = r#"
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
"#;
        assert_eq!(classify_os_release(content), "debian");
    }

    #[test]
    fn fedora_classified_as_rhel() {
        let content = "ID=fedora\nVERSION_ID=39\n";
        assert_eq!(classify_os_release(content), "rhel");
    }

    #[test]
    fn arch_classified_as_arch() {
        let content = "ID=arch\nID_LIKE=\n";
        assert_eq!(classify_os_release(content), "arch");
    }

    #[test]
    fn manjaro_classified_as_arch() {
        let content = "ID=manjaro\nID_LIKE=arch\n";
        assert_eq!(classify_os_release(content), "arch");
    }

    #[test]
    fn empty_os_release_is_unknown() {
        assert_eq!(classify_os_release(""), "unknown");
    }

    #[test]
    fn random_file_with_arch_substring_does_not_match() {
        // Make sure we don't regress to the old substring-match bug.
        let content = "SOMEFIELD=maybearchived\nFOO=bar\n";
        assert_eq!(classify_os_release(content), "unknown");
    }
}
