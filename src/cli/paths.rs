use std::path::PathBuf;

use crate::cli::args::DaemonArgs;

#[allow(dead_code)]
pub fn environment_detection(args: &DaemonArgs) {
    let mut path = default_config_path(args);
    let error = if !path.exists() {
        std::fs::create_dir_all(&path).is_err()
    } else {
        path.push(".test");
        std::fs::File::create(&path).is_err()
    };

    if error {
        eprintln!("Cannot write to the default storage path: {:?}", path);
        eprintln!("Please run the program with sudo or specify a different path");
        std::process::exit(1);
    }
}

pub fn default_config_path(args: &DaemonArgs) -> PathBuf {
    if let Some(path) = &args.config {
        return path.clone();
    }

    let privileged_path = if cfg!(target_os = "windows") {
        PathBuf::from(r"C:\ProgramData\p2p-ddns")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/p2p-ddns")
    } else {
        PathBuf::from("/etc/p2p-ddns")
    };

    let normal_path = {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));

        if cfg!(target_os = "windows") {
            home.join("AppData").join("Local").join("p2p-ddns")
        } else if cfg!(target_os = "macos") {
            home.join("Library")
                .join("Application Support")
                .join("p2p-ddns")
        } else {
            home.join(".config").join("p2p-ddns")
        }
    };

    if args.daemon {
        let test_file = privileged_path.join("test");
        if test_file.exists() {
            match std::fs::remove_dir(&test_file) {
                Ok(_) => privileged_path,
                Err(_) => normal_path,
            }
        } else {
            match std::fs::create_dir_all(&test_file) {
                Ok(_) => {
                    std::fs::remove_dir(&test_file).ok();
                    privileged_path
                }
                Err(_) => normal_path,
            }
        }
    } else {
        normal_path
    }
}

/// Resolve the database file path.
///
/// - If `--config` points to a `.db` file, use it directly (backwards-compatible).
/// - Otherwise treat `--config` as a directory and use `<dir>/storage.db`.
pub fn storage_db_path(args: &DaemonArgs) -> PathBuf {
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| default_config_path(args));

    if config_path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("db"))
    {
        return config_path;
    }

    config_path.join("storage.db")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_db_path_accepts_db_file_config() {
        let mut args = DaemonArgs::default();
        args.config = Some(PathBuf::from("/tmp/p2p-ddns.db"));
        assert_eq!(storage_db_path(&args), PathBuf::from("/tmp/p2p-ddns.db"));
    }

    #[test]
    fn storage_db_path_uses_dir_config() {
        let mut args = DaemonArgs::default();
        args.config = Some(PathBuf::from("/tmp/p2p-ddns"));
        assert_eq!(
            storage_db_path(&args),
            PathBuf::from("/tmp/p2p-ddns").join("storage.db")
        );
    }
}
