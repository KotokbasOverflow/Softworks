//! age encryption helpers shared by `hist` and `snip`.
//!
//! Binary age format throughout (no armor): backups and exports stay compact
//! and auto-detectable via `AGE_MAGIC`. Recipients are X25519 `age1...`
//! keys; passphrases use scrypt through `decrypt_with_passphrase`.
//!
//! Secret-handling notes: passphrases arrive as `&str` and are copied into a
//! `SecretString` for the KDF; callers should drop the source string promptly
//! (it cannot be wiped through a borrow).

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result};
use std::path::Path;

/// age v1 magic prefix, used for format auto-detection.
pub const AGE_MAGIC: &[u8] = b"age-encryption.org/";

/// True when `data` starts with the age v1 magic.
pub fn is_age_blob(data: &[u8]) -> bool {
    data.starts_with(AGE_MAGIC)
}

/// True when `data` is a passphrase-encrypted (scrypt) age blob.
/// Errors when `data` is not an age blob at all.
pub fn is_passphrase_blob(data: &[u8]) -> Result<bool> {
    age::Decryptor::new(data)
        .map(|d| d.is_scrypt())
        .map_err(|e| anyhow::anyhow!("not an age blob: {e}"))
}

/// Encrypt `plaintext` to an X25519 `age1...` recipient.
pub fn encrypt_to_recipient(plaintext: &[u8], recipient: &str) -> Result<Vec<u8>> {
    let recipient: age::x25519::Recipient = recipient
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid age recipient {recipient:?}: {e}"))?;
    age::encrypt(&recipient, plaintext).map_err(|e| anyhow::anyhow!("age encryption failed: {e}"))
}

/// Decrypt with an X25519 identity (`AGE-SECRET-KEY-...`).
pub fn decrypt_with_identity(ciphertext: &[u8], identity: &str) -> Result<Vec<u8>> {
    let identity: age::x25519::Identity = identity
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid age identity: {e}"))?;
    age::decrypt(&identity, ciphertext).map_err(|e| anyhow::anyhow!("age decryption failed: {e}"))
}

/// Decrypt a scrypt (passphrase-encrypted) blob. Fails on a wrong passphrase.
pub fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let identity =
        age::scrypt::Identity::new(SecretString::new(passphrase.to_owned().into_boxed_str()));
    age::decrypt(&identity, ciphertext)
        .map_err(|e| anyhow::anyhow!("age decryption failed (wrong passphrase?): {e}"))
}

/// Read an X25519 identity from `path` (first non-comment line).
/// Refuses group/other-readable files on unix: an identity file readable by
/// others defeats the encryption.
pub fn read_identity_file(path: &Path) -> Result<age::x25519::Identity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("cannot stat {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "refusing to read identity {}: permissions {:o} are too open (chmod 600)",
                path.display(),
                mode & 0o777
            );
        }
    }
    let content =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .with_context(|| format!("no identity found in {}", path.display()))?;
    line.parse()
        .map_err(|e| anyhow::anyhow!("invalid age identity in {}: {e}", path.display()))
}

/// Decrypt an age-encrypted import blob.
/// An identity file wins when given; otherwise scrypt (passphrase) blobs
/// need `passphrase`, and key-encrypted blobs without an identity file are
/// an error. Fails closed: nothing is returned on any key mismatch.
pub fn decrypt_import_blob(
    blob: &[u8],
    identity_path: Option<&Path>,
    passphrase: Option<&str>,
) -> Result<Vec<u8>> {
    if let Some(path) = identity_path {
        let identity = read_identity_file(path)?;
        let secret = identity.to_string();
        return decrypt_with_identity(blob, secret.expose_secret());
    }
    if is_passphrase_blob(blob).unwrap_or(false) {
        let passphrase =
            passphrase.context("passphrase-encrypted import needs an interactive passphrase")?;
        return decrypt_with_passphrase(blob, passphrase);
    }
    anyhow::bail!("age-encrypted import needs --age-identity (key-encrypted file)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (String, String) {
        use age::secrecy::ExposeSecret;
        let id = age::x25519::Identity::generate();
        (
            id.to_public().to_string(),
            id.to_string().expose_secret().to_owned(),
        )
    }

    #[test]
    fn recipient_roundtrip() {
        let (recipient, identity) = keypair();
        let blob = encrypt_to_recipient(b"backup-bytes hunter2", &recipient).unwrap();
        assert!(is_age_blob(&blob));
        assert!(!blob.windows(7).any(|w| w == b"hunter2"));
        let back = decrypt_with_identity(&blob, &identity).unwrap();
        assert_eq!(back, b"backup-bytes hunter2");
    }

    #[test]
    fn garbage_recipient_rejected() {
        assert!(encrypt_to_recipient(b"x", "not-a-key").is_err());
        assert!(encrypt_to_recipient(b"x", "").is_err());
    }

    #[test]
    fn wrong_identity_fails() {
        let (recipient, _) = keypair();
        let (_, other_identity) = keypair();
        let blob = encrypt_to_recipient(b"secret", &recipient).unwrap();
        assert!(decrypt_with_identity(&blob, &other_identity).is_err());
    }

    #[test]
    fn non_age_bytes_not_detected() {
        assert!(!is_age_blob(b""));
        assert!(!is_age_blob(br#"[{"name":"x"}]"#));
    }

    #[test]
    fn passphrase_roundtrip_and_wrong_fails() {
        let recipient = age::scrypt::Recipient::new(SecretString::new(
            "correct horse".to_owned().into_boxed_str(),
        ));
        let blob = age::encrypt(&recipient, b"export-bytes").unwrap();
        assert!(is_age_blob(&blob));
        let back = decrypt_with_passphrase(&blob, "correct horse").unwrap();
        assert_eq!(back, b"export-bytes");
        assert!(decrypt_with_passphrase(&blob, "wrong horse").is_err());
    }

    #[test]
    fn identity_file_roundtrip_and_perms() {
        let dir = std::env::temp_dir().join(format!(
            "secdetect-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.txt");
        let (_, identity) = keypair();
        std::fs::write(&path, format!("# test key\n{identity}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let loaded = read_identity_file(&path).unwrap();
        // The loaded identity must actually work: encrypt to its public key,
        // decrypt with the original secret string.
        let blob = encrypt_to_recipient(b"ping", &loaded.to_public().to_string()).unwrap();
        let back = decrypt_with_identity(&blob, &identity).unwrap();
        assert_eq!(back, b"ping");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_identity_file(&path).is_err());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
