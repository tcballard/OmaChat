use crate::CoreError;
use std::{
    collections::HashMap,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

pub const CONFIRMATION_TTL_SECONDS: u64 = 2 * 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfirmationAction {
    PanicErase,
}

impl ConfirmationAction {
    fn file_name(&self) -> &'static str {
        match self {
            Self::PanicErase => "panic.token",
        }
    }
}

#[derive(Debug)]
struct PendingToken {
    action: ConfirmationAction,
    token: String,
    expires_at: u64,
}

#[derive(Debug)]
pub struct IssuedConfirmation {
    pub token_path: PathBuf,
    pub expires_at: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ConfirmationError {
    Missing,
    Mismatch,
    Expired,
}

#[derive(Debug)]
pub struct DestructiveConfirmations {
    directory: PathBuf,
    pending: Mutex<HashMap<&'static str, PendingToken>>,
}

impl DestructiveConfirmations {
    #[must_use]
    pub fn new(state_directory: &Path) -> Self {
        Self {
            directory: state_directory.join("confirmations"),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Mint a fresh token for `action`, replacing any outstanding token of
    /// the same kind. The token travels out of band: the caller learns only
    /// the path, and must be able to read the daemon's state directory to
    /// obtain the value itself.
    pub fn issue(
        &self,
        action: ConfirmationAction,
        now: u64,
    ) -> Result<IssuedConfirmation, CoreError> {
        let mut pending = self.pending.lock().expect("confirmation mutex poisoned");
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| CoreError::Random)?;
        let token = hex::encode(bytes);
        fs::create_dir_all(&self.directory).map_err(CoreError::Io)?;
        fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))
            .map_err(CoreError::Io)?;
        let token_path = self.directory.join(action.file_name());
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&token_path)
            .map_err(CoreError::Io)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(CoreError::Io)?;
        file.write_all(token.as_bytes()).map_err(CoreError::Io)?;
        let expires_at = now.saturating_add(CONFIRMATION_TTL_SECONDS);
        pending.insert(
            action.file_name(),
            PendingToken {
                action,
                token,
                expires_at,
            },
        );
        Ok(IssuedConfirmation {
            token_path,
            expires_at,
        })
    }

    pub fn redeem(
        &self,
        action: &ConfirmationAction,
        presented: &str,
        now: u64,
    ) -> Result<(), ConfirmationError> {
        let mut pending_tokens = self.pending.lock().expect("confirmation mutex poisoned");
        let Some(pending) = consume_pending_token(&mut pending_tokens, &self.directory, action)
        else {
            return Err(ConfirmationError::Missing);
        };
        if pending.expires_at <= now {
            return Err(ConfirmationError::Expired);
        }
        if &pending.action != action || pending.token != presented {
            return Err(ConfirmationError::Mismatch);
        }
        Ok(())
    }
}

fn consume_pending_token(
    pending: &mut HashMap<&'static str, PendingToken>,
    directory: &Path,
    action: &ConfirmationAction,
) -> Option<PendingToken> {
    let removed = pending.remove(action.file_name());
    let _ = fs::remove_file(directory.join(action.file_name()));
    removed
}

#[cfg(test)]
mod tests {
    use super::{
        CONFIRMATION_TTL_SECONDS, ConfirmationAction, ConfirmationError, DestructiveConfirmations,
    };
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn issue_writes_a_private_single_use_token() {
        let state = tempdir().expect("state directory");
        let confirmations = DestructiveConfirmations::new(state.path());
        let issued = confirmations
            .issue(ConfirmationAction::PanicErase, 1_000)
            .expect("issue token");
        assert_eq!(issued.expires_at, 1_000 + CONFIRMATION_TTL_SECONDS);
        let mode = std::fs::metadata(&issued.token_path)
            .expect("token metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let token = std::fs::read_to_string(&issued.token_path).expect("token file");
        assert_eq!(token.len(), 64, "32 random bytes hex encoded");

        confirmations
            .redeem(&ConfirmationAction::PanicErase, &token, 1_010)
            .expect("first redemption succeeds");
        assert!(!issued.token_path.exists(), "redemption consumes the file");
        assert_eq!(
            confirmations.redeem(&ConfirmationAction::PanicErase, &token, 1_010),
            Err(ConfirmationError::Missing),
            "tokens are single use"
        );
    }

    #[test]
    fn wrong_token_burns_the_pending_confirmation() {
        let state = tempdir().expect("state directory");
        let confirmations = DestructiveConfirmations::new(state.path());
        let issued = confirmations
            .issue(ConfirmationAction::PanicErase, 0)
            .expect("issue token");
        assert_eq!(
            confirmations.redeem(&ConfirmationAction::PanicErase, "ERASE", 1),
            Err(ConfirmationError::Mismatch),
            "the legacy constant is no longer a confirmation"
        );
        let token = std::fs::read_to_string(&issued.token_path);
        assert!(
            token.is_err(),
            "a failed guess consumes the outstanding token"
        );
    }

    #[test]
    fn expired_tokens_are_rejected() {
        let state = tempdir().expect("state directory");
        let confirmations = DestructiveConfirmations::new(state.path());
        let issued = confirmations
            .issue(ConfirmationAction::PanicErase, 100)
            .expect("issue token");
        let token = std::fs::read_to_string(&issued.token_path).expect("token file");
        assert_eq!(
            confirmations.redeem(
                &ConfirmationAction::PanicErase,
                &token,
                issued.expires_at + 1
            ),
            Err(ConfirmationError::Expired)
        );
    }
}
