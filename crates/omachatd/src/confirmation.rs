//! Single-use, TTL-bounded confirmation tokens for destructive commands.
//!
//! A destructive command (`panic`, `claim-registry-handle`) is a two-phase
//! exchange: the client first requests a confirmation, the daemon mints a
//! random token and places it in a 0600 file inside the 0700
//! `<state_dir>/confirmations/` directory, and the client must echo that
//! token back within the TTL. This replaces the in-band constant `"ERASE"`
//! (a typo guard, not authorization). Same-uid processes can still read the
//! state directory — this is a deliberate-two-step and freshness guarantee
//! layered on the peer-credential gate, not a hard boundary; see SECURITY.md.

use crate::CoreError;
use std::{
    collections::HashMap,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

/// A confirmation token is useless after two minutes: long enough for an
/// interactive `--confirm` round trip, short enough that a token left in the
/// state directory by an abandoned command is not a standing authorization.
pub const CONFIRMATION_TTL_SECONDS: u64 = 120;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfirmationAction {
    PanicErase,
    RegistryClaim { handle: String },
}

impl ConfirmationAction {
    /// One outstanding token per action kind; a claim token additionally
    /// pins the exact handle through the pending-entry comparison.
    fn file_name(&self) -> &'static str {
        match self {
            Self::PanicErase => "panic.token",
            Self::RegistryClaim { .. } => "registry-claim.token",
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
        file.write_all(token.as_bytes()).map_err(CoreError::Io)?;
        let expires_at = now.saturating_add(CONFIRMATION_TTL_SECONDS);
        self.pending
            .lock()
            .expect("confirmation mutex poisoned")
            .insert(
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

    /// Single use, burn on attempt: the pending entry and the token file are
    /// consumed by every redemption attempt for the action kind, matched or
    /// not, so a wrong guess costs the outstanding token instead of leaving
    /// it available for retries. Tokens are 256-bit random values, so a
    /// non-constant-time comparison leaks nothing recoverable within one
    /// attempt.
    pub fn redeem(
        &self,
        action: &ConfirmationAction,
        presented: &str,
        now: u64,
    ) -> Result<(), ConfirmationError> {
        let removed = self
            .pending
            .lock()
            .expect("confirmation mutex poisoned")
            .remove(action.file_name());
        let _ = fs::remove_file(self.directory.join(action.file_name()));
        let Some(pending) = removed else {
            return Err(ConfirmationError::Missing);
        };
        if pending.expires_at < now {
            return Err(ConfirmationError::Expired);
        }
        if &pending.action != action || pending.token != presented {
            return Err(ConfirmationError::Mismatch);
        }
        Ok(())
    }
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

    #[test]
    fn claim_tokens_are_bound_to_their_handle() {
        let state = tempdir().expect("state directory");
        let confirmations = DestructiveConfirmations::new(state.path());
        let issued = confirmations
            .issue(
                ConfirmationAction::RegistryClaim {
                    handle: "tom".into(),
                },
                0,
            )
            .expect("issue token");
        let token = std::fs::read_to_string(&issued.token_path).expect("token file");
        assert_eq!(
            confirmations.redeem(
                &ConfirmationAction::RegistryClaim {
                    handle: "alice".into()
                },
                &token,
                1,
            ),
            Err(ConfirmationError::Mismatch),
            "a token minted for one handle must not confirm another"
        );
    }
}
