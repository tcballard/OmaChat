use crate::sealed::{
    FILE_KEY_NAME, ProviderKind, SealedStore, StoreError, delete_secret_service_key, sync_directory,
};
use std::{fs, path::Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PanicEraseReport {
    pub provider: ProviderKind,
}

impl SealedStore {
    /// Cryptographically erase this store by removing the only master-key
    /// copy before unlinking ciphertext and synchronizing directory metadata.
    /// This is not a claim of physical overwrite on CoW, SSD, snapshot, backup,
    /// or networked storage.
    pub async fn panic_erase(&self) -> Result<PanicEraseReport, StoreError> {
        let metadata = fs::symlink_metadata(&self.state_directory).map_err(StoreError::Io)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(StoreError::UnsafeEraseTarget);
        }
        let parent = self
            .state_directory
            .parent()
            .ok_or(StoreError::UnsafeEraseTarget)?
            .to_owned();
        if self.state_directory == Path::new("/") || self.state_directory.file_name().is_none() {
            return Err(StoreError::UnsafeEraseTarget);
        }
        match self.provider {
            ProviderKind::File => match fs::remove_file(self.state_directory.join(FILE_KEY_NAME)) {
                Ok(()) => sync_directory(&self.state_directory)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(StoreError::MissingMasterKey);
                }
                Err(error) => return Err(StoreError::Io(error)),
            },
            ProviderKind::SecretService => delete_secret_service_key().await?,
        }
        self.key
            .lock()
            .expect("master-key mutex poisoned")
            .zeroize();
        fs::remove_dir_all(&self.state_directory).map_err(StoreError::Io)?;
        sync_directory(&parent)?;
        Ok(PanicEraseReport {
            provider: self.provider,
        })
    }
}
