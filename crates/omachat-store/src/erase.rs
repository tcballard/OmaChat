use crate::sealed::{
    FILE_KEY_NAME, ProviderKind, SealedStore, StoreError, delete_secret_service_key, sync_directory,
};
use std::{fs, path::Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PanicEraseReport {
    pub provider: ProviderKind,
}

impl SealedStore {
    /// Does not overwrite bytes on CoW, SSD, snapshot, backup, or networked storage.
    pub async fn panic_erase(&self) -> Result<PanicEraseReport, StoreError> {
        self.erase_process_key()?;
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
        let key_cleanup = self.delete_external_master_key().await;
        let ciphertext_cleanup = delete_ciphertext_before_reporting(&self.state_directory, &parent);
        key_cleanup?;
        ciphertext_cleanup?;
        Ok(PanicEraseReport {
            provider: self.provider,
        })
    }

    fn erase_process_key(&self) -> Result<(), StoreError> {
        self.key_state
            .lock()
            .expect("master-key state mutex poisoned")
            .erase()
    }

    async fn delete_external_master_key(&self) -> Result<(), StoreError> {
        match self.provider {
            ProviderKind::File => match fs::remove_file(self.state_directory.join(FILE_KEY_NAME)) {
                Ok(()) => sync_directory(&self.state_directory),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Err(StoreError::MissingMasterKey)
                }
                Err(error) => Err(StoreError::Io(error)),
            },
            ProviderKind::SecretService => delete_secret_service_key().await,
        }
    }
}

fn delete_ciphertext_before_reporting(
    state_directory: &Path,
    parent: &Path,
) -> Result<(), StoreError> {
    fs::remove_dir_all(state_directory)
        .map_err(StoreError::Io)
        .and_then(|()| sync_directory(parent))
}
