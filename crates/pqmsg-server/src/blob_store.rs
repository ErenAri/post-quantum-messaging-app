use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct BlobStore {
    backend: BlobStoreBackend,
}

#[derive(Clone)]
enum BlobStoreBackend {
    InMemory(Arc<Mutex<HashMap<String, Vec<u8>>>>),
    LocalFs { root: Arc<PathBuf> },
}

impl BlobStore {
    pub fn in_memory() -> Self {
        Self {
            backend: BlobStoreBackend::InMemory(Arc::new(Mutex::new(HashMap::new()))),
        }
    }

    pub fn local_fs(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self {
            backend: BlobStoreBackend::LocalFs {
                root: Arc::new(root),
            },
        })
    }

    pub fn put(&self, object_key: &str, bytes: &[u8]) -> std::io::Result<()> {
        match &self.backend {
            BlobStoreBackend::InMemory(map) => {
                map.lock()
                    .expect("blob store lock poisoned")
                    .insert(object_key.to_string(), bytes.to_vec());
                Ok(())
            }
            BlobStoreBackend::LocalFs { root } => {
                let path = object_path(root, object_key)?;
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, bytes)
            }
        }
    }

    pub fn get(&self, object_key: &str) -> std::io::Result<Option<Vec<u8>>> {
        match &self.backend {
            BlobStoreBackend::InMemory(map) => Ok(map
                .lock()
                .expect("blob store lock poisoned")
                .get(object_key)
                .cloned()),
            BlobStoreBackend::LocalFs { root } => {
                let path = object_path(root, object_key)?;
                match fs::read(path) {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(error) => Err(error),
                }
            }
        }
    }

    pub fn delete(&self, object_key: &str) -> std::io::Result<()> {
        match &self.backend {
            BlobStoreBackend::InMemory(map) => {
                map.lock()
                    .expect("blob store lock poisoned")
                    .remove(object_key);
                Ok(())
            }
            BlobStoreBackend::LocalFs { root } => {
                let path = object_path(root, object_key)?;
                match fs::remove_file(path) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error),
                }
            }
        }
    }
}

fn object_path(root: &Path, object_key: &str) -> std::io::Result<PathBuf> {
    if object_key.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "object key must not be empty",
        ));
    }
    let candidate = Path::new(object_key);
    if candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "object key must be relative and must not contain parent traversal",
        ));
    }
    Ok(root.join(candidate))
}
