use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::errors::MemDBError;

/// "DB" defines the "trait" of trie and database interaction.
/// You should first write the data to the cache and write the data
/// to the database in bulk after the end of a set of operations.
pub trait DB: Send + Sync {
    type Error: Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    fn contains(&self, key: &[u8]) -> Result<bool, Self::Error>;

    /// Inserts data into the cache.
    fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Self::Error>;

    /// Removes data from the cache.
    fn remove(&self, key: &[u8]) -> Result<(), Self::Error>;

    /// Inserts a batch of data into the cache.
    fn insert_batch<I>(&self, items: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    {
        for (key, value) in items {
            self.insert(key, value)?;
        }

        Ok(())
    }

    /// Removes a batch of data into the cache.
    fn remove_batch<I: IntoIterator<Item = A>, A: AsRef<[u8]>>(
        &self,
        keys: I,
    ) -> Result<(), Self::Error> {
        for key in keys {
            self.remove(key.as_ref())?;
        }
        Ok(())
    }

    /// Flushes data to the DB from the cache.
    fn flush(&self) -> Result<(), Self::Error>;
}

#[derive(Default, Debug, Clone)]
pub struct MemoryDB {
    // If "light" is true, the data is deleted from the database at the time of submission.
    light: bool,
    storage: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl MemoryDB {
    pub fn new(light: bool) -> Self {
        MemoryDB {
            light,
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl DB for MemoryDB {
    type Error = MemDBError;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.storage.read().get(key).cloned())
    }

    fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Self::Error> {
        self.storage.write().insert(key, value);
        Ok(())
    }

    fn contains(&self, key: &[u8]) -> Result<bool, Self::Error> {
        Ok(self.storage.read().contains_key(key))
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        if self.light {
            self.storage.write().remove(key);
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<T: ?Sized + DB> DB for Arc<T> {
    type Error = T::Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        T::get(self, key)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, Self::Error> {
        T::contains(self, key)
    }

    fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Self::Error> {
        T::insert(self, key, value)
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        T::remove(self, key)
    }

    fn flush(&self) -> Result<(), Self::Error> {
        T::flush(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memdb_get() {
        let memdb = MemoryDB::new(true);
        memdb
            .insert(b"test-key".to_vec(), b"test-value".to_vec())
            .unwrap();
        let v = memdb.get(b"test-key").unwrap().unwrap();

        assert_eq!(v, b"test-value")
    }

    #[test]
    fn test_memdb_contains() {
        let memdb = MemoryDB::new(true);
        memdb.insert(b"test".to_vec(), b"test".to_vec()).unwrap();

        let contains = memdb.contains(b"test").unwrap();
        assert!(contains)
    }

    #[test]
    fn test_memdb_remove() {
        let memdb = MemoryDB::new(true);
        memdb.insert(b"test".to_vec(), b"test".to_vec()).unwrap();

        memdb.remove(b"test").unwrap();
        let contains = memdb.contains(b"test").unwrap();
        assert!(!contains)
    }
}
