#![allow(clippy::needless_doctest_main)]
//! ## Usage
//!
//! ```rust
//! use std::sync::Arc;
//!
//! // use hasher::{Hasher, HasherKeccak}; // https://crates.io/crates/hasher
//!
//! use cita_trie::MemoryDB;
//! use cita_trie::{PatriciaTrie, Trie};

//! fn main() {
//!     let memdb = MemoryDB::new(true);
//!
//!     let key = "test-key".as_bytes();
//!     let value = "test-value".as_bytes();
//!
//!     let root = {
//!         let mut trie = PatriciaTrie::new(memdb.clone());
//!         trie.insert(key.to_vec(), value.to_vec()).unwrap();
//!
//!         let v = trie.get(key).unwrap();
//!         assert_eq!(Some(value.to_vec()), v);
//!         trie.root().unwrap()
//!     };
//!
//!     let mut trie = PatriciaTrie::from(memdb.clone(), &root).unwrap();
//!     let exists = trie.contains(key).unwrap();
//!     assert_eq!(exists, true);
//!     let removed = trie.remove(key).unwrap();
//!     assert_eq!(removed, true);
//!     let new_root = trie.root().unwrap();
//!     println!("new root = {:?}", new_root);
//!
//! }
//! ```

mod nibbles;
mod node;
mod tests;

mod db;
mod errors;
mod trie;

pub use db::{MemoryDB, DB};
pub use errors::{MemDBError, TrieError};
pub use trie::{PatriciaTrie, Trie};
pub use verify::verify_proof;

mod verify {
    use std::sync::Arc;

    use sha3::Digest;

    use crate::{trie::TrieResult, MemoryDB, PatriciaTrie, Trie, TrieError, DB};

    pub fn verify_proof(
        root_hash: &[u8],
        key: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> TrieResult<Option<Vec<u8>>> {
        let memdb = Arc::new(MemoryDB::new(true));
        for node_encoded in proof.into_iter() {
            let hash = sha3::Keccak256::digest(&node_encoded);

            if root_hash == hash.as_slice() || node_encoded.len() >= sha3::Keccak256::output_size()
            {
                memdb.insert(hash.to_vec(), node_encoded).unwrap();
            }
        }

        PatriciaTrie::from(memdb, root_hash)
            .or(Err(TrieError::InvalidProof))?
            .get(key)
            .or(Err(TrieError::InvalidProof))
    }
}
