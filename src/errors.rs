use std::error::Error;
use std::fmt;

use rlp::DecoderError;

#[derive(Debug)]
pub enum TrieError {
    DB(String),
    Decoder(DecoderError),
    InvalidData,
    InvalidStateRoot,
    InvalidProof,
}

impl Error for TrieError {}

impl fmt::Display for TrieError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TrieError::DB(ref err) => write!(f, "trie error: {:?}", err),
            TrieError::Decoder(ref err) => write!(f, "trie error: {:?}", err),
            TrieError::InvalidData => f.write_str("trie error: invalid data"),
            TrieError::InvalidStateRoot => f.write_str("trie error: invalid state root"),
            TrieError::InvalidProof => f.write_str("trie error: invalid proof"),
        }
    }
}

impl From<DecoderError> for TrieError {
    fn from(error: DecoderError) -> Self {
        TrieError::Decoder(error)
    }
}

#[derive(Debug)]
pub enum MemDBError {}

impl Error for MemDBError {}

impl fmt::Display for MemDBError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "error")
    }
}
