use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::mem;
use std::ops::Deref;
use std::ptr::NonNull;

use rlp::{Prototype, Rlp, RlpStream};
use sha3::Digest;

use crate::db::{MemoryDB, DB};
use crate::errors::TrieError;
use crate::nibbles::{NibbleSlice, NibbleVec};
use crate::node::{empty_children, BranchNode, ExtensionNode, Node};

pub type TrieResult<T> = Result<T, TrieError>;

pub trait Trie<D: DB> {
    /// Returns the value for key stored in the trie.
    fn get(&self, key: &[u8]) -> TrieResult<Option<Vec<u8>>>;

    /// Checks that the key is present in the trie
    fn contains(&self, key: &[u8]) -> TrieResult<bool>;

    /// Inserts value into trie and modifies it if it exists
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> TrieResult<()>;

    /// Removes any existing value for key from the trie.
    fn remove(&mut self, key: &[u8]) -> TrieResult<bool>;

    /// Saves all the nodes in the db, clears the cache data, recalculates the root.
    /// Returns the root hash of the trie.
    fn root(&mut self) -> TrieResult<Vec<u8>>;

    /// Prove constructs a merkle proof for key. The result contains all encoded nodes
    /// on the path to the value at key. The value itself is also included in the last
    /// node and can be retrieved by verifying the proof.
    ///
    /// If the trie does not contain a value for key, the returned proof contains all
    /// nodes of the longest existing prefix of the key (at least the root node), ending
    /// with the node that proves the absence of the key.
    fn get_proof(&self, key: &[u8]) -> TrieResult<Vec<Vec<u8>>>;

    /// return value if key exists, None if key not exist, Error if proof is wrong
    fn verify_proof(
        &self,
        root_hash: &[u8],
        key: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> TrieResult<Option<Vec<u8>>>;
}

#[derive(Debug, Clone)]
pub struct PatriciaTrie<D>
where
    D: DB + Clone,
{
    root: Node,
    root_hash: Vec<u8>,

    db: D,
    backup_db: Option<D>,

    cache: RefCell<HashMap<Vec<u8>, Vec<u8>>>,
    passing_keys: HashSet<[u8; 32]>,
    gen_keys: RefCell<HashSet<[u8; 32]>>,
}

impl<D: DB + Clone> Drop for PatriciaTrie<D> {
    fn drop(&mut self) {
        let node = mem::replace(&mut self.root, Node::Empty);
        self.drop_inner(node)
    }
}

impl<D: DB + Clone> PatriciaTrie<D> {
    fn drop_inner(&mut self, node: Node) {
        match node {
            Node::Empty => {}
            Node::Leaf(mut leaf) => {
                // eprintln!("leaf = {:#?}", leaf);
                let leaf = unsafe { Box::from_raw(leaf.as_mut()) };
            }
            Node::Extension(mut ext) => {
                // eprintln!("ext = {:#?}", ext);
                let ext_owned = unsafe { Box::from_raw(ext.as_mut()) };
                self.drop_inner(ext_owned.node);
            }
            Node::Branch(mut branch) => {
                // eprintln!("branch = {:#?}", branch);
                let branch_owned = unsafe { Box::from_raw(branch.as_mut()) };
                for node in branch_owned.children {
                    // eprintln!("node = {:#?}", node);
                    self.drop_inner(node);
                }
            }
            Node::Hash(mut hash_node) => unsafe {
                let hash_node_mut = hash_node.as_mut();
                // let nnn = self.recover_from_db(&hash_node_mut.hash).unwrap();
                // self.drop_inner(nnn);
                // eprintln!("hash_node = {:02x?}", hash_node_mut.hash);
                let _ = Box::from_raw(hash_node_mut);
            },
        }
    }

    // fn _print(&self, node: Node) {
    //     let mut buf = Vec::new();
    //
    // }

    // fn print(&self, node: Node, buf: &mut Vec<String>) {
    //     unsafe {
    //         match node {
    //             Node::Empty => {
    //                 return;
    //             }
    //             Node::Leaf(leaf) => {
    //                 format!("{:?}", leaf.as_ref())
    //             }
    //             Node::Extension(mut ext) => {
    //                 self.print()
    //                 let ext_owned = unsafe { Box::from_raw(ext.as_mut()) };
    //                 self.drop_inner(ext_owned.node);
    //             }
    //             Node::Branch(mut branch) => {
    //                 eprintln!("branch = {:#?}", branch);
    //                 let branch_owned = unsafe { Box::from_raw(branch.as_mut()) };
    //                 for node in branch_owned.children {
    //                     eprintln!("node = {:#?}", node);
    //                     self.drop_inner(node);
    //                 }
    //             }
    //             Node::Hash(mut hash_node) => unsafe {
    //                 let hash_node_mut = hash_node.as_mut();
    //                 // let nnn = self.recover_from_db(&hash_node_mut.hash).unwrap();
    //                 // self.drop_inner(nnn);
    //                 eprintln!("hash_node = {:02x?}", hash_node_mut.hash);
    //                 let _ = Box::from_raw(hash_node_mut);
    //             },
    //         }
    //     }
    // }
}

#[derive(Clone, Debug)]
enum TraceStatus {
    Start,
    Doing,
    Child(u8),
    End,
}

#[derive(Clone, Debug)]
struct TraceNode {
    node: Node,
    status: TraceStatus,
}

impl TraceNode {
    fn advance(&mut self) {
        self.status = match &self.status {
            TraceStatus::Start => TraceStatus::Doing,
            TraceStatus::Doing => match self.node {
                Node::Branch(_) => TraceStatus::Child(0),
                _ => TraceStatus::End,
            },
            TraceStatus::Child(i) if *i < 15 => TraceStatus::Child(i + 1),
            _ => TraceStatus::End,
        }
    }
}

impl From<Node> for TraceNode {
    fn from(node: Node) -> TraceNode {
        TraceNode {
            node,
            status: TraceStatus::Start,
        }
    }
}

pub struct TrieIterator<'a, D>
where
    D: DB + Clone,
{
    trie: &'a PatriciaTrie<D>,
    nibble: NibbleVec,
    nodes: Vec<TraceNode>,
}

impl<'a, D> Iterator for TrieIterator<'a, D>
where
    D: DB + Clone,
{
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut now = self.nodes.last().cloned();
            if let Some(ref mut now) = now {
                self.nodes.last_mut().unwrap().advance();

                match (now.status.clone(), &now.node) {
                    (TraceStatus::End, node) => {
                        match *node {
                            Node::Leaf(ref leaf) => {
                                let cur_len = self.nibble.len();
                                self.nibble
                                    .truncate(cur_len - unsafe { leaf.as_ref() }.key.len());
                            }

                            Node::Extension(ref ext) => {
                                let cur_len = self.nibble.len();
                                self.nibble
                                    .truncate(cur_len - unsafe { ext.as_ref() }.prefix.len());
                            }

                            Node::Branch(_) => {
                                self.nibble.pop();
                            }
                            _ => {}
                        }
                        self.nodes.pop();
                    }

                    (TraceStatus::Doing, Node::Extension(ref ext)) => {
                        self.nibble
                            .extend_from_slice(&unsafe { ext.as_ref() }.prefix);
                        self.nodes
                            .push((unsafe { ext.as_ref() }.node.clone()).into());
                    }

                    (TraceStatus::Doing, Node::Leaf(ref leaf)) => {
                        self.nibble.extend_from_slice(&unsafe { leaf.as_ref() }.key);
                        return Some((
                            self.nibble.encode_raw().0,
                            unsafe { leaf.as_ref() }.value.clone(),
                        ));
                    }

                    (TraceStatus::Doing, Node::Branch(ref branch)) => {
                        let value = unsafe { branch.as_ref() }.value.clone();
                        if let Some(data) = value {
                            return Some((self.nibble.encode_raw().0, data));
                        } else {
                            continue;
                        }
                    }

                    (TraceStatus::Doing, Node::Hash(ref hash_node)) => {
                        if let Ok(n) = self
                            .trie
                            .recover_from_db(&unsafe { hash_node.as_ref() }.hash.clone())
                        {
                            self.nodes.pop();
                            self.nodes.push(n.into());
                        } else {
                            //error!();
                            return None;
                        }
                    }

                    (TraceStatus::Child(i), Node::Branch(ref branch)) => {
                        if i == 0 {
                            self.nibble.push(0);
                        } else {
                            self.nibble.pop();
                            self.nibble.push(i);
                        }
                        self.nodes
                            .push((unsafe { branch.as_ref() }.children[i as usize].clone()).into());
                    }

                    (_, Node::Empty) => {
                        self.nodes.pop();
                    }
                    _ => {}
                }
            } else {
                return None;
            }
        }
    }
}

impl<D> PatriciaTrie<D>
where
    D: DB + Clone,
{
    pub fn iter(&self) -> TrieIterator<D> {
        let nodes = vec![self.root.clone().into()];
        TrieIterator {
            trie: self,
            nibble: NibbleVec::from_raw(vec![], false),
            nodes,
        }
    }
    pub fn new(db: D) -> Self {
        Self {
            root: Node::Empty,
            root_hash: sha3::Keccak256::digest(rlp::NULL_RLP.as_ref()).to_vec(),

            cache: RefCell::new(HashMap::new()),
            passing_keys: HashSet::new(),
            gen_keys: RefCell::new(HashSet::new()),

            db,
            backup_db: None,
        }
    }

    pub fn from(db: D, root: &[u8]) -> TrieResult<Self> {
        match db.get(root).map_err(|e| TrieError::DB(e.to_string()))? {
            Some(data) => {
                let mut trie = Self {
                    root: Node::Empty,
                    root_hash: root.to_vec(),

                    cache: RefCell::new(HashMap::new()),
                    passing_keys: HashSet::new(),
                    gen_keys: RefCell::new(HashSet::new()),

                    db,
                    backup_db: None,
                };

                trie.root = trie.decode_node(&data)?;
                Ok(trie)
            }
            None => Err(TrieError::InvalidStateRoot),
        }
    }

    // extract specified height statedb in full node mode
    pub fn extract_backup(
        db: D,
        backup_db: Option<D>,
        root_hash: &[u8],
    ) -> TrieResult<(Self, Vec<Vec<u8>>)> {
        let mut pt = Self {
            root: Node::Empty,
            root_hash: sha3::Keccak256::digest(rlp::NULL_RLP.as_ref()).to_vec(),

            cache: RefCell::new(HashMap::new()),
            passing_keys: HashSet::new(),
            gen_keys: RefCell::new(HashSet::new()),

            db,
            backup_db,
        };

        let root = pt.recover_from_db(root_hash)?;
        pt.root = root.clone();
        pt.root_hash = root_hash.to_vec();

        let mut addr_list = vec![];
        pt.iter().for_each(|(k, _v)| addr_list.push(k));
        let encoded = pt.cache_node(root)?;
        pt.cache
            .borrow_mut()
            .insert(sha3::Keccak256::digest(&encoded).to_vec(), encoded);

        // store data in backup db
        pt.backup_db
            .clone()
            .unwrap()
            .insert_batch(pt.cache.borrow_mut().drain())
            .map_err(|e| TrieError::DB(e.to_string()))?;
        pt.backup_db
            .clone()
            .unwrap()
            .flush()
            .map_err(|e| TrieError::DB(e.to_string()))?;
        Ok((pt, addr_list))
    }
}

impl<D> Trie<D> for PatriciaTrie<D>
where
    D: DB + Clone,
{
    /// Returns the value for key stored in the trie.
    fn get(&self, key: &[u8]) -> TrieResult<Option<Vec<u8>>> {
        self.get_at(self.root.clone(), &NibbleVec::from_raw(key.to_vec(), true))
    }

    /// Checks that the key is present in the trie
    fn contains(&self, key: &[u8]) -> TrieResult<bool> {
        Ok(self
            .get_at(self.root.clone(), &NibbleVec::from_raw(key.to_vec(), true))?
            .map_or(false, |_| true))
    }

    /// Inserts value into trie and modifies it if it exists
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> TrieResult<()> {
        if value.is_empty() {
            self.remove(&key)?;
            return Ok(());
        }
        let root = self.root.clone();
        self.root = self.insert_at(root, &NibbleVec::from_raw(key, true), value.to_vec())?;
        Ok(())
    }

    /// Removes any existing value for key from the trie.
    fn remove(&mut self, key: &[u8]) -> TrieResult<bool> {
        let (n, removed) =
            self.delete_at(self.root.clone(), &NibbleVec::from_raw(key.to_vec(), true))?;
        self.root = n;
        Ok(removed)
    }

    /// Saves all the nodes in the db, clears the cache data, recalculates the root.
    /// Returns the root hash of the trie.
    fn root(&mut self) -> TrieResult<Vec<u8>> {
        self.commit()
    }

    /// Prove constructs a merkle proof for key. The result contains all encoded nodes
    /// on the path to the value at key. The value itself is also included in the last
    /// node and can be retrieved by verifying the proof.
    ///
    /// If the trie does not contain a value for key, the returned proof contains all
    /// nodes of the longest existing prefix of the key (at least the root node), ending
    /// with the node that proves the absence of the key.
    fn get_proof(&self, key: &[u8]) -> TrieResult<Vec<Vec<u8>>> {
        let mut path =
            self.get_path_at(self.root.clone(), &NibbleVec::from_raw(key.to_vec(), true))?;
        match self.root {
            Node::Empty => {}
            _ => path.push(self.root.clone()),
        }
        Ok(path.into_iter().rev().map(|n| self.encode_raw(n)).collect())
    }

    /// return value if key exists, None if key not exist, Error if proof is wrong
    fn verify_proof(
        &self,
        root_hash: &[u8],
        key: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> TrieResult<Option<Vec<u8>>> {
        let memdb = MemoryDB::new(true);
        for node_encoded in proof.into_iter() {
            let hash = sha3::Keccak256::digest(&node_encoded);

            if root_hash == hash.as_slice() || node_encoded.len() >= sha3::Keccak256::output_size()
            {
                memdb.insert(hash.to_vec(), node_encoded).unwrap();
            }
        }
        let trie = PatriciaTrie::from(memdb, root_hash).or(Err(TrieError::InvalidProof))?;
        trie.get(key).or(Err(TrieError::InvalidProof))
    }
}

impl<D> PatriciaTrie<D>
where
    D: DB + Clone,
{
    fn get_at(&self, n: Node, partial: &NibbleSlice) -> TrieResult<Option<Vec<u8>>> {
        match n {
            Node::Empty => Ok(None),
            Node::Leaf(leaf) => {
                let leaf_ref = unsafe { leaf.as_ref() };

                if &*leaf_ref.key == partial {
                    Ok(Some(leaf_ref.value.clone()))
                } else {
                    Ok(None)
                }
            }
            Node::Branch(branch) => {
                let branch_ref = unsafe { branch.as_ref() };

                if partial.is_empty() || partial.at(0) == 16 {
                    Ok(branch_ref.value.clone())
                } else {
                    let index = partial.at(0);
                    self.get_at(branch_ref.children[index].clone(), partial.offset(1))
                }
            }
            Node::Extension(extension) => {
                let extension_ref = unsafe { extension.as_ref() };

                let prefix = &extension_ref.prefix;
                let match_len = partial.common_prefix(prefix);
                if match_len == prefix.len() {
                    self.get_at(extension_ref.node.clone(), partial.offset(match_len))
                } else {
                    Ok(None)
                }
            }
            Node::Hash(mut hash_node) => {
                // Construct a new node from database and get a value from it
                let hash_node_ref = unsafe { hash_node.as_ref() };
                eprintln!("LLLLLLLLLLLLLLLLLLLLLLLL = {:02x?}", hash_node_ref.hash);
                // todo(arsenron): can we cache it?
                let trie = PatriciaTrie::from(self.db.clone(), hash_node_ref.hash.as_slice())
                    .unwrap();
                trie
                    .get_at(trie.root.clone(), partial)
            }
        }
    }

    fn insert_at(&mut self, n: Node, partial: &NibbleSlice, value: Vec<u8>) -> TrieResult<Node> {
        match n {
            Node::Empty => Ok(Node::from_leaf(partial.to_owned(), value)),
            Node::Leaf(mut leaf) => {
                let mut leaf_mut = unsafe { leaf.as_mut() };

                let old_partial = &leaf_mut.key;
                let match_index = partial.common_prefix(old_partial);
                if match_index == old_partial.len() {
                    // replace leaf value
                    leaf_mut.value = value;
                    return Ok(Node::Leaf(leaf));
                }
                let mut branch = BranchNode {
                    children: empty_children(),
                    value: None,
                };

                let leaf_owned = unsafe { Box::from_raw(leaf_mut) };
                let old_partial = &leaf_owned.key;
                // todo(arsenron): Remove unnecessary allocation, i.e. mutate previous one
                let n = Node::from_leaf(
                    old_partial.offset(match_index + 1).to_owned(),
                    leaf_owned.value,
                );
                branch.insert(old_partial.at(match_index), n);

                let n = Node::from_leaf(partial.offset(match_index + 1).to_owned(), value);
                branch.insert(partial.at(match_index), n);

                let branch = Node::Branch(NonNull::new(Box::leak(Box::new(branch))).unwrap());
                if match_index == 0 {
                    // no common prefix
                    Ok(branch)
                } else {
                    // include a common prefix
                    let common_prefix = partial.slice(0, match_index).to_owned();
                    Ok(Node::from_extension(common_prefix, branch))
                }
            }
            Node::Branch(mut branch) => {
                eprintln!("BRANCH!!!!!!!!!!!!!!!");
                let mut branch_mut = unsafe { branch.as_mut() };

                if partial.at(0) == 0x10 {
                    branch_mut.value = Some(value);
                    return Ok(Node::Branch(branch));
                }

                let child = branch_mut.children[partial.at(0)].clone();
                let new_child = self.insert_at(child, partial.offset(1), value)?;
                branch_mut.children[partial.at(0)] = new_child;
                Ok(Node::Branch(branch))
            }
            Node::Extension(mut ext) => {
                eprintln!("EXT!!!!!!!!!!!!!!!");
                let mut ext_mut = unsafe { ext.as_mut() };

                let match_index = partial.common_prefix(&ext_mut.prefix);

                if match_index == 0 {
                    let ext_owned = unsafe { Box::from_raw(ext.as_mut()) };
                    let mut branch = BranchNode {
                        children: empty_children(),
                        value: None,
                    };
                    branch.insert(
                        ext_owned.prefix.at(0),
                        if ext_owned.prefix.len() == 1 {
                            ext_owned.node
                        } else {
                            Node::from_extension(
                                ext_owned.prefix.offset(1).to_owned(),
                                ext_owned.node,
                            )
                        },
                    );
                    let branch = Box::leak(Box::new(branch));
                    let node = Node::Branch(NonNull::new(branch).unwrap());

                    return self.insert_at(node, partial, value);
                }

                let sub_node = ext_mut.node.clone();
                let prefix = ext_mut.prefix.clone();

                if match_index == prefix.len() {
                    let new_node = self.insert_at(sub_node, partial.offset(match_index), value)?;
                    unsafe { Box::from_raw(ext_mut) };
                    return Ok(Node::from_extension(prefix.clone(), new_node));
                }

                let new_ext = Node::from_extension(prefix.offset(match_index).to_owned(), sub_node);
                let new_node = self.insert_at(new_ext, partial.offset(match_index), value)?;
                ext_mut.prefix = prefix.slice(0, match_index).to_owned();
                ext_mut.node = new_node;
                Ok(Node::Extension(ext))
            }
            Node::Hash(hash_node) => {
                let hash_node_ref = unsafe { hash_node.as_ref() };

                self.passing_keys.insert(hash_node_ref.hash);
                let n = self.recover_from_db(&hash_node_ref.hash)?;
                self.insert_at(n, partial, value)
            }
        }
    }

    fn delete_at(&mut self, n: Node, partial: &NibbleSlice) -> TrieResult<(Node, bool)> {
        let (new_n, deleted) = match n {
            Node::Empty => Ok((Node::Empty, false)),
            Node::Leaf(mut leaf) => {
                let leaf_ref = unsafe { leaf.as_ref() };

                if &*leaf_ref.key == partial {
                    unsafe { Box::from_raw(leaf.as_mut()) };
                    return Ok((Node::Empty, true));
                }
                Ok((Node::Leaf(leaf), false))
            }
            Node::Branch(mut branch) => {
                let mut branch_ref = unsafe { branch.as_mut() };

                let index = partial.at(0);
                if index == 0x10 {
                    branch_ref.value = None;
                    return Ok((Node::Branch(branch), true));
                }

                let node = branch_ref.children[index].clone();

                let (new_n, deleted) = self.delete_at(node, partial.offset(1))?;
                if deleted {
                    branch_ref.children[index] = new_n;
                }

                Ok((Node::Branch(branch), deleted))
            }
            Node::Extension(mut ext) => {
                let mut ext_ref = unsafe { ext.as_mut() };

                let prefix = &ext_ref.prefix;
                let match_len = partial.common_prefix(prefix);

                if match_len == prefix.len() {
                    let (new_n, deleted) =
                        self.delete_at(ext_ref.node.clone(), partial.offset(match_len))?;

                    if deleted {
                        ext_ref.node = new_n;
                    }

                    Ok((Node::Extension(ext), deleted))
                } else {
                    Ok((Node::Extension(ext), false))
                }
            }
            Node::Hash(hash_node) => {
                let hash = unsafe { hash_node.as_ref() }.hash;
                self.passing_keys.insert(hash);

                let n = self.recover_from_db(&hash)?;
                self.delete_at(n, partial)
            }
        }?;

        if deleted {
            Ok((self.degenerate(new_n)?, deleted))
        } else {
            Ok((new_n, deleted))
        }
    }

    fn degenerate(&mut self, n: Node) -> TrieResult<Node> {
        match n {
            Node::Branch(mut branch) => {
                let branch_ref = unsafe { branch.as_ref() };
                let mut empty = true;
                let mut ext_to = None;
                for (index, node) in branch_ref.children.iter().enumerate() {
                    match node {
                        Node::Empty => continue,
                        _ => {
                            let was_empty = mem::replace(&mut empty, false);
                            // if there's exactly one used node, store its index,
                            // set another flag if at least one node is not mpty
                            if ext_to.is_none() && was_empty {
                                ext_to = Some(index);
                            } else {
                                ext_to = None;
                                break;
                            }
                        }
                    }
                }

                match (empty, ext_to, branch_ref.value.as_ref()) {
                    // if only a value node, transmute to leaf.
                    (true, None, Some(_)) => {
                        let key = NibbleVec::from_raw(vec![], true);
                        let value = branch_ref.value.clone().unwrap();
                        unsafe { Box::from_raw(branch.as_mut()) };
                        Ok(Node::from_leaf(key, value))
                    }
                    (true, Some(_), _) => unreachable!(),
                    // if only one node. make an extension.
                    (false, Some(used_index), None) => {
                        let n = branch_ref.children[used_index].clone();

                        let new_node =
                            Node::from_extension(NibbleVec::from_hex(vec![used_index as u8]), n);
                        unsafe { Box::from_raw(branch.as_mut()) };
                        self.degenerate(new_node)
                    }
                    _ => Ok(Node::Branch(branch)),
                }
            }
            Node::Extension(mut ext) => {
                let ext_ref = unsafe { ext.as_ref() };

                let prefix = &ext_ref.prefix;
                match ext_ref.node.clone() {
                    Node::Extension(mut sub_ext) => {
                        let sub_ext_ref = unsafe { sub_ext.as_ref() };

                        let new_prefix = prefix.join(&sub_ext_ref.prefix);
                        let new_n = Node::from_extension(new_prefix, sub_ext_ref.node.clone());
                        unsafe { Box::from_raw(sub_ext.as_mut()) };
                        self.degenerate(new_n)
                    }
                    Node::Leaf(mut leaf) => {
                        let leaf_ref = unsafe { leaf.as_ref() };

                        let new_prefix = prefix.join(&leaf_ref.key);
                        let value = leaf_ref.value.clone();
                        unsafe { Box::from_raw(leaf.as_mut()) };
                        Ok(Node::from_leaf(new_prefix, value))
                    }
                    // try again after recovering node from the db.
                    Node::Hash(mut hash_node) => {
                        let hash = unsafe { hash_node.as_ref().hash };
                        self.passing_keys.insert(hash);

                        let new_node = self.recover_from_db(&hash)?;

                        let n = Node::from_extension(ext_ref.prefix.clone(), new_node);
                        unsafe { Box::from_raw(hash_node.as_mut()) };
                        self.degenerate(n)
                    }
                    _ => Ok(Node::Extension(ext)),
                }
            }
            _ => Ok(n),
        }
    }

    // Get nodes path along the key, only the nodes whose encode length is greater than
    // hash length are added.
    // For embedded nodes whose data are already contained in their parent node, we don't need to
    // add them in the path.
    // In the code below, we only add the nodes get by `get_node_from_hash`, because they contains
    // all data stored in db, including nodes whose encoded data is less than hash length.
    fn get_path_at(&self, n: Node, partial: &NibbleSlice) -> TrieResult<Vec<Node>> {
        match n {
            Node::Empty | Node::Leaf(_) => Ok(vec![]),
            Node::Branch(branch) => {
                let branch_ref = unsafe { branch.as_ref() };

                if partial.is_empty() || partial.at(0) == 16 {
                    Ok(vec![])
                } else {
                    let node = branch_ref.children[partial.at(0)].clone();
                    self.get_path_at(node, partial.offset(1))
                }
            }
            Node::Extension(ext) => {
                let ext_ref = unsafe { ext.as_ref() };

                let prefix = &ext_ref.prefix;
                let match_len = partial.common_prefix(prefix);

                if match_len == prefix.len() {
                    self.get_path_at(ext_ref.node.clone(), partial.offset(match_len))
                } else {
                    Ok(vec![])
                }
            }
            Node::Hash(hash_node) => {
                let n = self.recover_from_db(&unsafe { hash_node.as_ref() }.hash.clone())?;
                let mut rest = self.get_path_at(n.clone(), partial)?;
                rest.push(n);
                Ok(rest)
            }
        }
    }

    fn commit(&mut self) -> TrieResult<Vec<u8>> {
        let encoded = self.encode_node(self.root.clone());
        let root_hash = if encoded.len() < sha3::Keccak256::output_size() {
            let hash = sha3::Keccak256::digest(&encoded).to_vec();
            self.cache.borrow_mut().insert(hash.clone(), encoded);
            hash
        } else {
            encoded
        };

        self.db
            .insert_batch(self.cache.borrow_mut().drain())
            .map_err(|e| TrieError::DB(e.to_string()))?;

        let removed_keys: Vec<Vec<u8>> = self
            .passing_keys
            .iter()
            .filter(|h| !self.gen_keys.borrow().contains(*h))
            .map(|h| h.to_vec())
            .collect();

        self.db
            .remove_batch(removed_keys)
            .map_err(|e| TrieError::DB(e.to_string()))?;

        self.root_hash = root_hash.to_vec();
        self.gen_keys.borrow_mut().clear();
        self.passing_keys.clear();
        let prev_root = mem::replace(&mut self.root, Node::Empty);
        self.drop_inner(prev_root);
        self.root = self.recover_from_db(&root_hash)?;
        Ok(root_hash)
    }

    fn encode_node(&self, n: Node) -> Vec<u8> {
        // Returns the hash value directly to avoid double counting.
        if let Node::Hash(hash_node) = n {
            return unsafe { hash_node.as_ref() }.hash.to_vec();
        }

        let data = self.encode_raw(n);
        // Nodes smaller than 32 bytes are stored inside their parent,
        // Nodes equal to 32 bytes are returned directly
        if data.len() < sha3::Keccak256::output_size() {
            data
        } else {
            let hash = sha3::Keccak256::digest(&data);
            self.cache.borrow_mut().insert(hash.to_vec(), data);

            self.gen_keys.borrow_mut().insert(hash.into());
            hash.to_vec()
        }
    }

    fn encode_raw(&self, n: Node) -> Vec<u8> {
        match n {
            Node::Empty => rlp::NULL_RLP.to_vec(),
            Node::Leaf(leaf) => {
                let leaf_ref = unsafe { leaf.as_ref() };

                let mut stream = RlpStream::new_list(2);
                stream.append(&leaf_ref.key.encode_compact());
                stream.append(&leaf_ref.value);
                stream.out().to_vec()
            }
            Node::Branch(branch) => {
                let branch_ref = unsafe { branch.as_ref() };

                let mut stream = RlpStream::new_list(17);
                for i in 0..16 {
                    let n = branch_ref.children[i].clone();
                    let data = self.encode_node(n);
                    if data.len() == sha3::Keccak256::output_size() {
                        stream.append(&data);
                    } else {
                        stream.append_raw(&data, 1);
                    }
                }

                match &branch_ref.value {
                    Some(v) => stream.append(v),
                    None => stream.append_empty_data(),
                };
                stream.out().to_vec()
            }
            Node::Extension(ext) => {
                let ext_ref = unsafe { ext.as_ref() };

                let mut stream = RlpStream::new_list(2);
                stream.append(&ext_ref.prefix.encode_compact());
                let data = self.encode_node(ext_ref.node.clone());
                if data.len() == sha3::Keccak256::output_size() {
                    stream.append(&data);
                } else {
                    stream.append_raw(&data, 1);
                }
                stream.out().to_vec()
            }
            Node::Hash(_hash) => unreachable!(),
        }
    }

    #[allow(clippy::only_used_in_recursion)]
    fn decode_node(&self, data: &[u8]) -> TrieResult<Node> {
        let r = Rlp::new(data);

        match r.prototype()? {
            Prototype::Data(0) => Ok(Node::Empty),
            Prototype::List(2) => {
                let key = r.at(0)?.data()?;
                let key = NibbleVec::from_compact(key.to_vec());

                if key.is_leaf() {
                    Ok(Node::from_leaf(key, r.at(1)?.data()?.to_vec()))
                } else {
                    let n = self.decode_node(r.at(1)?.as_raw())?;

                    Ok(Node::from_extension(key, n))
                }
            }
            Prototype::List(17) => {
                let mut nodes = empty_children();
                #[allow(clippy::needless_range_loop)]
                for i in 0..nodes.len() {
                    let rlp_data = r.at(i)?;
                    let n = self.decode_node(rlp_data.as_raw())?;
                    nodes[i] = n;
                }

                // The last element is a value node.
                let value_rlp = r.at(16)?;
                let value = if value_rlp.is_empty() {
                    None
                } else {
                    Some(value_rlp.data()?.to_vec())
                };

                Ok(Node::from_branch(nodes, value))
            }
            _ => {
                if r.is_data() && r.size() == sha3::Keccak256::output_size() {
                    eprintln!("PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP");
                    Ok(Node::from_hash(r.data()?.try_into().unwrap()))
                } else {
                    Err(TrieError::InvalidData)
                }
            }
        }
    }

    fn recover_from_db(&self, key: &[u8]) -> TrieResult<Node> {
        match self.db.get(key).map_err(|e| TrieError::DB(e.to_string()))? {
            Some(value) => Ok(self.decode_node(&value)?),
            None => Ok(Node::Empty),
        }
    }

    // fn recover_from_db_with_insert(&self, key: &[u8], root: Node, partial: &NibbleSlice) -> TrieResult<Node> {
    //     match self.db.get(key).map_err(|e| TrieError::DB(e.to_string()))? {
    //         Some(value) => {
    //             let decoded = self.decode_node(&value)?;
    //             self.insert_at(decoded, partial, )
    //             Ok(self.decode_node(&value)?)
    //         },
    //         None => Ok(Node::Empty),
    //     }
    // }

    fn cache_node(&self, n: Node) -> TrieResult<Vec<u8>> {
        match n {
            Node::Empty => Ok(rlp::NULL_RLP.to_vec()),
            Node::Leaf(leaf) => {
                let leaf_ref = unsafe { leaf.as_ref() };

                let mut stream = RlpStream::new_list(2);
                stream.append(&leaf_ref.key.encode_compact());
                stream.append(&leaf_ref.value);
                Ok(stream.out().to_vec())
            }
            Node::Branch(branch) => {
                let branch_ref = unsafe { branch.as_ref() };

                let mut stream = RlpStream::new_list(17);
                for i in 0..16 {
                    let n = branch_ref.children[i].clone();
                    let data = self.cache_node(n)?;
                    if data.len() == sha3::Keccak256::output_size() {
                        stream.append(&data);
                    } else {
                        stream.append_raw(&data, 1);
                    }
                }

                match &branch_ref.value {
                    Some(v) => stream.append(v),
                    None => stream.append_empty_data(),
                };
                Ok(stream.out().to_vec())
            }
            Node::Extension(ext) => {
                let ext_ref = unsafe { ext.as_ref() };

                let mut stream = RlpStream::new_list(2);
                stream.append(&ext_ref.prefix.encode_compact());
                let data = self.cache_node(ext_ref.node.clone())?;
                if data.len() == sha3::Keccak256::output_size() {
                    stream.append(&data);
                } else {
                    stream.append_raw(&data, 1);
                }
                Ok(stream.out().to_vec())
            }
            Node::Hash(hash_node) => {
                let hash = unsafe { hash_node.as_ref() }.hash;
                let next_node = self.recover_from_db(&hash)?;
                let data = self.cache_node(next_node)?;
                self.cache.borrow_mut().insert(hash.to_vec(), data);
                Ok(hash.to_vec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::distributions::Alphanumeric;
    use rand::seq::SliceRandom;
    use rand::{thread_rng, Rng};
    use sha3::Digest;
    use std::collections::{HashMap, HashSet};

    use super::{PatriciaTrie, Trie};
    use crate::db::{MemoryDB, DB};

    #[test]
    fn test_trie_insert() {
        let memdb = MemoryDB::new(true);
        let mut trie = PatriciaTrie::new(memdb);
        trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
        trie.insert(b"tswq".to_vec(), b"test2".to_vec()).unwrap();
        eprintln!("trie = {:#?}", trie.root);
    }

    #[test]
    fn test_trie_get() {
        let memdb = MemoryDB::new(true);
        let mut trie = PatriciaTrie::new(memdb);
        trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
        let v = trie.get(b"test").unwrap();

        assert_eq!(Some(b"test".to_vec()), v)
    }

    #[test]
    fn test_trie_random_insert() {
        let memdb = MemoryDB::new(true);
        let mut trie = PatriciaTrie::new(memdb);

        for _ in 0..1000 {
            let rand_str: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
            let val = rand_str.as_bytes();
            trie.insert(val.to_vec(), val.to_vec()).unwrap();

            let v = trie.get(val).unwrap();
            assert_eq!(v.map(|v| v.to_vec()), Some(val.to_vec()));
        }
    }

    #[test]
    fn test_trie_contains() {
        let memdb = MemoryDB::new(true);
        let mut trie = PatriciaTrie::new(memdb);
        trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
        assert!(trie.contains(b"test").unwrap());
        assert!(!trie.contains(b"test2").unwrap());
    }

    #[test]
    fn test_trie_remove() {
        let memdb = MemoryDB::new(true);
        let mut trie = PatriciaTrie::new(memdb);
        trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
        let removed = trie.remove(b"test").unwrap();
        assert!(removed)
    }

    #[test]
    fn test_trie_random_remove() {
        let memdb = MemoryDB::new(true);
        let mut trie = PatriciaTrie::new(memdb);

        for _ in 0..1000 {
            let rand_str: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
            let val = rand_str.as_bytes();
            trie.insert(val.to_vec(), val.to_vec()).unwrap();

            let removed = trie.remove(val).unwrap();
            assert!(removed);
        }
    }

    #[test]
    fn test_trie_from_root() {
        let memdb = MemoryDB::new(true);
        let root = {
            let mut trie = PatriciaTrie::new(memdb.clone());
            trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test1".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test2".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test23".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test33".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test44".to_vec(), b"test".to_vec()).unwrap();
            trie.root().unwrap()
        };

        let mut trie = PatriciaTrie::from(memdb.clone(), &root).unwrap();
        let v1 = trie.get(b"test33").unwrap();
        assert_eq!(Some(b"test".to_vec()), v1);
        let v2 = trie.get(b"test44").unwrap();
        assert_eq!(Some(b"test".to_vec()), v2);
        let root2 = trie.root().unwrap();
        assert_eq!(hex::encode(root), hex::encode(root2));
    }

    #[test]
    fn test_trie_from_root_and_insert() {
        let memdb = MemoryDB::new(true);
        let root = {
            let mut trie = PatriciaTrie::new(memdb.clone());
            trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test1".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test2".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test23".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test33".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test44".to_vec(), b"test".to_vec()).unwrap();
            trie.commit().unwrap()
        };

        let mut trie = PatriciaTrie::from(memdb.clone(), &root).unwrap();
        trie.insert(b"test55".to_vec(), b"test55".to_vec()).unwrap();
        trie.commit().unwrap();
        let v = trie.get(b"test55").unwrap();
        assert_eq!(Some(b"test55".to_vec()), v);
    }

    #[test]
    fn test_trie_from_root_and_delete() {
        let memdb = MemoryDB::new(true);
        let root = {
            let mut trie = PatriciaTrie::new(memdb.clone());
            trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test1".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test2".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test23".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test33".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test44".to_vec(), b"test".to_vec()).unwrap();
            trie.commit().unwrap()
        };

        let mut trie = PatriciaTrie::from(memdb.clone(), &root).unwrap();
        let removed = trie.remove(b"test44").unwrap();
        assert!(removed);
        let removed = trie.remove(b"test33").unwrap();
        assert!(removed);
        let removed = trie.remove(b"test23").unwrap();
        assert!(removed);
    }

    #[test]
    fn test_multiple_trie_roots() {
        let k0 = ethereum_types::H256::from_low_u64_le(0);
        let k1 = ethereum_types::H256::from_low_u64_le(1);
        let v = ethereum_types::H256::from_low_u64_le(0x1234);

        let root1 = {
            let memdb = MemoryDB::new(true);
            let mut trie = PatriciaTrie::new(memdb);
            trie.insert(k0.as_bytes().to_vec(), v.as_bytes().to_vec())
                .unwrap();
            trie.root().unwrap()
        };

        let root2 = {
            let memdb = MemoryDB::new(true);
            let mut trie = PatriciaTrie::new(memdb);
            trie.insert(k0.as_bytes().to_vec(), v.as_bytes().to_vec())
                .unwrap();
            trie.insert(k1.as_bytes().to_vec(), v.as_bytes().to_vec())
                .unwrap();
            trie.root().unwrap();
            trie.remove(k1.as_ref()).unwrap();
            trie.root().unwrap()
        };

        let root3 = {
            let memdb = MemoryDB::new(true);
            let mut trie1 = PatriciaTrie::new(memdb.clone());
            trie1
                .insert(k0.as_bytes().to_vec(), v.as_bytes().to_vec())
                .unwrap();
            trie1
                .insert(k1.as_bytes().to_vec(), v.as_bytes().to_vec())
                .unwrap();
            trie1.root().unwrap();
            let root = trie1.root().unwrap();
            let mut trie2 = PatriciaTrie::from(memdb.clone(), &root).unwrap();
            trie2.remove(k1.as_bytes()).unwrap();
            trie2.root().unwrap()
        };

        assert_eq!(root1, root2);
        assert_eq!(root2, root3);
    }

    #[test]
    fn test_delete_stale_keys_with_random_insert_and_delete() {
        let memdb = MemoryDB::new(true);
        let mut trie = PatriciaTrie::new(memdb);

        let mut rng = rand::thread_rng();
        let mut keys = vec![];
        for _ in 0..100 {
            let random_bytes: Vec<u8> = (0..rng.gen_range(2, 30))
                .map(|_| rand::random::<u8>())
                .collect();
            trie.insert(random_bytes.clone(), random_bytes.clone())
                .unwrap();
            keys.push(random_bytes.clone());
        }
        trie.commit().unwrap();
        let slice = &mut keys;
        slice.shuffle(&mut rng);

        for key in slice.iter() {
            trie.remove(key).unwrap();
        }
        trie.commit().unwrap();

        let empty_node_key = sha3::Keccak256::digest(&rlp::NULL_RLP);
        let value = trie.db.get(empty_node_key.as_ref()).unwrap().unwrap();
        assert_eq!(value, &rlp::NULL_RLP)
    }

    #[test]
    fn insert_full_branch() {
        let memdb = MemoryDB::new(true);
        let mut trie = PatriciaTrie::new(memdb);

        trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
        trie.insert(b"test1".to_vec(), b"test".to_vec()).unwrap();
        trie.insert(b"test2".to_vec(), b"test".to_vec()).unwrap();
        trie.insert(b"test23".to_vec(), b"test".to_vec()).unwrap();
        trie.insert(b"test33".to_vec(), b"test".to_vec()).unwrap();
        trie.insert(b"test44".to_vec(), b"test".to_vec()).unwrap();
        trie.root().unwrap();

        let v = trie.get(b"test").unwrap();
        assert_eq!(Some(b"test".to_vec()), v);
    }

    #[test]
    fn iterator_trie() {
        let memdb = MemoryDB::new(true);
        let root1;
        let mut kv = HashMap::new();
        kv.insert(b"test".to_vec(), b"test".to_vec());
        kv.insert(b"test1".to_vec(), b"test1".to_vec());
        kv.insert(b"test11".to_vec(), b"test2".to_vec());
        kv.insert(b"test14".to_vec(), b"test3".to_vec());
        kv.insert(b"test16".to_vec(), b"test4".to_vec());
        kv.insert(b"test18".to_vec(), b"test5".to_vec());
        kv.insert(b"test2".to_vec(), b"test6".to_vec());
        kv.insert(b"test23".to_vec(), b"test7".to_vec());
        kv.insert(b"test9".to_vec(), b"test8".to_vec());
        {
            let mut trie = PatriciaTrie::new(memdb.clone());
            let mut kv = kv.clone();
            kv.iter().for_each(|(k, v)| {
                trie.insert(k.clone(), v.clone()).unwrap();
            });
            root1 = trie.root().unwrap();

            trie.iter()
                .for_each(|(k, v)| assert_eq!(kv.remove(&k).unwrap(), v));
            assert!(kv.is_empty());
        }

        {
            let mut trie = PatriciaTrie::new(memdb.clone());
            let mut kv2 = HashMap::new();
            kv2.insert(b"test".to_vec(), b"test11".to_vec());
            kv2.insert(b"test1".to_vec(), b"test12".to_vec());
            kv2.insert(b"test14".to_vec(), b"test13".to_vec());
            kv2.insert(b"test22".to_vec(), b"test14".to_vec());
            kv2.insert(b"test9".to_vec(), b"test15".to_vec());
            kv2.insert(b"test16".to_vec(), b"test16".to_vec());
            kv2.insert(b"test2".to_vec(), b"test17".to_vec());
            kv2.iter().for_each(|(k, v)| {
                trie.insert(k.clone(), v.clone()).unwrap();
            });

            trie.root().unwrap();

            let mut kv_delete = HashSet::new();
            kv_delete.insert(b"test".to_vec());
            kv_delete.insert(b"test1".to_vec());
            kv_delete.insert(b"test14".to_vec());

            kv_delete.iter().for_each(|k| {
                trie.remove(k).unwrap();
            });

            kv2.retain(|k, _| !kv_delete.contains(k));

            trie.root().unwrap();
            trie.iter()
                .for_each(|(k, v)| assert_eq!(kv2.remove(&k).unwrap(), v));
            assert!(kv2.is_empty());
        }

        let trie = PatriciaTrie::from(memdb, &root1).unwrap();
        trie.iter()
            .for_each(|(k, v)| assert_eq!(kv.remove(&k).unwrap(), v));
        assert!(kv.is_empty());
    }
}
