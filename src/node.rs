use std::fmt::{Debug, Formatter};
use std::ptr::NonNull;

use crate::nibbles::NibbleVec;

#[derive(Clone)]
pub enum Node {
    Empty,
    Leaf(NonNull<LeafNode>),
    Extension(NonNull<ExtensionNode>),
    Branch(NonNull<BranchNode>),
    Hash(NonNull<HashNode>),
}

unsafe impl Send for Node {}

unsafe impl Sync for Node {}

impl Debug for Node {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        unsafe {
            match self {
                Node::Empty => {
                    write!(f, "empty")
                }
                Node::Leaf(leaf) => {
                    write!(f, "{:#?}", leaf.as_ref())
                }
                Node::Extension(ext) => {
                    write!(f, "{:#?}", ext.as_ref())
                }
                Node::Branch(b) => {
                    write!(f, "{:#?}", b.as_ref())
                }
                Node::Hash(h) => {
                    write!(f, "{:#?}", h.as_ref())
                }
            }
        }
    }
}

impl Node {
    pub fn from_leaf(key: NibbleVec, value: Vec<u8>) -> Self {
        let ptr = Box::leak(Box::new(LeafNode { key, value }));
        Node::Leaf(NonNull::new(ptr).unwrap())
    }

    pub fn from_branch(children: [Node; 16], value: Option<Vec<u8>>) -> Self {
        let ptr = Box::leak(Box::new(BranchNode { children, value }));
        Node::Branch(NonNull::new(ptr).unwrap())
    }

    pub fn from_extension(prefix: NibbleVec, node: Node) -> Self {
        let ptr = Box::leak(Box::new(ExtensionNode { prefix, node }));
        Node::Extension(NonNull::new(ptr).unwrap())
    }

    pub fn from_hash(hash: [u8; 32]) -> Self {
        eprintln!("hash = {:02x?}", hash);
        let ptr = Box::leak(Box::new(HashNode { hash }));
        Node::Hash(NonNull::new(ptr).unwrap())
    }
}

#[derive(Debug)]
pub struct LeafNode {
    pub key: NibbleVec,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub struct BranchNode {
    pub children: [Node; 16],
    pub value: Option<Vec<u8>>,
}

impl BranchNode {
    pub(crate) fn insert(&mut self, i: usize, n: Node) {
        debug_assert!((0usize..=16).contains(&i));
        if i == 16 {
            // Leaf node is substituted by branch node, so we deallocate a leaf node
            if let Node::Leaf(mut leaf) = n {
                let leaf_owned = unsafe { Box::from_raw(leaf.as_mut()) };
                self.value = Some(leaf_owned.value);
            } else {
                panic!("The n must be leaf node")
            }
        } else {
            self.children[i] = n
        }
    }
}

#[derive(Debug)]
pub struct ExtensionNode {
    pub prefix: NibbleVec,
    pub node: Node,
}

#[derive(Debug)]
pub struct HashNode {
    pub hash: [u8; 32],
}

pub fn empty_children() -> [Node; 16] {
    [
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
    ]
}
