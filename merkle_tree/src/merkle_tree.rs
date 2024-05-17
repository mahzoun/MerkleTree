use sha2::{Sha256, Digest};
use std::fmt;

#[derive(Debug, Clone)]
pub struct MerkleTree {
    root: Option<MerkleNode>,
}

#[derive(Debug, Clone)]
struct MerkleNode {
    hash: Vec<u8>,
    left: Option<Box<MerkleNode>>,
    right: Option<Box<MerkleNode>>,
}

impl fmt::Display for MerkleNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", sha2::Sha256::digest(&self.hash))
    }
}

impl MerkleTree {
    pub fn new(data: Vec<Vec<u8>>) -> Self {
        let leaves = data.into_iter().map(MerkleNode::new_leaf).collect();
        let root = MerkleTree::build_tree(leaves);
        MerkleTree { root }
    }

    fn build_tree(mut nodes: Vec<MerkleNode>) -> Option<MerkleNode> {
        while nodes.len() > 1 {
            let mut next_level = vec![];

            for chunk in nodes.chunks(2) {
                let left = chunk[0].clone();
                let right = if chunk.len() == 2 { chunk[1].clone() } else { chunk[0].clone() };
                next_level.push(MerkleNode::new_internal(left, right));
            }

            nodes = next_level;
        }

        nodes.into_iter().next()
    }

    pub fn root_hash(&self) -> Option<String> {
        self.root.as_ref().map(|node| format!("{:x}", Sha256::digest(&node.hash)))
    }
}

impl MerkleNode {
    fn new_leaf(data: Vec<u8>) -> Self {
        let hash = Sha256::digest(&data).to_vec();
        MerkleNode { hash, left: None, right: None }
    }

    fn new_internal(left: MerkleNode, right: MerkleNode) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&left.hash);
        hasher.update(&right.hash);
        let hash = hasher.finalize().to_vec();
        MerkleNode { hash, left: Some(Box::new(left)), right: Some(Box::new(right)) }
    }
}


impl MerkleTree {
    pub fn generate_proof(&self, index: usize) -> Option<Vec<Vec<u8>>> {
        self.root.as_ref().and_then(|root| {
            let mut proof = vec![];
            MerkleTree::generate_proof_rec(&root, index, &mut proof, 0)?;
            Some(proof)
        })
    }

    fn generate_proof_rec(node: &MerkleNode, index: usize, proof: &mut Vec<Vec<u8>>, current_index: usize) -> Option<usize> {
        if node.left.is_none() && node.right.is_none() {
            return Some(current_index + 1);
        }

        let left = node.left.as_ref().unwrap();
        let right = node.right.as_ref().unwrap();

        let next_index = if index < current_index + 2.pow(left.depth() as u32) {
            proof.push(right.hash.clone());
            MerkleTree::generate_proof_rec(&left, index, proof, current_index)?
        } else {
            proof.push(left.hash.clone());
            MerkleTree::generate_proof_rec(&right, index, current_index + 2.pow(left.depth() as u32))?
        };

        Some(next_index)
    }

    pub fn verify_proof(root_hash: &[u8], proof: &[Vec<u8>], leaf: Vec<u8>, index: usize) -> bool {
        let mut computed_hash = Sha256::digest(&leaf).to_vec();
        let mut current_index = index;

        for sibling_hash in proof {
            let mut hasher = Sha256::new();
            if current_index % 2 == 0 {
                hasher.update(&computed_hash);
                hasher.update(sibling_hash);
            } else {
                hasher.update(sibling_hash);
                hasher.update(&computed_hash);
            }
            computed_hash = hasher.finalize().to_vec();
            current_index /= 2;
        }

        computed_hash == root_hash
    }
}

impl MerkleNode {
    fn depth(&self) -> usize {
        match (&self.left, &self.right) {
            (Some(left), Some(right)) => 1 + usize::max(left.depth(), right.depth()),
            _ => 0,
        }
    }
}


