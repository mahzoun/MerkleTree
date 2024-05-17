mod merkle_tree;

use merkle_tree::MerkleTree;

fn main() {
    let data = vec![
        b"hello".to_vec(),
        b"world".to_vec(),
        b"this".to_vec(),
        b"is".to_vec(),
        b"merkle".to_vec(),
        b"tree".to_vec(),
    ];

    let tree = MerkleTree::new(data);

    println!("Root hash: {:?}", tree.root_hash());

    if let Some(proof) = tree.generate_proof(0) {
        println!("Proof for first leaf: {:?}", proof);
        let leaf = b"hello".to_vec();
        let root_hash = hex::decode(tree.root_hash().unwrap()).unwrap();
        let result = MerkleTree::verify_proof(&root_hash, &proof, leaf, 0);
        println!("Verification result: {}", result);
    } else {
        println!("Could not generate proof");
    }
}
