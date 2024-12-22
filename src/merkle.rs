use ark_ff::PrimeField;

pub struct MerkleTree<E: PrimeField> {
    pub leaves: Vec<E>,
    pub intermediate_nodes: Vec<Vec<E>>,
    pub root: E,
}

impl<E: PrimeField> MerkleTree<E> {
    pub fn new(leaves: Vec<E>) -> Self {
        let mut current_nodes = leaves.clone();
        let mut intermediate_nodes: Vec<Vec<E>> = vec![];

        while current_nodes.len() > 1 {
            let mut next_level = Vec::with_capacity(current_nodes.len() / 2);

            for chunk in current_nodes.chunks(2) {
                // hash two adjacent elements
                // TODO: find a hash function to use
                let node = chunk[0] + chunk[1];
                next_level.push(node);
            }

            current_nodes = next_level.clone();
            intermediate_nodes.push(next_level);
        }

        // return the root (or zero if input was empty)
        let root = current_nodes.first().cloned().unwrap_or_else(|| E::zero());

        Self {
            leaves,
            intermediate_nodes,
            root,
        }
    }

    // given the index of a leaf, return the sibling path of it to the root
    pub fn get_merkle_path(self, index: u64) -> Vec<E> {
        let mut path = Vec::new();
        let mut current_index = index;

        let mut all_nodes = Vec::new();
        all_nodes.push(self.leaves);
        all_nodes.extend(self.intermediate_nodes);

        for level in &all_nodes {
            // get sibling index - if current_index is even, add 1; if odd, subtract 1
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            // get the sibling node if it exists in the level
            if let Some(&sibling) = level.get(sibling_index as usize) {
                path.push(sibling);
            }

            // update current_index for next level up
            current_index /= 2;
        }

        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr as F;

    #[test]
    fn test_merkle_root() {
        // create a simple vector
        let poly: Vec<F> = vec![F::from(1u32), F::from(2u32), F::from(3u32), F::from(4u32)];

        let merkle_tree = MerkleTree::new(poly);
        let merkle_root = merkle_tree.root;

        // result should be hash( hash(1 || 2) || hash(3 || 4))
        assert_eq!(merkle_root, F::from(10u32));
    }

    #[test]
    fn test_merkle_path() {
        let poly: Vec<F> = vec![
            F::from(1u32),
            F::from(2u32),
            F::from(3u32),
            F::from(4u32),
            F::from(5u32),
            F::from(6u32),
            F::from(7u32),
            F::from(8u32),
        ];

        let merkle_tree = MerkleTree::new(poly);
        let merkle_path = merkle_tree.get_merkle_path(3);

        let expected_path = vec![
            F::from(3u32),
            F::from(3u32),  // hash(1 || 2)
            F::from(26u32), // hash(hash(5 || 6) || hash(7 || 8))
        ];

        assert_eq!(merkle_path, expected_path);
    }
}
