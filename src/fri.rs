use crate::merkle::{self, MerkleTree};
use crate::utils::{fold_polynomial, get_evaluation_points, get_omega};
use ark_ff::PrimeField;

pub struct FRI<E: PrimeField> {
    blowup_factor: u64,
    prover: Prover<E>,
    verifier: Verifier<E>,
}

/// Items that need to be stored by the prover
pub struct Prover<E: PrimeField> {
    // Initial polynomial and all the intermediate folded polynomials (in coefficient form)
    polys: Vec<Vec<E>>,
    // Merkle trees constructed from initial polynomial and intermediate folder polynomials (in evaluation form)
    merkle_trees: Vec<MerkleTree<E>>,
}

impl<E: PrimeField> Default for Prover<E> {
    fn default() -> Self {
        Self {
            polys: Vec::new(),
            merkle_trees: Vec::new(),
        }
    }
}

/// Items that need to be stored by the verifier
pub struct Verifier<E: PrimeField> {
    // Random values that are sent to the prover during the commit phase (in reality this would be fiat shamir)
    random_values: Vec<E>,
}

impl<E: PrimeField> Default for Verifier<E> {
    fn default() -> Self {
        Self {
            random_values: Vec::new(),
        }
    }
}

impl<E: PrimeField> FRI<E> {
    pub fn new(blowup_factor: u64) -> Self {
        Self {
            blowup_factor,
            prover: Prover::default(),
            verifier: Verifier::default(),
        }
    }

    pub fn commit(mut self, mut poly: Vec<E>, random_values: Vec<E>) -> Vec<E> {
        // vector that stores the commitment at each round
        let mut commitments: Vec<E> = vec![];

        // vector that stores the initial polynomial and intermediate folded polynomials
        // NOTE: doesn't include the final plaintext
        let mut polys: Vec<Vec<E>> = vec![];

        // vector that stores the merkle tree for the initial polynomial and folded polynomials
        let mut merkle_trees: Vec<MerkleTree<E>> = vec![];

        // roots of unity point
        let mut omega = get_omega(&poly);

        // fold the polynomial until it's a constant polynomial
        let mut random_value_idx = 0;
        while poly.len() > 1 {
            // at each round, commit to the merkle tree
            let eval_points = get_evaluation_points(&poly, omega, self.blowup_factor);
            let merkle_tree = MerkleTree::new(eval_points);
            let merkle_root = merkle_tree.root;
            commitments.push(merkle_root);
            polys.push(poly.clone());
            merkle_trees.push(merkle_tree);

            // TODO: better error handling if random_values length is insufficient
            poly = fold_polynomial(&poly, random_values[random_value_idx]);
            random_value_idx += 1;
            // evaluation points for the next round are used using the square of current roots of unity point
            omega = omega.pow([2]);
        }

        // the final commitment is a plaintext
        assert_eq!(poly.len(), 1);
        commitments.push(poly[0]);

        // prover store the information needed
        self.prover = Prover {
            polys,
            merkle_trees,
        };

        // verifier stores the information needed
        // TODO: move this somewhere else
        self.verifier = Verifier { random_values };

        commitments
    }

    pub fn query() {}

    pub fn verify() {}
}
