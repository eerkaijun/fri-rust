use crate::merkle::MerkleTree;
use crate::utils::{fold_polynomial, get_evaluation_points, get_omega};
use ark_ff::PrimeField;

pub struct FRI {
    blowup_factor: u64,
}

impl FRI {
    pub fn new(blowup_factor: u64) -> Self {
        Self { blowup_factor }
    }

    pub fn prove() {}

    pub fn commit<E: PrimeField>(self, mut poly: Vec<E>, random_values: Vec<E>) -> Vec<E> {
        // vector that stores the commitment at each round
        let mut commitments: Vec<E> = vec![];

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

            // TODO: better error handling if random_values length is insufficient
            poly = fold_polynomial(&poly, random_values[random_value_idx]);
            random_value_idx += 1;
            // evaluation points for the next round are used using the square of current roots of unity point
            omega = omega.pow([2]);
        }

        // the final commitment is a plaintext
        assert_eq!(poly.len(), 1);
        commitments.push(poly[0]);

        commitments
    }

    pub fn query() {}

    pub fn verify() {}
}
