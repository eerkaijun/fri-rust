use crate::utils::{fold_polynomial, get_evaluation_points, get_merkle_root};
use ark_ff::PrimeField;

pub struct FRI {
    blowup_factor: u64,
}

impl FRI {
    pub fn new(blowup_factor: u64) -> Self {
        Self { blowup_factor }
    }

    pub fn prove() {}

    pub fn commit<E: PrimeField>(self, mut poly: Vec<E>, random_values: &[E]) -> Vec<E> {
        // vector that stores the commitment at each round
        let mut commitments: Vec<E> = vec![];

        // fold the polynomial until it's a constant polynomial
        let mut random_value_idx = 0;
        while poly.len() > 1 {
            // at each round, commit to the merkle tree
            let eval_points = get_evaluation_points(&poly, self.blowup_factor);
            let merkle_root = get_merkle_root(&eval_points);
            commitments.push(merkle_root);

            // TODO: better error handling if random_values length is insufficient
            poly = fold_polynomial(&poly, random_values[random_value_idx]);
            random_value_idx += 1;            
        }

        // the final commitment is a plaintext
        assert_eq!(poly.len(), 1);
        commitments.push(poly[0]);

        commitments
    }

    pub fn query() {}

    pub fn verify() {}
}
