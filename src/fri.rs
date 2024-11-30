use crate::utils::fold_polynomial;
use ark_ff::PrimeField;

pub struct FRI {
    blowup_factor: u64,
}

impl FRI {
    pub fn new(blowup_factor: u64) -> Self {
        Self { blowup_factor }
    }

    pub fn prove() {}

    pub fn commit<E: PrimeField>(mut poly: Vec<E>, random_values: &[E]) {
        // fold the polynomial until it's a constant polynomial
        let mut random_value_idx = 0;
        while poly.len() > 1 {
            // TODO: better error handling if random_values length is insufficient
            poly = fold_polynomial(&poly, random_values[random_value_idx]);
            random_value_idx += 1;

            // TODO: at each round, commit to the merkle tree
        }
    }

    pub fn query() {}

    pub fn verify() {}
}
