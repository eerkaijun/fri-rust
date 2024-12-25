use ark_ff::PrimeField;
use ark_std::log2;

/// helper function to evaluate polynomial at a point
pub fn evaluate<E: PrimeField>(poly: &[E], point: E) -> E {
    let mut value = E::ZERO;

    for i in 0..poly.len() {
        value += poly[i] * point.pow(&[i as u64]);
    }

    value
}

/// helper function to get the roots of unity of a polynomial
pub fn get_omega<E: PrimeField>(coeffs: &[E]) -> E {
    let mut coeffs = coeffs.to_vec();
    let n = coeffs.len() - 1;
    if !n.is_power_of_two() {
        let num_coeffs = coeffs.len().checked_next_power_of_two().unwrap();
        // pad the coefficients with zeros to the nearest power of two
        for i in coeffs.len()..num_coeffs {
            coeffs[i] = E::ZERO;
        }
    }

    let m = coeffs.len();
    let exp = log2(m);
    let mut omega = E::TWO_ADIC_ROOT_OF_UNITY;
    for _ in exp..E::TWO_ADICITY {
        omega.square_in_place();
    }
    omega
}

/// given a set of coefficients of a polynomial, evaluate at roots of unity domain
pub fn get_evaluation_points<E: PrimeField>(coeffs: &[E], omega: E, blowup_factor: u64) -> Vec<E> {
    let evaluation_size = coeffs.len() as u64 * blowup_factor;
    let mut evaluation_vec = vec![];
    for i in 0..evaluation_size {
        evaluation_vec.push(evaluate(coeffs, omega.pow([i])));
    }

    evaluation_vec
}

/// helper function to fold a polynomial into its odd and even component and
/// add them back up by multiplying the odd component with a random value
pub fn fold_polynomial<E: PrimeField>(poly: &[E], random_value: E) -> Vec<E> {
    // collect the odd coefficients
    let odd_poly: Vec<E> = poly.iter().skip(1).step_by(2).copied().collect();

    // collect the even coefficients
    let even_poly: Vec<E> = poly.iter().step_by(2).copied().collect();

    // we assume that poly will always be of degree 2^n, so number of coefficients will be even
    // odd_poly and even_poly has the same number of coefficients
    let folded_poly = even_poly
        .into_iter()
        .zip(odd_poly)
        .map(|(even_coeff, odd_coeff)| even_coeff + random_value * odd_coeff)
        .collect();
    folded_poly
}

/// helper function to get the merkle root given the element and its sibling elements
pub fn reconstruct_merkle_root<E: PrimeField>(element: E, merkle_path: Vec<E>) -> E {
    let mut accumulator = element;
    for sibling in merkle_path {
        // hash two adjacent elements
        // TODO: find a hash function to use
        accumulator += sibling;
    }
    accumulator
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr as F;
    use ark_ff::Field;
    use ark_std::UniformRand;

    // BLS12_381 curve uses a prime field
    #[test]
    fn test_fold_polynomial() {
        // sanity check that F is a prime field
        let mut rng = ark_std::test_rng();
        let a = F::rand(&mut rng);
        let modulus = F::MODULUS;
        assert_eq!(a.pow(&modulus), a);

        // create a simple polynomial with coefficients in Fp64
        let poly: Vec<F> = vec![
            F::from(1u32), // x^0
            F::from(2u32), // x^1
            F::from(3u32), // x^2
            F::from(4u32), // x^3
        ];

        let random_value = F::from(5u32);

        let folded = fold_polynomial(&poly, random_value);

        // for polynomial 1 + 2x + 3x^2 + 4x^3
        // even coefficients are [1, 3]
        // odd coefficients are [2, 4]
        // after folding with random value r:
        // result should be [(1 + 5*2), (3 + 5*4)]
        assert_eq!(folded.len(), 2);
        assert_eq!(folded[0], F::from(11u32));
        assert_eq!(folded[1], F::from(23u32));
    }
}
