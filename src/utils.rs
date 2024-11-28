use ark_ff::Field;

/// helper function to fold a polynomial into its odd and even component and
/// add them back up by multiplying the odd component with a random value
pub fn fold_polynomial<E: Field>(poly: &[E], random_value: E) -> Vec<E> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fq2 as F;

    // TODO: figure out how to not use BLS curve
    #[test]
    fn test_fold_polynomial() {
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
