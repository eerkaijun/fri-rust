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
