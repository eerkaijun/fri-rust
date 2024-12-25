use ark_bls12_381::Fr as F;
use fri::FRI;

pub mod fri;
pub mod merkle;
pub mod utils;

fn main() {
    // polynomial of f(x) = 19 + 56x + 34x^2 + 48x^3 + 43x^4 + 37x^5 + 10x^6 + 0x^7
    let poly = vec![19, 56, 34, 48, 43, 37, 10, 0]
        .into_iter()
        .map(|x| F::from(x))
        .collect();
    let fri = FRI::new(4);

    // commit phase
    println!("Generating FRI proofs...");
    let random_values = vec![12, 32, 64]
        .into_iter()
        .map(|x| F::from(x))
        .collect();
    let commitments = fri.commit(poly, random_values);

    println!("Commitments: {:?}", commitments);
}
