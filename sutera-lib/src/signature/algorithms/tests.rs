use crate::signature::algorithms::SigningAlgorithm as _;

use super::macros::algorithm_tests;
use assert_matches::assert_matches;
use rand::rngs::StdRng;
use rand::SeedableRng;

algorithm_tests! {
    #[test]
    fn verify_correct_sign() {
        let mut rng = StdRng::seed_from_u64(0);
        let private_key = Algorithm::generate_private_key(&mut rng);
        let public_key = Algorithm::to_public_key(&private_key).unwrap();
        let data = b"hello, world!";
        let signature = Algorithm::sign(data, &private_key).unwrap();
        assert_matches!(Algorithm::verify(data, &signature, &public_key), Ok(true));
    }
}

algorithm_tests! {
    #[test]
    fn verify_unmatched_content() {
        let mut rng = StdRng::seed_from_u64(0);
        let private_key = Algorithm::generate_private_key(&mut rng);
        let public_key = Algorithm::to_public_key(&private_key).unwrap();
        let data = b"hello, world!";
        let signature = Algorithm::sign(data, &private_key).unwrap();
        assert_matches!(Algorithm::verify(b"broken content", &signature, &public_key), Ok(false));
    }
}

algorithm_tests! {
    #[test]
    fn verify_unmatched_signature() {
        let mut rng = StdRng::seed_from_u64(0);
        let private_key = Algorithm::generate_private_key(&mut rng);
        let public_key = Algorithm::to_public_key(&private_key).unwrap();
        let data = b"hello, world!";
        let fake_data = b"original!";
        let signature = Algorithm::sign(fake_data, &private_key).unwrap();
        assert_matches!(Algorithm::verify(data, &signature, &public_key), Ok(false));
    }
}

algorithm_tests! {
    #[test]
    fn verify_unmatched_public_key() {
        let mut rng = StdRng::seed_from_u64(0);
        let private_key = Algorithm::generate_private_key(&mut rng);
        let data = b"hello, world!";
        let signature = Algorithm::sign(data, &private_key).unwrap();
        let fake_public_key = Algorithm::to_public_key(&Algorithm::generate_private_key(&mut rng)).unwrap();
        assert_matches!(Algorithm::verify(data, &signature, &fake_public_key), Ok(false));
    }
}
