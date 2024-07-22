use blake3::Hash;
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

struct PublicParams {
    p: BigUint,
    g: BigUint,
}

struct Proof {
    t: BigUint,
    s: BigUint,
}

fn setup() -> PublicParams {
    // Use smaller numbers for testing
    let p = BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16).unwrap();
    let g = BigUint::from(2u32);
    PublicParams { p, g }
}

fn generate_secret(params: &PublicParams) -> (BigUint, BigUint) {
    let mut rng = thread_rng();
    let x = rng.gen_biguint_range(&BigUint::from(1u32), &params.p);
    let y = params.g.modpow(&x, &params.p);
    (x, y)
}

fn prove(params: &PublicParams, x: &BigUint, y: &BigUint) -> Proof {
    let mut rng = thread_rng();
    let r = rng.gen_biguint_range(&BigUint::from(1u32), &params.p);
    let t = params.g.modpow(&r, &params.p);

    let c = calculate_challenge(params, y, &t);
    let s = (r + c * x) % (&params.p - 1u32);

    Proof { t, s }
}

fn verify(params: &PublicParams, y: &BigUint, proof: &Proof) -> bool {
    let c = calculate_challenge(params, y, &proof.t);
    let lhs = params.g.modpow(&proof.s, &params.p);
    let rhs = (&proof.t * y.modpow(&c, &params.p)) % &params.p;
    lhs == rhs
}

fn calculate_challenge(params: &PublicParams, y: &BigUint, t: &BigUint) -> BigUint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&params.g.to_bytes_be());
    hasher.update(&y.to_bytes_be());
    hasher.update(&t.to_bytes_be());
    let result = hasher.finalize();
    BigUint::from_bytes_be(result.as_bytes()) % (&params.p - 1u32)
}

fn main() {
    let params = setup();
    let (secret, public) = generate_secret(&params);

    println!("Secret: {}", secret);
    println!("Public: {}", public);
    println!("");
    let proof = prove(&params, &secret, &public);
    println!("Proof S: {}", proof.s);
    let is_valid = verify(&params, &public, &proof);

    println!("Proof valid: {}", is_valid);
}

