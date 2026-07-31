fn main() {
    let key = oetp_core::signing::generate_keypair();
    let sk_hex = hex::encode(key.to_bytes());
    let pk_hex = hex::encode(key.verifying_key().to_bytes());
    println!("{}", sk_hex);
    println!("{}", pk_hex);
}
