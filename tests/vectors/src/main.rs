// Test vectors for crosslink-profiles: the node's own derivations, with the crates it uses.
use rand::SeedableRng;
use std::hash::Hasher;
use zcash_transparent::keys::{AccountPrivKey, NonHardenedChildIndex, TransparentKeyScope};

fn finalizer_key_from_seed(seed: &[u8]) -> ed25519_zebra::SigningKey {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(seed);
    let mut rng = rand::rngs::StdRng::seed_from_u64(hasher.finish());
    ed25519_zebra::SigningKey::new(&mut rng)
}

fn main() {
    let entropies: Vec<[u8; 32]> = vec![[0u8; 32], core::array::from_fn(|i| i as u8), core::array::from_fn(|i| (255 - i * 7) as u8)];
    println!("[");
    for (n, e) in entropies.iter().enumerate() {
        let text = format!("Crosslink default finalizer identity seed {:?}", e);
        let sk = finalizer_key_from_seed(text.as_bytes());
        let vk = ed25519_zebra::VerificationKey::from(&sk);
        let pk: [u8; 32] = vk.into();
        let addr_sig = sk.sign(b"Zcash Crosslink Finalizer Address v1");
        let addr_sig_bytes: [u8; 64] = addr_sig.into();

        let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, e).unwrap();
        let seed64 = mnemonic.to_seed("");
        let apk = AccountPrivKey::from_seed(&zcash_protocol::consensus::TEST_NETWORK, &seed64[..32], zip32::AccountId::ZERO).unwrap();
        let mut tpubs = vec![];
        for i in 0..3u32 {
            let idx = NonHardenedChildIndex::from_index(i).unwrap();
            let p = apk.to_account_pubkey().derive_address_pubkey(TransparentKeyScope::EXTERNAL, idx).unwrap();
            let s = apk.derive_external_secret_key(idx).unwrap();
            let s2p = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &s);
            assert_eq!(p.serialize(), s2p.serialize());
            tpubs.push(format!("\"{}\"", hex::encode(p.serialize())));
        }
        println!(
            "  {{\"entropy\": \"{}\", \"seed_text\": {:?}, \"finalizer_pubkey\": \"{}\", \"address_sig\": \"{}\", \"mnemonic\": \"{}\", \"transparent_pubkeys\": [{}]}}{}",
            hex::encode(e), text, hex::encode(pk), hex::encode(addr_sig_bytes), mnemonic, tpubs.join(", "),
            if n + 1 < entropies.len() { "," } else { "" }
        );
    }
    // explicit_bft_key_seed: the string is used as-is
    for s in ["encapsulate-test-seed", "from"] {
        let sk = finalizer_key_from_seed(s.as_bytes());
        let pk: [u8; 32] = ed25519_zebra::VerificationKey::from(&sk).into();
        eprintln!("explicit {:?} -> {}", s, hex::encode(pk));
    }
    println!("]");
}
