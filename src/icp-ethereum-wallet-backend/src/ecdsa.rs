use ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyResponse;
use ic_secp256k1::{PublicKey, DerivationPath};
use ic_ethereum_types::Address;

/// Representation of an ECDSA public key returned from the IC.
/// Stores both the raw public key and its associated chain code.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EcdsaPublicKey {
    public_key: PublicKey,
    chain_code: Vec<u8>,
}

impl EcdsaPublicKey {
    /// Derives a new public key from the current one using a given derivation path.
    /// This mimics hierarchical deterministic wallet derivation (BIP-32 style).
    pub fn derive_new_public_key(&self, derivation_path: &DerivationPath) -> Self {
        // derive_subkey returns a tuple (derived_key, new_chain_code)
        let (dk, cc) = self.public_key.derive_subkey(derivation_path);
        Self {
            public_key: dk,
            chain_code: cc.to_vec(),
        }
    }
}

impl AsRef<PublicKey> for EcdsaPublicKey {
    /// Allows `&EcdsaPublicKey` to be automatically converted into `&PublicKey`.
    fn as_ref(&self) -> &PublicKey {
        &self.public_key
    }
}

impl From<EcdsaPublicKeyResponse> for EcdsaPublicKey {
    /// Converts an `EcdsaPublicKeyResponse` (from IC management canister)
    /// into a usable `EcdsaPublicKey` struct.
    fn from(value: EcdsaPublicKeyResponse) -> Self {
        let public_key =
            PublicKey::deserialize_sec1(&value.public_key).expect("Failed to deserialize public key");

        EcdsaPublicKey {
            public_key,
            chain_code: value.chain_code,
        }
    }
}

impl From<&EcdsaPublicKey> for Address {
    /// Converts an `EcdsaPublicKey` into an Ethereum `Address`.
    /// Uses the standard Ethereum rule: Keccak256(uncompressed_pubkey[1..]) → last 20 bytes.
    fn from(value: &EcdsaPublicKey) -> Self {
        // Serialize public key in uncompressed SEC1 format (65 bytes)
        let key_bytes = value.as_ref().serialize_sec1(false);

        // Sanity check: first byte must be 0x04 for uncompressed keys
        debug_assert_eq!(key_bytes[0], 0x04, "Uncompressed public key should start with 0x04");

        // Hash the X and Y coordinates with Keccak256
        let hash = ic_sha3::Keccak256::hash(&key_bytes[1..]);

        // Take the last 20 bytes of the hash as the Ethereum address
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..32]);

        Address::new(addr)
    }
}
