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

