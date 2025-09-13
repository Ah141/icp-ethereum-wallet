use crate::ecdsa::EcdsaPublicKey; // Our wrapper around ECDSA public keys
use crate::state::{lazy_call_ecdsa_public_key, read_state}; // Utilities for accessing state and fetching public keys
use candid::Principal; // Identity type on the Internet Computer
use ic_secp256k1::{PublicKey, RecoveryId}; // Secp256k1 crypto primitives
use ic_ethereum_types::Address; // Ethereum address type (20 bytes)
use serde_bytes::ByteBuf; // For handling byte arrays in a structured way

// -----------------------------------------------------------------------------
// Struct representing an Ethereum wallet linked to a Principal (owner)
// -----------------------------------------------------------------------------
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EthereumWallet {
    owner: Principal,               // The canister/user that owns this wallet
    derived_public_key: EcdsaPublicKey, // Public key derived for this specific wallet
}

// Allow EthereumWallet to be referenced as a PublicKey
impl AsRef<PublicKey> for EthereumWallet {
    fn as_ref(&self) -> &PublicKey {
        self.derived_public_key.as_ref()
    }
}

impl EthereumWallet {
    // -------------------------------------------------------------------------
    // Create a new wallet for a given owner Principal
    // Fetches the canister's ECDSA public key (lazy), derives a per-owner key
    // -------------------------------------------------------------------------
    pub async fn new(owner: Principal) -> Self {
        let derived_public_key = derive_public_key(&owner, &lazy_call_ecdsa_public_key().await);
        Self {
            owner,
            derived_public_key,
        }
    }

    // -------------------------------------------------------------------------
    // Compute the Ethereum address (20-byte hash of public key)
    // -------------------------------------------------------------------------
    pub fn ethereum_address(&self) -> Address {
        Address::from(&self.derived_public_key)
    }

    // -------------------------------------------------------------------------
    // Sign a 32-byte message hash with ECDSA using the management canister
    // Returns the 64-byte signature and the RecoveryId
    // -------------------------------------------------------------------------
    pub async fn sign_with_ecdsa(&self, message_hash: [u8; 32]) -> ([u8; 64], RecoveryId) {
        use ic_cdk::api::management_canister::ecdsa::SignWithEcdsaArgument;

        // Derive path for this wallet (unique to owner)
        let derivation_path = derivation_path(&self.owner);
        // Get the ECDSA key id from state
        let key_id = read_state(|s| s.ecdsa_key_id());

        // Call the management canister to sign the message hash
        let (result,) =
            ic_cdk::api::management_canister::ecdsa::sign_with_ecdsa(SignWithEcdsaArgument {
                message_hash: message_hash.to_vec(),
                derivation_path,
                key_id,
            })
            .await
            .expect("failed to sign with ecdsa");

        // Ensure the signature is exactly 64 bytes (r,s components of secp256k1)
        let signature_length = result.signature.len();
        let signature = <[u8; 64]>::try_from(result.signature).unwrap_or_else(|_| {
            panic!(
                "BUG: invalid signature from management canister. Expected 64 bytes but got {} bytes",
                signature_length
            )
        });

        // Compute recovery ID so signature can be verified/recovered in Ethereum
        let recovery_id = self.compute_recovery_id(&message_hash, &signature);

        // If recovery id has a reduced x-coordinate (extremely rare), trap
        if recovery_id.is_x_reduced() {
            ic_cdk::trap("BUG: affine x-coordinate of r is reduced which is so unlikely to happen that it's probably a bug");
        }
        (signature, recovery_id)
    }

    // -------------------------------------------------------------------------
    // Compute the recovery ID from signature and message hash
    // Ensures the signature is valid, and attempts to recover public key
    // -------------------------------------------------------------------------
    fn compute_recovery_id(&self, message_hash: &[u8], signature: &[u8]) -> RecoveryId {
        use alloy_primitives::hex;

        // Verify the signature against the stored public key
        assert!(
            self.as_ref()
                .verify_signature_prehashed(message_hash, signature),
            "failed to verify signature prehashed, digest: {:?}, signature: {:?}, public_key: {:?}",
            hex::encode(message_hash),
            hex::encode(signature),
            hex::encode(self.as_ref().serialize_sec1(true)),
        );

        // Try to recover public key from signature and message hash
        self.as_ref()
            .try_recovery_from_digest(message_hash, signature)
            .unwrap_or_else(|e| {
                panic!(
                    "BUG: failed to recover public key {:?} from digest {:?} and signature {:?}: {:?}",
                    hex::encode(self.as_ref().serialize_sec1(true)),
                    hex::encode(message_hash),
                    hex::encode(signature),
                    e
                )
            })
    }
}

// -----------------------------------------------------------------------------
// Derive a new public key from canister’s ECDSA root public key
// This makes sure each Principal gets a unique sub-key
// -----------------------------------------------------------------------------
fn derive_public_key(owner: &Principal, public_key: &EcdsaPublicKey) -> EcdsaPublicKey {
    use ic_secp256k1::{DerivationIndex, DerivationPath};
    let derivation_path = DerivationPath::new(
        derivation_path(owner)
            .into_iter()
            .map(DerivationIndex)
            .collect(),
    );
    public_key
        .derive_new_public_key(&derivation_path)
}

// -----------------------------------------------------------------------------
// Create a derivation path based on:
//  - A schema version (to allow upgrades later)
//  - The owner principal ID (unique per user)
// -----------------------------------------------------------------------------
fn derivation_path(owner: &Principal) -> Vec<Vec<u8>> {
    const SCHEMA_V1: u8 = 1;
    [
        ByteBuf::from(vec![SCHEMA_V1]),           // first element: schema version
        ByteBuf::from(owner.as_slice().to_vec()), // second element: owner's principal as bytes
    ]
    .iter()
    .map(|x| x.to_vec())
    .collect()
}
