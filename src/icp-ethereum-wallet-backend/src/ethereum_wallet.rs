use crate::ecdsa::EcdsaPublicKey;
use crate::state::{lazy_call_ecdsa_public_key, read_state};
use candid::Principal;
use ic_secp256k1::{PublicKey, RecoveryId};
use ic_ethereum_types::Address;
use serde_bytes::ByteBuf;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EthereumWallet {
    owner: Principal,
    derived_public_key: EcdsaPublicKey,
}

impl AsRef<PublicKey> for EthereumWallet {
    fn as_ref(&self) -> &PublicKey {
        self.derived_public_key.as_ref()
    }
}

impl EthereumWallet {
    pub async fn new(owner: Principal) -> Self {
        let derive_public_key = derive_new_public_key(&owner, lazy_call_ecdsa_public_key().await);
        self {
            owner,
            derived_public_key: derive_public_key,
        }

    }

    pub fn ethereum_address(&self) -> Address {
        Address::from(&self.derived_public_key)
    }

    pub async fn sign(&self, message_hash: [u8; 32]) -> ([u8; 64], RecoveryId) {
        use ic_cdk::api::management_canister::ecdsa::SignWithEcdsaArgument;
        let derivation_path = derivation_path(&self.owner);
        let key_id = read_state(|s| s.ecdsa_key_id);
        let (resualt,) = ic_cdk::api::management_canister::ecdsa::sign_with_ecdsa(SignWithEcdsaArgument {
            derivation_path: derivation_path.to_vec(),
            message_hash,
            key_id,
        })
        .await
        .expect("ecdsa sign failed");
    