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
