use ic_cdk::api::management_canister::ecdsa::EcdsapublickeyResponse;
use ic_secp256k1::{PublicKey, DerivationPath};
use ic_ethereum_types::Address;


#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EcdsaPublicKey{
    public_key: PublicKey,
    chin_code:vec<u8>,
}
