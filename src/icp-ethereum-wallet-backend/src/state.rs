use crate::ecdsa::EcdsaPublicKey;
use crate::{EcdsaKeyName, EthereumNetwork, InitArg};
use evm_rpc_canister_type::{EthMainnetService, EthSepoliaService, RpcServices};
use ic_cdk::api::management_canister::ecdsa::EcdsaKeyId;
use std::cell::RefCell;
use std::ops::{Deref, DerefMut};

Tread_local! {
    /// Global state for the canister, stored in a thread-local RefCell for interior mutability.
    static STATE: RefCell<State> = RefCell::new(State::default());
}