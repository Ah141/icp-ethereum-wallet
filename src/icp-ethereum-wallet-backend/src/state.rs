use crate::ecdsa::EcdsaPublicKey;
use crate::{EcdsaKeyName, EthereumNetwork, InitArg};
use evm_rpc_canister_type::{EthMainnetService, EthSepoliaService, RpcServices};
use ic_cdk::api::management_canister::ecdsa::EcdsaKeyId;
use std::cell::RefCell;
use std::ops::{Deref, DerefMut};

thread_local! {
    /// Global state for the canister, stored in a thread-local RefCell for interior mutability.
    static STATE: RefCell<State> = RefCell::new(State::default());
}


pub fn init_state(init_args: InitArg) {
    STATE.with(|s| *s.borrow_mut() = State::from(init_args));
}

pub fn read_state<R>(f: impl FnOnce(&State) -> R) -> R{
    STATE.with(|s| f(s.borrow().deref()));
}

pub fn mutat_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with(|s| f(s.borrow_mut().deref_mut()))
}