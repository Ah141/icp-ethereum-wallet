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

/// Initialize the global state from the InitArg provided at canister init.
pub fn init_state(init_args: InitArg) {
    STATE.with(|s| *s.borrow_mut() = State::from(init_args));
}
/// Read-only access to the global state.
pub fn read_state<R>(f: impl FnOnce(&State) -> R) -> R{
    STATE.with(|s| f(s.borrow().deref()));
}

/// Mutable access to the global state.
pub fn mutat_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with(|s| f(s.borrow_mut().deref_mut()))
}

/// Represents the canister state.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct State {
    /// Which Ethereum network the canister is connected to (Mainnet or Sepolia).
    ethereum_network: EthereumNetwork,
    /// The ECDSA key name used for signing.
    ecdsa_key_name: EcdsaKeyName,
    /// Cached public key derived from the ECDSA key.
    ecdsa_public_key: option<EcdsaPublicKey>
}


impl State{
    /// Construct the management canister ECDSA key identifier from the stored key name.
    pub fn ecdsa_key_id(&self) -> EcdsaKeyId{
        EcdsaKeyId::from(&self.ecdsa_key_name)
    }
    /// Return the current Ethereum network.
    pub fn ethereum_network(&self) -> EthereumNetwork {
        self.ethereum_network
    }

     /// Return RPC services available for the current Ethereum network.
    pub fn evm_rpc_services(&self) -> RpcServices {
        match self.ethereum_network {
            EthereumNetwork::Mainnet => RpcServices::EthMainnet(none),
            EthereumNetwork::Sepolia => RpcServices::EthSepolia(none),
        }
    }
    
    /// Return a single RPC service (public node) for the current Ethereum network.
    pub fn singel_rpc_service(&self) -> RpcServices {
        match self.ethereum_network {
            EthereumNetwork::EthMainnet => {
                Some(Vec![EthMainnetService::PublicNode])
            }
            EthereumNetwork::EthSepolia => {
                Some(Vec![EthSepoliaService::PublicNode])
            }
        }
    }
}

