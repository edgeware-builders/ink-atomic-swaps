#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

#[ink::contract]
mod atomic_swap {
    use scale::Encode;
    
    use ink_storage::{
        collections::{
            HashMap as StorageHashMap,
        },
        traits::{
            PackedLayout,
            SpreadLayout,
        },
    };

    pub type HashedProof = [u8; 32];
    pub type Secret = [u8; 32];
    pub type SwapId = [u8; 32];
    pub type PaymentHash = [u8; 32];
    pub type LockTime = u64;

    #[derive(scale::Encode, scale::Decode, SpreadLayout, PackedLayout)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            PartialEq,
            Eq,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub enum PaymentState {
        Uninitialized,
        PaymentSent,
        ReceivedSpent,
        SenderRefunded
    }

    #[derive(scale::Encode, scale::Decode, SpreadLayout, PackedLayout)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            PartialEq,
            Eq,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub enum SecretHashAlgo {
        Sha2x256,
        Keccak256,
        Blake2x256,
    }

    #[derive(scale::Encode, scale::Decode, SpreadLayout, PackedLayout)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            PartialEq,
            Eq,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub struct Payment {
        payment_hash: HashedProof,
        lock_time: u64,
        state: PaymentState,
        secret_hash_algo: SecretHashAlgo,
    }

    #[ink(event)]
    pub struct PaymentSent {
        #[ink(topic)]
        id: Vec<u8>,
    }

    #[ink(event)]
    pub struct PaymentClaimed {
        #[ink(topic)]
        id: Vec<u8>,
    }

    #[ink(event)]
    pub struct SenderRefunded {
        #[ink(topic)]
        id: Vec<u8>,
    }

    #[ink(storage)]
    #[cfg(not(feature = "ink-as-dependency"))]
    pub struct AtomicSwaps {
        counter: u64,
        reverse_ids: StorageHashMap<SwapId, u64>,
        ids: StorageHashMap<u64, SwapId>,
        pending_swaps: StorageHashMap<u64, (
            AccountId,      // 0 - creator 
            AccountId,      // 1 - target
            HashedProof,    // 2 - hash of secret
            LockTime,       // 3 - lock time to redeem swap
            u8,             // 4 - PaymentState
            u8,             // 5 - SecretHashAlgo
            PaymentHash,    // 6 - payment hash to check against
        )>,
    }

    // /// The error types.
    // #[derive(Debug, PartialEq, Eq, scale::Encode)]
    // #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    // pub enum Error {
    //     /// Returned if the transfer failed.
    //     TransferFailed,
    //     /// Insufficient funds to execute transfer.
    //     InsufficientFunds,
    //     /// Transfer failed because it would have brought the contract's
    //     /// balance below the subsistence threshold.
    //     /// This is necessary to keep enough funds in the contract to
    //     /// allow for a tombstone to be created.
    //     BelowSubsistenceThreshold,
    //     InvalidPaymentHash,
    // }

    impl AtomicSwaps {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                counter: 0,
                reverse_ids: StorageHashMap::new(),
                ids: StorageHashMap::new(),
                pending_swaps: StorageHashMap::new()
            }
        }

        /// Constructor that initializes the `bool` value to `false`.
        ///
        /// Constructors can delegate to other constructors.
        #[ink(constructor)]
        pub fn default() -> Self {
            Self::new()
        }

        /// Simply returns the current value of our `bool`.
        #[ink(message)]
        pub fn get(&self) -> bool {
            true
        }

        #[ink(message)]
        pub fn create_swap(
            &mut self,
            id: SwapId,
            target: AccountId,
            hashed_proof: HashedProof,
            lock_time: LockTime,
            hash_algo: u8,
        ) {
            let caller = Self::env().caller();
            let amount = Self::env().transferred_balance();
            self.counter += 1;
            self.ids[&self.counter] = id;
            self.reverse_ids[&id] = self.counter;

            let mut buf = Vec::new();
            buf.extend_from_slice(&caller.encode());
            buf.extend_from_slice(&target.encode());
            buf.extend_from_slice(&hashed_proof.encode());
            buf.extend_from_slice(&amount.encode());
            let mut payment_hash = [0x00_u8; 32];
            ink_env::hash_bytes::<ink_env::hash::Blake2x256>(&buf[..], &mut payment_hash);
            self.pending_swaps[&self.counter] = (
                caller,
                target,
                hashed_proof,
                lock_time,
                1,              // PaymentState::PaymentSent
                hash_algo,
                payment_hash,
            );

            Self::env().emit_event(
                PaymentSent { id: id.to_vec() }
            );
        }

        #[ink(message)]
        pub fn claim_swap(
            &mut self,
            id: SwapId,
            amount: Balance,
            secret: Secret,
            sender: AccountId,
        ) {
            let caller = Self::env().caller();
            let counter_id = self.reverse_ids[&id];
            let swap = self.pending_swaps[&counter_id];

            let algo = self.get_hash_algo(swap.5);
            let expected_hash = self.hash_using(algo, secret);

            let mut buf = Vec::new();
            buf.extend_from_slice(&sender.encode());
            buf.extend_from_slice(&caller.encode());
            buf.extend_from_slice(&expected_hash.encode());
            buf.extend_from_slice(&amount.encode());
            let mut payment_hash = [0x00_u8; 32];
            ink_env::hash_bytes::<ink_env::hash::Blake2x256>(&buf[..], &mut payment_hash);
 
            if payment_hash == swap.6 {
                self.pending_swaps[&counter_id].4 = 2;
                // TODO: remove unwrap, add error handling
                self.env().transfer(self.env().caller(), amount).unwrap();
                // .map_err(|err| {
                //     match err {
                //         ink_env::Error::BelowSubsistenceThreshold => {
                //             Error::BelowSubsistenceThreshold
                //         }
                //         _ => Error::TransferFailed,
                //     }
                // });
                Self::env().emit_event(
                    PaymentClaimed { id: id.to_vec() }
                );
            } else {
                
            }
        }

        pub fn refund_sender(
            &mut self,
            id: SwapId,
            target: AccountId,
            proof: HashedProof,
            amount: Balance,
        ) {
            let caller = Self::env().caller();
            let counter_id = self.reverse_ids[&id];
            let swap = self.pending_swaps[&counter_id];

            let payment_state = self.get_payment_state(swap.4);
            if payment_state == PaymentState::PaymentSent {
                let mut buf = Vec::new();
                buf.extend_from_slice(&caller.encode());
                buf.extend_from_slice(&target.encode());
                buf.extend_from_slice(&proof.encode());
                buf.extend_from_slice(&amount.encode());
                let mut payment_hash = [0x00_u8; 32];
                ink_env::hash_bytes::<ink_env::hash::Blake2x256>(&buf[..], &mut payment_hash);

                if payment_hash == swap.2 && swap.3 >= self.env().block_timestamp() {
                    self.pending_swaps[&counter_id].4 = 3;
                    // TODO: remove unwrap, add error handling
                    self.env().transfer(self.env().caller(), amount).unwrap();
                    // .map_err(|err| {
                    //     match err {
                    //         ink_env::Error::BelowSubsistenceThreshold => {
                    //             Error::BelowSubsistenceThreshold
                    //         }
                    //         _ => Error::TransferFailed,
                    //     }
                    // });
                    Self::env().emit_event(
                        SenderRefunded { id: id.to_vec() }
                    );
                }
            }
        }

        fn hash_using(&self, algo: SecretHashAlgo, secret: Secret) -> HashedProof {
            let mut output = [0x00_u8; 32];
            match algo {
                SecretHashAlgo::Sha2x256 => {
                    ink_env::hash_bytes::<ink_env::hash::Sha2x256>(&secret, &mut output);
                    output
                },
                SecretHashAlgo::Keccak256 => {
                    ink_env::hash_bytes::<ink_env::hash::Keccak256>(&secret, &mut output);
                    output
                },
                SecretHashAlgo::Blake2x256 => {
                    ink_env::hash_bytes::<ink_env::hash::Blake2x256>(&secret, &mut output);
                    output
                },
            }
        }

        fn get_hash_algo(&self, inx: u8) -> SecretHashAlgo {
            match inx {
                0 => SecretHashAlgo::Sha2x256,
                1 => SecretHashAlgo::Keccak256,
                2 => SecretHashAlgo::Blake2x256,
                _ => SecretHashAlgo::Sha2x256
            }
        }

        fn get_payment_state(&self, inx: u8) -> PaymentState {
            match inx {
                0 => PaymentState::Uninitialized,
                1 => PaymentState::PaymentSent,
                2 => PaymentState::ReceivedSpent,
                3 => PaymentState::SenderRefunded,
                _ => PaymentState::Uninitialized,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        

    }
}
