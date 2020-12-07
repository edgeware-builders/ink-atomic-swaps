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

		#[ink(message, payable, selector = "0xCAFEBABE")]
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
			self.ids.insert(self.counter, id);
			self.reverse_ids.insert(id, self.counter);

			let mut buf = Vec::new();
			buf.extend_from_slice(&caller.encode());
			buf.extend_from_slice(&target.encode());
			buf.extend_from_slice(&hashed_proof.encode());
			buf.extend_from_slice(&amount.encode());
			let mut payment_hash = [0x00_u8; 32];
			ink_env::hash_bytes::<ink_env::hash::Blake2x256>(&buf[..], &mut payment_hash);
			self.pending_swaps.insert(self.counter, (
				caller,
				target,
				hashed_proof,
				lock_time,
				1,              // PaymentState::PaymentSent
				hash_algo,
				payment_hash,
			));

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
			let swap_opt = self.pending_swaps.get(&counter_id);
			assert!(swap_opt.is_some());
			let swap = swap_opt.unwrap();

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
		use super::*;
		use ink_env::{
			call,
			test,
		};
		use ink_lang as ink;
		use crate::atomic_swap::HashedProof;
		use scale::Encode;

		fn set_sender(sender: AccountId) {
			let callee = ink_env::account_id::<ink_env::DefaultEnvironment>()
				.unwrap_or([0x0; 32].into());
			test::push_execution_context::<ink_env::DefaultEnvironment>(
				sender,
				callee,
				1000000,
				1000000,
				test::CallData::new(call::Selector::new([0x00; 4])), // dummy
			);
		}

		fn default_accounts(
		) -> ink_env::test::DefaultAccounts<ink_env::DefaultEnvironment> {
			ink_env::test::default_accounts::<ink_env::DefaultEnvironment>()
				.expect("Off-chain environment should have been initialized already")
		}

		fn set_balance(account_id: AccountId, balance: Balance) {
			ink_env::test::set_account_balance::<ink_env::DefaultEnvironment>(
				account_id, balance,
			)
			.expect("Cannot set account balance");
		}

		fn get_balance(account_id: AccountId) -> Balance {
			ink_env::test::get_account_balance::<ink_env::DefaultEnvironment>(account_id)
				.expect("Cannot set account balance")
		}

		fn contract_id() -> AccountId {
			ink_env::test::get_current_contract_account_id::<ink_env::DefaultEnvironment>(
			)
			.expect("Cannot get contract id")
		}

		fn build_contract() -> AtomicSwaps {
			let accounts = default_accounts();
			set_sender(accounts.alice);
			set_balance(contract_id(), 0);
			AtomicSwaps::new()
		}

		fn create_hashed_proof(algo: SecretHashAlgo, secret: [u8; 32]) -> HashedProof {
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

		fn build_proposal_hash(sender: ink_env::AccountId, target: ink_env::AccountId, proof: HashedProof, amount: u128) -> [u8;32] {
			let mut buf = Vec::new();
			buf.extend_from_slice(&sender.encode());
			buf.extend_from_slice(&target.encode());
			buf.extend_from_slice(&proof.encode());
			buf.extend_from_slice(&amount.encode());
			let mut output = [0x00_u8; 32];
			ink_env::hash_bytes::<ink_env::hash::Blake2x256>(&buf[..], &mut output);
			output
		}

		#[ink::test]
		fn setup() {
			let contract = build_contract();
			assert_eq!(contract.counter, 0);
			let swap = contract.pending_swaps.get(&1);
			assert!(swap.is_none());
		}

		#[ink::test]
		fn flow() {
			let mut contract = build_contract();
			let accounts = default_accounts();
			set_sender(accounts.alice);
			set_balance(accounts.alice, 100);

			let amount = 10;
			let swap_id: [u8; 32] = [9; 32];
			let target = accounts.bob;

			let algo = SecretHashAlgo::Sha2x256;
			let secret: [u8; 32] = [1; 32];
			let hashed_proof = create_hashed_proof(algo, secret);
			let lock_time = 100u64;
			let hash_algo_inx = 0;

			let mut data = ink_env::test::CallData::new(ink_env::call::Selector::new([
				0xCA, 0xFE, 0xBA, 0xBE,
			]));
			data.push_arg(&accounts.alice);

			// Push the new execution context which sets Alice as caller and
			// the `mock_transferred_balance` as the value which the contract
			// will see as transferred to it.
			ink_env::test::push_execution_context::<ink_env::DefaultEnvironment>(
				accounts.alice,
				contract_id(),
				1000000,
				amount,
				data,
			);

			contract.create_swap(
				swap_id,
				target,
				hashed_proof,
				lock_time,
				hash_algo_inx,
			);

			assert_eq!(get_balance(accounts.alice), 90);

			let swap = contract.pending_swaps.get(&1);
			assert_eq!(test::recorded_events().count(), 1);
			assert!(swap.is_some());
			let unwrapped = swap.unwrap();
			assert_eq!(unwrapped.0, accounts.alice);
			assert_eq!(unwrapped.1, accounts.bob);
			assert_eq!(unwrapped.2, hashed_proof);
			assert_eq!(unwrapped.3, lock_time);
			assert_eq!(unwrapped.4, 1);
			assert_eq!(unwrapped.5, 0);
			assert_eq!(unwrapped.6, build_proposal_hash(
				accounts.alice,
				accounts.bob,
				hashed_proof,
				amount,
			));
		}
	}
}
