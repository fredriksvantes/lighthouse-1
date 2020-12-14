use crate::test_utils::TestRandom;
use crate::*;

use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{BitVector, ByteList, ByteVector, VariableList};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// The body of a `BeaconChain` block, containing operations.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
#[serde(bound = "T: EthSpec")]
pub struct BeaconBlockBody<T: EthSpec> {
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    pub graffiti: Graffiti,
    pub proposer_slashings: VariableList<ProposerSlashing, T::MaxProposerSlashings>,
    pub attester_slashings: VariableList<AttesterSlashing<T>, T::MaxAttesterSlashings>,
    pub attestations: VariableList<Attestation<T>, T::MaxAttestations>,
    pub deposits: VariableList<Deposit, T::MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, T::MaxVoluntaryExits>,

    // Phase 1
    pub chunk_challenges: VariableList<CustodyChunkChallenge<T>, T::MaxCustodyChunkChallenges>,
    pub chunk_challenge_responses:
        VariableList<CustodyChunkResponse<T>, T::MaxCustodyChunkChallengeResponses>,
    pub custody_key_reveals: VariableList<CustodyKeyReveal, T::MaxCustodyKeyReveals>,
    pub early_derived_secret_reveals:
        VariableList<EarlyDerivedSecretReveal, T::MaxEarlyDerivedSecretReveals>,
    pub custody_slashings: VariableList<SignedCustodySlashing<T>, T::MaxCustodySlashings>,
    pub shard_transitions: FixedVector<ShardTransition<T>, T::MaxShards>,
    pub light_client_bits: BitVector<T::LightClientCommitteeSize>,
    pub light_client_signature: Signature,
}

impl<T: EthSpec> Default for BeaconBlockBody<T> {
    fn default() -> Self {
        BeaconBlockBody {
            randao_reveal: Signature::empty(),
            light_client_signature: Signature::empty(),
            ..Default::default()
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
#[serde(bound = "T: EthSpec")]
pub struct CustodyChunkChallenge<T: EthSpec> {
    pub responder_index: u64,
    pub shard_transition: ShardTransition<T>,
    pub attestation: Attestation<T>,
    pub data_index: u64,
    pub chunk_index: u64,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct CustodyChunkResponse<T: EthSpec> {
    pub challenge_index: u64,
    pub chunk_index: u64,
    pub chunk: ByteVector<T::BytesPerCustodyChunk>,
    pub branch: FixedVector<Hash256, T::CustodyResponseDepthInc>,
}

// TODO: impl TestRandom for ByteVector
impl<T: EthSpec> TestRandom for CustodyChunkResponse<T> {
    fn random_for_test(_rng: &mut impl RngCore) -> Self {
        Self {
            challenge_index: Default::default(),
            chunk_index: Default::default(),
            chunk: Default::default(),
            branch: Default::default(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct CustodyKeyReveal {
    pub revealer_index: u64,
    pub reveal: Signature,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct EarlyDerivedSecretReveal {
    pub revealed_index: u64,
    pub epoch: Epoch,
    pub reveal: Signature,
    pub masker_index: u64,
    pub mask: Hash256,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
#[serde(bound = "T: EthSpec")]
pub struct SignedCustodySlashing<T: EthSpec> {
    pub message: CustodySlashing<T>,
    pub signature: Signature,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(bound = "T: EthSpec")]
pub struct CustodySlashing<T: EthSpec> {
    pub data_index: u64,
    pub malefactor_index: u64,
    pub malefactor_secret: Signature,
    pub whistleblower_index: u64,
    pub shard_transition: ShardTransition<T>,
    pub attestation: Attestation<T>,
    pub data: ByteList<T::MaxShardBlockSize>,
}

// TODO: impl TestRandom for ByteList
impl<T: EthSpec> TestRandom for CustodySlashing<T> {
    fn random_for_test(_rng: &mut impl RngCore) -> Self {
        Self {
            data_index: Default::default(),
            malefactor_index: Default::default(),
            malefactor_secret: Signature::empty(),
            whistleblower_index: Default::default(),
            shard_transition: Default::default(),
            attestation: Default::default(),
            data: ByteList::with_capacity(T::MaxShardBlockSize::to_usize())
                .unwrap(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct ShardState {
    pub slot: Slot,
    pub gasprice: u64,
    pub latest_block_root: H256,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
#[serde(bound = "T: EthSpec")]
pub struct ShardTransition<T: EthSpec> {
    pub start_slot: Slot,
    pub shard_block_lengths: VariableList<u64, T::MaxShardBlocksPerAttestation>,
    pub shard_data_roots: VariableList<H256, T::MaxShardBlocksPerAttestation>,
    pub shard_states: VariableList<ShardState, T::MaxShardBlocksPerAttestation>,
    pub proposer_signature_aggregate: Signature,
}

impl<T: EthSpec> Default for ShardTransition<T> {
    fn default() -> Self {
        ShardTransition {
            proposer_signature_aggregate: Signature::empty(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BeaconBlockBody<MainnetEthSpec>);
}
