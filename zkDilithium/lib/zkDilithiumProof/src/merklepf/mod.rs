// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use log::debug;
use std::{time::Instant};
use winterfell::{
    math::{fields::f23201::BaseElement, log2, FieldElement, StarkField}, FieldExtension, HashFunction, ProofOptions, Prover, StarkProof, Trace, VerifierError
};

use crate::utils::poseidon_23_spec::{
    CYCLE_LENGTH as HASH_CYCLE_LEN, NUM_ROUNDS as NUM_HASH_ROUNDS,
    STATE_WIDTH as HASH_STATE_WIDTH, RATE_WIDTH as HASH_RATE_WIDTH,
    DIGEST_SIZE as HASH_DIGEST_WIDTH
};

mod air;
use air::MerkleAir;

mod prover;
use prover::MerkleProver;

use self::air::PublicInputs;

// CONSTANTS
// ================================================================================================

pub const STORAGE_START: usize = HASH_STATE_WIDTH*3;

pub(crate) fn prove(
    attributes: Vec<Vec<[BaseElement; HASH_DIGEST_WIDTH]>>,
    disclosed_indices: Vec<Vec<usize>>,
    comm: Vec<[BaseElement; HASH_RATE_WIDTH]>,
    nonce: Vec<[BaseElement; 12]>
) -> StarkProof {
        let options = ProofOptions::new(
            48, // number of queries
            4,  // blowup factor
            20,  // grinding factor
            HashFunction::Blake3_256,
            FieldExtension::Sextic,
            8,   // FRI folding factor
            128, // FRI max remainder length
        );
        debug!(
            "Generating proof for correctness of Merkle tree"
        );

        // create a prover
        let now = Instant::now();
        let prover = MerkleProver::new(options.clone(), attributes, disclosed_indices, comm, nonce);

        // generate execution trace
        let trace = prover.build_trace();

        let trace_width = trace.width();
        let trace_length = trace.length();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms \n",
            trace_width,
            log2(trace_length),
            now.elapsed().as_millis()
        );

        // generate the proof
        prover.prove(trace).unwrap()
    }

pub(crate) fn verify(proof: StarkProof, disclosed_attributes: Vec<Vec<[BaseElement; HASH_DIGEST_WIDTH]>>, indices: Vec<Vec<usize>>, num_of_attributes: Vec<usize>, comm: Vec<[BaseElement; HASH_RATE_WIDTH]>, nonce: Vec<[BaseElement; 12]>) -> Result<(), VerifierError> {
    let pub_inputs = PublicInputs{disclosed_attributes, indices, num_of_attributes, comm, nonce};
    winterfell::verify::<MerkleAir>(proof, pub_inputs)
}

pub(crate) fn verify_with_wrong_inputs(proof: StarkProof, disclosed_attributes: Vec<Vec<[BaseElement; HASH_DIGEST_WIDTH]>>, indices: Vec<Vec<usize>>, num_of_attributes: Vec<usize>, comm: Vec<[BaseElement; HASH_RATE_WIDTH]>, nonce: Vec<[BaseElement; 12]>) -> Result<(), VerifierError> {
    let pub_inputs = PublicInputs{disclosed_attributes, indices, num_of_attributes, comm, nonce};
    winterfell::verify::<MerkleAir>(proof, pub_inputs)
}
