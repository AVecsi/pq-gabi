// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree, Serializable, ByteWriter
};

use super::{BaseElement, FieldElement, ProofOptions, HASH_CYCLE_LEN, HASH_DIGEST_WIDTH, HASH_RATE_WIDTH, HASH_STATE_WIDTH};
use crate::utils::{EvaluationResult, is_binary, poseidon_23_spec, are_equal};

pub struct PublicInputs {
    pub disclosed_attributes: Vec<[BaseElement; HASH_DIGEST_WIDTH]>,
    pub indices: Vec<usize>,
    pub comm: [BaseElement; HASH_RATE_WIDTH],
    pub nonce: [BaseElement; 12]
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, _target: &mut W) {
        // target.write(&self.ctilde[..]);
        for i in 0..self.nonce.len() {
            _target.write(self.nonce[i]);
        }
    }
}

pub struct MerkleAir {
    context: AirContext<BaseElement>,
    disclosed_attributes: Vec<[BaseElement; HASH_DIGEST_WIDTH]>,
    disclosed_indices: Vec<usize>,
    comm: [BaseElement; HASH_RATE_WIDTH],
    nonce: [BaseElement; 12]
}

impl Air for MerkleAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        //TODO
        // let degrees = vec![TransitionConstraintDegree::new(1), TransitionConstraintDegree::new(1)];
        // assert_eq!(TRACE_WIDTH, trace_info.width());
        // FibAir {
        //     context: AirContext::new(trace_info, degrees, 3, options),
        //     result: pub_inputs,
        // }
        MerkleAir {
            context: AirContext::new(trace_info, Vec::new(), 0, options),
            disclosed_attributes: pub_inputs.disclosed_attributes,
            disclosed_indices: pub_inputs.indices,
            comm: pub_inputs.comm,
            nonce: pub_inputs.nonce
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        // expected state width is 2 field elements
        //debug_assert_eq!(TRACE_WIDTH, current.len());
        //debug_assert_eq!(TRACE_WIDTH, next.len());

        // TODO
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut main_assertions = Vec::new();

        main_assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = Vec::new();
        result.append(&mut poseidon_23_spec::get_round_constants());

        result
    }
}

fn assert_hash<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    ark: &[E],
    flag: E
) {
    poseidon_23_spec::enforce_round(
        &mut result[0..(2*HASH_STATE_WIDTH)],
        &current[0..(HASH_STATE_WIDTH)],
        &next[(2*HASH_STATE_WIDTH)..(3*HASH_STATE_WIDTH)],
        &ark[0..HASH_STATE_WIDTH],
        flag,
    );
    poseidon_23_spec::enforce_round(
        &mut result[(4*HASH_STATE_WIDTH)..(6*HASH_STATE_WIDTH)],
        &next[(2*HASH_STATE_WIDTH)..(3*HASH_STATE_WIDTH)],
        &next[(HASH_STATE_WIDTH)..(2*HASH_STATE_WIDTH)],
        &ark[HASH_STATE_WIDTH..2*HASH_STATE_WIDTH],
        flag,
    );
    poseidon_23_spec::enforce_round(
        &mut result[(2*HASH_STATE_WIDTH)..(4*HASH_STATE_WIDTH)],
        &next[(HASH_STATE_WIDTH)..(2*HASH_STATE_WIDTH)],
        &next[0..(HASH_STATE_WIDTH)],
        &ark[2*HASH_STATE_WIDTH..3*HASH_STATE_WIDTH],
        flag,
    );
}
