// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree, Serializable, ByteWriter
};

use super::{BaseElement, FieldElement, ProofOptions, HASH_CYCLE_LEN, HASH_DIGEST_WIDTH, HASH_RATE_WIDTH, HASH_STATE_WIDTH};
use crate::utils::{EvaluationResult, is_binary, poseidon_23_spec, are_equal};

const HASH_CYCLE_MASK: [BaseElement; HASH_CYCLE_LEN] = [
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ZERO,
];

pub struct PublicInputs {
    pub disclosed_attributes: Vec<[BaseElement; HASH_DIGEST_WIDTH]>,
    pub indices: Vec<usize>,
    pub num_of_attributes: usize,
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
    num_of_attributes: usize,
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
        let mut degrees = Vec::new();
        degrees.append(&mut vec![TransitionConstraintDegree::with_cycles(3, vec![trace_info.length()]); 6*HASH_STATE_WIDTH]); //hash_space
        MerkleAir {
            context: AirContext::new(trace_info, degrees, pub_inputs.disclosed_attributes.len()*HASH_DIGEST_WIDTH+pub_inputs.num_of_attributes*(HASH_STATE_WIDTH-HASH_RATE_WIDTH), options),
            disclosed_attributes: pub_inputs.disclosed_attributes,
            disclosed_indices: pub_inputs.indices,
            num_of_attributes: pub_inputs.num_of_attributes,
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
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        debug_assert_eq!(self.trace_length(), current.len());
        debug_assert_eq!(self.trace_length(), next.len());

        let hashmask_flag = periodic_values[0];
        let ark = &periodic_values[1..];
        
        // Assert the poseidon round was computed correctly was computed correctly whenever a permutation needs to be applied
        assert_hash(&mut result[0..6*HASH_STATE_WIDTH],
            &current[0..3*HASH_STATE_WIDTH],
            &next[0..3*HASH_STATE_WIDTH],
            &ark,
            hashmask_flag
        );

        //Assert at the end of a hash cycle the result is moved to the end of storage

        //Assert on the load from storage steps, the correct data is loaded

        //Assert the storage is copied correctly
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut main_assertions = Vec::new();

        //Assert that the disclosed attributes were loaded to the hash space on the correct step
        let highest_disclosed_index = self.disclosed_indices[self.disclosed_indices.len() - 1];
        let mut i = 1;
        while i < highest_disclosed_index {
            i *= 2;
        }
        let load_attribute_steps = leaf_steps_in_postorder(i);

        let mut j = 0;
        for (i, step) in load_attribute_steps.iter().enumerate() {
            //i*2th and i*2+1th attributes are loaded in step
            if self.disclosed_indices.contains(&(i*2)) {
                for k in 0..HASH_DIGEST_WIDTH{
                    main_assertions.push(Assertion::single(k, step*HASH_CYCLE_LEN, self.disclosed_attributes[j][k]));
                }
                j += 1;
            }

            if self.disclosed_indices.contains(&(i*2 + 1)) {
                for k in HASH_DIGEST_WIDTH..2*HASH_DIGEST_WIDTH{
                    main_assertions.push(Assertion::single(k, step*HASH_CYCLE_LEN, self.disclosed_attributes[j][k - HASH_DIGEST_WIDTH]));
                }
                j += 1;
            }
        }

        let num_of_attributes = i32::pow(2, ((self.trace_info().width() - 3*HASH_STATE_WIDTH)/HASH_DIGEST_WIDTH) as u32);
        for i in 0..num_of_attributes {
            for k in HASH_RATE_WIDTH..HASH_STATE_WIDTH {
                main_assertions.push(Assertion::single(k, i as usize * HASH_CYCLE_LEN, BaseElement::ZERO));
            }
        }

        main_assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = Vec::new();
        result.push(get_hashmask_constants(self.trace_length(), self.num_of_attributes));
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

fn postorder_traversal(n: usize, nodes: &[usize]) -> Vec<usize> {
    // Simulates postorder traversal of a tree with nodes.
    if n > nodes.len() {
        // Base case: If the node doesn't exist, return empty
        return vec![];
    }
    // Recursive calls for left and right children
    let left = postorder_traversal(2 * n, nodes);
    let right = postorder_traversal(2 * n + 1, nodes);

    // Current node last (postorder)
    [left, right, vec![nodes[n - 1]]].concat()
}

//TODO didnt test thoroughly
fn leaf_steps_in_postorder(num_nodes: usize) -> Vec<usize> {
    // Step 1: Generate node indices for a fully balanced binary tree
    let nodes: Vec<usize> = (0..=num_nodes).collect();

    // Step 2: Simulate postorder traversal
    let postorder = postorder_traversal(1, &nodes);

    // Step 3: Identify leaves (indices from 2^(h-1) to 2^h - 1)
    let leaf_start = (num_nodes + 1) / 2;
    let leaf_end = num_nodes + 1;
    let leaf_nodes: Vec<usize> = (leaf_start..leaf_end).collect();

    // Step 4: Find steps where leaf nodes appear in the postorder sequence
    postorder
        .iter()
        .enumerate()
        .filter_map(|(i, &node)| if leaf_nodes.contains(&node) { Some(i) } else { None })
        .collect()
}

fn get_hashmask_constants(padded_trace_length: usize, num_of_attributes: usize) -> Vec<BaseElement> {
    let mut hashmask_const = vec![BaseElement::ZERO; padded_trace_length];
    //TODO when adding the commitment don't forget to change this
    let trace_length = (num_of_attributes as usize - 1) * HASH_CYCLE_LEN - 2;
    for i in 0..trace_length{
        hashmask_const[i] = HASH_CYCLE_MASK[i%HASH_CYCLE_LEN];
    }

    hashmask_const
}