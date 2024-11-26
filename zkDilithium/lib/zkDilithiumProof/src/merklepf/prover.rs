// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    crypto::MerkleTree, ConstraintCompositionCoefficients, Trace, TraceInfo, TraceTable,
};

use super::{
    BaseElement, MerkleAir, FieldElement, ProofOptions, air::PublicInputs,
    Prover, HASH_CYCLE_LEN, HASH_DIGEST_WIDTH, HASH_RATE_WIDTH, HASH_STATE_WIDTH, STORAGE_START, NUM_HASH_ROUNDS
};

use crate::utils::poseidon_23_spec::{self};

// FIBONACCI PROVER
// ================================================================================================

pub struct MerkleProver {
    options: ProofOptions,
    attributes: Vec<[BaseElement; HASH_DIGEST_WIDTH]>,
    disclosed_indices: Vec<usize>,
    comm: [BaseElement; HASH_RATE_WIDTH],
    nonce: [BaseElement; 12]
}

impl MerkleProver {
    pub fn new(options: ProofOptions, attributes: Vec<[BaseElement; HASH_DIGEST_WIDTH]>, disclosed_indices: Vec<usize>, comm: [BaseElement; HASH_RATE_WIDTH], nonce: [BaseElement; 12]) -> Self {
        Self { options, attributes, disclosed_indices, comm, nonce }
    }

    pub fn build_trace(&self) -> TraceTable<BaseElement> {
        //number of attributes must be power of 2

        //TODO for now it is not counting with multiple certificates, only 1.
        let trace_width = HASH_STATE_WIDTH*3 + (self.attributes.len().trailing_zeros() as usize)*HASH_DIGEST_WIDTH;
        let trace_length = (self.attributes.len() as usize - 1) * HASH_CYCLE_LEN - 2;

        //trace length must be power of 2
        let mut i = 16;
        //Added 2 because of the winterfell artifact at the end of trace
        while i < trace_length + 2 {
            i *= 2;
        }
        let trace_padded_length = i;

        let load_attribute_steps = leaf_steps_in_postorder((self.attributes.len()) - 1);


        //TODO randomized commitment not included yet
        let mut trace = TraceTable::new(trace_width, trace_padded_length);
        trace.fill(
            |state| {
                for i in 0..HASH_DIGEST_WIDTH {
                    state[i] = self.attributes[0][i];
                    state[HASH_DIGEST_WIDTH + i] = self.attributes[1][i];
                }
            },
            |step, state| {
                if step < trace_length {
                    let cycle_pos = step % HASH_CYCLE_LEN;
                    let _cycle_num = (step + 1) / HASH_CYCLE_LEN;

                    // apply poseidon round in all but the last round of HASH_CYCLE
                    if cycle_pos < NUM_HASH_ROUNDS {
                        poseidon_23_spec::apply_round(&mut state[0..(3*HASH_STATE_WIDTH)], step);
                    } else {
                        //After the hashing steps, it's time to move some data

                        //TODO probably could move this counter out of this block and keep it updated instead of recounting all the time.
                        let mut stored_counter = 0;

                        while state[STORAGE_START + stored_counter * HASH_DIGEST_WIDTH] != BaseElement::ZERO {
                            stored_counter += 1;
                        }

                        //Move hash result to the end of storage.
                        for i in 0..HASH_DIGEST_WIDTH {
                            state[STORAGE_START + stored_counter * HASH_DIGEST_WIDTH + i] = state[i];
                        }
                        stored_counter += 1;

                        //Determine if we need to load attributes
                        let mut index = 0;
                        for i in 0..load_attribute_steps.len() {
                            if load_attribute_steps[i] == _cycle_num {
                                index = i;
                                break;
                            }
                        }
                        //self.load_attribute_steps.contains(&_cycle_num)
                        if index != 0 {
                            //Load two attributes to hash space
                            for i in 0..HASH_DIGEST_WIDTH {
                                state[i] = self.attributes[index * 2][i];
                                state[HASH_DIGEST_WIDTH + i] = self.attributes[index * 2 + 1][i];
                            }
                        } else {
                            //Move two elements from storage to hash space
                            for i in 0..HASH_DIGEST_WIDTH {
                                state[i] = state[STORAGE_START + HASH_DIGEST_WIDTH * (stored_counter - 2) + i];
                                state[HASH_DIGEST_WIDTH + i] = state[STORAGE_START + HASH_DIGEST_WIDTH * (stored_counter - 1) + i];

                                state[STORAGE_START + HASH_DIGEST_WIDTH * (stored_counter - 2) + i] = BaseElement::ZERO;
                                state[STORAGE_START + HASH_DIGEST_WIDTH * (stored_counter - 1) + i] = BaseElement::ZERO;
                            }
                        }
                        for i in HASH_RATE_WIDTH..HASH_STATE_WIDTH {
                            state[i] = BaseElement::ZERO;
                        }
                    }
                }

                // Artifact of winterfell. Used to prevent constant polynomial when interpolating
                if step==trace_padded_length-2 {
                    for i in 0..trace_width{
                        state[i] = BaseElement::new(123 as u32);
                    }
                }

                /* for i in 0..state.len() {
                    print!("{} ", state[i]);
                }
                println!(); */
            },
        );

        trace
    }
}

impl Prover for MerkleProver {
    type BaseField = BaseElement;
    type Air = MerkleAir;
    type Trace = TraceTable<BaseElement>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        let mut disclosed_attributes: Vec<[BaseElement; HASH_DIGEST_WIDTH]> = vec![];
        for i in 0..self.disclosed_indices.len() {
            disclosed_attributes.push(self.attributes[self.disclosed_indices[i]]);
        }
        PublicInputs{disclosed_attributes: disclosed_attributes, indices: self.disclosed_indices.clone(), num_of_attributes: self.attributes.len(), comm: self.comm, nonce: self.nonce}
    }
    fn options(&self) -> &ProofOptions {
        &self.options
    }
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

fn leaf_steps_in_postorder(num_nodes: usize) -> Vec<usize> {
    // Step 1: Generate node indices for a fully balanced binary tree
    let nodes: Vec<usize> = (1..=num_nodes).collect();

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
