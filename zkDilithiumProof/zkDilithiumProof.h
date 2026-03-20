#include <stdint.h>
#include <stdlib.h>

#ifndef ZKDILITHIUM_PROOF_H
#define ZKDILITHIUM_PROOF_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define N 256

#define K 4

#define TRACE_WIDTH (HASH_IND + (3 * HASH_STATE_WIDTH))

#define AUX_WIDTH ((((1 + 4) + 4) + 4) + 1)

#define S_BALL_START HASH_CYCLE_LEN

#define COM_START (HASH_CYCLE_LEN * (S_BALL_END + 1))

#define COM_END (HASH_CYCLE_LEN * (S_BALL_END + 2))

#define PIT_START (HASH_CYCLE_LEN * (S_BALL_END + 3))

#define PIT_LEN (((N + 2) * HASH_CYCLE_LEN) / (HASH_CYCLE_LEN - 2))

#define PIT_END (PIT_START + PIT_LEN)

#define PADDED_TRACE_LENGTH 512

#define _TRACE_LENGTH PIT_END

#define CAUX 0

#define ZAUX (CAUX + 1)

#define WAUX (ZAUX + 4)

#define QWAUX (WAUX + 4)

#define GAMMA (QWAUX + 4)

#define POLYMULTASSERT (GAMMA + 1)

#define FIRST_ATTR_IND 0

#define STORAGE_IND HASH_DIGEST_WIDTH

#define HASH_IND (STORAGE_IND + HASH_DIGEST_WIDTH)

#define HASHING_PHASE_START 0

#define STATE_WIDTH 35

#define RATE_WIDTH 24

/**
 * 12 elements (can be serialized into 32-bytes) are returned as digest.
 */
#define DIGEST_SIZE 12

/**
 * Number of full rounds we use is actually 21 with 3 permutations applied per row of the trace table
 */
#define NUM_ROUNDS 7

#define CYCLE_LENGTH 8

typedef struct CCredential {
  const uint32_t *attributes;
  uintptr_t num_attributes;
  uintptr_t num_user_attributes;
  const uintptr_t *disclosed_indices;
  uintptr_t num_disclosed;
  const uint32_t *salted_hash;
  const uint32_t *salt;
} CCredential;

typedef struct CDisclosure {
  const uint32_t *disclosed_attributes;
  uintptr_t num_disclosed;
  const uintptr_t *disclosed_indices;
  uintptr_t num_all_attributes;
  uintptr_t num_user_attributes;
  const uint32_t *salted_hash;
} CDisclosure;

const uint8_t *prove_signature(const uint32_t *z_ptr,
                               const uint32_t *w_ptr,
                               const uint32_t *qw_ptr,
                               const uint32_t *ctilde_ptr,
                               const uint32_t *m_ptr,
                               const uint32_t *comm_ptr,
                               const uint32_t *comr_ptr,
                               const uint32_t *nonce_ptr,
                               uintptr_t *out_proof_bytes_len);

uint32_t verify_signature(const uint8_t *proof_bytes_ptr,
                          uintptr_t proof_bytes_len,
                          const uint32_t *comm_ptr,
                          const uint32_t *nonce_ptr);

const uint8_t *prove_attributes(const struct CCredential *creds,
                                uintptr_t num_creds,
                                uintptr_t *out_len);

uint32_t verify_attributes(const uint8_t *proof_bytes_ptr,
                           uintptr_t proof_bytes_len,
                           const struct CDisclosure *discls_ptr,
                           uintptr_t num_discls);

void free_proof(uint8_t *ptr, uintptr_t len);

#endif /* ZKDILITHIUM_PROOF_H */
