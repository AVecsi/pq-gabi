#include <stdint.h>
#include <stdlib.h>

unsigned char* prove_signature(uint32_t* z_ptr, uint32_t*  w_ptr, uint32_t*  qw_ptr, uint32_t*  ctilde_ptr, uint32_t*  m_ptr, uint32_t*  comm_ptr, uint32_t*  comr_ptr, uint32_t*  nonce_ptr, size_t* out_proof_bytes_len);

int verify_signature(unsigned char* proof_bytes_ptr, size_t proof_bytes_len, uint32_t* comm_ptr, uint32_t*  nonce_ptr);

unsigned char* prove_attributes(size_t num_of_certs, uint32_t* cert_list_ptr, size_t* num_of_attributes, size_t* disclosed_indices_ptr, size_t* num_of_disclosed_indices, uint32_t* merkle_commitments_ptr, uint32_t* secret_commitments_ptr, uint32_t* nonces_ptr, uint32_t* secret_nonce_ptr, size_t* out_proof_bytes_len);

int verify_attributes(unsigned char* proof_bytes_ptr, size_t proof_bytes_len, size_t num_of_certs, uint32_t* disclosed_attributes_ptr, size_t* num_of_disclosed_attributes, size_t* disclosed_indices_ptr, size_t* num_of_attributes_ptr, uint32_t* merkle_commitments_ptr, uint32_t* secret_commitments_ptr, uint32_t* nonces_ptr, uint32_t* secret_nonce_ptr);