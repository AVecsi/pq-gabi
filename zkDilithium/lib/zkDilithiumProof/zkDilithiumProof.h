#include <stdint.h>

unsigned char* prove(uint32_t* zBytes, uint32_t*  wBytes, uint32_t*  qwBytes, uint32_t*  ctildeBytes, uint32_t*  mBytes, uint32_t*  commBytes, uint32_t*  comrBytes, uint32_t*  nonceBytes, int* out_len);

int verify(unsigned char* proofBytes, int* len, uint32_t* commBytes, uint32_t*  nonceBytes);