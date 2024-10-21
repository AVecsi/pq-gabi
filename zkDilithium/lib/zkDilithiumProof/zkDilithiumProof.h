#include <stdint.h>

unsigned char* prove(uint32_t* zBytes, uint32_t*  wBytes, uint32_t*  qwBytes, uint32_t*  ctildeBytes, uint32_t*  mBytes, uint32_t*  comrBytes);

int verify(unsigned char* proofBytes, unsigned char* mBytes);