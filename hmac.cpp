#include "mbedtls/sha256.h"

#define BLOCKSIZE 64

void hmac_sha256(const unsigned char *key_5c, const unsigned char *key_36, const int n, const unsigned char *message, unsigned char *output) {
  unsigned char h1[32];
  mbedtls_sha256_context ctx;
  
  mbedtls_sha256_init(&ctx);
  
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, key_36, BLOCKSIZE);
  mbedtls_sha256_update(&ctx, message, n);
  mbedtls_sha256_finish(&ctx, h1);
  
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, key_5c, BLOCKSIZE);
  mbedtls_sha256_update(&ctx, h1, sizeof(h1));
  mbedtls_sha256_finish(&ctx, output);

  mbedtls_sha256_free(&ctx);
}
