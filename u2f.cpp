#include "u2f.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/aes.h"
#include <string.h>
#include "esp32-hal-log.h"
#include "esp32-hal.h"
#include "hmac.h"
#include "esp_system.h"

bool user_presence_check();

static uint8_t CERTIFICATE_DER[] = { 0x30, 0x82, 0x01, 0x6d, 0x30, 0x82, 0x01, 0x12, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xad, 0x16, 0x25, 0x76, 0x3d, 0x31, 0xe2, 0xf0, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x46, 0x69, 0x64, 0x6f, 0x42, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x33, 0x30, 0x37, 0x31, 0x34, 0x33, 0x32, 0x35, 0x36, 0x5a, 0x17, 0x0d, 0x34, 0x39, 0x30, 0x34, 0x31, 0x38, 0x31, 0x34, 0x33, 0x32, 0x35, 0x36, 0x5a, 0x30, 0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x46, 0x69, 0x64, 0x6f, 0x42, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xcb, 0xf8, 0x47, 0xb3, 0x96, 0xe6, 0xa0, 0x2d, 0xe3, 0xbe, 0xb5, 0x47, 0xa7, 0xa3, 0xd6, 0x54, 0x02, 0x33, 0xa3, 0x96, 0x85, 0x2c, 0x01, 0x40, 0x72, 0x2a, 0x59, 0x27, 0x94, 0x34, 0x6c, 0x3d, 0xae, 0x66, 0x76, 0xa2, 0x78, 0x83, 0x35, 0x88, 0x3d, 0xcb, 0x92, 0x28, 0x0b, 0xc6, 0xbf, 0xeb, 0xd8, 0xca, 0x05, 0x5c, 0x0e, 0x23, 0x96, 0x9d, 0x2c, 0x30, 0x53, 0xd2, 0xf5, 0x1a, 0xea, 0xb4, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xe7, 0x53, 0x25, 0x43, 0x89, 0xb4, 0x9b, 0x5c, 0x11, 0x5c, 0xb2, 0x1d, 0xc9, 0x31, 0x78, 0x40, 0x94, 0x2d, 0xe0, 0x3d, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xe7, 0x53, 0x25, 0x43, 0x89, 0xb4, 0x9b, 0x5c, 0x11, 0x5c, 0xb2, 0x1d, 0xc9, 0x31, 0x78, 0x40, 0x94, 0x2d, 0xe0, 0x3d, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xb1, 0x2f, 0x34, 0x09, 0xe4, 0x01, 0xe7, 0xf1, 0x54, 0xfd, 0x7e, 0x6d, 0x30, 0x97, 0xb6, 0x38, 0x56, 0x30, 0xc9, 0xe7, 0x36, 0x43, 0xbd, 0xfe, 0x4c, 0x01, 0x21, 0xbe, 0xc2, 0x5f, 0xa5, 0x5a, 0x02, 0x21, 0x00, 0x84, 0x84, 0x7d, 0xb6, 0xe9, 0x9d, 0x1a, 0x9e, 0xf9, 0x72, 0xe6, 0x29, 0x61, 0x95, 0xa1, 0x65, 0x8d, 0x76, 0x16, 0xec, 0x3c, 0x9c, 0x35, 0x4b, 0x56, 0x18, 0x85, 0xd0, 0xce, 0x6a, 0x71, 0x43 };
static uint8_t PRIVATE_KEY[] = { 0x0c, 0xd6, 0xa2, 0x6e, 0x95, 0x25, 0xd2, 0xc1, 0x8d, 0x5d, 0x3e, 0x32, 0xf1, 0xd5, 0x6e, 0xca, 0x1f, 0x30, 0xaf, 0x68, 0x7d, 0x18, 0x53, 0x42, 0xf5, 0xac, 0x4f, 0x38, 0x71, 0x2c, 0x9d, 0xe3 };

static uint8_t AES_KEY[] = { 172, 195, 189, 108, 184, 127, 239, 135, 167, 36, 71, 68, 84, 105, 247, 156 };
static uint8_t RND_IV[] = { 183, 245, 227, 170, 48, 66, 75, 19, 85, 196, 74, 48, 255, 211, 250, 216 };
static uint8_t KEY_5C[] = { 15, 162, 168, 118, 195, 97, 141, 230, 134, 145, 234, 248, 175, 72, 58, 123, 240, 136, 197, 3, 52, 46, 23, 222, 146, 98, 51, 62, 5, 53, 69, 214, 201, 51, 209, 158, 176, 73, 111, 219, 123, 131, 42, 136, 48, 230, 29, 93, 105, 87, 173, 24, 223, 203, 138, 104, 240, 113, 250, 207, 202, 113, 118, 30};
static uint8_t KEY_36[] = { 101, 200, 194, 28, 169, 11, 231, 140, 236, 251, 128, 146, 197, 34, 80, 17, 154, 226, 175, 105, 94, 68, 125, 180, 248, 8, 89, 84, 111, 95, 47, 188, 163, 89, 187, 244, 218, 35, 5, 177, 17, 233, 64, 226, 90, 140, 119, 55, 3, 61, 199, 114, 181, 161, 224, 2, 154, 27, 144, 165, 160, 27, 28, 116};

static uint32_t COUNTER = 0;

#define U2F_REGISTER_INS 0x01
#define U2F_AUTHENTICATE 0x02
#define U2F_VERSION      0x03

static uint8_t SW_NO_ERROR[] = {0x90, 0x00};  // The command completed successfully without error.
static uint8_t SW_CONDITIONS_NOT_SATISFIED[] = {0x69, 0x85};   // The request was rejected due to test-of-user-presence being required.
static uint8_t SW_WRONG_DATA[] = {0x6A, 0x80};   // The request was rejected due to an invalid key handle.
static uint8_t SW_WRONG_LENGTH[] = {0x67, 0x00};   // The length of the request was invalid.
static uint8_t SW_CLA_NOT_SUPPORTED[] = {0x6E, 0x00};   // The Class uint8_t of the request is not supported.
static uint8_t SW_INS_NOT_SUPPORTED[] = {0x6D, 0x00};   // The Instruction of the request is not supported.
static uint8_t SW_COMMAND_ABORTED[] = {0x6F, 0x00};   // operating system error)

#define BLOCKSIZE 16
#define KEYLENGTH 32
#define HASHSIZE 32
#define HMACSIZE 32
#define KEY_HANDLE_LENGTH (KEYLENGTH+HMACSIZE)


void log_buffer(const int n, const unsigned char*buffer) {
  char s[1024];
  char hex[] = "0123456789ABCDEF";
  
  for (int i=0; i<n; i++) {
    s[2*i] = hex[buffer[i] >> 4];
    s[2*i+1] = hex[buffer[i] & 0x0f];
  }
  s[2*n] = 0;
  log_d("%s", s);
}


uint8_t signature_to_asn1(const mbedtls_mpi *r, const mbedtls_mpi *s, unsigned char *signature) {
  uint8_t len_r, len_s;

  len_r = (mbedtls_mpi_bitlen(r) + 8) / 8;
  len_s = (mbedtls_mpi_bitlen(s) + 8) / 8;
  signature[0] = 0x30;
  signature[1] = len_r + len_s + 4;
  signature[2] = 0x02;
  signature[3] = len_r;
  mbedtls_mpi_write_binary(r, signature+4, len_r);
  signature[4+len_r] = 0x02;
  signature[5+len_r] = len_s;
  mbedtls_mpi_write_binary(s, signature+6+len_r, len_s);
  return 6+len_r+len_s;
}


int f_rng(void *ptr, unsigned char *buffer, size_t n) {
  (void)ptr; // Unused parameter

  size_t i = 0;
  uint32_t random_num;

  while (i < n) {
    random_num = random(); // <-- USE THE ARDUINO FUNCTION
    
    for (int j = 0; j < 4 && i < n; j++) {
      buffer[i] = ((uint8_t*)&random_num)[j];
      i++;
    }
  }
  return 0;
}


std::string u2f_process(std::string data) {
  if (data[0] != 0) return std::string((char*)SW_CLA_NOT_SUPPORTED, 2);
  uint8_t INS = data[1];
  if ((INS != U2F_REGISTER_INS) && (INS != U2F_AUTHENTICATE) && (INS != U2F_VERSION))
      return std::string((char*)SW_INS_NOT_SUPPORTED, 2);
  uint8_t P1 = data[2];
  uint8_t P2 = data[3];
  uint8_t Lc = data[4];
  if (INS == U2F_REGISTER_INS) {
    // if ((P1 == 0) && (P2 == 0)) {
    if (P2 != 0) return std::string((char*)SW_WRONG_DATA, 2);  // Google Chrome sends P1 = 0x03
    else {
      // u2f register
      uint16_t length_data = Lc;
      const char *req;
      uint16_t length_e;
      if (length_data == 0) {
        length_data = (data[5] << 8) | data[6];
        req = data.c_str()+7;
        length_e = (data[7+length_data+1] << 8) | data[7+length_data+1];
        if (data.length() != 9 + length_data) return std::string((char*)SW_WRONG_LENGTH, 2);
      }
      else {
        req = data.c_str()+5;
        length_e = data[5+length_data+1];
        if (data.length() != 6 + length_data) return std::string((char*)SW_WRONG_DATA, 2);
      }
      if (length_data != 64) return std::string((char*)SW_WRONG_DATA, 2);
      const unsigned char *challenge = (const unsigned char *)req;
      const unsigned char *application = (const unsigned char *)(req+32);

//      if (!user_presence_check()) {
//        return std::string((char*)SW_CONDITIONS_NOT_SATISFIED, 2);
//      }

      // initialize ecc
      int ret;
      mbedtls_ecp_group grp;
      mbedtls_mpi d;
      mbedtls_ecp_point Q;

      mbedtls_ecp_group_init( &grp );
      mbedtls_ecp_point_init( &Q );
      mbedtls_mpi_init( &d );

      ret = mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_SECP256R1 );
      if (ret) {
        mbedtls_ecp_point_free( &Q );
        mbedtls_ecp_group_free( &grp );
        return std::string((char*)SW_COMMAND_ABORTED, 2);
      }
      
      // generate key pair
      ret = mbedtls_ecp_gen_keypair_base( &grp, &grp.G, &d, &Q, &f_rng, 0 );
      if (ret) {
        mbedtls_ecp_point_free( &Q );
        mbedtls_ecp_group_free( &grp );
        return std::string((char*)SW_COMMAND_ABORTED, 2);
      }
      uint8_t user_public_key[65];
      size_t olen = 0; // Output length

      // This single function serializes the point into the uncompressed format
      // (0x04 followed by X and Y coordinates) directly into your buffer.
      ret = mbedtls_ecp_point_write_binary(&grp, &Q, 
                                     MBEDTLS_ECP_PF_UNCOMPRESSED, 
                                     &olen, user_public_key, sizeof(user_public_key));
      if (ret != 0) {
      // Handle error, for example:
      mbedtls_ecp_point_free(&Q);
      mbedtls_ecp_group_free(&grp);
      return std::string((char*)SW_COMMAND_ABORTED, 2);
      }

      mbedtls_ecp_point_free( &Q );
      
      // generate key handle
      uint8_t key_handle[KEY_HANDLE_LENGTH];
      uint8_t ecc_key[KEYLENGTH];
      mbedtls_mpi_write_binary(&d, ecc_key, sizeof(ecc_key));
      uint8_t IV[sizeof(RND_IV)];
      for (uint8_t i=0; i<sizeof(IV); i++) IV[i] = RND_IV[i];
      mbedtls_aes_context aes_ctx;
      mbedtls_aes_init( &aes_ctx );
      mbedtls_aes_setkey_enc( &aes_ctx, AES_KEY, sizeof(AES_KEY) * 8 );
      mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, KEYLENGTH, IV, ecc_key, key_handle);
      mbedtls_aes_free( &aes_ctx );
      for (uint8_t i=0; i<HASHSIZE; i++) key_handle[i+KEYLENGTH] = application[i];
      hmac_sha256(KEY_5C, KEY_36, KEYLENGTH+HASHSIZE, key_handle, key_handle+sizeof(ecc_key));
      
      // Signature generation
      // 1. hash values
      uint8_t hash[HASHSIZE];
      uint8_t input;
      mbedtls_sha256_context ctx;
      mbedtls_sha256_init(&ctx);
      mbedtls_sha256_starts(&ctx, 0);
      input = 0x00;
      mbedtls_sha256_update(&ctx, &input, 1);
      mbedtls_sha256_update(&ctx, application, HASHSIZE);
      mbedtls_sha256_update(&ctx, challenge, HASHSIZE);
      mbedtls_sha256_update(&ctx, key_handle, KEY_HANDLE_LENGTH);
      mbedtls_sha256_update(&ctx, user_public_key, sizeof(user_public_key));
      mbedtls_sha256_finish(&ctx, hash);
      mbedtls_sha256_free(&ctx);
      // 2. compute ECDSA
      mbedtls_mpi_read_binary(&d, PRIVATE_KEY, sizeof(PRIVATE_KEY));
      mbedtls_mpi r, s;
      mbedtls_mpi_init( &r );
      mbedtls_mpi_init( &s );
      mbedtls_ecdsa_sign( &grp, &r, &s, &d, hash, HASHSIZE, &f_rng, 0);
      mbedtls_ecp_group_free( &grp );

      uint8_t signature[2*KEYLENGTH+6];
      uint8_t len_signature;
      len_signature = signature_to_asn1(&r, &s, signature);

      mbedtls_mpi_free(&d);
      mbedtls_mpi_free(&r);
      mbedtls_mpi_free(&s);
      
      // write response
      uint16_t i, offset;
      std::string response = std::string(1+sizeof(user_public_key)+1+KEY_HANDLE_LENGTH+sizeof(CERTIFICATE_DER)+len_signature+sizeof(SW_NO_ERROR), 0);
      response[0] = 0x05;
      offset = 1;
      for (i=0; i<sizeof(user_public_key); i++, offset++)
        response[offset] = user_public_key[i];
      response[offset] = KEY_HANDLE_LENGTH;
      offset += 1;
      for (i=0; i<KEY_HANDLE_LENGTH; i++, offset++)
        response[offset] = key_handle[i];
      for (i=0; i<sizeof(CERTIFICATE_DER); i++, offset++)
        response[offset] = CERTIFICATE_DER[i];
      for (i=0; i<len_signature; i++, offset++)
        response[offset] = signature[i];
      for (i=0; i<sizeof(SW_NO_ERROR); i++, offset++)
        response[offset] = SW_NO_ERROR[i];

      return response;
    }
  }
  else if (INS == U2F_AUTHENTICATE) {
    if (P2 != 0) return std::string((char*)SW_WRONG_DATA, 2);
    else if ( (P1 != 0x03) && (P1 != 0x07) && (P1 != 0x08) ) {
      return std::string((char*)SW_WRONG_DATA, 2);
    }
    else {
      // u2f authentication
      uint16_t length_data = Lc;
      const char *req;
      uint16_t length_e;
      if (length_data == 0) {
        length_data = (data[5] << 8) | data[6];
        req = data.c_str()+7;
        length_e = (data[7+length_data+1] << 8) | data[7+length_data+1];
        if (data.length() != 9 + length_data) return std::string((char*)SW_WRONG_LENGTH, 2);
      }
      else {
        req = data.c_str()+5;
        length_e = data[5+length_data+1];
        if (data.length() != 6 + length_data) return std::string((char*)SW_WRONG_DATA, 2);
      }
      if (length_data != 64+1+KEY_HANDLE_LENGTH) return std::string((char*)SW_WRONG_DATA, 2);
      if (req[64] != KEY_HANDLE_LENGTH) return std::string((char*)SW_WRONG_DATA, 2);
      const unsigned char *challenge = (const unsigned char *)(req);
      const unsigned char *application = (const unsigned char *)(req+HASHSIZE);
      const unsigned char *key_handle = (const unsigned char *)(req+HASHSIZE+HASHSIZE+1);

      uint8_t user_presence = 0;
      if (P1 == 0x03) {  // enforce-user-presence-and-sign
        if (!user_presence_check()) {
          return std::string((char*)SW_CONDITIONS_NOT_SATISFIED, 2);
        }
        else user_presence = 1;
      }
      
      // verify key handle
      uint8_t input[2*HASHSIZE];
      uint8_t output[HASHSIZE];
      for (uint8_t i=0; i<HASHSIZE; i++) {
        input[i] = key_handle[i];
        input[i+32] = application[i];
      }
      hmac_sha256(KEY_5C, KEY_36, sizeof(input), input, output);
      uint8_t check = 0;
      for (uint8_t i=0; i<HASHSIZE; i++) check |= output[i] ^ key_handle[i+KEYLENGTH];
      if (check) return std::string((char*)SW_WRONG_DATA, 2);
      if (P1 == 0x07) return std::string((char*)SW_CONDITIONS_NOT_SATISFIED, 2); // check-only

      // decrypt key handle
      uint8_t IV[sizeof(RND_IV)];
      for (uint8_t i=0; i<sizeof(IV); i++) IV[i] = RND_IV[i];
      mbedtls_aes_context aes_ctx;
      mbedtls_aes_init( &aes_ctx );
      mbedtls_aes_setkey_dec( &aes_ctx, AES_KEY, sizeof(AES_KEY) * 8 );
      mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, sizeof(output), IV, key_handle, output);
      mbedtls_aes_free( &aes_ctx );
      log_d("*** private key");
      log_buffer(32, output);
      log_d("*** application");
      log_buffer(32, application);

      // increments every time it performs an authentication operation
      COUNTER += 1;  
      uint8_t counter_big[4];  // uint32_t is in little endian format
      counter_big[0] = (uint8_t)(COUNTER >> 24);
      counter_big[1] = (uint8_t)(COUNTER >> 16);
      counter_big[2] = (uint8_t)(COUNTER >> 8);
      counter_big[3] = (uint8_t)(COUNTER);

      // Bit 0 indicates whether user presence was verified. If Bit 0 is is to 1, then user presence was verified.

      // Signature generation
      // 1. hash values
      uint8_t hash[HASHSIZE];
      mbedtls_sha256_context ctx;
      mbedtls_sha256_init(&ctx);
      mbedtls_sha256_starts(&ctx, 0);
      mbedtls_sha256_update(&ctx, application, HASHSIZE);
      mbedtls_sha256_update(&ctx, &user_presence, 1);
      mbedtls_sha256_update(&ctx, counter_big, 4);
      mbedtls_sha256_update(&ctx, challenge, HASHSIZE);
      mbedtls_sha256_finish(&ctx, hash);
      mbedtls_sha256_free(&ctx);

      // 2. compute ECDSA
      mbedtls_ecp_group grp;
      mbedtls_mpi d;

      mbedtls_ecp_group_init( &grp );
      mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_SECP256R1 );
      mbedtls_mpi_init( &d );
      mbedtls_mpi_read_binary(&d, output, KEYLENGTH);
      
      mbedtls_mpi r, s;
      mbedtls_mpi_init( &r );
      mbedtls_mpi_init( &s );
      mbedtls_ecdsa_sign( &grp, &r, &s, &d, hash, sizeof(hash), &f_rng, 0);
      mbedtls_ecp_group_free( &grp );

      uint8_t signature[72];
      uint8_t len_signature;
      len_signature = signature_to_asn1(&r, &s, signature);

      mbedtls_mpi_free(&d);
      mbedtls_mpi_free(&r);
      mbedtls_mpi_free(&s);
      
      // write response
      uint16_t i, offset;
      std::string response = std::string(1+4+len_signature+sizeof(SW_NO_ERROR), 0);
      response[0] = user_presence;
      offset = 1;
      for (i=0; i<4; i++, offset++)
        response[offset] = ((uint8_t *)(&COUNTER))[3-i];  // ESP32 is little endian
      for (i=0; i<len_signature; i++, offset++)
        response[offset] = signature[i];
      for (i=0; i<sizeof(SW_NO_ERROR); i++, offset++)
        response[offset] = SW_NO_ERROR[i];

      return response;     
    }
  }
  else {
      // INS == U2V_VERSION
     if ((P1 != 0) || (P2 != 0)) return std::string((char*)SW_WRONG_DATA, 2);
     return std::string("U2F_V2");
  }
}
