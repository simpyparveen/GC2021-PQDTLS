//
// Created by user on 29/11/19.
//
#include <stdio.h>
#include "dtls-hmac.c"
int main(int argc, char **argv) {
  static unsigned char hmacbuf[DTLS_HMAC_DIGEST_SIZE];
  size_t len, i;
  dtls_hmac_context_t *hmacctx;

  if (argc < 3) {
    fprintf(stderr, "usage: %s key text", argv[0]);
    return -1;
  }

  dtls_hmac_storage_init();
    hmacctx = dtls_hmac_new("Mytestdata", strlen("Mytestdata");
  assert(hmacctx);
  dtls_hmac_update(hmacctx, "Mytestdata2", strlen("Mytestdata2"));

  len = dtls_hmac_finalize(hmacctx, hmacbuf);

  for(i = 0; i < len; i++)
    printf("%02x", hmacbuf[i]);
  printf("\n");

  dtls_hmac_free(hmacctx);

  return 0;
}
