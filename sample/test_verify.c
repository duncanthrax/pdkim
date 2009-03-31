/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Verification test & sample code.
 *
 *  Copyright (C) 2009  Tom Kistner <tom@duncanthrax.net>
 *  http://duncanthrax.net/pdkim/
 */

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pdkim1.h>

/* A DKIM public key record, as it usually resides in a DNS TXT record. */
char dns_txt_record[] = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"\
                        "gQC5+utIbbfbpssvW0TboF73Seos+1ijdPFGwc/z8Yu12cp"\
                        "jBvRb5/qRJd83XCySRs0QkK1zWx4soPffbtyJ9TU5mO76M2"\
                        "3lIuI5slJ4QLA0UznGxfHdfXpK9qRnmG6A4HRHC9B93pjTo"\
                        "6iBksRhIeSsTL94EbUJ625i0Lqg4i6NVQIDAQAB;";

/* This callback function is called by the PDKIM library to retrieve
 * DKIM public key records. A pointer to this function is passed to
 * the library with the pdkim_init_verify() call (see further below).
 * On success, this function must return 0 (PDKIM_OK). On failure, it
 * should return a non-0 value.
 *
 *    char *name
 *      The fully qualified name of the DNS TXT record to be
 *      retrieved ("selector._domainkey.domain.example").
 *
 *    char *answer
 *      Pointer to preallocated and zeroed memory of size
 *      PDKIM_DNS_TXT_MAX_RECLEN. The function should copy the
 *      retrieved DNS TXT record to that location.
 */
int query_dns_txt(char *name, char *answer) {
  /* This mockup function does not use DNS, but just returns
     a hardcoded record */
  strcpy(answer,dns_txt_record);
  return PDKIM_OK;
}

/* This function retrieves a message on STDIN and verifies present
 * DKIM signatures. Due to the limitations of this sample code, this
 * only works for signatures created with the key in test_sign.c.
 *
 * Please note that this sample code skips on some error checking
 * and handling for the sake of clarity and brevity.
 */
#define MAX_LINE_LEN 1024
int main(int argc, char *argv[]) {
  FILE *input;
  FILE *debug;
  char buffer[MAX_LINE_LEN];

  pdkim_ctx *ctx;
  pdkim_signature *signatures;

  /* pdkim_ctx *pdkim_init_verify(int mode,
   *                              int(*)(char *, char *))
   *
   * Initialize context for verification.
   *
   *    int mode
   *      PDKIM_INPUT_NORMAL or PDKIM_INPUT_SMTP. When SMTP
   *      input is used, the lib will deflate double-dots at
   *      the start of atline to a single dot, and it will
   *      stop processing input when a line with and single
   *      dot is received (Excess input will simply be ignored).
   *
   *    int(*)(char *, char *)
   *      Pointer to your DNS/TXT callback function. See
   *      the query_dns_txt() stub above. The lib does not
   *      include a DNS resolver, so you need to provide that
   *      yourself. If you develop an application that deals
   *      with email, you'll probably have something anyway.
   *
   * Returns: A pointer to a freshly allocated pdkim_ctx
   *          context.
   */
  ctx = pdkim_init_verify(PDKIM_INPUT_NORMAL,
                          &query_dns_txt
                         );

  /* void pdkim_set_debug_stream(pdkim_ctx *ctx,
   *                             FILE *debug)
   *
   * Set up debugging stream.
   *
   * When PDKIM was compiled with DEBUG defined (which is the
   * recommended default), you can set up a stream where it
   * sends debug output to. In this example, we simply use
   * STDERR (fd 2) for that purpose. If you don't set a debug
   * stream, no debug output is generated.
   */
  debug = fdopen(2,"a");
  pdkim_set_debug_stream(ctx,debug);

  /* int pdkim_feed(pdkim_ctx *ctx,
   *                char *data,
   *                int data_len)
   *
   * (Repeatedly) feed data to the signing algorithm. The message
   * data MUST use CRLF line endings (like SMTP uses on the
   * wire). The data chunks do not need to be a "line" - you
   * can split chunks at arbitrary locations.
   *
   *    char *data
   *      Pointer to data to feed. Please note that despite
   *      the example given below, this is not necessarily a
   *      C string.
   *
   *    int data_len
   *      Length of data being fed, in bytes.
   *
   * Returns: 0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
   */
  input = fdopen(0,"r");
  while (fgets(buffer, MAX_LINE_LEN, input)) {
    if (pdkim_feed(ctx,buffer,strlen(buffer)) != PDKIM_OK) {
      printf("pdkim_feed() error\n");
      goto BAIL;
    }
  }

  /* int pdkim_feed_finish(pdkim_ctx *ctx,
   *                       pdkim_signature **signatures,
   *
   * Signal end-of-message and retrieve the signature block(s).
   *
   *    pdkim_signature **signature
   *      Pass in a pointer to a pdkim_signature pointer.
   *      If the function returns PDKIM_OK, it will be set
   *      up to point to (several chained) freshly allocated
   *      pdkim_signature block(s). See pdkim.h for
   *      documentation on what these blocks contain.
   *
   * Returns: 0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
   */
  if (pdkim_feed_finish(ctx,&signatures) == PDKIM_OK) {
    while (signatures != NULL) {
      printf("Signature from domain '%s': ",signatures->domain);
      switch(signatures->verify_status) {
        case PDKIM_VERIFY_NONE:    printf("not verified\n"); break;
        case PDKIM_VERIFY_INVALID: printf("invalid\n"); break;
        case PDKIM_VERIFY_FAIL:    printf("verification failed\n"); break;
        case PDKIM_VERIFY_PASS:    printf("verification succeeded\n"); break;
      }
      /* Try next signature */
      signatures = signatures->next;
    }
  }

  BAIL:
  /* void pdkim_free_ctx(pdkim_ctx *ctx)
   *
   *  Free all allocated memory blocks referenced from
   *  the context (including signature blocks), as well
   *  as the context itself.
   */
  pdkim_free_ctx(ctx);

  fclose(input);
  fclose(debug);
}
