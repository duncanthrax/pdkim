/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Signing test & sample code.
 *
 *  Copyright (C) 2009  Tom Kistner <tom@duncanthrax.net>
 *  http://duncanthrax.net/pdkim/
 */

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pdkim1.h>

#define RSA_PRIVKEY "-----BEGIN RSA PRIVATE KEY-----\n\
MIICXQIBAAKBgQC5+utIbbfbpssvW0TboF73Seos+1ijdPFGwc/z8Yu12cpjBvRb\n\
5/qRJd83XCySRs0QkK1zWx4soPffbtyJ9TU5mO76M23lIuI5slJ4QLA0UznGxfHd\n\
fXpK9qRnmG6A4HRHC9B93pjTo6iBksRhIeSsTL94EbUJ625i0Lqg4i6NVQIDAQAB\n\
AoGBAIDGqJH/Pta9+GTzGovE0N0D9j1tUKPl/ocS/m4Ya7fgdQ36q8rTpyFICvan\n\
QUmL8sQsmZ2Nkygt0VSJy/VOr6niQmoi97PY0egxvvK5mtc/nxePCGwYLOMpB6ql\n\
0UptotmvJU3tjyHZbksOf6LlzvpAgk7GnxLF1Cg/RJhH9ubBAkEA6b32mr52u3Uz\n\
BjbVWez1XBcxgwHk8A4NF9yCpHtVRY3751FZbrhy7oa+ZvYokxS4dzrepZlB1dqX\n\
IXaq7CgakQJBAMuwpG4N5x1/PfLODD7PYaJ5GSIx6BZoJObnx/42PrIm2gQdfs6W\n\
1aClscqMyj5vSBF+cWWqu1i7j6+qugSswIUCQA3T3BPZcqKyUztp4QM53mX9RUOP\n\
yCBfZGzl8aCTXz8HIEDV8il3pezwcbEbnNjen+8Fv4giYd+p18j2ATSJRtECQGaE\n\
lG3Tz4PYG/zN2fnu9KwKmSzNw4srhY82D0GSWcHerhIuKjmeTw0Y+EAC1nPQHIy5\n\
gCd0Y/DIDgyTOCbML+UCQQClbgAoYnIpbTUklWH00Z1xr+Y95BOjb4lyjyIF98B2\n\
FA0nM8cHuN/VLKjjcrJUK47lZEOsjLv+qTl0i0Lp6giq\n\
-----END RSA PRIVATE KEY-----"

#define DOMAIN   "duncanthrax.net"
#define SELECTOR "cheezburger"

/* This small function signs the following message using the domain,
 * selector and RSA key above. It prints the signature header
 * followed by the message on STDOUT, so we can simply pipe that
 * to the verification test program (test_verify.c).
 *
 * Please note that this sample code skips on some error checking
 * and handling for the sake of clarity and brevity.
 */

char *test_message[] = {
  "From: Tom Kistner <tom@duncanthrax.net>\r\n",
  "X-Folded-Header: line one\r\n\tline two\r\n",
  "To: PDKIM\r\nSubject: PDKIM Test\r\n\r\nTes",
  "t 3,4\r\nHeute bug ich, morgen fix ich.\r\n",
  NULL
};

int main(int argc, char *argv[]) {
  FILE *debug;
  int i;

  pdkim_ctx       *ctx;
  pdkim_signature *signature;

  /* pdkim_ctx *pdkim_init_sign(int mode,
   *                            char *domain,
   *                            char *selector,
   *                            char *rsa_privkey)
   *
   * Initialize context for signing.
   *
   *    int mode
   *      PDKIM_INPUT_NORMAL or PDKIM_INPUT_SMTP. When SMTP
   *      input is used, the lib will deflate double-dots at
   *      the start of atline to a single dot, and it will
   *      stop processing input when a line with and single
   *      dot is received (Excess input will simply be ignored).
   *
   *    char *domain
   *      The domain to sign as. This value will land in the
   *      d= tag of the signature.
   *
   *    char *selector
   *      The selector string to use. This value will land in
   *      the s= tag of the signature.
   *
   *    char *rsa_privkey
   *      The private RSA key, in ASCII armor. It MUST NOT be
   *      encrypted.
   *
   * Returns: A pointer to a freshly allocated pdkim_ctx
   *          context.
   */
  ctx = pdkim_init_sign(PDKIM_INPUT_NORMAL,  /* Input type */
                        DOMAIN,              /* Domain   */
                        SELECTOR,            /* Selector */
                        RSA_PRIVKEY          /* Private RSA key */
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

  /* int pdkim_set_optional(pdkim_ctx *ctx,
   *                        char *sign_headers,
   *                        char *identity,
   *                        int canon_headers,
   *                        int canon_body,
   *                        long bodylength,
   *                        int algo,
   *                        unsigned long created,
   *                        unsigned long expires)
   *
   * OPTIONAL: Set additional optional signing options. If you do
   * not use this function, sensible defaults (see below) are used.
   * Any strings you pass in are dup'ed, so you can safely release
   * your copy even before calling pdkim_free() on your context.
   *
   *    char *sign_headers (default NULL)
   *      Colon-separated list of header names. Headers with
   *      a name matching the list will be included in the
   *      signature. When this is NULL, the list of headers
   *      recommended in RFC4781 will be used.
   *
   *    char *identity (default NULL)
   *      An identity string as described in RFC4781. It will
   *      be put into the i= tag of the signature.
   *
   *    int canon_headers (default PDKIM_CANON_SIMPLE)
   *      Canonicalization algorithm to use for headers. One
   *      of PDKIM_CANON_SIMPLE or PDKIM_CANON_RELAXED.
   *
   *    int canon_body (default PDKIM_CANON_SIMPLE)
   *      Canonicalization algorithm to use for the body. One
   *      of PDKIM_CANON_SIMPLE or PDKIM_CANON_RELAXED.
   *
   *    long bodylength (default -1)
   *      Amount of canonicalized body bytes to include in
   *      the body hash calculation. A value of 0 means that
   *      the body is not included in the signature. A value
   *      of -1 (the default) means that there is no limit.
   *
   *    int algo (default PDKIM_ALGO_RSA_SHA256)
   *      One of PDKIM_ALGO_RSA_SHA256 or PDKIM_ALGO_RSA_SHA1.
   *
   *    unsigned long created (default 0)
   *      Seconds since the epoch, describing when the signature
   *      was created. This is copied to the t= tag of the
   *      signature. Setting a value of 0 (the default) omits
   *      the tag from the signature.
   *
   *    unsigned long expires (default 0)
   *      Seconds since the epoch, describing when the signature
   *      expires. This is copied to the x= tag of the
   *      signature. Setting a value of 0 (the default) omits
   *      the tag from the signature.
   *
   *  Returns: 0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
   */
  pdkim_set_optional(ctx, NULL, NULL,
                     PDKIM_CANON_SIMPLE, PDKIM_CANON_SIMPLE,
                     -1, PDKIM_ALGO_RSA_SHA256, 0, 0);

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
  i = 0;
  while (test_message[i] != NULL) {
    if (pdkim_feed(ctx,
                   test_message[i],
                   strlen(test_message[i])) != PDKIM_OK) {
      printf("pdkim_feed() error\n");
      goto BAIL;
    }
    i++;
  }

  /* int pdkim_feed_finish(pdkim_ctx *ctx,
   *                       pdkim_signature **signature,
   *
   * Signal end-of-message and retrieve the signature block.
   *
   *    pdkim_signature **signature
   *      Pass in a pointer to a pdkim_signature pointer.
   *      If the function returns PDKIM_OK, it will be set
   *      up to point to a freshly allocated pdkim_signature
   *      block. See pdkim.h for documentation on what that
   *      block contains. Hint: Most implementations will
   *      simply want to retrieve a ready-to-use
   *      DKIM-Signature header, which can be found in
   *      *signature->signature_header. See the code below.
   *
   * Returns: 0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
   */
  if (pdkim_feed_finish(ctx,&signature) == PDKIM_OK) {

    /* Print signature to STDOUT, followed by the original
     * message. We can then pipe the output directly to
     * test_verify.c.
     */
    printf(signature->signature_header);
    printf("\r\n");

    i = 0;
    while (test_message[i] != NULL) {
      printf(test_message[i]);
      i++;
    }

  }

  BAIL:
  /* void pdkim_free_ctx(pdkim_ctx *ctx)
   *
   *  Free all allocated memory blocks referenced from
   *  the context, as well as the context itself.
   */
  pdkim_free_ctx(ctx);

  fclose(debug);
}
