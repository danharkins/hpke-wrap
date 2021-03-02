/*
 * Copyright (c) Dan Harkins, 2020, 2021
 *
 *  Copyright holder grants permission for redistribution and use in source 
 *  and binary forms, with or without modification, provided that the 
 *  following conditions are met:
 *     1. Redistribution of source code must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in all source files.
 *     2. Redistribution in binary form must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *
 *  "DISCLAIMER OF LIABILITY
 *  
 *  THIS SOFTWARE IS PROVIDED BY DAN HARKINS ``AS IS''
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAN HARKINS BE LIABLE 
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE."
 *
 * This license and distribution terms cannot be changed. In other words,
 * this code cannot simply be copied and put under another distribution
 * license (including the GNU public license).
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "hpke.h"

static void
print_buffer (char *str, unsigned char *buf, int len)
{
    int i;
    
    printf("%s\n", str);
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

/*
 * convert a test vector character string into a usable octet string
 */
void
s2os (char *str, unsigned char **os, int *oslen)
{
    int i, val;
    char *ptr;
    unsigned char *op;
    
    *oslen = strlen(str)/2;
    if ((*os = (unsigned char *)malloc(*oslen)) == NULL) {
        fprintf(stderr, "unable to allocate os in s2os\n");
        return;
    }
    memset(*os, 0, *oslen);
    ptr = str;
    op = *os;
    for (i = 0; i < *oslen; i++) {
        sscanf(ptr, "%02x", &val);
        *op = val & 0xff;
        op++;
        ptr++; ptr++;
    }
}

int
main (int argc, char **argv)
{
    int c, b64 = 0, pad = 0;
    hpke_ctx *ctx = NULL;
    unsigned char *aad = NULL, *info = NULL, *pt = NULL, *ct = NULL, *pkR = NULL, *k = NULL, *enc;
    int aad_len = 0, info_len = 0, t_len = 0, pkR_len = 0, debug = 0, enc_len;
    unsigned char *b64enc, *b64ct;
    int b64enc_len, b64ct_len;

    for (;;) {
        c = getopt(argc, argv, "a:i:p:c:k:d:bhf");
        if (c < 0) {
            break;
        }
        switch (c) {
            case 'a':
                s2os(optarg, &aad, &aad_len);
                break;
            case 'i':
                s2os(optarg, &info, &info_len);
                break;
            case 'p':
                pt = optarg;
                t_len = strlen(optarg);
                break;
            case'k':
                k = optarg;
                break;
            case 'd':
                debug = atoi(optarg);
                break;
            case 'b':
                b64 = 1;
                break;
            case 'h':
            default:
                fprintf(stderr, "USAGE: %s [-aikspbh]\n"
                        "\t-a  some AAD to include in the wrapping\n"
                        "\t-i  some info to include in the wrapping\n"
                        "\t-k  the recipient's public key in SECG uncompressed form\n"
                        "\t-p  the plaintext to wrap\n"
                        "\t-b  base64 encode the output (and base64 decode what's in -k)\n"
                        "\t-h  this help message\n",
                        argv[0]);
                exit(1);
        }
    }

    if ((pt == NULL) || (k == NULL)) {
        fprintf(stderr, "%s: at a minimum you need to specify plaintext, and a recipient public key\n",
                argv[0]);
        exit(1);
    }

    if (b64) {
        if ((pkR = (unsigned char *)malloc(strlen(k))) == NULL) {
            fprintf(stderr, "%s: unable to allocate space for recipient's public key!\n", argv[0]);
            exit(1);
        }
        memset(pkR, 0, strlen(k));
        pkR_len = EVP_DecodeBlock(pkR, k, strlen(k));
        pad = strlen(k);
        while (k[pad - 1] == '=') {
            pkR_len--;
            pad--;
        }
    } else {
        s2os(k, &pkR, &pkR_len);
    }
    /*
     * the recipient public key dictates our ephemeral key and therefore the KEM.
     * For simplicity, don't allow for a different KDF to be used, just use the
     * hash algorithm from the KEM.
     */
    switch (pkR_len) {
        case 32:
            /*
             * compact p256
             */
            if ((ctx = create_hpke_context(MODE_BASE, DHKEM_CP256,
                                           HKDF_SHA_256, AES_128_GCM)) == NULL) {
                fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
                exit(1);
            }
            break;
        case 48:
            /*
             * compact p384
             */
            if ((ctx = create_hpke_context(MODE_BASE, DHKEM_CP384,
                                           HKDF_SHA_384, AES_256_GCM)) == NULL) {
                fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
                exit(1);
            }
            break;
        case 65:
            /*
             * uncompressed p256
             */
            if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P256,
                                           HKDF_SHA_256, AES_128_GCM)) == NULL) {
                fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
                exit(1);
            }
            break;
        case 66:
            /*
             * compact p521 
             *
             */
            if ((ctx = create_hpke_context(MODE_BASE, DHKEM_CP521,
                                           HKDF_SHA_512, AES_256_GCM)) == NULL) {
                fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
                exit(1);
            }
            break;
        case 97:
            /*
             * uncompressed p384
             */
            if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P384,
                                           HKDF_SHA_384, AES_256_GCM)) == NULL) {
                fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
                exit(1);
            }
            break;
        case 133:
            /*
             * uncompressed p521
             */
            if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P521,
                                           HKDF_SHA_512, AES_256_GCM)) == NULL) {
                fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
                exit(1);
            }
            break;
        default:
            fprintf(stderr, "%s: unknown public key size, %d\n", argv[0], pkR_len);
            exit(1);
    }
    set_hpke_debug(ctx, debug);

    if (sender(ctx, pkR, pkR_len, info, info_len, NULL, 0, NULL, 0, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\nTry again with -f maybe\n", argv[0]);
        exit(1);
    }

    if ((ct = malloc(t_len+16)) == NULL) {
        fprintf(stderr, "can't allocate space for ciphertext!\n");
        exit(1);
    }
    wrap(ctx, aad, aad_len, pt, t_len, ct+16, ct);

    if (b64) {
        if ((b64enc = (unsigned char *)malloc(enc_len*2)) == NULL) {
            fprintf(stderr, "%s: unable to allocate room to encode ephemeral public key!\n", argv[0]);
            exit(1);
        }
        memset(b64enc, 0, (enc_len*2));
        b64enc_len = EVP_EncodeBlock(b64enc, enc, enc_len);

        if ((b64ct = (unsigned char *)malloc((t_len+16)*2)) == NULL) {
            fprintf(stderr, "%s: unable to allocate room to encode ephemeral public key!\n", argv[0]);
            exit(1);
        }
        memset(b64ct, 0, (t_len+16)*2);
        b64ct_len = EVP_EncodeBlock(b64ct, ct, t_len + 16);
        /*
         * do some pseudo-PEM nonsense to pretty-print this goo
         */
        printf("------ BEGIN ENC -------\n%s\n"
               "-------- END ENC -------\n"
               "------ BEGIN CT --------\n%s\n"
               "-------- END CT --------\n", b64enc, b64ct);

        free(b64enc);
        free(b64ct);
    } else {
        print_buffer("enc:", enc, enc_len);
        print_buffer("ct:", ct, t_len + 16);
    }
    free_hpke_context(ctx);
    free(ct);
    free(enc);
    free(pkR);

    exit(0);
}

