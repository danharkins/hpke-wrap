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
    int c, b64 = 0, kem = 0;
    unsigned char *ikm = NULL, *pk = NULL, *b64pk, *b64ikm;
    int ikm_len, pk_len, b64pk_len, b64ikm_len;

    for (;;) {
        c = getopt(argc, argv, "k:bh");
        if (c < 0) {
            break;
        }
        switch (c) {
            case 'k':
                kem = atoi(optarg);
                break;
            case 'b':
                b64 = 1;
                break;
            case 'h':
            default:
                fprintf(stderr, "USAGE: %s [-bh]\n"
                        "\t-k  kem the key will be for (16=p256, 17=p384, 18=p521, 19=cp256, 20=cp384, 21=cp521)\n"
                        "\t-b  base64 encode the output\n"
                        "\t-h  this help message\n",
                        argv[0]);
                exit(1);
        }
    }

    if (!kem) {
        fprintf(stderr, "USAGE: %s [-bh]\n"
                "\t-k  kem the key will be for (16=p256, 17=p384, 18=p521, 19=cp256, 20=cp384, 21=cp521)\n"
                "\t-b  base64 encode the output\n"
                "\t-h  this help message\n",
                argv[0]);
        exit(1);
    }
    if ((pk_len = generate_static_keypair (kem, &ikm, &ikm_len, &pk)) < 1) {
        fprintf(stderr, "%s: unable to generate keypair!\n", argv[0]);
        exit(1);
    }

    if (b64) {
        if ((b64pk = (unsigned char *)malloc(pk_len*2)) == NULL) {
            fprintf(stderr, "%s: unable to allocate room to encode ephemeral public key!\n", argv[0]);
            exit(1);
        }
        memset(b64pk, 0, (pk_len*2));
        b64pk_len = EVP_EncodeBlock(b64pk, pk, pk_len);

        if ((b64ikm = (unsigned char *)malloc(ikm_len*2)) == NULL) {
            fprintf(stderr, "%s: unable to allocate room to encode ephemeral public key!\n", argv[0]);
            exit(1);
        }
        memset(b64ikm, 0, (ikm_len*2));
        b64ikm_len = EVP_EncodeBlock(b64ikm, ikm, ikm_len);
        /*
         * do some pseudo-PEM nonsense to pretty-print this goo
         */
        printf("------ BEGIN IKM -------\n%s\n"
               "-------- END IKM -------\n"
               "------ BEGIN PK  --------\n%s\n"
               "-------- END PK  --------\n", b64ikm, b64pk);

        free(b64ikm);
        free(b64pk);
    } else {
        print_buffer("ikm:", ikm, ikm_len);
        print_buffer("pk:", pk, pk_len);
    }
    free(pk);
    free(ikm);

    exit(0);
}

