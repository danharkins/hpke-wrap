/*
 * Copyright (c) Dan Harkins, 2020
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
dump_buffer (unsigned char *buf, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (i && (i%4 == 0)) {
            printf(" ");
        }
        if (i && (i%32 == 0)) {
            printf("\n");
        }
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void
print_buffer (char *str, unsigned char *buf, int len)
{
    printf("%s\n", str);
    dump_buffer(buf, len);
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
    int x, b64 = 0, pad = 0;
    hpke_ctx *ctx = NULL;
    unsigned char *a = NULL, *i = NULL, *c = NULL, *k = NULL, *r = NULL, *ikmR = NULL;
    unsigned char *aad = NULL, *info = NULL, *pt = NULL, *ct = NULL, *pkS = NULL;
    int aad_len = 0, info_len = 0, t_len = 0, pkS_len = 0, ikmR_len = 0, strength = 0, debug = 0;

    for (;;) {
        x = getopt(argc, argv, "a:i:p:c:k:r:s:d:bh");
        if (x < 0) {
            break;
        }
        switch (x) {
            case 'a':
                a = optarg;
                break;
            case 'i':
                i = optarg;
                break;
            case 'c':
                c = optarg;
                break;
            case 'r':
                r = optarg;
                break;
            case'k':
                k = optarg;
                break;
            case 's':
                strength = atoi(optarg);
                break;
            case 'd':
                debug = atoi(optarg);
                break;
            case 'b':
                b64 = 1;
                break;
            case 'h':
            default:
                fprintf(stderr, "USAGE: %s [-aikrscbh]\n"
                        "\t-a  some AAD to include in the unwrapping\n"
                        "\t-i  some info to include in the unwrapping\n"
                        "\t-k  the sender's public key in SECG uncompressed form\n"
                        "\t-r  keying material to derive receiver's keypair\n"
                        "\t-s  a numeric indicator of 'strength' of the wrapping (e.g. 256, 384, or 512)\n"
                        "\t-c  the ciphertext to unwrap\n"
                        "\t-b  base64 decode the input prior to processing\n"
                        "\t-h  this help message\n",
                        argv[0]);
                exit(1);
        }
    }
    /*
     * sanity check...
     */
    if ((c == NULL) || (k == NULL) || (r == NULL) || (strength == 0)) {
        fprintf(stderr, "%s: at a minimum you need to specify ciphertext, "
                "a recipient public key, a key to derive your private key, and strength\n",
                argv[0]);
        exit(1);
    }
    if (b64) {
        if (a != NULL) {
            if ((aad = (unsigned char *)malloc(strlen(a))) == NULL) {
                fprintf(stderr, "%s: cannot allocate space for AAD!\n", argv[0]);
                exit(1);
            }
            memset(aad, 0, strlen(a));
            aad_len = EVP_DecodeBlock(aad, a, strlen(a));
            pad = strlen(a);
            while (a[pad - 1] == '=') {
                aad_len--;
                pad--;
            }
        }
        if (i != NULL) {
            if ((info = (unsigned char *)malloc(strlen(i))) == NULL) {
                fprintf(stderr, "%s: cannot allocate space for info!\n", argv[0]);
                exit(1);
            }
            memset(info, 0, strlen(i));
            info_len = EVP_DecodeBlock(info, i, strlen(i));
            pad = strlen(i);
            while (i[pad - 1] == '=') {
                info_len--;
                pad--;
            }
        }
        if ((ikmR = (unsigned char *)malloc(strlen(r))) == NULL) {
            fprintf(stderr, "%s: cannot allocate space for keying material!\n", argv[0]);
            exit(1);
        }
        memset(ikmR, 0, strlen(r));
        ikmR_len = EVP_DecodeBlock(ikmR, r, strlen(r));
        pad = strlen(r);
        while(r[pad - 1] == '=') {
            ikmR_len--;
            pad--;
        }
        if ((pkS = (unsigned char *)malloc(strlen(k))) == NULL) {
            fprintf(stderr, "%s: cannot allocate space for public key!\n", argv[0]);
            exit(1);
        }
        memset(pkS, 0, strlen(k));
        pkS_len = EVP_DecodeBlock(pkS, k, strlen(k));
        pad = strlen(k);
        while (k[pad - 1] == '=') {
            pkS_len--;
            pad--;
        }
        if ((ct = (unsigned char *)malloc(strlen(c))) == NULL) {
            fprintf(stderr, "%s: cannot allocate space for ciphertext!\n", argv[0]);
            exit(1);
        }
        memset(ct, 0, strlen(c));
        t_len = EVP_DecodeBlock(ct, c, strlen(c));
        pad = strlen(c);
        while (c[pad - 1] == '=') {
            t_len--;
            pad--;
        }
    } else {
        if (a != NULL) {
            s2os(a, &aad, &aad_len);
        }
        if (i != NULL) {
            s2os(i, &info, &info_len);
        }
        s2os(r, &ikmR, &ikmR_len);
        s2os(k, &pkS, &pkS_len);
        s2os(c, &ct, &t_len);
    }

    if (strength < 257) {
        if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P256,
                                       HKDF_SHA_256, AES_256_SIV,
                                       NULL, 0, NULL, 0)) == NULL) {
            fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
            exit(1);
        }
    } else if (strength < 385) {
        if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P384,
                                       HKDF_SHA_384, AES_512_SIV,
                                       NULL, 0, NULL, 0)) == NULL) {
            fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
            exit(1);
        }
    } else {
        if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P521,
                                       HKDF_SHA_512, AES_512_SIV,
                                       NULL, 0, NULL, 0)) == NULL) {
            fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
            exit(1);
        }
    }
    set_hpke_debug(ctx, debug);

    if (derive_local_static_keypair(ctx, ikmR, ikmR_len) < 1) {
        fprintf(stderr, "%s: can't fix static keypair to unwrap!\n", argv[0]);
        exit(1);
    }

    if (receiver(ctx, pkS, pkS_len, info, info_len) < 1) {
        fprintf(stderr, "%s: can't do decap!\n", argv[0]);
        exit(1);
    }

    if ((pt = malloc(t_len)) == NULL) {
        fprintf(stderr, "can't allocate space for plaintext!\n");
        exit(1);
    }
    memset(pt, 0, t_len);
    unwrap(ctx, aad, aad_len, ct+16, t_len - 16, pt, ct);

    printf("plaintext: %s\n", pt);

    free_hpke_context(ctx);
    if (aad != NULL) {
        free(aad);
    }
    if (info != NULL) {
        free(info);
    }
    free(ikmR);
    free(ct);
    free(pt);

    exit(0);
}

