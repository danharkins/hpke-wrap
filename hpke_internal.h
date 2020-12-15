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

#ifndef _HPKE_INTERNAL_H_
#define _HPKE_INTERNAL_H_
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include "hpke.h"

#define P256_COORD_LEN          32
#define P384_COORD_LEN          48
#define P521_COORD_LEN          66

#define HPKE_MAX_HASH_LEN       64
#define HPKE_MAX_KEY_LEN        32

/*
 * same function, different internals... grrrr
 */
#define KEM_LABELED     1
#define HPKE_LABELED    2

typedef struct _hpke_ctx {
    unsigned char mode;
    int debug;
    int setup;
    BN_CTX *bnctx;
    uint16_t kem;
    uint16_t kdf_id;
    uint16_t aead_id;
    const EVP_MD *kem_h;
    unsigned char kem_Nh;
    const EVP_MD *kdf_h;
    unsigned char kdf_Nh;
    unsigned char Ndh;
    unsigned char Nn;
    unsigned char Nk;
    unsigned char kdf_len;
    EC_GROUP *curve;
    BIGNUM *skmeE;                      /* for encap only */
    EC_POINT *pkmeE;                    /*     ditto      */
    BIGNUM *skmeS;
    EC_POINT *pkmeS;
    EC_POINT *pkPeer;
    EC_POINT *idPeer;                   /* for decap AUTH mode only */
    unsigned char key[HPKE_MAX_KEY_LEN];
    unsigned char base_nonce[AES_BLOCK_SIZE];
    unsigned char exporter[HPKE_MAX_HASH_LEN];
    unsigned char *psk;
    int psk_len;
    char *psk_id;
    int psk_id_len;
    uint32_t seq;
} hpke_ctx;

/*
 * an additional APIs, this is needed for test vectors but we don't want to
 * export this to an hpke app
 */
int get_exporter(hpke_ctx *, unsigned char **);

#endif  /* _HPKE_INTERNAL_H_ */

