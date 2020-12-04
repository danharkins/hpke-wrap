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
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "modes_local.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include "aes_siv.h"
#include "hpke_internal.h"
#include "hkdf.h"

/*
 * helpful debugging routines
 */
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
    printf("%s:\n", str);
    dump_buffer(buf, len);
    printf("\n");
}

static void
pp_a_bignum (char *str, BIGNUM *bn, int len)
{
    unsigned char *buf;

    if ((buf = malloc(len)) == NULL) {
        return;
    }
    memset(buf, 0, len);
    BN_bn2bin(bn, buf + (len - BN_num_bytes(bn)));
    print_buffer(str, buf, len);
    free(buf);
}

static void
print_ec_point (char *str, hpke_ctx *ctx, EC_POINT *point)
{
    BIGNUM *x = NULL, *y = NULL;
    
    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        !EC_POINT_get_affine_coordinates_GFp(ctx->curve, point, x, y, ctx->bnctx)) {
        goto fin;
    }
    printf("%s\n", str);
    pp_a_bignum("x", x, ctx->Ndh);
    pp_a_bignum("y", y, ctx->Ndh);
fin:
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
}

/*
 * append s2 to s1, returning an embiggened s1
 */
static unsigned char *
concat (unsigned char *s1, int *s1len, unsigned char *s2, int s2len)
{
    int newlen = *s1len + s2len;
    unsigned char *ptr;
    
    if ((s2 == NULL) || (s2len == 0)) {
        return s1;
    }
    if ((s1 = realloc(s1, newlen)) == NULL) {
        fprintf(stderr, "can't realloc string!\n");
        return NULL;
    }
    ptr = s1 + *s1len;
    memcpy(ptr, s2, s2len);
    *s1len = newlen;

    return s1;
}

/*
 * convert an EC_POINT to SECG uncompressed representation
 */
static int 
serialize_pubkey (hpke_ctx *ctx, EC_POINT *point, unsigned char **str)
{
    BIGNUM *x = NULL, *y = NULL;
    unsigned char *buf = NULL, secg_goo;
    int strlen;

    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        !EC_POINT_get_affine_coordinates_GFp(ctx->curve, point, x, y, ctx->bnctx)) {
        goto fin;
    }
    if ((buf = malloc(ctx->Ndh)) == NULL) {
        goto fin;
    }

    *str = NULL; strlen = 0;
    secg_goo = 0x04;            /* uncompressed */
    *str = concat(*str, &strlen, &secg_goo, 1);

    memset(buf, 0, ctx->Ndh);
    BN_bn2bin(x, buf + (ctx->Ndh - BN_num_bytes(x)));
    *str = concat(*str, &strlen, buf, ctx->Ndh);

    memset(buf, 0, ctx->Ndh);
    BN_bn2bin(y, buf + (ctx->Ndh - BN_num_bytes(y)));
    *str = concat(*str, &strlen, buf, ctx->Ndh);

fin:
    if (buf != NULL) {
        free(buf);
    }
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    return strlen;
}

/*
 * take an uncompressed SECG serialized public key and make an EC_POINT
 */
static EC_POINT *
deserialize_pubkey (hpke_ctx *ctx, unsigned char *str, int strlen)
{
    BIGNUM *x = NULL, *y = NULL;
    EC_POINT *point = NULL;
    
    if ((str[0] != 0x04) || (strlen != ((2 * ctx->Ndh) + 1))) {
        fprintf(stderr, "serialized pubkey is improperly formatted\n");
        goto fail;
    }
    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL)) {
        fprintf(stderr, "can't create bignums to deserialize!\n");
        goto fail;
    }
    BN_bin2bn(&str[1], ctx->Ndh, x);
    BN_bin2bn(&str[ctx->Ndh+1], ctx->Ndh, y);

    if ((point = EC_POINT_new(ctx->curve)) == NULL) {
        fprintf(stderr, "can't create point to deserialize!\n");
        goto fail;
    }
    if (!EC_POINT_set_affine_coordinates_GFp(ctx->curve, point, x, y, ctx->bnctx) ||
        !EC_POINT_is_on_curve(ctx->curve, point, ctx->bnctx)) {
        fprintf(stderr, "bad (x,y) coordinates in serialization!\n");
        EC_POINT_free(point);
        point = NULL;
        goto fail;
    }
fail:
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    return point;
}

/*
 * free the hpke context
 */
void
free_hpke_context (hpke_ctx *ctx)
{
    if (ctx->bnctx != NULL) {
        BN_CTX_free(ctx->bnctx);
    }
    if (ctx->skmeE != NULL) {
        BN_free(ctx->skmeE);
    }
    if (ctx->skmeS != NULL) {
        BN_free(ctx->skmeS);
    }
    if (ctx->pkmeE != NULL) {
        EC_POINT_free(ctx->pkmeE);
    }
    if (ctx->pkmeS != NULL) {
        EC_POINT_free(ctx->pkmeS);
    }
    if (ctx->pkPeer != NULL) {
        EC_POINT_free(ctx->pkPeer);
    }
    if (ctx->idPeer != NULL) {
        EC_POINT_free(ctx->idPeer);
    }
    if (ctx->psk != NULL) {
        free(ctx->psk);
    }
    if (ctx->psk_id != NULL) {
        free(ctx->psk_id);
    }
    if (ctx->curve != NULL) {
        EC_GROUP_free(ctx->curve);
    }
    free(ctx);
}

/*
 * create an hpke context for a particular kem, kdf, and aead. Optionally pass
 * a psk and psk_id for base derivation
 */
hpke_ctx *
create_hpke_context (unsigned char mode, uint16_t kem, uint16_t kdf_id, uint16_t aead_id,
                    char *psk, int psk_len, char *psk_id, int psk_id_len)
{
    hpke_ctx *ctx;
    int nid;

    if ((ctx = (hpke_ctx *)malloc(sizeof(hpke_ctx))) == NULL) {
        fprintf(stderr, "can't allocate context!\n");
        return NULL;
    }

    ctx->skmeE = NULL;
    ctx->pkmeE = NULL;
    ctx->skmeS = NULL;
    ctx->pkmeS = NULL;
    ctx->pkPeer = NULL;
    ctx->idPeer = NULL;

    if ((ctx->bnctx = BN_CTX_new()) == NULL) {
        fprintf(stderr, "can't create a bn context!\n");
        return NULL;
    }
    ctx->kem = kem;
    switch (kem) {
        case DHKEM_P256:
            ctx->kem_h = EVP_sha256();
            ctx->kem_Nh = 32;
            ctx->Ndh = 32;
            nid = NID_X9_62_prime256v1;
            break;
        case DHKEM_P384:
            ctx->kem_h = EVP_sha384();
            ctx->kem_Nh = 48;
            ctx->Ndh = 48;
            nid = NID_secp384r1;
            break;
        case DHKEM_P521:
            ctx->kem_h = EVP_sha512();
            ctx->kem_Nh = 64;
            ctx->Ndh = 66;
            nid = NID_secp521r1;
            break;
        default:
            fprintf(stderr, "unknown KEM: %d\n", kem);
            free(ctx);
            return NULL;
    }
    if ((ctx->curve = EC_GROUP_new_by_curve_name(nid)) == NULL) {
        fprintf(stderr, "unable to create keypair on p521\n");
        free(ctx);
        return NULL;
    }

    switch (kdf_id) {
        case HKDF_SHA_256:
            ctx->kdf_h = EVP_sha256();
            ctx->kdf_Nh = 32;
            break;
        case HKDF_SHA_384:
            ctx->kdf_h = EVP_sha384();
            ctx->kdf_Nh = 48;
            break;
        case HKDF_SHA_512:
            ctx->kdf_h = EVP_sha512();
            ctx->kdf_Nh = 64;
            break;
    }
    ctx->kdf_id = kdf_id;
    switch (aead_id) {
        case AES_128_GCM:
            ctx->Nn = 12;
            ctx->Nk = 16;
            break;
        case AES_256_GCM:
            ctx->Nn = 12;
            ctx->Nk = 32;
            break;
        case AES_256_SIV:
            ctx->Nn = 12;
            ctx->Nk = 32;
            break;
        case AES_512_SIV:
            ctx->Nn = 12;
            ctx->Nk = 64;
            break;
        case ChaCha20Poly:
            ctx->Nn = 12;
            ctx->Nk = 32;
            break;
        default:
            fprintf(stderr, "unknown AEAD: %d\n", aead_id);
            return NULL;
    }
    ctx->aead_id = aead_id;
    ctx->seq = 0;
    ctx->setup = 0;
    
    ctx->psk = NULL; ctx->psk_len = 0;
    ctx->psk_id = NULL; ctx->psk_id_len = 0;
    if (psk != NULL) {
        if ((mode == MODE_BASE) || (mode == MODE_AUTH)) {
            fprintf(stderr, "no psk mode indicated, but passed a psk!\n");
            free(ctx);
            return NULL;
        }
        if (psk_id == NULL) {
            fprintf(stderr, "psk is not NULL but psk_id is!\n");
            free(ctx);
            return NULL;
        }
        if ((ctx->psk = malloc(psk_len)) == NULL) {
            fprintf(stderr, "unable to allocate space for PSK!\n");
            free(ctx);
            return NULL;
        }
        if ((ctx->psk_id = malloc(psk_id_len)) == NULL) {
            fprintf(stderr, "unable to allocate space for PSK!\n");
            free(ctx->psk);
            free(ctx);
            return NULL;
        }
        ctx->psk_len = psk_len;
        memcpy(ctx->psk, psk, psk_len);
        ctx->psk_id_len = psk_id_len;
        memcpy(ctx->psk_id, psk_id, psk_id_len);
    } else if (psk_id != NULL) {
        fprintf(stderr, "psk is NULL but psk_id is not!\n");
        free(ctx);
        return NULL;
    } else if ((mode == MODE_PSK) || (mode == MODE_AUTH_PSK)) {
        fprintf(stderr, "indicated a PSK mode but no psk!\n");
        free(ctx);
        return NULL;
    }
    ctx->debug = 0;
    ctx->mode = mode;

    return ctx;
}

void
set_hpke_debug (hpke_ctx *ctx, int deb)
{
    ctx->debug = deb;
}

/*
 * compute a labeled HKDF extract.
 *
 * this routine is called for both kem and non-kem constructions with the
 * "type" indicating which flavor to do
 */
static void
labeled_extract (hpke_ctx *ctx, int type,
                 unsigned char *salt, int salt_len,
                 unsigned char *label, int label_len,
                 unsigned char *ikm, int ikm_len,
                 unsigned char *prk)
{
    uint16_t suite;
    unsigned char *str;
    int str_len;

    suite = htons(ctx->kem);
    str = NULL; str_len = 0;
    str = concat(str, &str_len, "HPKE-06", strlen("HPKE-06"));
    if (type == KEM_LABELED) {
        str = concat(str, &str_len, "KEM", 3);
        str = concat(str, &str_len, (unsigned char *)&suite, 2);
    } else {
        str = concat(str, &str_len, "HPKE", 4);
        str = concat(str, &str_len, (unsigned char *)&suite, 2);
        suite = htons(ctx->kdf_id);
        str = concat(str, &str_len, (unsigned char *)&suite, 2);
        suite = htons(ctx->aead_id);
        str = concat(str, &str_len, (unsigned char *)&suite, 2);
    }
    str = concat(str, &str_len, label, label_len);
    str = concat(str, &str_len, ikm, ikm_len);
    if (type == KEM_LABELED) {
        hkdf_extract(ctx->kem_h, salt, salt_len, str, str_len, prk);
    } else {
        hkdf_extract(ctx->kdf_h, salt, salt_len, str, str_len, prk);
    }        
    free(str);
    return;
}

/*
 * compute a labeled HKDF expand.
 *
 * this routine is called for both kem and non-kem constructions with the
 * "type" indicating which flavor to do
 */
static void
labeled_expand (hpke_ctx *ctx, int type, unsigned char *prk,
                unsigned char *label, int label_len,
                unsigned char *info, int info_len,
                unsigned char *out, int out_len)
{
    uint16_t suite, L;
    unsigned char *str;
    int str_len;

    suite = htons(ctx->kem);
    L = htons(out_len & 0xffff);

    str = NULL; str_len = 0;
    str = concat(str, &str_len, (unsigned char *)&L, 2);
    str = concat(str, &str_len, "HPKE-06", strlen("HPKE-06"));
    if (type == KEM_LABELED) {
        str = concat(str, &str_len, "KEM", 3);
        str = concat(str, &str_len, (unsigned char *)&suite, 2);
    } else {
        str = concat(str, &str_len, "HPKE", 4);
        str = concat(str, &str_len, (unsigned char *)&suite, 2);
        suite = htons(ctx->kdf_id);
        str = concat(str, &str_len, (unsigned char *)&suite, 2);
        suite = htons(ctx->aead_id);
        str = concat(str, &str_len, (unsigned char *)&suite, 2);
    }
    str = concat(str, &str_len, label, label_len);
    str = concat(str, &str_len, info, info_len);
    if (type == KEM_LABELED) {
        hkdf_expand(ctx->kem_h, prk, ctx->kem_Nh, str, str_len, out, out_len);
    } else {
        hkdf_expand(ctx->kdf_h, prk, ctx->kdf_Nh, str, str_len, out, out_len);
    }
    free(str);
    return;
}

/*
 * add the sender static keypair to the context (called by receiver only)
 */
int
assign_peer_static_keypair (hpke_ctx *ctx, unsigned char *pkS, int pkS_len)
{
    if ((ctx->idPeer = deserialize_pubkey(ctx, pkS, pkS_len)) == NULL) {
        fprintf(stderr, "unable to assign peer static keypair!\n");
        return -1;
    }
    return 1;
}

/*
 * derive a local static keypair, called by both sender and receiver
 */
int
derive_local_static_keypair (hpke_ctx *ctx, unsigned char *ikm, int ikm_len)
{
    unsigned char sec[P521_COORD_LEN], prk[P521_COORD_LEN];
    unsigned char counter;
    BIGNUM *order;
    const EC_POINT *G;

    if (((ctx->skmeS = BN_new()) == NULL) ||
        ((order = BN_new()) == NULL) ||
        ((ctx->pkmeS = EC_POINT_new(ctx->curve)) == NULL)) {
        fprintf(stderr, "unable to allocate state!\n");
        BN_free(order);
        return -1;
    }
    if (!EC_GROUP_get_order(ctx->curve, order, ctx->bnctx)) {
        fprintf(stderr, "you're out of order! this whole process is out of order!\n");
        return -1;
    }

    labeled_extract(ctx, KEM_LABELED, NULL, 0,
                    "dkp_prk", strlen("dkp_prk"), ikm, ikm_len, prk);
    counter = 0;
    do {
        labeled_expand(ctx, KEM_LABELED, prk, "candidate", strlen("candidate"), &counter, 1, sec, ctx->Ndh);
        if (ctx->kem == DHKEM_P521) {
            sec[0] &= 0x01;
        }
        counter++;
        BN_bin2bn(sec, ctx->Ndh, ctx->skmeS);
    } while (BN_ucmp(order, ctx->skmeS) < 0);
        
    G = EC_GROUP_get0_generator(ctx->curve);
    if (!EC_POINT_mul(ctx->curve, ctx->pkmeS, NULL, G, ctx->skmeS, ctx->bnctx)) {
        fprintf(stderr, "can't multiply priv*G!\n");
        BN_free(order);
        return -1;
    }

    BN_free(order);
    return 1;
}

/*
 * create an ephemeral keypair in order to encap (called by sender)
 */
int
derive_ephem_keypair (hpke_ctx *ctx, unsigned char *ikm, int ikm_len)
{
    unsigned char sec[P521_COORD_LEN], prk[P521_COORD_LEN];
    unsigned char counter;
    BIGNUM *order;
    const EC_POINT *G;

    if (((ctx->skmeE = BN_new()) == NULL) ||
        ((order = BN_new()) == NULL) ||
        ((ctx->pkmeE = EC_POINT_new(ctx->curve)) == NULL)) {
        fprintf(stderr, "unable to allocate state!\n");
        BN_free(order);
        return -1;
    }
    if (!EC_GROUP_get_order(ctx->curve, order, ctx->bnctx)) {
        fprintf(stderr, "you're out of order! this whole process is out of order!\n");
        return -1;
    }

    labeled_extract(ctx, KEM_LABELED, NULL, 0,
                    "dkp_prk", strlen("dkp_prk"), ikm, ikm_len, prk);
    counter = 0;
    do {
        labeled_expand(ctx, KEM_LABELED, prk, "candidate", strlen("candidate"), &counter, 1, sec, ctx->Ndh);
        if (ctx->kem == DHKEM_P521) {
            sec[0] &= 0x01;
        }
        counter++;
        BN_bin2bn(sec, ctx->Ndh, ctx->skmeE);
    } while (BN_ucmp(order, ctx->skmeE) < 0);
        
    G = EC_GROUP_get0_generator(ctx->curve);
    if (!EC_POINT_mul(ctx->curve, ctx->pkmeE, NULL, G, ctx->skmeE, ctx->bnctx)) {
        fprintf(stderr, "can't multiply priv*G!\n");
        BN_free(order);
        return -1;
    }

    BN_free(order);
    return 1;
}

/*
 * make a truly ephemeral keypair for the sender, send derive a random seed
 */
int
generate_ephem_keypair (hpke_ctx *ctx)
{
    unsigned char ikm[P521_COORD_LEN];

    if (!RAND_bytes(ikm, ctx->Ndh)) {
        fprintf(stderr, "unable to obtain random entrpy for keypair!\n");
        return -1;
    }
    derive_ephem_keypair(ctx, ikm, ctx->Ndh);
    return 1;
}

int
generate_static_keypair (int kem, unsigned char **ikm, int *ikm_len, unsigned char **pk)
{
    hpke_ctx *ctx;
    int pklen;

    if ((ctx = create_hpke_context(MODE_BASE, kem, HKDF_SHA_512, AES_512_SIV, NULL, 0, NULL, 0)) == NULL) {
        fprintf(stderr, "can't create hpke context to generate static keypair!\n");
        return -1;
    }
    if ((*ikm = (unsigned char *)malloc(ctx->Ndh)) == NULL) {
        fprintf(stderr, "can't allocate keying material to generate keypair!\n");
        free_hpke_context(ctx);
        return -1;
    }
    if (!RAND_bytes(*ikm, ctx->Ndh)) {
        fprintf(stderr, "can't allocate keying material to generate keypair!\n");
        free(*ikm);
        free_hpke_context(ctx);
        return -1;
    }
    derive_ephem_keypair(ctx, *ikm, ctx->Ndh);
    pklen = serialize_pubkey(ctx, ctx->pkmeE, pk);
    *ikm_len = ctx->Ndh;

    free_hpke_context(ctx);
    return pklen;
}

/*
 * returns length of "ssec" shared secret which is ctx->kem_Nh,
 */
static int
encap (hpke_ctx *ctx, unsigned char *pkSPeerbytes, int pkSPeerlen, unsigned char *ssec,
       unsigned char **enc, int *enc_len)
{
    BIGNUM *x = NULL;
    EC_POINT *secret = NULL;
    unsigned char *stat_enc, *kem_context, *dhres, prk[HPKE_MAX_HASH_LEN], dh[P521_COORD_LEN];
    int stat_enc_len, kem_cont_len, dhres_len, ret = 0;

    /*
     * if we haven't derived our keypair already then generate an ephemeral one
     */
    if (ctx->skmeE == NULL || ctx->pkmeE == NULL) {
        if (generate_ephem_keypair(ctx) < 1) {
            fprintf(stderr, "unable to generate keypair!\n");
            return -1;
        }
    }
    if (((ctx->mode == MODE_AUTH) || (ctx->mode == MODE_AUTH_PSK)) &&
        (ctx->skmeS == NULL)) {
        fprintf(stderr, "asymmetric auth mode set but no static key!\n");
        return -1;
    }
    if ((ctx->pkPeer = deserialize_pubkey(ctx, pkSPeerbytes, pkSPeerlen)) == NULL) {
        fprintf(stderr, "unable to deserialize pkSPeer!\n");
        return -1;
    }

    if (((secret = EC_POINT_new(ctx->curve)) == NULL) ||
        ((x = BN_new()) == NULL)) {
        fprintf(stderr, "unable to create secret point!\n");
        goto fail;
    }
    if (!EC_POINT_mul(ctx->curve, secret, NULL, ctx->pkPeer, ctx->skmeE, ctx->bnctx) ||
        !EC_POINT_get_affine_coordinates_GFp(ctx->curve, secret, x, NULL, ctx->bnctx)) {
        fprintf(stderr, "can't do DH!\n");
        goto fail;
    }
    memset(dh, 0, P521_COORD_LEN);
    BN_bn2bin(x, dh + (ctx->Ndh - BN_num_bytes(x)));
    if (ctx->debug) {
        pp_a_bignum("skmeE * pkPeer = secret.x", x, ctx->Ndh);
    }
    /*
     * do the ephermeral-static exchange with the recipient's static key
     */
    dhres = NULL; dhres_len = 0;
    dhres = concat(dhres, &dhres_len, dh, ctx->Ndh);

    if ((ctx->mode == MODE_AUTH) || (ctx->mode == MODE_AUTH_PSK)) {
        /*
         * if we're doing an asymmetric auth mode then do a static-static too
         */
        if (!EC_POINT_mul(ctx->curve, secret, NULL, ctx->pkPeer, ctx->skmeS, ctx->bnctx) ||
            !EC_POINT_get_affine_coordinates_GFp(ctx->curve, secret, x, NULL, ctx->bnctx)) {
            fprintf(stderr, "can't do DH!\n");
            goto fail;
        }
        memset(dh, 0, P521_COORD_LEN);
        BN_bn2bin(x, dh + (ctx->Ndh - BN_num_bytes(x)));
        if (ctx->debug) {
            pp_a_bignum("skmeS * pkPeer = secret.x", x, ctx->Ndh);
        }
        dhres = concat(dhres, &dhres_len, dh, ctx->Ndh);
    }        

    labeled_extract(ctx, KEM_LABELED, NULL, 0,
                    "eae_prk", strlen("eae_prk"), dhres, dhres_len, prk);
    free(dhres);

    if ((*enc_len = serialize_pubkey(ctx, ctx->pkmeE, enc)) < 1) {
        fprintf(stderr, "can't serialize pkE!\n");
        goto fail;
    }

    kem_context = NULL; kem_cont_len = 0;
    kem_context = concat(kem_context, &kem_cont_len, *enc, *enc_len);
    kem_context = concat(kem_context, &kem_cont_len, pkSPeerbytes, pkSPeerlen);

    if ((ctx->mode == MODE_AUTH) || (ctx->mode == MODE_AUTH_PSK)) {
        if ((stat_enc_len = serialize_pubkey(ctx, ctx->pkmeS, &stat_enc)) < 1) {
            fprintf(stderr, "can't serialize pkS!\n");
            goto fail;
        }
        kem_context = concat(kem_context, &kem_cont_len, stat_enc, stat_enc_len);
        free(stat_enc);
    }

    labeled_expand(ctx, KEM_LABELED, prk, "shared_secret", strlen("shared_secret"),
                   kem_context, kem_cont_len, ssec, ctx->kem_Nh);

    if (ctx->debug) {
        print_buffer("kem_context", kem_context, kem_cont_len);
        print_buffer("shared_secret", ssec, ctx->kem_Nh);
    }

    free(kem_context);
    ret = ctx->kem_Nh;
fail:
    if (secret != NULL) {
        EC_POINT_free(secret);
    }
    if (x != NULL) {
        BN_free(x);
    }
    return ret;
}

/*
 * returns length of "ssec" shared secret which is ctx->kem_Nh 
 */
static int
decap (hpke_ctx *ctx, unsigned char *pkEPeerbytes, int pkEPeerlen, unsigned char *ssec)
{
    BIGNUM *x = NULL;
    EC_POINT *secret = NULL;
    unsigned char *enc = NULL, *kem_context, *dhres, prk[HPKE_MAX_HASH_LEN], dh[P521_COORD_LEN];
    int kem_cont_len, enc_len, dhres_len, ret = 0;

    /*
     * make sure this is callable....
     */
    if (ctx->skmeS == NULL) {
        fprintf(stderr, "can't decap with no static key!\n");
        return -1;
    }
    if ((ctx->pkPeer = deserialize_pubkey(ctx, pkEPeerbytes, pkEPeerlen)) == NULL) {
        fprintf(stderr, "unable to deserialize pkEPeer!\n");
        return -1;
    }

    if (((secret = EC_POINT_new(ctx->curve)) == NULL) ||
        ((x = BN_new()) == NULL)) {
        fprintf(stderr, "unable to create secret point!\n");
        goto fail;
    }
    if (!EC_POINT_mul(ctx->curve, secret, NULL, ctx->pkPeer, ctx->skmeS, ctx->bnctx) ||
        !EC_POINT_get_affine_coordinates_GFp(ctx->curve, secret, x, NULL, ctx->bnctx)) {
        fprintf(stderr, "can't do DH!\n");
        goto fail;
    }
    memset(dh, 0, P521_COORD_LEN);
    BN_bn2bin(x, dh + (ctx->Ndh - BN_num_bytes(x)));
    if (ctx->debug) {
        pp_a_bignum("skmeS * pkEPeer = secret.x", x, ctx->Ndh);
    }
    
    /*
     * do the ephermeral-static exchange with the recipient's static key
     */
    dhres = NULL; dhres_len = 0;
    dhres = concat(dhres, &dhres_len, dh, ctx->Ndh);

    if ((ctx->mode == MODE_AUTH) || (ctx->mode == MODE_AUTH_PSK)) {
        /*
         * if we're doing an asymmetric auth mode then do a static-static too
         */
        if (!EC_POINT_mul(ctx->curve, secret, NULL, ctx->idPeer, ctx->skmeS, ctx->bnctx) ||
            !EC_POINT_get_affine_coordinates_GFp(ctx->curve, secret, x, NULL, ctx->bnctx)) {
            fprintf(stderr, "can't do DH!\n");
            goto fail;
        }
        memset(dh, 0, P521_COORD_LEN);
        BN_bn2bin(x, dh + (ctx->Ndh - BN_num_bytes(x)));
        if (ctx->debug) {
            pp_a_bignum("skmeS * pkSPeer = secret.x", x, ctx->Ndh);
        }
        dhres = concat(dhres, &dhres_len, dh, ctx->Ndh);
    }        

    labeled_extract(ctx, KEM_LABELED, NULL, 0,
                    "eae_prk", strlen("eae_prk"), dhres, dhres_len, prk);
    free(dhres);

    if ((enc_len = serialize_pubkey(ctx, ctx->pkmeS, &enc)) < 1) {
        fprintf(stderr, "can't serialize pkE!\n");
        goto fail;
    }

    kem_context = NULL; kem_cont_len = 0;
    kem_context = concat(kem_context, &kem_cont_len, pkEPeerbytes, pkEPeerlen);
    kem_context = concat(kem_context, &kem_cont_len, enc, enc_len);

    if ((ctx->mode == MODE_AUTH) || (ctx->mode == MODE_AUTH_PSK)) {
        free(enc);
        if ((enc_len = serialize_pubkey(ctx, ctx->idPeer, &enc)) < 1) {
            fprintf(stderr, "can't serialize pkS!\n");
            goto fail;
        }
        kem_context = concat(kem_context, &kem_cont_len, enc, enc_len);
    }
    free(enc);

    labeled_expand(ctx, KEM_LABELED, prk, "shared_secret", strlen("shared_secret"),
                   kem_context, kem_cont_len, ssec, ctx->kem_Nh);

    if (ctx->debug) {
        print_buffer("kem_context", kem_context, kem_cont_len);
        print_buffer("shared_secret", ssec, ctx->kem_Nh);
    }
    
    free(kem_context);
    ret = ctx->kem_Nh;
fail:
    if (secret != NULL) {
        EC_POINT_free(secret);
    }
    if (x != NULL) {
        BN_free(x);
    }
    return ret;
}

/*
 * the HPKE key schedule
 */
static int
key_schedule (hpke_ctx *ctx, unsigned char *shared, int shared_len, unsigned char *info, int info_len)
{
    unsigned char psk_id_hash[HPKE_MAX_HASH_LEN], info_hash[HPKE_MAX_HASH_LEN], sec[HPKE_MAX_HASH_LEN];
    unsigned char *key_sched_context;
    int key_sched_context_len;

    if (ctx->debug) {
        printf("kem_id: %d\nkdf_id: %d\naead_id: %d\n", ctx->kem, ctx->kdf_id, ctx->aead_id);
    }

    labeled_extract(ctx, HPKE_LABELED, NULL, 0,
                    "psk_id_hash", strlen("psk_id_hash"),
                    ctx->psk_id, ctx->psk_id_len, psk_id_hash);
    labeled_extract(ctx, HPKE_LABELED, NULL, 0,
                    "info_hash", strlen("info_hash"),
                    info, info_len, info_hash);

    key_sched_context = NULL; key_sched_context_len = 0;
    key_sched_context = concat(key_sched_context, &key_sched_context_len,
                               &ctx->mode, 1);
    key_sched_context = concat(key_sched_context, &key_sched_context_len,
                               psk_id_hash, ctx->kdf_Nh);
    key_sched_context = concat(key_sched_context, &key_sched_context_len,
                               info_hash, ctx->kdf_Nh);

    labeled_extract(ctx, HPKE_LABELED, shared, shared_len,
                    "secret", strlen("secret"),
                    ctx->psk, ctx->psk_len, sec);

    if (ctx->debug) {
        print_buffer("key sched context", key_sched_context, key_sched_context_len);
        print_buffer("secret", sec, ctx->kdf_Nh);
    }    

    labeled_expand(ctx, HPKE_LABELED, sec, "key", strlen("key"),
                   key_sched_context, key_sched_context_len, ctx->key, ctx->Nk);
    labeled_expand(ctx, HPKE_LABELED, sec, "base_nonce", strlen("base_nonce"),
                   key_sched_context, key_sched_context_len, ctx->base_nonce, ctx->Nn);
    labeled_expand(ctx, HPKE_LABELED, sec, "exp", strlen("exp"),
                   key_sched_context, key_sched_context_len, ctx->exporter, ctx->kdf_Nh);

    if (ctx->debug) {
        print_buffer("key", ctx->key, ctx->Nk);
        print_buffer("nonce", ctx->base_nonce, ctx->Nn);
        print_buffer("exp", ctx->exporter, ctx->kdf_Nh);
    }
    ctx->setup = 1;

    free(key_sched_context);
    return 1;
}

/*
 * Sender: get the peer's serialized static public key and some optional info,
 * generate a secret key, an exporter, and a base nonce in the context and
 * return "enc" which is sent to the peer for plumbing as a receiver.
 * Caller is responsible for freeing enc after use.
 */
int
sender (hpke_ctx *ctx, unsigned char *pkSPeerbytes, int pkSPeerlen,
        unsigned char *info, int info_len, unsigned char **enc, int *enc_len)
{
    unsigned char shared_secret[HPKE_MAX_HASH_LEN];
    int ss_len;
    
    if ((ss_len = encap(ctx, pkSPeerbytes, pkSPeerlen, shared_secret, enc, enc_len)) < 1) {
        fprintf(stderr, "sender can't do encap!\n");
        return -1;
    }

    if (key_schedule(ctx, shared_secret, ss_len, info, info_len) < 1) {
        fprintf(stderr, "sender can't do key schedule!\n");
        return -1;
    }

    return 1;
}

/*
 * Receiver: get the peer's serialized ephemeral public key and some optional info,
 * generate a secret key, an exporter, and a base nonce in the context
 */
int
receiver (hpke_ctx *ctx, unsigned char *pkEPeerbytes, int pkEPeerlen,
       unsigned char *info, int info_len)
{
    unsigned char shared_secret[HPKE_MAX_HASH_LEN];
    int ss_len;
    
    if ((ss_len = decap(ctx, pkEPeerbytes, pkEPeerlen, shared_secret)) < 1) {
        fprintf(stderr, "receiver can't do decap!\n");
        return -1;
    }

    if (key_schedule(ctx, shared_secret, ss_len, info, info_len) < 1) {
        fprintf(stderr, "receiver can't do key schedule!\n");
        return -1;
    }

    return 1;
}

/*
 * obtain the exporter from the context. Caller is responsible for freeing when done.
 * Returns size of allocated string.
 */
int
get_exporter (hpke_ctx *ctx, unsigned char **exporter)
{
    if (!ctx->setup) {
        return 0;
    }
    if ((*exporter = (unsigned char *)malloc(ctx->kdf_Nh)) == NULL) {
        return 0;
    }
    memcpy(*exporter, ctx->exporter, ctx->kdf_Nh);

    return ctx->kdf_Nh;
}

/*
 * AES-SIV-(256/512) encrypt-- get a context, aad, plaintext and a type (256 or 512) to produce
 * a ciphertext and tag
 */
static void
siv_wrap (hpke_ctx *ctx, int ver, unsigned char *aad, int aad_len, unsigned char *pt, int pt_len,
          unsigned char *ct, unsigned char *tag)
{
    siv_ctx sivc;

    siv_init(&sivc, ctx->key, ver);
    /*
     * AES-SIV takes a vector of AAD...
     *
     * deterministic, nonce-less HPKE does not need a nonce but we generate one
     * as part of the key schedule so we might as well use it. Just pass it as the
     * first component of the vector of AAD and send the passed AAD as the second 
     * component. 
     */
    siv_encrypt(&sivc, pt, ct, pt_len, tag, 2, ctx->base_nonce, ctx->Nn, aad, aad_len);
    return;
}

static int
evp_wrap (hpke_ctx *ctx, const EVP_CIPHER *whichone, unsigned char *aad, int aad_len,
          unsigned char *pt, int pt_len, unsigned char *ct, unsigned char *tag)
{
    EVP_CIPHER_CTX *cctx = NULL;
    int ret = -1, len = 0;
    unsigned char sequence[12], num[4];

    PUTU32(num, ctx->seq);
    memcpy(sequence, ctx->base_nonce, ctx->Nn);
    sequence[11] ^= num[3];
    sequence[10] ^= num[2];
    sequence[9]  ^= num[1];
    sequence[8]  ^= num[0];

    if (ctx->debug) {
        printf("wrap\nseq = %d\n", ctx->seq);
        print_buffer("nonce", ctx->base_nonce, ctx->Nn);
        print_buffer("num", num, 4);
        print_buffer("sequence", sequence, ctx->Nn);
        print_buffer("aad", aad, aad_len);
    }
    ctx->seq++;

    if ((cctx = EVP_CIPHER_CTX_new()) == NULL) {
        goto fin;
    }
    if (!EVP_EncryptInit_ex(cctx, whichone, NULL, ctx->key, sequence)) {
        fprintf(stderr, "can't initialize EVP encryption!\n");
        goto fin;
    }
    if (!EVP_EncryptUpdate(cctx, NULL, &len, aad, aad_len)) {
        fprintf(stderr, "can't add aad to encryption context\n");
        goto fin;
    }
    if (!EVP_EncryptUpdate(cctx, ct, &len, pt, pt_len)) {
        fprintf(stderr, "can't update plaintext into encryption context!\n");
        goto fin;
    }
    ret = len;
    if (!EVP_EncryptFinal(cctx, ct + len, &len)) {
        fprintf(stderr, "can't finalize encryption context!\n");
        ret = -1;
        goto fin;
    }
    ret += len;
    if (!EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)) {
        fprintf(stderr, "can't get tag from encryption context!\n");
        ret = -1;
        goto fin;
    }
fin:        
    if (cctx != NULL) {
        EVP_CIPHER_CTX_free(cctx);
    }
    return ret;
}

/*
 * generic wrapper to encryption: get context, aad, plaintext to produce a ciphertext and tag
 */
int
wrap (hpke_ctx *ctx, unsigned char *aad, int aad_len, unsigned char *pt, int pt_len,
      unsigned char *ct, unsigned char *tag)
{
    switch (ctx->aead_id) {
        case AES_128_GCM:
            if (evp_wrap(ctx, EVP_aes_128_gcm(), aad, aad_len, pt, pt_len, ct, tag) < 0) {
                return 0;
            }
            break;
        case AES_256_GCM:
            if (evp_wrap(ctx, EVP_aes_256_gcm(), aad, aad_len, pt, pt_len, ct, tag) < 0) {
                return 0;
            }
            break;
        case AES_256_SIV:
            siv_wrap(ctx, SIV_256, aad, aad_len, pt, pt_len, ct, tag);
            break;
        case AES_512_SIV:
            siv_wrap(ctx, SIV_512, aad, aad_len, pt, pt_len, ct, tag);
            break;
        case ChaCha20Poly:
            if (evp_wrap(ctx, EVP_chacha20_poly1305(), aad, aad_len, pt, pt_len, ct, tag) < 0) {
                return 0;
            }
            break;
    }
    return pt_len;
}

/*
 * AES-SIV-(256/512) decrypt-- given ciphertext, tag, aad, and a version (256 or 512) produce plaintext
 */
static int
siv_unwrap (hpke_ctx *ctx, int ver, unsigned char *aad, int aad_len, unsigned char *ct, int ct_len,
          unsigned char *pt, unsigned char *tag)
{
    siv_ctx sivc;

    siv_init(&sivc, ctx->key, ver);
    return siv_decrypt(&sivc, ct, pt, ct_len, tag, 2, ctx->base_nonce, ctx->Nn, aad, aad_len);
}

static int
evp_unwrap (hpke_ctx *ctx, const EVP_CIPHER *whichone, unsigned char *aad, int aad_len,
            unsigned char *ct, int ct_len, unsigned char *pt, unsigned char *tag)
{
    EVP_CIPHER_CTX *cctx = NULL;
    int ret = -1, len = 0;
    unsigned char sequence[12], num[4];

    PUTU32(num, ctx->seq);
    memcpy(sequence, ctx->base_nonce, ctx->Nn);
    sequence[11] ^= num[3];
    sequence[10] ^= num[2];
    sequence[9]  ^= num[1];
    sequence[8]  ^= num[0];

    if (ctx->debug) {
        printf("wrap\nseq = %d\n", ctx->seq);
        print_buffer("nonce", ctx->base_nonce, ctx->Nn);
        print_buffer("num", num, 4);
        print_buffer("sequence", sequence, ctx->Nn);
        print_buffer("aad", aad, aad_len);
    }
    ctx->seq++;

    if ((cctx = EVP_CIPHER_CTX_new()) == NULL) {
        goto fin;
    }
    if (!EVP_DecryptInit_ex(cctx, whichone, NULL, ctx->key, sequence)) {
        fprintf(stderr, "can't initialize EVP encryption!\n");
        goto fin;
    }
    if (!EVP_DecryptUpdate(cctx, NULL, &len, aad, aad_len)) {
        fprintf(stderr, "can't add aad to encryption context\n");
        goto fin;
    }
    if (!EVP_DecryptUpdate(cctx, pt, &len, ct, ct_len)) {
        fprintf(stderr, "can't update plaintext into encryption context!\n");
        goto fin;
    }
    ret = len;
    if (!EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)) {
        fprintf(stderr, "can't get tag from encryption context!\n");
        ret = -1;
        goto fin;
    }
    if (!EVP_EncryptFinal(cctx, pt + len, &len)) {
        fprintf(stderr, "can't finalize decryption context!\n");
        ret = -1;
        goto fin;
    }
    ret += len;
fin:        
    if (cctx != NULL) {
        EVP_CIPHER_CTX_free(cctx);
    }
    return ret;
}

/*
 * generic wrapper for decryption
 */
int
unwrap (hpke_ctx *ctx, unsigned char *aad, int aad_len, unsigned char *ct, int ct_len,
      unsigned char *pt, unsigned char *tag)
{
    int ret = -1;
    
    switch (ctx->aead_id) {
        case AES_128_GCM:
            ret = evp_unwrap(ctx, EVP_aes_128_gcm(), aad, aad_len, ct, ct_len, pt, tag);
            break;
        case AES_256_GCM:
            ret = evp_unwrap(ctx, EVP_aes_256_gcm(), aad, aad_len, ct, ct_len, pt, tag);
            break;
        case AES_256_SIV:
            ret = siv_unwrap(ctx, SIV_256, aad, aad_len, ct, ct_len, pt, tag);
            break;
        case AES_512_SIV:
            ret = siv_unwrap(ctx, SIV_512, aad, aad_len, ct, ct_len, pt, tag);
            break;
        case ChaCha20Poly:
            ret = evp_unwrap(ctx, EVP_chacha20_poly1305(), aad, aad_len, ct, ct_len, pt, tag);
            break;
    }
    if (ret < 0) {
        printf("decryption failed\n");
    }
    return ret;
}

