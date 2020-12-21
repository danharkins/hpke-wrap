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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "jsmn.h"
#include "hpke_internal.h"      // because we're mucking with an internal datastructure
                                // otherwise it should just be hpke.h
static int skip_object(jsmntok_t *t);
static int skip_array(jsmntok_t *t);
static int skip_string(jsmntok_t *t);
static int skip_primitive(jsmntok_t *t);
static int dump_object(jsmntok_t *t, char *, int);
static int dump_array(jsmntok_t *t, char *, int);
static int dump_string(jsmntok_t *t, char *, int);
static int dump_primitive(jsmntok_t *t, char *, int);

static int dump_level = 0;

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

/*
 * convert an ASCII character string into a usable octet string
 */
void
s2os (char *str, int slen, unsigned char **os, int *oslen)
{
    int i, val;
    char *ptr;
    unsigned char *op;
    
    *oslen = slen/2;
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

/*
 * skip over a single token by its type
 */
static int
skip_single (jsmntok_t *t)
{
    int i;
    
    switch (TOKTYPE(t)) {
        case JSMN_OBJECT:
            i = skip_object(t);
            break;
        case JSMN_ARRAY:
            i = skip_array(t);
            break;
        case JSMN_STRING:
            i = skip_string(t);
            break;
        case JSMN_PRIMITIVE:
            i = skip_primitive(t);
            break;
        default:
            i = 1;
    }
    return i;
}

static int
skip_string (jsmntok_t *t)
{
    return 1;
}

static int
skip_primitive (jsmntok_t *t)
{
    return 1;
}

/*
 * skip over an object
 */
static int
skip_object (jsmntok_t *tok)
{
    int i, j;
    jsmntok_t *t;

    i = 0;
    t = tok + 1;
    /*
     * an object is followed by another token and it's attributes...
     */
    for (j = 0; j < tok->size; j++) {
        i += skip_single(t);
        i += skip_single(t+1);
        t = tok + i + 1;
    }
    return i+1;
}

/*
 * skip over an array of tokens
 */
int
skip_array (jsmntok_t *tok)
{
    int i, j;
    jsmntok_t *t;

    i = 0;
    t = tok + 1;
    /*
     * an array is a series of tokens
     */
    for (j = 0; j < tok->size; j++) {
        i += skip_single(t);
        t = tok + i + 1;
    }
    return i+1;
}

void
dump_indent (void)
{
    int i;

    for (i = 0; i < dump_level; i++) {
        printf("\t");
    }
}

/*
 * dump a single token by its type
 */
static int
dump_single (jsmntok_t *t, char *buf, int len)
{
    int i;
    
    switch (TOKTYPE(t)) {
        case JSMN_OBJECT:
            i = dump_object(t, buf, len);
            break;
        case JSMN_ARRAY:
            i = dump_array(t, buf, len);
            break;
        case JSMN_STRING:
            i = dump_string(t, buf, len);
            break;
        case JSMN_PRIMITIVE:
            i = dump_primitive(t, buf, len);
            break;
        default:
            i = 1;
    }
    return i;
}

static int
dump_string (jsmntok_t *t, char *buf, int len)
{
    char *str;
    
    str = buf + TOKSTART(t);
    printf("string: %.*s", TOKLEN(t), str);
    return 1;
}

static int
dump_primitive (jsmntok_t *t, char *buf, int len)
{
    int val;
    
    val = atoi(buf + TOKSTART(t));
    printf("primitive: %d", val);
    return 1;
}

/*
 * got through each member of an object (which is token, token) and dump its contents
 */
static int
dump_object (jsmntok_t *tok, char *buf, int len)
{
    int i, j;
    jsmntok_t *t;

    dump_level++;
    i = 0;
    t = tok + 1;
    /*
     * an object is followed by another token and it's attributes...
     */
    printf("an object of %d\n", tok->size);
    for (j = 0; j < tok->size; j++) {
        dump_indent();
        i += dump_single(t, buf, len);
        printf(", ");
        i += dump_single(t+1, buf, len);
        printf("\n");
        t = tok + i + 1;
    }
    dump_level--;
    return i+1;
}

/*
 * go through each member of an array (just a single token) and print its contents
 */
int
dump_array (jsmntok_t *tok, char *buf, int len)
{
    int i, j;
    jsmntok_t *t;

    dump_level++;
    i = 0;
    t = tok + 1;
    /*
     * an array is a series of tokens
     */
    printf("an array of %d\n", tok->size);
    for (j = 0; j < tok->size; j++) {
        dump_indent();
        i += dump_single(t, buf, len);
        printf("\n");
        t = tok + i + 1;
    }
    dump_level--;
    return i+1;
}

/*
 * find the string that matches "match" and return the next token as an integer
 */
int
get_primitive (jsmntok_t *tok, char *buf, int len, char *match)
{
    jsmntok_t *t;
    int i, j, val;
    char *str;

    i = 0;
    t = tok + 1;
    for (j = 0; j < tok->size; j++) {
        if (TOKTYPE(t) == JSMN_STRING) {
            str = buf + TOKSTART(t);
            if (memcmp(buf + TOKSTART(t), match, strlen(match)) == 0) {
                i += skip_single(t);
                if (TOKTYPE(t+1) == JSMN_PRIMITIVE) {
                    val = atoi(buf + TOKSTART(t+1));
                    return val;
                }
                i += skip_single(t+1);
                t = tok + i + 1;
                continue;
            }
            i += skip_single(t);
            i += skip_single(t+1);
            t = tok + i + 1;
        }
    }
    return 0;
}

/*
 * find the string that matches "match" and return the next token as a string in "res"
 */
int
get_string (jsmntok_t *tok, char *buf, int len, char *match, char **res)
{
    jsmntok_t *t;
    int i, j;
    char *str;

    i = 0;
    t = tok + 1;
    for (j = 0; j < tok->size; j++) {
        if (TOKTYPE(t) == JSMN_STRING) {
            str = buf + TOKSTART(t);
            if ((TOKLEN(t) == strlen(match)) &&
                memcmp(buf + TOKSTART(t), match, TOKLEN(t)) == 0) {
                i += skip_single(t);
                if (TOKTYPE(t+1) == JSMN_STRING) {
                    *res = buf + TOKSTART(t+1);
                    return TOKLEN(t+1);
                }
                i += skip_single(t+1);
                t = tok + i + 1;
                continue;
            }
            i += skip_single(t);
            i += skip_single(t+1);
            t = tok + i + 1;
        }
    }
    return 0;
}

/*
 * For a single "exports" object, pull out the relevent strings 
 * and verify the decryption
 */
int
do_single_export (hpke_ctx *ctx, jsmntok_t *tok, char *buf, int len)
{
    char *str;
    unsigned char *context, *value, *myval;
    int context_len, value_len, explen, slen, res = -1;
    
    slen = get_string(tok, buf, len, "exporter_context", &str);
    s2os(str, slen, &context, &context_len);
    slen = get_string(tok, buf, len, "exported_value", &str);
    s2os(str, slen, &value, &value_len);
    explen = get_primitive(tok, buf, len, "L");

    export_secret(ctx, context, context_len, explen, &myval);
    if (memcmp(myval, value, explen) == 0) {
        res = 1;
    } else {
        print_buffer("exporter_context", context, context_len);
        printf("L: %d (value len = %d)\n", explen, value_len);
        print_buffer("expected value", value, value_len);
        print_buffer("computed value", myval, explen);
    }
    free(myval);
    free(context);
    free(value);
    return res;
}

int
do_exports (hpke_ctx *ctx, jsmntok_t *tok, char *buf, int len)
{
    jsmntok_t *t, *arr, *obj;
    int i, j, k, sz;

    i = 0;
    t = tok + 1;
    for (j = 0; j < tok->size; j++) {
        /*
         * the "exports" array of objects each of which reflects a single export API call
         */
        if (TOKTYPE(t) == JSMN_STRING) {
            if ((TOKLEN(t) == strlen("exports")) &&
                memcmp(buf + TOKSTART(t), "exports", TOKLEN(t)) == 0) {
                i += skip_single(t);
                if (TOKTYPE(t+1) == JSMN_ARRAY) {
                    arr = t + 1;
                    obj = arr + 1;
                    sz = 0;
                    for (k = 0; k < arr->size; k++) {
                        if (do_single_export(ctx, obj, buf, len) < 0) {
                            fprintf(stderr, "export %d of %d failed\n", k, arr->size);
                            return -1;
                        }
                        sz += skip_single(obj);
                        obj = arr + sz + 1;
                    }
                    return 1;
                }
                i += skip_single(t+1);
                t = tok + i + 1;
                continue;
            }
            i += skip_single(t);
            i += skip_single(t+1);
            t = tok + i + 1;
        }
    }
    return 1;
}

/*
 * For a single "encryptions" object, pull out the relevent strings 
 * and verify the decryption
 */
int
do_single_decryption (hpke_ctx *ctx, jsmntok_t *tok, char *buf, int len)
{
    char *str;
    unsigned char *aad, *ct, *nonce, *pt, *mypt;
    int aad_len, ct_len, nonce_len, pt_len, slen, res = -1;
    
    slen = get_string(tok, buf, len, "aad", &str);
    s2os(str, slen, &aad, &aad_len);
    slen = get_string(tok, buf, len, "ciphertext", &str);
    s2os(str, slen, &ct, &ct_len);
    slen = get_string(tok, buf, len, "nonce", &str);
    s2os(str, slen, &nonce, &nonce_len);
    slen = get_string(tok, buf, len, "plaintext", &str);
    s2os(str, slen, &pt, &pt_len);

    if ((mypt = (unsigned char *)malloc(pt_len)) == NULL) {
        fprintf(stderr, "unable to allocate space to decrypt!\n");
        return res;
    }
    unwrap(ctx, aad, aad_len, ct, ct_len-16, mypt, ct + (ct_len - 16));
    if (memcmp(mypt, pt, pt_len) == 0) {
        res = 1;
    }
    free(mypt);
    free(aad);
    free(ct);
    free(nonce);
    free(pt);
    return res;
}

int
do_decryptions (hpke_ctx *ctx, jsmntok_t *tok, char *buf, int len)
{
    jsmntok_t *t, *arr, *obj;
    int i, j, k, sz;

    i = 0;
    t = tok + 1;
    for (j = 0; j < tok->size; j++) {
        /*
         * the "encryptions" array of objects has everything we need for decryption
         * just do the same thing as do_encryptions()
         */
        if (TOKTYPE(t) == JSMN_STRING) {
            if ((TOKLEN(t) == strlen("encryptions")) &&
                memcmp(buf + TOKSTART(t), "encryptions", TOKLEN(t)) == 0) {
                i += skip_single(t);
                if (TOKTYPE(t+1) == JSMN_ARRAY) {
                    arr = t + 1;
                    obj = arr + 1;
                    sz = 0;
                    for (k = 0; k < arr->size; k++) {
                        if (do_single_decryption(ctx, obj, buf, len) < 0) {
                            fprintf(stderr, "decryption %d of %d failed\n", k, arr->size);
                            return -1;
                        }
                        sz += skip_single(obj);
                        obj = arr + sz + 1;
                    }
                    return 1;
                }
                i += skip_single(t+1);
                t = tok + i + 1;
                continue;
            }
            i += skip_single(t);
            i += skip_single(t+1);
            t = tok + i + 1;
        }
    }
    return 1;
}

/*
 * For a single "encryptions" object, pull out the relevent strings 
 * and verify the encryption
 */
int
do_single_encryption (hpke_ctx *ctx, jsmntok_t *tok, char *buf, int len)
{
    char *str;
    unsigned char *aad, *ct, *nonce, *pt, *myct;
    int aad_len, ct_len, nonce_len, pt_len, slen, res = -1;
    
    slen = get_string(tok, buf, len, "aad", &str);
    s2os(str, slen, &aad, &aad_len);
    slen = get_string(tok, buf, len, "ciphertext", &str);
    s2os(str, slen, &ct, &ct_len);
    slen = get_string(tok, buf, len, "nonce", &str);
    s2os(str, slen, &nonce, &nonce_len);
    slen = get_string(tok, buf, len, "plaintext", &str);
    s2os(str, slen, &pt, &pt_len);

    if ((myct = (unsigned char *)malloc(ct_len)) == NULL) {
        fprintf(stderr, "unable to allocate space to encrypt!\n");
        return res;
    }
    wrap(ctx, aad, aad_len, pt, pt_len, myct, myct+pt_len);
    if (memcmp(myct, ct, ct_len) == 0) {
        res = 1;
    }
    free(myct);
    free(aad);
    free(ct);
    free(nonce);
    free(pt);
    return res;
}

int
do_encryptions (hpke_ctx *ctx, jsmntok_t *tok, char *buf, int len)
{
    jsmntok_t *t, *arr, *obj;
    int i, j, k, sz;

    i = 0;
    t = tok + 1;
    for (j = 0; j < tok->size; j++) {
        /*
         * find "encryptions" which is an array of objects
         */
        if (TOKTYPE(t) == JSMN_STRING) {
            if ((TOKLEN(t) == strlen("encryptions")) &&
                memcmp(buf + TOKSTART(t), "encryptions", TOKLEN(t)) == 0) {
                i += skip_single(t);
                if (TOKTYPE(t+1) == JSMN_ARRAY) {
                    /*
                     * go through all the objects in the array...
                     */
                    arr = t + 1;
                    obj = arr + 1;
                    sz = 0;
                    for (k = 0; k < arr->size; k++) {
                        /*
                         * ...each of which represents a single encryption
                         */
                        if (do_single_encryption(ctx, obj, buf, len) < 0) {
                            fprintf(stderr, "encryption %d of %d failed\n", k, arr->size);
                            return -1;
                        }
                        sz += skip_single(obj);
                        obj = arr + sz + 1;
                    }
                    return 1;
                }
                i += skip_single(t+1);
                t = tok + i + 1;
                continue;
            }
            i += skip_single(t);
            i += skip_single(t+1);
            t = tok + i + 1;
        }
    }
    return 1;
}

int
main (int argc, char **argv)
{
    jsmn_parser p;
    jsmntok_t *tok, *toks, *t;
    int c, fd = -1, ntoks, ndata, i, j, len, kem, kdf, aead, mode, jsondump = 0, deb = 0, chatty = 0;
    char jsondata[8000000], *str;
    unsigned char *ikmE, *pkRm, *ikmS, *pkSm, *ikmR, *pkEm, *psk, *psk_id, *key, *exp, *info, *enc, *tvenc;
    int ikmE_len, pkRm_len, ikmS_len, pkSm_len, ikmR_len, pkEm_len, psk_len, psk_id_len;
    int key_len, exp_len, info_len, enc_len, tvenc_len;
    hpke_ctx *ctx;

    for (;;) {
        c = getopt(argc, argv, "t:vjhd");
        if (c < 0) {
            break;
        }
        switch (c) {
            case 't':
                if ((fd = open(optarg, O_RDONLY)) < 0) {
                    fprintf(stderr, "%s: unable to open %s\n", argv[0], optarg);
                    exit(1);
                }
                break;
            case 'v':
                deb = 1;
                break;
            case 'j':
                jsondump = 1;
                break;
            case 'd':
                chatty = 1;
                break;
            case 'h':
            default:
                fprintf(stderr, "USAGE: %s -t <tv> [-jvdh]\n"
                        "\t-t  the JSON test vectors\n"
                        "\t-j  dump the test vector contents\n"
                        "\t-d  chatty progress of test vectors\n"
                        "\t-v  verbose HPKE output\n"
                        "\t-h  this help message\n",
                        argv[0]);
                exit(1);
        }
    }
    if (fd < 1) {
        fprintf(stderr, "USAGE: %s -t <tv> [-jvdh]\n"
                "\t-t  the JSON test vectors\n"
                "\t-j  dump the test vector contents\n"
                "\t-d  chatty progress of test vectors\n"
                "\t-v  verbose HPKE output\n"
                "\t-h  this help message\n",
                argv[0]);
        exit(1);
    }
    memset(jsondata, 0, sizeof(jsondata));
    ndata = read(fd, jsondata, sizeof(jsondata));
    if (ndata < 1) {
        fprintf(stderr, "%s: failed to read json data (%d)\n", argv[0], ndata);
        exit(1);
    }
    close(fd);
    jsmn_init(&p);
    if ((ntoks = jsmn_parse(&p, jsondata, ndata, NULL, 1000)) == 0) {
        fprintf(stderr, "%s: unable to parse json data!\n", argv[0]);
        exit(1);
    }
    if (ntoks < 1) {
        fprintf(stderr, "%s: failure to parse json data (%d tokens)\n", argv[0], ntoks);
        exit(1);
    }
    if ((toks = (jsmntok_t *)malloc(ntoks * sizeof(jsmntok_t))) == NULL) {
        fprintf(stderr, "%s: unable to allocate %d jsmn tokens\n", argv[0], ntoks);
        exit(1);
    }
    jsmn_init(&p);
    if ((ntoks = jsmn_parse(&p, jsondata, ndata, toks, ntoks)) == 0) {
        fprintf(stderr, "%s: unable to parse json data!\n", argv[0]);
        exit(1);
    }
    tok = &toks[0];
    if (TOKTYPE(tok) != JSMN_ARRAY) {
        fprintf(stderr, "%s: first token is not a jsmn object!\n", argv[0]);
        exit(1);
    }
    j = 1;
    for (i = 0; i < tok->size; i++) {
        t = toks + j;
        if (TOKTYPE(t) != JSMN_OBJECT) {
            fprintf(stderr, "malformed test vectors!\n");
            exit(1);
        }
        kem = get_primitive(t, jsondata, ndata, "kem_id");
        /*
         * only interested in the KEMs using the NIST curves
         */
        if ((kem == 16) || (kem == 17) || (kem == 18)) {
            if (jsondump) {
                dump_object(t, jsondata, ndata);
            }
            mode = get_primitive(t, jsondata, ndata, "mode");
            kdf = get_primitive(t, jsondata, ndata, "kdf_id");
            aead = get_primitive(t, jsondata, ndata, "aead_id");
            if (chatty) {
                printf("%d- %d/%d/%d/%d: ", i, kem, mode, kdf, aead); fflush(stdout);
            }
            len = get_string(t, jsondata, ndata, "ikmE", &str);
            s2os(str, len, &ikmE, &ikmE_len);
            len = get_string(t, jsondata, ndata, "pkRm", &str);
            s2os(str, len, &pkRm, &pkRm_len);
            len = get_string(t, jsondata, ndata, "ikmS", &str);
            s2os(str, len, &ikmS, &ikmS_len);
            len = get_string(t, jsondata, ndata, "pkSm", &str);
            s2os(str, len, &pkSm, &pkSm_len);
            len = get_string(t, jsondata, ndata, "ikmR", &str);
            s2os(str, len, &ikmR, &ikmR_len);
            len = get_string(t, jsondata, ndata, "pkEm", &str);
            s2os(str, len, &pkEm, &pkEm_len);
            len = get_string(t, jsondata, ndata, "info", &str);
            s2os(str, len, &info, &info_len);
            len = get_string(t, jsondata, ndata, "psk", &str);
            s2os(str, len, &psk, &psk_len);
            len = get_string(t, jsondata, ndata, "psk_id", &str);
            s2os(str, len, &psk_id, &psk_id_len);
            len = get_string(t, jsondata, ndata, "key", &str);
            s2os(str, len, &key, &key_len);
            len = get_string(t, jsondata, ndata, "enc", &str);
            s2os(str, len, &tvenc, &tvenc_len);
            len = get_string(t, jsondata, ndata, "exporter_secret", &str);
            s2os(str, len, &exp, &exp_len);
            /*
             * do the sender side first...
             */
            if ((ctx = create_hpke_context(mode, kem, kdf, aead)) == NULL) {
                fprintf(stderr, "%s: unable to create HPKE context!\n", argv[0]);
                exit(1);
            }
            if (deb) {
                set_hpke_debug(ctx, 1);
            }
            if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
                fprintf(stderr, "%s: unable to derive ephemeral keypair!\n", argv[0]);
                exit(1);
            }
            switch (mode) {
                case MODE_BASE:
                    if (sender(ctx, pkRm, pkRm_len, info, info_len, NULL, 0, NULL, 0, &enc, &enc_len) < 1) {
                        fprintf(stderr, "%s: can't invoke BASE sender\n", argv[0]);
                        exit(1);
                    }
                    break;
                case MODE_PSK:
                    if (sender(ctx, pkRm, pkRm_len, info, info_len,
                               psk, psk_len, psk_id, psk_id_len, &enc, &enc_len) < 1) {
                        fprintf(stderr, "%s: can't invoke PSK sender\n", argv[0]);
                        exit(1);
                    }
                    break;
                case MODE_AUTH:
                    if (derive_local_static_keypair(ctx, ikmS, ikmS_len) < 1) {
                        fprintf(stderr, "%s: can't derive local AUTH static key\n", argv[0]);
                        exit(1);
                    }
                    if (sender(ctx, pkRm, pkRm_len, info, info_len, NULL, 0, NULL, 0, &enc, &enc_len) < 1) {
                        fprintf(stderr, "%s: can't invoke AUTH sender\n", argv[0]);
                        exit(1);
                    }
                    break;
                case MODE_AUTH_PSK:
                    if (derive_local_static_keypair(ctx, ikmS, ikmS_len) < 1) {
                        fprintf(stderr, "%s: can't derive local AUTH static key\n", argv[0]);
                        exit(1);
                    }
                    if (sender(ctx, pkRm, pkRm_len, info, info_len,
                               psk, psk_len, psk_id, psk_id_len, &enc, &enc_len) < 1) {
                        fprintf(stderr, "%s: can't invoke AUTH sender\n", argv[0]);
                        exit(1);
                    }
                    break;
            }                    
            if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
                fprintf(stderr, "Send key schedule %d failed!\n", i);
                print_buffer("ctx->key", ctx->key, ctx->Nk);
                print_buffer("json key", key, key_len);
                print_buffer("ctx->exp", ctx->exporter, ctx->kdf_Nh);
                print_buffer("json exp", exp, exp_len);
                exit(1);
            }
            if ((tvenc_len != enc_len) || memcmp(tvenc, enc, enc_len)) {
                fprintf(stderr, "enc mismatch %d!\n", i);
                print_buffer("tv enc", tvenc, tvenc_len);
                print_buffer("computed enc", enc, enc_len);
            }
            if (chatty) {
                printf("send..."); fflush(stdout);
            }
            if (do_encryptions(ctx, t, jsondata, ndata) < 0) {
                fprintf(stderr, "Encryption failed!\n");
                exit(1);
            }
            if (chatty) {
                printf("encryptions..."); fflush(stdout);
            }
            free(enc);
            free_hpke_context(ctx);
            /*
             * now do the receiver side...
             */
            if ((ctx = create_hpke_context(mode, kem, kdf, aead)) == NULL) {
                fprintf(stderr, "%s: unable to create HPKE context!\n", argv[0]);
                exit(1);
            }
            if (deb) {
                set_hpke_debug(ctx, 1);
            }
            if (derive_local_static_keypair(ctx, ikmR, ikmR_len) < 1) {
                fprintf(stderr, "%s: unable to derive local static keypair\n", argv[0]);
                exit(1);
            }
            switch (mode) {
                case MODE_BASE:
                    if (receiver(ctx, pkEm, pkEm_len, info, info_len, NULL, 0, NULL, 0) < 1) {
                        fprintf(stderr, "%s: can't invoke BASE receiver\n", argv[0]);
                        exit(1);
                    }
                    break;
                case MODE_PSK:
                    if (receiver(ctx, pkEm, pkEm_len, info, info_len,
                                 psk, psk_len, psk_id, psk_id_len) < 1) {
                        fprintf(stderr, "%s: can't invoke PSK receiver\n", argv[0]);
                        exit(1);
                    }
                    break;
                case MODE_AUTH:
                    if (assign_peer_static_keypair(ctx, pkSm, pkSm_len) < 1) {
                        fprintf(stderr, "%s: can't derive local AUTH static peer key\n", argv[0]);
                        exit(1);
                    }
                    if (receiver(ctx, pkEm, pkEm_len, info, info_len, NULL, 0, NULL, 0) < 1) {
                        fprintf(stderr, "%s: can't invoke AUTH receiver\n", argv[0]);
                        exit(1);
                    }
                    break;
                case MODE_AUTH_PSK:
                    if (assign_peer_static_keypair(ctx, pkSm, pkSm_len) < 1) {
                        fprintf(stderr, "%s: can't derive local AUTH static peer key\n", argv[0]);
                        exit(1);
                    }
                    if (receiver(ctx, pkEm, pkEm_len, info, info_len,
                                 psk, psk_len, psk_id, psk_id_len) < 1) {
                        fprintf(stderr, "%s: can't invoke AUTH receiver\n", argv[0]);
                        exit(1);
                    }
                    break;
            }                    
            if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
                fprintf(stderr, "Receive key sechedule %d failed\n", i);
                print_buffer("ctx->key", ctx->key, ctx->Nk);
                print_buffer("json key", key, key_len);
                print_buffer("ctx->exp", ctx->exporter, ctx->kdf_Nh);
                print_buffer("json exp", exp, exp_len);
                exit(1);
            }
            if (chatty) {
                printf("receive..."); fflush(stdout);
            }
            if (do_decryptions(ctx, t, jsondata, ndata) < 0) {
                fprintf(stderr, "Decryption failed!\n");
                exit(1);
            }
            if (chatty) {
                printf("decryptions..."); fflush(stdout);
            }

            if (do_exports(ctx, t, jsondata, ndata) < 0) {
                fprintf(stderr, "Exporter failed!\n");
                exit(1);
            }
            if (chatty) {
                printf("exports..."); fflush(stdout);
            }
            free_hpke_context(ctx);

            free(ikmE);
            free(pkRm);
            free(ikmS);
            free(pkSm);
            free(ikmR);
            free(pkEm);
            free(info);
            free(psk);
            free(psk_id);
            free(key);
            free(exp);
            free(tvenc);
            if (chatty) {
                printf("Passed!\n");
            }
        } else {
            if (chatty) {
                printf("%d does not use NIST curve, skip\n", i);
            }
//            if (jsondump) {
//                dump_object(t, jsondata, ndata);
//            }
        }
        j += skip_object(t);
    }
    free(toks);
    printf("all tests passed\n");
    exit(0);
}
