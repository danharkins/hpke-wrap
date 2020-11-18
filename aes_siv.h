/*
 * Copyright (c) The Industrial Lounge, 2007
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
 *  THIS SOFTWARE IS PROVIDED BY THE INDUSTRIAL LOUNGE ``AS IS'' 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INDUSTRIAL LOUNGE BE LIABLE
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
#ifndef _SIV_H_
#define _SIV_H_

#include <openssl/aes.h>

/*
 * stolen from openssl's aes_locl.h
 */
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64))
# define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
# define GETU32(p) SWAP(*((u32 *)(p)))
# define PUTU32(ct, st) { *((u32 *)(ct)) = SWAP((st)); }
#else
# define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
# define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }
#endif
#ifdef AES_LONG
typedef unsigned long u32;
#else
typedef unsigned int u32;
#endif
typedef unsigned short u16;
typedef unsigned char u8;

typedef struct _siv_ctx {
    unsigned char K1[AES_BLOCK_SIZE];
    unsigned char K2[AES_BLOCK_SIZE];
    unsigned char T[AES_BLOCK_SIZE];
    unsigned char benchmark[AES_BLOCK_SIZE];
    AES_KEY ctr_sched;
    AES_KEY s2v_sched;
} siv_ctx;

#define AES_128_BYTES	16
#define AES_192_BYTES	24
#define AES_256_BYTES	32
#define SIV_256         256
#define SIV_384         384
#define SIV_512         512

/*
 * non-exported APIs needed for a more full-throated SIV implementation
void aes_cmac (siv_ctx *, const unsigned char *, int, unsigned char *);
void siv_reset(siv_ctx *);
void s2v_benchmark(siv_ctx *);
void s2v_add(siv_ctx *, const unsigned char *);
void s2v_update(siv_ctx *, const unsigned char *, int);
int s2v_final(siv_ctx *, const unsigned char *, int, unsigned char *);
void siv_restart(siv_ctx *);
void siv_aes_ctr(siv_ctx *, const unsigned char *, const int, unsigned char *, 
                 const unsigned char *);
 */

/*
 * exported APIs
 */
int siv_init(siv_ctx *, const unsigned char *, int);
int siv_encrypt(siv_ctx *, const unsigned char *, unsigned char *, 
                const int, unsigned char *, const int, ... );
int siv_decrypt(siv_ctx *, const unsigned char *, unsigned char *,
                const int, unsigned char *, const int, ... );

#endif /* _SIV_H_ */
