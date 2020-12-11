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

#ifndef _HPKE_H_
#define _HPKE_H_
#include <arpa/inet.h>

#define DHKEM_P256      0x0010
#define DHKEM_P384      0x0011
#define DHKEM_P521      0x0012

#define HKDF_SHA_256    0x0001
#define HKDF_SHA_384    0x0002
#define HKDF_SHA_512    0x0003

#define AES_128_GCM     0x0001
#define AES_256_GCM     0x0002
#define ChaCha20Poly    0x0003
#define AES_256_SIV     0x0004
#define AES_512_SIV     0x0005

#define MODE_BASE       0x00
#define MODE_PSK        0x01
#define MODE_AUTH       0x02
#define MODE_AUTH_PSK   0x03

typedef struct _hpke_ctx hpke_ctx;

hpke_ctx *create_hpke_context(unsigned char, uint16_t, uint16_t, uint16_t);
void free_hpke_context(hpke_ctx *);
int assign_peer_static_keypair(hpke_ctx *, unsigned char *, int);
int generate_static_keypair(int, unsigned char **, int *, unsigned char **);
int derive_local_static_keypair(hpke_ctx *, unsigned char *, int);
int derive_ephem_keypair(hpke_ctx *, unsigned char *, int);
int generate_ephem_keypair(hpke_ctx *);
int sender(hpke_ctx *, unsigned char *, int, unsigned char *, int, char *, int, char *, int, 
           unsigned char **, int *);
int receiver(hpke_ctx *, unsigned char *, int, unsigned char *, int, char *, int, char *, int);
int get_exporter(hpke_ctx *, unsigned char **);
int wrap(hpke_ctx *, unsigned char *, int, unsigned char *, int, unsigned char *, unsigned char *);
int unwrap(hpke_ctx *, unsigned char *, int, unsigned char *, int, unsigned char *, unsigned char *);
void set_hpke_debug(hpke_ctx *, int);

#endif  /* _HPKE_H_ */

