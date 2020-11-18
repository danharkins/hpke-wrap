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
    char *a31ikmE = "827f27da166dfeaa8929c92d2a67018a66d7b465a44c168220088d430461bb72";
    char *a31pkRm = "04a33be520167c96134a03754478b115880f307fcfc7ae9873d6449963e2487b3a021be50200f71d4fe9c6dc4a2db04451fa8ff8b5840e1263697df8854b1187df";
    char *a31ikmR = "3c991968c9ce6f8e8f0fef41083ab91e9855b368b8714d78aacde3fc74b0fb5e";
    char *a31pkEm = "04a01b79a7807750c860610342450d54b5d4d91b8c51b698b37b6fdee6b97fa73da344ce28dafd89dc1daa929d1aa76349f6f4bc2bb0782674121a620072eb3b15";
    char *a31key = "0f1d817716a9fcfb3a733d7a9495b5ea";
    char *a31exp = "cec277f90ab42ff8b7e35a10802b5155f112eaf5b97ce19f9986ffccf77aa59e";

    char *a32ikmE = "38ba9b0034b4b5817a48e331882952b5f73c3e8b3fa8bae22b1350bee31b0b52";
    char *a32pkRm = "04c84a9e3179b21364316447674430bff4592844fcc1b508f3aded9d76bc324f6b345c74c142e4d2d02c7c9ac3dfcab28f8a819bf105ea0bb917d4d1b4bf10a2da";
    char *a32psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a32psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a32key = "3059b5cdb3be25ad8bcd5d670cfd8923";
    char *a32exp = "7f800f9dfbfdab3115997928daae8adc47849de64a329dca5808aad1eb88f9a6";

    char *a33ikmE = "b93d334f9b1de8d7e3ca0605fdb8d076a6a5fdaafde8eca7d67da75146413ff5";
    char *a33pkRm = "04fe92a2804e2a3881aed4a8460b91f17e473b31159f972a92dad286a43545f9c83a2c02624cbdcf16fa4a605224269cb59c2e60dd3e83b45c17e0716c824c7a2d";
    char *a33ikmS = "972ef5a16a6c0d7f4a02d3411c7e15f962c90406820685627bfd1a30c26c92d7";
    char *a33key = "b3bd2473b024dc462f0599ff8f88f26d";
    char *a33exp = "12b1f1e6712be78f1a39320356e81ff8dc21ec457c35e4d98aa08af0cc6ee717";

    char *a34ikmE = "ab72de85d4f56ece8c99eaf846f1309761726aebdfcc98ee0b2325a0b0e05747";
    char *a34pkRm = "0415df4b0cffe5238d4e5d9a128fd19ef0b1ca9c3a499e250060e4fe186400a8d68f5e16fa0ca3635c411e0fb0d7059757b5612d3803c69f96c1c140fe80fa5282";
    char *a34ikmS = "50750d36da3239c76d4d4ec1129460e5fec239b77d7a0de8094d58da7d4a24eb";
    char *a34pkSm = "046f215a93873508bbe37be23394cc79478fe719b72f4faca3237d67532279c74c9f1fd2b69a82bbb92af5b3b3af50020d7a199ed7e8c617aee8c78d5f3fdb15bd";
    char *a34ikmR = "b27e63ef5f94a3aed99170485f0c9335b160c8cd56c3b270c11442b0d66cb458";
    char *a34pkEm = "0451c17475f92a0f950a56bf5912798fd7a45ba0048fa04302c2c8013692f319165da9d853a2ecd8399d323e0a4d8fbb24c22031442709129c73d9e38194ee19b4";
    char *a34psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a34psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a34key = "78a83144b32ef6a55d8e95b6cf608a69";
    char *a34exp = "4aab5e9c447f32892d0f171dd168b257e0b827da0fcd53543cd1f47649762220";
    char *a34pt = "4265617574792069732074727574682c20747275746820626561757479";
    char *a34aad1 = "436f756e742d30";
    char *a34aad2 = "436f756e742d31";
    char *a34aad3 = "436f756e742d32";

    char *a44ikmE = "6145eeffb6f33b85f251e569175ec958a2df0bada63280e84021b3693b6bec6e";
    char *a44pkRm = "04de9e529271229501a424c3784b40aea872ad36d7b05bf5dbb76851349eadac3f97a729b1f697f154d3e0a5a53da3ff6bc59fcb6bb543873962fda2b08238ded0";
    char *a44ikmS = "247bfb9453018e7456d0fcea197bfa180f8ed21fb03c50781d4d1ea76c73b41d";
    char *a44pkSm = "04e8e975005ffc567698b3d6d48bf967c7306d5a480ac049589da8bda8892354428cf88a4ac3188901b976805f34a2b9e250cf1ae0da92ba5c35cc7cdbdabeda37";
    char *a44ikmR = "66b2e8f713bdaefae23d0bd3bcf5ac7567873d399cfc5821928e008f981be915";
    char *a44pkEm = "0450a79483be0a777de1d5d6ca60d2a32b351ff99061d360e433ccd023b71640ff6dd6b40de4b30634cdb22e804d12b0082c22dbba47ca4775cdbceaa78dcef3cb";
    char *a44psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a44psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a44key = "f54a5adc57021b3d66c2687cc3b82fbf";
    char *a44exp = "2b8756aab46ffc1b45ebcd31bb555929cea5996181bb0d5a5426cffaf77031923db93501ceae9afedaf800cc3433650654b589634b144cddab69dbbba758f536";
    char *a44pt = "4265617574792069732074727574682c20747275746820626561757479";
    char *a44aad1 = "436f756e742d30";
    char *a44aad2 = "436f756e742d31";
    char *a44aad3 = "436f756e742d32";
    
    char *a61ikmE = "3fdb7eab3a6a99de8abbcb507be5704ae6a8994008b8a8e6b63fbd97fa8619c66bd8665c22079939f3f63f978c5806802b22ba5bb396da9cf252ee67068bf57461bf";
    char *a61pkRm = "04017b4d008b6602cf87554f1ae3f97c647da3ad5f347d73124495c6817d14f75c181c07519bf2988a37e14967ca10254364678268c6558714d8ff6d4d821bb4f523d101c55f6d4f9ab0d4bce925444e2219a2b0f96920051294ef36b03dd4c69bd332df0d884794d44f0eb2d5ad7af9396dc946d8e4a5325724a2f8f9d6b52cba7524b644";
    char *a61key = "57aeffb38c9b286367fde962c7d32bbab27075fa4d03d9a7465358d9e6fc6342";
    char *a61exp = "effa5f770620d75f76deec0f400dd42009c8088d296e58484e2a8d61e475d5a53639b7a909ca0651ab7787912962d2ea1e9133ed96db68fbc6cc4b9d9ab8ab2a";

    char *a64ikmE = "4ebb461a5c46330d6de3a40d19ac499cc206733cf1a4fb3ba922d976aa1c45848668f04a3b5a4845a0d1c83755967d8914a9824fbb8823d161c16c93c51636e1ad89";
    char *a64pkRm = "040161142294012f7f1e7af7ba86611de6d4cf7a7eb40498b7b40aee7ae2e9d8ac41b6a1615e076e0ffd0239e1e465b0b791601cfb62212732820223a2ef5f0e0ab3d7002c283a89ac436fd2967c5975b9db046c50fab2dbcc9b17de528f2d3d6ef4e520d111f433fdd8ee7885c89215668775bce903d73f4a0253407eeec920817fa04ae8";
    char *a64ikmS = "e0f2ada4f2a900fded767dc9868119ee3e4767afac667a780b68e5e2b4d7d363dbf02717ab314369c45f34dcec3de384a65e8453a971ad0353a507f34dc1d5d9b8f5";
    char *a64pkSm = "0401e965e58f927c571f468a1cfeb8eaf2c906cfa9f43f3c427dc8e5b4379c70e420f90f86c517ff17d1eb35aa7f071e89c07523099e14f7e033087a089984deaa73a90100bc0ee78fa5bf8d3956c1ca9d07ccc3ad6dca951108bbf0835fa2375dd3d45760b7999444e670b73cac2622d3fd75152217b17b88dac4935820c8c5a97550b509";
    char *a64ikmR = "1ae2f1008c46c7a6e9275b1e29c906475c6bc019b1dfc38cbce68c5233de9d33ba93fe9d7b9ea5beb04f4adc5a3b72238f6e3d904d29eb0680ea240103d3335a3c47";
    char *a64pkEm = "04005ecbb8a44f65b079fb6a025d0ed2a7c675113836b5143f7886bcf89cfb2cf0d26672874fb03124e0e6303cdecb139f964e78169aff79d7f57feebc66cf58747a3f010b14f67c282b091a5aefc87672951e5ddcb9f04897320a43c5aab8b9d03f1fc00a0c2f8b5af41abece59b17ca0f8427df7cb1cf79d01ac4013179a8cc66e94cee7";
    char *a64psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a64psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a64key = "ca510f3500c9050ca1b21b958464296bb16baceb4dee8fa6a3076a2430423d0a";
    char *a64exp = "f83d533341fb594fa6e2c4004fd10d73c9e939c7305a7ced4b92a64904ed0602994fd00cff4e4e06ba6e45d5d685650b24162ed4a6c31d944598649fe71cd44e";
    

    char *tvinfo = "4f6465206f6e2061204772656369616e2055726e";
    unsigned char *ikmE, *pkRm, *ikmR, *pkEm, *pkSm, *ikmS, *psk, *psk_id, *key, *exp, *info, *pt, *ct, *aad, *enc;
    int ikmE_len, pkRm_len, ikmR_len, pkEm_len, pkSm_len, ikmS_len, psk_len, psk_id_len, key_len, exp_len, info_len, pt_len, aad_len, enc_len;
    hpke_ctx *ctx;

    s2os(tvinfo, &info, &info_len);     /* same info every test */

    printf("A3.1 test\n");
    s2os(a31ikmE, &ikmE, &ikmE_len);
    s2os(a31pkRm, &pkRm, &pkRm_len);
    s2os(a31key, &key, &key_len);
    s2os(a31exp, &exp, &exp_len);
    s2os(a31ikmR, &ikmR, &ikmR_len);
    s2os(a31pkEm, &pkEm, &pkEm_len);

    if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P256,
                                   HKDF_SHA_256, AES_128_GCM, NULL, 0, NULL, 0)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.1 send failed!\n");
        exit(1);
    }
    free(enc);
    printf("A3.1 send passes!\n");
    free_hpke_context(ctx);

    if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P256,
                                   HKDF_SHA_256, AES_128_GCM, NULL, 0, NULL, 0)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }

    if (derive_local_static_keypair(ctx, ikmR, ikmR_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (receiver(ctx, pkEm, pkEm_len, info, info_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.1 receive failed!\n");
        exit(1);
    }
    printf("A3.1 recv passes!\n");

    free_hpke_context(ctx);
    free(ikmE);
    free(pkRm);
    free(ikmR);
    free(pkEm);
    free(key);
    free(exp);

    printf("--------------------------------------------\nA3.2 test\n");
    s2os(a32ikmE, &ikmE, &ikmE_len);
    s2os(a32pkRm, &pkRm, &pkRm_len);
    s2os(a32psk, &psk, &psk_len);
    s2os(a32psk_id, &psk_id, &psk_id_len);
    s2os(a32key, &key, &key_len);
    s2os(a32exp, &exp, &exp_len);
    
    if ((ctx = create_hpke_context(MODE_PSK, DHKEM_P256,
                                   HKDF_SHA_256, AES_128_GCM, 
                                   psk, psk_len, psk_id, psk_id_len)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.2 failed!\n");
        exit(1);
    }
    printf("A3.2 passes!\n");

    free_hpke_context(ctx);
    free(enc);
    free(ikmE);
    free(pkRm);
    free(psk);
    free(psk_id);
    free(key);
    free(exp);

    printf("--------------------------------------------\nA3.3 test\n");
    s2os(a33ikmE, &ikmE, &ikmE_len);
    s2os(a33pkRm, &pkRm, &pkRm_len);
    s2os(a33ikmS, &ikmS, &ikmS_len);
    s2os(a33key, &key, &key_len);
    s2os(a33exp, &exp, &exp_len);

    if ((ctx = create_hpke_context(MODE_AUTH, DHKEM_P256,
                                   HKDF_SHA_256, AES_128_GCM, NULL, 0, NULL, 0)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }
    if (derive_local_static_keypair(ctx, ikmS, ikmS_len) < 1) {
        fprintf(stderr, "%s: can't derive static keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.3 failed!\n");
        exit(1);
    }
    printf("A3.3 passes!\n");

    free_hpke_context(ctx);
    free(enc);
    free(ikmE);
    free(pkRm);
    free(ikmS);
    free(key);
    free(exp);

    printf("--------------------------------------------\nA3.4 test\n");
    s2os(a34ikmE, &ikmE, &ikmE_len);
    s2os(a34pkRm, &pkRm, &pkRm_len);
    s2os(a34ikmS, &ikmS, &ikmS_len);
    s2os(a34pkSm, &pkSm, &pkSm_len);
    s2os(a34psk, &psk, &psk_len);
    s2os(a34psk_id, &psk_id, &psk_id_len);
    s2os(a34key, &key, &key_len);
    s2os(a34exp, &exp, &exp_len);
    s2os(a34ikmR, &ikmR, &ikmR_len);
    s2os(a34pkEm, &pkEm, &pkEm_len);

    if ((ctx = create_hpke_context(MODE_AUTH_PSK, DHKEM_P256,
                                   HKDF_SHA_256, AES_128_GCM,
                                   psk, psk_len, psk_id, psk_id_len)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }
    if (derive_local_static_keypair(ctx, ikmS, ikmS_len) < 1) {
        fprintf(stderr, "%s: can't derive static keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.4 failed!\n");
        exit(1);
    }
    free(enc);
    printf("A3.4 send passes!\n");

    s2os(a34pt, &pt, &pt_len);
    if ((ct = malloc(pt_len+16)) == NULL) {
        fprintf(stderr, "can't allocate space for ciphertext!\n");
        exit(1);
    }
    s2os(a34aad1, &aad, &aad_len);
    wrap(ctx, aad, aad_len, pt, pt_len, ct, ct+pt_len);
    print_buffer("ciphertext", ct, pt_len+16);
    free(aad);

    s2os(a34aad2, &aad, &aad_len);
    wrap(ctx, aad, aad_len, pt, pt_len, ct, ct+pt_len);
    print_buffer("ciphertext", ct, pt_len+16);
    free(aad);

    s2os(a34aad3, &aad, &aad_len);
    wrap(ctx, aad, aad_len, pt, pt_len, ct, ct+pt_len);
    print_buffer("ciphertext", ct, pt_len+16);
    free(aad);
    free(pt);
    free(ct);

    free_hpke_context(ctx);

    if ((ctx = create_hpke_context(MODE_AUTH_PSK, DHKEM_P256,
                                   HKDF_SHA_256, AES_128_GCM,
                                   psk, psk_len, psk_id, psk_id_len)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }

    if (derive_local_static_keypair(ctx, ikmR, ikmR_len) < 1) {
        fprintf(stderr, "%s: can't derive local static keypair!\n", argv[0]);
        exit(1);
    }
    if (assign_peer_static_keypair(ctx, pkSm, pkSm_len) < 1) {
        fprintf(stderr, "%s: can't assign static peer key!\n", argv[0]);
        exit(1);
    }

    if (receiver(ctx, pkEm, pkEm_len, info, info_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.4 receive failed!\n");
        exit(1);
    }

    printf("A3.4 recv passes!\n");
    free_hpke_context(ctx);
    free(ikmE);
    free(pkRm);
    free(ikmR);
    free(pkEm);
    free(ikmS);
    free(pkSm);
    free(psk);
    free(psk_id);
    free(key);
    free(exp);

    printf("--------------------------------------------\nA4.4 test\n");

    s2os(a44ikmE, &ikmE, &ikmE_len);
    s2os(a44ikmS, &ikmS, &ikmS_len);
    s2os(a44pkRm, &pkRm, &pkRm_len);
    s2os(a44pkSm, &pkSm, &pkSm_len);
    s2os(a44psk, &psk, &psk_len);
    s2os(a44psk_id, &psk_id, &psk_id_len);
    s2os(a44ikmR, &ikmR, &ikmR_len);
    s2os(a44pkEm, &pkEm, &pkEm_len);
    s2os(a44key, &key, &key_len);
    s2os(a44exp, &exp, &exp_len);
    
    if ((ctx = create_hpke_context(MODE_AUTH_PSK, DHKEM_P256,
                                   HKDF_SHA_512, AES_128_GCM,
                                   psk, psk_len, psk_id, psk_id_len)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }
    if (derive_local_static_keypair(ctx, ikmS, ikmS_len) < 1) {
        fprintf(stderr, "%s: can't derive static keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 4.4 failed!\n");
        exit(1);
    }
    printf("A4.4 send passes!\n");

    s2os(a44pt, &pt, &pt_len);
    if ((ct = malloc(pt_len+16)) == NULL) {
        fprintf(stderr, "can't allocate space for ciphertext!\n");
        exit(1);
    }
    s2os(a44aad1, &aad, &aad_len);
    wrap(ctx, aad, aad_len, pt, pt_len, ct, ct+pt_len);
    print_buffer("ciphertext", ct, pt_len+16);
    free(aad);

    s2os(a44aad2, &aad, &aad_len);
    wrap(ctx, aad, aad_len, pt, pt_len, ct, ct+pt_len);
    print_buffer("ciphertext", ct, pt_len+16);
    free(aad);

    s2os(a44aad3, &aad, &aad_len);
    wrap(ctx, aad, aad_len, pt, pt_len, ct, ct+pt_len);
    print_buffer("ciphertext", ct, pt_len+16);
    free(aad);
    free(pt);
    free(ct);

    free_hpke_context(ctx);

    if ((ctx = create_hpke_context(MODE_AUTH_PSK, DHKEM_P256,
                                   HKDF_SHA_512, AES_128_GCM,
                                   psk, psk_len, psk_id, psk_id_len)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }

    if (derive_local_static_keypair(ctx, ikmR, ikmR_len) < 1) {
        fprintf(stderr, "%s: can't derive local static keypair!\n", argv[0]);
        exit(1);
    }
    if (assign_peer_static_keypair(ctx, pkSm, pkSm_len) < 1) {
        fprintf(stderr, "%s: can't assign static peer key!\n", argv[0]);
        exit(1);
    }

    if (receiver(ctx, pkEm, pkEm_len, info, info_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 4.4 receive failed!\n");
        exit(1);
    }

    printf("A4.4 recv passes!\n");
    free_hpke_context(ctx);

    free(ikmE);
    free(ikmS);
    free(pkRm);
    free(pkSm);
    free(psk);
    free(psk_id);
    free(ikmR);
    free(pkEm);
    free(key);
    free(exp);
    free(enc);

    printf("--------------------------------------------\nA6.1 test\n");

    s2os(a61ikmE, &ikmE, &ikmE_len);
    s2os(a61pkRm, &pkRm, &pkRm_len);
    s2os(a61key, &key, &key_len);
    s2os(a61exp, &exp, &exp_len);

    if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P521,
                                   HKDF_SHA_512, AES_256_GCM, NULL, 0, NULL, 0)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }
    free(enc);

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 6.1 failed!\n");
        exit(1);
    }
    printf("A6.1 passes!\n");
#if 0
    s2os(a31ikmE, &pt, &pt_len);
    if ((ct = malloc(pt_len+AES_BLOCK_SIZE)) == NULL) {
        fprintf(stderr, "can't allocate space for ciphertext!\n");
        exit(1);
    }
    s2os(a34aad1, &aad, &aad_len);
    wrap(ctx, aad, aad_len, pt, pt_len, ct+AES_BLOCK_SIZE, ct);
    print_buffer("ciphertext", ct, pt_len+16);

    free(pt);
    free(ct);
    free(aad);
#endif
    free_hpke_context(ctx);
    free(ikmE);
    free(pkRm);
    free(key);
    free(exp);

    printf("--------------------------------------------\nA6.4 test\n");

    s2os(a64ikmE, &ikmE, &ikmE_len);
    s2os(a64ikmS, &ikmS, &ikmS_len);
    s2os(a64pkRm, &pkRm, &pkRm_len);
    s2os(a64pkSm, &pkSm, &pkSm_len);
    s2os(a64psk, &psk, &psk_len);
    s2os(a64psk_id, &psk_id, &psk_id_len);
    s2os(a64ikmR, &ikmR, &ikmR_len);
    s2os(a64pkEm, &pkEm, &pkEm_len);
    s2os(a64key, &key, &key_len);
    s2os(a64exp, &exp, &exp_len);

    if ((ctx = create_hpke_context(MODE_AUTH_PSK, DHKEM_P521,
                                   HKDF_SHA_512, AES_256_GCM,
                                   psk, psk_len, psk_id, psk_id_len)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }
    if (derive_local_static_keypair(ctx, ikmS, ikmS_len) < 1) {
        fprintf(stderr, "%s: can't derive static keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 6.4 failed!\n");
        exit(1);
    }
    printf("A6.4 passes!\n");

    free_hpke_context(ctx);
    free(ikmE);
    free(ikmS);
    free(pkRm);
    free(pkSm);
    free(psk);
    free(psk_id);
    free(ikmR);
    free(pkEm);
    free(key);
    free(exp);
    free(enc);

    printf("all tests pass!\n");
    free(info);

    exit(0);
}

