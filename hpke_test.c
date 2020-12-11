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

/*
 * we have an hpke context that's primed and ready to encrypt, do it!
 */
void
do_encryptions (hpke_ctx *ctx)
{
    char *ptgoo = "4265617574792069732074727574682c20747275746820626561757479";
    char *aad0 = "436f756e742d30";
    char *aad1 = "436f756e742d31";
    char *aad2 = "436f756e742d32";
    char *aad4 = "436f756e742d34";
    unsigned char *pt, *ct, *aad;
    int pt_len, aad_len;

    s2os(ptgoo, &pt, &pt_len);
    if ((ct = malloc(pt_len+16)) == NULL) {
        fprintf(stderr, "can't allocate space for ciphertext!\n");
        exit(1);
    }
    s2os(aad0, &aad, &aad_len);
    wrap(ctx, aad, aad_len, pt, pt_len, ct, ct+pt_len);
    print_buffer("ciphertext", ct, pt_len+16);
    free(aad);

    s2os(aad1, &aad, &aad_len);
    wrap(ctx, aad, aad_len, pt, pt_len, ct, ct+pt_len);
    print_buffer("ciphertext", ct, pt_len+16);
    free(aad);

    s2os(aad2, &aad, &aad_len);
    wrap(ctx, aad, aad_len, pt, pt_len, ct, ct+pt_len);
    print_buffer("ciphertext", ct, pt_len+16);
    free(aad);

    s2os(aad2, &aad, &aad_len);
    wrap(ctx, aad, aad_len, pt, pt_len, ct, ct+pt_len); // dummy 3
    free(aad);

    s2os(aad4, &aad, &aad_len);
    wrap(ctx, aad, aad_len, pt, pt_len, ct, ct+pt_len);
    print_buffer("ciphertext", ct, pt_len+16);
    free(aad);

    free(pt);
    free(ct);
}

void
do_decrypt (hpke_ctx *ctx, char *ct_str, char *aad_str)
{
    unsigned char *ct, *pt, *aad;
    int ct_len, aad_len;

    s2os(aad_str, &aad, &aad_len);
    s2os(ct_str, &ct, &ct_len);
    if ((pt = malloc(ct_len-16)) == NULL) {
        fprintf(stderr, "unable to allocate plaintext buffer!\n");
        return;
    }
    unwrap(ctx, aad, aad_len, ct, ct_len-16, pt, ct + (ct_len - 16));
    print_buffer("plaintext", pt, ct_len - 16);
    free(aad);
    free(ct);
    free(pt);
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

    char *a31ct0 = "6691e12b2ff62ee7afd44b1ffeb5cc90399f0509d153d8c1bd56dec39bc1df84617a6daf3c1a96dcfa5d6eab5d";
    char *a31ct1 = "3bcc473facb1803c3b526b61e0cb5158ea0c9148df3a2b86b55e8e49464720491fd557093f8303d825ead9b864";
    char *a31ct2 = "32a45576443463950cca04906d2ca90d7271b6cab593a3a76bc5f19447ee1890c1eb07c3b5419c6a2f3f480851";
    char *a31ct4 = "03ac6b8b51f5a1897b59115d3b4854e1f044e25942c802531c1766db9552f6262986eb089bbc171405b4c4cf7b";

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

    char *a41ikmE = "6a15ae6050f8f3a0aae56777f77633e81181c03f218a212691d3560a455cc5a8";
    char *a41pkRm = "04410fa2c036febbe2b60303b4d1eddf24ae346a1ee13fa1c40b73a05f223ee1d366329798d7c53d2a25662976d05742effb776df47ebc1333d36a9d3b71f35097";
    char *a41ikmR = "4aabd6f3276cf14e0ba493e8937306019f2af84b6c079b7cf89a81a4539d0039";
    char *a41pkEm = "047a1779b86e30662292221d847731c01bc152f1c3ca9816233ca43b78d9d37b1b286e8cb0fdd6b56e5feed4643937b8054390c70c17e7db87bb5b9fd39bc3ddc1";
    char *a41key = "29ca2d66bbfc6736ace0b1cc015a7669";
    char *a41exp = "4173b69a1acf63bd5707d66e6252662ae69bd35ba66af3bd2e8e4182d74b81c54267db3a638020aa92734a5cb4ee654c1d39f99625b9ac2299bc0dfab64902b8";

    char *a42ikmE = "e76eb1beff6bfda05df316cdfdd206984a5647ed4ed66ea74ce66626a115418d";
    char *a42pkRm = "04f80d0e92e33606bedc68e4b52b2c67661029b3b191f6bb338a7ea533082c8dd7e4f5bc26876f471759053a5fc34e72e2e9cfff32e053bd056576f4782f7f86c5";
    char *a42psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a42psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a42key = "0fe5fad216ec3cfac88273d43e537b45";
    char *a42exp = "081e617c3369139d11873a934d7686f029f940e62ff9f6828bfce600dae5023e474a32b9fd0c6b0fc2ec11b34cd18d7465ee8a12278a66f953b708618103960a";

    char *a43ikmE = "a2854b15706ff6b1c184d1134545cd7496d6633ad1bb6bf3b6bfc483be5856b6";
    char *a43pkRm = "0416358ac8e863e83c4690c690b0bb3ae1dea320446ec1c18badace8882cc0834050ecfe6ba5da1b6bbc63b47364ebc95108f0412c2c6864f45b9aca4bf3cc28e0";
    char *a43ikmS = "a06672f3c860ca33c54e0f8b503ec2e7442fad9cb190c58c9dfa14fd07de3edf";
    char *a43key = "0f77225c162f9f56288288af3d59f136";
    char *a43exp = "27a55255900f52b16c21d3d30b5af4e72e12c6d798f450067c31252eb7c53e22e5013cbe9b5fe00f559ff0f8410c53c7e8094732637f7ae350da39ee9043824e";

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
    
    char *a51ikmE = "9df8b42914e9fce352d49c922ddf1fdcd48f81a956ab5acd5ccfbca35f5c0beb";
    char *a51pkRm = "04b8562b9b63e1ee70c11043c660b1a274a3cfe6c79ab2d53a2f3b416534a0f0840261ef7e883b80b1a89457de1d98dbcbfde581a1c0536393e387a193e231c6dc";
    char *a51ikmR = "211e281360f0cdb9c2b5f657619628a0e2e9ef6b246949f165f5ee950f9bc7f8";
    char *a51pkEm = "04b8c41a294b8d1da8bd64a9894abb3d579904b86f3aa4da89f4e9563189d93ce8110c51b3b38ef23b8b9296a596c71ab48947b97d65e4ad545bb4def204ef5c88";
    char *a51key = "e9a081bdfe019f452e5799c23351a83c7fcde509d5a3859a3557c2ffbc1fe191";
    char *a51exp = "a6fa6f2f65d731f4256386ffe35ea3c42596c48ee8c77e4f593f1d417469dda8";

    char *a52ikmE = "7d4bdde35e62157602b7f6647fcc5908d4c7aa568f19d26d3c7e0e6cd1c7f952";
    char *a52pkRm = "04807b48c94311e802aa56f7b00ae88c0b9a6ec0fc948afcd5bc6e5e0ad41aeb4e9ef2511bb9a6b7b9e0522dd5868cdb40cc773f030ac2751cfd745cf9baa51357";
    char *a52psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a52psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a52key = "62f430439c16fe9cebf9a70cbdac465531fb9cb81e55d21f7034620457e75257";
    char *a52exp = "1642a15dc9da12df5dde65486b3e6215f3c62db433e44b10237ef1c0452c036d";

    char *a53ikmE = "d1eb88204fbb88b34b9bfd437ed0a3385676cf13e1d16885d26a9271ba9c9100";
    char *a53pkRm = "044aefaf297802c7d01062f1a2ff6648035fa70b0b4a9c77f15ef8a6fd9ce987e03389c6df8e84ba367cdf0746441286976adf7b49dccd4f25b5adca1d0b256b26";
    char *a53ikmS = "11d4a3df0386a92456d5b16b49e5b74ae674c7b381925762d7a180d3b0fa8df7";
    char *a53key = "e3c3372fe9188723349c2fdd611266291a808b31fcb07bc858f8fbdfdce63cf0";
    char *a53exp = "dfa30f8d46590cb9f706999ece2e76985203e2eeeaef2ac56b1bef05ace34fbb";

    char *a54ikmE = "75422f8364da556a73f8ff16f70ab9b46b9b89089baf7c6897dcd3f040713d57";
    char *a54pkRm = "047ce9f6d438178cd79004a762d794657893fdfac7d66874688763a35299463337bf85323da8672c3ee276b762e63853a7f3a8a6bc1b07b3a8b0edf804499c94e4";
    char *a54ikmS = "557e7fe9f5bcab34814bdc82f61502bbd35fa81595dd610f553bebe032412c93";
    char *a54pkSm = "04363e618990bde7ac3f127dd38289eb9efcc0af2630bcb26f064fc9c9a52686e8f2b2adc515b26360f15d7d41f552b1ae5635ab4db5ec4aadc5243e250f1e748a";
    char *a54ikmR = "e1b8fed84588b7ecc6bab2dccf2a93508075265de18856b9f0768a3dc1b3fc2b";
    char *a54pkEm = "0413a0da6df148265544f31c634c67f3e12c323dfbc07b2d652159242371e043141f323958c852bc10646ca44a4e641b162432aa4193b6b8b93c06d11831568481";
    char *a54psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a54psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a54key = "a0464ab1cb323356b3945c8c90afe6985b1e7eacd36292726edce5d96e17ac33";
    char *a54exp = "63343a898ef5717a6a127b9c64a80f1068376d6c65e6b7108f87f5804aa6c945";

    char *a54ct0 = "043118c110de11697966d1d4fb3782d4d5043c283b4fd16e4630656854fc2cff45b0f10ce205914f79771b039f";
    char *a54ct1 = "cfc4100ee22cffd749d01f95483a97d5671170732c36b1e7232c016566e9349c744dd50345eeeaa57d956a2fa2";
    char *a54ct2 = "0cf651270751e720ac78f8d995f1a5ec96e6dc107f77a4750e484e0e2e6eb1f7c3da4f018e3486752409389ffc";
    char *a54ct4 = "ffbb22b9ad07e95b07b34eb07a5f82ccca90d43c3aa89ee5a23a66cf34d03b835a7da410505c678fe6e617c3ed";

    char *a61ikmE = "3fdb7eab3a6a99de8abbcb507be5704ae6a8994008b8a8e6b63fbd97fa8619c66bd8665c22079939f3f63f978c5806802b22ba5bb396da9cf252ee67068bf57461bf";
    char *a61pkRm = "04017b4d008b6602cf87554f1ae3f97c647da3ad5f347d73124495c6817d14f75c181c07519bf2988a37e14967ca10254364678268c6558714d8ff6d4d821bb4f523d101c55f6d4f9ab0d4bce925444e2219a2b0f96920051294ef36b03dd4c69bd332df0d884794d44f0eb2d5ad7af9396dc946d8e4a5325724a2f8f9d6b52cba7524b644";
    char *a61key = "57aeffb38c9b286367fde962c7d32bbab27075fa4d03d9a7465358d9e6fc6342";
    char *a61exp = "effa5f770620d75f76deec0f400dd42009c8088d296e58484e2a8d61e475d5a53639b7a909ca0651ab7787912962d2ea1e9133ed96db68fbc6cc4b9d9ab8ab2a";
    char *a61ikmR = "2e99ac709379c7eb15ca068253bbae4dd6297c2397f47a89b8cb3ef4e83f235f83cb1ce3d2f754c47431ff0d0d8d2c429a7b6768d9524c3be60b9fb7749c49cb816b";
    char *a61pkEm = "0401e9b3a83397ce01151df7c6def62d04561d5876ccc57437ca01af81a8f7a1a077b66d054bab46b830d7cb335db6acd7c7863a8dc2ec1840e8ac2e4e74f99fea26340040f749f3b37512472b1da3df31854dc97a21fabad42be41ee0243613230ad69ba2676693547ddb4d3454ac9a61d6f4ae756739a0ef226809bde93bd8b19d14cb06";
    char *a61ct0 = "00f4bff0895c34013c8c0e153a647e8c7aaf494a61da3f88e127cadbd628e46351f59574834a7081ebbf98536e";
    char *a61ct1 = "de0ddf5e9e229008da337d718b48096ef8f74d2332806c3cc0a9e32858adaad88193ee26867bd63947c19149a8";
    char *a61ct2 = "384ae15d9a021d1b77d43657b176ea635807f29ff8bd79fd4dd05003f64c6d8f48d281d4b1e7dea1f6e5434547";
    char *a61ct4 = "505456abc31145bb5301d3e572465f7e8f6f20864dac6f1dd27962848c4eeea9d553ad3dabbae88d687cfcd40b";

    char *a62ikmE = "ae300665d34d5ab7c0508a94a741ba2cb285966106ba9cefbe1f9c24c3eb626108d0c9ccc8291d90c50c6d04ac181ccd8efc2cc52383eb205637a84d2be5362bf247";
    char *a62pkRm = "040186c1b7bf3e57c5eb7443be70506d9f70a4915e63b25b9a9859953ab30d3dc7c97792f93cc7c1371421b1473ae13482a1c57c36b79d2f29c862f307dc8d19c8d30a01cb116e09d7222fde60863619246eebd883bec14fb4b12ef01d232b2450d654ea304f2367493b981bbe235128b3e176b9fecd0c3e3b7736f0fe5a999abaa0dc65e5";
    char *a62psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a62psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a62key = "420619b93c512bd517df22fc43ea0047607c74b355b17cd69aef81edc6a607f7";
    char *a62exp = "527430fac6f9ff3839fa2e3af11b9fa74857261288d01a702d753ebacd5b2bee52359df82dcdf637182d4d12a3c4efd3c513dac6f9fea685d10fcb5e5f87d1e2";

    char *a63ikmE = "11c0c7337b294452826e14a7f6c9e7981a03c467a08f47a8b478b37f3e9c90266898e3c3f8e84235a6a2837269c84b355d7f5ca133085172a08f00c3857da8a1410b";
    char *a63pkRm = "04014e2183dd2d23116fc3b6af53d7bc384337c6c78d897a2dc2e86997dcaf6bc868edc3ffc369922a6579f16bc3ef22eb331f72af62ac22435a8c3be602754d4ebcab01bb42d322ab634f723bf99f6a25fbbdbd655813a95b1833a64f831f7a20dc9fe14f31ba47690d57d6ea52ae9182d4af7012d568773187a52e9976268c6320940312";
    char *a63ikmS = "bab663b9c05f680f401a494ae8c8714fd95cbcd56a01e9e8194b4b3da863a5e8313d4916dc58f6d3aaa2dafe420ae81b2a6c0075223afc6b13f3734a26ca30da5e38";
    char *a63key = "e24bb29b558daeec9941ac6af01d73ec337e0bf0d5aa6140e25b4f4f1354503d";
    char *a63exp = "40365288e3146348d6c1da7d4fb57b1fbdae5536ac8c025dc7d9d3389d41a97f28526cc2955db087a1b9d94e609395f81c0206f360a507a32ad52f3b6b0ebd67";

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
    
    char *a71ikmE = "ef168d98d05db0cf76e899ab9c2312c7a2aab2900b60bcf1b7bc15bb52faa525";
    char *a71pkEm = "04af80f916845b9ea52f876cdb60410d7bc5d1bbf61c88587829f790fe9986d079a37bb33787723ff4dd2bf652168dd3ef33383e69ec5a6f4bfc3560da106fa972";
    char *a71ikmR = "6dda6060975f92374251995ec83b4546d9c8b0c295f1f6a6c6f6b63e7437c48d";
    char *a71pkRm = "04da3cd864bfbd6b393f717c19977cef207cb63a51b31821ba8ff0009424230967e8520793ed5904bb7791bb9571b9e7d8d867724fe75399d9bc1f429360fe87e7";
    char *a71key = "20986ea8d82f6c16d48cba2d596bc2d0549d2480ce36d1365fe5533c15e23ee0";
    char *a71exp = "caf40f1b361c863dca9e7c2a8e26c137e3f57ac876b635b5a148cc3b96ba35b3";

    char *a74ikmE = "0b5d9f35f82aa9384117405b48f81b736f6dc1c9212f6a75aab10f5464f31c0cab1df6a13b2215d73fb9b861ba3a4c720fdcabf7541d34e08ebbda053c4be094d2d4";
    char *a74pkEm = "0401ba608d8a5557b95f1cd7d6b9e6d01054134e989c08a08a823a98af3319374f1e722d9817f5afdf74e9b55eb0615c4162291e34a51c23cab0afdb31eba1cc0026b4013083fec687518677b65aa3f35b0889c54099b2ea396a485833520e9d8630df9eb134879abc44397fe3790f257f5e6471a1fc9acc32de35bfb47e5471e09baed6d3";
    char *a74ikmS = "12354967c280e84c9d42cf1b7d1362f6ffd3906dc65bbde0541205edaf64826ba2098a5d2f4a34ca901b5d05040addbf37d5cc91bd8eabe49efc1d04fd0ab4e6ee46";
    char *a74pkSm = "04006bc57505cb19a65e1a92c67dd6dcfa6f96b6d95e6f06850ae332e7c1af4104c19ab55d4404fad16ea482e197aaba55ba5b94236d871d18e4262f099c523aaa07e201494dac7922c7eab61d842524c8f45bcc518a666b31af83e0366740abf61f641a85decefbe45480b10e71eeb4861be1081aa4da1fcaa470086fb3904ee977297c39";
    char *a74ikmR = "0df21d7e6d44d4d0d304ff12fa6c27ae5a92b992bf70db95e2ed45f781e6220f66cd2e8563ec87ed071d4b9a86d842fd46c625d2f51b59fe869f082641e2484175a7";
    char *a74pkRm = "0400b8e265a3ea1f3c5ba5339c9373d055baa205e9f9113890fbcb02b9720995072817d12d55c5e10f967ca8e5dac5007e6aeaec0ba2056867b1316f83e88a1119a3e6012addded9b9b1afee7331f9aa711a3c0b9c7417dcd1a580c31a769d369fcca0f9d37e3331ec59be9972dff02a87da05abd077b56ef332ca48ea67b7cd49db0f3005";
    char *a74psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a74psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a74key = "c3d1d621e651075c0b5192eeb8f55a5ba1db21614761f8c5805a0373070eef95734d7bada4caa0921aa9f8684069ed714201f7dd1ab89209562540099f11971e";
    char *a74exp = "4201f7dd1ab89209562540099f11971e199649a38b92592727bd4517587e2d9a1d7a1f9df9c527eddecdc177b295855d63b452d6e915321d423ba6fc894f8bcb";

    char *tvinfo = "4f6465206f6e2061204772656369616e2055726e";
    unsigned char *ikmE, *pkRm, *ikmR, *pkEm, *pkSm, *ikmS, *psk, *psk_id, *key, *exp, *info, *enc;
    int ikmE_len, pkRm_len, ikmR_len, pkEm_len, pkSm_len, ikmS_len, psk_len, psk_id_len, key_len, exp_len, info_len, enc_len;
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
                                   HKDF_SHA_256, AES_128_GCM)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len, NULL, 0, NULL, 0, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.1 send failed!\n");
        exit(1);
    }
    free(enc);
    printf("A3.1 send passes!\n");

    printf("A3.1 encryptions\n");
    do_encryptions(ctx);
    
    free_hpke_context(ctx);

    if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P256,
                                   HKDF_SHA_256, AES_128_GCM)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_local_static_keypair(ctx, ikmR, ikmR_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (receiver(ctx, pkEm, pkEm_len, info, info_len, NULL, 0, NULL, 0) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.1 receive failed!\n");
        exit(1);
    }
    printf("A3.1 recv passes!\n");
    printf("A3.1 decryptions\n");
    do_decrypt(ctx, a31ct0, "436f756e742d30");
    do_decrypt(ctx, a31ct1, "436f756e742d31");
    do_decrypt(ctx, a31ct2, "436f756e742d32");
    ctx->seq++;                                 // ignore #3
    do_decrypt(ctx, a31ct4, "436f756e742d34");

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
                                   HKDF_SHA_256, AES_128_GCM)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len,
               psk, psk_len, psk_id, psk_id_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.2 failed!\n");
        exit(1);
    }
    printf("A3.2 passes!\n");

    printf("A3.2 encryptions\n");
    do_encryptions(ctx);

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
                                   HKDF_SHA_256, AES_128_GCM)) == NULL) {
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

    if (sender(ctx, pkRm, pkRm_len, info, info_len, NULL, 0, NULL, 0, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.3 failed!\n");
        exit(1);
    }
    printf("A3.3 passes!\n");

    printf("A3.3 encryptions\n");
    do_encryptions(ctx);

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
                                   HKDF_SHA_256, AES_128_GCM)) == NULL) {
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

    if (sender(ctx, pkRm, pkRm_len, info, info_len,
               psk, psk_len, psk_id, psk_id_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.4 failed!\n");
        exit(1);
    }
    free(enc);
    printf("A3.4 send passes!\n");

    printf("A3.4 encryptions\n");
    do_encryptions(ctx);

    free_hpke_context(ctx);

    if ((ctx = create_hpke_context(MODE_AUTH_PSK, DHKEM_P256,
                                   HKDF_SHA_256, AES_128_GCM)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_local_static_keypair(ctx, ikmR, ikmR_len) < 1) {
        fprintf(stderr, "%s: can't derive local static keypair!\n", argv[0]);
        exit(1);
    }
    if (assign_peer_static_keypair(ctx, pkSm, pkSm_len) < 1) {
        fprintf(stderr, "%s: can't assign static peer key!\n", argv[0]);
        exit(1);
    }

    if (receiver(ctx, pkEm, pkEm_len, info, info_len,
                 psk, psk_len, psk_id, psk_id_len) < 1) {
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

    printf("--------------------------------------------\nA4.1 test\n");
    s2os(a41ikmE, &ikmE, &ikmE_len);
    s2os(a41pkRm, &pkRm, &pkRm_len);
    s2os(a41key, &key, &key_len);
    s2os(a41exp, &exp, &exp_len);
    s2os(a41ikmR, &ikmR, &ikmR_len);
    s2os(a41pkEm, &pkEm, &pkEm_len);

    if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P256,
                                   HKDF_SHA_512, AES_128_GCM)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len, NULL, 0, NULL, 0, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 4.1 send failed!\n");
        exit(1);
    }
    free(enc);
    printf("A4.1 send passes!\n");

    printf("A4.1 encryptions\n");
    do_encryptions(ctx);

    free_hpke_context(ctx);

    if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P256,
                                   HKDF_SHA_512, AES_128_GCM)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }

    set_hpke_debug(ctx, 1);

    if (derive_local_static_keypair(ctx, ikmR, ikmR_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (receiver(ctx, pkEm, pkEm_len, info, info_len, NULL, 0, NULL, 0) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.1 receive failed!\n");
        exit(1);
    }
    printf("A4.1 recv passes!\n");

    free_hpke_context(ctx);
    free(ikmE);
    free(pkRm);
    free(ikmR);
    free(pkEm);
    free(key);
    free(exp);

    printf("--------------------------------------------\nA4.2 test\n");
    s2os(a42ikmE, &ikmE, &ikmE_len);
    s2os(a42pkRm, &pkRm, &pkRm_len);
    s2os(a42psk, &psk, &psk_len);
    s2os(a42psk_id, &psk_id, &psk_id_len);
    s2os(a42key, &key, &key_len);
    s2os(a42exp, &exp, &exp_len);
    
    if ((ctx = create_hpke_context(MODE_PSK, DHKEM_P256,
                                   HKDF_SHA_512, AES_128_GCM)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }

    set_hpke_debug(ctx, 1);

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len,
               psk, psk_len, psk_id, psk_id_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.2 failed!\n");
        exit(1);
    }
    printf("A4.2 passes!\n");

    printf("A4.2 encryptions\n");
    do_encryptions(ctx);

    free_hpke_context(ctx);
    free(enc);
    free(ikmE);
    free(pkRm);
    free(psk);
    free(psk_id);
    free(key);
    free(exp);

    printf("--------------------------------------------\nA4.3 test\n");
    s2os(a43ikmE, &ikmE, &ikmE_len);
    s2os(a43pkRm, &pkRm, &pkRm_len);
    s2os(a43ikmS, &ikmS, &ikmS_len);
    s2os(a43key, &key, &key_len);
    s2os(a43exp, &exp, &exp_len);

    if ((ctx = create_hpke_context(MODE_AUTH, DHKEM_P256,
                                   HKDF_SHA_512, AES_128_GCM)) == NULL) {
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

    if (sender(ctx, pkRm, pkRm_len, info, info_len, NULL, 0, NULL, 0, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 4.3 failed!\n");
        exit(1);
    }
    printf("A4.3 passes!\n");

    printf("A4.3 encryptions\n");
    do_encryptions(ctx);

    free_hpke_context(ctx);
    free(enc);
    free(ikmE);
    free(pkRm);
    free(ikmS);
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
                                   HKDF_SHA_512, AES_128_GCM)) == NULL) {
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

    if (sender(ctx, pkRm, pkRm_len, info, info_len,
               psk, psk_len, psk_id, psk_id_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 4.4 failed!\n");
        exit(1);
    }
    printf("A4.4 send passes!\n");

    printf("A4.4 encryptions\n");
    do_encryptions(ctx);

    free_hpke_context(ctx);

    if ((ctx = create_hpke_context(MODE_AUTH_PSK, DHKEM_P256,
                                   HKDF_SHA_512, AES_128_GCM)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_local_static_keypair(ctx, ikmR, ikmR_len) < 1) {
        fprintf(stderr, "%s: can't derive local static keypair!\n", argv[0]);
        exit(1);
    }
    if (assign_peer_static_keypair(ctx, pkSm, pkSm_len) < 1) {
        fprintf(stderr, "%s: can't assign static peer key!\n", argv[0]);
        exit(1);
    }

    if (receiver(ctx, pkEm, pkEm_len, info, info_len, psk, psk_len, psk_id, psk_id_len) < 1) {
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

    printf("--------------------------------------------\nA5.1 test\n");
    s2os(a51ikmE, &ikmE, &ikmE_len);
    s2os(a51pkRm, &pkRm, &pkRm_len);
    s2os(a51key, &key, &key_len);
    s2os(a51exp, &exp, &exp_len);
    s2os(a51ikmR, &ikmR, &ikmR_len);
    s2os(a51pkEm, &pkEm, &pkEm_len);

    if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P256,
                                   HKDF_SHA_256, ChaCha20Poly)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len, NULL, 0, NULL, 0, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 5.1 send failed!\n");
        exit(1);
    }
    free(enc);
    printf("A5.1 send passes!\n");

    printf("A5.1 encryptions\n");
    do_encryptions(ctx);

    free_hpke_context(ctx);
    free(ikmE);
    free(pkRm);
    free(ikmR);
    free(pkEm);
    free(key);
    free(exp);
    
    printf("--------------------------------------------\nA5.2 test\n");
    s2os(a52ikmE, &ikmE, &ikmE_len);
    s2os(a52pkRm, &pkRm, &pkRm_len);
    s2os(a52psk, &psk, &psk_len);
    s2os(a52psk_id, &psk_id, &psk_id_len);
    s2os(a52key, &key, &key_len);
    s2os(a52exp, &exp, &exp_len);
    
    if ((ctx = create_hpke_context(MODE_PSK, DHKEM_P256,
                                   HKDF_SHA_256, ChaCha20Poly)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len,
               psk, psk_len, psk_id, psk_id_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 5.2 failed!\n");
        exit(1);
    }
    printf("A5.2 passes!\n");

    printf("A5.2 encryptions\n");
    do_encryptions(ctx);

    free_hpke_context(ctx);
    free(enc);
    free(ikmE);
    free(pkRm);
    free(psk);
    free(psk_id);
    free(key);
    free(exp);

    printf("--------------------------------------------\nA5.3 test\n");
    s2os(a53ikmE, &ikmE, &ikmE_len);
    s2os(a53pkRm, &pkRm, &pkRm_len);
    s2os(a53ikmS, &ikmS, &ikmS_len);
    s2os(a53key, &key, &key_len);
    s2os(a53exp, &exp, &exp_len);

    if ((ctx = create_hpke_context(MODE_AUTH, DHKEM_P256,
                                   HKDF_SHA_256, ChaCha20Poly)) == NULL) {
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

    if (sender(ctx, pkRm, pkRm_len, info, info_len, NULL, 0, NULL, 0, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 5.3 failed!\n");
        exit(1);
    }
    printf("A5.3 passes!\n");

    printf("A5.3 encryptions\n");
    do_encryptions(ctx);

    free_hpke_context(ctx);
    free(enc);
    free(ikmE);
    free(pkRm);
    free(ikmS);
    free(key);
    free(exp);

    printf("--------------------------------------------\nA5.4 test\n");
    s2os(a54ikmE, &ikmE, &ikmE_len);
    s2os(a54pkRm, &pkRm, &pkRm_len);
    s2os(a54ikmS, &ikmS, &ikmS_len);
    s2os(a54pkSm, &pkSm, &pkSm_len);
    s2os(a54psk, &psk, &psk_len);
    s2os(a54psk_id, &psk_id, &psk_id_len);
    s2os(a54key, &key, &key_len);
    s2os(a54exp, &exp, &exp_len);
    s2os(a54ikmR, &ikmR, &ikmR_len);
    s2os(a54pkEm, &pkEm, &pkEm_len);

    if ((ctx = create_hpke_context(MODE_AUTH_PSK, DHKEM_P256,
                                   HKDF_SHA_256, ChaCha20Poly)) == NULL) {
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

    if (sender(ctx, pkRm, pkRm_len, info, info_len,
               psk, psk_len, psk_id, psk_id_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.4 failed!\n");
        exit(1);
    }
    free(enc);
    printf("A5.4 send passes!\n");

    printf("A5.4 encryptions\n");
    do_encryptions(ctx);

    free_hpke_context(ctx);

    if ((ctx = create_hpke_context(MODE_AUTH_PSK, DHKEM_P256,
                                   HKDF_SHA_256, ChaCha20Poly)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_local_static_keypair(ctx, ikmR, ikmR_len) < 1) {
        fprintf(stderr, "%s: can't derive local static keypair!\n", argv[0]);
        exit(1);
    }
    if (assign_peer_static_keypair(ctx, pkSm, pkSm_len) < 1) {
        fprintf(stderr, "%s: can't assign static peer key!\n", argv[0]);
        exit(1);
    }

    if (receiver(ctx, pkEm, pkEm_len, info, info_len, psk, psk_len, psk_id, psk_id_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 5.4 receive failed!\n");
        exit(1);
    }
    printf("A5.4 recv passes!\n");
    printf("A5.4 decryptions\n");
    do_decrypt(ctx, a54ct0, "436f756e742d30");
    do_decrypt(ctx, a54ct1, "436f756e742d31");
    do_decrypt(ctx, a54ct2, "436f756e742d32");
    ctx->seq++;                                 // ignore #3
    do_decrypt(ctx, a54ct4, "436f756e742d34");

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

    printf("--------------------------------------------\nA6.1 test\n");

    s2os(a61ikmE, &ikmE, &ikmE_len);
    s2os(a61pkRm, &pkRm, &pkRm_len);
    s2os(a61key, &key, &key_len);
    s2os(a61exp, &exp, &exp_len);
    s2os(a61ikmR, &ikmR, &ikmR_len);
    s2os(a61pkEm, &pkEm, &pkEm_len);

    if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P521,
                                   HKDF_SHA_512, AES_256_GCM)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len, NULL, 0, NULL, 0, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }
    free(enc);

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 6.1 failed!\n");
        exit(1);
    }
    printf("A6.1 passes!\n");

    printf("A6.1 encryptions\n");
    do_encryptions(ctx);

    free_hpke_context(ctx);

    if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P521, HKDF_SHA_512, AES_256_GCM)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_local_static_keypair(ctx, ikmR, ikmR_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (receiver(ctx, pkEm, pkEm_len, info, info_len, NULL, 0, NULL, 0) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 3.1 receive failed!\n");
        exit(1);
    }
    printf("A6.1 recv passes\n");
    printf("A6.1 decryptions\n");
    do_decrypt(ctx, a61ct0, "436f756e742d30");
    do_decrypt(ctx, a61ct1, "436f756e742d31");
    do_decrypt(ctx, a61ct2, "436f756e742d32");
    ctx->seq++;                                 // ignore #3
    do_decrypt(ctx, a61ct4, "436f756e742d34");

    free_hpke_context(ctx);
    free(ikmE);
    free(pkRm);
    free(ikmR);
    free(pkEm);
    free(key);
    free(exp);

    printf("--------------------------------------------\nA6.2 test\n");
    s2os(a62ikmE, &ikmE, &ikmE_len);
    s2os(a62pkRm, &pkRm, &pkRm_len);
    s2os(a62psk, &psk, &psk_len);
    s2os(a62psk_id, &psk_id, &psk_id_len);
    s2os(a62key, &key, &key_len);
    s2os(a62exp, &exp, &exp_len);
    
    if ((ctx = create_hpke_context(MODE_PSK, DHKEM_P521,
                                   HKDF_SHA_512, AES_256_GCM)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len,
               psk, psk_len, psk_id, psk_id_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 6.2 failed!\n");
        exit(1);
    }
    printf("A6.2 passes!\n");

    printf("A6.2 encryptions\n");
    do_encryptions(ctx);

    free_hpke_context(ctx);
    free(enc);
    free(ikmE);
    free(pkRm);
    free(psk);
    free(psk_id);
    free(key);
    free(exp);

    printf("--------------------------------------------\nA6.3 test\n");
    s2os(a63ikmE, &ikmE, &ikmE_len);
    s2os(a63pkRm, &pkRm, &pkRm_len);
    s2os(a63ikmS, &ikmS, &ikmS_len);
    s2os(a63key, &key, &key_len);
    s2os(a63exp, &exp, &exp_len);

    if ((ctx = create_hpke_context(MODE_AUTH, DHKEM_P521, HKDF_SHA_512, AES_256_GCM)) == NULL) {
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

    if (sender(ctx, pkRm, pkRm_len, info, info_len, NULL, 0, NULL, 0, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 6.3 failed!\n");
        exit(1);
    }
    printf("A6.3 passes!\n");

    printf("A6.3 encryptions\n");
    do_encryptions(ctx);

    free_hpke_context(ctx);
    free(enc);
    free(ikmE);
    free(pkRm);
    free(ikmS);
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

    if ((ctx = create_hpke_context(MODE_AUTH_PSK, DHKEM_P521, HKDF_SHA_512, AES_256_GCM)) == NULL) {
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

    if (sender(ctx, pkRm, pkRm_len, info, info_len,
               psk, psk_len, psk_id, psk_id_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 6.4 failed!\n");
        exit(1);
    }
    printf("A6.4 passes!\n");

    printf("A6.4 encryptions\n");
    do_encryptions(ctx);

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

    printf("--------------------------------------------\nA7.1 test\n");

    s2os(a71ikmE, &ikmE, &ikmE_len);
    s2os(a71pkRm, &pkRm, &pkRm_len);
    s2os(a71ikmR, &ikmR, &ikmR_len);
    s2os(a71pkEm, &pkEm, &pkEm_len);
    s2os(a71key, &key, &key_len);
    s2os(a71exp, &exp, &exp_len);

    if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P256, HKDF_SHA_256, AES_256_SIV)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_ephem_keypair(ctx, ikmE, ikmE_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (sender(ctx, pkRm, pkRm_len, info, info_len, NULL, 0, NULL, 0, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 7.1 send failed!\n");
        exit(1);
    }
    free(enc);
    printf("A7.1 send passes!\n");

    printf("A7.1 encryptions\n");
    do_encryptions(ctx);
    
    free_hpke_context(ctx);

    if ((ctx = create_hpke_context(MODE_BASE, DHKEM_P256, HKDF_SHA_256, AES_256_SIV)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_local_static_keypair(ctx, ikmR, ikmR_len) < 1) {
        fprintf(stderr, "%s: can't derive ephemeral keypair!\n", argv[0]);
        exit(1);
    }

    if (receiver(ctx, pkEm, pkEm_len, info, info_len, NULL, 0, NULL, 0) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 7.1 receive failed!\n");
        exit(1);
    }
    printf("A7.1 recv passes!\n");

    free_hpke_context(ctx);
    free(ikmE);
    free(pkRm);
    free(ikmR);
    free(pkEm);
    free(key);
    free(exp);

    printf("--------------------------------------------\nA7.4 test\n");

    s2os(a74ikmE, &ikmE, &ikmE_len);
    s2os(a74ikmS, &ikmS, &ikmS_len);
    s2os(a74pkRm, &pkRm, &pkRm_len);
    s2os(a74pkSm, &pkSm, &pkSm_len);
    s2os(a74psk, &psk, &psk_len);
    s2os(a74psk_id, &psk_id, &psk_id_len);
    s2os(a74ikmR, &ikmR, &ikmR_len);
    s2os(a74pkEm, &pkEm, &pkEm_len);
    s2os(a74key, &key, &key_len);
    s2os(a74exp, &exp, &exp_len);
    
    if ((ctx = create_hpke_context(MODE_AUTH_PSK, DHKEM_P521, HKDF_SHA_512, AES_512_SIV)) == NULL) {
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

    if (sender(ctx, pkRm, pkRm_len, info, info_len,
               psk, psk_len, psk_id, psk_id_len, &enc, &enc_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 4.4 failed!\n");
        exit(1);
    }
    printf("A7.4 send passes!\n");

    printf("A7.4 encryptions\n");
    do_encryptions(ctx);

    free_hpke_context(ctx);

    if ((ctx = create_hpke_context(MODE_AUTH_PSK, DHKEM_P521, HKDF_SHA_512, AES_512_SIV)) == NULL) {
        fprintf(stderr, "%s: can't create HPKE context!\n", argv[0]);
        exit(1);
    }
    set_hpke_debug(ctx, 1);

    if (derive_local_static_keypair(ctx, ikmR, ikmR_len) < 1) {
        fprintf(stderr, "%s: can't derive local static keypair!\n", argv[0]);
        exit(1);
    }
    if (assign_peer_static_keypair(ctx, pkSm, pkSm_len) < 1) {
        fprintf(stderr, "%s: can't assign static peer key!\n", argv[0]);
        exit(1);
    }

    if (receiver(ctx, pkEm, pkEm_len, info, info_len, psk, psk_len, psk_id, psk_id_len) < 1) {
        fprintf(stderr, "%s: can't do encap!\n", argv[0]);
        exit(1);
    }

    if (memcmp(ctx->key, key, ctx->Nk) || memcmp(ctx->exporter, exp, ctx->kdf_Nh)) {
        fprintf(stderr, "test 4.4 receive failed!\n");
        exit(1);
    }

    printf("A7.4 recv passes!\n");

    free_hpke_context(ctx);

    free(ikmE);
    free(ikmS);
    free(pkRm);
    free(pkSm);
    free(psk);
    free(psk_id);
    free(ikmR);
    free(pkEm);
    free(enc);
    free(key);
    free(exp);

    printf("all tests pass!\n");
    free(info);

    exit(0);
}

