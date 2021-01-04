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
    char *a31ikmE = "217684b3a5dae4e826b32f539381aaab0fcd4829319beffbf60f7e52ae9ea7d1";
    char *a31pkRm = "04dc8b502e23e9bd533918ad19238aa39e334f5fac3114875fcf3be3a67f003fa5215d39a8bb0d42e2a883a0b7f3cea08bf73aaa3b3e057ab6db766e75d2a141e3";
    char *a31ikmR = "cc82b085f48f5fc966237b8fd9f88f919b3ecb7067937e6e051316759652446e";
    char *a31pkEm = "043da16e83494bb3fc8137ae917138fb7daebf8afba6ce7325478908c653690be70a9c9f676106cfb87a5c3edd1251c5fae33a12aa2c5eb7991498e345aa766004";
    char *a31key = "42794156fa4b990dacda4e1625b52f9d";
    char *a31exp = "b5ed294c49327fd46172b0623a01125432a51d6447cf053c57ca1de30df7352c";

    char *a31ct0 = "bec8250980e4e092e821bb9e90d2ad445980048bde2419355315cefcc9b018aeb9912df99483dabe0927bcaa0b";
    char *a31ct1 = "8c3476a017d986bb00d1675cee7d051bf68e3a27311463a0fd59c44d66c61c34a205702f29a7476fc8bf12a03c";
    char *a31ct2 = "e7674cc026ee19360f08108f9bd54b5d4c6aabf94d0b350d319d9cd9bdd9c41e4d807e76d7f9ffff5c6a7416e3";
    char *a31ct4 = "401ab30e14b87c8b5ce90eb7ee8a1800ed4d5034ab6afe792a1df81b59fc65151c6ed4847015aadf7423d395f4";

    char *a32ikmE = "87de910e077b5ecd0bc741a716cb819dd10fd1b9641030cc34b73e15f5b82419";
    char *a32pkRm = "0475072da3e5d06e61a356af605cc937ec9363fa3c4faccb309afc1fb7c001a7f708d8c609a05327bd07c05dd4ad258d8e1e5ae21d291bab1e00769c8b7948353e";
    char *a32psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a32psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a32key = "b2bc0d3b74a5adaa215a56ee24bcd5a5";
    char *a32exp = "e2dcd92c807e115f30e6ce2f931c9b7703354205aaa176ef9d439c8688830a70";

    char *a33ikmE = "065d5319c2ec55de1961da81f2b1c5269fc0d3e91f6845116c67f8aa3b2359be";
    char *a33pkRm = "04e52bea06f7df551af20abd964320e8cff1ee8c2a29a25e6c18af57db6270d58332f68faba6b81c65e8cc585456819dd831754fb60c617b4d6b75c381a87335da";
    char *a33ikmS = "bad181a04924b176f973874c5d8a9fbefef99bbff0974bd08b5bb2bff7bf7e33";
    char *a33key = "74bdf9a5e59a7b9fa7d2f79776c91ead";
    char *a33exp = "4e8f1ce833028ae349056fb95c8aaa1b439c89e66a12cd7663c488f1f57ded68";

    char *a34ikmE = "f8583351cdaf7ab4ec91ad306602d4822fd0f84a2e5ea563c360d4ba6308f93a";
    char *a34pkRm = "0464b4a0b01cccadebb4ccc46260699cb995579feed53241a7e210665b89ea9607d978400eea20b4921b92eda98ad63fd55271304c28489ef2f7a340912ba49566";
    char *a34ikmS = "bb16b05e401acb2d245f825df3317024aede39c92952a42c19846d97384f79ce";
    char *a34pkSm = "04b373ecb4a475ffac6efa4924c5b8327d47bcfc028dbc2be44b0c23c2eac7302d1943d8d5a01991888103f0357c346b047cea6137aefb016cebdc52f58b72c862";
    char *a34ikmR = "3b16243c4382065ef6fa0701442f80810ed68fdc361a13b953733d9ce82a9e4c";
    char *a34pkEm = "04dd8aae40c4286412f9ba7951066da54ea42c2cf21f83d66ec9b4ab3358637a18797495bc8f717937e75d31846a585afda6113be5c82d9b8b0cda43f0a76d05d5";
    char *a34psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a34psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a34key = "393a59b50e6b394a4ca0c3f9bebaac7e";
    char *a34exp = "b61db4f5d5118602108cbef98f6a51d0977cc166f070b9dd597269907268ab31";

    char *a41ikmE = "1be1a54220f95e65d4865efc314753feab34d867fb922613506839698e165744";
    char *a41pkRm = "04fe24564aef5463d7fb4efc238a4c6029364a0fbfbfa2201eb935fb1e6ef7cf9f5f3ecf4d98017c42d25ed11e5c37795c6996dbf79f54db013258373ea09ff3ff";
    char *a41ikmR = "a3a4746d926dd36270656e365e6914c9c0b22e447e2ab670f221700e3c880d9e";
    char *a41pkEm = "045703c14ae77d584727e31f1179c680977359ab12a8842344d25d70d94c989c7cbbc0d2de9258ce4258d2841e5b80d232e5226d5788f25835e53301e4b8b32c45";
    char *a41key = "d0aa3853ec6a21814c2876a76b62f3c7";
    char *a41exp = "b5c030ccb103a70348dce847de662ab57c01519165b63f13c12e6d2187ca5469077130df244e0dbc0f93fde972d9c39676e9c763272e28d3bd66366660386d17";

    char *a42ikmE = "c62c050ffc3573b9d0f5fe976afc913ee415b5746f9da906f205b591898e296d";
    char *a42pkRm = "04303656e359e35ff4c337ab17f6daefbe3a60adbe9a09608623a0d81c7d01a3b3cd4de3e54fe92b039c98c86c3c5f1f4ef3c8d229375537bbedae8e26a9ed6f12";
    char *a42psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a42psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a42key = "30a72ea42ab066063c1a7fd99641ac76";
    char *a42exp = "d762b3b46ec8c4551ec2daad04153efaa9821707069af57a161fbb961e5cc0aed0e89dfa8e7ca06ee6d93757ac8744447f434c19d6efb0a926ba3fb77f471b7a";

    char *a43ikmE = "729bf523707d5e574aca2180a334ffeb5f56a3a8b326ca60225cc1389309978c";
    char *a43pkRm = "041135938c8882b61de5ae7466b76d795bbb1490ab64ae79e86632ceb15026c9c62cf02fc523a48ed7bcd23b06c046b638bb15890698cd84569f72d3c8a8d18764";
    char *a43ikmS = "157225ca14ab53875997e5f5bdd5bce4c714c631e4774d145313aa0f97ea46ef";
    char *a43key = "8168f3f41ba5c2a91680a52d3864e842";
    char *a43exp = "706cbf9128b9e0d2007f231b6ddef31799bf648abdda67b916c77885417c6362418ee1494799613088f5029509c1afbfcec32d269e4fae9d2fc8158966c9fa76";

    char *a44ikmE = "c77066b17070dcb73af19d0e52f94ee22f2e2da85f509b877d4a6bb2d9cfe742";
    char *a44pkRm = "04205d8891d2234ff0656f0478bec3582e19e41b006e6eca94860735e4e8541d793ac37e4d7b71d7fe7e79ca8e41b8b0defb3d510e42abefaf25b6296ab2b6b5ad";
    char *a44ikmS = "4f8d660d9aadc7f1d2eba192fd1510028b23626d96aa5d8e077fcb1248fd84ee";
    char *a44pkSm = "04c7fa4aa253ce2ddf9d9f48b170721f850bb7d111f6763c25207cac56f66d1a9ca525dfcd3bba8c95c1077230868f8ab8a841a5caa8e52aa019be4ae54635344a";
    char *a44ikmR = "4f3df69eca2cd20da5068badaaca64393299d41435b7fb2c869327f350a9c33b";
    char *a44pkEm = "041bdc639637ed1cb1ce00cce7093ac2bfc199c763fa8a9d76012ea6aa2230ffcd5f2e26014dd1d18461fa3e8cb82511e7c804307c5d107b3a8cf392d65900f25f";
    char *a44psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a44psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a44key = "7d069bc8de13d63e068ce2ffcae5eaea";
    char *a44exp = "d584d697189c664ff6be2b9bdad061a47e0360b1f6243e07b64e34c7098cf092a89e0c738180a19da9873a0c22909bf85e7c211ef0e2bd62770036c529dc069f";
    
    char *a51ikmE = "1c7ea2dd703c3a98678dcb4a0c75029c803bcddd7f045c497e5ad2f6120c006d";
    char *a51pkRm = "0494eb40a3754f10995ab4fa52871d23731e551c401fdac3fe91ad5022241483006830de6232df192e003f08103bb7a8f62af6ba115fcc9b993afd939337b5d1f5";
    char *a51ikmR = "fa73e26ec21d46f603dc79eef82c023a738fe93e4bd559fa84d154887f05d117";
    char *a51pkEm = "04115d2cc2e317e363c2884f3f850f99e1292a1c0fb5c768f18096858a1fbf0ee1d573f3a6a40543207094ad89a2e1f87a1dc46bc98638e635dc2aefd40275d1d2";
    char *a51key = "40fb9b449fb4d8dafb435125bac1574b3321f51441492fd286f325b0db2bcbd6";
    char *a51exp = "3f54879c6b015df5d6887d1326edd7dc5861789a51dbce7e74a7135eb738e50f";

    char *a52ikmE = "26f07846c6436ac9e1f9fc3dd0b815308f59bce72142cbfb770c31d1a5ec0f72";
    char *a52pkRm = "0468416621586e3f9d55b277e4205472b04a33173f366b946d5e2b61242220b89cd91076873158dc0424232fc9b181c850480a54c54380a39434735d60d9a6051c";
    char *a52psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a52psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a52key = "f03ecda0fe9dcdf6677afe4d0c5b63317c539fad44cf467000f13121fd56ec1f";
    char *a52exp = "d85015754a4581003a3b835b08eab687a782862b4a3ded3d1e82c9eaccb3f28e";

    char *a53ikmE = "82c9f7cdc3d55b5523d1eef476e3438d2e5dd910d13b17308f53fc61ac93c2a8";
    char *a53pkRm = "04ce41ebe6d8931e4252adae4a792355510b73fedb04c58c779828763ab63d83fc2ec6eb22359c36da0d3daa654f72cb79e81fcc8345d36285aefb66b9094549c0";
    char *a53ikmS = "c65c7e9d5913816dfe0f5246ef876fd69ab045e88256eeaac1d16e810a4ee1d0";
    char *a53key = "ea8b805ac458810c7b9dc316b1e84f7531c26b765ffb5b6eb0e08adb5f020e26";
    char *a53exp = "a1eef29eab08f7774c2119b03f5d6e79ae734d5c42830e2dad16461efdf51fb4";

    char *a54ikmE = "d25ae0f5772d29c7631b3e6fbeddbd5ea3480cfcdedf52b62ea53a78eada0b51";
    char *a54pkRm = "049da19c2e909d90ed12c59fd476bc49283cf2efc99088171603d83801aa8f762f6ac7d66d333d4c43b5489e92dcb0a11c59efd5729ae633f96da99fc073ef32fc";
    char *a54ikmS = "330f1e1338cfb63cd4fb94f5f315da37d71e89350446b2510e76d2dfa8568181";
    char *a54pkSm = "048e36f8faa39be80d56ab8db82fb29c66c6a0507efe6e16385ad3269c88476048e9d905fe5b930f8e84a9dc4f8a39e19971273515e4a29d762fa721d26b5fc771";
    char *a54ikmR = "991577662e9bed488a7152b4994e212806919d1c685ac81b2c83bc307c835f98";
    char *a54pkEm = "04522b87fef8597fb474df8bffbb338bb4aa7870ca1a9ca00b7280933110559cc90985ac90c68af10c5ec2a8a7602e0d124efec764808917dcea31a44a7ed7d887";
    char *a54psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a54psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a54key = "cb923fa29319dbd29c8eb0e3f508140c55b1abab7358f8a7cfa90fe636849e27";
    char *a54exp = "d7a2c747836c0d76542c98535c4268767bdfb8fdf5b4cdd452cb0affa2013a45";

    char *a54ct0 = "0a0a68b3cdc8c4cc5129c2db2d5e66062757b5ef7c50e72b3df94baffcdeb1e9ccab54a48357b68d339508e07e";
    char *a54ct1 = "60207e04871f4a3327ea7079b217700b24db58632ad208476d4a83e3bca6c3d68060c1a4336bf36f34ecc608db";
    char *a54ct2 = "35f45af0971268fdd8fa8c41780ad734140917a712e3eace6daad62852be1ba1c687d53250ee1db700f2269fa7";
    char *a54ct4 = "0e77d22a859a074cc6f2bad3a5e419e3d1ba5fd06e1dbc7283878f5e07b641a7877616dc6d07120ec6f9fc834e";

    char *a61ikmE = "ea39fec1941c5f516e19533f40d415c65fde023c10c559f3845e71ffccea478101573d069cc67874d5b2aba6a22eb51cdd689836b7e9cabbb4469c57947db7316fa7";
    char *a61pkRm = "04003aefb3330e704d6c22ce7b67bab9b0e404be7f1374d0e6d3feeadc57f6b2031c5669516a8cbc309e895c6634fcfe95039a4648fc093f5bdad77756b363073d80c1005163c6fbea2c8268bebf70c6ca79928938d3e8d71471b1f116c1f3d23930e361219b7e104d3a76b7377f18a84abdbc84a41ddc9a83d6b6e7c55887a95fc66a6137";
    char *a61ikmR = "8249fd42416aba5b0d51dcd3548d774ae172148cbba1519107c5d84a160225441a9c018fdf3b9ffc2c41c1c62e29208d5165a59e7f14fe93b4f911cbbebda1904391";
    char *a61pkEm = "040197302e6c03e86ca3d9aa27ccd387944acc362099711a96b874f7bb07eaf770a0e11228441d184aff4be0916184f2b38779b9127b5edb9c8046f7b558d75fffefea01dd5754fc8c82b4076558d53fb2f3e60fd1f809d2bc9d304c2d3f35e28ae7757d5129295c94bbfe1ef2d01a459ecb7a361a8ae43a3d38e41d01b466f73ebef26ab7";
    char *a61key = "780b67de89a3c702fc30c5f159f25292c0e2f16560ea9c6b4b6183fd542c094e";
    char *a61exp = "82a365c4c7bc1d11e2c43aae232b23f709abce3bae7e70c0c48cf6f73dcf31655a466cf64a5ebb059196a7cf28996f050b8b9990480a44d5ece8e02e76b4340a";
    char *a61ct0 = "173900910caf7c88867dfa2a67ef51b092246818ff889f1f7652cfa7ba6ff46e14657d491c8276fb0518521b98";
    char *a61ct1 = "dcd904b4b5f6f28c7a2f6df76feddf873a9d50df9ce80414088f5a2f5774072ae262a4d022eb70e5fbe78aa3aa";
    char *a61ct2 = "b20313aa367924629b7bb987dc7fe773b423e679a6a95ef9fc0bee22c92ee2e6ca5df41038f42ab2b04ae141f5";
    char *a61ct4 = "f2d5f28f1325df43b603bf58587daa38d3843972582e5d8f8e07570b0c861324b58b2a1f14460f2382defc3a1b";

    char *a62ikmE = "b563555965facaa37a5e754cf2e50193953e1d527e61637e521df1868354799258f0d15d8807750cea08e9b6a358d2440ab06725861b237fb69973cf41e802434433";
    char *a62pkRm = "040035d455bcf95a7c9d492dc4ba04110435706a6fe6e53fb5aacdb624a03ce9cfebae3cbad679615ce00dd455b78a3b7de5d891f4ce4f6832c5ec190dec97a31a7965015000e29189dd08b1058d5d66fa995b068022781c6ea7ec16dfc2d33891ebecaadb17003dcce0f6bdc6fe6d7c4d0cd912c536c1f69d08faf6e7f299b0ffc2057c87";
    char *a62psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a62psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a62key = "030217f89b8673d7702c8698cf7e1eddaf1ad4b5c457c9f4888d8d22bd3816c7";
    char *a62exp = "f747a66e44d7de00c8486f04d3a0d37f3f43c2c0d7355a7810c9eea7b16eec36d3c1e590dc2c48f024ac2c2dc2418c7fa901c2b1ce1903d230986f5b04745fe3";


    char *a63ikmE = "c9621b9ef899275dc970606a2b0806fe860f62d539f3ee618a9409009b8ae154bc4acf495dd9fa8f850c4dca82b923b42270d7b16ed343c7e86e3036c88d0d7d77ee";
    char *a63pkRm = "0400c171be51c683af5ff8eb5a0e03c907a6f6e14d8314a4f81733ddd6055b8c8126f50b539f7b825356ae96d638f357122739c950f80ce5d7ed0a65bad442b66b38770111861d3ba2d5d57c0f5064e7b60781d38785f04ae767840cb764bf854b0d411337c9e4e415b3491a97c1a2555bac39e2910ce0e010379929ac3e0d2938c8baf6ca";
    char *a63ikmS = "d8779e14425887ebb21b1952b1a0b77842830aef910724b082807dfebc8ec309b4969da762369e77834593970215b85510c9a0347ff14c8583aae7c9c2208275b740";
    char *a63key = "6a2322915597c63a3dfd1acb98e095aa7b0b43d7b6113f0009b1518daeeab81f";
    char *a63exp = "85aeb64ee2265bc1f9b2fe3fcfb94adab727c7729b5f2bb526045e95f11ae9834d08f81e59ec4fb6cc0112dce1e0e029b1ff60082af01f463e469a9268284cf1";

    char *a64ikmE = "d7537fd470c0beece615e26dd109922460292e973127cb4e22da16c0756fc336224e07dbecdf36edd144ebcd82aece3db52f814a33a639b5e7c964b27f6e3195cd73";
    char *a64pkRm = "0401c45cce1bda6afdefd49a12d9fc2d091f89e87e6d7932023342ce78d87e564a0ca371795554d687a0d5d5982df2ab507091f0ffa70235710ebdc19db8968876d7ed00d4051e3d606e88886c97de770fbc6270978d71c6b7a374f2cde4f66c776678799991cb35e09000b2b001bf035a1aa67f18d551c0d2c7a8a7a8e38956325c775892";
    char *a64ikmS = "1e8d0026273feb61537181872e03ed2c7756f0ed1c4bb9ecd159614c2afdcaacc5fcf70f6d30d7ea6760c98a1ce1138a82497eb72461ca5da50c8729d431de53857f";
    char *a64pkSm = "04000890a9d2ef896c4c307b4e8c6e56639b68d442309e8a67ebdd80108b4bf3501b30c341a119b61bba2d17fa5a61f570be6ccc0f930057c1fa51050830e932eb2c3a006e1b2e05fc108b4851df60235fe387ae441c74df048e7a4c31e93f4ef3f44ecd2e7aeaf34f03db68a91e5cc7862a35aa4e6503cd40ac4456ea5b0c21e1fb00e26a";
    char *a64ikmR = "f0858f5e1865db4fe45dc3274bcd273a29088d80f9203a16ec1210e3d81dd50a99f15c427d547fea55593e2ef834beb5f80c536fdd2881a8943c05488a371a3c988d";
    char *a64pkEm = "04013c31cd06bce15d1b463800639a69d289d76144c1426f9061f4b0245b8490d48e29ecb8b3f2165970f341544a50d6017957e5c3f09b71f0a3b56af12383a53fbd9200b1d5c6833a5095d97982d2e3528b38e4664bf29a719beeb3bb2b7e5c4e2acb3f0bc1387eafa7048e5718a27b6d7e25ca4b7e750386cde8d89e52c39f98db734671";
    char *a64psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *a64psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *a64key = "efdc16c82ea9dd9761b6379e11e78c87931700e1f6714dc8c24019ff083e3c98";
    char *a64exp = "702d2ed8e95bd3d75202950a39ff26a7cf24b4f6bbd9556646992c7770b3c8d74fb8e82fe6da5518ce364ac3cd0a93cf15ccc86cc6f18af420a62ad8c06cd9c1";
    
    char *siv256ikmE = "217684b3a5dae4e826b32f539381aaab0fcd4829319beffbf60f7e52ae9ea7d1";
    char *siv256pkEm = "043da16e83494bb3fc8137ae917138fb7daebf8afba6ce7325478908c653690be70a9c9f676106cfb87a5c3edd1251c5fae33a12aa2c5eb7991498e345aa766004";
    char *siv256ikmR = "cc82b085f48f5fc966237b8fd9f88f919b3ecb7067937e6e051316759652446e";
    char *siv256pkRm = "04dc8b502e23e9bd533918ad19238aa39e334f5fac3114875fcf3be3a67f003fa5215d39a8bb0d42e2a883a0b7f3cea08bf73aaa3b3e057ab6db766e75d2a141e3";
    char *siv256key = "22ef69e34070dcdd1077908179bf78940cfa97dae90f351ead88e690c6c30f5b";
    char *siv256exp = "68d3ccdfd8cc270ffb82b5f4b59c91faf17374291a4f6fef5e8c765a2616f6b7";

    char *siv512ikmE = "d7537fd470c0beece615e26dd109922460292e973127cb4e22da16c0756fc336224e07dbecdf36edd144ebcd82aece3db52f814a33a639b5e7c964b27f6e3195cd73";
    char *siv512pkEm = "04013c31cd06bce15d1b463800639a69d289d76144c1426f9061f4b0245b8490d48e29ecb8b3f2165970f341544a50d6017957e5c3f09b71f0a3b56af12383a53fbd9200b1d5c6833a5095d97982d2e3528b38e4664bf29a719beeb3bb2b7e5c4e2acb3f0bc1387eafa7048e5718a27b6d7e25ca4b7e750386cde8d89e52c39f98db734671";
    char *siv512ikmS = "1e8d0026273feb61537181872e03ed2c7756f0ed1c4bb9ecd159614c2afdcaacc5fcf70f6d30d7ea6760c98a1ce1138a82497eb72461ca5da50c8729d431de53857f";
    char *siv512pkSm = "04000890a9d2ef896c4c307b4e8c6e56639b68d442309e8a67ebdd80108b4bf3501b30c341a119b61bba2d17fa5a61f570be6ccc0f930057c1fa51050830e932eb2c3a006e1b2e05fc108b4851df60235fe387ae441c74df048e7a4c31e93f4ef3f44ecd2e7aeaf34f03db68a91e5cc7862a35aa4e6503cd40ac4456ea5b0c21e1fb00e26a";
    char *siv512ikmR = "f0858f5e1865db4fe45dc3274bcd273a29088d80f9203a16ec1210e3d81dd50a99f15c427d547fea55593e2ef834beb5f80c536fdd2881a8943c05488a371a3c988d";
    char *siv512pkRm = "0401c45cce1bda6afdefd49a12d9fc2d091f89e87e6d7932023342ce78d87e564a0ca371795554d687a0d5d5982df2ab507091f0ffa70235710ebdc19db8968876d7ed00d4051e3d606e88886c97de770fbc6270978d71c6b7a374f2cde4f66c776678799991cb35e09000b2b001bf035a1aa67f18d551c0d2c7a8a7a8e38956325c775892";
    char *siv512psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
    char *siv512psk_id = "456e6e796e20447572696e206172616e204d6f726961";
    char *siv512key = "b8be7a95b03c89cc978acb8adccf7b6f4f9a0632640db0d9dbbf453c68136b834161f8dcde4c9629495fc2d143219c6c333e479de42015a877728266fdaefd16";
    char *siv512exp = "333e479de42015a877728266fdaefd16a99d361129929448313258a381ecda3bccc8f7bfc57411ecc2ad87efdfecabdbb530e2f6ca6ddc6c58a5915279dc2086";

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
        fprintf(stderr, "test 4.2 failed!\n");
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

    printf("--------------------------------------------\nSIV-256 test\n");

    s2os(siv256ikmE, &ikmE, &ikmE_len);
    s2os(siv256pkRm, &pkRm, &pkRm_len);
    s2os(siv256ikmR, &ikmR, &ikmR_len);
    s2os(siv256pkEm, &pkEm, &pkEm_len);
    s2os(siv256key, &key, &key_len);
    s2os(siv256exp, &exp, &exp_len);

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
        print_buffer("key should be", ctx->key, ctx->Nk);
        print_buffer("exp should be", ctx->exporter, ctx->kdf_Nh);
        fprintf(stderr, "SIV-256 send failed!\n");
        exit(1);
    }
    free(enc);
    printf("SIV-256 send passes!\n");

    printf("SIV-256 encryptions\n");
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
        fprintf(stderr, "SIV-256 receive failed!\n");
        exit(1);
    }
    printf("SIV-256 recv passes!\n");

    free_hpke_context(ctx);
    free(ikmE);
    free(pkRm);
    free(ikmR);
    free(pkEm);
    free(key);
    free(exp);

    printf("--------------------------------------------\nSIV-512 test\n");

    s2os(siv512ikmE, &ikmE, &ikmE_len);
    s2os(siv512ikmS, &ikmS, &ikmS_len);
    s2os(siv512pkRm, &pkRm, &pkRm_len);
    s2os(siv512pkSm, &pkSm, &pkSm_len);
    s2os(siv512psk, &psk, &psk_len);
    s2os(siv512psk_id, &psk_id, &psk_id_len);
    s2os(siv512ikmR, &ikmR, &ikmR_len);
    s2os(siv512pkEm, &pkEm, &pkEm_len);
    s2os(siv512key, &key, &key_len);
    s2os(siv512exp, &exp, &exp_len);
    
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
        print_buffer("key should be", ctx->key, ctx->Nk);
        print_buffer("exp should be", ctx->exporter, ctx->kdf_Nh);
        fprintf(stderr, "SIV-512 failed!\n");
        exit(1);
    }
    printf("SIV-512 send passes!\n");

    printf("SIV-512 encryptions\n");
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
        fprintf(stderr, "SIV-512 receive failed!\n");
        exit(1);
    }

    printf("SIV-512 recv passes!\n");

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

