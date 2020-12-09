# hpke-wrap

Implementation of Hybrid Public Key Encryption (draft-irtf-cfrg-hpke-06)

  Note: all modes are supported but only KEMs with NIST curves, also supports AES-SIV
        as an AEAD even though that's not part of the draft.

  This distribution requires OpenSSL. Hand-edit the Makefile to point to the right
  location.

How it works
------------

The sender wants to send an encrypted string to a receiver. It is assumed the sender
has the receiver's public identity key and trusts it. The sender can provide
authentication of the message if the receiver trusts the sender's static identity key.
Also, a pre-shared key can be mixed into the internal keying material to provide
post-quantum resistance.

The sender can include optional information that is mixed into the keying material and
can optionally include associated data with the wrapped message. If this is not
transmitted with the public key and ciphertext it is assumed the receiver has the
ability to create the identical info and aad.

Exported APIs
-------------

All the code lives in hpke.c and apps that call these APIs need to include hpke.h.

* HPKE Context

  Create an opaque context for HPKE. Takes the mode, the KEM id, the KDF id, the AEAD id,
  an optional PSK and PSK ID.

  Mode is one of: MODE_BASE, MODE_PSK, MODE_AUTH, MODE_AUTH_PSK
  KEM id is one of: DHKEM_P256, DHKEM_P384, DHKEM_P521
  KDF id is one of: HKDF_SHA_256, HKDF_SHA_384, HKDF_SHA_512
  AEAD id is one of: AES_128_GCM, AES_256_GCM, AES_256_SIV, AES_512_SIV, ChaCha20Poly
  
  hpke_ctx *ctx;

  ctx = create_hpke_context(mode, kem_id, kdf_id, aead_id, psk, psk_len, psk_id, psk_id_len);

  Debugging for certain internal state can be turned on and off in a context

  set_hpke_debug(ctx, debugging)

    - if debugging is non-zero internal state will be printed to standard out if it's
      zero then it will not be printed

  A context is freed when not needed anymore
  
  free_hpke_context(ctx);
  
* Putting keys in a context

  derive_ephem_keypair(ctx, ikm, ikmlen)
  
    - derive an ephemeral key pair appropriate for the KEM from an input string
    - this is called by senders

  generate_ephem_keypair(ctx)

    - create a truly random ephemeral key (not one generated from an input string)
    - this is called by senders who choose not to derive ephemeral keys

  derive_local_static_keypair(ctx, ikm, ikmlen)

    - derive a static identity key appropriate for the KEM from an input string
    - this is called by receivers
    - this can be called by senders if the mode provides for authentication
    
  assign_peer_static_keypair(ctx, pubkey, keylen)

    - add a sender's trusted identity key to the context to validate authenticated modes
    - this is called by receivers 

* Generating keying material

  sender(ctx, receiver_pubkey, receiver_keylen, info, infolen, ephem_pubkey, ephem_keylen)

    - generate internal keying material to encrypt messages for the receiver
    - info may be empty
    - the ephemeral key is returned

  receiver(ctx, ephem_pubkey, ephem_keylen, info, infolen)

    - generate internal keying material to decrypt messages from the sender
    - info may be empty

* Encrypt (wrap) and Decrypt (unwrap)

  wrap(ctx, aad, aadlen, plaintext, plaintext_len, ciphertext, tag)

    - encrypt and authenticate a plaintext using the keying material in a context
    - aad may be empty
    - called by senders

  unwrap(ctx, aad, aadlen, ciphertext, ciphertext_len, plaintext, tag)

    - decrypt and validate a ciphertext using keying material in a context
    - add may be empty
    - called by receivers

* Creating a usable keypair

  generate_static_keypair(kem, ikm, ikm_len, pk)

    - returns some keying material suitable to create a keypair on the curve indicated
      by kem. This should be sent to derive_local_static_keypair(). Also returns the
      serialized version of the corresponding public key. This should be sent to people
      who want to wrap stuff for you, they'll pass it in sender() before they wrap()
      stuff for you.
    - recipient is responsible for freeing ikm and pk.

Additional routines
-------------------

hpke_genkey.c

  Generates a keypair for use with wrap and unwrap.

  USAGE: ./hpke_genkey [-bh]
        -k  kem the key will be for (16=p256, 17=p384, 18=p521)
        -b  base64 encode the output
        -h  this help message

hpke_test.c

  Validates some of the test vectors from the -06 version of the draft as well
  as some AES-SIV test vectors that aren't

hpke_wrap.c

  Encrypt and authenticate a plaintext to a recipient identified by a public key.

  USAGE: ./hpke_wrap [-aikspbh]
        -a  some AAD to include in the wrapping
        -i  some info to include in the wrapping
        -k  the recipient's public key in SECG uncompressed form
        -p  the plaintext to wrap
        -b  base64 encode the output
        -h  this help message

hpke_unwrap.c

  Decrypt and validate a ciphertext that had been wrapped by hpke_wrap.

  USAGE: ./hpke_unwrap [-aikrscbh]
        -a  some AAD to include in the unwrapping
        -i  some info to include in the unwrapping
        -k  the sender's public key in SECG uncompressed form
        -r  keying material to derive receiver's keypair
        -c  the ciphertext to unwrap
        -b  base64 decode the input prior to processing
        -h  this help message
