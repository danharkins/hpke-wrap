# hpke-wrap

Implementation of Hybrid Public Key Encryption (draft-irtf-cfrg-hpke-12)

  Supports proposed compact representation for the NIST curves in the form of additional
  KEMs-- 19 for p256, 20 for p384, and 21 for p521-- as well as AES-SIV as an AEAD. Also
  supports a mode where a rolling receiver window is used to handle use of HPKE in
  lossy networks. 

  Note: all modes are supported but only KEMs with NIST curves.

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
This implementation has an unexported .h file, hpke_internal.h, which is used
by hpke.c but no one who calls hpke.c

aes_siv.[ch] is an implementation of RFC 5297. hkdf.[ch] is an implementation of
RFC 5869. jsmn.[ch] is some code written by Serge. A Zaitsev (spasibo, Serge!) to
parse json and is used to process the test vectors.

* HPKE Context

  Create an opaque context for HPKE. Takes the mode, the KEM id, the KDF id,
  and the AEAD id.

  Mode is one of: MODE_BASE, MODE_PSK, MODE_AUTH, MODE_AUTH_PSK
  KEM id is one of: DHKEM_P256, DHKEM_P384, DHKEM_P521, DHKEM_CP256, DHKEM_CP384, DHKEM_CP521
  KDF id is one of: HKDF_SHA_256, HKDF_SHA_384, HKDF_SHA_512
  AEAD id is one of: AES_128_GCM, AES_256_GCM, AES_256_SIV, AES_512_SIV, ChaCha20Poly,
		    EXPORTER-ONLY
  
  hpke_ctx *ctx;

  ctx = create_hpke_context(mode, kem_id, kdf_id, aead_id);

  Debugging for certain internal state can be turned on and off in a context:

  set_hpke_debug(ctx, debugging)

    - if debugging is non-zero internal state will be printed to standard out if it's
      zero then it will not be printed


  A receive window to address packet replay on lossy networks (where packets can
  be dropped and reordered) can be added by setting this capability in both the
  sender and receiver contexts:
  
      NOTE: this capability is NOT in the HPKE spec and the proposal to add it
      is still in the works.

  set_hpke_recv_window(ctx, setting)

    - if setting is non-zero the sender will include the sequence number used to
      construct the AEAD counter as part of the ciphertext and the receiver will
      parse ciphertext as if that sequence number is there and use it as part of
      its receive window processing

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

  sender(ctx, receiver_pubkey, receiver_keylen, info, infolen,
  	 psk, psk_len, psk_id, psk_id_len, ephem_pubkey, ephem_keylen)

    - generate internal keying material to encrypt messages for the receiver
    - info may be empty
    - psk and psk_id may be empty and if so psk_len and psk_id_len must be 0
    - the ephemeral key is returned

  receiver(ctx, ephem_pubkey, ephem_keylen, info, infolen, psk, psk_len, psk_id, psk_id_len)

    - generate internal keying material to decrypt messages from the sender
    - info may be empty
    - psk and psk_id may be empty and if so psk_len and psk_id_len must be 0

* Encrypt (wrap) and Decrypt (unwrap)

  wrap(ctx, aad, aadlen, plaintext, plaintext_len, ciphertext, tag)

    - encrypt and authenticate a plaintext using the keying material in a context
    - aad may be empty
    - called by senders

  unwrap(ctx, aad, aadlen, ciphertext, ciphertext_len, plaintext, tag)

    - decrypt and validate a ciphertext using keying material in a context
    - add may be empty
    - called by receivers

* Exporting secrets

  The HPKE context maintains an "exporter" in its key schedule and it can
  derive secrets from it. To obtain a secret, pass in an "exporter context"
  and how many octets you want, and get back a value. Caller is responsible
  for freeing returned_value when done.

  export_secret(ctx, export_context, context_len, export_len, **returned_value)

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

  A public key and input keying material to derive the keypair is output. The
  public key is provided to someone who wants to send something to you and
  the input keying material is used to generate the local identity key when
  you receive something encrypted with your public key.

parse_tv.c 

  Take the JSON verson of the test vectors and go through them all, testing
  all of the KEMs that use the NIST curves. 

  USAGE: ./parse_tv -t <tv> [-jvdh]
        -t  the JSON test vectors
        -j  dump the test vector contents
        -d  chatty progress of test vectors
        -v  verbose HPKE output
        -h  this help message

hpke_wrap.c

  Encrypt and authenticate a plaintext to a recipient identified by a public key.
  Defaults to AES-SIV with a key size dependent on the recipient's public key.

  USAGE: ./hpke_wrap [-aikspbh]
        -a  some AAD to include in the wrapping
        -i  some info to include in the wrapping
        -k  the recipient's public key
        -p  the plaintext to wrap
        -b  base64 encode the output
	-w  include sequence number in ciphertext
        -h  this help message

hpke_unwrap.c

  Decrypt and validate a ciphertext that had been wrapped by hpke_wrap. Defaults
  to AES-SIV with a key size dependent on the size of the sender's public key.

  USAGE: ./hpke_unwrap [-aikrscbh]
        -a  some AAD to include in the unwrapping
        -i  some info to include in the unwrapping
        -k  the sender's public key
        -r  keying material to derive receiver's keypair
        -c  the ciphertext to unwrap
        -b  base64 decode the input prior to processing
	-w  implement a rolling receive window with sequence number from ciphertext
        -h  this help message

test-vectors-dnhpke.json

  A copy of the -09 test vectors plus new ones for compressed KEMs and deterministic AEAD


