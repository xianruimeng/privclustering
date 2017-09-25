/**
 \file 		pa.h
 \author 	Daniel Demmler
 \copyright Copyright (C) 2015 EC SPRIDE - daniel.demmler@ec-spride.de

 \brief		A library implementing the Damgaard Jurik Nielsen cryptosystem with s=1 (Same properties as Paillier, but more efficient).
 based on:<br>
 libpa - A library implementing the Paillier cryptosystem.
 (http://hms.isi.jhu.edu/acsc/libpa/)
 */

/*
 libpa - v0.9
 A library implementing the Damgaard Jurik Nielsen cryptosystem with s=1 (~Paillier).
 based on:
 libpaillier - A library implementing the Paillier cryptosystem.
 (http://hms.isi.jhu.edu/acsc/libpaillier/)

 2015 EC SPRIDE
 daniel.demmler@ec-spride.de

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 General Public License for more details.
 */

#ifndef _PAE_H_
#define _PAE_H_
#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../../../abycore/util/powmod.h"

/*
 On memory handling:

 At no point is any special effort made to securely "shred" sensitive
 memory or prevent it from being paged out to disk. This means that
 it is important that functions dealing with private keys and
 plaintexts (e.g., pa_keygen and pa_enc) only be run on
 trusted machines. The resulting ciphertexts and public keys,
 however, may of course be handled in an untrusted manner.

 */

/******
 TYPES
 *******/

/*
 This represents a public key, which is the modulus n plus a generator h.
 */
typedef struct {
	int bits; /* e.g., 1024 */
	int rbits; /* e.g., 512 */
	mpz_t n; /* public modulus n = p q */
	mpz_t n_squared; /* cached to avoid recomputing */
	mpz_t h; /* generator h = -x^2 mod n */
	mpz_t h_s; /* h_s = h^n mod n^2 */
} pa_pubkey_t;

/*
 This represents a Paillier private key; it needs to be used with a
 pa_pubkey_t to be meaningful. It includes the Carmichael
 function (lambda) of the modulus. The other value is kept for
 efficiency and should be considered private.
 */
typedef struct {
	mpz_t lambda; /* lambda(n), i.e., lcm(p-1,q-1) */
	mpz_t lambda_inverse; /* inverse of lambda (mod n)*/
	mpz_t p; /* cached to avoid recomputing */
	mpz_t q; /* cached to avoid recomputing */
	mpz_t q_inverse; /* inverse of q (mod p) */
	mpz_t q_squared_inverse; /* inverse of q^2 (mod p^2) */
	mpz_t p_minusone; /* cached to avoid recomputing */
	mpz_t q_minusone; /* cached to avoid recomputing */
	mpz_t p_squared; /* cached to avoid recomputing */
	mpz_t q_squared; /* cached to avoid recomputing */
	mpz_t ordpsq; /* p^2-p */
	mpz_t ordqsq; /* q^2-q */
} pa_prvkey_t;





typedef struct {
    mpz_t m;
} pa_text;

    /*
      This is a (semantic rather than structural) type for ciphertexts.
      These can also be converted to or from byte arrays (for example in
      order to store them in a file).
     */
typedef struct {
    mpz_t c;
} pa_cipher;

/*
 This is the type of the callback functions used to obtain the
 randomness needed by the probabilistic algorithms. The functions
 pa_get_rand_devrandom and pa_get_rand_devurandom
 (documented later) may be passed to any library function requiring a
 pa_get_rand_t, or you may implement your own. If you implement
 your own such function, it should fill in "len" random bytes in the
 array "buf".
 */
typedef void (*pa_get_rand_t)(void* buf, int len);


/*****************
 BASIC OPERATIONS
 *****************/

/*
 Generate a keypair of length modulusbits using randomness from the
 provided get_rand function. Space will be allocated for each of the
 keys, and the given pointers will be set to point to the new
 pa_pubkey_t and pa_prvkey_t structures. The functions
 pa_get_rand_devrandom and pa_get_rand_devurandom may be
 passed as the final argument.
 */
void pa_keygen(unsigned int modulusbits, pa_pubkey_t** pub, pa_prvkey_t** prv);

/*
 Encrypt the given plaintext with the given public key using
 randomness from get_rand for blinding. If res is not null, its
 contents will be overwritten with the result. Otherwise, a new
 pa_ciphertext_t will be allocated and returned.
 */
void pa_encrypt(mpz_t res, pa_pubkey_t* pub, mpz_t pt, gmp_randstate_t rnd);
 

pa_cipher* pa_encrypt_0(pa_cipher* res, pa_pubkey_t* pub, mpz_t plaintext, gmp_randstate_t rnd);

pa_text* pa_text_from_ui(unsigned long int x);

pa_cipher* pa_create_enc_zero();
pa_cipher* pa_cipher_init();


  /*****************************
     USE OF ADDITIVE HOMOMORPHISM
     *****************************/


/*
            Multiply the two ciphertexts assuming the modulus in the given
            public key and store the result in the contents of res, which is
            assumed to have already been allocated.
     */
void pa_mul(pa_pubkey_t* pub, pa_cipher* res, pa_cipher* ct0, pa_cipher* ct1);

    /*
      If ct is an encryption of x and pt is a negative number, 
      then res will become an encryption of x * pt mod n, where n is
      the modulus in pub.
     */
void pa_exp_neg(pa_pubkey_t* pub, pa_cipher* res, pa_cipher* ct, pa_text* pt) ;

    /*
            Multiply the two ciphertexts assuming the modulus in the given
            public key and store the result in the contents of res, which is
            assumed to have already been allocated.
     */
void pa_sub(pa_pubkey_t* pub, pa_cipher* res, pa_cipher* ct0, pa_cipher* ct1);

    /*
      Raise the given ciphertext to power pt and store the result in res,
      which is assumed to be already allocated. If ct is an encryption of
      x, then res will become an encryption of x * pt mod n, where n is
      the modulus in pub.
     */
void pa_exp(pa_pubkey_t* pub, pa_cipher* res, pa_cipher* ct, pa_text* pt);

/*
 Encrypt the given plaintext with the given public key using
 randomness from get_rand for blinding. If res is not null, its
 contents will be overwritten with the result. Otherwise, a new
 pa_ciphertext_t will be allocated and returned.
 */
void pa_encrypt_crt(mpz_t res, pa_pubkey_t* pub, pa_prvkey_t* prv, mpz_t pt, gmp_randstate_t rnd);

/**
 * fixed base encryption. Requires pre-computed fixed base table.
 */
void pa_encrypt_fb(mpz_t res, pa_pubkey_t* pub, mpz_t plaintext, gmp_randstate_t rnd);

/*
 Decrypt the given ciphertext with the given key pair. If res is not
 null, its contents will be overwritten with the result. Otherwise, a
 new pa_plaintext_t will be allocated and returned.
 */
void pa_decrypt(mpz_t res, pa_pubkey_t* pub, pa_prvkey_t* prv, mpz_t ct);

/**********************
 KEY IMPORT AND EXPORT
 **********************/

/*
 Import or export public and private keys from or to hexadecimal,
 ASCII strings, which are suitable for I/O. Note that the
 corresponding public key is necessary to initialize a private key
 from a hex string. In all cases, the returned value is allocated for
 the caller and the values passed are unchanged.
 */
char* pa_pubkey_to_hex(pa_pubkey_t* pub);
char* pa_prvkey_to_hex(pa_prvkey_t* prv);
pa_pubkey_t* pa_pubkey_from_hex(char* str);
pa_prvkey_t* pa_prvkey_from_hex(char* str, pa_pubkey_t* pub);

/********
 CLEANUP
 ********/

/*
 These free the structures allocated and returned by various
 functions within library and should be used when the structures are
 no longer needed.
 */
void pa_freepubkey(pa_pubkey_t* pub);
void pa_freeprvkey(pa_prvkey_t* prv);

void pa_freeplaintext(pa_text* pt);
void pa_freeciphertext(pa_cipher* ct);

/***********
 MISC STUFF
 ***********/

/*
 Just a utility used internally when we need round a number of bits
 up the number of bytes necessary to hold them.
 */
#define PAILLIER_BITS_TO_BYTES(n) ((n) % 8 ? (n) / 8 + 1 : (n) / 8)

void pa_pow_mod_n_crt(mpz_t res, const mpz_t b, const mpz_t e, const pa_pubkey_t* pub, const pa_prvkey_t* prv);
void pa_pow_mod_n_squared_crt(mpz_t res, const mpz_t b, const mpz_t e, const pa_pubkey_t* pub, const pa_prvkey_t* prv);

/**
 * create full public key given only n and h (e.g., after a key exchange)
 */
void pa_complete_pubkey(unsigned int modulusbits, pa_pubkey_t** pub, mpz_t n, mpz_t h);

#endif
