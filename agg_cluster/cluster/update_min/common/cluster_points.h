
#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstring>
#include <gmp.h>
#include <iostream>
#include <ctime>
#include <vector>
#include <math.h>

#include "paillier_eff.h"
#include "update-min-circuit.h"

//Utility libs
#include "../../../abycore/util/crypto/crypto.h"
#include "../../../abycore/util/parse_options.h"
//ABY Party class
#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/util/socket.h"



#ifndef _CLUSTER_POINT_H_
#define _CLUSTER_POINT_H_




const int VECTOR_SEND_RECV_ID = 100;
const int MATRIX_SEND_RECV_ID = 200;
//#define MATRIX_SEND_ID = 400;


using namespace std;


uint32_t find_min(uint32_t nthreads, seclvl seclvl, e_mt_gen_alg mt_alg,
	pa_pubkey_t* pub, pa_prvkey_t* prv, 
	vector<pa_cipher*> cipher_vector, 
	e_role role, CSocket& socket, 
	char* address, int port, gmp_randstate_t rnd);


void mpz_to_ui(uint32_t *x_ui, mpz_t x);

/**
 * send one mpz_t to sock
 */
void sendmpz_t(mpz_t t, CSocket sock, BYTE * buf);

/**
 * receive one mpz_t from sock. t must be initialized.
 */
void receivempz_t(mpz_t t, CSocket sock, BYTE * buf);

/**
 * send one mpz_t to sock, allocates buffer
 */
void sendmpz_t(mpz_t t, CSocket sock);

/**
 * receive one mpz_t from sock. t must be initialized.
 */
void receivempz_t(mpz_t t, CSocket sock);

/**
 * send a vector of encryptions
 * if role == 1: send the v
 * if role == 0: receive the v
 * ...
 */
vector<pa_cipher*> recv_enc(uint32_t size, CSocket socket, string address, int port);
bool send_enc(vector<pa_cipher*> v, CSocket socket, string address, int port);

vector< vector<pa_cipher*> > recv_vect_enc(uint32_t size, CSocket socket, string address, int port);
bool send_vect_enc(vector< vector<pa_cipher*> > v, CSocket socket, string address, int port);

bool send_matrix_enc(vector< vector<pa_cipher*> > v, CSocket socket, string address, int port);
vector< vector<pa_cipher*> > recv_matrix_enc(uint32_t size, CSocket socket, string address, int port);


#endif