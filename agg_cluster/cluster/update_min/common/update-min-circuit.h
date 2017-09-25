/**
 \file 		min-euclidean-dist-circuit.h
 \author 	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2015 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Affero General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			This program is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Affero General Public License for more details.
			You should have received a copy of the GNU Affero General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Implementation of Minimum Euclidean Distance Circuit
 */

#ifndef __UPDATE_MIN_H_
#define __UPDATE_MIN_H_

#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/aby/abyparty.h"

#include "paillier_eff.h"
#include "timer.hpp"
#include <cassert>
#include <vector>

using namespace std;

/**
 * Build the Efficient Curcuit for the minimum index 
 */
share* build_Min_Ind_dist_circ_eff(share** A, share** B, share** index, uint32_t size, Circuit* dstcirc, BooleanCircuit* mincirc);


/**
 * Server (garbler) decrypt and return plaintext..
 */
uint32_t* blinding(pa_pubkey_t* pub, pa_prvkey_t* prv, vector<pa_cipher*> c_vect);

/**
 * A (Client, evaluator) : generate randomness, add enc(d_i) + enc(r_i)
 * return encryptions
 */
vector<pa_cipher*> homo_add_randomness(pa_pubkey_t* pub, vector<pa_cipher*> c_vect, 
					vector<pa_text*> randomness, gmp_randstate_t rnd);

/**
 * Execute of the protocol, [A(rand) <==> B(rand+ct)]
 * return A gets the index (minimum)...
 */
uint64_t exec_min_circ(e_role role, 
		char* address, seclvl seclvl, uint32_t size,
		uint32_t* client_vect, uint32_t* server_vect,
		uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing dstsharing,
		e_sharing minsharing);

/**
 * Testing the correctness of curcuit. (efficient version)
 */
int32_t test_min_ind_enc_dist_circuit_eff(e_role role, char* address, seclvl seclvl, 
		uint32_t size, uint32_t nthreads, e_mt_gen_alg mt_alg, 
		e_sharing dstsharing, e_sharing minsharing);

/**
 * Verifying the correctness
 */
uint32_t verify_min_index_rand_dist(uint32_t* party_A_rand_dist, uint32_t* party_B_rand,  uint32_t size);


/**
 * Testing the curcuit only using Yao .... (bit of slow ...)
 */
int32_t test_min_ind_enc_dist_circuit(e_role role, char* address, seclvl seclvl, uint32_t size, uint32_t nthreads, e_mt_gen_alg mt_alg,	e_sharing minsharing);

share* build_Min_Ind_dist_circ(share** A, share** B, share** index, uint32_t size, BooleanCircuit* mincirc);

#endif /* __UPDATE_MIN_H_ */
