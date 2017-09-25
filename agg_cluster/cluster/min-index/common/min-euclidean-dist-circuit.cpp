/**
 \file 		min-euclidean-dist-circuit.cpp
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
#include "min-euclidean-dist-circuit.h"
#include <cmath>

using namespace std;

int32_t test_min_eucliden_dist_circuit(
		e_role role, char* address, seclvl seclvl, 
		uint32_t srv_size, uint32_t clt_size,
		uint32_t dim, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing dstsharing, e_sharing minsharing) {

	uint32_t bitlen = 8, i, j, temp, tempsum, maxbitlen=32;
	uint64_t output;
	ABYParty* party = new ABYParty(role, address, seclvl, maxbitlen, nthreads, mt_alg);
	vector<Sharing*>& sharings = party->GetSharings();

	crypto* crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	uint32_t **server_points, **client_points;
	uint64_t verify;

	Circuit *distcirc, *mincirc;
	
	share ***Sshr, ***Cshr, **Ssqr, **Csqr, *mindst;
	share **Index;	


	srand(time(NULL));
	
        cout<<"Server size : "<<srv_size<<endl;
	
	//generate srv_size * dim * bitlen random bits as server points
	server_points = (uint32_t**) malloc(sizeof(uint32_t*) * srv_size);
	for(i = 0; i < srv_size; i++) {
		server_points[i] = (uint32_t*) malloc(sizeof(uint32_t) * dim);
		for(j = 0; j < dim; j++) {
			server_points[i][j] = rand() % ((uint64_t) 1 << bitlen);	
		}
	}
       

	
	//generate clt_size * dim * bitlen random bits as client points
        cout<<"Client size : "<<clt_size<<endl;

	client_points = (uint32_t**) malloc(sizeof(uint32_t*) * clt_size);

	for(i = 0; i < clt_size; i++) {
		client_points[i] = (uint32_t*) malloc(sizeof(uint32_t) * dim);
		for(j = 0; j < dim; j++) {
		     client_points[i][j] = rand() % ((uint64_t) 1 << bitlen);
		}
	}

	distcirc = sharings[dstsharing]->GetCircuitBuildRoutine();
	mincirc =  sharings[minsharing]->GetCircuitBuildRoutine();
	
	Index = (share**) malloc(sizeof(share*) * (clt_size*srv_size));

	//set server input
	Sshr = (share***) malloc(sizeof(share**) * srv_size);
	for (i = 0; i < srv_size; i++) {
		Sshr[i] = (share**) malloc(sizeof(share*) * dim);
		for (j = 0; j < dim; j++) {
			Sshr[i][j] = distcirc->PutINGate(1, server_points[i][j], bitlen, SERVER);
		}
	}

	Ssqr = (share**) malloc(sizeof(share*) * srv_size);
	for (i = 0; i < srv_size; i++) {
		tempsum = 0; 
		for (j = 0; j < dim; j++) {
			temp = server_points[i][j];
			tempsum += (temp * temp);
		}
		Ssqr[i] = mincirc->PutINGate(1, tempsum, 2*bitlen+ceil_log2(dim), SERVER);
	}

	for (i = 0; i < srv_size*clt_size; i++) {
		Index[i] = mincirc->PutINGate(1, i, ceil_log2(srv_size*clt_size), CLIENT);
	}


	//set client input
	Cshr = (share***) malloc(sizeof(share**) * clt_size);
	for (i = 0; i < clt_size; i++) {
		Cshr[i] = (share**) malloc(sizeof(share*) * dim);
		for (j = 0; j < dim; j++) {
			Cshr[i][j] = distcirc->PutINGate(1, 2*client_points[i][j], bitlen+1, CLIENT);
		}
	}

	Csqr = (share**) malloc(sizeof(share*) * clt_size);
	for (i = 0; i < clt_size; i++) {
		tempsum = 0; 
		for (j = 0; j < dim; j++) {
			temp = client_points[i][j];
			tempsum += (temp * temp);
		}
		Csqr[i] = mincirc->PutINGate(1, tempsum, 2*bitlen+ceil_log2(dim), CLIENT);
	}

    //@TODO
        
	mindst = build_min_euclidean_dist_circuit(Sshr, Cshr, Index, srv_size, clt_size, dim, Ssqr, Csqr, distcirc, (BooleanCircuit*) mincirc);

	mindst = mincirc->PutOUTGate(mindst, ALL);
	
	party->ExecCircuit();

	output = mindst->get_clear_value<uint64_t>();

	CBitVector out;
	//out.AttachBuf(output, (uint64_t) AES_BYTES * nvals);

	cout << "Testing min Euclidean distance in " << get_sharing_name(dstsharing) << " and " <<
		get_sharing_name(minsharing) << " sharing: " << endl;

	cout << "Circuit result = " << output << endl;
	verify = verify_min_euclidean_dist(server_points, client_points, srv_size, clt_size, dim);
	cout << "Verification result = " << verify << endl;

//	PrintTimings();

	//TODO free
	for(uint32_t i = 0; i < srv_size; i++) {
		free(server_points[i]);
		free(Sshr[i]);
	}

	free(server_points);
	free(Sshr);
	free(Ssqr);

	//TODO free
	for(uint32_t i = 0; i < clt_size; i++) {
		free(client_points[i]);
		free(Cshr[i]);
	}
	free(client_points);
	free(Cshr);
	free(Csqr);

	return 0;
}

//Build_
share* build_min_euclidean_dist_circuit(
		share*** S, share*** C, share** index,  
		uint32_t srv_size, uint32_t clt_size, uint32_t d, share** Ssqr, share** Csqr, 
		Circuit* distcirc, BooleanCircuit* mincirc) {

   share **distance, *temp, *mindist;
   
   
   uint32_t i, j, k;
   uint32_t size = srv_size*clt_size;
  
   distance = (share**) malloc(sizeof(share*) * size);
   assert(mincirc->GetCircuitType() == C_BOOLEAN);

   uint32_t ctr = 0;
   
   share* min_index;

   int count = 0;   
   for (j=0; j<clt_size; j++){				
	for (i=0; i<srv_size; i++) {
		count++;
	
	   distance[ctr] = distcirc->PutMULGate(S[i][0], C[j][0]);
	   for (k=1; k < d; k++) {
	  	temp = distcirc->PutMULGate(S[i][k], C[j][k]);
		distance[ctr] = distcirc->PutADDGate(distance[ctr], temp);
	   }
	   temp = mincirc->PutADDGate(Ssqr[i], Csqr[j]);
	   distance[ctr] = mincirc->PutA2YGate(distance[ctr]);
	   distance[ctr] = mincirc->PutSUBGate(temp, distance[ctr]);
	   ctr++;
	}
   }
   cout<<"Count total points: "<<count<<endl;
   mindist = mincirc->PutArgMinGate(distance, index, size);
   free(distance);
   return mindist;
}

uint64_t verify_min_euclidean_dist(uint32_t** server_points, uint32_t** client_points, 
	uint32_t srv_size, uint32_t clt_size, uint32_t dim) {
	
	uint32_t i, j, k;
	uint64_t mindist, tmpdist;

	mindist = MAX_UINT;

	uint32_t index = 0;
	uint32_t ctr=0, ctr_min = 0;
	for(j=0; j < clt_size; j++){
		for(i=0; i < srv_size; i++) {
			tmpdist = 0;		
			for(k=0; k < dim; k++) {
//				cout<<pow((int) abs(server_points[i][k] - client_points[j][k]), 2)<<endl;
				if(server_points[i][k] > client_points[j][k])
					tmpdist += pow((server_points[i][k] - client_points[j][k]), 2);
				else
					tmpdist += pow((client_points[j][k] - server_points[i][k]), 2);

			}
//			cout<<ctr<<"dist: "<<tmpdist<<endl;
//			ctr++;
			if(tmpdist < mindist){
				mindist = tmpdist;
				index = j*srv_size + i;
//				cout<<"j: "<<j<<" i:"<<i<<endl;
				ctr_min = ctr;
			}
		}
	}

	cout<<"minimum index is :"<<index<<endl;
//	cout<<"ctr index is :"<<ctr++<<endl;
	return mindist;
}
