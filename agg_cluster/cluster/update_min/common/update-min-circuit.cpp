/**
 \file 		min-euclidean-dist-circuit.cpp
 */
 
#include "update-min-circuit.h"
#include <cmath>



// Efficient implementation using Arithmatic Curcuit and Yao...
/**
 *
 */
uint32_t* blinding(pa_pubkey_t* pub, pa_prvkey_t* prv, vector<pa_cipher*> c_vect)
{
	uint32_t* randomness_add_ct;
	uint32_t i;

	size_t size = c_vect.size();

	randomness_add_ct = (uint32_t*) malloc(sizeof(uint32_t) * size);

	for(i=0; i<c_vect.size(); ++i){//    
	 mpz_t results;
	 mpz_init(results);
         pa_decrypt(results, pub, prv, c_vect[i]->c);
	 randomness_add_ct[i] = mpz_get_ui (results);        
       	 mpz_clear(results);
	}
	return randomness_add_ct;
}


vector<pa_cipher*> 
	homo_add_randomness(pa_pubkey_t* pub, vector<pa_cipher*> c_vect, 
				vector<pa_text*> randomness, gmp_randstate_t rnd)
{
	uint32_t i;
	//uint32_t *party_A_rand_dist;


	size_t size = c_vect.size();

	// party_A_rand_dist = (uint32_t*) malloc(sizeof(uint32_t) * size);

	// for(i = 0; i < size; i++) {
	// 	party_A_rand_dist[i] = rand() % ((uint32_t) 1 << bitlen);	
	// }   

    vector<pa_cipher*> enc_rand;
    enc_rand.resize(size);

    vector<pa_cipher*> enc_rand_ct;
    enc_rand_ct.resize(size);

	for(i = 0; i < size; i++) {
		
		enc_rand[i] = pa_encrypt_0(0, pub, randomness[i]->m, rnd);

		enc_rand_ct[i] = pa_cipher_init();

		pa_mul(pub, enc_rand_ct[i], c_vect[i], enc_rand[i]);

	}   
	return enc_rand_ct;
}

/**
 * 
 * 
 */
uint64_t exec_min_circ(e_role role, 
		char* address, seclvl seclvl, uint32_t size,
		uint32_t* client_vect, uint32_t* server_vect,
		uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing dstsharing,
		e_sharing minsharing)
{

    Timer t;

	uint32_t bitlen = 10, i, j, temp, tempsum, maxbitlen=32;
	uint64_t output;
	
	ABYParty* party = new ABYParty(role, address, seclvl, maxbitlen, nthreads, mt_alg);
	vector<Sharing*>& sharings = party->GetSharings();

	crypto* crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	
	uint64_t verify;

	Circuit *distcirc, *mincirc; //
	
	share **Ashr, **Bshr, *min_ind, **Index;
	
	
    distcirc = sharings[dstsharing]->GetCircuitBuildRoutine();
	mincirc =  sharings[minsharing]->GetCircuitBuildRoutine();


	//set server input
	Ashr = (share**) malloc(sizeof(share*) * size);
	Bshr = (share**) malloc(sizeof(share*) * size);
	Index = (share**) malloc(sizeof(share*) * (size));
	for (i = 0; i < size; i++) {	
		Ashr[i] = distcirc->PutINGate(1, -client_vect[i], bitlen*4, CLIENT);
		Bshr[i] = distcirc->PutINGate(1, server_vect[i], bitlen*4, SERVER);
		Index[i] = mincirc->PutINGate(1, i, ceil_log2(size), CLIENT);
	}

        
        t.start();
	min_ind = build_Min_Ind_dist_circ_eff(Ashr, Bshr, Index, size, distcirc, (BooleanCircuit*) mincirc);

	min_ind = mincirc->PutOUTGate(min_ind, CLIENT);
	party->ExecCircuit();

	t.stop();
	cout<<"Actual Curcuit time "<<t.elapsed_time()<<" s."<<endl;
        t.start();
	output = min_ind->get_clear_value<uint64_t>();

	//CBitVector out;
	//out.AttachBuf(output, (uint64_t) AES_BYTES * nvals);

	// cout << "Testing index min in " << get_sharing_name(dstsharing) << " AND " <<
	// 	get_sharing_name(minsharing) << " sharing: " << endl;

	// cout << "Circuit result = " << output << endl;
	// verify = verify_min_index_rand_dist(party_A_rand_dist, party_B_rand, size);
	// cout << "Verification result = " << verify << endl;

//	PrintTimings();

	//TODO free
	for(uint32_t i = 0; i < size; i++) {
		free(Index[i]);
		free(Ashr[i]);
		free(Bshr[i]);
	}
	free(Index);
	free(Ashr);
	free(Bshr);
        t.stop();
        cout<<"After curcuit cleaning time "<<t.elapsed_time()<<" s."<<endl;
	return output;
}




		free(Bshr[i]);
	}
	free(Index);
	free(Ashr);
	free(Bshr);
        t.stop();
        cout<<"After curcuit cleaning time "<<t.elapsed_time()<<" s."<<endl;
	return output;
}



// Efficient implementation using Arithmatic Curcuit and Yao...
int32_t test_min_ind_enc_dist_circuit_eff(
		e_role role, char* address, seclvl seclvl, 
		uint32_t size, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing dstsharing,
		e_sharing minsharing) {

	uint32_t bitlen = 8, i, j, temp, tempsum, maxbitlen=32;
	uint64_t output;
	
	ABYParty* party = new ABYParty(role, address, seclvl, maxbitlen, nthreads, mt_alg);
	vector<Sharing*>& sharings = party->GetSharings();

	crypto* crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	
	uint32_t *party_A_rand_dist, *party_B_rand;
	
	uint64_t verify;

	Circuit *distcirc, *mincirc; //
	
	share **Ashr, **Bshr, *min_ind, **Index;
		
    distcirc = sharings[dstsharing]->GetCircuitBuildRoutine();
	mincirc =  sharings[minsharing]->GetCircuitBuildRoutine();
	
	srand(time(NULL));
	
    cout<<"party A (dist - randomness) size : "<< size <<endl;
	//generate party_A_size * bitlen random bits as server points
	party_A_rand_dist = (uint32_t*) malloc(sizeof(uint32_t) * size);
	for(i = 0; i < size; i++) {
		party_A_rand_dist[i] = rand() % ((uint32_t) 1 << bitlen);	
	}   
	
	//generate party_A_size * bitlen random bits as server points
    cout<<"party B (randomness) size : "<< size <<endl;
	party_B_rand = (uint32_t*) malloc(sizeof(uint32_t) * size);

	for(i = 0; i < size; i++) {
		party_B_rand[i] = rand() % ((uint32_t) 1 << maxbitlen);

		party_A_rand_dist[i] = party_A_rand_dist[i] + party_B_rand[i];
	}


	//set server input
	Ashr = (share**) malloc(sizeof(share*) * size);
	Bshr = (share**) malloc(sizeof(share*) * size);
	Index = (share**) malloc(sizeof(share*) * (size));
	for (i = 0; i < size; i++) {
		Ashr[i] = distcirc->PutINGate(1, party_A_rand_dist[i], bitlen*4, CLIENT);
		Bshr[i] = distcirc->PutINGate(1, -party_B_rand[i], bitlen*4, SERVER);
		Index[i] = mincirc->PutINGate(1, i, ceil_log2(size), CLIENT);
	}

           
	min_ind = build_Min_Ind_dist_circ_eff(Ashr, Bshr, Index, size, distcirc, (BooleanCircuit*) mincirc);

	min_ind = mincirc->PutOUTGate(min_ind, ALL);
	
	party->ExecCircuit();

	output = min_ind->get_clear_value<uint64_t>();

	//CBitVector out;
	//out.AttachBuf(output, (uint64_t) AES_BYTES * nvals);

	cout << "Testing index min in " << get_sharing_name(dstsharing) << " AND " <<
		get_sharing_name(minsharing) << " sharing: " << endl;

	cout << "Circuit result = " << output << endl;
	verify = verify_min_index_rand_dist(party_A_rand_dist, party_B_rand, size);
	cout << "Verification result = " << verify << endl;

//	PrintTimings();

	//TODO free
	for(uint32_t i = 0; i < size; i++) {
		free(Index[i]);
		free(Ashr[i]);
		free(Bshr[i]);
	}

	free(party_A_rand_dist);
	free(party_B_rand);
	free(Index);
	free(Ashr);
	free(Bshr);
	free(crypt);

	return 0;

}

int32_t test_min_ind_enc_dist_circuit(
		e_role role, char* address, seclvl seclvl, 
		uint32_t size, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing minsharing) {

	uint32_t bitlen = 8, i, j, temp, tempsum, maxbitlen=32;
	uint64_t output;
	
	ABYParty* party = new ABYParty(role, address, seclvl, maxbitlen, nthreads, mt_alg);
	vector<Sharing*>& sharings = party->GetSharings();

	crypto* crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	
	uint32_t *party_A_rand_dist, *party_B_rand;
	
	uint64_t verify;

	Circuit *mincirc; //*distcirc, 
	
	share **Ashr, **Bshr, *min_ind, **Index;
	
	
   // distcirc = sharings[dstsharing]->GetCircuitBuildRoutine();
	mincirc =  sharings[minsharing]->GetCircuitBuildRoutine();
	
	srand(time(NULL));
	
    cout<<"party A (dist + randomness) size : "<< size <<endl;
	//generate party_A_size * bitlen random bits as server points
	party_A_rand_dist = (uint32_t*) malloc(sizeof(uint32_t) * size);
	for(i = 0; i < size; i++) {
		party_A_rand_dist[i] = rand() % ((uint32_t) 1 << bitlen);	
	}   
	
	//generate party_A_size * bitlen random bits as server points
    cout<<"party B (randomness) size : "<< size <<endl;
	party_B_rand = (uint32_t*) malloc(sizeof(uint32_t) * size);

	for(i = 0; i < size; i++) {
		party_B_rand[i] = rand() % ((uint32_t) 1 << bitlen);	
		party_A_rand_dist[i] = party_A_rand_dist[i] + party_B_rand[i];
	}


	//set server input
	Ashr = (share**) malloc(sizeof(share*) * size);
	Bshr = (share**) malloc(sizeof(share*) * size);
	Index = (share**) malloc(sizeof(share*) * (size));
	for (i = 0; i < size; i++) {
		Ashr[i] = mincirc->PutINGate(1, party_A_rand_dist[i], bitlen*4, CLIENT);
		Bshr[i] = mincirc->PutINGate(1, party_B_rand[i], bitlen*4, SERVER);
		Index[i] = mincirc->PutINGate(1, i, ceil_log2(size), CLIENT);
	}


           
	min_ind = build_Min_Ind_dist_circ(Ashr, Bshr, Index, size, (BooleanCircuit*) mincirc);

	min_ind = mincirc->PutOUTGate(min_ind, ALL);
	
	party->ExecCircuit();

	output = min_ind->get_clear_value<uint64_t>();

	//CBitVector out;
	//out.AttachBuf(output, (uint64_t) AES_BYTES * nvals);

	cout << "Testing index min in (only)"<< get_sharing_name(minsharing) << " sharing: " << endl;

	cout << "Circuit result = " << output << endl;
	verify = verify_min_index_rand_dist(party_A_rand_dist, party_B_rand, size);
	cout << "Verification result = " << verify << endl;

//	PrintTimings();

	//TODO free
	for(i = 0; i < size; i++) {
		free(Index[i]);
		free(Ashr[i]);
		free(Bshr[i]);
	}

	free(party_A_rand_dist);
	free(party_B_rand);
	free(Index);
	free(Ashr);
	free(Bshr);

	return 0;
}

//Build_
share* build_Min_Ind_dist_circ_eff(share** A, share** B, 
				share** index, uint32_t size,
				Circuit* distcirc, 
				BooleanCircuit* mincirc) {

   share **distance;
   share* min_index;

   uint32_t i;
 
   distance = (share**) malloc(sizeof(share*) * size);

   assert(mincirc->GetCircuitType() == C_BOOLEAN);
   
   for (i=0; i<size; i++){				
	   distance[i] = distcirc->PutADDGate(A[i], B[i]);
   	   //temp = mincirc->PutADDGate(Ssqr[i], Csqr[j]);
	   distance[i] = mincirc->PutA2YGate(distance[i]);
	}

   min_index = mincirc->PutArgMinGate(distance, index, size);
   

    //TODO free
    for(i = 0; i < size; i++) {
		free(distance[i]);
	}

   free(distance);
   
   return min_index;
}


uint32_t verify_min_index_rand_dist(
	uint32_t* party_A_rand_dist, uint32_t* party_B_rand,  uint32_t size){

	uint32_t i;
	uint32_t min_ind, temp, mindist;

	mindist = MAX_UINT;

	for(i=0; i<size; i++) {

		temp = party_A_rand_dist[i] - party_B_rand[i];
		
//		cout<< i <<": "<< temp << endl;
		if(temp < mindist){
			mindist = temp;
			min_ind = i;
		}
	}

	cout<<"minimum index is :"<<min_ind<<endl;
//	cout<<"ctr index is :"<<ctr++<<endl;
	ABYParty* party = new ABYParty(role, address, seclvl, maxbitlen, nthreads, mt_alg);
	vector<Sharing*>& sharings = party->GetSharings();

	crypto* crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	
	uint64_t verify;

	Circuit *distcirc, *mincirc; //
	
	share **Ashr, **Bshr, *min_ind, **Index;
	
	
    distcirc = sharings[dstsharing]->GetCircuitBuildRoutine();
	mincirc =  sharings[minsharing]->GetCircuitBuildRoutine();
	
	srand(time(NULL));
	
    //set server input
	Ashr = (share**) malloc(sizeof(share*) * size);
	Bshr = (share**) malloc(sizeof(share*) * size);
	Index = (share**) malloc(sizeof(share*) * (size));
	for (i = 0; i < size; i++) {
		Ashr[i] = distcirc->PutINGate(1, party_A_rand_dist[i], bitlen*4, SERVER);
		Bshr[i] = distcirc->PutINGate(1, -party_B_rand[i], bitlen*4, CLIENT);
		Index[i] = mincirc->PutINGate(1, i, ceil_log2(size), CLIENT);
	}
          
	min_ind = build_Min_Ind_dist_circ_eff(Ashr, Bshr, Index, size, distcirc, (BooleanCircuit*) mincirc);

	min_ind = mincirc->PutOUTGate(min_ind, CLIENT);
	
	party->ExecCircuit();

	output = min_ind->get_clear_value<uint64_t>();

	cout << "Testing index min in " << get_sharing_name(dstsharing) << " AND " <<
		get_sharing_name(minsharing) << " sharing: " << endl;
	cout << "Circuit result = " << output << endl;

	verify = verify_min_index_rand_dist(party_A_rand_dist, party_B_rand, size);

	cout << "Verification result = " << verify << endl;
	//TODO free
	for(uint32_t i = 0; i < size; i++) {
		free(Index[i]);
		free(Ashr[i]);
		free(Bshr[i]);
	}

	free(Index);
	free(Ashr);
	free(Bshr);

	return 1;
}*/

//Build_
share* build_Min_Ind_dist_circ(share** A, share** B, 
				share** index, uint32_t size, 
				BooleanCircuit* mincirc) {

   share **distance;
   share *min_index;

   uint32_t i;
 
   distance = (share**) malloc(sizeof(share*) * size);

   assert(mincirc->GetCircuitType() == C_BOOLEAN);
   
   for (i=0; i<size; i++){				
	   distance[i] = mincirc->PutSUBGate(A[i], B[i]);
   	   //temp = mincirc->PutADDGate(Ssqr[i], Csqr[j]);
	   //distance[ctr] = mincirc->PutSUBGate(temp, distance[ctr]);
	}

   min_index = mincirc->PutArgMinGate(distance, index, size);
   
   free(distance);
   
   return min_index;
}
