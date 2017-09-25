//Utility libs
#include "../../abycore/util/crypto/crypto.h"
#include "../../abycore/util/parse_options.h"
//ABY Party class
#include "../../abycore/aby/abyparty.h"


#include "common/update-min-circuit.h"
#include "common/cluster_points.h"
#include "common/timer.hpp"
#include "common/paillier_eff.h"
#include "PrivHcluster.h"
#include "hcluster.h"

using namespace std;

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* bitlen, 
	uint32_t* sizevals, uint32_t* secparam, string* address, uint16_t* port, int32_t* test_op) {

	uint32_t int_role = 0, int_port = 0;
	bool useffc = false;

	parsing_ctx options[] = { { (void*) &int_role, T_NUM, 'r', "Role: 0/1", true, false }, 
			{ (void*) sizevals, T_NUM, 'n', "encrypted distances size", false, false }, 
			{ (void*) bitlen, T_NUM, 'b', "Bit-length, default 32", false, false }, 
			{ (void*) secparam, T_NUM, 's', "Symmetric Security Bits, default: 128", false, false }, 
			{ (void*) address, T_STR, 'a', "IP-address, default: localhost", false, false }, 
			{ (void*) &int_port, T_NUM, 'p', "Port, default: 7766", false, false }, 
			{ (void*) test_op, T_NUM, 't', "Single test (leave out for all operations), default: off", false, false } };

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}
	//delete options;
	return 1;
}

bool DEBUG = true;

void test_min_rand_index(e_role role, uint32_t nthreads, seclvl seclvl,
		e_mt_gen_alg mt_alg, CSocket& socket, char* address, 
		int port, int data_size)
{

    gmp_randstate_t m_randstate;
    gmp_randinit_default(m_randstate);
    gmp_randseed_ui(m_randstate, rand());

    cout << "Test connection" << endl;
    pa_pubkey_t* pub; //The public key
    pa_prvkey_t* prv; //The private key 
//    paillier_pq_sk* pq_sk;

	uint32_t maxbitlen = 32, i; 

    pa_keygen(1024, &pub, &prv);

    vector<pa_text*> a;
    vector<pa_cipher*> ca;
    
    a.resize(data_size);
    ca.resize(data_size);
    
    srand(time(NULL));
    
    uint32_t temp = 1000000;
    uint32_t min_indx = 0;

	Timer timer;

    if(role == CLIENT){
    	timer.start();
 	    for(i = 0; i < a.size();i++){
	 	   	
	 	   	uint32_t R = rand() % ((uint32_t) 1 << 8);
		   	
		   	if(R < temp){
	 	      		temp = R;
	 	      		min_indx = i;
	 	    }

	 	    a[i]  = pa_text_from_ui(R); 
	 	    ca[i] = pa_encrypt_0(0, pub, a[i]->m, m_randstate);
 	    }  
    	cout<< "minimum index is : "<<min_indx <<endl;
    	timer.stop();
    	cout<< "encrypting randomness time :"<< timer.elapsed_time()*1000<< " milli-sec."<<endl;
	}
    
    //Client holds enc(dist_i), sample random values, Client (party_A)

	assert(role == 1 || role == 0);
	uint32_t size = ca.size();


	uint32_t* party_A_rand;
	uint32_t* dist_rand_B;

	vector<pa_text*> randomness;
	randomness.resize(size);

	party_A_rand = (uint32_t*) malloc(sizeof(uint32_t) * size);
	dist_rand_B  = (uint32_t*) malloc(sizeof(uint32_t) * size);
	
	//===============================
	if(role == CLIENT){//client
		cout<<"client generate randomness"<<endl;
		//srand(time(NULL));
		for(i = 0; i < size; i++) {
			party_A_rand[i] = rand() % ((uint32_t) 1 << maxbitlen-1);	
			randomness[i] = pa_text_from_ui(party_A_rand[i]);
		}   


		timer.start();

		vector<pa_cipher*> cipher_to_B;
		cipher_to_B = homo_add_randomness(pub, ca, randomness, m_randstate);
		timer.stop();

		cout<< "Time for homo_add is "<<timer.elapsed_time()*1000.00 <<" ms."<<endl;

		timer.start();
    	if(send_enc(cipher_to_B, socket, address, port)){
    	       cout<<"sent!!"<<endl;
    	}
    	timer.stop();
    	cout<< "Time for sending is "<<timer.elapsed_time()*1000.00 <<" ms."<<endl;

	}else{//Server ....\

		vector< pa_cipher* > v;
	
		timer.start();

        v = recv_enc(size, socket, address, port);

        for(i =0; i<size; ++i){// receive initial pid when connected
            mpz_t results;
            mpz_init(results);
            pa_decrypt(results, pub, prv, v[i]->c);
            mpz_to_ui(&dist_rand_B[i], results);
            mpz_clear(results);
        }
       	timer.stop();
    	cout<< "Time for receiving and decrypting is "<<timer.elapsed_time()*1000.00 <<" ms."<<endl;

	}

    // }
    //return minimum index of ca.....
   uint32_t index;

    //Execute of the protocol, [A(rand) <==> B(rand+ct)]
    index = exec_min_circ(role, address, seclvl, size, party_A_rand, dist_rand_B,
		nthreads, mt_alg, S_ARITH, S_YAO);

    free(party_A_rand);
    free(dist_rand_B);
    
    cout<<"minimum index is:"<<index<<endl;

    if(index == min_indx){
    	cout<< "PASS!!!!"<<endl;
    }
}


vector<int> dataA;
vector<int> dataB;

/*
	test clustering algorithm ... pass!!
**/
void test_cluster_steps(){

    vector< vector<double> > matrix;

    int i, j;
/*
    srand(time(NULL));

    for (i = 0; i < num_items; i++) {
         matrix[i].resize(num_items);
         for (j = 0; j < num_items; j++){
         	matrix[i][j] = rand() % 120;
         }
    }
*/
    // for (i = 0; i < num_items; i++) {
    //    matrix[i].resize(num_items);
    // }
     
    uint32_t sizeA = dataA.size();
    uint32_t sizeB = dataB.size();

   //  vector<double> dataA;
   //  vector<double> dataB;

   //  for(i=0; i<sizeA; i++){
	  // dataA.push_back(i*2 + 2);
   //  }
  
   //  for(i=0; i<sizeB; i++){
	  // dataB.push_back(i+3);
   //  }

    vector<double> temp;

    for(i=0; i<sizeA; i++){
	  temp.push_back(dataA[i]);
    }
    for(i=0; i<sizeB; i++){
      temp.push_back(dataB[i]);
    }
    
    matrix.resize(sizeA + sizeB);

    for(i = 0 ; i < matrix.size(); i ++)
    {
  	  matrix[i].resize(sizeA + sizeB);

  	   for(j = 0; j < sizeA+sizeB; ++j)
  	   {
         matrix[i][j] = pow(temp[i]-temp[j] ,2);
  	   }
    }

    temp.clear();
  

     // matrix[1][0] = 0.71;
     // matrix[2][0] = 5.66;
 
     // matrix[2][1] = 4.95;

     // matrix[3][0] = 3.61;
     // matrix[3][1] = 2.92;
     // matrix[3][2] = 2.24;
    
     // matrix[4][0] = 4.24;
     // matrix[4][1] = 3.54;
     // matrix[4][2] = 1.41;
     // matrix[4][3] = 1.00;


     // matrix[5][0] = 3.20;
     // matrix[5][1] = 2.50;
     // matrix[5][2] = 2.50;
     // matrix[5][3] = 0.50;
     // matrix[5][4] = 1.12;

 //    matrix[1][0] = 206;

 //    matrix[2][0] = 429;
 //    matrix[2][1] = 233;

 //    matrix[3][0] = 1504;
 //    matrix[3][1] = 1308;
 //    matrix[3][2] = 1075;
    
 //    matrix[4][0] = 963;
 //    matrix[4][1] = 802;
 //    matrix[4][2] = 671;
 //    matrix[4][3] = 1329;
    
 //    matrix[5][0] = 2976;
 //    matrix[5][1] = 2815;
 //    matrix[5][2] = 2684;
 //    matrix[5][3] = 3273;
 //    matrix[5][4] = 2013;

 	 	 	 	

	// matrix[6][0] = 3095;
 //    matrix[6][1] = 2934;
 //    matrix[6][2] = 2799;
 //    matrix[6][3] = 3053;
 //    matrix[6][4] = 2142;
 //    matrix[6][5] = 808;

 	 	 	 	 	 	

 //    matrix[7][0] = 2979;
 //    matrix[7][1] = 2786;
 //    matrix[7][2] = 2631;
 //    matrix[7][3] = 2687;
 //    matrix[7][4] = 2054;
 //    matrix[7][5] = 1131;
 //    matrix[7][6] = 379;

 //    matrix[8][0] = 1949;
 //    matrix[8][1] = 1771;
 //    matrix[8][2] = 1616;
 //    matrix[8][3] = 2037;
 //    matrix[8][4] = 996;
 //    matrix[8][5] = 1307;
 //    matrix[8][6] = 1235;
 //    matrix[8][7] = 1059;


    uint32_t num_cl = 3;
    
    HCluster aa;
    
    matrix = aa.make_sym_matrix(matrix);

    for(i = 0; i < matrix.size(); ++i)
    {
  		for(j = 0; j < matrix.size(); ++j)
  	    {
         cout<< matrix[i][j]<< " ";
  	    }
        cout<<endl;
    }

    HCluster c(matrix);
    c.AggClustering(num_cl);
    c.outputCluster();

}



/*
	test Privacy-Preserving Clustering Algorithm ... pass!!
**/
int test_priv_clustering(vector<int> a_data, vector<int> b_data, e_role role, uint32_t nthreads, seclvl seclvl,
		e_mt_gen_alg mt_alg, CSocket& socket, char* address, 
		int port)
{

  uint32_t i, j, k;
 

  pa_pubkey_t* pub; //The public key
  pa_prvkey_t* prv; //The private key 

  pa_keygen(512, &pub, &prv);


  uint32_t sizeA = a_data.size();
  uint32_t sizeB = b_data.size();

  // vector<int> dataA;
  // vector<int> dataB;

  // for(i=0; i<sizeA; i++){
		// dataA.push_back(i*2 + 2);
  // }
  
  // for(i=0; i<sizeB; i++){
		// dataB.push_back(i+3);
  // }

  vector<int> temp;

  for(i=0; i<sizeA; i++){
		temp.push_back(dataA[i]);
  }
  for(i=0; i<sizeB; i++){
		temp.push_back(dataB[i]);
  }
  

  vector< vector<int> > distances;

  distances.resize(sizeA + sizeB);

  for(i = 0 ; i < distances.size(); i ++)
  {
  	distances[i].resize(sizeA + sizeB);
  	
  	for(j = 0; j < sizeA+sizeB; ++j)
  	{
       distances[i][j] = pow(temp[i]-temp[j] ,2);
  	}

  }

  for(i = 0; i < sizeB+sizeA; ++i)
  {
  	for(j = 0; j < sizeB+sizeA; ++j)
  	{
       cout<< distances[i][j]<< " ";
  	}
    cout<<endl;
  }
 

  cout<<dataA.size()<<endl;

  PRHCluster pcluster(pub, prv, role, socket, address, port, nthreads, seclvl, 
  		mt_alg, a_data, b_data, sizeA, sizeB);

  pcluster.AggClustering(3);

  if(role == CLIENT) pcluster.outputCluster();

	return 1;
}




int main(int argc, char** argv) {

	e_role role;
	uint32_t bitlen = 32, sizeval = 10, secparam = 128, nthreads = 1;
	uint16_t port = 1122;
	string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &sizeval, &secparam, &address, &port, &test_op);

	seclvl seclvl = get_sec_lvl(secparam);
	
	CSocket socket;
//	test_min_rand_index(role, nthreads, seclvl, mt_alg, socket, (char*) address.c_str(), port, (uint32_t) sizeval);



  	//srand(time(NULL));
  	uint32_t a_size = 50;
  	uint32_t b_size = 50;
    
  	uint32_t i, j;
    for (i = 0; i < a_size; i++) {
       dataA.push_back(rand() % 112);
    }
    for (i = 0; i < b_size; i++) {
       dataB.push_back(rand() % 112);
    }
	cout<<"here"<<endl;
    test_cluster_steps();
    
    
    
	Timer t;
	t.start();
	
	test_priv_clustering(dataA, dataB, role, nthreads, seclvl, mt_alg, socket, (char*) address.c_str(), port);

	t.stop();
	cout<<" Elasped time is "<< t.elapsed_time()<< " sec."<<endl;

	cout<<"\n====================================\n"<<endl;


	return 0;
}

//void testing(){

	//test_min_rand_index(role, nthreads, seclvl, mt_alg, socket, (char*) address.c_str(), port, sizeval);
	
	//	test_connection(role, socket, address, port);	

  	//Client (1) is the evaluator (received the garbled circuits)...

	//test_min_ind_enc_dist_circuit_eff(role, (char*) address.c_str(),
	//    seclvl, sizeval, nthreads, mt_alg, S_ARITH, S_YAO);

	//test_min_ind_enc_dist_circuit(role, (char*) address.c_str(), seclvl, sizeval, nthreads, mt_alg, S_YAO);

//}
