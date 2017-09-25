#include "PrivHcluster.h"

#include "common/cluster_points.h"

#include <iostream>
#include <ostream>

#define DEBUG = 1;

//copy a's value to target
pa_cipher* copy_cipher(pa_cipher* target, pa_cipher* a){

    if(!target){
        target = (pa_cipher*) malloc(sizeof (pa_cipher));
        mpz_init(target->c);
    }
    mpz_set(target->c, a->c);
    return target;
}


int writeFile (string fileName, string content) 
{
  ofstream myfile;
  myfile.open (fileName);
  myfile << content<<endl;
  myfile.close();
  return 0;
}

//set up sizeA, sizeB
// 0 ... sizeA - 1,  sizeA, ...., sizeA + (sizeB-1) 
// one dimension ... ...

PRHCluster::PRHCluster(pa_pubkey_t* pub, pa_prvkey_t* prv, 
        e_role r, CSocket _socket,  string _address, int _port,
		uint32_t _nthreads,	seclvl _seclevel, e_mt_gen_alg _mt_alg,
		vector<int> dataA, vector<int> dataB, uint32_t sizeA, uint32_t sizeB)
{

	this->role = r;
	this->socket = _socket;
	this->address = _address;
	this->port = _port;
	this->nthreads = _nthreads;
	this->seclevel = _seclevel;
	this->mt_alg = _mt_alg;

    gmp_randinit_default(rand_state);
    gmp_randseed_ui(rand_state, rand());

    this->pub = pub;
    this->prv = prv;

    pa_text* zero;
    zero = pa_text_from_ui(0);
    this->enc_zero = pa_cipher_init();
    this->enc_zero = pa_encrypt_0(0, pub, zero->m, rand_state);   
   
    this->sizeA = sizeA;
    this->sizeB = sizeB;
 
    uint32_t SIZE =  sizeA + sizeB;

    //initial number of clusters (points)
    CLUSTER_Arr.resize(SIZE);
    distMatrix.resize(SIZE);

    uint32_t i, j, k = 0;
    //set PCluster id ...
    for (i = 0; i < SIZE; ++i) {
        PCluster c;
        c.insert_id(i);
        CLUSTER_Arr[i] = c;

        //distance matrix
        distMatrix[i].resize(SIZE);
    }

    if(role == CLIENT){
        for (i = 0; i < sizeA; ++i) {
            for(j = 0; j < i; ++j){           
               //(d_i - d_j)^2
               uint32_t dist_ij = pow(dataA[i] - dataA[j], 2);
               pa_text* msg_dataA;
               msg_dataA = pa_text_from_ui(dist_ij);
               distMatrix[i][j] = pa_encrypt_0(0, pub, msg_dataA->m, rand_state);
            }
        }
        cout<<"Client setup done ...."<<endl;
    }
    //setupDistMatrix(role, data);

    cout<<"Begin to 2pc on distMatrix ... \n"<<endl;
     //setup the distMatrix ...
        

    t.start();    
    if(role == SERVER){
        
        vector< vector<pa_cipher*> > dataB_enc; //data points ...
        vector< vector<pa_cipher*> > B_enc_dist; //distance matrix ...
        
        //updating the 
        ServerDistEnc(dataB, dataB_enc, B_enc_dist);

        cout<<"Server is sending the ciphers...."<<endl;
        //sending ....
        if(send_vect_enc(dataB_enc, socket, address, port)){
            cout<<"sending the initial enc(distance) ...\nSent."<<endl;
        }
        //sending ....
        if(send_matrix_enc(B_enc_dist, socket, address, port)){
            cout<<"sending the initial enc(distance) ...\nSent."<<endl;
        }

        dataB_enc.clear();
        B_enc_dist.clear();
    }
    else if(role == CLIENT){

        vector< vector< pa_cipher*> > recv_data; //b
        vector< vector< pa_cipher*> > recv_B_dist;
        vector< vector< pa_cipher*> > enc_matrix_data;

        //encrypted pairwise distance computation
        cout<<"receiving pairwise distance computation"<<endl;
        recv_data = recv_vect_enc(sizeB, socket, address, port);

        //encrypted distance   : nB X nB
        recv_B_dist = recv_matrix_enc(sizeB, socket, address, port);

        //Processing the homomorphic operations... correct!!!
        ClientDistRecEnc(dataA, recv_data, enc_matrix_data);
        
        cout<<"Constructing distMatrix ... "<<endl;

        //set matrix A(Client) & B(Server) ...
        for(j = 0; j < sizeB; j++){
            for(i = 0;  i < sizeA; i++){
                distMatrix[sizeA + j][ i ] = pa_cipher_init();
                distMatrix[sizeA + j][ i ] = enc_matrix_data[i][j];
            }
        }       
        //set matrix A(Client) & B(Server) ...
        //lower triangle ...
        for(i = 1;  i< sizeB; i++){
            for(j = 0; j < i; j++){

                distMatrix[sizeA + i][ sizeA + j ] = pa_cipher_init();
                distMatrix[sizeA + i][ sizeA + j ] = recv_B_dist[i][j];
            }
        }

       distMatrix = make_sym_matrix(distMatrix);
       
       recv_data.clear();
       recv_B_dist.clear();
       enc_matrix_data.clear();
    }

    t.stop();

    string setup_time = "setup time :" + to_string(t.elapsed_time()) + " s.";

    cout<<"Done setup!!\n";
    cout<<"=========================================="<<endl;
}

PRHCluster::~PRHCluster() {
   distMatrix.clear();
   CLUSTER_Arr.clear();
}

//perform pairwise homomorphic operations on the distances ...
void PRHCluster::ClientDistRecEnc(
    vector <int> data, vector <vector <pa_cipher*> >& recv_data, 
    vector< vector<pa_cipher*> >&  matrix_enc)
{
    cout<<"received data size: "<<recv_data.size()<<endl;
    
    for(size_t i = 0; i < data.size(); ++i){

        pa_text*  two_p;
        pa_text*  p_square; 
        
        p_square = pa_text_from_ui(data[i] * data[i]);
        two_p = pa_text_from_ui( 2 * data[i]);
    
        pa_cipher* enc_p_square;
        enc_p_square = pa_encrypt_0(0, pub, p_square->m, rand_state);
           
        vector<pa_cipher*> temp_vect;
        temp_vect.resize(recv_data.size());
        
        for(size_t j = 0; j < recv_data.size(); ++j){
    
            pa_cipher* eclidean;
            eclidean = pa_cipher_init();
    
            pa_cipher* results;
            results = pa_cipher_init();
    
            pa_cipher* two_pq;
            two_pq = pa_cipher_init();  
    
            pa_mul(pub, results, recv_data[j][0], enc_p_square); // results <- P^2+ Q^2
            pa_exp(pub, two_pq, recv_data[j][1], two_p); //2pq
            pa_sub(pub, eclidean, results, two_pq);
    
            temp_vect[j] = eclidean;
        }
        
        matrix_enc.push_back(temp_vect);
        temp_vect.clear();
    }
   
}


/* B_enc: 
 * dataB X 2 < ... Enc(p_j), Enc(p^2_j) ... >, 
 * dataB X dataB <  enc(d_ij) >  
 */
void PRHCluster::ServerDistEnc(vector <int> data, vector< vector<pa_cipher*> >& B_enc,
        vector< vector<pa_cipher*> >& B_enc_dist){

    size_t i, j;
    
    for(i = 0; i < data.size(); i++){
        
        vector<pa_cipher*> v;
        
        pa_text* p; 
        pa_text* p_square;
                
        p_square = pa_text_from_ui(data[i] * data[i]); 
        p = pa_text_from_ui(data[i]); 

        v.push_back(pa_encrypt_0(0, pub, p_square->m, rand_state));      
        v.push_back(pa_encrypt_0(0, pub, p->m, rand_state));

        B_enc.push_back(v);

        v.clear();
    }

    /** Enc(dist) b/w points in B (server ...) **/
    for (i = 0; i < data.size(); i++) {   
        
        vector<pa_cipher*> v;  
        for(j = 0; j < i; ++j){   
            //d_i^2 + d_j^2 - 2 * d_ij 
            uint32_t dist_ij = pow(data[i], 2) +  pow(data[j],2) - 2 * data[i] * data[j];
            pa_text* msg_dataB;
            msg_dataB = pa_text_from_ui(dist_ij);
            v.push_back(pa_encrypt_0(0, pub, msg_dataB->m, rand_state));
        }
      
        B_enc_dist.push_back(v);
        v.clear();
    }
}

/*
*
*/
void PRHCluster::AggClustering(uint32_t num_cl) {
 
  int curr_num_clusters = total_points, debugcount = 0;

  int server_rev_size;

  if(role == SERVER) server_rev_size = sizeA+sizeB;

  while (curr_num_clusters >= num_cl) 
  {
    
    cout<<"*********** "<< debugcount++ <<"th iteration ***********"<<endl;
    //get minimum index i & j
    //convert to 1-d array ...
    vector<Cord_ij> cord_vect;
    vector<pa_cipher*> pairwise_dist;

    int indx = 0;
    int new_size = distMatrix.size() * (distMatrix.size() - 1) / 2;

    cord_vect.resize(new_size);
    pairwise_dist.resize(new_size);

    if(role == CLIENT){
        cout<<"Client begins to setup encrypted arr... \n";
        cout<<"----------------"<<endl;

        for (unsigned k = 0; k < distMatrix.size(); k++) {
            for (unsigned l = 0; l < k; l++) {
                if (k != l) {
     
                  Cord_ij indx_lk;
                  indx_lk.cord_i = k;
                  indx_lk.cord_j = l;
                  indx_lk.index = indx;
                  cord_vect[indx] = indx_lk;
                  //set ciphers...
                  pairwise_dist[indx] = (pa_cipher*) malloc(sizeof(pa_cipher));
                  mpz_init(pairwise_dist[indx]->c);
                  mpz_set(pairwise_dist[indx]->c,distMatrix[k][l]->c);

                  indx++;
                }
            }
        }//end for k...


    }//end if client
    else if(role == SERVER){
        new_size =  server_rev_size * (server_rev_size - 1) /2;
    }


   //Server wait for client for the ith-iteration ... ...
   // while(!recv_start_signal()){
        cout<< "waiting for the minimum circuit ... " <<endl;
   //    wait(10);
   // }

    //2PC to get minimum ... 
    t.start();

    //-----------------------------------------------------
    //Different PORT!!!!!
    int min_index = min_rand_index(role, new_size, pairwise_dist, port+1000+debugcount);
    t.stop();
    //-----------------------------------------------------
    cout<<"2 PC for the minimum index: "<<t.elapsed_time()<<" s"<<endl;
    
    if(role == CLIENT){
        t.start();
        cout<<"Client updates the matrix ..."<<endl;

        int i = cord_vect[min_index].cord_i;
        int j = cord_vect[min_index].cord_j;
        
       
        //merge ith and jth clusters...
        merge(i, j);
        //-----------------------------------

        if(CLUSTER_Arr.size() == num_cl){
            cout<<"Client clustering done ...."<<endl;
            break;
        }

        //update distance metric
        updateDistMatrix(i, j);

        //update clusters();
        curr_num_clusters--;
        t.stop();
        //-----------------------------------------------------
        cout<<"distance matrix updated time: "<<t.elapsed_time()<<" s"<<endl;
    

    }else if (role == SERVER){//Server ...

        server_rev_size --;

        if(server_rev_size == num_cl)
        {
            cout<<"Client clustering done ...."<<endl;
            break;
        }
    }

    //Free the memory
    cord_vect.clear();
    // for (unsigned f = 0; f < pairwise_dist.size(); ++f)
    // {
    //    // mpz_clear(pairwise_dist[f]->c);
    //     free(pairwise_dist[f]);
    // }
    pairwise_dist.clear();
    
    cout<<"************************************"<<endl;
   }
}

void PRHCluster::outputCluster(){
    int i;
    for (i = 0;  i < CLUSTER_Arr.size(); i++) {
         cout<<"PCluster "<< i<<" ( ";
         for(auto p: CLUSTER_Arr[i].getPoints())
             cout<<" "<< p;
        cout<<")"<<endl;
    }
}

//Client holds enc(dist_i), sample random values, Client (party_A)
uint32_t PRHCluster::min_rand_index(e_role role, int data_size, vector<pa_cipher*> ca, int p_port)
{

	uint32_t maxbitlen = 32, min_indx = 0, i;
    
	assert(role == 1 || role == 0);

	uint32_t size = ca.size();
	uint32_t* party_A_rand;
	uint32_t* dist_rand_B;

	vector<pa_text*> randomness;
	randomness.resize(size);


	party_A_rand = (uint32_t*) malloc(sizeof(uint32_t) * size);
	dist_rand_B  = (uint32_t*) malloc(sizeof(uint32_t) * size);

	//===============================
	if(role == CLIENT) {//Client

        t.start();

        cout<<"generating randomness & performing homo blinding ...."<<endl;

        for(i = 0; i < size; i++) 
	    {
	    	party_A_rand[i] = rand() % ((uint32_t) 1 << maxbitlen-1);	//@todo.. 
	    	randomness[i] = pa_text_from_ui(party_A_rand[i]);
	    }   

        t.stop();
        cout<<"sample randomness processing time is "<<t.elapsed_time()<<" s."<<endl;

        t.start();
	    vector<pa_cipher*> cipher_to_B;
 	    cipher_to_B = homo_add_randomness(pub, ca, randomness, rand_state);
        t.stop();
        cout<<"client homomorphic time is "<<t.elapsed_time()<<" s."<<endl;

       
        t.start();
    	if(send_enc(cipher_to_B, socket, address, p_port)){
    	   	  cout<<"Client sent "<<size<< " ciphers"<<endl;
    	}
        t.stop();
        cout<<"client homomorphic time is "<<t.elapsed_time()<<" s."<<endl;



        cipher_to_B.clear();

	}else if (role == SERVER) {//Server ....
               
        vector< pa_cipher* > v;
        
        cout<<"Tries to recv ..."<<endl;

        v = recv_enc(data_size, socket, address, p_port);

        cout<<"++++++++++++\nServer received "<< data_size <<endl;

             // t.start();
        for(i = 0; i < data_size; ++i){
          	  mpz_t results;
          	  mpz_init(results);
              pa_decrypt(results, pub, prv, v[i]->c);
              mpz_to_ui(&dist_rand_B[i], results);
              mpz_clear(results);           
        }
             // t.stop();
             // cout<<"Server decryption time: "<<t.elapsed_time() <<" s."<<endl;
        v.clear();
	}


    uint32_t index;

    string output_role = (role == 1) ?  "Client" : "Server";

    t.start();

    cout<<"ROLE " << output_role << " begins to 2PC ..."<<endl;

    //Execute of the protocol, [A(rand) <==> B(rand+ct)]
    //connecting on the port 1111
    index = exec_min_circ(role, (char*) address.c_str(), seclevel, data_size, party_A_rand, dist_rand_B, 
                                             nthreads, mt_alg, S_ARITH, S_YAO);

    t.stop();
    cout<<"min_index circuit time: "<<t.elapsed_time() <<" s."<<endl;

    randomness.clear();
    free(party_A_rand);
    free(dist_rand_B);  

  //  cout<<"done minimum circuit ....."<<endl;
    cout<<"-------------------------------"<<endl;

    return index;
}


/***
 * Merge the ith and jth PCluster in Cluster_ARR no change privacy ...
 */
void PRHCluster::merge(int i, int j) {

    uint32_t k;

    PCluster merge_cluster;
    vector<int> cluster_ij;
    vector<int> c_i_points = CLUSTER_Arr[i].getPoints();
    vector<int> c_j_points = CLUSTER_Arr[j].getPoints();
    
    int c_i_size = c_i_points.size();
    vector<int>::iterator it;
   
    it = cluster_ij.begin();
    cluster_ij.insert(it, c_i_points.begin(), c_i_points.end());    

    it = cluster_ij.begin();
    cluster_ij.insert(it + c_i_size, c_j_points.begin(), c_j_points.end());
       
    merge_cluster.setPoints(cluster_ij);


    vector<PCluster> temp_v;

    for (k = 0; k < CLUSTER_Arr.size(); k++) {
        if (k != i && k != j)
            temp_v.push_back(CLUSTER_Arr[k]);
    }

    temp_v.push_back(merge_cluster);
   // cout<<" temp temp_v size :" <<temp_v.size()<<endl;   
    CLUSTER_Arr.clear();
    CLUSTER_Arr.resize(temp_v.size());

    for(k =0; k<temp_v.size(); k++){
        CLUSTER_Arr[k] = temp_v[k];
    }

    cluster_ij.clear();
    c_i_points.clear();
    c_j_points.clear();
    temp_v.clear();
}


/***
 * udpate the distance 
 */
void PRHCluster::updateDistMatrix(int i, int j) {

    //double D_ij = distMatrix[i][j];
	pa_cipher* D_ij = copy_cipher(0, distMatrix[i][j]);

    uint32_t k, l;

    uint32_t o_size = distMatrix.size();
    uint32_t new_size = o_size - 1;

    vector< vector<pa_cipher*> > new_distMatrix(new_size);

    for(k = 0 ; k < new_distMatrix.size(); ++k){
        new_distMatrix[k].resize(new_size);
    }
    
    int ctr;

    vector<pa_cipher*> d_i_vect;
    vector<pa_cipher*> d_j_vect;

    d_i_vect.resize(distMatrix.size()-2); //@TODO less than 2 ...
    d_j_vect.resize(distMatrix.size()-2); //@TODO less than 2 ...

    ctr = 0;
    for (k = 0; k < distMatrix.size(); k++) {
        if(k != i && k!=j){
            d_i_vect[ctr] = copy_cipher(0, distMatrix[k][i]);
            d_j_vect[ctr] = copy_cipher(0, distMatrix[k][j]);
            ctr++;
        }
    }

    ctr = 0;
    for (k = 0; k < distMatrix.size(); k++) {
        vector<pa_cipher*> row_v;
        if (k != i && k != j) {//

            for (l = 0; l < distMatrix.size(); l++) {
                if (l != i && l != j) {
                    row_v.push_back(distMatrix[k][l]);
                }
            }   
            new_distMatrix[ctr] = row_v;
            ctr++;
        }  
        row_v.clear();
    }
    
    //homomorphic updating ... ...
    vector<pa_cipher*> dist_temp(new_size - 1);
    
    //Updating ... ...
    for(k = 0;  k < new_size-1 ; k++){       
        dist_temp[k] = lance_william(D_ij, d_i_vect[k], d_j_vect[k]);
    }

    for (k = 0; k < new_size -1 ; k++) {
        new_distMatrix[new_size - 1][k] = dist_temp[k];
        new_distMatrix[k][new_size - 1] = dist_temp[k];
    }

    new_distMatrix[new_size - 1][new_size - 1] = copy_cipher(0, enc_zero);

    distMatrix.clear();
    distMatrix.resize(new_size);

    for(k = 0; k< new_size; k++){
        distMatrix[k].resize(new_size);
        for(l = 0; l < new_size; l++)
            distMatrix[k][l] = copy_cipher(0, new_distMatrix[k][l]);
    }

// #ifdef ssDEBUG
//     for(k = 0; k< new_size; k++){
//         for(l = 0; l < new_size; l++){
//             mpz_t results;
//             mpz_init(results);
//             pa_decrypt(results, pub, prv, distMatrix[k][l]->c);
//             gmp_printf("%Zd ", results);
//             mpz_clear(results);  
//         }
//         cout<<endl;
//     }
//     cout<<endl;
// #endif

    ///Free memory....
    mpz_clear(D_ij->c);
    free(D_ij);
     
    d_i_vect.clear();
    d_j_vect.clear();
    dist_temp.clear();
    new_distMatrix.clear();

// #ifdef sssDEBUG    
//     cout<<"old size is "  <<o_size<<endl;
//     cout<<"new size is "  <<new_size<<endl;
//     cout<<"updated size: "<<distMatrix.size()<<endl;
// #endif

}


/**
 * single linkage....
 */
pa_cipher* PRHCluster::lance_william(pa_cipher* d_ij, pa_cipher* d_ik, pa_cipher* d_jk) {
    //TODO!!!!!!!!!!!!!
    mpz_t md_ik, md_jk;
    mpz_init(md_ik);mpz_init(md_jk);

    pa_decrypt(md_ik, pub, prv, d_ik->c); 
    pa_decrypt(md_jk, pub, prv, d_jk->c); 
    
    uint32_t di, dj;
    mpz_to_ui(&di, md_ik);
    mpz_to_ui(&dj, md_jk);

    //gmp_printf("minimum(d_ik %Zd, d_jk %Zd): ", md_ik, md_jk);
    //MINIMUM!!!!
    if(di < dj){
       // cout<<"----"<<endl;
       // gmp_printf("%Zd\n", md_ik); 
       mpz_clear(md_ik);
       mpz_clear(md_jk);
       return d_ik;
    }
    else {
       // cout<<"----"<<endl;
       // gmp_printf("%Zd\n", md_jk); 
       mpz_clear(md_ik);
       mpz_clear(md_jk);
       
       return d_jk;
    }

   // return (d_jk + d_ik - abs(d_ik - d_jk)) / 2.0;
}

vector< vector<pa_cipher*> >  PRHCluster::make_sym_matrix(vector< vector<pa_cipher*> > matrix) {

	for (unsigned i = 0; i < matrix.size(); i++) {
        for (unsigned j = 0; j <= i; j++) {
            if (i != j) 
            	matrix[j][i] = matrix[i][j];
            else
                matrix[i][j] = pa_create_enc_zero();
        }
    }
    return matrix;
}



// void PRHCluster::setupDistMatrix(e_role role, vector<int> dataA, vector<int> dataB){

//     uint32_t i, j;

//     if(role == SERVER){
        
//         vector< vector<pa_cipher*> > dataB_enc; //data points ...
//         vector< vector<pa_cipher*> > B_enc_dist; //distance matrix ...
        
//         //updating the 
//         ServerDistEnc(dataB, dataB_enc, B_enc_dist);

//         cout<<"Server is sending the ciphers...."<<endl;
//         //sending ....
//         if(send_vect_enc(dataB_enc, socket, address, port)){
//             cout<<"sending the initial enc(distance) ...\nSent."<<endl;
//         }
//         //sending ....
//         if(send_matrix_enc(B_enc_dist, socket, address, port)){
//             cout<<"sending the initial enc(distance) ...\nSent."<<endl;
//         }
//     }
//     else if(role == CLIENT){

//         vector< vector< pa_cipher*> > recv_data; //b
//         vector< vector< pa_cipher*> > recv_B_dist;
//         vector< vector <pa_cipher*> > enc_matrix_data;

//         //encrypted pairwise distance computation   : 
//         cout<<"receiving"<<endl;
//         recv_data = recv_vect_enc(sizeB, socket, address, port);
//         //encrypted distance   : nB X nB
//         recv_B_dist = recv_matrix_enc(sizeB, socket, address, port);

//         //Processing the homomorphic operations...
//         ClientDistRecEnc(dataA, recv_data, enc_matrix_data);
        
//         cout<<"Constructing the distMatrix"<<endl;

//         //set matrix A(Client) & B(Server) ...
//         for(i = 0;  i < sizeA; i++){
//             for(j = 0; j < sizeB; j++){
//                 distMatrix[sizeA + j][ i ] = pa_cipher_init();
//                 distMatrix[sizeA + j][ i ] = enc_matrix_data[i][j];
//             }
//         }
        
//         //set matrix A(Client) & B(Server) ...
//         for(i = 0;  i< sizeB; i++){
//             for(j = 0; j < sizeB; j++){
//                 distMatrix[sizeA + i][ sizeA + j ] = pa_cipher_init();
//                 distMatrix[sizeA + i][ sizeA + j ] = recv_B_dist[i][j];

//             }
//         }

//        distMatrix = make_sym_matrix(distMatrix);
//     }
// }
