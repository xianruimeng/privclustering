//Utility libs
#include "../../abycore/util/crypto/crypto.h"
#include "../../abycore/util/parse_options.h"
//ABY Party class
#include "../../abycore/aby/abyparty.h"


#include "common/update-min-circuit.h"
#include "common/cluster_points.h"
#include "common/timer.hpp"
#include "common/paillier_eff.h"

#include <set>
#include <cmath>
#include <vector>
#include <iostream>
#include <iomanip>



#ifndef PR_HCLUSTER_H
#define PR_HCLUSTER_H

using namespace std;


/**
 *
 */

class Cord_ij {
public:
    int cord_i;
    int cord_j;
    int index;
    //Cordij(); 
    //Cordij(int i, int j, int id) : cord_i(i), cord_j(j), index(id) {}
};

class PCluster {
    uint32_t id; 
    vector<int> ind_set;

public:
    //PCluster();

    void insert_id(int id) {
        ind_set.push_back(id);
    }

    void setPoints(vector<int> &ind) {
        this->ind_set.clear();
        this->ind_set = ind;
    }

    vector<int> getPoints() {
        return ind_set;
    }
};

class PRHCluster {
public:

    PRHCluster() {};
    ~PRHCluster();


	PRHCluster(pa_pubkey_t* pub, pa_prvkey_t* prv, 
        e_role r, CSocket _socket,  string _address, int _port,
		uint32_t _nthreads,	seclvl _seclevel, e_mt_gen_alg _mt_alg,
		vector<int> dataA, vector<int> dataB, uint32_t sizeA, uint32_t sizeB);

    //void setupDistMatrix(e_role role, vector<int> dataA, vector<int> dataB);

    /** Perform the bottom up clustering.. **/
    void AggClustering(uint32_t num_cl);

    /**  updating the distance matrix after merging  **/
    void updateDistMatrix(int i, int j);

    int getLevel();
    int getNumberCluters();
    
    /** Merge ith, jth clusters **/
    void merge(int i, int j);


    /** get updated distances ... **/
    //double lance_william(double d_ij, double d_ik, double d_jk);
    pa_cipher* lance_william(pa_cipher* d_ij, pa_cipher* d_ik, pa_cipher* d_jk);

    /** Set up the symmetric matrix **/
    vector< vector<pa_cipher*> >  make_sym_matrix(vector< vector<pa_cipher*> > matrix); //
    
    void outputCluster();

    void ClientDistRecEnc(vector <int> data, vector <vector <pa_cipher*> >& recv_data, 
    	vector< vector<pa_cipher*> >&  matrix_enc);

    void ServerDistEnc(vector <int> data, vector< vector<pa_cipher*> >& B_enc,
        vector< vector<pa_cipher*> >& B_enc_dist);

    uint32_t min_rand_index(e_role role, int data_size, vector<pa_cipher*> ca, int p_port);

    //-------------------//
    unsigned int modulusbits;   
   //Network and alg...    

    CSocket socket;
    string address;
    int port;
    uint32_t nthreads;
    seclvl seclevel;
    e_mt_gen_alg mt_alg;
    e_role role;

    pa_cipher* enc_zero;

   //-------------------// 


private:

    pa_pubkey_t* pub; //The public key
    pa_prvkey_t* prv; //The private key 
    
    gmp_randstate_t rand_state;

    Timer t;

    int num_clutsters;

    uint32_t SIZE;
    uint32_t sizeA;//server data size
    uint32_t sizeB;//client (evaluator) data size

    int total_points;
    
    vector< vector<pa_cipher*> > distMatrix; ///encrypted distance matrix ...

    vector<PCluster> CLUSTER_Arr;


};

#endif
